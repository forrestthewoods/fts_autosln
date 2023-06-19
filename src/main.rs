use anyhow::anyhow;
use dashmap::{DashMap, DashSet};
use itertools::Itertools;
use pdb::*;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{c_void, CString, OsString};
use std::io::Write;
use std::os::windows::prelude::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use uuid::Uuid;

use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Diagnostics::Debug as WinDbg;
use windows_sys::Win32::System::ProcessStatus::MODULEINFO as ModuleInfo;
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW, GetModuleInformation};
use windows_sys::Win32::System::SystemServices as WinSys;
use windows_sys::Win32::System::Threading as WinThread;

fn main() -> anyhow::Result<()> {
    println!("hello world");

    let start = std::time::Instant::now();
    //sln_from_exe()?;
    sln_from_pid("UnrealEditor.exe")?;
    let end = std::time::Instant::now();
    println!("Elapsed Milliseconds: {}", (end - start).as_millis());

    println!("goodbye cruel world");
    Ok(())
}

fn sln_from_pid(name: &str) -> anyhow::Result<()> {
    // Find process
    let s = sysinfo::System::new_all();
    let (pid, proc) = s
        .processes()
        .iter()
        .filter(|(pid, proc)| proc.name() == name)
        .next()
        .ok_or_else(|| anyhow!("No proc containing {name}"))?;
    println!("{pid} {}", proc.name());

    // Get handle to process
    let process_handle = unsafe {
        WinThread::OpenProcess(
            WinThread::PROCESS_QUERY_INFORMATION | WinThread::PROCESS_VM_READ,
            0,
            pid.as_u32(),
        )
    };

    if process_handle == 0 {
        anyhow::bail!("Failed to open pid/process [{}]/[{}]", pid, proc.name());
    }

    println!("handle: {:?}", process_handle);
    let process_handle2 = windows::Win32::Foundation::HANDLE(process_handle);

    // Get PDB paths
    let mut pdb_paths : Vec<PathBuf> = Default::default();
    unsafe {
        // Find modules
        const MAX_MODULE_HANDES: usize = 16384;
        let mut module_handles: [isize; MAX_MODULE_HANDES] = [0; MAX_MODULE_HANDES];

        // Enumerate modules
        let mut bytes_needed: u32 = 0;
        let result = EnumProcessModules(
            process_handle,
            module_handles.as_mut_ptr(),
            (std::mem::size_of::<isize>() * MAX_MODULE_HANDES) as u32,
            &mut bytes_needed,
        );
        anyhow::ensure!(
            result != 0,
            "Failed to enumerate modules. Result: [{result}] Last Error: [{}]",
            std::io::Error::last_os_error()
        );

        // Get module directories
        let mut module_dirs: HashSet<PathBuf> = Default::default();

        let windows_dirname = OsString::from("windows");
        let system32_dirname = OsString::from("system32");
        let num_modules = (bytes_needed as usize / std::mem::size_of::<isize>()) as usize;
        for i in 0..num_modules {
            const MAX_PATH: usize = windows_sys::Win32::Foundation::MAX_PATH as usize;
            let mut sz_mod_name: [u16; MAX_PATH] = [0; MAX_PATH];

            if GetModuleFileNameExW(
                process_handle,
                module_handles[i as usize],
                sz_mod_name.as_mut_ptr(),
                MAX_PATH as u32,
            ) != 0
            {
                let module_name = OsString::from_wide(&sz_mod_name);
                //println!("    module: {}", module_name.to_string_lossy());

                let module_path: PathBuf = module_name.into();

                let module_dir: PathBuf = module_path
                    .parent()
                    .ok_or_else(|| anyhow!("Couldn't get parent dir from {:?}", module_path))?
                    .into();

                // Ignore windows/System32
                let skip = module_dir
                    .components()
                    .tuples()
                    .any(|(a, b)| windows_dirname.eq_ignore_ascii_case(a) && system32_dirname.eq_ignore_ascii_case(b));
                if skip {
                    continue;
                }

                // Store module dir and filepath
                module_dirs.insert(module_dir);
            }
        }

        // Build the PDB search path
        let mut search_path: String = module_dirs.iter().map(|d| d.to_string_lossy()).join(";");
        if let Ok(nt_symbol_path) = env::var("_NT_SYMBOL_PATH") {
            search_path.push(';');
            search_path.push_str(&nt_symbol_path);
        }

        let search_path_cstr = path_to_cstring(&OsString::from(&search_path)).unwrap();
        let search_path_pcstr = windows::core::PCSTR(search_path_cstr.as_ptr() as *const u8);

        // Set options before initialize
        WinDbg::SymSetOptions(WinDbg::SYMOPT_DEBUG);

        // Initialize symbols, including loaded modules
        let success = WinDbg::SymInitialize(process_handle2, search_path_pcstr, true);
        println!("SymInitialize result: [{success:?}]");

        // Iterate modules
        for i in 0..num_modules {
            // Get PDB path
            let mut pdb_image: WinDbg::IMAGEHLP_MODULE64 = Default::default();
            pdb_image.SizeOfStruct = std::mem::size_of::<WinDbg::IMAGEHLP_MODULE64>() as u32;
            let success : bool = WinDbg::SymGetModuleInfo64(process_handle2, module_handles[i] as u64, &mut pdb_image).0 == 1;
            
            if success {
                let path_bytes = pdb_image.LoadedPdbName.to_vec();
                let path_string = String::from_utf8(path_bytes.clone())?.replace("\0", "");
                if !path_string.is_empty() {
                    println!("pdb path: [{}]", &path_string);
                    pdb_paths.push(path_string.into());
                }
            }
        }
    }

    // Cleanup
    unsafe {
        WinDbg::SymCleanup(process_handle2);
        windows_sys::Win32::Foundation::CloseHandle(process_handle);
    }

    let source_roots: Vec<PathBuf> = vec!["C:/Program Files/Epic Games/UE_5.1".into()];
    let exclude_dirs: Vec<String> = ["Visual Studio".into(), "Windows Kits".into()].into_iter().collect();
    let sln_name = PathBuf::from("sln_from_pid");
    let sln_dir = PathBuf::from("c:/temp/foo_pid");
    return build_sln(&sln_name, &sln_dir, proc.exe(), &pdb_paths, &source_roots, &exclude_dirs);
}

fn sln_from_exe() -> anyhow::Result<()> {
    // Define target
    let test_target: PathBuf = "C:/Program Files/Epic Games/UE_5.1/Engine/Binaries/Win64/UnrealEditor.exe".into();
    //let test_target : PathBuf = "C:/source_control/fts_autosln/target/debug/deps/fts_autosln.exe".into();
    //let test_target: PathBuf = "C:/temp/cpp/autosln_tests/x64/Debug/autosln_tests.exe".into();

    let source_roots: Vec<PathBuf> = vec!["C:/Program Files/Epic Games/UE_5.1".into()];
    //let source_roots: Vec<PathBuf> = vec!["C:/source_control/fts_autosln".into()];
    let exclude_dirs: Vec<String> = ["Visual Studio".into(), "Windows Kits".into()].into_iter().collect();

    // Get PDBs for target
    println!("Finding PDBs");
    let pdbs = find_all_pdbs(&test_target)?;

    let sln_name = PathBuf::from("sln_from_exe");
    let sln_dir = PathBuf::from("c:/temp/foo_exe");
    return build_sln(&sln_name, &sln_dir, &test_target, &pdbs, &source_roots, &exclude_dirs);
}

fn build_sln(sln_name: &Path, sln_dir: &Path, exe_path: &Path, pdbs: &[PathBuf], source_roots: &[PathBuf], exclude_dirs: &[String]) -> anyhow::Result<()> {

    // Map PDB paths to local files
    println!("Finding local files");
    let processed_paths: Arc<DashSet<String>> = Default::default();
    let known_maps: Arc<DashMap<PathBuf, PathBuf>> = Default::default();
    let stuff: Vec<(PathBuf, HashSet<PathBuf>, HashSet<PathBuf>)> = pdbs
        .par_iter()
        .map(|pdb_path| {
            let pdb_name: PathBuf = pdb_path.file_stem().unwrap().into();
            let mut headers: HashSet<PathBuf> = Default::default();
            let mut source_files: HashSet<PathBuf> = Default::default();

            let pdb_files = get_source_files(&pdb_path).unwrap_or_default();

            for filepath in pdb_files {
                // Don't process the same paths over and over
                let lowerpath = filepath.to_string_lossy().to_ascii_lowercase();
                let inserted = processed_paths.insert(lowerpath);
                if !inserted {
                    continue;
                }

                if let Some(local_file) = to_local_file(filepath, &source_roots, &known_maps) {
                    if exclude_dirs
                        .iter()
                        .any(|exclude| local_file.to_string_lossy().contains(exclude))
                    {
                        continue;
                    }

                    let ext = local_file.extension().unwrap_or_default();
                    if ext == "h" || ext == "hpp" || ext == "inl" {
                        headers.insert(local_file);
                    } else {
                        source_files.insert(local_file);
                    }
                }
            }

            (pdb_name, headers, source_files)
        })
        .collect();

    let headers: Vec<PathBuf> = stuff
        .iter()
        .flat_map(|(_, headers, _)| headers.iter())
        .sorted_by_cached_key(|filepath| filepath.file_stem().unwrap())
        .cloned()
        .unique_by(|path| path.to_string_lossy().to_ascii_lowercase())
        .collect();

    let source_files: HashMap<PathBuf, Vec<PathBuf>> = stuff
        .into_iter()
        .map(|(pdb, _, files)| {
            (
                pdb,
                files
                    .iter()
                    .sorted_by_cached_key(|filepath| filepath.file_stem().unwrap())
                    .cloned()
                    .collect(),
            )
        })
        .collect();

    // Write solution
    std::fs::create_dir_all(sln_dir)?;
    let mut sln_path = sln_dir.join(sln_name);
    sln_path.set_extension("sln");
    println!("Writing sln - [{}]", sln_path.to_string_lossy());

    let mut file = std::fs::File::create(sln_path)?;
    file.write_all("\n".as_bytes())?; // empty newline
    file.write_all("Microsoft Visual Studio Solution File, Format Version 12.00\n".as_bytes())?;
    file.write_all("# Visual Studio Version 17\n".as_bytes())?;
    file.write_all("VisualStudioVersion = 17.5.33424.131\n".as_bytes())?;
    file.write_all("MinimumVisualStudioVersion = 10.0.40219.1\n".as_bytes())?;

    // exe project
    let sln_id = Uuid::new_v4();
    file.write_all(
        format!(
            "Project(\"{{{}}}\") = \"{}\", {:?}, \"{{{}}}\"\n",
            Uuid::new_v4(),
            exe_path.file_name().unwrap().to_string_lossy(),
            exe_path,
            sln_id
        )
        .as_bytes(),
    )?;
    file.write_all("\tProjectSection(DebuggerProjectSystem) = preProject\n".as_bytes())?;
    file.write_all("\t\tPortSupplier = 00000000-0000-0000-0000-000000000000\n".as_bytes())?;
    file.write_all(format!("\t\tExecutable = {}\n", exe_path.to_string_lossy()).as_bytes())?;
    file.write_all("\t\tRemoteMachine = DESKTOP-1U7T4L2\n".as_bytes())?;
    file.write_all(
        format!(
            "\t\tStartingDirectory = {}\n",
            exe_path.parent().unwrap().to_string_lossy()
        )
        .as_bytes(),
    )?;
    file.write_all("\t\tEnvironment = Default\n".as_bytes())?;
    file.write_all("\t\tLaunchingEngine = 00000000-0000-0000-0000-000000000000\n".as_bytes())?;
    file.write_all("\t\tUseLegacyDebugEngines = No\n".as_bytes())?;
    file.write_all("\t\tLaunchSQLEngine = No\n".as_bytes())?;
    file.write_all("\t\tAttachLaunchAction = No\n".as_bytes())?;
    file.write_all("\t\tIORedirection = Auto\n".as_bytes())?;
    file.write_all("\t\tEndProjectSection\n".as_bytes())?;
    file.write_all("\tEndProjectSection\n".as_bytes())?;
    file.write_all("EndProject\n".as_bytes())?;

    // source_code project
    let vcxproj_id = Uuid::new_v4();
    file.write_all(
        format!(
            "Project(\"{{{}}}\") = \"source_code\", \"{}.vcxproj\", \"{{{}}}\"\n",
            Uuid::new_v4(),
            sln_name.to_string_lossy(),
            vcxproj_id
        )
        .as_bytes(),
    )?;
    file.write_all("EndProject\n".as_bytes())?;

    file.write_all("Global\n".as_bytes())?;
    file.write_all("\tGlobalSection(SolutionConfigurationPlatforms) = preSolution\n".as_bytes())?;
    file.write_all("\t\tRelease|x64 = Release|x64\n".as_bytes())?;
    file.write_all("\tEndGlobalSection\n".as_bytes())?;
    file.write_all("\tGlobalSection(ProjectConfigurationPlatforms) = postSolution\n".as_bytes())?;
    file.write_all(format!("\t\t{{{}}}.Release|x64.ActiveCfg = Release|x64\n", sln_id).as_bytes())?;
    file.write_all(format!("\t\t{{{}}}.Release|x64.ActiveCfg = Release|x64\n", vcxproj_id).as_bytes())?;
    file.write_all("\tEndGlobalSection\n".as_bytes())?;
    file.write_all("\tGlobalSection(ExtensibilityGlobals) = postSolution\n".as_bytes())?;
    file.write_all(format!("\t\tSolutionGuid = {{{}}}\n", Uuid::new_v4()).as_bytes())?;
    file.write_all("\tEndGlobalSection\n".as_bytes())?;
    file.write_all("EndGlobal\n".as_bytes())?;

    // Write vcxproj
    let mut vcxproj_path = sln_dir.join(sln_name);
    vcxproj_path.set_extension("vcxproj");
    println!("Writing vcxproj - [{}", vcxproj_path.to_string_lossy());

    let mut file = std::fs::File::create(vcxproj_path)?;
    file.write_all("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n".as_bytes())?;
    file.write_all(
        "<Project DefaultTargets=\"Build\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n".as_bytes(),
    )?;

    file.write_all("<ItemGroup Label=\"ProjectConfigurations\">\n".as_bytes())?;
    file.write_all("    <ProjectConfiguration Include=\"Release|x64\">\n".as_bytes())?;
    file.write_all("      <Configuration>Release</Configuration>\n".as_bytes())?;
    file.write_all("      <Platform>x64</Platform>\n".as_bytes())?;
    file.write_all("    </ProjectConfiguration>\n".as_bytes())?;
    file.write_all("</ItemGroup>\n".as_bytes())?;

    file.write_all("  <PropertyGroup Label=\"Globals\">\n".as_bytes())?;
    file.write_all("    <VCProjectVersion>16.0</VCProjectVersion>\n".as_bytes())?;
    file.write_all("    <Keyword>Win32Proj</Keyword>\n".as_bytes())?;
    file.write_all(format!("    <ProjectGuid>{{{}}}</ProjectGuid>\n", vcxproj_id).as_bytes())?;
    file.write_all("    <RootNamespace>autoslntests</RootNamespace>\n".as_bytes())?;
    file.write_all("    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>\n".as_bytes())?;
    file.write_all("  </PropertyGroup>\n".as_bytes())?;

    file.write_all("<Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.Default.props\" />\n".as_bytes())?;
    file.write_all("<Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.props\" />\n".as_bytes())?;
    file.write_all("<Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.targets\" />\n".as_bytes())?;

    file.write_all("  <ItemGroup>\n".as_bytes())?;

    for source_file in headers
        .iter()
        .chain(source_files.iter().flat_map(|(_, files)| files.iter()))
    {
        file.write_all(format!("    <ClInclude Include={:?} />\n", source_file).as_bytes())?;
    }

    file.write_all("  </ItemGroup>\n".as_bytes())?;
    file.write_all("</Project>\n".as_bytes())?;

    // Write vcxproj.filters
    let mut filters_path = sln_dir.join(sln_name);
    filters_path.set_extension("vcxproj.filters");
    println!("Writing vcxproj.filters - [{}", filters_path.to_string_lossy());

    let mut file = std::fs::File::create(filters_path)?;
    file.write_all("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n".as_bytes())?;
    file.write_all(
        "<Project ToolsVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n".as_bytes(),
    )?;

    // Unique identifiers
    file.write_all("  <ItemGroup>\n".as_bytes())?;
    file.write_all("    <Filter Include=\"Headers\">\n".as_bytes())?;
    file.write_all(format!("      <UniqueIdentifier>{{{}}}</UniqueIdentifier>\n", Uuid::new_v4()).as_bytes())?;
    file.write_all("    </Filter>\n".as_bytes())?;
    for (pdb_name, _) in &source_files {
        file.write_all(format!("    <Filter Include={:?}>\n", pdb_name).as_bytes())?;
        file.write_all(format!("      <UniqueIdentifier>{{{}}}</UniqueIdentifier>\n", Uuid::new_v4()).as_bytes())?;
        file.write_all("    </Filter>\n".as_bytes())?;
    }
    file.write_all("  </ItemGroup>\n".as_bytes())?;

    // File paths with filter
    file.write_all("  <ItemGroup>\n".as_bytes())?;
    for filepath in &headers {
        file.write_all(format!("    <ClInclude Include={:?}>\n", filepath).as_bytes())?;
        file.write_all("      <Filter>Headers</Filter>\n".as_bytes())?;
        file.write_all("    </ClInclude>\n".as_bytes())?;
    }
    for (pdb_name, filepaths) in &source_files {
        for filepath in filepaths {
            file.write_all(format!("    <ClInclude Include={:?}>\n", filepath).as_bytes())?;
            file.write_all(format!("      <Filter>{}</Filter>\n", pdb_name.to_string_lossy()).as_bytes())?;
            file.write_all("    </ClInclude>\n".as_bytes())?;
        }
    }
    file.write_all("  </ItemGroup>\n".as_bytes())?;
    file.write_all("</Project>\n".as_bytes())?;

    // Success!
    Ok(())
}

fn file_exists(path: &Path) -> bool {
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.is_file() {
            return true;
        } else if meta.is_symlink() {
            // Follow symlink
            if let Ok(real_path) = std::fs::read_link(&path) {
                if let Ok(meta) = std::fs::metadata(&real_path) {
                    if meta.is_file() {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

fn to_local_file(
    file: PathBuf,
    user_roots: &[PathBuf],
    known_maps: &Arc<DashMap<PathBuf, PathBuf>>,
) -> Option<PathBuf> {
    if file_exists(&file) {
        return Some(file);
    } else {
        // See if a known map applies
        for kvp in known_maps.iter() {
            let src = kvp.key();
            let dst = kvp.value();

            if file.starts_with(src) {
                let tail = file.strip_prefix(src).ok()?;
                let maybe_filepath = dst.join(tail);
                if file_exists(&maybe_filepath) {
                    //println!("it helped!");
                    return Some(maybe_filepath.to_owned());
                }
            }
        }

        // Couldn't find file. See if it exists relative to a root
        let components: Vec<_> = file.components().collect();
        let mut idx: i32 = components.len() as i32 - 1;
        let mut relpath = PathBuf::new();
        while idx >= 0 {
            let comp: &Path = components[idx as usize].as_ref();
            relpath = if relpath.as_os_str().is_empty() {
                comp.to_path_buf()
            } else {
                comp.join(&relpath)
            };

            for user_root in user_roots {
                let maybe_filepath = user_root.join(&relpath);
                //println!("    {:?}", maybe_filepath);
                if file_exists(&maybe_filepath) {
                    // create a new known map
                    let pdb_path: PathBuf = components.iter().take(idx as usize).collect();
                    //println!("inserting {:?}, {:?}", pdb_path, user_root);
                    known_maps.insert(pdb_path, user_root.to_owned());

                    return Some(maybe_filepath);
                }
            }

            idx -= 1;
        }

        None
    }
}

fn find_all_pdbs(target: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut pdbs: Vec<PathBuf> = Default::default();

    let mut open_list: Vec<(PathBuf, PathBuf)> = vec![split_filepath(target)?];
    let mut closed_list: HashSet<PathBuf> = Default::default();

    while !open_list.is_empty() {
        // Split into filename/directory
        let (filename, dir) = open_list.pop().unwrap();

        // Try to find PDB
        let full_path = dir.join(&filename);
        let pdb_path = full_path.with_extension("pdb");
        let pdb_metadata = std::fs::metadata(&pdb_path);
        if let Ok(meta) = pdb_metadata {
            if meta.is_file() {
                pdbs.push(pdb_path);
            }
        }

        // Get list of dependencies
        if let Ok(deps) = get_dependencies(&filename, &dir) {
            for dep in deps {
                let inserted = closed_list.insert(dep.clone());
                if inserted {
                    // Add new deps to open list
                    open_list.push((dep, dir.clone()));
                }
            }
        }
    }

    Ok(pdbs)
}

fn get_source_files(pdb: &PathBuf) -> anyhow::Result<Vec<PathBuf>> {
    let mut result: Vec<PathBuf> = Default::default();

    // Open PDB
    let pdbfile = std::fs::File::open(&pdb)?;
    let mut pdb = pdb::PDB::open(pdbfile)?;
    let string_table = pdb.string_table()?;

    // Iterate PDB modules
    let di = pdb.debug_information()?;
    let mut modules = di.modules()?;
    while let Some(module) = modules.next()? {
        if let Some(module_info) = pdb.module_info(&module)? {
            let line_program = module_info.line_program()?;

            // Iterate files
            let mut file_iter = line_program.files();
            while let Some(file) = file_iter.next()? {
                // Construct file path
                let raw_filepath = string_table.get(file.name)?;
                let filename_utf8 = std::str::from_utf8(raw_filepath.as_bytes())?;
                let filepath = PathBuf::from(filename_utf8);

                // Verify file exists on disk
                //                let roots: Vec<PathBuf> = vec!["C:/ue511/UE_5.1".into()];

                if false {
                    let file_meta = std::fs::metadata(&filepath);
                    if let Ok(meta) = file_meta {
                        if meta.is_file() {
                            result.push(filepath);
                        }
                    }
                } else {
                    result.push(filepath);
                }
            }
        }
    }

    Ok(result)
}

fn split_filepath(path: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    let filename = path
        .file_name()
        .ok_or_else(|| anyhow!("Couldn't get filename from {:?}", path))?;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("Couldn't get parent from {:?}", path))?;

    Ok((filename.into(), dir.into()))
}

fn get_dependencies(filename: &Path, dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut result: Vec<PathBuf> = Default::default();

    let name: &std::ffi::OsStr = filename.as_os_str();
    let dir: &std::ffi::OsStr = dir.as_os_str();

    let c_name = path_to_cstring(&name).unwrap();
    let c_path = path_to_cstring(&dir).unwrap();

    let name = windows::core::PCSTR(c_name.as_ptr() as *const u8);
    let path = windows::core::PCSTR(c_path.as_ptr() as *const u8);

    unsafe {
        let image = WinDbg::ImageLoad(name, path);
        if image.is_null() {
            anyhow::bail!("Could not load image {:?}{:?}", path, name);
        }

        let file_header = (*image).FileHeader;
        let optional_header = &(*file_header).OptionalHeader;
        let mapped_address = (*image).MappedAddress;
        if optional_header.NumberOfRvaAndSizes >= 2 {
            let virtual_address = optional_header.DataDirectory[1].VirtualAddress;
            let mut import_desc = get_ptr_from_virtual_address(virtual_address, file_header, mapped_address)
                as *const WinSys::IMAGE_IMPORT_DESCRIPTOR;

            loop {
                if (*import_desc).TimeDateStamp == 0 && (*import_desc).Name == 0 {
                    break;
                }

                let name_ptr =
                    get_ptr_from_virtual_address((*import_desc).Name, file_header, mapped_address) as *const i8;

                let name = std::ffi::CStr::from_ptr(name_ptr).to_str()?;
                result.push(name.into());
                import_desc = import_desc.offset(1);
            }
        }
    }

    Ok(result)
}

unsafe fn get_ptr_from_virtual_address(
    addr: u32,
    image_header: *const WinDbg::IMAGE_NT_HEADERS64,
    mapped_address: *const u8,
) -> *const c_void {
    let section_header = get_enclosing_section_header(addr, image_header);
    if section_header == std::ptr::null() {
        return std::ptr::null();
    }

    let delta = (*section_header).VirtualAddress - (*section_header).PointerToRawData;
    let offset = (addr - delta) as isize;
    mapped_address.offset(offset) as *const c_void
}

unsafe fn get_enclosing_section_header(
    addr: u32,
    image_header: *const WinDbg::IMAGE_NT_HEADERS64,
) -> *const WinDbg::IMAGE_SECTION_HEADER {
    // Not sure how do replicate this macro in rust
    // so offset is hardcoded
    //#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    //    ((ULONG_PTR)(ntheader) +                                            \
    //     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
    //     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    //    ))
    const OFFSET: isize = 264; // computed in C++ via

    let sections: *const WinDbg::IMAGE_SECTION_HEADER = cast_ptr(image_header, OFFSET);

    let num_sections = (*image_header).FileHeader.NumberOfSections as isize;
    for idx in 0..num_sections {
        let section = sections.offset(idx);

        let start = (*section).VirtualAddress;
        let end = start + (*section).Misc.VirtualSize;
        if addr >= start && addr < end {
            return section;
        }
    }

    std::ptr::null()
}

unsafe fn cast_ptr<T, U>(ptr: *const T, offset: isize) -> *const U {
    let void_ptr = ptr as *mut std::ffi::c_void; // Cast to void pointer
    let offset_ptr = void_ptr.offset(offset); // Offset by a certain number of bytes
    offset_ptr as *mut U // Cast to desired type
}

fn path_to_cstring(path: &std::ffi::OsStr) -> Option<CString> {
    let path_str = path.to_string_lossy();
    let bytes = path_str.as_bytes();
    let mut null_terminated = Vec::with_capacity(bytes.len() + 1);
    null_terminated.extend_from_slice(bytes);
    CString::new(null_terminated).ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn do_stuff() {}
}
