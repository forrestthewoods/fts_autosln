use anyhow::anyhow;
use itertools::*;
use pdb::*;
use std::collections::HashSet;
use std::ffi::{c_void, CString};
use std::os::windows::prelude::OsStrExt;
use std::path::{Path, PathBuf};

use windows::Win32::System::Diagnostics::Debug as WinDbg;
use windows_sys::Win32::System::SystemServices as WinSys;

fn main() {
    println!("hello world");

    // Define target
    let test_target = "C:/ue511/UE_5.1/Engine/Binaries/Win64/UnrealEditor.exe";
    //let test_target = "C:/source_control/fts_autosln/target/debug/deps/fts_autosln.exe";
    //let test_target = "C:/temp/cpp/autosln_tests/x64/Debug/autosln_tests.exe";

    // Get PDBs for target
    let pdbs = find_all_pdbs(&PathBuf::from(test_target));

    // Get filepaths from PDBs
    let mut source_files: HashSet<PathBuf> = Default::default();
    if let Ok(pdbs) = pdbs {
        for pdb in pdbs {
            if let Ok(pdb_files) = get_source_files(&pdb) {
                source_files.extend(pdb_files);
            }
        }
    }

    let sorted_files: Vec<_> = source_files.iter().sorted().collect();
    for file in &sorted_files {
        println!("{:?}", file);
    }

    // Get roots from list of filepaths
    for root in find_roots(sorted_files.iter().map(|b| *b)) {
        println!("Root: {:?}", root);
    }

    println!("goodbye cruel world");
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
                println!("pdb: {:?}", pdb_path);
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
            //let import_desc = windows::Win32::System::Diagnostics::Debug::GetPointer
            let virtual_address = optional_header.DataDirectory[1].VirtualAddress;

            let mut import_desc =
                get_ptr_from_virtual_address(virtual_address, file_header, mapped_address)
                    as *const WinSys::IMAGE_IMPORT_DESCRIPTOR;

            loop {
                if (*import_desc).TimeDateStamp == 0 && (*import_desc).Name == 0 {
                    break;
                }

                let name_ptr =
                    get_ptr_from_virtual_address((*import_desc).Name, file_header, mapped_address)
                        as *const i8;

                let name = std::ffi::CStr::from_ptr(name_ptr).to_str()?;
                result.push(name.into());
                import_desc = import_desc.offset(1);
            }
        }
    }

    Ok(result)
}

fn find_roots<'a, I: Iterator<Item = &'a PathBuf>>(paths: I) -> Vec<PathBuf> {
    // bool is if its been "shortened" at least once
    let mut maybe_roots: Vec<(PathBuf, bool)> = Default::default();

    // Iterate all paths
    for path in paths {
        // Lowercase
        let path : PathBuf = path.as_os_str().to_ascii_lowercase().into();

        // iterate all roots
        let mut any_matches = false;
        for i in 0..maybe_roots.len() {
            let maybe_root = &maybe_roots[i].0;

            // Count how many leading characters are the same
            let matching_part: PathBuf = path
                .components()
                .zip(maybe_root.components())
                .take_while(|(a, b)| a == b)
                .map(|(a, _)| a)
                .collect();

            // Do nothing if matching part is already root
            if matching_part == *maybe_root {
                any_matches = true;
                break;
            }

            // Ignore drive letters
            let os_str = matching_part.as_os_str();
            let matching_len = os_str.len();
            if matching_len == 3 {
                let a = os_str.encode_wide().nth(1).unwrap();
                let b = os_str.encode_wide().nth(2).unwrap();

                let sep = ":".encode_utf16().nth(0).unwrap();
                let slash_a = "\\".encode_utf16().nth(0).unwrap();
                let slash_b = "/".encode_utf16().nth(0).unwrap();
                if a == sep && (b == slash_a || b == slash_b) {
                    continue;
                }
            }

            // This matching part may be shorter
            if matching_len > 0 && matching_len < maybe_root.as_os_str().len() {
                maybe_roots[i] = (matching_part, true);
                any_matches = true;
                break;
            }
        }

        // Didn't align with anything. This is maybe a root!
        if !any_matches {
            maybe_roots.push((path.to_path_buf(), false));
        }
    }

    // Our maybe_roots are now known roots
    maybe_roots
        .into_iter()
        .filter_map(|(path, shortened)| if shortened { Some(path) } else { None })
        .collect()
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
    use super::*;

    #[test]
    fn find_roots() {
        let paths : Vec<PathBuf> = vec![
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\asio\\1.12.2\\asio\\system_context.hpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\asio\\1.12.2\\asio\\system_executor.hpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\asio\\1.12.2\\asio\\thread_pool.hpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\asio\\1.12.2\\asio\\wait_traits.hpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\asio\\1.12.2\\asio\\windows\\object_handle.hpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\asio\\1.12.2\\asio\\windows\\overlapped_handle.hpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\asio\\1.12.2\\asio\\windows\\random_access_handle.hpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\libSampleRate\\Private\\LibSampleRateModule.cpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\libSampleRate\\Private\\common.h".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\libSampleRate\\Private\\samplerate.cpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\libSampleRate\\Private\\src_linear.cpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\libSampleRate\\Private\\src_sinc.cpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\libSampleRate\\Private\\src_zoh.cpp".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\mimalloc\\include\\mimalloc-atomic.h".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\mimalloc\\include\\mimalloc-internal.h".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\mimalloc\\src\\alloc-aligned.c".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\mimalloc\\src\\alloc-posix.c".into(),
            "D:\\build\\++UE5\\Sync\\Engine\\Source\\ThirdParty\\mimalloc\\src\\alloc.c".into(),
        ];

        let roots = super::find_roots(paths.iter());
        for root in &roots {
            println!("root: {:?}", root);
        }
        assert_eq!(roots.len(), 1);
    }
}
