use anyhow::anyhow;
use pdb::*;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::ffi::{c_void, CString};
use std::path::{Path, PathBuf};

use windows::Win32::System::Diagnostics::Debug as WinDbg;
use windows_sys::Win32::System::SystemServices as WinSys;

fn main() -> anyhow::Result<()> {
    println!("hello world");
    let start = std::time::Instant::now();

    // Define target
    let test_target = "C:/ue511/UE_5.1/Engine/Binaries/Win64/UnrealEditor.exe";
    //let test_target = "C:/source_control/fts_autosln/target/debug/deps/fts_autosln.exe";
    //let test_target = "C:/temp/cpp/autosln_tests/x64/Debug/autosln_tests.exe";

    // Get PDBs for target
    let pdbs = find_all_pdbs(&PathBuf::from(test_target))?;

    // Get filepaths from PDBs
    let source_files: HashSet<PathBuf> = pdbs
        .par_iter()
        .flat_map(|pdb| get_source_files(&pdb).unwrap_or_default())
        .collect();

    let file_exists = |path: &Path| {
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
    };

    let user_roots: Vec<PathBuf> = vec!["C:/ue511/UE_5.1/".into()];
    let mut known_maps: HashMap<PathBuf,PathBuf> = Default::default();

    // Find local files
    let local_files: Vec<PathBuf> = source_files
        //.into_par_iter()
        .into_iter()
        .filter_map(|file| {
            if file_exists(&file) {
                return Some(file);
            } else {
                // See if a known map applies 
                for (src, dst) in &known_maps {
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

                    for user_root in &user_roots {
                        let maybe_filepath = user_root.join(&relpath);
                        //println!("    {:?}", maybe_filepath);
                        if file_exists(&maybe_filepath) {
                            // create a new known map
                            let pdb_path : PathBuf = components.iter().take(idx as usize).collect();
                            //println!("inserting {:?}, {:?}", pdb_path, user_root);
                            known_maps.insert(pdb_path, user_root.to_owned());

                            return Some(maybe_filepath);
                        }
                    }

                    idx -= 1;
                }

                None
            }
        })
        .collect();

    // for local_file in local_files.iter().sorted() {
    //     println!("localfile: {:?}", local_file);
    // }


    let end = std::time::Instant::now();
    println!("Elapsed Milliseconds: {}", (end - start).as_millis());
    println!("goodbye cruel world");

    Ok(())
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
    fn do_stuff() {}
}
