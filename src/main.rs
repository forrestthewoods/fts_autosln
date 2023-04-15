use anyhow::anyhow;
use std::ffi::{CStr, CString, c_void};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows::core::*;

use windows::Win32::System::Diagnostics::Debug as WinDbg;
use windows_sys::Win32::System::SystemServices as WinSys;

fn main() {
    println!("hello world");
    hacky_tests();
    println!("goodbye cruel worl");
}

fn find_all_pdbs(target: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let filename = target.file_name().ok_or_else(|| anyhow!("Couldn't get filename from {:?}", target))?;
    let dir = target.parent().ok_or_else(|| anyhow!("Couldn't get parent from {:?}", target))?;
    
    //let test = s!(filename);

    Ok(Default::default())
}



fn hacky_tests() {
    //let name1 = s!("UnrealEditor.exe");
    //let path1 = s!("C:/ue511/UE_5.1/Engine/Binaries/Win64");

    let path = PathBuf::from("C:/ue511/UE_5.1/Engine/Binaries/Win64/UnrealEditor.exe");
    let name : &std::ffi::OsStr = path.file_name().unwrap();
    let dir : &std::ffi::OsStr = path.parent().unwrap().as_os_str();

    let c_name = path_to_cstring(&name).unwrap();
    let c_path = path_to_cstring(&dir).unwrap();

    let name = windows::core::PCSTR(c_name.as_ptr() as *const u8);
    let path = windows::core::PCSTR(c_path.as_ptr() as *const u8);

    unsafe {
        let image = WinDbg::ImageLoad(name, path);
        //let image = WinDbg::ImageLoad(c_name.as_ptr(), c_path.as_ptr());
        println!("{:?}", image);
        let file_header = (*image).FileHeader;
        let optional_header = &(*file_header).OptionalHeader;
        let mapped_address = (*image).MappedAddress;
        if optional_header.NumberOfRvaAndSizes >= 2 {
            //let import_desc = windows::Win32::System::Diagnostics::Debug::GetPointer
            let virtual_address = optional_header.DataDirectory[1].VirtualAddress;
            
            let mut import_desc = get_ptr_from_virtual_address(
                virtual_address,
                file_header,
                mapped_address) as *const WinSys::IMAGE_IMPORT_DESCRIPTOR;

            println!("ImportDesc: {:?}", import_desc);

            loop {
                if (*import_desc).TimeDateStamp == 0 && (*import_desc).Name == 0 {
                    break;
                }

                let name_ptr = get_ptr_from_virtual_address(
                    (*import_desc).Name,
                    file_header,
                    mapped_address) as * const i8;

                let name = std::ffi::CStr::from_ptr(name_ptr).to_str();
                println!("Will this explode? {:?}", name);
                import_desc = import_desc.offset(1);
            }
        }
    }
}

unsafe fn get_ptr_from_virtual_address(
    addr: u32, 
    image_header: * const WinDbg::IMAGE_NT_HEADERS64,
    mapped_address: * const u8) -> * const c_void
{
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
    image_header: * const WinDbg::IMAGE_NT_HEADERS64) 
-> * const WinDbg::IMAGE_SECTION_HEADER 
{
    // Not sure how do replicate this macro in rust
    // so offset is hardcoded
    //#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    //    ((ULONG_PTR)(ntheader) +                                            \
    //     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
    //     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    //    ))
    const OFFSET : isize = 264; // computed in C++ via

    let sections : * const WinDbg::IMAGE_SECTION_HEADER = cast_ptr(image_header, OFFSET);

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