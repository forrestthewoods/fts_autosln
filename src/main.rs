// use std::ffi::CString;
// use std::ptr::null_mut;
// use winapi::ctypes::c_void;
// use winapi::shared::minwindef::{DWORD, HINSTANCE, LPVOID};
// use winapi::um::handleapi::CloseHandle;
// use winapi::um::libloaderapi::{FreeLibrary, GetModuleHandleA, LoadLibraryExA};
// use winapi::um::memoryapi::UnmapViewOfFile;
// use winapi::um::processthreadsapi::GetCurrentProcess;
// use winapi::um::sysinfoapi::GetModuleInformation;
// use winapi::um::winnt::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, MEM_RELEASE, PAGE_READONLY};
// use std::ffi::CString;
// use winapi::ctypes::c_char;
use windows::{core::*};

fn main() {
    // let path = "C:/ue511/UE_5.1/Engine/Binaries/Win64/UnrealEditor-Core.dll";

    // let c_path = CString::new(path).expect("Failed to create CString");
    // let lpcstr = c_path.as_ptr() as *const c_char;
    // let mut exeHandle : HINSTANCE;

    // //let test : winapi::um::win
    // unsafe {
    //     let test = winapi::um::winuser::LoadImageA(
    //         &mut exeHandle, 
    //         lpcstr, type_, cx, cy, fuLoad)
    // }

    let name = s!("UnrealEditor.exe");
    let path = s!("C:/ue511/UE_5.1/Engine/Binaries/Win64");

    unsafe {
        let handle = windows::Win32::System::Diagnostics::Debug::ImageLoad(name, path);
        println!("{:?}", handle);
    }

    println!("hello world");
}
