use core::str;
use injection::open_process;
use std::{env, process::Command, thread, time::Duration};

mod injection;

fn find_target_process() -> Option<u32> {
    // Use tasklist instead of Windows API to get pid, to avoid being detected as virus.
    // This approach avoids calling process enumeration APIs that trigger AV heuristics.
    let output = Command::new("tasklist")
        .args(["/fo", "csv", "/nh"])
        .output()
        .ok()?;

    let mut pids: Vec<u32> = Vec::new();
    for line in output.stdout.split(|x| *x == b'\n' || *x == b'\r') {
        for prefix in [b"\"th123.exe\",".as_slice(), b"th123.exe,".as_slice()] {
            if line.starts_with(prefix) {
                let rest = &line[prefix.len()..];
                let stripped = if rest.first() == Some(&b'"') {
                    &rest[1..]
                } else {
                    rest
                };
                if let Some(pid_str) = stripped.split(|x| !x.is_ascii_digit()).next() {
                    if let Ok(pid_s) = str::from_utf8(pid_str) {
                        if let Ok(pid) = pid_s.parse::<u32>() {
                            pids.push(pid);
                        }
                    }
                }
            }
        }
    }

    match pids.len() {
        0 => {
            eprintln!("Cannot find th123.exe process!");
            None
        }
        1 => Some(pids[0]),
        n => {
            eprintln!(
                "Found {} th123.exe processes. Please use SWRSToys instead.",
                n
            );
            None
        }
    }
}

fn load_mod() -> Result<(), String> {
    println!("Giuroll Loader - Searching for Hisoutensoku...");

    let pid = find_target_process().ok_or("Target process not found")?;
    println!("Found th123.exe (PID: {})", pid);

    // Small delay to appear more like normal user-initiated action
    thread::sleep(Duration::from_millis(100));

    let process = unsafe { open_process(pid) }
        .map_err(|e| format!("Failed to open process {}: {}", pid, e))?;

    let path = env::current_dir()
        .map_err(|e| format!("Failed to get current directory: {}", e))?;

    let dll_path = path.join("giuroll_loader_dll.dll");
    let dll_path_str = dll_path
        .to_str()
        .ok_or("Failed to convert path to string")?;

    unsafe { injection::inject_dll(process, dll_path_str) }
        .map_err(|e| format!("Failed to inject DLL: {}", e))?;

    println!("Successfully loaded giuroll_loader_dll.dll into process {}", pid);
    Ok(())
}

fn main() {
    match load_mod() {
        Ok(()) => {
            println!("The loader will exit in 10 seconds.");
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
    thread::sleep(Duration::from_secs(10));
}
