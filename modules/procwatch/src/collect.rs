//! The sweep itself, one implementation per platform behind a shared
//! shape: read the process table into [`Entry`] rows and let the engine
//! diff them. v1.0 ships two sweeps -- the /proc tree and the toolhelp
//! snapshot -- both cheap, neither readable as a subscription from
//! outside the process. The ETW or WMI subscription collector is the
//! later widening, dropping in behind the same diff engine; a platform
//! with no table to read answers an empty sweep and the watch reports
//! nothing rather than pretending.

use super::table::Entry;

/// The /proc sweep: every numeric directory is a process, and its stat
/// file carries the comm and the parent. The comm is a name, not a path
/// -- exactly the fact the rows carry.
#[cfg(not(windows))]
pub(crate) fn snapshot() -> Vec<Entry> {
    let mut entries = Vec::new();
    let Ok(directory) = std::fs::read_dir("/proc") else {
        return entries;
    };
    for candidate in directory.flatten() {
        let Some(pid) = candidate
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // Layout: "pid (comm) state ppid ...". The comm may itself hold
        // spaces or parentheses, so the field walk starts after the
        // last closing parenthesis, not after the first.
        let Some(rest) = stat.rsplit_once(')') else {
            continue;
        };
        let mut fields = rest.1.split_whitespace();
        let (Some(_state), Some(parent)) = (fields.next(), fields.next()) else {
            continue;
        };
        let comm = stat
            .split_once('(')
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.rsplit_once(')').map(|(name, _)| name))
            .unwrap_or_default();
        entries.push(Entry {
            pid,
            ppid: parent.parse().unwrap_or_default(),
            name: comm.to_string(),
        });
    }
    entries
}

/// The toolhelp sweep: one snapshot of the process table, walked entry
/// by entry. The snapshot is the same read Task Manager's list is; the
/// diff engine is what turns cadenced snapshots into creation rows.
#[cfg(windows)]
pub(crate) fn snapshot() -> Vec<Entry> {
    use core::ffi::c_void;

    const TH32CS_SNAPPROCESS: u32 = 0x2;
    const INVALID_HANDLE_VALUE: *mut c_void = usize::MAX as *mut c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> *mut c_void;
        fn Process32FirstW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    let mut entries = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
            return entries;
        }
        let mut row = ProcessEntry32W {
            size: std::mem::size_of::<ProcessEntry32W>() as u32,
            ..zeroed_entry()
        };
        let mut walking = Process32FirstW(snapshot, &mut row);
        while walking != 0 {
            entries.push(Entry {
                pid: row.process_id,
                ppid: row.parent_process_id,
                name: utf16_until_nul(&row.exe_file),
            });
            walking = Process32NextW(snapshot, &mut row);
        }
        CloseHandle(snapshot);
    }
    entries
}

/// One row of the toolhelp walk, the layout `Process32FirstW` fills:
/// plain data, the size naming the structure generation, the image name
/// a NUL-terminated UTF-16 tail.
#[cfg(windows)]
#[repr(C)]
struct ProcessEntry32W {
    size: u32,
    usage: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    threads: u32,
    parent_process_id: u32,
    priority_class_base: i32,
    flags: u32,
    exe_file: [u16; 260],
}

/// The zeroed snapshot row, so the exe_file tail is NUL-filled before
/// the walk fills the name.
#[cfg(windows)]
fn zeroed_entry() -> ProcessEntry32W {
    // SAFETY: ProcessEntry32W is a plain-data C struct; zero bits are a
    // valid value for every field (the walk overwrites the ones it reads,
    // and the tail stays the NUL terminator the name decode stops at).
    unsafe { std::mem::zeroed() }
}

/// Decodes a UTF-16 field up to its NUL terminator, dropping pairs that
/// are not characters rather than failing the whole row.
#[cfg(windows)]
fn utf16_until_nul(field: &[u16]) -> String {
    use std::char::decode_utf16;

    decode_utf16(field.iter().copied().take_while(|&unit| unit != 0))
        .map(|decoded| decoded.unwrap_or('\u{fffd}'))
        .collect()
}
