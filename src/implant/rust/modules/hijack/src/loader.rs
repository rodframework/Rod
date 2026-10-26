//! The loader's order, as the module's platform surface -- the search
//! the operating system runs when a binary loads a DLL: the
//! application's own directory first, then System32 -- and the
//! KnownDLLs list standing before both, taking its members straight
//! from System32 no matter what sits beside the binary. The checks
//! that order needs (a file's presence, the system directory's real
//! path, the KnownDLLs names) and the file operations the seat itself
//! needs (copy, delete) are spoken through kernel32 and advapi32
//! directly -- a module owes the loader no dependency for any of it.
//! Everything that must hold for a test (the seat-path arithmetic,
//! the row renderings) is a plain function this host runs anywhere;
//! only the calls sit behind `cfg(windows)`, and the Windows crosses
//! the CI lane builds prove they compile.

/// Where the planted file for a seat lands: the binary's own
/// directory, joined to the imported name. A binary with no directory
/// cannot name a seat -- the loader's first search stop is exactly
/// that directory.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn seat_path(binary: &str, dll: &str) -> Option<String> {
    let directory = binary.rsplit_once('\\')?.0;
    Some(format!(r"{directory}\{dll}"))
}

/// The row a listed slot renders: the DLL's name and where it stands
/// in the loader's order, so the operator reads what a plant would do
/// -- shadow a copy the system also carries, or supply one it does
/// not.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn slot_row(dll: &str, in_system32: bool) -> String {
    if in_system32 {
        format!("{dll}: system32 carries it; the binary's directory still loads first")
    } else {
        format!("{dll}: absent everywhere the loader looks")
    }
}

/// The Win32 error codes the actions can meet, as the messages the
/// operator reads. A code outside the table stands as its number --
/// never a guess at what the site's file system meant by it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn status_message(status: i32) -> String {
    match status {
        2 => "the file does not exist".to_string(),
        3 => "the path is a directory, not a file".to_string(),
        5 => "access denied (the directory or the file needs privileges the implant lacks)"
            .to_string(),
        80 => "the file already exists".to_string(),
        other => format!("file error {other}"),
    }
}

// ---- the Windows calls ----

#[cfg(windows)]
mod win {
    type Hkey = isize;
    type Lstatus = i32;

    const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002usize as isize;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const ERROR_SUCCESS: Lstatus = 0;
    const ERROR_NO_MORE_ITEMS: Lstatus = 259;
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileAttributesW(filename: *const u16) -> u32;
        fn CopyFileW(existing: *const u16, new: *const u16, failIfExists: i32) -> i32;
        fn DeleteFileW(filename: *const u16) -> i32;
        fn GetLastError() -> u32;
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hkey: Hkey,
            lpsubkey: *const u16,
            reserved: u32,
            samdesired: u32,
            phkresult: *mut Hkey,
        ) -> Lstatus;
        fn RegEnumValueW(
            hkey: Hkey,
            dwindex: u32,
            lpvaluename: *mut u16,
            lpcchvaluename: *mut u32,
            lpreserved: *const u32,
            lptype: *mut u32,
            lpdata: *mut u8,
            lpcbdata: *mut u32,
        ) -> Lstatus;
        fn RegCloseKey(hkey: Hkey) -> Lstatus;
    }

    /// A NUL-terminated UTF-16 string, the encoding every `*W` entry
    /// point takes.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Whether a path names something that exists. A directory
    /// counts: the loader would not read a directory as a DLL, but
    /// the caller's question is whether the name is taken.
    pub(crate) fn file_exists(path: &str) -> bool {
        unsafe { GetFileAttributesW(wide(path).as_ptr()) != INVALID_FILE_ATTRIBUTES }
    }

    /// Copies the source into the seat, refusing to overwrite: a file
    /// already on the seat may be a real dependency some other seat
    /// planted, and replacing it is the operator's explicit remove,
    /// made first.
    pub(crate) fn copy_file(source: &str, seat: &str) -> Result<(), i32> {
        unsafe {
            let ok = CopyFileW(wide(source).as_ptr(), wide(seat).as_ptr(), 1);
            (ok != 0).then_some(()).ok_or(GetLastError() as i32)
        }
    }

    /// Deletes the planted file.
    pub(crate) fn delete_file(seat: &str) -> Result<(), i32> {
        unsafe {
            let ok = DeleteFileW(wide(seat).as_ptr());
            (ok != 0).then_some(()).ok_or(GetLastError() as i32)
        }
    }

    /// The system directory's real path, where the loader looks
    /// second.
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

    /// The KnownDLLs names, as the Session Manager recorded them: the
    /// DLLs the loader takes from System32 regardless of what sits
    /// beside a binary. A key that refuses reads as an empty list --
    /// the plants that list would veto are the classic system DLLs,
    /// and refusing the whole verb over a listing would strand the
    /// seats it names for open.
    pub(crate) fn known_dlls() -> Vec<String> {
        unsafe {
            let mut key: Hkey = 0;
            let subkey = wide(r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs");
            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut key,
            ) != ERROR_SUCCESS
            {
                return Vec::new();
            }

            let mut names = Vec::new();
            let mut name: Vec<u16> = vec![0; 1024];
            let mut index: u32 = 0;
            loop {
                let mut name_len = name.len() as u32;
                let status = RegEnumValueW(
                    key,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                match status {
                    ERROR_SUCCESS => {
                        names.push(String::from_utf16_lossy(&name[..name_len as usize]));
                        index += 1;
                    }
                    ERROR_NO_MORE_ITEMS => break,
                    _ => break,
                }
            }
            RegCloseKey(key);
            names
        }
    }
}

#[cfg(windows)]
pub(crate) use win::{copy_file, delete_file, file_exists, known_dlls, system_directory};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seat_lands_in_the_binarys_own_directory() {
        assert_eq!(
            seat_path(r"C:\app\app.exe", "VERSION.DLL"),
            Some(r"C:\app\VERSION.DLL".to_string())
        );
        // A directory itself names a seat beside it, the same way the
        // loader resolves the binary's directory.
        assert_eq!(
            seat_path(r"C:\app\tools\run.exe", "d3d11.dll"),
            Some(r"C:\app\tools\d3d11.dll".to_string())
        );
        // No directory, no seat: the loader's first stop cannot be
        // named from a bare file name.
        assert_eq!(seat_path("app.exe", "VERSION.DLL"), None);
    }

    #[test]
    fn the_slot_rows_say_what_a_plant_would_do() {
        assert!(
            slot_row("VERSION.DLL", true).contains("loads first"),
            "{}",
            slot_row("VERSION.DLL", true)
        );
        assert!(
            slot_row("d3d11.dll", false).contains("absent everywhere"),
            "{}",
            slot_row("d3d11.dll", false)
        );
    }

    #[test]
    fn the_status_table_names_the_codes_operators_meet() {
        assert_eq!(status_message(2), "the file does not exist");
        assert!(
            status_message(5).contains("access denied"),
            "{}",
            status_message(5)
        );
        assert_eq!(status_message(80), "the file already exists");
        // An untabled code keeps its number -- never a guessed cause.
        assert_eq!(status_message(123), "file error 123");
    }
}
