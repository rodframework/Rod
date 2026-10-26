//! The Windows registry edge (the module's whole platform surface):
//! the Run key under HKCU or HKLM. The calls are advapi32's own -- a
//! module owes the loader no dependency for six functions -- with the
//! UTF-16 and error-code handling this file owns once, so the verb's
//! dispatch stays pure grammar. Everything that must hold for a test
//! (paths, messages, the LSTATUS table) is a plain function this host
//! runs anywhere; only the calls themselves sit behind `cfg(windows)`,
//! and the Windows crosses the CI lane builds prove they compile.

use crate::arguments::Hive;

/// The one key the module addresses: the classic Run seat, executed at
/// every interactive logon. RunOnce and the startup folder are the
/// family's later widening, not this module's v1.0 surface.
// The pure half below compiles everywhere so its tests run on any host;
// off Windows the library target itself never calls it, and the lane's
// warnings-are-errors would otherwise fail the host build.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const RUN_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg_attr(not(windows), allow(dead_code))]
impl Hive {
    /// The display name every row and message prints: the registry's
    /// own abbreviation, what an operator reads on a Windows host.
    pub(crate) fn display(self) -> &'static str {
        match self {
            Hive::Hkcu => "HKCU",
            Hive::Hklm => "HKLM",
        }
    }

    /// The full seat path a row names: `HKCU\Software\...\Run`.
    pub(crate) fn seat_path(self) -> String {
        format!(r"{}\{}", self.display(), RUN_PATH)
    }
}

/// The LSTATUS codes the three actions can meet, as the messages the
/// operator reads. A code outside the table stands as its number --
/// never a guess at what the site's registry meant by it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn status_message(status: i32) -> String {
    match status {
        2 => "the value does not exist".to_string(),
        5 => "access denied (HKLM seats need an elevated implant)".to_string(),
        other => format!("registry error {other}"),
    }
}

// ---- the Windows calls ----

#[cfg(windows)]
mod win {
    use super::{Hive, RUN_PATH};

    use std::os::raw::c_void;

    /// One listed seat: the value's name and the command line it
    /// carries, as read -- a REG_EXPAND_SZ stays unexpanded, because
    /// expanding it is the operating system's job at logon, not the
    /// reader's guess.
    pub(crate) struct Seat {
        pub name: String,
        pub command: String,
    }

    // The registry's own types: an HKEY handle, the predefined roots'
    // constants, and the access and option masks the three calls use.
    type Hkey = isize;
    type Lstatus = i32;

    const HKEY_CURRENT_USER: Hkey = 0x8000_0001usize as isize;
    const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002usize as isize;

    const ERROR_SUCCESS: Lstatus = 0;
    const ERROR_FILE_NOT_FOUND: Lstatus = 2;
    const ERROR_NO_MORE_ITEMS: Lstatus = 259;

    const REG_OPTION_NON_VOLATILE: u32 = 0;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegCreateKeyExW(
            hkey: Hkey,
            lpsubkey: *const u16,
            reserved: u32,
            lpclass: *const u16,
            dwoptions: u32,
            samdesired: u32,
            lpsecurityattributes: *const c_void,
            phkresult: *mut Hkey,
            lpdwdisposition: *mut u32,
        ) -> Lstatus;
        fn RegSetValueExW(
            hkey: Hkey,
            lpvaluename: *const u16,
            reserved: u32,
            dwtype: u32,
            lpdata: *const u8,
            cbdata: u32,
        ) -> Lstatus;
        fn RegOpenKeyExW(
            hkey: Hkey,
            lpsubkey: *const u16,
            uloptions: u32,
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
        fn RegDeleteValueW(hkey: Hkey, lpvaluename: *const u16) -> Lstatus;
        fn RegCloseKey(hkey: Hkey) -> Lstatus;
    }

    /// A NUL-terminated UTF-16 string, the encoding every `*W` entry
    /// point takes.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    impl Hive {
        pub(crate) fn root(self) -> Hkey {
            match self {
                Hive::Hkcu => HKEY_CURRENT_USER,
                Hive::Hklm => HKEY_LOCAL_MACHINE,
            }
        }
    }

    pub(crate) fn write(hive: Hive, name: &str, command: &str) -> Result<(), i32> {
        // REG_SZ bytes: the command as UTF-16 with its terminating NUL
        // -- the encoding the logon reader expects of the value.
        let value: Vec<u8> = command
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        unsafe {
            let mut key: Hkey = 0;
            let subkey = wide(RUN_PATH);
            let status = RegCreateKeyExW(
                hive.root(),
                subkey.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            );
            if status != ERROR_SUCCESS {
                return Err(status);
            }
            let valuename = wide(name);
            let status = RegSetValueExW(
                key,
                valuename.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr(),
                value.len() as u32,
            );
            RegCloseKey(key);
            (status == ERROR_SUCCESS).then_some(()).ok_or(status)
        }
    }

    pub(crate) fn delete(hive: Hive, name: &str) -> Result<(), i32> {
        unsafe {
            let mut key: Hkey = 0;
            let subkey = wide(RUN_PATH);
            let status = RegOpenKeyExW(hive.root(), subkey.as_ptr(), 0, KEY_SET_VALUE, &mut key);
            if status != ERROR_SUCCESS {
                return Err(status);
            }
            let valuename = wide(name);
            let status = RegDeleteValueW(key, valuename.as_ptr());
            RegCloseKey(key);
            (status == ERROR_SUCCESS).then_some(()).ok_or(status)
        }
    }

    /// Every seat under the hive's Run key. A missing key is an empty
    /// report, not a failure: no key is no seats, and the verb's list
    /// says so in its own words.
    pub(crate) fn enumerate(hive: Hive) -> Result<Vec<Seat>, i32> {
        unsafe {
            let mut key: Hkey = 0;
            let subkey = wide(RUN_PATH);
            let status = RegOpenKeyExW(
                hive.root(),
                subkey.as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                &mut key,
            );
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(Vec::new());
            }
            if status != ERROR_SUCCESS {
                return Err(status);
            }

            // The buffers: value names cap far below 16383 characters
            // by the API's own contract, and a command line beyond the
            // data buffer's 16 KiB is a seat this reader reports as
            // oversized rather than one it truncates.
            let mut name: Vec<u16> = vec![0; 16384];
            let mut data: Vec<u8> = vec![0; 16384];
            let mut seats = Vec::new();
            let mut index: u32 = 0;
            loop {
                let mut name_len = name.len() as u32;
                let mut data_len = data.len() as u32;
                let mut value_type: u32 = 0;
                let status = RegEnumValueW(
                    key,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null(),
                    &mut value_type,
                    data.as_mut_ptr(),
                    &mut data_len,
                );
                match status {
                    ERROR_SUCCESS => {
                        let seat_name = String::from_utf16_lossy(&name[..name_len as usize]);
                        seats.push(Seat {
                            name: seat_name,
                            command: value_text(value_type, &data[..data_len as usize]),
                        });
                        index += 1;
                    }
                    ERROR_NO_MORE_ITEMS => break,
                    _ => {
                        // A value too large for the buffer re-reads into
                        // one its own size; a value still refusing stands
                        // as its error, named, not skipped in silence.
                        if data_len as usize > data.len() && data_len <= 1 << 20 {
                            data.resize(data_len as usize, 0);
                            continue;
                        }
                        RegCloseKey(key);
                        return Err(status);
                    }
                }
            }
            RegCloseKey(key);
            Ok(seats)
        }
    }

    /// A value's data as the row prints it: the string kinds decode
    /// from their UTF-16 up to the NUL, anything else says what it is
    /// instead of guessing characters out of binary.
    fn value_text(value_type: u32, data: &[u8]) -> String {
        if !matches!(value_type, REG_SZ | REG_EXPAND_SZ) {
            return format!("(value of type {value_type})");
        }
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|&unit| unit != 0)
            .collect();
        String::from_utf16_lossy(&units)
    }
}

#[cfg(windows)]
pub(crate) use win::{delete, enumerate, write};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seat_path_names_hive_and_key() {
        assert_eq!(
            Hive::Hkcu.seat_path(),
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        );
        assert_eq!(
            Hive::Hklm.seat_path(),
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        );
    }

    #[test]
    fn the_status_table_names_the_two_codes_operators_meet() {
        assert_eq!(status_message(2), "the value does not exist");
        assert!(
            status_message(5).contains("elevated"),
            "{}",
            status_message(5)
        );
        // An untabled code keeps its number -- never a guessed cause.
        assert_eq!(status_message(1010), "registry error 1010");
    }
}
