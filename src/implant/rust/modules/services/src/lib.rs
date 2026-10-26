//! The persistence family's second module (architecture.md Sec 5.4):
//! `persist.services`, the Windows service seat -- one discrete
//! installable and removable technique, the pairing todo.md's family
//! criterion turns on: the verb that installs a seat is the verb that
//! removes it, and both ride the task audit every dispatched action
//! already enters.
//!
//! The grammar gives one verb three actions -- `install` creates the
//! service record with its binary path, `remove` marks it for
//! deletion, `list` reports the seats the database carries (the
//! default: a bare task is a read). Every write needs the
//! administrator's access the SCM demands, and the module's refusals
//! say so rather than leaving the elevation fact to be discovered. The
//! seat is one record in the SCM database with its command line as
//! plain text, Windows logs its installation as Event 7045, and it
//! runs at every boot while it sits -- the manifest says all of this
//! rather than leaving it to be found out.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load services` task's content, then task `persist.services`
//! like any compiled verb. A non-Windows build compiles for the lane
//! and refuses the verb at run time: the technique has no seat to
//! touch there.

mod arguments;
mod scm;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

// The action the Windows dispatch matches on; off Windows the verb
// refuses before the name is ever spoken, and an unused import would be
// a build warning the lane turns into a failure.
#[cfg(windows)]
use arguments::Action;

pub struct Services;

impl Plugin for Services {
    fn name(&self) -> &'static str {
        "services"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("persist.services", services)]
    }
}

fn services(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    arguments::validate(&arguments)?;
    execute(&arguments)
}

/// The Windows execution: the action the task named against the
/// service database.
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
        "persist.services: service seats are a Windows technique; this \
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
    // An existing service of the same name is the manager's own
    // refusal (a service with that name already exists), not this
    // module's silent retarget: over a live seat is the operator's
    // explicit remove, made first.
    match scm::create(name, command) {
        Ok(()) => Ok(format!("installed {name} = {command} (auto-start at boot)")),
        Err(status) => Err(format!(
            "persist.services: {name}: {}",
            scm::status_message(status)
        )),
    }
}

#[cfg(windows)]
fn remove(arguments: &Arguments) -> Result<String, String> {
    let name = arguments.name.as_deref().unwrap_or_default();
    // Deletion is the manager's mark, not an act: the answer says when
    // the seat was running, because the record outlives the call until
    // that service stops.
    match scm::delete(name) {
        Ok(was_running) => Ok(if was_running {
            format!("removed {name} (it was running -- the delete completes when it stops)")
        } else {
            format!("removed {name}")
        }),
        Err(status) => Err(format!(
            "persist.services: {name}: {}",
            scm::status_message(status)
        )),
    }
}

/// The read: every WIN32 service the database carries, sorted by name
/// so two reads of one host report in the same order. A name riding
/// the task narrows the report to that seat -- the confirmation half
/// of an install the operator just ran.
#[cfg(windows)]
fn list(arguments: &Arguments) -> Result<String, String> {
    match scm::enumerate() {
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
                .map(|seat| format!("{} = {}", seat.name, seat.rest))
                .collect();
            Ok(if rows.is_empty() {
                match arguments.name.as_deref() {
                    Some(wanted) => format!("no service named '{wanted}'"),
                    None => "no services in the local database".to_string(),
                }
            } else {
                rows.join("\n")
            })
        }
        Err(status) => Err(format!("persist.services: {}", scm::status_message(status))),
    }
}

rod_plugin!(Services);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_task_is_the_read() {
        // The default action is list: a bare task reports and writes
        // nothing -- on a non-Windows build it refuses, naming why.
        #[cfg(windows)]
        {
            let output = services("").expect("the read runs");
            assert!(output.contains('='), "{output}");
        }
        #[cfg(not(windows))]
        {
            let refusal = services("").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }

    #[test]
    fn a_bad_grammar_refuses_before_anything_runs() {
        assert!(services("uninstall UpdateCheck").is_err());
        assert!(services("install UpdateCheck").is_err());
        assert!(services("remove UpdateCheck cmd /c x").is_err());
        assert!(services("list UpdateCheck cmd /c x").is_err());
    }
}
