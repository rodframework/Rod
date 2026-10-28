//! The conformance fixture plugin: the exec-v1 module the harness stages
//! through module.load (extending/implants.md, Tier 2). One verb answers a
//! marker over the stdio protocol and one artifact run exercises the ABI 2
//! return -- the two clauses `plugin.load-exec-v1` and
//! `plugin.artifact-return` read.

use rod_plugin_sdk::{rod_plugin, Plugin, Verb, VerbOutput};

pub struct Conform;

impl Plugin for Conform {
    fn name(&self) -> &'static str {
        "conform"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![
            Verb::new("conform.plugin", marker),
            Verb::with_artifact("conform.artifact", artifact),
        ]
    }
}

fn marker(arguments: &str) -> Result<String, String> {
    // The marker round trip: the harness issues the verb with its own
    // marker string and reads it back in the task output.
    Ok(format!("conform:{arguments}"))
}

fn artifact(arguments: &str) -> Result<VerbOutput, String> {
    // The artifact return: the argument string rides back as the run's
    // bytes, so the harness proves byte equality through the exfil arm
    // exactly like a compiled handler's artifact.
    Ok(VerbOutput::artifact(
        "conform.bin",
        "application/octet-stream",
        arguments.as_bytes().to_vec(),
        "the conform artifact run",
    ))
}

rod_plugin!(Conform);
