//! Drives the emitted shims in-process: the same extern "C" symbols the
//! implant's loader resolves, called directly. Pins the ABI constants, the
//! init/name/verb_name/run family, the allocation discipline (out strings
//! and artifact buffers die through rod_plugin_free), the artifact return
//! ABI 2 adds, and the panic fence.

use rod_plugin_sdk::{rod_plugin, Plugin, RodArtifact, RodStr, Verb, VerbOutput};

pub struct Demo;

impl Plugin for Demo {
    fn name(&self) -> &'static str {
        "demo"
    }
    fn verbs(&self) -> Vec<Verb> {
        vec![
            Verb::new("demo.echo", echo),
            Verb::new("demo.fail", fail),
            Verb::new("demo.panic", panic_handler),
            Verb::with_artifact("demo.dump", dump),
        ]
    }
}

fn echo(arguments: &str) -> Result<String, String> {
    // Touch the allocator so the test exercises module-owned memory, not
    // just borrowed slices.
    let owned = format!("echo:{arguments}");
    Ok(owned + &"-".repeat(3))
}

fn fail(_arguments: &str) -> Result<String, String> {
    Err("demo.fail: refused by the handler".into())
}

fn panic_handler(_arguments: &str) -> Result<String, String> {
    panic!("handler exploded");
}

fn dump(arguments: &str) -> Result<VerbOutput, String> {
    Ok(VerbOutput::artifact(
        "dump.bin",
        "application/octet-stream",
        arguments.as_bytes().to_vec(),
        "collected the dump",
    ))
}

rod_plugin!(Demo);

unsafe fn read(string: RodStr) -> String {
    let bytes = string.as_slice().expect("a valid RodStr").to_vec();
    rod_plugin_free(string.ptr, string.len);
    String::from_utf8(bytes).unwrap_or_default()
}

// Copies an artifact out and returns every buffer through the module's
// free, the same discipline the host loader keeps.
unsafe fn read_artifact(artifact: RodArtifact) -> Option<(String, String, Vec<u8>)> {
    if artifact.name.ptr.is_null() {
        unsafe {
            rod_plugin_free(artifact.content_type.ptr, artifact.content_type.len);
            rod_plugin_free(artifact.data.ptr, artifact.data.len);
        }
        return None;
    }
    let name = unsafe { read(artifact.name) };
    let content_type = unsafe { read(artifact.content_type) };
    let bytes = unsafe { artifact.data.as_slice().expect("a valid RodStr") }.to_vec();
    unsafe { rod_plugin_free(artifact.data.ptr, artifact.data.len) };
    Some((name, content_type, bytes))
}

#[test]
fn the_shim_family_speaks_the_documented_abi() {
    assert_eq!(unsafe { rod_plugin_abi() }, rod_plugin_sdk::ABI_VERSION);
    let count = unsafe { rod_plugin_init() };
    assert_eq!(count, 4);
    assert_eq!(unsafe { read(rod_plugin_name()) }, "demo");
    assert_eq!(unsafe { read(rod_plugin_verb_name(0)) }, "demo.echo");
    assert_eq!(unsafe { read(rod_plugin_verb_name(3)) }, "demo.dump");
    // An out-of-range index is the empty string, not a crash.
    assert_eq!(unsafe { read(rod_plugin_verb_name(99)) }, "");
}

#[test]
fn run_carries_strings_both_ways() {
    unsafe { rod_plugin_init() };
    let mut out = RodStr::empty();
    let mut artifact = RodArtifact::none();
    let status =
        unsafe { rod_plugin_run(0, RodStr::from_slice(b"payload"), &mut out, &mut artifact) };
    assert_eq!(status, 0);
    assert_eq!(unsafe { read(out) }, "echo:payload---");
    assert!(unsafe { read_artifact(artifact) }.is_none());
    // A bad index is a shim error with the empty out string.
    let mut none = RodStr::empty();
    let mut no_artifact = RodArtifact::none();
    let status = unsafe {
        rod_plugin_run(
            42,
            RodStr::from_slice(b"payload"),
            &mut none,
            &mut no_artifact,
        )
    };
    assert_eq!(status, -1);
    assert_eq!(none.len, 0);
    assert!(no_artifact.name.ptr.is_null());
}

#[test]
fn artifact_runs_cross_the_boundary_named_and_typed() {
    unsafe { rod_plugin_init() };
    let mut out = RodStr::empty();
    let mut artifact = RodArtifact::none();
    let status =
        unsafe { rod_plugin_run(3, RodStr::from_slice(b"PAYLOAD"), &mut out, &mut artifact) };
    assert_eq!(status, 0);
    assert_eq!(unsafe { read(out) }, "collected the dump");
    let Some((name, content_type, bytes)) = (unsafe { read_artifact(artifact) }) else {
        panic!("the dump verb answers an artifact");
    };
    assert_eq!(name, "dump.bin");
    assert_eq!(content_type, "application/octet-stream");
    assert_eq!(bytes, b"PAYLOAD");
}

#[test]
fn handler_failures_and_panics_report_through_the_boundary() {
    unsafe { rod_plugin_init() };
    let mut failed = RodStr::empty();
    let mut no_artifact = RodArtifact::none();
    let status =
        unsafe { rod_plugin_run(1, RodStr::from_slice(b""), &mut failed, &mut no_artifact) };
    assert_eq!(status, 1);
    assert_eq!(unsafe { read(failed) }, "demo.fail: refused by the handler");
    assert!(no_artifact.name.ptr.is_null());
    let mut panicked = RodStr::empty();
    let mut also_none = RodArtifact::none();
    let status =
        unsafe { rod_plugin_run(2, RodStr::from_slice(b""), &mut panicked, &mut also_none) };
    assert_eq!(status, -2);
    let report = unsafe { read(panicked) };
    assert!(report.contains("panicked"), "{report}");
    assert!(report.contains("demo.panic"), "{report}");
    // The fence held: the test runner is still alive and the table still
    // answers.
    assert_eq!(unsafe { read(rod_plugin_verb_name(0)) }, "demo.echo");
}
