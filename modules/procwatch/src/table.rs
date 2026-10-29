//! The watch's engine: the platform-free halves both collectors feed.
//! The diff decides what a creation is, the ring bounds what the watch
//! remembers, and the renderer speaks the recon output grammar -- one
//! JSON finding per line (extending/tradecraft.md), the shape the
//! topology view parses.

/// One process as a sweep saw it. The name is whatever the platform's
/// table carries -- a comm on Linux, an image name on Windows.
#[derive(Clone)]
pub(crate) struct Entry {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    pub(crate) name: String,
}

/// The creations between two sweeps: every entry of the current sweep
/// whose pid the previous sweep did not hold. Pid reuse can mint a
/// phantom start when a table slot turns over between sweeps -- the
/// diff answers table membership, not process identity, and the cadence
/// keeps the window one period wide.
pub(crate) fn creations(previous: &[Entry], current: &[Entry]) -> Vec<Entry> {
    current
        .iter()
        .filter(|entry| !previous.iter().any(|seen| seen.pid == entry.pid))
        .cloned()
        .collect()
}

/// One buffered row: the creation the sweep diffed, with the sequence
/// number the flush cursor walks.
struct Row {
    seq: u64,
    pid: u32,
    ppid: u32,
    name: String,
    seen: u64,
}

/// The bounded memory of the watch: creations land in order and the
/// oldest evict when the capacity is full -- the watch answers for the
/// recent past, never the whole of it.
pub(crate) struct Ring {
    rows: std::collections::VecDeque<Row>,
}

/// Enough rows for a long quiet span: at one burst row per pid slot this
/// holds thousands of starts, and an operator who lets it roll over
/// reads the eviction notice the flush prepends.
const CAPACITY: usize = 4096;

impl Ring {
    pub(crate) fn new() -> Ring {
        Ring {
            rows: std::collections::VecDeque::new(),
        }
    }

    pub(crate) fn push_creation(&mut self, next_seq: &mut u64, entry: &Entry, seen: u64) {
        if self.rows.len() >= CAPACITY {
            self.rows.pop_front();
        }
        self.rows.push_back(Row {
            seq: *next_seq,
            pid: entry.pid,
            ppid: entry.ppid,
            name: entry.name.clone(),
            seen,
        });
        *next_seq += 1;
    }

    /// The oldest row the buffer still holds, for the eviction notice.
    pub(crate) fn oldest_seq(&self) -> Option<u64> {
        self.rows.front().map(|row| row.seq)
    }

    /// Renders the rows at or past the cursor, in order. The read is
    /// non-destructive: the cursor, not the buffer, decides what the
    /// next ask returns, and eviction alone shortens the window.
    pub(crate) fn take_since(&self, cursor: u64) -> Vec<String> {
        self.rows
            .iter()
            .skip_while(|row| row.seq < cursor)
            .map(|row| render(&row.name, row.pid, row.ppid, row.seen))
            .collect()
    }
}

/// One finding, the recon grammar's line shape. The string escaper is
/// the grammar's own: a name carrying a quote or a control byte must not
/// mint a second line an operator's parser would read as a row.
fn render(name: &str, pid: u32, ppid: u32, seen: u64) -> String {
    let mut escaped = String::with_capacity(name.len());
    for character in name.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' | '\r' => escaped.push_str(" "),
            control if (control as u32) < 0x20 => escaped.push('?'),
            plain => escaped.push(plain),
        }
    }
    format!("{{\"pid\":{pid},\"ppid\":{ppid},\"name\":\"{escaped}\",\"seen\":{seen}}}")
}
