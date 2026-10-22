use std::collections::{HashMap, VecDeque};

use prost::Message;

use crate::handlers::Outcome;
use crate::wire::{Frame, FrameKind, TaskAck, TaskResult};

/// The upstream batch and the task ledger: one owner for everything the
/// implant owes the server, so a carriage's failure semantics are a method
/// call rather than scattered state.
///
/// The batch discipline is the wire contract's own (extending/implants.md):
/// queued frames leave only when a response was processed whole, so a failed
/// contact re-sends the batch verbatim; the server records results
/// first-wins, so re-sending is safe. The ledger is the dedup half of the
/// dispatch strand: a redelivered task is answered from the cache and never
/// re-executed. Staged transfers live on the session (their held bytes
/// outlive any one carriage), not here -- only their results ride the batch.
#[derive(Default)]
pub struct Outbox {
    queue: VecDeque<Frame>,
    /// Completed tasks by id: (wire outcome, output). A held entry answers
    /// any redelivery from the cache.
    ledger: HashMap<String, (Outcome, String)>,
}

impl Outbox {
    pub fn queue(&mut self, frame: Frame) {
        self.queue.push_back(frame);
    }

    /// Records a task's outcome and queues its TaskResult. The wire's
    /// numeric outcome codes live behind this boundary -- the rest of the
    /// implant speaks `Outcome`.
    pub fn result(&mut self, task_id: &str, outcome: Outcome, output: &str) {
        let wire = if outcome == Outcome::Succeeded {
            crate::wire::rod::TaskOutcome::Succeeded as i32
        } else {
            crate::wire::rod::TaskOutcome::Failed as i32
        };
        self.push_result(task_id, outcome, output, wire, None);
    }

    /// A staged task's result carries the payload hash the implant computed
    /// over what it reassembled (ADR-010's both-side arm): the server
    /// compares it against the artifact it served, so Succeeded means both
    /// sides held the same bytes.
    pub fn result_with_payload_sha(
        &mut self,
        task_id: &str,
        outcome: Outcome,
        output: &str,
        payload_sha256: &str,
    ) {
        let wire = if outcome == Outcome::Succeeded {
            crate::wire::rod::TaskOutcome::Succeeded as i32
        } else {
            crate::wire::rod::TaskOutcome::Failed as i32
        };
        self.push_result(task_id, outcome, output, wire, Some(payload_sha256));
    }

    fn push_result(
        &mut self,
        task_id: &str,
        outcome: Outcome,
        output: &str,
        wire: i32,
        payload_sha256: Option<&str>,
    ) {
        self.ledger
            .insert(task_id.to_string(), (outcome, output.to_string()));
        self.queue.push_back(Frame {
            payload: TaskResult {
                task_id: task_id.to_string(),
                outcome: wire,
                output: output.to_string(),
                payload_sha256: payload_sha256.map(str::to_string),
            }
            .encode_to_vec(),
            kind: FrameKind::TaskResult as i32,
        });
    }

    /// The batch snapshot a contact attempt sends; nothing is consumed until
    /// [`Self::batch_crossed`] names the attempt a success.
    pub fn batch(&self) -> Vec<Frame> {
        self.queue.iter().cloned().collect()
    }

    /// The attempt crossed and its response was processed: everything queued
    /// for it is delivered.
    pub fn batch_crossed(&mut self, sent: usize) {
        for _ in 0..sent {
            self.queue.pop_front();
        }
    }

    pub fn holds(&self, task_id: &str) -> bool {
        self.ledger.contains_key(task_id)
    }

    pub fn cached(&self, task_id: &str) -> Option<(Outcome, String)> {
        self.ledger.get(task_id).cloned()
    }

    pub fn acknowledge(&mut self, task_id: &str) {
        self.queue.push_back(Frame {
            payload: TaskAck {
                task_id: task_id.to_string(),
            }
            .encode_to_vec(),
            kind: FrameKind::TaskAck as i32,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::Outcome;

    #[test]
    fn failed_attempts_resend_the_batch_verbatim() {
        let mut outbox = Outbox::default();
        outbox.result("t-1", Outcome::Succeeded, "ok");
        outbox.result("t-2", Outcome::Failed, "no");
        let batch = outbox.batch();
        assert_eq!(batch.len(), 2);
        // A snapshot consumes nothing: the next attempt re-sends it whole.
        assert_eq!(outbox.batch(), batch);
        outbox.batch_crossed(batch.len());
        assert!(outbox.batch().is_empty());
    }

    #[test]
    fn results_carry_the_wire_outcome_codes_and_feed_the_ledger() {
        let mut outbox = Outbox::default();
        outbox.result("t-1", Outcome::Succeeded, "ok");
        outbox.result("t-2", Outcome::Failed, "no");
        let frames = outbox.batch();
        let ok = TaskResult::decode(frames[0].payload.as_ref()).expect("frame one");
        assert_eq!(ok.outcome, 1);
        assert_eq!(ok.task_id, "t-1");
        let failed = TaskResult::decode(frames[1].payload.as_ref()).expect("frame two");
        assert_eq!(failed.outcome, 2);
        assert!(outbox.holds("t-1"));
        assert_eq!(
            outbox.cached("t-1"),
            Some((Outcome::Succeeded, "ok".to_string()))
        );
        assert_eq!(outbox.cached("missing"), None);
    }

    #[test]
    fn acknowledgments_queue_as_ack_frames() {
        let mut outbox = Outbox::default();
        outbox.acknowledge("t-9");
        let batch = outbox.batch();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].kind(), FrameKind::TaskAck);
        let ack = TaskAck::decode(batch[0].payload.as_ref()).expect("the ack decodes");
        assert_eq!(ack.task_id, "t-9");
    }

    #[test]
    fn staged_results_carry_the_payload_hash() {
        let mut outbox = Outbox::default();
        outbox.result_with_payload_sha(
            "t-1",
            Outcome::Succeeded,
            "/tmp/x: 4 bytes written",
            &"ab".repeat(32),
        );
        let batch = outbox.batch();
        let result = TaskResult::decode(batch[0].payload.as_ref()).expect("the result decodes");
        assert_eq!(result.payload_sha256.as_deref(), Some(&"ab".repeat(32)[..]));
        // The ordinary result stays the plain shape: no field on the wire.
        outbox.result("t-2", Outcome::Succeeded, "ok");
        let plain = TaskResult::decode(outbox.batch()[1].payload.as_ref()).expect("decodes");
        assert_eq!(plain.payload_sha256, None);
    }
}
