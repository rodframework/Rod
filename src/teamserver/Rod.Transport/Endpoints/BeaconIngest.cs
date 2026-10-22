using System.Collections.Concurrent;
using System.Text;
using Google.Protobuf;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Implants;
using Rod.CoreState.Live;
using Rod.CoreState.Sessions;
using Rod.CoreState.Tasks;
using Rod.V1;
// The domain entity shares its name with the BCL Task; this file uses the
// Rod.CoreState.Tasks types (TaskId, TaskOutcome, TaskService) but never the
// entity by name, so pin Task to the BCL type the async signatures need.
using Task = System.Threading.Tasks.Task;

namespace Rod.Transport.Endpoints;

// The shared upstream-frame ingest for every beacon transport
// (architecture.md Sec 8): the same capture-and-audit composition whether a
// frame crossed a live beacon stream or a plain-HTTP envelope contact. Task state
// lives in core, the audit event in the audit layer, and this is where both
// meet on a completed task (architecture.md Sec 10.3/11) -- extracted from
// BeaconEndpoint so every transport drives the identical paths.

/// <summary>
/// The identity context threaded from a completed handshake down to the frame
/// handler. The handshake resolves it once; passing it as a single value keeps
/// the handler signatures short and avoids re-deriving engagement/operator from
/// each task record (exfil chunks carry a task id but the operator who deployed
/// the implant is not on the task the way it is on TaskCompleted). Capabilities
/// are the advertised verb set, re-passed to each session touch so the
/// last-seen refresh never clobbers the handshake advertisement.
/// <see cref="TaskAcks"/> carries the handshake's receive-ack negotiation
/// (architecture.md Sec 10.3): a stream whose handshake echoed the arm counts
/// its dispatches delivered only once their acks cross, and requeues the
/// ack-less remainder when the stream ends.
/// </summary>
internal sealed record BeaconSessionContext(
    ImplantId Implant,
    EngagementId EngagementId,
    SessionId SessionId,
    OperatorId OperatorId,
    IReadOnlyCollection<string> Capabilities,
    bool TaskAcks = false);

/// <summary>
/// A validated staged-pull demand handed to the caller's sink: the task, and
/// -- when the demanding implant resumed (architecture.md Sec 15.3, ADR-010)
/// -- the byte offset it holds with the SHA-256 prefix proof for those bytes.
/// A fresh demand carries neither, and the answering run starts at 0.
/// </summary>
internal sealed record StagedPullDemand(TaskId Task, ulong? Offset = null, byte[]? PrefixSha256 = null);

/// <summary>
/// Ingests upstream beacon frames -- task results, exfil chunks, staged pulls,
/// channel output -- into the same core-state, audit, and live-event
/// composition every beacon transport shares. Per-connection state (the exfil
/// reassembly buffers and the channel decoders) lives on the connection
/// <see cref="OpenConnection"/> returns, so one transport connection's partial
/// buffers never leak into another's.
/// </summary>
internal sealed class BeaconIngest
{
    private readonly TaskService _tasks;
    private readonly ITaskRepository _taskRecords;
    private readonly IImplantRepository _implants;
    private readonly IAuditStore _audit;
    private readonly IArtifactStore _artifacts;
    private readonly ILiveEventBus _bus;
    private readonly TimeProvider _clock;
    private readonly Channels.TaskRelayHub _relays;
    private readonly Channels.SocksProxyHub _socks;
    private readonly BeaconDiagnostics _diagnostics;
    // The cross-connection exfil reassembly (ADR-010's upload arm): one
    // bounded store for the whole process, so a run spans connections and
    // carriages. The channel decoders stay per-connection -- a channel is
    // session-scoped by contract, an upload run is not.
    private readonly ExfilStreamStore _exfilStreams;

    public BeaconIngest(
        TaskService tasks,
        ITaskRepository taskRecords,
        IImplantRepository implants,
        IAuditStore audit,
        IArtifactStore artifacts,
        ILiveEventBus bus,
        TimeProvider clock,
        Channels.TaskRelayHub relays,
        Channels.SocksProxyHub socks,
        BeaconDiagnostics diagnostics)
    {
        _tasks = tasks;
        _taskRecords = taskRecords;
        _implants = implants;
        _audit = audit;
        _artifacts = artifacts;
        _bus = bus;
        _clock = clock;
        _relays = relays;
        _socks = socks;
        _diagnostics = diagnostics;
        _exfilStreams = new ExfilStreamStore(clock);
    }

    /// <summary>
    /// Opens the per-connection ingest: the frame handler plus the channel
    /// decoders scoped to one transport connection, over the shared exfil
    /// stream store.
    /// </summary>
    public BeaconConnectionIngest OpenConnection()
        => new(_tasks, _taskRecords, _implants, _audit, _artifacts, _bus, _clock, _relays, _socks, _diagnostics, _exfilStreams);

    // The served-side hash for the both-side check (ADR-010): the staged
    // artifact a task's issuer bound to it, hashed exactly as the implant
    // hashes its reassembled run. No staged bytes at all also mismatches --
    // a result claiming a hash for a task whose payload is gone is not a
    // success. Shared by the connection ingest and the DNS bridge, whose
    // grammar carries the reported hash on the result text's tail instead
    // of the proto field.
    internal static async Task<bool> StagedHashMatchesAsync(
        IArtifactStore artifacts,
        TaskId taskId,
        string reportedHex,
        CancellationToken cancellationToken)
    {
        var staged = (await artifacts.ForTaskAsync(taskId.Value, cancellationToken))
            .FirstOrDefault(a => a.Name == StagedArtifacts.NameFor(taskId.Value));
        if (staged is null)
            return false;
        var served = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(staged.Content));
        return string.Equals(served, reportedHex, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// One connection's share of the beacon ingest: the frame dispatch plus the
/// per-connection channel decoders over the shared exfil stream store. A
/// channel's decode state dies with its connection, matching the channel's
/// session scope; an exfil run's bytes outlive the connection (ADR-010's
/// upload arm), so they live on the store the whole process shares. The
/// caller is the sole ingester for its connection; the seam queue the
/// progress frames drain from is the one concurrent surface (the live
/// session runner's writer reads it while its reader ingests).
/// </summary>
internal sealed class BeaconConnectionIngest
{
    private readonly TaskService _tasks;
    private readonly ITaskRepository _taskRecords;
    private readonly IImplantRepository _implants;
    private readonly IAuditStore _audit;
    private readonly IArtifactStore _artifacts;
    private readonly ILiveEventBus _bus;
    private readonly TimeProvider _clock;
    private readonly Channels.TaskRelayHub _relays;
    private readonly Channels.SocksProxyHub _socks;
    private readonly BeaconDiagnostics _diagnostics;
    // The process-wide exfil stream store (see BeaconIngest): placement,
    // caps, and idle eviction live there; this class contributes the
    // connection's seam marks for progress reporting.
    private readonly ExfilStreamStore _exfil;
    // Per-connection incremental UTF-8 decoding for channel output, one decoder
    // per task id; dies with the connection, matching the channel's scope.
    private readonly ChannelDecoders _decoders = new();
    // The streams this connection touched with offset-bearing chunks, in
    // arrival order: the seam report a response answers with. Reader-only
    // writes (the sole ingester enqueues); the response builders drain.
    private readonly ConcurrentQueue<(Guid TaskId, string Name)> _seams = new();

    public BeaconConnectionIngest(
        TaskService tasks,
        ITaskRepository taskRecords,
        IImplantRepository implants,
        IAuditStore audit,
        IArtifactStore artifacts,
        ILiveEventBus bus,
        TimeProvider clock,
        Channels.TaskRelayHub relays,
        Channels.SocksProxyHub socks,
        BeaconDiagnostics diagnostics,
        ExfilStreamStore exfil)
    {
        _tasks = tasks;
        _taskRecords = taskRecords;
        _implants = implants;
        _audit = audit;
        _artifacts = artifacts;
        _bus = bus;
        _clock = clock;
        _relays = relays;
        _socks = socks;
        _diagnostics = diagnostics;
        _exfil = exfil;
    }

    /// <summary>
    /// Whether a task belongs on this session's stream: its own implant's
    /// tasking, or -- the fronting half (architecture.md Sec 5.2) -- the
    /// tasking of a Pivot child this session's implant fronts, which executes
    /// on this stream because the child has no process of its own. The
    /// engagement binding holds either way: a fronted child enrols into its
    /// parent's engagement, so a foreign engagement never reaches the fronted
    /// branch.
    /// </summary>
    private async Task<bool> BelongsToSessionAsync(
        Rod.CoreState.Tasks.Task task,
        BeaconSessionContext session,
        CancellationToken cancellationToken)
    {
        if (task.EngagementId != session.EngagementId)
            return false;
        if (task.ImplantId == session.Implant)
            return true;

        var target = await _implants.FindAsync(task.ImplantId, cancellationToken);
        return target is { Class: ImplantClass.Pivot, ParentImplantId: { } parent }
               && parent == session.Implant;
    }

    /// <summary>
    /// Ingests one upstream frame: dispatch on its kind. TASK_RESULT (and the
    /// legacy UNSPECIFIED default, which older implants still send) takes the
    /// capture-and-audit path; EXFIL_CHUNK reassembles a streamed artifact into
    /// the artifact store; STAGED_PULL hands the implant's demand for a staged
    /// payload to the caller's sink (each transport answers demands its own
    /// way -- the stream queues them for its dispatch writer, an envelope
    /// contact answers them in the same response); CHANNEL_OUTPUT appends a
    /// streaming task's chunk onto its transcript; TASK_ACK hands the
    /// implant's receive-ack to the caller's sink (architecture.md Sec 10.3 --
    /// the dispatch strand). Non-result, non-exfil frames are ignored
    /// (keepalives, etc.).
    /// </summary>
    /// <param name="stagedPullSink">
    /// Receives each validated staged-pull demand. Called only for a pull whose
    /// task belongs to this session's implant and holds a staged payload.
    /// </param>
    /// <param name="taskAckSink">
    /// Receives each validated receive-ack. Called only for an ack whose task
    /// belongs on this session's stream and is still Dispatched; a transport
    /// with no ack ledger of its own (the poll carriers) passes a no-op.
    /// </param>
    /// <param name="maxExfilStreamBytes">
    /// The per-stream byte cap exfil placement enforces for this call's
    /// chunks -- the frame carriages' default, or the DNS arm's smaller
    /// ceiling when the datagram grammar carries the run.
    /// </param>
    public async Task IngestAsync(
        BeaconSessionContext session,
        Frame frame,
        Action<StagedPullDemand> stagedPullSink,
        Action<TaskId> taskAckSink,
        CancellationToken cancellationToken,
        int maxExfilStreamBytes = ExfilStreamStore.FrameStreamBytes)
    {
        // The one seam every upstream frame crosses (ADR-008's beacon latency
        // distribution): observe the whole dispatch, whatever it decodes into
        // -- a keepalive's cheap parse and a terminal exfil chunk's artifact
        // write both count, because both are work the server did between the
        // frame arriving and being done with it.
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        try
        {
            await IngestFrameAsync(session, frame, stagedPullSink, taskAckSink, maxExfilStreamBytes, cancellationToken);
        }
        finally
        {
            _diagnostics.Observe(System.Diagnostics.Stopwatch.GetElapsedTime(started));
        }
    }

    private async Task IngestFrameAsync(
        BeaconSessionContext session,
        Frame frame,
        Action<StagedPullDemand> stagedPullSink,
        Action<TaskId> taskAckSink,
        int maxExfilStreamBytes,
        CancellationToken cancellationToken)
    {
        switch (frame.Kind)
        {
            case FrameKind.ExfilChunk:
                await HandleExfilChunkAsync(session, frame, maxExfilStreamBytes, cancellationToken);
                return;
            case FrameKind.StagedPull:
                await HandleStagedPullAsync(session, frame, stagedPullSink, cancellationToken);
                return;
            case FrameKind.ChannelOutput:
                await HandleChannelOutputAsync(session, frame, cancellationToken);
                return;
            case FrameKind.TaskAck:
                await HandleTaskAckAsync(session, frame, taskAckSink, cancellationToken);
                return;
            case FrameKind.TaskResult:
            case FrameKind.Unspecified:
            default:
                await HandleTaskResultAsync(session, frame, cancellationToken);
                return;
        }
    }

    // A TaskAck frame (architecture.md Sec 10.3 -- the dispatch strand): the
    // implant parsed the task's frame, which is the delivery evidence the
    // server below the result never had. The task must belong on this
    // session's stream -- the same ownership rule every upstream path holds --
    // and still be Dispatched; an ack for a completed task is a late straggler
    // with nothing left to clear, and an ack for a foreign task is dropped
    // rather than handed to the sink. The task's own lifecycle is untouched:
    // the ack is delivery evidence, not a transition.
    private async Task HandleTaskAckAsync(
        BeaconSessionContext session,
        Frame frame,
        Action<TaskId> taskAckSink,
        CancellationToken cancellationToken)
    {
        TaskAck ack;
        try
        {
            ack = TaskAck.Parser.ParseFrom(frame.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return;
        }

        if (!TaskId.TryParse(ack.TaskId, out var taskId))
            return;

        var task = await _taskRecords.FindAsync(taskId, cancellationToken);
        if (task is null
            || task.Status != Rod.CoreState.Tasks.TaskStatus.Dispatched
            || !await BelongsToSessionAsync(task, session, cancellationToken))
        {
            return;
        }

        taskAckSink(task.Id);
    }

    // A TaskResult frame: capture the outcome into the task and append the audit
    // event, then fan the completion out to connected operators. Pre-dates the
    // FrameKind discriminator: UNSPECIFIED frames fall through here too so older
    // implants keep working. The task must belong on this session's stream --
    // its own tasking, or a fronted Pivot child's (Sec 5.2), the same
    // ownership rule the exfil, staged-pull, and channel-output paths hold --
    // otherwise a session could forge a result onto another implant's (or
    // another engagement's) dispatched task and poison its record.
    private async Task HandleTaskResultAsync(
        BeaconSessionContext session,
        Frame frame,
        CancellationToken cancellationToken)
    {
        TaskResult result;
        try
        {
            result = TaskResult.Parser.ParseFrom(frame.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return; // Not a result frame; ignore for now (keepalives, etc.).
        }

        if (!TaskId.TryParse(result.TaskId, out var taskId))
            return;

        var owned = await _taskRecords.FindAsync(taskId, cancellationToken);
        if (owned is null || !await BelongsToSessionAsync(owned, session, cancellationToken))
            return;

        // Map the wire outcome onto the core-state enum (RecordResultAsync takes
        // the core type). Both namespaces define TaskOutcome; qualify both sides.
        var outcome = result.Outcome switch
        {
            Rod.V1.TaskOutcome.Succeeded => Rod.CoreState.Tasks.TaskOutcome.Succeeded,
            Rod.V1.TaskOutcome.Failed => Rod.CoreState.Tasks.TaskOutcome.Failed,
            _ => Rod.CoreState.Tasks.TaskOutcome.Failed,
        };
        var output = result.Output;

        // The both-side half of the resume arm (architecture.md Sec 15.3,
        // ADR-010): a staged task's result may carry the payload hash the
        // implant computed over what it reassembled. The served artifact is
        // the server's own view of the same bytes, so a mismatch is recorded
        // as the task's failure -- Succeeded means both sides held identical
        // bytes, and a lying or broken executor cannot mark its own task done.
        // An absent field is the ordinary result shape and changes nothing.
        if (owned.StagedBytes is not null
            && result.HasPayloadSha256
            && !await BeaconIngest.StagedHashMatchesAsync(_artifacts, taskId, result.PayloadSha256, cancellationToken))
        {
            outcome = Rod.CoreState.Tasks.TaskOutcome.Failed;
            output = $"staged payload hash mismatch: implant reported {result.PayloadSha256}: {output}";
        }

        TaskCompleted completed;
        try
        {
            completed = await _tasks.RecordResultAsync(taskId, output, outcome, cancellationToken);
        }
        catch (InvalidOperationException)
        {
            // An unknown task id or a retransmitted result after a reconnect
            // (the task is no longer Dispatched). Ignore the frame rather than
            // tearing the session down: the result for this id is either already
            // recorded or belongs to someone else.
            return;
        }

        // The final result closes the channel, and with it any relay bridged
        // onto it (architecture.md Sec 10.1 tunnel, Sec 10.3): the tunnel is
        // over, so the operator-side tool's connection ends rather than
        // stalls on a listener nothing more will cross.
        _relays.CloseTask(completed.TaskId.Value, "the tunnel task completed");
        _socks.CloseTask(completed.TaskId.Value, "the tunnel task completed");

        // The store stamps the chain hashes on append; the call site supplies only
        // the audited facts (AuditEvent.Fact leaves PreviousHash/Hash empty).
        await _audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: completed.EngagementId.Value,
                operatorId: completed.IssuedBy.Value,
                implantId: completed.ImplantId.Value,
                taskId: completed.TaskId.Value,
                verb: completed.Verb,
                kind: AuditEventKind.TaskCompleted,
                payload: completed.Arguments,
                output: completed.Output,
                outcome: completed.Outcome.ToString(),
                at: completed.CompletedAt),
            cancellationToken);

        // Fan the completion out to connected operator sessions.
        // The audit write above is the durable record; this live event is the
        // transient projection operators read while connected, so they see the
        // outcome without re-polling the task endpoint.
        await _bus.PublishAsync(
            LiveEvent.TaskCompleted(
                completed.EngagementId,
                completed.IssuedBy,
                completed.ImplantId,
                completed.TaskId,
                payload: $"{completed.Outcome}: {completed.Output}",
                completed.CompletedAt),
            cancellationToken);
    }

    // An ExfilChunk frame: place it in the shared per-(task, artifact) stream
    // store; on the terminal chunk, build the artifact, save it scoped to the
    // engagement, and append an ExfilCaptured audit event. The artifact is
    // bound to the task that triggered the push (the implant stamps the task
    // id on each chunk before sending), so it lands in the same
    // engagement-scoped store as operator-attached artifacts. An
    // offset-bearing chunk (ADR-010's upload arm) also marks the stream's
    // seam, so the contact's response carries the progress frame the sender
    // resumes from.
    private async Task HandleExfilChunkAsync(
        BeaconSessionContext session,
        Frame frame,
        int maxExfilStreamBytes,
        CancellationToken cancellationToken)
    {
        ExfilChunk chunk;
        try
        {
            chunk = ExfilChunk.Parser.ParseFrom(frame.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return; // Malformed chunk; ignore rather than tearing down the stream.
        }

        if (!Guid.TryParse(chunk.TaskId, out var taskId))
            return;

        var result = _exfil.Append(taskId, chunk, maxExfilStreamBytes);
        if (chunk.HasOffset)
            _seams.Enqueue((taskId, chunk.Name));

        if (result.Outcome != ExfilStreamStore.AppendOutcome.Completed)
            return;

        // The terminal chunk closed a complete run. Before materializing an
        // artifact, verify the task the implant stamped really belongs on this
        // session's stream -- its own tasking, or a fronted Pivot child's
        // (Sec 5.2) -- otherwise an implant could attach evidence to another
        // engagement's task ids. The placed bytes stay discarded on a refusal:
        // the store answered Completed, and a stream this session cannot own
        // was never theirs to finish.
        var task = await _taskRecords.FindAsync(new TaskId(taskId), cancellationToken);
        if (task is null || !await BelongsToSessionAsync(task, session, cancellationToken))
            return;

        // Build the artifact from the reassembled bytes, save it scoped to the
        // engagement and bound to the task, and record the capture in the audit
        // trail.
        var reassembled = result.Reassembled!;
        var artifactId = Guid.NewGuid();
        var now = _clock.GetUtcNow();
        var artifact = new Artifact(
            ArtifactId: artifactId,
            EngagementId: session.EngagementId.Value,
            TaskId: taskId,
            OperatorId: session.OperatorId.Value,
            Name: reassembled.Name,
            ContentType: reassembled.ContentType,
            Content: reassembled.Data,
            Size: reassembled.Data.Length,
            StoredAt: now);

        await _artifacts.SaveAsync(artifact, cancellationToken);

        await _audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: session.EngagementId.Value,
                operatorId: session.OperatorId.Value,
                implantId: session.Implant.Value,
                taskId: taskId,
                // The chunk stream is the task's own evidence arm, not an
                // exfil.push exclusive: a screenshot verb (and any future
                // artifact-producing verb) flows the same frames, so the
                // capture records the verb that actually produced it.
                verb: task.Verb,
                kind: AuditEventKind.ExfilCaptured,
                payload: $"{artifact.Name};{artifact.ContentType}",
                output: null,
                outcome: artifactId.ToString("N"),
                at: now),
            cancellationToken);

        // Fan the capture out to connected operator sessions so a live operator
        // sees the artifact arrive without re-polling the artifact endpoint.
        await _bus.PublishAsync(
            LiveEvent.TaskCompleted(
                session.EngagementId,
                session.OperatorId,
                session.Implant,
                new TaskId(taskId),
                payload: $"{task.Verb}: {artifact.Name};{artifact.ContentType}",
                now),
            cancellationToken);
    }

    // A StagedPull frame: the implant demands a staged task's payload
    // (architecture.md Sec 10). Validated against the connection's own implant
    // -- a demand naming another implant's task is dropped, not answered -- then
    // handed to the caller's sink, which answers it through the transport's own
    // path. The task's own lifecycle is untouched: the demand is a transport
    // read of staged bytes, not a task transition. A resuming demand (ADR-010)
    // carries the offset and prefix proof; a malformed proof (not 32 bytes)
    // degrades to the fresh shape rather than being dropped, so the demanding
    // implant still resolves.
    private async Task HandleStagedPullAsync(
        BeaconSessionContext session,
        Frame frame,
        Action<StagedPullDemand> stagedPullSink,
        CancellationToken cancellationToken)
    {
        StagedPull pull;
        try
        {
            pull = StagedPull.Parser.ParseFrom(frame.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return;
        }

        if (!TaskId.TryParse(pull.TaskId, out var taskId))
            return;

        var task = await _taskRecords.FindAsync(taskId, cancellationToken);
        if (task is null || task.StagedBytes is null || !await BelongsToSessionAsync(task, session, cancellationToken))
            return;

        stagedPullSink(new StagedPullDemand(
            task.Id,
            pull.HasOffset ? pull.Offset : null,
            pull.HasPrefixSha256 && pull.PrefixSha256.Length == 32 ? pull.PrefixSha256.ToByteArray() : null));
    }

    // A ChannelOutput frame (architecture.md Sec 10.3, the streaming task
    // shape): one chunk of a live channel's output. The task must belong on
    // this connection's stream -- its own tasking or a fronted Pivot child's
    // (Sec 5.2) -- an implant cannot stream onto another's tasks -- and must
    // still be Dispatched; a straggler after the final TaskResult (a
    // retransmission, a race at close) carries nothing new and is ignored
    // rather than tearing the stream down. The decoded chunk lands on the
    // task's transcript and fans out live so a connected operator reads the
    // channel as it prints.
    private async Task HandleChannelOutputAsync(
        BeaconSessionContext session,
        Frame frame,
        CancellationToken cancellationToken)
    {
        ChannelOutput output;
        try
        {
            output = ChannelOutput.Parser.ParseFrom(frame.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return; // Malformed chunk; ignore rather than tearing down the stream.
        }

        if (!TaskId.TryParse(output.TaskId, out var taskId))
            return;

        var task = await _taskRecords.FindAsync(taskId, cancellationToken);
        if (task is null || !await BelongsToSessionAsync(task, session, cancellationToken))
            return;

        // An empty chunk is a legal heartbeat on some channel implementations;
        // nothing to append.
        if (output.Data.Length == 0)
            return;

        // A relay bound onto this channel takes the raw bytes (architecture.md
        // Sec 10.1 tunnel, Sec 10.3): the operator-side tool's socket must
        // carry what the channel carried, not the lossy UTF-8 projection the
        // transcript decodes below. A task with no relay bound -- the common
        // case on every channel -- costs one dictionary lookup; a SOCKS proxy
        // re-frames the same bytes into its connections.
        _relays.TryDeliver(taskId.Value, output.Data.Memory);
        _socks.TryDeliver(taskId.Value, output.Data.Memory);

        var text = _decoders.Decode(taskId.Value, output.Data.Span);

        TaskAppended appended;
        try
        {
            appended = await _tasks.AppendChannelOutputAsync(taskId, text, cancellationToken);
        }
        catch (InvalidOperationException)
        {
            return;
        }

        // The audit trail needs no per-chunk event: the transcript is the
        // task's own record and lands whole in its TaskCompleted event. The
        // live event is the transient projection -- connected operators read
        // the channel as it prints, without re-polling the task.
        await _bus.PublishAsync(
            LiveEvent.ChannelOutput(
                appended.EngagementId,
                appended.IssuedBy,
                appended.ImplantId,
                appended.TaskId,
                text,
                _clock.GetUtcNow()),
            cancellationToken);
    }

    /// <summary>
    /// Drains the streams this connection touched with offset-bearing chunks
    /// into the seam-report frames its response carries (ADR-010's upload
    /// arm), one frame per stream at the store's freshest held count. Only a
    /// contact that sent offset-bearing chunks drains anything, so the
    /// kind-bearing downstream frame never reaches an implant that did not
    /// opt in structurally by sending one.
    /// </summary>
    public IReadOnlyList<Frame> TakeExfilProgress()
    {
        if (_seams.IsEmpty)
            return Array.Empty<Frame>();

        // One frame per stream even when several of its chunks crossed this
        // connection: arrival order keeps the last mention newest, and the
        // held count is read fresh from the store at drain time.
        var latest = new Dictionary<(Guid TaskId, string Name), byte>();
        while (_seams.TryDequeue(out var seam))
            latest[seam] = 0;
        return latest.Keys
            .Select(seam => new Frame
            {
                Kind = FrameKind.ExfilProgress,
                Payload = ByteString.CopyFrom(new ExfilProgress
                {
                    TaskId = new TaskId(seam.TaskId).ToString(),
                    Name = seam.Name,
                    HeldBytes = _exfil.Held(seam.TaskId, seam.Name),
                }.ToByteArray()),
            })
            .ToList();
    }

    // Incremental UTF-8 decoding for channel output, one decoder per task id.
    // A channel may emit a chunk that splits a multi-byte code point across
    // frames -- the shell does not frame on character boundaries -- and a
    // per-chunk GetString would corrupt the transcript at every split. The
    // decoder holds the partial bytes and completes the character on the next
    // chunk, so the transcript decodes what the channel actually printed.
    // Invalid sequences decode to the replacement character, the documented
    // lossy behavior for a text transcript carrying non-UTF-8 output. The
    // owning transport loop is the sole writer, so a plain Dictionary is safe; the
    // decoders die with the connection, matching the channel's scope.
    private sealed class ChannelDecoders
    {
        private readonly Dictionary<Guid, Decoder> _byTask = new();

        public string Decode(Guid taskId, ReadOnlySpan<byte> data)
        {
            if (!_byTask.TryGetValue(taskId, out var decoder))
            {
                decoder = Encoding.UTF8.GetDecoder();
                _byTask[taskId] = decoder;
            }

            var chars = new char[decoder.GetCharCount(data, flush: false)];
            var written = decoder.GetChars(data, chars, flush: false);
            return new string(chars, 0, written);
        }
    }
}
