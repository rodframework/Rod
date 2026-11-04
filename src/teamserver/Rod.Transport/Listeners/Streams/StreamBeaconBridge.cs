using Google.Protobuf;
using Microsoft.Extensions.Logging;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Implants;
using Rod.CoreState.Sessions;
using Rod.CoreState.Deployment;
using Rod.CoreState.Tasks;
using Rod.CoreState.Transports;
using Rod.Transport.Channels;
using Rod.Transport.Endpoints;
using Rod.Transport.Payloads;
using Rod.V1;
using Task = System.Threading.Tasks.Task;

namespace Rod.Transport.Listeners.Streams;

// The stream contact bridge (architecture.md Sec 8): the transport-blind
// contact flow the named-pipe and raw-TCP listeners share. One connection is
// one poll contact -- the request message carries the handshake first, then
// any results, exfil chunks, staged pulls, and channel output; the response
// message carries the handshake response, staged chunk runs answering the
// request's demands, and queued tasking while the dispatch budget lasts. The
// per-frame paths are the shared beacon compositions (BeaconIngest,
// BeaconTasking), so a result captured over a stream listener is
// indistinguishable in core state, the audit trail, and the live bus from one
// captured over the WebSocket beacon -- the same property the envelope carries.
//
// The opening message may also carry an EnrollRequest ahead of its handshake
// (Sec 8, the same full-independence step QUIC took): the certificate-less
// posture makes the carriage clean -- no TLS, no second connection -- so a
// no-egress segment can enroll its first implant over the pipe or socket it
// already reaches.
//
// The identity posture is the certificate-less one (Sec 8): no client
// certificate rides a pipe or a raw socket, so the implant is identified by
// the id in its handshake -- the DNS posture extended to a handshake-capable
// transport. The enrolled, kill-date, and retired gates apply in full, and
// dispatched tasking keeps the full Sec 9 signature posture: an implant that
// verifies its tasking (Tier 1) is protected no matter which transport
// delivered it.

/// <summary>
/// Serves one contact over a duplex stream: read the request message, run
/// the envelope's sequential poll flow (handshake, ingest, staged answers,
/// budgeted dispatch), and write the response message.
/// </summary>
internal sealed class StreamBeaconBridge
{
    /// <summary>
    /// The dispatched-tasking budget for one response message, the same budget
    /// the envelope applies: tasking frames are claimed only while they fit,
    /// and a task that does not fit is requeued for the next contact.
    /// </summary>
    public const int MaxDispatchBytes = 4 * 1024 * 1024;

    // How long one contact may take end to end: a client that connects and
    // goes silent must not pin a handler on a transport with no HTTP timeouts
    // of its own. Generous against a slow poll cycle, bounded against a dead
    // peer.
    private static readonly TimeSpan ContactTimeout = TimeSpan.FromSeconds(30);

    private readonly HandshakeService _handshake;
    private readonly ISessionRegistry _sessions;
    private readonly TaskService _tasks;
    private readonly BeaconIngest _ingest;
    private readonly BeaconTasking _tasking;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;
    private readonly DegradedChannelHub _degraded;
    private readonly EnrollmentService _enrollment;
    private readonly IDeployTokenService _tokens;
    private readonly IPayloadStore _payloads;
    private readonly Rod.CoreState.Campaigns.ICampaignStore _campaigns;
    private readonly EnvelopeContactKeys _contactKeys;
    private readonly SessionSealKeys _sessionKeys;
    private readonly ILogger<StreamBeaconBridge> _logger;
    private readonly BeaconSessionRunner _runner;

    // The handshake capability that switches a connection from the poll
    // exchange to the held live session (architecture.md Sec 8, the socket
    // family's stream mode): the implant's stream-mode client advertises it,
    // the poll client does not, and an older server ignores it -- the extra
    // advertisement reads as an unknown capability, so an old teamserver
    // serves the connection as an ordinary poll contact.
    public const string LiveSessionCapability = "channels.live";

    public StreamBeaconBridge(
        HandshakeService handshake,
        ISessionRegistry sessions,
        TaskService tasks,
        BeaconIngest ingest,
        BeaconTasking tasking,
        IAuditStore audit,
        TimeProvider clock,
        DegradedChannelHub degraded,
        EnrollmentService enrollment,
        IDeployTokenService tokens,
        IPayloadStore payloads,
        Rod.CoreState.Campaigns.ICampaignStore campaigns,
        EnvelopeContactKeys contactKeys,
        SessionSealKeys sessionKeys,
        ITaskDispatchWake wake,
        LiveChannelHub channels,
        TaskRelayHub relays,
        SocksProxyHub socks,
        Rod.Transport.Channels.ChainHub chain,
        ILogger<StreamBeaconBridge> logger)
    {
        _handshake = handshake;
        _sessions = sessions;
        _tasks = tasks;
        _ingest = ingest;
        _tasking = tasking;
        _audit = audit;
        _clock = clock;
        _degraded = degraded;
        _enrollment = enrollment;
        _tokens = tokens;
        _payloads = payloads;
        _campaigns = campaigns;
        _contactKeys = contactKeys;
        _sessionKeys = sessionKeys;
        _logger = logger;
        _runner = new BeaconSessionRunner(
            sessions, tasks, clock, wake, channels, degraded, relays, socks, chain, ingest, tasking);
    }

    /// <summary>
    /// Handles one connection in the shape its handshake advertises: the
    /// ordinary poll exchange -- one contact, then closed, the next cycle
    /// reconnecting -- or, when the handshake advertises
    /// <see cref="LiveSessionCapability"/>, the held live session the stream
    /// modes run (server-push tasking, live channels). Every failure -- a
    /// malformed message, a vanished client, a refused handshake answered
    /// with a bare handshake response -- ends the connection; the next
    /// contact reconnects, the cadence the poll shape keeps and the stream
    /// shape's reconnects borrow.
    /// </summary>
    /// <param name="carrier">
    /// The carrier name the contact's presence stamps ride: "pipe" for a
    /// listener's own socket, "chain" for a chained contact a parent's
    /// tunnel.bind channel carried in (Sec 5.2) -- the roster's badges read
    /// the difference.
    /// </param>
    /// <param name="chainParent">
    /// On a chained contact, the implant whose channel carried it in: the
    /// carrying parent is the lineage a chained enrollment records (the
    /// child cannot name its own, and a frame that tries is overridden --
    /// the carriage is the authority), and a null ingress listener suits a
    /// contact that arrived over no listener of its own. Null on an
    /// ordinary listener contact, which keeps the frame's own parent field.
    /// </param>
    public async Task HandleContactAsync(
        Stream stream,
        Listener? listener,
        CancellationToken stoppingToken,
        string carrier = "pipe",
        ImplantId? chainParent = null)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        bounded.CancelAfter(ContactTimeout);
        var cancellationToken = bounded.Token;
        try
        {
            // The opening message may carry an EnrollRequest ahead of its
            // handshake (Sec 8), so the first decode accepts the enroll
            // seal too; every later message on the connection is a contact.
            var opened = await ReadAndDecodeAsync(stream, allowEnroll: true, cancellationToken);
            if (opened is null)
                return;
            var frames = opened.Frames;
            var sealedKey = (KeyId: opened.Sealed && opened.Session is null ? opened.KeyId : Guid.Empty, opened.Key);
            var isSealed = opened.Sealed;
            var contactCounter = opened.Counter;
            var bodySession = opened.Session;

            // Enrollment over the stream contact (Sec 8, the same
            // full-independence step QUIC took): the opening message may
            // carry an EnrollRequest ahead of its handshake -- the
            // certificate-less posture makes the carriage clean, no TLS and
            // no second connection. The arm answers as its own message and
            // reads the next message as the contact.
            if (frames.Count > 0 && frames[0].Kind == FrameKind.EnrollRequest)
            {
                if (!await ServeEnrollmentAsync(stream, listener, frames[0], opened, chainParent, cancellationToken))
                    return;

                // The handshake is the next frame the connection carries: the
                // remainder of the enroll message when it rode one, else the
                // next message's first frame.
                frames = frames.Skip(1).ToList();
                if (frames.Count == 0)
                {
                    var next = await ReadAndDecodeAsync(stream, allowEnroll: false, cancellationToken);
                    if (next is null)
                        return;
                    frames = next.Frames;
                    sealedKey = (next.Sealed && next.Session is null ? next.KeyId : Guid.Empty, next.Key);
                    isSealed = next.Sealed;
                    contactCounter = next.Counter;
                    bodySession = next.Session;
                }
            }

            // The implant speaks first here too: the first frame is the
            // handshake, and -- with no certificate to read an identity from --
            // the handshake is the identity: the implant id it carries.
            HandshakeRequest handshakeRequest;
            if (frames.Count == 0
                || !TryParseHandshake(frames[0], out handshakeRequest)
                || !ImplantId.TryParse(handshakeRequest.ImplantId, out var implantId))
            {
                await RespondAsync(stream, BeaconHandshake.Response(HandshakeStatus.Unspecified, engagementId: null, replayNonces: false), sealedKey, isSealed, bodySession, stoppingToken);
                return;
            }

            // The key posture gates, checked before the handshake opens
            // anything (the envelope route's own rules, carried here): an
            // implant bound to a build key at enroll contacts sealed under
            // exactly that key -- a plaintext body from it is the refused
            // downgrade, another artifact's key does not impersonate it --
            // and the counter must clear the floor: a replayed body,
            // whatever it claims, turns away without a session or a touch.
            // An R2 body authenticates by the session it opened under, so
            // the baked-key check stands down for it while the session it
            // addressed must still be this implant's own. The refusal is
            // the dropped connection, the raw carriage's answer to the HTTP
            // problem body -- and the session-key arm's contract violations
            // (an offer on a session body, an offer with frames riding, an
            // ordinary baked-key body from an implant holding an agreed
            // session) drop the same way, so the client's reconnect answers
            // with a fresh agreement contact.
            var offeredAgreement = false;
            if (_contactKeys.TryGet(implantId) is { } bound)
            {
                if (!isSealed || (bodySession is null && sealedKey.KeyId != bound.KeyId))
                    return;
            }
            if (bodySession is { } openedSession && openedSession.Implant != implantId)
                return;
            // The arm's contract refusals sit ahead of the floor on purpose:
            // a refused posture must not advance it, or the forgery would
            // lock the honest contact out of its counter.
            if (bodySession is not null && handshakeRequest.HasSessionPublic && handshakeRequest.SessionPublic.Length > 0)
                return;
            offeredAgreement = bodySession is null
                && isSealed
                && handshakeRequest.HasSessionPublic
                && handshakeRequest.SessionPublic.Length > 0
                && sealedKey.Key.Length == AesGcmEnvelope.KeyBytes;
            if (offeredAgreement && frames.Count > 1)
                return;
            if (!offeredAgreement
                && bodySession is null
                && isSealed
                && sealedKey.KeyId != Guid.Empty
                && _sessionKeys.TryLatest(implantId) is not null)
                return;
            if (isSealed && !_contactKeys.Accept(implantId, contactCounter))
                return;

            var (response, handshake) = await TryHandshakeAsync(implantId, handshakeRequest);

            // The agreement exchange (Sec 9): the server's ephemeral rides
            // the handshake response sealed under the baked key -- the last
            // body that key opens -- and the frames after it on this
            // connection seal under the session keys. An offer the schedule
            // cannot take answers without the echo and keeps the baked-key
            // seal.
            SessionSealKeys.Entry? agreedSession = null;
            if (offeredAgreement
                && response.Status == HandshakeStatus.Ok
                && handshake is not null
                && _sessionKeys.Agree(
                    handshake.ImplantId, sealedKey.KeyId, sealedKey.Key, handshakeRequest.SessionPublic.Span)
                    is { } agreement)
            {
                response.SessionPublic = ByteString.CopyFrom(agreement.ServerPublic);
                agreedSession = agreement.Entry;
            }
            if (response.Status != HandshakeStatus.Ok || handshake is null)
            {
                await RespondAsync(stream, response, sealedKey, isSealed, bodySession, stoppingToken);
                return;
            }

            // A genuinely new session is recorded; a reused one (every
            // contact after the first) is not, the same flood guard the
            // stream and the envelope apply (architecture.md Sec 10.3, Sec 11).
            await BeaconHandshake.AppendSessionOpenedAsync(_audit, handshake, handshakeRequest);

            var session = new BeaconSessionContext(
                implantId,
                handshake.EngagementId,
                handshake.SessionId,
                handshake.DeployedBy,
                handshakeRequest.Capabilities,
                handshake.TaskAcks);

            // One presence touch per contact, then the session guard: if the
            // session this handshake holds was closed out from under it, stop
            // after the handshake response so the implant re-handshakes on its
            // next cycle.
            await _sessions.TouchAsync(session.Implant, session.Capabilities, _clock.GetUtcNow(), carrier, cancellationToken);
            var active = await _sessions.GetActiveAsync(session.Implant, cancellationToken);
            if (active is null || active.Id != session.SessionId)
            {
                await RespondAsync(stream, response, sealedKey, isSealed, bodySession, stoppingToken);
                return;
            }

            // The live session (the stream mode's advertisement): the opening
            // exchange ends here -- the handshake response rides as its own
            // message, and the shared session runner holds the connection,
            // pushing tasking the moment it is queued and draining result
            // frames as they cross (architecture.md Sec 8, the same runner
            // the WebSocket beacon runs). The runner runs under the
            // listener's own lifetime: the
            // contact timeout above bounds the opening exchange, not a held
            // session. Sealing rides the same per-message counter discipline
            // the poll exchange carries: every inbound message is a fresh
            // counter over the contact purpose tag, every outbound frame
            // leaves sealed under the response tag when the connection
            // opened sealed. A connection that just agreed session keys runs
            // its held traffic under them; the agreement's own handshake
            // response sealed under the baked key above.
            if (session.Capabilities.Contains(LiveSessionCapability))
            {
                await RespondAsync(stream, response, sealedKey, isSealed, bodySession, stoppingToken);
                var liveSession = agreedSession ?? bodySession;
                var livePending = new Queue<Frame>(frames.Skip(1));
                await _runner.RunAsync(
                    session,
                    async liveToken =>
                    {
                        while (livePending.Count == 0)
                        {
                            var message = await TryReadLiveMessageAsync(
                                stream, implantId, sealedKey, isSealed, liveSession, liveToken);
                            if (message is null)
                                throw new EndOfStreamException();
                            foreach (var frame in message)
                                livePending.Enqueue(frame);
                        }
                        return livePending.Dequeue();
                    },
                    (frame, liveToken) => WriteLiveFrameAsync(stream, frame, sealedKey, isSealed, liveSession, liveToken),
                    stoppingToken,
                    carrier);
                return;
            }

            // An agreed poll connection closes on the agreement: the
            // handshake response is the whole answer, sealed under the baked
            // key, and the connection's next cycle runs under the session
            // keys.
            if (agreedSession is not null)
            {
                await RespondAsync(stream, response, sealedKey, isSealed, bodySession, stoppingToken);
                return;
            }

            var outbound = new List<Frame> { HandshakeFrame(response) };

            // Ingest the request's remaining frames (results, exfil chunks,
            // staged pulls, channel output) through the shared composition,
            // collecting validated staged demands for the response. Receive
            // acks from a negotiated implant are accepted and handed to a
            // no-op sink: a poll carrier keeps no ack ledger -- one connection
            // is one contact, answered whole or not at all -- so the arm's
            // requeue never applies on this path (architecture.md Sec 10.3).
            var connection = _ingest.OpenConnection();
            var stagedPulls = new List<StagedPullDemand>();
            for (var i = 1; i < frames.Count; i++)
            {
                await connection.IngestAsync(
                    session,
                    frames[i],
                    stagedPullSink: stagedPulls.Add,
                    taskAckSink: static _ => { },
                    cancellationToken);
            }

            // The exfil seam reports ride ahead of the staged runs and
            // tasking (ADR-010's upload arm): offset-bearing chunks placed
            // this contact answer with the byte count the server holds, so
            // the sender's next message serves only the unheld remainder.
            outbound.AddRange(connection.TakeExfilProgress());

            // Answer each demand with its chunk run in this response, before
            // any new tasking: the implant is blocked on bytes it already
            // accepted a task for (architecture.md Sec 10, the typed arm). A
            // resumed demand (ADR-010) answers from the offset it proved,
            // and the run budget splits evenly across the demands and ends
            // short of terminal past it -- a run larger than one body spans
            // contacts through the resume discipline, the poll shape's own
            // body-budget answer (the upload arm's mirror).
            var share = Math.Max(
                BeaconTasking.StagedChunkSize,
                BeaconTasking.MaxStagedRunBytes / Math.Max(1, stagedPulls.Count));
            foreach (var pull in stagedPulls)
                outbound.AddRange(await _tasking.StagedChunkRunAsync(
                    pull.Task.Value, pull.Offset, pull.PrefixSha256, share, cancellationToken));

            // Dispatch queued tasking while the budget lasts. The claim
            // evaluation every poll carrier runs decides what fits: a channel
            // verb claims only under the degraded discipline -- the
            // session's opt-in -- and without it parks, requeued for a
            // stream transport to claim (architecture.md Sec 10.3). A
            // requeued task joins the skip set for the rest of this
            // contact, so a task this carrier cannot serve parks without
            // standing at the queue head and starving the tasks behind it.
            var degraded = session.Capabilities.Contains(DegradedChannelHub.Capability);
            var budget = MaxDispatchBytes;
            var skipped = new HashSet<TaskId>();
            while (true)
            {
                var dispatched = await _tasks.DispatchNextAsync(session.Implant, cancellationToken, exclude: skipped);
                if (dispatched is null)
                    break;

                var frame = await _tasking.MarshalFrameAsync(dispatched, cancellationToken);
                var wireSize = EnvelopeFraming.WireSize(frame);

                if (TransportCapabilities.EvaluateClaim(
                        TransportCapabilities.MessagePipe, dispatched.Verb, wireSize, budget, degraded)
                    != ClaimDecision.Claim)
                {
                    await _tasks.RequeueAsync(dispatched.TaskId, CancellationToken.None);
                    skipped.Add(dispatched.TaskId);
                    continue;
                }

                budget -= wireSize;
                outbound.Add(frame);
                await _tasking.RecordDispatchAsync(dispatched, cancellationToken);
            }

            // The store-and-forward half, the envelope's own: parked operator
            // input rides after the tasking as ChannelInput frames within the
            // budget the tasking left, and the sweep closes channels the
            // implant stopped collecting.
            if (degraded)
            {
                await _degraded.SweepIdleAsync(cancellationToken);
                outbound.AddRange(_degraded.Drain(session.Implant, budget));
            }

            await ReplyAsync(stream, outbound, sealedKey, isSealed, bodySession, stoppingToken);
        }
        catch (Exception ex) when (
            ex is OperationCanceledException
            or IOException
            or ObjectDisposedException
            or System.Net.Sockets.SocketException)
        {
            // The client vanished or the host is stopping: the connection
            // ends, and the next contact reconnects. A dispatched task whose
            // response write failed stays claimed for its result -- the same
            // retransmission tolerance the envelope carries.
        }
    }

    // One live-session message in: the framed body, or the same counter-
    // covered sealed shape every contact body carries (a fresh counter per
    // message, the floor turned by the same ledger the poll exchange uses) --
    // under the session keys once the connection agreed them, under the
    // baked key otherwise. Null drops the connection -- an unsealable or
    // malformed body is the refused cycle, not a negotiated one.
    private async Task<List<Frame>?> TryReadLiveMessageAsync(
        Stream stream,
        ImplantId implantId,
        (Guid KeyId, byte[] Key) sealedKey,
        bool isSealed,
        SessionSealKeys.Entry? session,
        CancellationToken cancellationToken)
    {
        byte[] body;
        try
        {
            body = await StreamContactFraming.ReadMessageAsync(stream, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException)
        {
            return null;
        }

        if (!isSealed)
        {
            try
            {
                return EnvelopeFraming.Parse(body);
            }
            catch (EnvelopeFramingException)
            {
                return null;
            }
        }

        if (session is not null)
        {
            if (EnvelopeBeaconContact.TryReadSessionSealedKeyId(body, out var sessionText) is not { } sessionId
                || sessionId != session.SessionId)
                return null;
            var plain = AesGcmEnvelope.TryUnwrapSession(
                sessionText, session.SessionId, session.RequestKey, AesGcmEnvelope.ContactRequestAad);
            if (plain is null || plain.Length < 8)
                return null;
            var sessionCounter = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(plain);
            if (!_contactKeys.Accept(implantId, sessionCounter))
                return null;
            try
            {
                return EnvelopeFraming.Parse(plain[8..]);
            }
            catch (EnvelopeFramingException)
            {
                return null;
            }
        }

        if (EnvelopeBeaconContact.TryReadSealedKeyId(body, out var sealedText) is not { } keyId
            || keyId != sealedKey.KeyId)
            return null;
        var plainBaked = AesGcmEnvelope.TryUnwrap(sealedText, sealedKey.KeyId, sealedKey.Key, AesGcmEnvelope.ContactRequestAad);
        if (plainBaked is null || plainBaked.Length < 8)
            return null;
        var counter = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(plainBaked);
        if (!_contactKeys.Accept(implantId, counter))
            return null;
        try
        {
            return EnvelopeFraming.Parse(plainBaked[8..]);
        }
        catch (EnvelopeFramingException)
        {
            return null;
        }
    }

    // One live-session frame out: its own message, sealed under the response
    // purpose tag -- under the session keys once the connection agreed them,
    // else under the baked key when it opened sealed -- the runner's one
    // frame per message, the held stream's own shape.
    private static async Task WriteLiveFrameAsync(
        Stream stream, Frame frame, (Guid KeyId, byte[] Key) sealedKey, bool isSealed,
        SessionSealKeys.Entry? session, CancellationToken cancellationToken)
    {
        var body = EnvelopeFraming.Encode(new[] { frame });
        if (session is not null)
            body = System.Text.Encoding.UTF8.GetBytes(AesGcmEnvelope.WrapSession(
                body, session.SessionId, session.ResponseKey, AesGcmEnvelope.ContactResponseAad));
        else if (isSealed)
            body = System.Text.Encoding.UTF8.GetBytes(AesGcmEnvelope.Wrap(
                body, sealedKey.KeyId, sealedKey.Key, AesGcmEnvelope.ContactResponseAad));
        await StreamContactFraming.WriteMessageAsync(stream, body, cancellationToken);
    }

    // One response message out: the framed body, or the same body sealed
    // under the key the request verified with -- the session's response key
    // when the body opened under a session, else the baked key -- a sealed
    // cycle answers sealed, handshake refusals included, so the wire carries
    // no readable frame bytes in either direction.
    private static async Task ReplyAsync(
        Stream stream, IReadOnlyList<Frame> outbound, (Guid KeyId, byte[] Key) sealedKey, bool isSealed,
        SessionSealKeys.Entry? session, CancellationToken stoppingToken)
    {
        var body = EnvelopeFraming.Encode(outbound);
        if (session is not null)
            body = System.Text.Encoding.UTF8.GetBytes(AesGcmEnvelope.WrapSession(
                body, session.SessionId, session.ResponseKey, AesGcmEnvelope.ContactResponseAad));
        else if (isSealed)
            body = System.Text.Encoding.UTF8.GetBytes(AesGcmEnvelope.Wrap(
                body, sealedKey.KeyId, sealedKey.Key, AesGcmEnvelope.ContactResponseAad));
        await StreamContactFraming.WriteMessageAsync(stream, body, stoppingToken);
    }

    private async Task RespondAsync(
        Stream stream, HandshakeResponse response, (Guid, byte[]) sealedKey, bool isSealed,
        SessionSealKeys.Entry? session, CancellationToken stoppingToken)
        => await ReplyAsync(
            stream, new[] { HandshakeFrame(response) }, sealedKey, isSealed, session, stoppingToken);

    // The enroll exchange on the opening connection (Sec 8): a kind-bearing
    // EnrollRequest frame -- the enroll body the web route carries, promoted
    // into the rod.v1 frame grammar -- answered by an EnrollResponse frame.
    // The shared ScopedEnrollment flow does the work the web route drives it
    // for, scoped by this connection's own listener (the ingress the HTTP
    // route resolves from the local port, the pipe or socket listener knows
    // directly), with the same refusal rules and audit arc. A chained
    // contact (Sec 5.2) carries no listener of its own -- its ingress is the
    // parent's channel, so the null ingress keeps the enrollment
    // token-scoped -- and names its carrying parent as the lineage, the
    // frame's own parent field overridden (the carriage is the authority, so
    // a child cannot misreport it). A refusal answers the status frame and
    // ends the connection (no identity exists to hold a session); an
    // acceptance is followed by the ordinary handshake on the same
    // connection.
    private async Task<bool> ServeEnrollmentAsync(
        Stream stream,
        Listener? listener,
        Frame frame,
        DecodedMessage opened,
        ImplantId? chainParent,
        CancellationToken cancellationToken)
    {
        Rod.V1.EnrollRequest request;
        try
        {
            request = Rod.V1.EnrollRequest.Parser.ParseFrom(frame.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            await WriteEnrollResponseAsync(
                stream, new Rod.V1.EnrollResponse { Status = EnrollStatus.Unspecified }, opened, cancellationToken);
            return false;
        }

        // A shared-tier socket refuses implant ingress outright (Sec 8) --
        // the same rule ScopedEnrollment enforces from the listener record,
        // kept here so the named refusal reads on the listener's own log.
        if (listener is not null && listener.EngagementId is null)
        {
            _logger.LogInformation(
                "Stream enroll refused on {Name}: the socket is not engagement-scoped.", listener.Name);
            await WriteEnrollResponseAsync(
                stream, new Rod.V1.EnrollResponse { Status = EnrollStatus.BadToken }, opened, cancellationToken);
            return false;
        }

        var outcome = await ScopedEnrollment.EnrollAsync(
            new EnrollWireFields(
                request.DeployTokenSecret,
                NullWhenEmpty(request.Class),
                request.PublicKey.IsEmpty ? null : request.PublicKey.ToByteArray(),
                chainParent?.ToString() ?? NullWhenEmpty(request.ParentImplantId),
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

        if (!outcome.Accepted)
        {
            // The token states carry over the wire; the problem causes (a
            // malformed request, a closed engagement) collapse to the
            // generic refusal -- the same "no signal beyond no" the web
            // route keeps -- with the cause named server-side.
            if (outcome.Problem is { } problem)
                _logger.LogInformation(
                    "Stream enroll refused on {Name}: {Problem}.", listener?.Name ?? "a chained contact", problem);
            else
                _logger.LogInformation(
                    "Stream enroll refused on {Name}: status {Status}.",
                    listener?.Name ?? "a chained contact", outcome.Status);
            await WriteEnrollResponseAsync(
                stream, new Rod.V1.EnrollResponse { Status = outcome.Status }, opened, cancellationToken);
            return false;
        }

        var enrolled = outcome.Enrolled!;
        _logger.LogInformation(
            "Rod stream listener {Name} enrolled implant {Implant} into {Engagement}.",
            listener?.Name ?? "a chained contact", enrolled.ImplantId, enrolled.EngagementId);

        var response = ScopedEnrollmentResponse.Build(outcome);

        await WriteEnrollResponseAsync(stream, response, opened, cancellationToken);
        return true;
    }

    private static async Task WriteEnrollResponseAsync(
        Stream stream, Rod.V1.EnrollResponse response, DecodedMessage opened, CancellationToken cancellationToken)
    {
        var body = EnvelopeFraming.Encode(new[]
        {
            new Frame { Kind = FrameKind.EnrollResponse, Payload = ByteString.CopyFrom(response.ToByteArray()) },
        });
        // A sealed exchange answers sealed, refusals included: the client
        // that baked a key reads its answer under it, and the wire carries
        // no readable frame bytes in either direction.
        if (opened.Sealed)
            body = System.Text.Encoding.UTF8.GetBytes(AesGcmEnvelope.Wrap(
                body, opened.KeyId, opened.Key, AesGcmEnvelope.EnrollResponseAad));
        await StreamContactFraming.WriteMessageAsync(stream, body, cancellationToken);
    }

    private static string? NullWhenEmpty(string value)
        => value.Length == 0 ? null : value;

    // One decoded inbound message: the frames, and -- when the body was a
    // sealed shape -- the key it verified under and the counter it carried
    // (the session entry instead of the baked key when the body was the R2
    // shape).
    private sealed record DecodedMessage(
        List<Frame> Frames, bool Sealed, Guid KeyId, byte[] Key, long Counter,
        SessionSealKeys.Entry? Session = null);

    // Reads one message and decodes its body: the plaintext framed shape, or
    // the sealed shape (architecture.md Sec 8/9) -- base64 of
    // magic || keyId || nonce || ciphertext || tag, AES-256-GCM under the
    // artifact's per-build key, the same application-layer seal the
    // cleartext http posture carries, so a bare socket or pipe leaks no
    // frame bytes either. The contact body wraps a strictly increasing
    // counter (8 bytes, big-endian) ahead of the framed bytes; the enroll
    // exchange (the opening message, allowEnroll) seals its frames without
    // one. A body that names no known key, or does not verify under it, is
    // undecodable -- null, the dropped connection.
    private async Task<DecodedMessage?> ReadAndDecodeAsync(
        Stream stream, bool allowEnroll, CancellationToken cancellationToken)
    {
        byte[] body;
        try
        {
            body = await StreamContactFraming.ReadMessageAsync(stream, cancellationToken);
        }
        catch (Exception ex) when (ex is EnvelopeFramingException or IOException or OperationCanceledException)
        {
            return null;
        }

        var framed = body;
        var sealedShape = (Sealed: false, KeyId: Guid.Empty, Key: Array.Empty<byte>());
        SessionSealKeys.Entry? session = null;
        long counter = 0;
        if (EnvelopeBeaconContact.TryReadSealedKeyId(body, out var sealedText) is { } keyId)
        {
            var carrier = await _payloads.FindByEnvelopeKeyAsync(keyId, cancellationToken);
            if (carrier?.EnvelopeKey is not { } key)
                return null;
            byte[]? plain = null;
            if (allowEnroll)
                plain = AesGcmEnvelope.TryUnwrap(sealedText, keyId, key, AesGcmEnvelope.EnrollRequestAad);
            if (plain is null)
            {
                plain = AesGcmEnvelope.TryUnwrap(sealedText, keyId, key, AesGcmEnvelope.ContactRequestAad);
                if (plain is null || plain.Length < 8)
                    return null;
                counter = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(plain);
                plain = plain[8..];
            }
            framed = plain;
            sealedShape = (true, keyId, key);
        }
        else if (EnvelopeBeaconContact.TryReadSessionSealedKeyId(body, out var sessionText) is { } sessionId)
        {
            // The R2 body (Sec 9, session key agreement): the session id
            // addresses an agreement this process made -- none to find is
            // the dropped connection, so the client's reconnect runs the
            // agreement again.
            var entry = _sessionKeys.TryGet(sessionId);
            if (entry is null)
                return null;
            var plain = AesGcmEnvelope.TryUnwrapSession(
                sessionText, sessionId, entry.RequestKey, AesGcmEnvelope.ContactRequestAad);
            if (plain is null || plain.Length < 8)
                return null;
            counter = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(plain);
            framed = plain[8..];
            session = entry;
            sealedShape = (true, Guid.Empty, Array.Empty<byte>());
        }

        try
        {
            return new DecodedMessage(
                EnvelopeFraming.Parse(framed), sealedShape.Sealed, sealedShape.KeyId, sealedShape.Key,
                counter, session);
        }
        catch (EnvelopeFramingException)
        {
            // A malformed body gets no answer: the connection is dropped,
            // not negotiated.
            return null;
        }
    }

    private static bool TryParseHandshake(Frame frame, out HandshakeRequest request)
    {
        try
        {
            request = HandshakeRequest.Parser.ParseFrom(frame.Payload);
            return true;
        }
        catch (InvalidProtocolBufferException)
        {
            request = new HandshakeRequest();
            return false;
        }
    }

    private async Task<(HandshakeResponse Response, HandshakeResult? Handshake)> TryHandshakeAsync(
        ImplantId implantId,
        HandshakeRequest request)
    {
        try
        {
            var result = await _handshake.HandshakeAsync(
                new HandshakeCommand(
                    ImplantId: implantId,
                    MajorVersion: request.Version?.Major ?? -1,
                    MinorVersion: request.Version?.Minor ?? -1,
                    Capabilities: request.Capabilities,
                    // No certificate rides this transport (Sec 8): the null
                    // binding is the id-alone posture, and the enrolled,
                    // kill-date, and retired gates still apply.
                    CertificateEngagementId: null,
                    ReplayNonces: request.ReplayNonces,
                    TaskAcks: request.TaskAcks,
                    SleepSeconds: request.HasSleepSeconds ? request.SleepSeconds : null,
                    JitterSeconds: request.HasJitterSeconds ? request.JitterSeconds : null),
                CancellationToken.None);
            return (BeaconHandshake.Response(
                HandshakeStatus.Ok, result.EngagementId.ToString(),
                result.ReplayNonces, result.TaskAcks), result);
        }
        catch (HandshakeException ex)
        {
            return (BeaconHandshake.Response(
                BeaconHandshake.MapStatus(ex.Reason), engagementId: null, replayNonces: false), Handshake: null);
        }
    }

    private static Frame HandshakeFrame(HandshakeResponse response)
        => new() { Payload = ByteString.CopyFrom(response.ToByteArray()) };
}
