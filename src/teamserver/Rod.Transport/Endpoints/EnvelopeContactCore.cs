using System.Buffers.Binary;
using System.Text;
using Google.Protobuf;
using Microsoft.Extensions.Logging;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Deployment;
using Rod.CoreState.Sessions;
using Rod.CoreState.Tasks;
using Rod.CoreState.Transports;
using Rod.Transport.Channels;
using Rod.Transport.Listeners;
using Rod.Transport.Payloads;
using Rod.V1;
using Task = System.Threading.Tasks.Task;

namespace Rod.Transport.Endpoints;

// The envelope contact's transport-independent half (architecture.md
// Sec 8): the sealed-body unwrap, the handshake gates, and the
// ingest-then-dispatch composition every envelope-shaped carrier runs.
// The HTTP endpoint owns the route, the CORS posture, and the status
// mapping; a datagram carrier (the optional WireGuard transport) owns
// its socket and drops what the HTTP half would answer with a status
// code. The frames and the seal are the same bytes on either face, so
// a result captured over one is indistinguishable from the other in
// core state, the audit trail, and the live bus.
//
// A carrier that enrolls in-band (the same full-independence step the
// stream and DNS carriages took, Sec 8) names its listener in the
// contact options: the contact may then open with an EnrollRequest
// frame -- the web route's JSON body promoted into the frame grammar,
// sealed under the enroll purpose tag without a counter -- answered by
// an EnrollResponse frame and nothing else. One exchange carries one
// enrollment: the enroll message rides alone, and the frames that
// follow it arrive on the next contact, after the ordinary handshake.

/// <summary>
/// One envelope contact's outcome: the HTTP status the route maps onto
/// (or a datagram carrier drops), the problem text for the refusal
/// statuses, and the response body -- sealed when the request was.
/// </summary>
/// <param name="Status">200, 401, or 413 -- the HTTP vocabulary the
/// route carries and every other carrier reads as answered-or-refused.</param>
/// <param name="Problem">The refusal's operator-readable reason.</param>
/// <param name="Body">The response body: the reply frames, sealed when
/// the request body was.</param>
internal readonly record struct EnvelopeContactResult(
    int Status,
    string? Problem,
    byte[] Body,
    bool Sealed)
{
    public static EnvelopeContactResult Ok(byte[] body, bool sealedBody) => new(200, null, body, sealedBody);

    public static EnvelopeContactResult Refused(int status, string problem)
        => new(status, problem, Array.Empty<byte>(), false);
}

/// <summary>
/// The per-carrier facts of one contact: the dispatch budget (a wire
/// property -- a body carrier spends megabytes, a datagram carrier its
/// packet size), the carrier's capability entry for the claim gate, the
/// presence stamp the session records, and whether an unidentified
/// handshake may stand by implant id alone (the cleartext postures).
/// </summary>
/// <param name="Enrollment">
/// The in-band enrollment context, when this carrier enrolls its
/// contacts' first exchanges (the datagram shape the WireGuard transport
/// runs): the listener the contact arrived on, which scopes the
/// enrollment and its audit. Null keeps the contact path
/// handshake-only -- the HTTP route enrolls through its own web route,
/// so it passes nothing.
/// </param>
internal sealed record EnvelopeContactOptions(
    int DispatchBudget,
    CarrierCapabilities Carrier,
    string PresenceCarrier,
    bool CleartextIdentityFallback,
    EnvelopeEnrollmentContext? Enrollment = null);

/// <summary>The listener an in-band enrollment scopes itself by.</summary>
internal sealed record EnvelopeEnrollmentContext(Listener Listener);

/// <summary>
/// The shared envelope contact composition. One instance serves the
/// whole process; contacts are independent.
/// </summary>
internal sealed class EnvelopeContactCore
{
    private readonly HandshakeService _handshake;
    private readonly ISessionRegistry _sessions;
    private readonly TaskService _tasks;
    private readonly BeaconIngest _ingest;
    private readonly BeaconTasking _tasking;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;
    private readonly IPayloadStore _payloads;
    private readonly EnvelopeContactKeys _contactKeys;
    private readonly DegradedChannelHub _degraded;
    private readonly EnrollmentService _enrollment;
    private readonly IDeployTokenService _tokens;
    private readonly Rod.CoreState.Campaigns.ICampaignStore _campaigns;
    private readonly ILogger<EnvelopeContactCore> _logger;

    public EnvelopeContactCore(
        HandshakeService handshake,
        ISessionRegistry sessions,
        TaskService tasks,
        BeaconIngest ingest,
        BeaconTasking tasking,
        IAuditStore audit,
        TimeProvider clock,
        IPayloadStore payloads,
        EnvelopeContactKeys contactKeys,
        DegradedChannelHub degraded,
        EnrollmentService enrollment,
        IDeployTokenService tokens,
        Rod.CoreState.Campaigns.ICampaignStore campaigns,
        ILogger<EnvelopeContactCore> logger)
    {
        _handshake = handshake;
        _sessions = sessions;
        _tasks = tasks;
        _ingest = ingest;
        _tasking = tasking;
        _audit = audit;
        _clock = clock;
        _payloads = payloads;
        _contactKeys = contactKeys;
        _degraded = degraded;
        _enrollment = enrollment;
        _tokens = tokens;
        _campaigns = campaigns;
        _logger = logger;
    }

    /// <summary>
    /// Runs one contact: a request body of frames (sealed under the
    /// per-artifact key by default) in, the reply body out. The first
    /// frame speaks -- the handshake -- and everything after it rides
    /// the shared per-frame paths.
    /// </summary>
    public async Task<EnvelopeContactResult> ContactAsync(
        byte[] body,
        EnvelopeContactOptions options,
        CancellationToken cancellationToken)
    {
        // The sealed body (architecture.md Sec 8/9): base64 of
        // magic || keyId || nonce || ciphertext || tag, AES-256-GCM under the
        // artifact's per-build key, wrapping a strictly increasing counter
        // (8 bytes, big-endian) ahead of the framed bytes. The key id resolves
        // the key beside the stored payload; the GCM tag authenticates the
        // whole body, counter and frames together. The opening exchange of a
        // carrier that enrolls in-band may instead carry the enroll seal (no
        // counter -- the enrollment is a one-shot exchange, not a session's
        // replayable stream).
        long contactCounter = 0;
        var sealedKey = (KeyId: Guid.Empty, Key: Array.Empty<byte>());
        var isSealed = false;
        var framed = body;
        if (EnvelopeBeaconContact.TryReadSealedKeyId(body, out var sealedText) is { } keyId)
        {
            var carrier = await _payloads.FindByEnvelopeKeyAsync(keyId, cancellationToken);
            if (carrier?.EnvelopeKey is not { } key)
                return EnvelopeContactResult.Refused(
                    401, "The contact body did not verify under its artifact key.");

            byte[]? plain = null;
            if (options.Enrollment is not null)
                plain = AesGcmEnvelope.TryUnwrap(sealedText, keyId, key, AesGcmEnvelope.EnrollRequestAad);
            if (plain is null)
            {
                plain = AesGcmEnvelope.TryUnwrap(sealedText, keyId, key, AesGcmEnvelope.ContactRequestAad);
                if (plain is null || plain.Length < CounterBytes)
                    return EnvelopeContactResult.Refused(
                        401, "The contact body did not verify under its artifact key.");
                contactCounter = BinaryPrimitives.ReadInt64BigEndian(plain);
                framed = plain[CounterBytes..];
            }
            else
            {
                framed = plain;
            }
            sealedKey = (keyId, key);
            isSealed = true;
        }

        // Every envelope response after a verified unwrap seals the same way,
        // handshake refusals included: the sealed client must be able to read
        // its own refusal statuses, and the carrier leaks no frame bytes in
        // either direction.
        byte[] Reply(IReadOnlyList<Frame> outbound)
            => isSealed
                ? Encoding.UTF8.GetBytes(
                    AesGcmEnvelope.Wrap(
                        EnvelopeFraming.Encode(outbound), sealedKey.KeyId, sealedKey.Key,
                        AesGcmEnvelope.ContactResponseAad))
                : EnvelopeFraming.Encode(outbound);

        List<Frame> frames;
        try
        {
            frames = EnvelopeFraming.Parse(framed);
        }
        catch (EnvelopeFramingException ex)
        {
            return ex.Oversized
                ? EnvelopeContactResult.Refused(413, "The request body is too large for the contact.")
                : EnvelopeContactResult.Refused(400, "The request body is not a delimited frame sequence.");
        }

        // The in-band enrollment arm (Sec 8, the stream carriage's own
        // full-independence step on the envelope's frames): an opening
        // EnrollRequest frame is the whole exchange -- answered by one
        // EnrollResponse frame, acceptance or refusal both, and nothing
        // behind it rides this contact. The handshake that follows an
        // acceptance arrives as the next contact's opening frame, the
        // datagram discipline's one-exchange-per-contact shape.
        if (frames.Count > 0
            && frames[0].Kind == FrameKind.EnrollRequest
            && options.Enrollment is { } enrollment)
        {
            return await AnswerEnrollmentAsync(
                frames[0], enrollment.Listener, sealedKey, isSealed, cancellationToken);
        }

        // The implant speaks first here too: the first frame is the handshake.
        HandshakeRequest handshakeRequest;
        if (frames.Count == 0 || !EnvelopeBeaconContact.TryParseHandshake(frames[0], out handshakeRequest))
            return EnvelopeContactResult.Ok(Reply(new[] { EnvelopeBeaconContact.HandshakeFrame(BeaconHandshake.Response(HandshakeStatus.Unspecified, engagementId: null, replayNonces: false)) }), isSealed);

        // The key posture gates, checked before the handshake opens anything:
        // an implant bound to a build key at enroll contacts sealed under
        // exactly that key (a plaintext body from it is the refused downgrade;
        // another artifact's key does not impersonate it), and the counter
        // must clear the floor -- a replayed body, whatever it claims, turns
        // away without a session, a touch, or an audit record.
        if (ImplantId.TryParse(handshakeRequest.ImplantId, out var sealedImplant))
        {
            if (_contactKeys.TryGet(sealedImplant) is { } bound)
            {
                if (!isSealed)
                    return EnvelopeContactResult.Refused(
                        401, "This implant contacts under its artifact key; the plaintext frame body is refused.");
                if (sealedKey.KeyId != bound.KeyId)
                    return EnvelopeContactResult.Refused(
                        401, "The contact body did not verify under its artifact key.");
            }
            if (isSealed && !_contactKeys.Accept(sealedImplant, contactCounter))
                return EnvelopeContactResult.Refused(
                    401, "The contact body carries a counter at or below the accepted floor.");
        }

        // The identity for the handshake: the handshake's implant id, which
        // the sealed body authenticated above and which stands by reach only
        // in the cleartext postures (the anything-with-reach tradeoff those
        // carriers document).
        var (response, handshake) = await EnvelopeBeaconContact.TryHandshakeAsync(
            _handshake, handshakeRequest, options.CleartextIdentityFallback || isSealed);
        if (response.Status != HandshakeStatus.Ok || handshake is null)
            return EnvelopeContactResult.Ok(Reply(new[] { EnvelopeBeaconContact.HandshakeFrame(response) }), isSealed);

        // A genuinely new session is recorded; a reused one (every contact
        // after the first) is not, the same flood guard the stream applies
        // (architecture.md Sec 10.3, Sec 11).
        await BeaconHandshake.AppendSessionOpenedAsync(_audit, handshake, handshakeRequest);

        // The session context carries the handshake's identity (the implant
        // the handshake authenticated).
        var session = new BeaconSessionContext(
            handshake.ImplantId,
            handshake.EngagementId,
            handshake.SessionId,
            handshake.DeployedBy,
            handshakeRequest.Capabilities,
            handshakeRequest.TaskAcks);

        // One presence touch per contact -- a contact is the poll-cadence unit
        // here, not the individual frame. Then the session guard: if the
        // session this handshake holds was closed out from under it, stop
        // after the handshake response so the implant re-handshakes on its
        // next cycle.
        await _sessions.TouchAsync(session.Implant, session.Capabilities, _clock.GetUtcNow(), options.PresenceCarrier, cancellationToken);
        var active = await _sessions.GetActiveAsync(session.Implant, cancellationToken);
        if (active is null || active.Id != session.SessionId)
            return EnvelopeContactResult.Ok(Reply(new[] { EnvelopeBeaconContact.HandshakeFrame(response) }), isSealed);

        var outbound = new List<Frame> { EnvelopeBeaconContact.HandshakeFrame(response) };

        // Ingest the request's remaining frames (results, exfil chunks, staged
        // pulls, channel output) through the shared composition, collecting
        // validated staged demands for the response. The receive-ack frames a
        // negotiated implant sends are accepted here and handed to a no-op
        // sink: a poll carrier keeps no ack ledger -- its contact either
        // completed whole or answered nothing -- so the arm's requeue never
        // applies on this path (architecture.md Sec 10.3).
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

        // The exfil seam reports ride ahead of the staged runs and tasking:
        // offset-bearing chunks placed this contact answer with the byte
        // count the server holds, so the sender's next body serves only the
        // unheld remainder (ADR-010's upload arm).
        outbound.AddRange(connection.TakeExfilProgress());

        // Answer each demand with its chunk run in this response, before any
        // new tasking: the implant is blocked on bytes it already accepted a
        // task for (architecture.md Sec 10, the typed arm). A resumed demand
        // (ADR-010) is answered from the offset it proved, so an interrupted
        // run costs the unserved remainder, not the whole payload. The run
        // budget splits evenly across the demands -- every pending transfer
        // takes its share of progress each contact, so none starves against
        // the implant's idle bound -- and a run larger than the share ends
        // short of terminal and spans contacts through that same resume
        // discipline.
        var share = Math.Max(
            BeaconTasking.StagedChunkSize,
            BeaconTasking.MaxStagedRunBytes / Math.Max(1, stagedPulls.Count));
        foreach (var pull in stagedPulls)
            outbound.AddRange(await _tasking.StagedChunkRunAsync(
                pull.Task.Value, pull.Offset, pull.PrefixSha256, share, cancellationToken));

        // Dispatch queued tasking while the budget lasts. The claim
        // evaluation every poll carrier runs decides what fits: a channel
        // verb claims only under the degraded discipline -- the session's
        // opt-in -- and without it parks, requeued for a stream transport
        // to claim (architecture.md Sec 10.3). A requeued task joins the
        // skip set for the rest of this contact, so a task this carrier
        // cannot serve parks without standing at the queue head and
        // starving the tasks behind it.
        var degraded = session.Capabilities.Contains(DegradedChannelHub.Capability);
        var budget = options.DispatchBudget;
        var skipped = new HashSet<TaskId>();
        while (true)
        {
            var dispatched = await _tasks.DispatchNextAsync(session.Implant, cancellationToken, exclude: skipped);
            if (dispatched is null)
                break;

            var frame = await _tasking.MarshalFrameAsync(dispatched, cancellationToken);
            var wireSize = EnvelopeFraming.WireSize(frame);

            if (TransportCapabilities.EvaluateClaim(
                    options.Carrier, dispatched.Verb, wireSize, budget, degraded)
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

        // The store-and-forward half: parked operator input rides after the
        // tasking, as ChannelInput frames within the budget the tasking left
        // -- the poll cycle's answer to the live stream's input pump. The
        // sweep on the way closes channels the implant stopped collecting.
        if (degraded)
        {
            await _degraded.SweepIdleAsync(cancellationToken);
            outbound.AddRange(_degraded.Drain(session.Implant, budget));
        }

        return EnvelopeContactResult.Ok(Reply(outbound), isSealed);
    }

    /// <summary>
    /// The in-band enrollment exchange (Sec 8): a kind-bearing
    /// EnrollRequest frame -- the enroll body the web route carries as
    /// JSON, promoted into the rod.v1 frame grammar -- answered by an
    /// EnrollResponse frame under the enroll response purpose tag when
    /// the request sealed. The shared ScopedEnrollment flow does the
    /// work every ingress drives, scoped by the listener this contact
    /// arrived on, with the same refusal rules and audit arc. A refusal
    /// answers its status frame; an acceptance is followed by the
    /// ordinary handshake on the carrier's next contact.
    /// </summary>
    private async Task<EnvelopeContactResult> AnswerEnrollmentAsync(
        Frame frame,
        Listener listener,
        (Guid KeyId, byte[] Key) sealedKey,
        bool isSealed,
        CancellationToken cancellationToken)
    {
        Rod.V1.EnrollRequest request;
        try
        {
            request = Rod.V1.EnrollRequest.Parser.ParseFrom(frame.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return EnvelopeContactResult.Ok(
                EnrollReply(new Rod.V1.EnrollResponse { Status = EnrollStatus.Unspecified }, sealedKey, isSealed),
                isSealed);
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

        // The token states carry over the wire; the problem causes (a
        // malformed request, a closed engagement) collapse to the generic
        // refusal -- the same "no signal beyond no" the web route keeps --
        // with the cause named server-side.
        if (!outcome.Accepted)
        {
            if (outcome.Problem is { } problem)
                _logger.LogInformation("Enroll refused on listener {Name}: {Problem}.", listener.Name, problem);
            else
                _logger.LogInformation(
                    "Enroll refused on listener {Name}: status {Status}.", listener.Name, outcome.Status);
        }
        else
        {
            _logger.LogInformation(
                "Listener {Name} enrolled implant {Implant} into {Engagement} over an in-band contact.",
                listener.Name, outcome.Enrolled!.ImplantId, outcome.Enrolled.EngagementId);
        }

        return EnvelopeContactResult.Ok(
            EnrollReply(ScopedEnrollmentResponse.Build(outcome), sealedKey, isSealed),
            isSealed);
    }

    // One enrollment answer body: the framed EnrollResponse, sealed under
    // the enroll response purpose tag when the request sealed -- the wire
    // carries no readable frame bytes in either direction.
    private static byte[] EnrollReply(
        Rod.V1.EnrollResponse response, (Guid KeyId, byte[] Key) sealedKey, bool isSealed)
    {
        var body = EnvelopeFraming.Encode(new[]
        {
            new Frame { Kind = FrameKind.EnrollResponse, Payload = ByteString.CopyFrom(response.ToByteArray()) },
        });
        return isSealed
            ? Encoding.UTF8.GetBytes(
                AesGcmEnvelope.Wrap(body, sealedKey.KeyId, sealedKey.Key, AesGcmEnvelope.EnrollResponseAad))
            : body;
    }

    private static string? NullWhenEmpty(string value)
        => value.Length == 0 ? null : value;

    /// <summary>
    /// The sealed contact counter's size in bytes: an 8-byte unsigned
    /// big-endian integer, room for one fresh value per attempt for any
    /// cadence an implant will ever run.
    /// </summary>
    private const int CounterBytes = 8;
}
