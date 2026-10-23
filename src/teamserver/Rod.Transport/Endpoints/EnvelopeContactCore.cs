using System.Buffers.Binary;
using System.Text;
using Google.Protobuf;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Sessions;
using Rod.CoreState.Tasks;
using Rod.CoreState.Transports;
using Rod.Transport.Channels;
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
internal sealed record EnvelopeContactOptions(
    int DispatchBudget,
    CarrierCapabilities Carrier,
    string PresenceCarrier,
    bool CleartextIdentityFallback);

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
        DegradedChannelHub degraded)
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
        // whole body, counter and frames together.
        long contactCounter = 0;
        var sealedKey = (KeyId: Guid.Empty, Key: Array.Empty<byte>());
        var isSealed = false;
        var framed = body;
        if (EnvelopeBeaconContact.TryReadSealedKeyId(body, out var sealedText) is { } keyId)
        {
            var carrier = await _payloads.FindByEnvelopeKeyAsync(keyId, cancellationToken);
            if (carrier?.EnvelopeKey is not { } key
                || AesGcmEnvelope.TryUnwrap(sealedText, keyId, key, AesGcmEnvelope.ContactRequestAad)
                    is not { } plaintext
                || plaintext.Length < CounterBytes)
                return EnvelopeContactResult.Refused(
                    401, "The contact body did not verify under its artifact key.");

            contactCounter = BinaryPrimitives.ReadInt64BigEndian(plaintext);
            framed = plaintext[CounterBytes..];
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
    /// The sealed contact counter's size in bytes: an 8-byte unsigned
    /// big-endian integer, room for one fresh value per attempt for any
    /// cadence an implant will ever run.
    /// </summary>
    private const int CounterBytes = 8;
}
