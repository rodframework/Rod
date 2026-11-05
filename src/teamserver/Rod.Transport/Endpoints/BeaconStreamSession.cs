using System.Buffers.Binary;
using System.Text;
using Google.Protobuf;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Pki;
using Rod.CoreState.Sessions;
using Rod.CoreState.Tasks;
using Rod.Transport.Channels;
using Rod.Transport.Payloads;
using Rod.V1;
// The domain entity shares its name with the BCL Task; pin Task to the BCL
// type the signatures need, as every file mixing both namespaces does.
using Task = System.Threading.Tasks.Task;

namespace Rod.Transport.Endpoints;

// The beacon stream session (architecture.md Sec 8, the web posture's
// interactive tier): the transport-neutral half of the live tasking session.
// The handshake, the auth, the frame grammar, and the session-key agreement
// are the envelope contact's own, message-shaped instead of body-shaped --
// every message carries the same sealed-or-plaintext framed-frames body the
// envelope POST does, so the per-artifact key authenticates and seals on
// every front, and an implant that speaks the envelope already speaks
// everything but the socket.
//
// Two transports drive this core: the WebSocket route (its message loop and
// per-message sealing) and the listener bridge's route-forward session (the
// externalized listener's live carriage, ADR-025). Each supplies the first
// message, a receive loop, a send sink, and the front's cleartext posture;
// the session is the same in core state, the audit trail, and the live bus
// on either.

/// <summary>
/// One live beacon session over a message-shaped transport. Constructed per
/// host from the DI services the session's halves share; run once per
/// connection.
/// </summary>
internal sealed class BeaconStreamSession
{
    // One message's frame budget: the envelope's wire-body cap governs a POST
    // body; a stream message gets the same ceiling here so a runaway client
    // cannot pin memory a POST could not.
    internal const int MaxMessageBytes = 8 * 1024 * 1024;

    private static readonly ReadOnlyMemory<byte> CounterZero = new byte[8];

    private readonly HandshakeService _handshake;
    private readonly ISessionRegistry _sessions;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;
    private readonly IPayloadStore _payloads;
    private readonly EnvelopeContactKeys _contactKeys;
    private readonly SessionSealKeys _sessionKeys;
    private readonly BeaconSessionRunner _runner;

    public BeaconStreamSession(
        HandshakeService handshake,
        ISessionRegistry sessions,
        TaskService tasks,
        IAuditStore audit,
        TimeProvider clock,
        ITaskDispatchWake wake,
        LiveChannelHub channels,
        Rod.Transport.Channels.DegradedChannelHub degraded,
        TaskRelayHub relays,
        SocksProxyHub socks,
        ChainHub chain,
        BeaconIngest ingest,
        BeaconTasking tasking,
        IPayloadStore payloads,
        EnvelopeContactKeys contactKeys,
        SessionSealKeys sessionKeys)
    {
        _handshake = handshake;
        _sessions = sessions;
        _audit = audit;
        _clock = clock;
        _payloads = payloads;
        _contactKeys = contactKeys;
        _sessionKeys = sessionKeys;
        _runner = new BeaconSessionRunner(
            sessions, tasks, clock, wake, channels, degraded, relays, socks, chain, ingest, tasking);
    }

    /// <summary>
    /// Runs one live session: <paramref name="receiveAsync"/> answers the
    /// next message's bytes (null when the peer closed), and
    /// <paramref name="sendAsync"/> writes one message the transport shapes
    /// itself -- the payload and whether it is text (a base64 seal) or
    /// binary (plaintext frames), the two shapes every message-carrying
    /// medium distinguishes.
    /// </summary>
    /// <param name="firstMessage">
    /// The contact body the first message carried: the sealed envelope under
    /// the per-artifact key, or the plaintext framed frames of the lab
    /// posture.
    /// </param>
    /// <param name="cleartextFront">
    /// The front the peer dialed was cleartext -- the lab posture an
    /// id-only handshake may stand on. The WebSocket route reads its
    /// request's scheme; the bridge reads its listener's public endpoint.
    /// </param>
    public async Task RunAsync(
        byte[] firstMessage,
        Func<CancellationToken, Task<byte[]?>> receiveAsync,
        Func<byte[], bool, CancellationToken, Task> sendAsync,
        bool cleartextFront,
        CancellationToken cancellationToken,
        string carrier = "web")
    {
        // Send one frame batch: sealed under the session's response key once
        // the connection agreed one, else under the artifact key when the
        // session sealed (text carrying the base64 envelope, the same shape
        // the envelope route replies with), raw binary otherwise.
        async Task SendFramesAsync(
            bool sealedBody, IReadOnlyList<Frame> frames,
            (Guid KeyId, byte[] Key) sealedKey, SessionSealKeys.Entry? sessionKeys,
            CancellationToken token)
        {
            byte[] payload;
            bool text;
            if (sessionKeys is { } session)
            {
                payload = Encoding.UTF8.GetBytes(AesGcmEnvelope.WrapSession(
                    EnvelopeFraming.Encode(frames), session.SessionId, session.ResponseKey,
                    AesGcmEnvelope.ContactResponseAad));
                text = true;
            }
            else if (sealedBody)
            {
                payload = Encoding.UTF8.GetBytes(AesGcmEnvelope.Wrap(
                    EnvelopeFraming.Encode(frames), sealedKey.KeyId, sealedKey.Key,
                    AesGcmEnvelope.ContactResponseAad));
                text = true;
            }
            else
            {
                payload = EnvelopeFraming.Encode(frames);
                text = false;
            }
            await sendAsync(payload, text, token);
        }

        // 1. The first message is the contact body the envelope route reads.
        long contactCounter = 0;
        var sealedKey = (KeyId: Guid.Empty, Key: Array.Empty<byte>());
        SessionSealKeys.Entry? sessionKeys = null;
        var isSealed = false;
        var framed = firstMessage;
        if (EnvelopeBeaconContact.TryReadSealedKeyId(firstMessage, out var sealedText) is { } keyId)
        {
            var keyCarrier = await _payloads.FindByEnvelopeKeyAsync(keyId, cancellationToken);
            if (keyCarrier?.EnvelopeKey is not { } artifactKey
                || AesGcmEnvelope.TryUnwrap(sealedText, keyId, artifactKey, AesGcmEnvelope.ContactRequestAad)
                is not { } plaintext
                || plaintext.Length < CounterZero.Length)
            {
                // The unwrap failed, so there is nothing to seal a refusal
                // under: the raw unspecified refusal leaks only the status.
                await SendFramesAsync(sealedBody: false,
                    new[] { EnvelopeBeaconContact.HandshakeFrame(
                        BeaconHandshake.Response(HandshakeStatus.Unspecified, engagementId: null, replayNonces: false)) },
                    sealedKey, sessionKeys: null, cancellationToken);
                return;
            }
            contactCounter = BinaryPrimitives.ReadInt64BigEndian(plaintext);
            framed = plaintext[CounterZero.Length..];
            sealedKey = (keyId, artifactKey);
            isSealed = true;
        }
        else if (EnvelopeBeaconContact.TryReadSessionSealedKeyId(firstMessage, out var sessionText) is { } sessionId)
        {
            // The R2 body (Sec 9, session key agreement): the session id
            // addresses an agreement this process made. None to find -- a
            // restart, or a session this teamserver never agreed -- is the
            // dropped connection: no response the client could mistake for a
            // verdict, so its reconnect runs the agreement again.
            var entry = _sessionKeys.TryGet(sessionId);
            if (entry is null)
                return;
            if (AesGcmEnvelope.TryUnwrapSession(sessionText, sessionId, entry.RequestKey, AesGcmEnvelope.ContactRequestAad)
                is not { } plaintext
                || plaintext.Length < CounterZero.Length)
                return;
            contactCounter = BinaryPrimitives.ReadInt64BigEndian(plaintext);
            framed = plaintext[CounterZero.Length..];
            sessionKeys = entry;
            isSealed = true;
        }

        // 2. The handshake -- the same parse, gates, and identity rules the
        // envelope applies, because this is the same posture on a different
        // socket.
        List<Frame> frames;
        try
        {
            frames = EnvelopeFraming.Parse(framed);
        }
        catch (EnvelopeFramingException)
        {
            return; // A malformed body gets no answer; the connection ends.
        }

        if (frames.Count == 0 || !EnvelopeBeaconContact.TryParseHandshake(frames[0], out var handshakeRequest))
        {
            await SendFramesAsync(isSealed, new[] { EnvelopeBeaconContact.HandshakeFrame(
                BeaconHandshake.Response(HandshakeStatus.Unspecified, engagementId: null, replayNonces: false)) },
                sealedKey, sessionKeys, cancellationToken);
            return;
        }

        // The key posture gates, the envelope's own: a key-bound implant must
        // arrive sealed under exactly its bound key, and the counter must
        // clear the accepted floor. An R2 body authenticates by the session
        // it opened under, so the baked-key check stands down for it while
        // the session it addressed must still be this implant's own. The
        // session-key arm's contract violations (an offer on a session body,
        // an offer with frames riding, an ordinary baked-key body from an
        // implant holding an agreed session) are dropped connections -- the
        // raw carriage's refusal, one the client's reconnect answers with a
        // fresh agreement contact.
        var offeredAgreement = false;
        if (ImplantId.TryParse(handshakeRequest.ImplantId, out var sealedImplant))
        {
            if (_contactKeys.TryGet(sealedImplant) is { } bound)
            {
                if (!isSealed || (sessionKeys is null && sealedKey.KeyId != bound.KeyId))
                {
                    await SendFramesAsync(isSealed, new[] { EnvelopeBeaconContact.HandshakeFrame(
                        BeaconHandshake.Response(HandshakeStatus.Unspecified, engagementId: null, replayNonces: false)) },
                        sealedKey, sessionKeys, cancellationToken);
                    return;
                }
            }
            if (sessionKeys is { } opened && opened.Implant != sealedImplant)
                return;
            // The arm's contract refusals sit ahead of the floor on purpose:
            // a refused posture must not advance it, or the forgery would
            // lock the honest contact out of its counter.
            if (sessionKeys is not null && handshakeRequest.HasSessionPublic && handshakeRequest.SessionPublic.Length > 0)
                return;
            offeredAgreement = sessionKeys is null
                && isSealed
                && handshakeRequest.HasSessionPublic
                && handshakeRequest.SessionPublic.Length > 0
                && sealedKey.Key.Length == AesGcmEnvelope.KeyBytes;
            if (offeredAgreement && frames.Count > 1)
                return;
            if (!offeredAgreement
                && sessionKeys is null
                && isSealed
                && sealedKey.KeyId != Guid.Empty
                && _sessionKeys.TryLatest(sealedImplant) is not null)
                return;
            if (isSealed && !_contactKeys.Accept(sealedImplant, contactCounter))
            {
                await SendFramesAsync(isSealed, new[] { EnvelopeBeaconContact.HandshakeFrame(
                    BeaconHandshake.Response(HandshakeStatus.Unspecified, engagementId: null, replayNonces: false)) },
                    sealedKey, sessionKeys, cancellationToken);
                return;
            }
        }

        // The handshake's identity binding: no transport certificate exists
        // anywhere in the surface (the per-artifact key is the identity), so
        // the binding is the sealed body's posture -- which stands by reach
        // alone only in the cleartext lab shape.
        var (response, handshake) = await EnvelopeBeaconContact.TryHandshakeAsync(
            _handshake, handshakeRequest, isSealed || cleartextFront);

        // The agreement exchange (Sec 9): the server's ephemeral rides the
        // handshake response sealed under the baked key -- the last body that
        // key opens -- and every message after it on this connection seals
        // under the session keys. An offer the schedule cannot take answers
        // without the echo and keeps the baked-key seal.
        if (offeredAgreement
            && handshake is not null
            && _sessionKeys.Agree(
                handshake.ImplantId, sealedKey.KeyId, sealedKey.Key, handshakeRequest.SessionPublic.Span)
                is { } agreement)
        {
            response.SessionPublic = ByteString.CopyFrom(agreement.ServerPublic);
            await SendFramesAsync(isSealed, new[] { EnvelopeBeaconContact.HandshakeFrame(response) },
                sealedKey, sessionKeys: null, cancellationToken);
            sessionKeys = agreement.Entry;
        }
        else
        {
            await SendFramesAsync(isSealed, new[] { EnvelopeBeaconContact.HandshakeFrame(response) },
                sealedKey, sessionKeys, cancellationToken);
        }
        if (response.Status != HandshakeStatus.Ok || handshake is null)
            return;

        // A genuinely new session is recorded; a reused one is not -- the same
        // flood guard the envelope contact applies
        // (architecture.md Sec 10.3, Sec 11).
        await BeaconHandshake.AppendSessionOpenedAsync(_audit, handshake, handshakeRequest);

        var session = new BeaconSessionContext(
            handshake.ImplantId,
            handshake.EngagementId,
            handshake.SessionId,
            handshake.DeployedBy,
            handshakeRequest.Capabilities,
            handshakeRequest.TaskAcks);

        // The same session guard the envelope applies: a session closed out
        // from under this handshake ends the stream before the loop starts,
        // so the implant re-handshakes on its reconnect.
        await _sessions.TouchAsync(session.Implant, session.Capabilities, _clock.GetUtcNow(), carrier, cancellationToken);
        var active = await _sessions.GetActiveAsync(session.Implant, cancellationToken);
        if (active is null || active.Id != session.SessionId)
            return;

        // 3. The live session: the shared runner over message adapters. Each
        //    message unwraps (and floor-checks its counter) exactly like the
        //    envelope's request body -- under the session keys once the
        //    connection agreed them, under the baked key otherwise; each
        //    frame leaves as its own message, sealed the same way.
        var pending = new Queue<Frame>();
        await _runner.RunAsync(
            session,
            async token =>
            {
                while (pending.Count == 0)
                {
                    var message = await receiveAsync(token);
                    if (message is null)
                        return null;
                    if (message.Length > MaxMessageBytes)
                        throw new EnvelopeFramingException(oversized: true);
                    byte[] plaintext;
                    if (sessionKeys is { } live)
                    {
                        if (EnvelopeBeaconContact.TryReadSessionSealedKeyId(message, out var messageSession) is not { } messageSessionId
                            || messageSessionId != live.SessionId
                            || AesGcmEnvelope.TryUnwrapSession(messageSession, live.SessionId, live.RequestKey, AesGcmEnvelope.ContactRequestAad)
                                is not { } unsealed
                            || unsealed.Length < CounterZero.Length
                            || !_contactKeys.Accept(session.Implant, BinaryPrimitives.ReadInt64BigEndian(unsealed)))
                            throw new InvalidOperationException("A sealed message did not verify under its session key.");
                        plaintext = unsealed[CounterZero.Length..];
                    }
                    else if (isSealed)
                    {
                        if (EnvelopeBeaconContact.TryReadSealedKeyId(message, out var messageSealed) is not { } messageKey
                            || messageKey != sealedKey.KeyId
                            || AesGcmEnvelope.TryUnwrap(messageSealed, sealedKey.KeyId, sealedKey.Key, AesGcmEnvelope.ContactRequestAad)
                                is not { } unsealed
                            || unsealed.Length < CounterZero.Length
                            || !_contactKeys.Accept(session.Implant, BinaryPrimitives.ReadInt64BigEndian(unsealed)))
                            throw new InvalidOperationException("A sealed message did not verify under its artifact key.");
                        plaintext = unsealed[CounterZero.Length..];
                    }
                    else
                    {
                        plaintext = message;
                    }
                    foreach (var frame in EnvelopeFraming.Parse(plaintext))
                        pending.Enqueue(frame);
                }
                return pending.Dequeue();
            },
            (frame, token) => SendFramesAsync(isSealed, new[] { frame }, sealedKey, sessionKeys, token),
            cancellationToken,
            carrier: carrier);
    }
}
