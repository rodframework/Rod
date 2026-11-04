using Microsoft.Extensions.Logging;
using Rod.CoreState.Transports;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners.Streams;

namespace Rod.Transport.Listeners.Bridge;

// The route-forward carriage's kernel half (ADR-025, the https shape): one
// duplex connection per medium peer carrying request/answer units
// dispatched by path. The routes are the implant family's own -- the JSON
// enroll exchange and the envelope contact -- driven through the same
// cores the HTTP routes drive, so a contact that crossed the bridge is
// indistinguishable in core state, the audit trail, and the live bus from
// one that crossed Kestrel. The scope is the peer: this bridge belongs to
// one listener, known directly, no local port to resolve.
//
// The web families' asset routes (hooks, lures, artifact fetch) are the
// same carriage's later arms: the unit already carries the method, the
// path, and the observed peer facts they audit by, and the answers carry
// a content type -- the https listener package lands them here without a
// carriage change.

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
            byte[] unit;
            try
            {
                unit = await StreamContactFraming.ReadMessageAsync(stream, stoppingToken);
            }
            catch (Exception ex) when (
                ex is IOException or OperationCanceledException or ObjectDisposedException
                or System.Net.Sockets.SocketException)
            {
                // The peer went or the listener is stopping: the connection
                // ends, and the peer's next request reconnects.
                return;
            }

            (int Status, string ContentType, byte[] Body) answer;
            if (!BridgeRouteProtocol.TryDecodeRequest(
                    unit, out var method, out var path, out _, out _, out var body))
            {
                return;
            }

            try
            {
                answer = await DispatchAsync(method, path, body, listener, cleartextFallback, stoppingToken);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogInformation(
                    ex, "Bridge route dispatch failed on listener {Name} for {Path}.", listener.Name, path);
                answer = (502, "application/json; charset=utf-8",
                    System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
                        new Problem("The forwarded request could not be served."),
                        System.Text.Json.JsonSerializerOptions.Web));
            }

            try
            {
                await StreamContactFraming.WriteMessageAsync(
                    stream, BridgeRouteProtocol.EncodeResponse(answer.Status, answer.ContentType, answer.Body),
                    stoppingToken);
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
        byte method,
        string path,
        byte[] body,
        Listener listener,
        bool cleartextFallback,
        CancellationToken cancellationToken)
    {
        if (method == BridgeRouteProtocol.MethodPost
            && string.Equals(path, "/implants/enroll", StringComparison.Ordinal))
        {
            var enroll = await _enrollment.HandleAsync(body, listener, cancellationToken);
            return (enroll.Status, enroll.ContentType, enroll.Body);
        }

        if (method == BridgeRouteProtocol.MethodPost
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
                401 => (
                    401,
                    "application/json; charset=utf-8",
                    System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
                        new Problem(contact.Problem ?? "The contact was refused."),
                        System.Text.Json.JsonSerializerOptions.Web)),
                413 => (413, "application/octet-stream", []),
                _ => (
                    400,
                    "application/json; charset=utf-8",
                    System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
                        new Problem(contact.Problem ?? "The request body was refused."),
                        System.Text.Json.JsonSerializerOptions.Web)),
            };
        }

        return (
            404,
            "application/json; charset=utf-8",
            System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
                new Problem("No such route on this listener's bridge."),
                System.Text.Json.JsonSerializerOptions.Web));
    }
}
