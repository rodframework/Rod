using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Rod.Transport.Endpoints;

// The serving cores (hooks, lures, the payload fetch): the transport-neutral
// halves of the web families' public routes, extracted the way the enrollment
// exchange was (ADR-025) so the listener bridge's route-forward carriage can
// drive them beside the HTTP routes -- the same cores, the same audit arcs,
// the same bytes, whatever front the request crossed.

/// <summary>
/// What the wire showed a serving core: the peer address, the user agent, the
/// browser-only Origin header (present when and only when a browser asked),
/// and the listener fact the audit trail names the ingress by -- the local
/// port an HTTP route resolved, or the bridge listener's own id.
/// </summary>
internal sealed record RouteWireFacts(
    string Peer,
    string UserAgent,
    string? Origin,
    string ListenerFact);

/// <summary>
/// One served route's transport-neutral answer: the status, the content type,
/// the body, the download name an attachment carries, and the response
/// headers the route's posture adds (cache control, the browser-only CORS
/// answer). The HTTP route writes these onto its response; the bridge's
/// route-forward carriage carries them as <c>header-*</c> answer fields --
/// one answer, two transports.
/// </summary>
internal sealed record ServedRoute(
    int Status,
    string? ContentType,
    byte[] Body,
    string? FileName = null)
{
    public IReadOnlyDictionary<string, string> Headers { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public static ServedRoute Bytes(int status, string contentType, byte[] body) => new(status, contentType, body);

    public static ServedRoute NotFound() => new(404, null, []);

    public static ServedRoute Problem(int status, string detail)
        => new(status, "application/json; charset=utf-8",
            JsonSerializer.SerializeToUtf8Bytes(new Problem(detail), JsonSerializerOptions.Web));
}

/// <summary>
/// The browser-only CORS posture the web families need (architecture.md
/// Sec 8): a cross-origin <c>fetch</c> from the hooked page cannot read its
/// answer without <c>Access-Control-Allow-Origin</c> on the response. The
/// header is answered only when the request carries an <c>Origin</c> header
/// -- only browsers send one, so non-browser implant traffic and its wire
/// fingerprint are unchanged -- and the hook stays a simple-request client
/// (plain bodies, no custom headers), so no preflight is ever needed.
/// </summary>
internal static class CrossOriginHttp
{
    /// <summary>
    /// Marks this response readable cross-origin when the request came from
    /// a browser. Registers on the response's starting event so every
    /// result shape (bytes, text, JSON, problem) carries the header.
    /// </summary>
    public static void Allow(HttpContext http)
    {
        if (http.Request.Headers.Origin.Count == 0)
            return;
        http.Response.OnStarting(() =>
        {
            http.Response.Headers.AccessControlAllowOrigin = "*";
            return Task.CompletedTask;
        });
    }
}
