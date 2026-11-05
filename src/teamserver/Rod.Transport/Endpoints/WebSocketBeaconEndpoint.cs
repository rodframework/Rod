using System.Net.WebSockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Transport.Payloads;

namespace Rod.Transport.Endpoints;

// The WebSocket beacon stream (architecture.md Sec 8, the web posture's
// interactive tier): the same tasking session every live carriage runs, over a
// WebSocket on the plain-HTTP listener family -- so an implant whose only
// front is a web front can still hold the live channel (shell.interact,
// tunnel.forward, tunnel.socks) without faking it with back-to-back polls.
// The handshake, the auth, and the frame grammar are the envelope contact's
// own; the session itself lives in BeaconStreamSession, the transport-neutral
// core the listener bridge's live carriage shares (ADR-025) -- this class owns
// only the WebSocket plumbing.

/// <summary>
/// Maps the WebSocket beacon route. Mapped alongside the operator API and the
/// envelope contact on every listener like them; the identity rules are the
/// envelope's (the sealed body's artifact key over the web posture, the
/// cleartext id fallback in the lab posture only).
/// </summary>
public static class WebSocketBeaconEndpoints
{
    /// <summary>The WebSocket beacon route, in the implant family with enroll and the envelope.</summary>
    public const string Route = "/implants/beacon/stream";

    public static IEndpointRouteBuilder MapWebSocketBeaconEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(Route, async (
            HttpContext http,
            WebSocketBeaconStream stream,
            CancellationToken cancellationToken)
            => await stream.HandleAsync(http, cancellationToken))
            .WithName(nameof(WebSocketBeaconStream));
        return endpoints;
    }
}

/// <summary>
/// One WebSocket beacon stream: the message adapters around the shared
/// session core -- one message in (the receive loop, fragments accumulated
/// until EndOfMessage), one message out (the payload and its text/binary
/// shape the core computed).
/// </summary>
internal sealed class WebSocketBeaconStream
{
    private readonly BeaconStreamSession _session;

    public WebSocketBeaconStream(BeaconStreamSession session)
    {
        _session = session;
    }

    public async Task HandleAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (!http.WebSockets.IsWebSocketRequest)
        {
            http.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        using var ws = await http.WebSockets.AcceptWebSocketAsync();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var first = await ReceiveMessageAsync(ws, linked.Token);
        if (first is null)
            return;

        await _session.RunAsync(
            first,
            token => ReceiveMessageAsync(ws, token),
            (payload, text, token) => ws.SendAsync(
                payload, text ? WebSocketMessageType.Text : WebSocketMessageType.Binary,
                endOfMessage: true, token),
            cleartextFront: !http.Request.IsHttps,
            linked.Token,
            carrier: "web");
    }

    // One message in: fragments accumulate until EndOfMessage; null on a clean
    // client close, the transport's own exception on an abort.
    private static async Task<byte[]?> ReceiveMessageAsync(WebSocket ws, CancellationToken cancellationToken)
    {
        var buffer = new byte[16 * 1024];
        using var message = new MemoryStream();
        while (true)
        {
            var received = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);
            if (received.MessageType == WebSocketMessageType.Close)
                return null;
            message.Write(buffer, 0, received.Count);
            if (message.Length > BeaconStreamSession.MaxMessageBytes)
                throw new EnvelopeFramingException(oversized: true);
            if (received.EndOfMessage)
                return message.ToArray();
        }
    }
}
