using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.Transport.Listeners;

namespace Rod.Transport.Endpoints;

// The browser-hook serving edge (architecture.md Sec 8): the public route a
// victim's browser fetches. The unguessable route id is the credential --
// the shape where the capability URL is the gate -- so the route serves
// without a header, a token, or any ceremony a `<script src>` cannot carry.
// The listener scope check still applies: the ingress socket must answer
// for the hook record's engagement, the same refusal the enroll and payload
// fetch routes run, so a shared-tier socket (the operator front) carries no
// hook either.
//
// Because the hook runs on the victim page's origin, every fetch and every
// enroll/contact it makes afterwards is cross-origin: the hook family (and
// the enroll and beacon routes it rides) answer the browser-only CORS
// header, but only when the request itself carries an Origin header -- a
// non-browser client never sends one, so implant traffic and its fingerprint
// are unchanged.
//
// The serve itself lives in HookServingCore: the transport-neutral half the
// listener bridge's route-forward carriage drives beside this route.

/// <summary>
/// Maps the hook serving routes onto the implant family.
/// </summary>
public static class HookServingEndpoints
{
    /// <summary>The hook script route, in the implant family with enroll.</summary>
    public const string Route = "/implants/hooks/{hookId}";

    public static IEndpointRouteBuilder MapHookServingEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(Route, FetchHookAsync).WithName(nameof(FetchHookAsync));
        endpoints.MapGet(Route + "/page", FetchHookPageAsync).WithName(nameof(FetchHookPageAsync));
        return endpoints;
    }

    private static async Task<IResult> FetchHookAsync(
        string hookId,
        HttpRequest http,
        IListenerRegistry listeners,
        IPayloadStore payloads,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
        => await ServeAsync(hookId, page: false, http, listeners, payloads, audit, clock, cancellationToken);

    private static async Task<IResult> FetchHookPageAsync(
        string hookId,
        HttpRequest http,
        IListenerRegistry listeners,
        IPayloadStore payloads,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
        => await ServeAsync(hookId, page: true, http, listeners, payloads, audit, clock, cancellationToken);

    private static async Task<IResult> ServeAsync(
        string hookId,
        bool page,
        HttpRequest http,
        IListenerRegistry listeners,
        IPayloadStore payloads,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(hookId, out var hookValue))
            return Results.BadRequest(new Problem("Hook id is not a valid identifier."));

        var facts = HttpRouteFacts.Of(http);
        var ingress = await listeners.FindByLocalPortAsync(
            http.HttpContext.Connection.LocalPort, cancellationToken);
        var served = await HookServingCore.ServeAsync(
            hookValue, page, ingress, facts, payloads, audit, clock, cancellationToken);

        return served.Write(http.HttpContext);
    }
}

/// <summary>
/// The HTTP route's wire facts and the response writer: the adapter between
/// the serving cores' transport-neutral answers and an ASP.NET request --
/// the same two halves the bridge's route-forward carriage carries as
/// request fields and answer fields.
/// </summary>
internal static class HttpRouteFacts
{
    // What the wire showed an HTTP request: the peer, the user agent, the
    // browser-only Origin, and the listener fact the audit payloads name the
    // ingress by -- the local port.
    public static RouteWireFacts Of(HttpRequest http)
    {
        var remote = http.HttpContext.Connection.RemoteIpAddress is { } remoteIp
            ? $"{remoteIp}:{http.HttpContext.Connection.RemotePort}"
            : "unknown";
        return new RouteWireFacts(
            remote,
            http.Headers.UserAgent.ToString(),
            http.Headers.Origin.Count > 0 ? http.Headers.Origin.ToString() : null,
            $"listenerPort={http.HttpContext.Connection.LocalPort}");
    }

    /// <summary>Writes one serving core's answer onto the response: status,
    /// content type, the posture's headers, the body, and the download name
    /// an attachment carries.</summary>
    public static IResult Write(this ServedRoute served, HttpContext http)
    {
        http.Response.StatusCode = served.Status;
        foreach (var (name, value) in served.Headers)
            http.Response.Headers[name] = value;
        if (served.Status == StatusCodes.Status404NotFound && served.ContentType is null)
            return Results.NotFound();
        if (served.FileName is { } fileName)
            return Results.File(served.Body, served.ContentType, fileName);
        if (served.ContentType is null)
            return Results.StatusCode(served.Status);
        return Results.Bytes(served.Body, served.ContentType);
    }
}
