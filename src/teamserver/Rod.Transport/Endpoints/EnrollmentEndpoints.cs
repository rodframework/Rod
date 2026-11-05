using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Live;
using Rod.CoreState.Deployment;
using Rod.Transport.Payloads;
using Rod.V1;

namespace Rod.Transport.Endpoints;

/// <summary>
/// The implant-side enrollment endpoint: a presenting payload redeems its
/// token and receives a certificate bound to <c>(implant_id, engagement_id)</c>
/// plus the CA chain. The engagement is resolved from the redeemed token -- a
/// real artifact carries the secret and the endpoint, not the engagement id.
///
/// Outcomes are mapped to the wire <see cref="EnrollStatus"/>: the language-
/// neutral contract lives in Rod.Protocol (architecture.md Sec 8/9), so this is
/// the layer that translates the core's redeem exceptions into status codes.
///
/// A child implant derives from a parent through the same endpoint
///architecture.md Sec 5.2: the request carries the parent implant id,
/// the service resolves and validates it against the redeemed token's
/// engagement, and the recorded linkage is echoed on the response.
///
/// The payload fetch route below is the pre-enroll half of deployment
/// (architecture.md Sec 6): an artifact presents the deployment credential its
/// own build baked, each served fetch spending one use of it, and receives
/// the payload bytes it then runs -- bytes whose own baked credential is
/// what the enrollment that follows spends.
/// </summary>
public static class EnrollmentEndpoints
{
    public static IEndpointRouteBuilder MapEnrollmentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/implants");

        group.MapPost("/enroll", EnrollAsync)
            .WithName(nameof(EnrollAsync));
        group.MapGet("/payloads/{payloadId}", FetchPayloadAsync)
            .WithName(nameof(FetchPayloadAsync));
        group.MapGet("/loaders/{payloadId}/payload", FetchLoaderPayloadAsync)
            .WithName(nameof(FetchLoaderPayloadAsync));

        return endpoints;
    }

    // Serves a loader's sealed payload: the loader half of the two-tier
    // delivery (architecture.md Sec 6), the plain fetch's exact governance
    // with the sealed delivery added. The serve lives in PayloadFetchCore;
    // this half is the HTTP adapter -- the token header, the wire facts,
    // the ingress resolution.
    private static async Task<IResult> FetchLoaderPayloadAsync(
        string payloadId,
        HttpRequest http,
        IDeployTokenService tokens,
        Rod.Transport.Listeners.IListenerRegistry listeners,
        TimeProvider clock,
        IPayloadStore payloads,
        IAuditStore audit,
        ILiveEventBus live,
        CancellationToken cancellationToken)
        => await FetchAsync(payloadId, loaderTier: true, http, tokens, listeners, clock, payloads, audit, live, cancellationToken);

    // Serves a built payload to a presenting downloader one-liner: the
    // deploy token resolves the engagement, the fetch redeems one use of
    // it, and every fetch a resolvable credential gate-keeps lands on the
    // audit trail. The serve lives in PayloadFetchCore; this half is the
    // HTTP adapter.
    private static async Task<IResult> FetchPayloadAsync(
        string payloadId,
        HttpRequest http,
        IDeployTokenService tokens,
        Rod.Transport.Listeners.IListenerRegistry listeners,
        TimeProvider clock,
        IPayloadStore payloads,
        IAuditStore audit,
        ILiveEventBus live,
        CancellationToken cancellationToken)
        => await FetchAsync(payloadId, loaderTier: false, http, tokens, listeners, clock, payloads, audit, live, cancellationToken);

    private static async Task<IResult> FetchAsync(
        string payloadId,
        bool loaderTier,
        HttpRequest http,
        IDeployTokenService tokens,
        Rod.Transport.Listeners.IListenerRegistry listeners,
        TimeProvider clock,
        IPayloadStore payloads,
        IAuditStore audit,
        ILiveEventBus live,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(payloadId, out var payloadValue))
            return Results.BadRequest(new Problem("Payload id is not a valid identifier."));

        var facts = HttpRouteFacts.Of(http);
        var ingress = await listeners.FindByLocalPortAsync(
            http.HttpContext.Connection.LocalPort, cancellationToken);
        var served = await PayloadFetchCore.ServeAsync(
            payloadValue,
            http.Headers["X-Deploy-Token"].ToString(),
            loaderTier,
            ingress,
            facts,
            tokens,
            payloads,
            audit,
            live,
            clock,
            cancellationToken);

        return served.Write(http.HttpContext);
    }

    private static async Task EnrollAsync(
        HttpContext http,
        Rod.Transport.Listeners.IListenerRegistry listeners,
        EnrollmentExchange exchange,
        CancellationToken cancellationToken)
    {
        // A browser-hooked page enrolls cross-origin (architecture.md Sec 8):
        // the browser-only CORS answer, served only when a browser asked.
        CrossOriginHttp.Allow(http);

        byte[] requestBody;
        using (var buffer = new MemoryStream())
        {
            await http.Request.Body.CopyToAsync(buffer, cancellationToken);
            requestBody = buffer.ToArray();
        }

        // The ingress this socket carries (architecture.md Sec 8): the
        // listener the local port resolves names the engagement a token must
        // belong to. The shared refusal rules, the enrollment, the audit
        // arc, and the contact key binding live in the shared exchange --
        // the same half the listener bridge's route-forward carriage drives
        // with its own listener's scope, no port to resolve. A socket the
        // registry does not know (the in-memory test harness, which binds
        // no real ports) stays token-scoped only, the shape the harness has
        // always used.
        var ingress = await listeners.FindByLocalPortAsync(
            http.Connection.LocalPort, cancellationToken);

        var answer = await exchange.HandleAsync(requestBody, ingress, cancellationToken);
        http.Response.StatusCode = answer.Status;
        http.Response.ContentType = answer.ContentType;
        await http.Response.Body.WriteAsync(answer.Body, cancellationToken);
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    public sealed record EnrollRequest(
        string DeployTokenSecret,
        string? Class = null,
        string? PublicKey = null,
        string? ParentImplantId = null,
        string? Hostname = null,
        string? Os = null,
        string? Arch = null,
        string? Username = null,
        string? KillDate = null,
        // The baked contact cadence the implant reported about itself, in
        // seconds; null on either means "not supplied", the same shape the
        // proto's optional fields carry.
        double? SleepSeconds = null,
        double? JitterSeconds = null);


    /// <summary>
    /// Mirrors the wire <see cref="Rod.V1.EnrollResponse"/>. <see cref="Status"/>
    /// is the wire enum so the JSON contract and the proto contract cannot drift.
    /// Certificate material is base64 over JSON; the proto carries raw bytes.
    /// <see cref="ParentImplantId"/> records the child's lineage
    /// server-side, implant-side: the binary wire surface carries it as
    /// <c>parent_implant_id</c>, and this JSON contract is the live producer on the
    /// HTTP enroll path.
    /// </summary>
    public sealed record EnrollmentResponse(
        EnrollStatus Status,
        string? ImplantId,
        string? EngagementId,
        string? LeafCertificate,
        string[]? CaChain,
        string? ParentImplantId = null);
}
