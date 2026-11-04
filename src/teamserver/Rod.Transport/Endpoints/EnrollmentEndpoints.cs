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
    // delivery (architecture.md Sec 6). The route's id names the loader
    // artifact itself -- the fetch path a loader bakes -- and the loader's
    // record carries the payload it delivers plus the seal key the loader
    // bakes. The serve is the payload fetch's exact governance (token gate,
    // engagement scope, redeem only on a serve, the audit fact with the
    // fetcher's wire shape) with one addition: the bytes leave sealed, an
    // R1 body under the loader payload AAD and a fresh nonce, so nothing on
    // the wire between front and target is readable or forgeable without
    // the loader's own baked key. A loader whose record lost its key or its
    // delivered payload serves nothing -- a deleted half is a dead
    // delivery, recorded as such.
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
    {
        var secret = http.Headers["X-Deploy-Token"].ToString();
        if (string.IsNullOrWhiteSpace(secret))
            return Results.Json(
                new Problem("X-Deploy-Token header is required."),
                statusCode: StatusCodes.Status401Unauthorized);
        if (!Guid.TryParse(payloadId, out var payloadValue))
            return Results.BadRequest(new Problem("Payload id is not a valid identifier."));

        var remote = http.HttpContext.Connection.RemoteIpAddress is { } remoteIp
            ? $"{remoteIp}:{http.HttpContext.Connection.RemotePort}"
            : "unknown";
        var userAgent = http.Headers.UserAgent.ToString();
        var fetcher = $"remote={remote} listenerPort={http.HttpContext.Connection.LocalPort} "
            + $"ua={(string.IsNullOrWhiteSpace(userAgent) ? "none" : userAgent)}";

        try
        {
            var token = await tokens.VerifyAsync(secret, clock.GetUtcNow(), cancellationToken);
            if (!await TokenMatchesListenerScopeAsync(http, listeners, token, cancellationToken))
            {
                await RecordFetchAsync(audit, clock, token.EngagementId, token.Id, payloadValue,
                    fetcher, "refused:scope", cancellationToken: cancellationToken);
                return Results.Json(
                    new Problem("Deploy token was not accepted."),
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            // The loader record: the id a loader bakes is its own, and the
            // record's stage reference is what makes it a loader. Anything
            // else on this route is a plain payload id on the wrong path --
            // indistinguishable from nonexistent, same as the payload
            // fetch's engagement rule.
            var loader = await payloads.FindAsync(payloadValue, token.EngagementId.Value, cancellationToken);
            if (loader?.DeliversPayloadId is not { } deliversId)
            {
                await RecordFetchAsync(audit, clock, token.EngagementId, token.Id, payloadValue,
                    fetcher, "refused:not-loader", cancellationToken: cancellationToken);
                return Results.NotFound(new Problem("Payload does not exist in this engagement."));
            }
            var delivered = await payloads.FindAsync(deliversId, token.EngagementId.Value, cancellationToken);
            if (delivered is null || loader.EnvelopeKeyId is not { } keyId || loader.EnvelopeKey is not { } key)
            {
                await RecordFetchAsync(audit, clock, token.EngagementId, token.Id, payloadValue,
                    fetcher, "refused:seal", delivered?.Fingerprint, cancellationToken);
                return Results.NotFound(new Problem("Payload does not exist in this engagement."));
            }

            var redeemed = await tokens.RedeemAsync(secret, clock.GetUtcNow(), cancellationToken);

            // Sealed under the loader's own key, a fresh nonce per serve:
            // the loader is the only party that can open what this route
            // hands out, and no two serves share ciphertext.
            var sealedPayload = AesGcmEnvelope.WrapBody(delivered.Content, keyId, key, AesGcmEnvelope.LoaderPayloadAad);
            await RecordFetchAsync(audit, clock, redeemed.EngagementId, redeemed.Id, payloadValue,
                fetcher, "delivered", delivered.Fingerprint, cancellationToken);
            await live.PublishAsync(
                LiveEvent.PayloadFetched(
                    redeemed.EngagementId,
                    $"{fetcher} delivered={delivered.Fingerprint} sealed",
                    clock.GetUtcNow()),
                cancellationToken);
            return Results.File(sealedPayload, "application/octet-stream", $"rod-delivered-{deliversId:N}.bin");
        }
        catch (DeployTokenRedeemException ex)
        {
            if (ex.EngagementId is { } engagement && ex.TokenId is { } tokenId)
                await RecordFetchAsync(audit, clock, engagement, tokenId, payloadValue,
                    fetcher, $"refused:{ex.Reason.ToString().ToLowerInvariant()}",
                    cancellationToken: cancellationToken);
            return Results.Json(
                new Problem("Deploy token was not accepted."),
                statusCode: StatusCodes.Status401Unauthorized);
        }
    }

    // Serves a built payload to a presenting downloader one-liner. The deploy
    // token in the X-Deploy-Token header resolves the engagement; the payload
    // must exist in that engagement, so a token for one engagement never
    // reaches another engagement's payloads (architecture.md Sec 3). The
    // fetch REDEEMS one use of the token: the download gate is the token's
    // whole job -- the enrollment that follows rides the credential baked
    // into the fetched artifact, not this one. A single-use token authorizes
    // exactly one download; an unlimited budget (maxUses 0) serves until
    // expiry.
    // Every fetch a resolvable credential gate-keeps lands on the audit
    // trail, served or refused -- the fetcher speaks no Rod protocol yet,
    // so the fact is system-attributed and carries what the wire showed
    // (source address, user agent, the socket it landed on). A credential
    // whose secret resolves to no engagement (unknown, or hard-deleted with
    // its launcher row) leaves no record: it belongs to nobody.
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
    {
        var secret = http.Headers["X-Deploy-Token"].ToString();
        if (string.IsNullOrWhiteSpace(secret))
            return Results.Json(
                new Problem("X-Deploy-Token header is required."),
                statusCode: StatusCodes.Status401Unauthorized);
        if (!Guid.TryParse(payloadId, out var payloadValue))
            return Results.BadRequest(new Problem("Payload id is not a valid identifier."));

        // What the wire showed, captured before any branching: every fact --
        // served or refused -- describes the same fetcher.
        var remote = http.HttpContext.Connection.RemoteIpAddress is { } remoteIp
            ? $"{remoteIp}:{http.HttpContext.Connection.RemotePort}"
            : "unknown";
        var userAgent = http.Headers.UserAgent.ToString();
        var fetcher = $"remote={remote} listenerPort={http.HttpContext.Connection.LocalPort} "
            + $"ua={(string.IsNullOrWhiteSpace(userAgent) ? "none" : userAgent)}";

        try
        {
            // Resolve without spending first: every refusal below (a foreign
            // socket, an unknown payload) must leave the budget whole, and
            // only a fetch that actually serves bytes redeems its use.
            var token = await tokens.VerifyAsync(secret, clock.GetUtcNow(), cancellationToken);

            // The scope check an engagement's own listener enforces: the
            // token must belong to the engagement this socket answers for, so
            // a leaked token from another engagement is refused here, before
            // any bytes leave -- and a shared-tier socket (the operator
            // front) refuses implant ingress outright.
            if (!await TokenMatchesListenerScopeAsync(http, listeners, token, cancellationToken))
            {
                await RecordFetchAsync(audit, clock, token.EngagementId, token.Id, payloadValue,
                    fetcher, "refused:scope", cancellationToken: cancellationToken);
                return Results.Json(
                    new Problem("Deploy token was not accepted."),
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            // Scoped by the token's engagement: a payload id from another
            // engagement is indistinguishable from a nonexistent one.
            var payload = await payloads.FindAsync(payloadValue, token.EngagementId.Value, cancellationToken);
            if (payload is null)
            {
                await RecordFetchAsync(audit, clock, token.EngagementId, token.Id, payloadValue,
                    fetcher, "refused:payload", cancellationToken: cancellationToken);
                return Results.NotFound(new Problem("Payload does not exist in this engagement."));
            }

            // The download's redemption, after every refusal: one served
            // fetch spends one use, and a token at zero serves no more.
            var redeemed = await tokens.RedeemAsync(secret, clock.GetUtcNow(), cancellationToken);

            // The serve is the deployment's first observable footprint. The
            // same frame reaches connected operators live, so a launcher
            // row's remaining budget moves the moment a target pulls it. The
            // enrollment that may follow is the identity-bearing half of the
            // exchange; a burned one-liner pulled by a scanner enrolls never,
            // and this is the only record it leaves.
            await RecordFetchAsync(audit, clock, redeemed.EngagementId, redeemed.Id, payloadValue,
                fetcher, "served", payload.Fingerprint, cancellationToken);
            await live.PublishAsync(
                LiveEvent.PayloadFetched(
                    redeemed.EngagementId,
                    $"{fetcher} payload={payload.Fingerprint} served",
                    clock.GetUtcNow()),
                cancellationToken);

            return Results.File(payload.Content, payload.ContentType, $"rod-payload-{payloadValue:N}.bin");
        }
        catch (DeployTokenRedeemException ex)
        {
            // A credential that still resolves keeps its attempts on the
            // trail: expired, spent, or revoked, the fact says who came back
            // and why it was refused -- the budget-burned retry is exactly
            // the fact an operator wants while the launcher row lives. The
            // wire answer stays uniform: no distinction between unknown,
            // expired, spent, and revoked for the fetcher to read.
            if (ex.EngagementId is { } engagement && ex.TokenId is { } tokenId)
                await RecordFetchAsync(audit, clock, engagement, tokenId, payloadValue,
                    fetcher, $"refused:{ex.Reason.ToString().ToLowerInvariant()}",
                    cancellationToken: cancellationToken);
            return Results.Json(
                new Problem("Deploy token was not accepted."),
                statusCode: StatusCodes.Status401Unauthorized);
        }
    }

    // The one fetch fact: what the wire showed, which credential gated it,
    // and how it ended. The payload names itself in the library's
    // vocabulary -- the fingerprint the Payloads tab matches on -- with the
    // bare artifact id beside it for correlating a pasted command's URL;
    // a fetch that never resolved a payload can name only the id it asked
    // for. Audit-only -- the live push rides the served frame alone,
    // because a refusal moves no state an operator's row displays.
    private static async Task RecordFetchAsync(
        IAuditStore audit,
        TimeProvider clock,
        EngagementId engagement,
        DeployTokenId tokenId,
        Guid payloadId,
        string fetcher,
        string outcome,
        string? fingerprint = null,
        CancellationToken cancellationToken = default)
    {
        var payloadText = fingerprint is null
            ? $"payload={payloadId:N}"
            : $"payload={fingerprint} id={payloadId:N}";
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: OperatorId.Empty.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "payload.fetched",
                kind: AuditEventKind.PayloadFetched,
                payload: $"{fetcher} {payloadText} token={tokenId}",
                output: null,
                outcome,
                at: clock.GetUtcNow()),
            cancellationToken);
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

    // The engagement-scope check shared by enroll and the payload fetch: the
    // socket this request arrived on must be the token's own engagement's
    // listener. A shared-tier (startup-configuration) socket refuses implant
    // ingress outright -- the operator front carries no enrollment, and each
    // engagement brings its own listener. A socket the registry does not know
    // (the in-memory test harness, which binds no real ports) stays
    // token-scoped only, the shape the harness has always used.
    private static async Task<bool> TokenMatchesListenerScopeAsync(
        HttpRequest http,
        Rod.Transport.Listeners.IListenerRegistry listeners,
        Rod.CoreState.Deployment.RedeemedDeployToken token,
        CancellationToken cancellationToken)
    {
        var listener = await listeners.FindByLocalPortAsync(http.HttpContext.Connection.LocalPort, cancellationToken);
        return listener is null || listener.EngagementId == token.EngagementId;
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
