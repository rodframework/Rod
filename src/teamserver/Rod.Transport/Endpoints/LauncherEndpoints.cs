using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Listeners;
using Rod.CoreState.Launchers;
using Rod.CoreState.Operators;
using Rod.CoreState.ShellSessions;
using Rod.CoreState.Deployment;
using Rod.Transport.Listeners.ShellCatch;

namespace Rod.Transport.Endpoints;

// The standalone launcher surface: the operator's "give me the one-liner that
// beacons" (architecture.md Sec 8), without a caught shell to grow from. The
// shell console's Upgrade render and this endpoint share one definition of the
// flow -- resolve the web front and the payload, mint the download
// credential, render the paste-ready downloader families -- so both surfaces
// answer identically whichever one an operator drives.
//
// Every render this endpoint cuts is kept: the engagement holds its launcher
// rows -- url, credential, policy, provenance -- so an operator can come back
// to a render at any time (re-copy the command, watch the credential's
// budget, revoke it the moment it leaks, and delete the row when it is
// spent). The commands are re-rendered on read from the row's url and secret,
// so an old row always copies in the current command shape.

/// <summary>
/// The engagement-scoped launcher registry endpoints: render-and-keep a
/// launcher set, list what was kept, revoke a credential, and delete a row
/// (which revokes the credential first -- one action closes the lifecycle,
/// and the audit trail keeps the mint's history). The credential policy is
/// the operator's -- the shell upgrade always mints single-use for thirty
/// minutes (one paste, one download), while a kept render can widen the
/// budget and window for a many-host deployment.
/// </summary>
public static class LauncherEndpoints
{
    public static IEndpointRouteBuilder MapLauncherEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints
            .MapGroup("/engagements/{engagementId}/launchers")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));

        // POST on the collection renders a launcher set and keeps the row:
        // the call creates the one artifact this resource exists to produce
        // (the minted credential plus the one-liners), so the plain
        // collection POST is the render.
        group.MapPost("/", RenderLauncherAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(RenderLauncherAsync));
        group.MapGet("/", ListLaunchersAsync).WithName(nameof(ListLaunchersAsync));
        group.MapPost("/{launcherId}:revoke", RevokeLauncherAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(RevokeLauncherAsync));
        group.MapDelete("/{launcherId}", DeleteLauncherAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(DeleteLauncherAsync));

        return endpoints;
    }

    // The default token policy and the bounds an operator may widen it to:
    // one paste one download, thirty minutes, up to unlimited uses or a day --
    // a credential wider than the engagement's patience does not outlive it.
    private const int DefaultMaxUses = 1;
    private const int MaxUsesBound = 1000;
    private const int DefaultLifetimeMinutes = 30;
    private const int LifetimeMinutesBound = 24 * 60;

    private static async Task<IResult> RenderLauncherAsync(
        string engagementId,
        LauncherRenderRequest? body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        IListenerStore listenerStore,
        IPayloadStore payloads,
        IDeployTokenService tokens,
        ILauncherStore launchers,
        IOperatorRepository operators,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        // The rendering operator is the authenticated operator, resolved off
        // the session principal rather than named in the body.
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        var maxUses = body?.MaxUses ?? DefaultMaxUses;
        if (maxUses < 0 || maxUses > MaxUsesBound)
            return Results.BadRequest(new Problem($"MaxUses must be between 0 (unlimited) and {MaxUsesBound}."));
        var lifetimeMinutes = body?.LifetimeMinutes ?? DefaultLifetimeMinutes;
        if (lifetimeMinutes < 1 || lifetimeMinutes > LifetimeMinutesBound)
            return Results.BadRequest(new Problem($"LifetimeMinutes must be between 1 and {LifetimeMinutesBound}."));

        var (failure, set) = await LauncherRender.ResolveAsync(
            engagement,
            new LauncherSelection(
                body?.PayloadId,
                body?.ListenerId,
                maxUses,
                TimeSpan.FromMinutes(lifetimeMinutes),
                operatorId.Value,
                AuditOrigin: "origin=launcher"),
            engagements,
            listenerStore,
            payloads,
            tokens,
            audit,
            clock,
            cancellationToken);
        if (set is null)
            return failure!;

        // Keep the row: the snapshot the operator returns to. The payload's
        // target OS rides beside its id so the row's re-rendered one-liners
        // stay filtered to the payload's own families even after the payload
        // leaves the library.
        var row = new Launcher(
            LauncherId.New(),
            engagement,
            set.Payload.PayloadId,
            LauncherRender.OsOf(set.Payload.Target),
            set.Front.Id,
            set.Front.Name,
            set.Front.PublicEndpoint,
            set.Token.Id,
            set.Token.Secret,
            set.Url,
            maxUses,
            set.Token.ExpiresAt,
            clock.GetUtcNow(),
            operatorId.Value);
        await launchers.SaveAsync(row, cancellationToken);

        // The renderer is the principal itself; resolve the handle with the
        // tolerance the listing applies.
        var creator = await operators.FindAsync(operatorId.Value, cancellationToken);

        return Results.Ok(await ResponseOfAsync(
            row,
            set.Launchers,
            set.Payload.Fingerprint,
            creator?.Handle ?? operatorId.Value.ToString(),
            tokens,
            cancellationToken));
    }

    private static async Task<IResult> ListLaunchersAsync(
        string engagementId,
        ILauncherStore launchers,
        IPayloadStore payloads,
        IOperatorRepository operators,
        IDeployTokenService tokens,
        CancellationToken cancellationToken)
    {
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        var rows = await launchers.ListByEngagementAsync(engagement, cancellationToken);

        // Resolve the rows' cutting operators to handles once per request,
        // the tolerance the audit read applies (the bare id when the account
        // no longer resolves): the member role cannot walk the operator
        // roster to do it client-side, so the read names the actor itself.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in rows.Select(r => r.CreatedBy.Value).Where(id => id != Guid.Empty).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        var body = new List<LauncherResponse>();
        foreach (var row in rows)
        {
            // The commands are re-rendered on read, so the row always copies
            // in the current shape -- filtered to the payload's own families
            // through the row's OS snapshot, so a Windows row never re-offers
            // a Unix one-liner (and a payload whose target was never recorded
            // keeps every family). The fingerprint join is display-only: it
            // puts the row in the payload library's own vocabulary, and reads
            // null once the payload is deleted (the row still names the id it
            // delivered).
            var rendered = ShellUpgradeLaunchers.Render(row.Url, row.TokenSecret, row.PayloadOs)
                .Select(l => new ShellLauncherResponse(l.Id, l.Os, l.Command))
                .ToArray();
            var delivered = await payloads.FindAsync(row.PayloadId, engagement.Value, cancellationToken);
            body.Add(await ResponseOfAsync(
                row,
                rendered,
                delivered?.Fingerprint,
                handles.GetValueOrDefault(row.CreatedBy.Value, row.CreatedBy.Value.ToString()),
                tokens,
                cancellationToken));
        }
        return Results.Ok(body);
    }

    private static async Task<IResult> RevokeLauncherAsync(
        string engagementId,
        string launcherId,
        ClaimsPrincipal user,
        ILauncherStore launchers,
        IDeployTokenService tokens,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!LauncherId.TryParse(launcherId, out var rowId))
            return Results.BadRequest(new Problem("Launcher id is not a valid identifier."));

        // The engagement in the path must own the row; a foreign engagement's
        // row is indistinguishable from an unknown one (architecture.md Sec 3).
        var row = await launchers.FindAsync(rowId, cancellationToken);
        if (row is null || row.EngagementId != engagement)
            return Results.NotFound(new Problem("Launcher does not exist in this engagement."));
        if (row.RevokedAt is not null)
            return Results.BadRequest(new Problem("This launcher's credential is already revoked."));

        // The revocation kills the credential wherever it lives -- the row's
        // own fetch, and any copy of the command that carries it.
        var at = clock.GetUtcNow();
        if (!await tokens.RevokeAsync(row.TokenId, cancellationToken))
        {
            // The token is already gone (spent to zero, expired and swept):
            // the honest answer is still to mark the row, but the wire says
            // the credential needed no killing.
            if (!row.Revoke(at))
                return Results.BadRequest(new Problem("This launcher's credential is already revoked."));
            await launchers.SaveAsync(row, cancellationToken);
            return Results.Ok(RevokedResponse(row, alreadyDead: true));
        }

        row.Revoke(at);
        await launchers.SaveAsync(row, cancellationToken);

        // The revocation is recorded like every engagement fact
        // (architecture.md Sec 11): attributed to the acting operator, the
        // outcome the revoked token id.
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "revoke-deploy-token",
                kind: AuditEventKind.DeployTokenRevoked,
                payload: $"origin=launcher requestedBy={operatorId.Value.Value}",
                output: null,
                outcome: row.TokenId.ToString(),
                at: at),
            cancellationToken);

        return Results.Ok(RevokedResponse(row, alreadyDead: false));
    }

    private static async Task<IResult> DeleteLauncherAsync(
        string engagementId,
        string launcherId,
        ClaimsPrincipal user,
        ILauncherStore launchers,
        IDeployTokenService tokens,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!LauncherId.TryParse(launcherId, out var rowId))
            return Results.BadRequest(new Problem("Launcher id is not a valid identifier."));

        // The engagement in the path must own the row.
        var row = await launchers.FindAsync(rowId, cancellationToken);
        if (row is null || row.EngagementId != engagement)
            return Results.NotFound(new Problem("Launcher does not exist in this engagement."));

        // Delete closes the whole lifecycle: the credential dies wherever its
        // copies live first (a pasted command stops working at its next
        // fetch), then the row goes -- a spent row is safe to drop outright,
        // and the mint's history is the audit trail, not the list. A
        // credential already dead (spent to zero, expired and swept) needs no
        // killing; the row still goes.
        if (row.RevokedAt is null)
        {
            var at = clock.GetUtcNow();
            // The hard kill, not the revoke: deleting the row removes the
            // credential's resolution outright, so post-delete attempts on
            // the secret read Unknown and leave no record -- a revoked-row
            // credential keeps refusing visibly; a deleted-row one is gone.
            await tokens.DeleteAsync(row.TokenId, cancellationToken);
            row.Revoke(at);
            // The revocation is recorded like every engagement fact
            // (architecture.md Sec 11) -- deleting a live launcher is a
            // credential kill, and the trail is where "what happened to it"
            // lives after the row is gone.
            await audit.AppendAsync(
                AuditEvent.Fact(
                    eventId: Guid.NewGuid(),
                    engagementId: engagement.Value,
                    operatorId: operatorId.Value.Value,
                    implantId: Guid.Empty,
                    taskId: Guid.Empty,
                    verb: "revoke-deploy-token",
                    kind: AuditEventKind.DeployTokenRevoked,
                    payload: $"origin=launcher-delete requestedBy={operatorId.Value.Value}",
                    output: null,
                    outcome: row.TokenId.ToString(),
                    at),
                cancellationToken);
        }

        if (!await launchers.RemoveAsync(rowId, cancellationToken))
            return Results.NotFound(new Problem("Launcher does not exist in this engagement."));

        return Results.NoContent();
    }

    // The row's response shape: the snapshot plus the live credential state,
    // joined from the token store. A null remaining count means the token is
    // no longer stored -- revoked, or spent to zero -- and reads as "no
    // downloads left". The payload fingerprint is joined from the library so
    // the row reads in the same identifier the Payloads tab shows; null when
    // the payload no longer exists there.
    private static async Task<LauncherResponse> ResponseOfAsync(
        Launcher row,
        IReadOnlyList<ShellLauncherResponse> commands,
        string? payloadFingerprint,
        string createdByHandle,
        IDeployTokenService tokens,
        CancellationToken cancellationToken)
    {
        var state = await tokens.FindAsync(row.TokenId, cancellationToken);
        return new LauncherResponse(
            row.Id.ToString(),
            row.PayloadId.ToString("N"),
            payloadFingerprint,
            row.Url,
            row.FrontName,
            row.FrontEndpoint,
            row.TokenSecret,
            row.MaxUses,
            row.ExpiresAt,
            row.CreatedAt,
            row.CreatedBy.ToString(),
            createdByHandle,
            row.RevokedAt,
            TokenRemainingUses: state is null ? null : state.RemainingUses,
            TokenExpiresAt: state?.ExpiresAt,
            Launchers: commands);
    }

    private static RevokedLauncherResponse RevokedResponse(Launcher row, bool alreadyDead)
        => new(row.Id.ToString(), row.TokenId.ToString(), row.RevokedAt!.Value, alreadyDead);

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    /// <summary>
    /// Names the payload and the web listener the fetch should ride
    /// (either may be omitted for the engagement's own preference: the newest
    /// build, the hardened front), and the deployment credential's policy:
    /// how many redeems it allows (0 = unlimited) and how long it lives.
    /// </summary>
    public sealed record LauncherRenderRequest(
        string? PayloadId = null,
        string? ListenerId = null,
        int? MaxUses = null,
        int? LifetimeMinutes = null);

    /// <summary>
    /// One kept launcher row: what it delivers and where it fetches from, the
    /// re-copyable credential with its policy and provenance, the revocation
    /// state, and the paste-ready one-liners re-rendered from the row's url
    /// and secret. The payload fingerprint is the library's identifier for
    /// what the fetch delivers -- the same value the Payloads tab shows --
    /// and is null when that payload has since been deleted.
    /// </summary>
    public sealed record LauncherResponse(
        string LauncherId,
        string PayloadId,
        string? PayloadFingerprint,
        string Url,
        string FrontName,
        string FrontEndpoint,
        string TokenSecret,
        int MaxUses,
        DateTimeOffset ExpiresAt,
        DateTimeOffset CreatedAt,
        string CreatedBy,
        // The cutting operator's handle, resolved at read time -- the member
        // role cannot walk the operator roster to map the id client-side, so
        // the read names the actor itself. The bare id stands in when the
        // account no longer resolves.
        string CreatedByHandle,
        DateTimeOffset? RevokedAt,
        int? TokenRemainingUses,
        DateTimeOffset? TokenExpiresAt,
        IReadOnlyList<ShellLauncherResponse> Launchers);

    /// <summary>
    /// The answer to a revocation: the row, its credential's id, when the
    /// handle was pulled, and whether the credential was already dead (spent
    /// or expired) when the operator pulled it.
    /// </summary>
    public sealed record RevokedLauncherResponse(
        string LauncherId,
        string TokenId,
        DateTimeOffset RevokedAt,
        bool AlreadyDead);
}

/// <summary>What one render asked for, beyond the engagement it targets.</summary>
internal sealed record LauncherSelection(
    string? PayloadId,
    string? ListenerId,
    int MaxUses,
    TimeSpan Lifetime,
    OperatorId RequestedBy,
    string AuditOrigin);

/// <summary>The resolved pieces one render is made of.</summary>
internal sealed record LauncherSet(
    PayloadRecord Payload,
    ListenerDefinition Front,
    DeployToken Token,
    string Url,
    IReadOnlyList<ShellLauncherResponse> Launchers);

/// <summary>
/// The shared render flow behind both launcher surfaces: the shell console's
/// Upgrade render (a caught shell growing a beacon) and the standalone
/// launcher endpoint. Everything except the calling endpoint's scoping lives
/// here, so the one-liners, the credential policy, and the mint's audit arc
/// cannot drift between the two.
/// </summary>
internal static class LauncherRender
{
    /// <summary>
    /// Resolves, mints, audits, and renders. Returns a failure result instead
    /// of a set when the engagement has no web listener to serve the fetch,
    /// no payload to grow into, or a name that matches neither.
    /// </summary>
    public static async Task<(IResult? Failure, LauncherSet? Set)> ResolveAsync(
        EngagementId engagement,
        LauncherSelection selection,
        IEngagementRepository engagements,
        IListenerStore listenerStore,
        IPayloadStore payloads,
        IDeployTokenService tokens,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (await engagements.FindAsync(engagement, cancellationToken) is not { } engagementRow)
            return (Results.NotFound(new Problem("Engagement does not exist.")), null);

        // The payload fetch rides the engagement's web listeners, so the URL
        // needs one to exist. The operator may name the front the fetch
        // should use (several listeners, one specific redirector); unnamed,
        // the hardened members are preferred over cleartext.
        var webListeners = (await listenerStore.ListAsync(cancellationToken))
            .Where(l => l.EngagementId == engagement && IsWebTransport(l.Transport))
            .ToList();
        ListenerDefinition? webListener;
        if (selection.ListenerId is { } namedListener)
        {
            webListener = Guid.TryParse(namedListener, out var named)
                ? webListeners.FirstOrDefault(l => l.Id == named)
                : null;
            if (webListener is null)
                return (
                    Results.BadRequest(new Problem(
                        "ListenerId does not name one of this engagement's HTTP(S) listeners.")),
                    null);
        }
        else
        {
            webListener = webListeners
                .OrderByDescending(l => l.Transport == "https")
                .ThenByDescending(l => l.Transport == "mtls")
                .ThenBy(l => l.CreatedAt)
                .FirstOrDefault();
        }
        if (webListener is null)
            return (
                Results.BadRequest(new Problem(
                    "The engagement has no HTTP(S) listener to serve the payload fetch; create one first.")),
                null);

        // The payload to grow into: the operator names one, or the newest
        // build in the engagement stands in.
        var payload = await ResolvePayloadAsync(payloads, engagement, selection.PayloadId, cancellationToken);
        if (payload is null)
            return (
                Results.BadRequest(new Problem(
                    "No payload exists in this engagement; build one first, or name an existing payload id.")),
                null);

        // A payload whose baked enrollment credential is dead delivers an
        // artifact that can never enroll -- the fetch would spend its freshly
        // minted download credential on a beacon that stops at the refusal.
        // Dead means the token left the store (revoked or swept), counted to
        // zero, or past its window; a credential-free build (the manual-mint
        // shape) is the operator's own delivery story and rides.
        if (payload.TokenId is { } baked)
        {
            var credential = await tokens.FindAsync(new DeployTokenId(baked), cancellationToken);
            if (credential is null
                || (credential.MaxUses != 0 && credential.RemainingUses <= 0)
                || credential.ExpiresAt <= clock.GetUtcNow())
                return (
                    Results.BadRequest(new Problem(
                        "This payload's baked enrollment credential is dead (revoked, spent, or expired) -- "
                        + "a fetch would deliver an artifact that can never enroll. "
                        + "Build a fresh payload, or pick one whose credential still lives.")),
                    null);
        }

        // One download credential for the fetch: every served fetch spends
        // one use, the window is the operator's, and the enrollment that
        // follows rides the credential baked into the fetched artifact. The
        // mint is issued by the engagement's owner and recorded on the trail
        // with the rendering operator named; the secret itself never rides
        // the audit.
        var at = clock.GetUtcNow();
        var token = await tokens.MintAsync(
            engagement, engagementRow.OwnerId, at,
            maxUses: selection.MaxUses, lifetime: selection.Lifetime,
            cancellationToken: cancellationToken);
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: engagementRow.OwnerId.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "mint-deploy-token",
                kind: AuditEventKind.DeployTokenMinted,
                payload: $"{selection.AuditOrigin} requestedBy={selection.RequestedBy.Value} uses={(selection.MaxUses == 0 ? "unlimited" : selection.MaxUses)} lifetime={selection.Lifetime.TotalMinutes:0}m",
                output: null,
                outcome: token.Id.ToString(),
                at),
            cancellationToken);

        var url = $"{webListener.PublicEndpoint.TrimEnd('/')}/implants/payloads/{payload.PayloadId:N}";
        return (null, new LauncherSet(
            payload,
            webListener,
            token,
            url,
            // The payload's own families alone: a one-liner for another OS
            // spends the fetch credential on bytes that cannot run there.
            ShellUpgradeLaunchers.Render(url, token.Secret, OsOf(payload.Target))
                .Select(l => new ShellLauncherResponse(l.Id, l.Os, l.Command))
                .ToArray()));
    }

    // The OS half of a stored payload target ("linux/amd64" -> "linux"):
    // the families key on the OS alone. The separator tolerance covers the
    // slash the build pipeline stamps and any dash-joined spelling a stored
    // record carries; an unrecognized or missing target reads null, which
    // renders every family.
    internal static string? OsOf(string? target)
    {
        var trimmed = target?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(trimmed))
            return null;
        var stem = trimmed.Split('/', '-')[0];
        return stem is "linux" or "windows" ? stem : null;
    }

    private static bool IsWebTransport(string transport)
        => transport is "http" or "https" or "mtls";

    private static async Task<PayloadRecord?> ResolvePayloadAsync(
        IPayloadStore payloads,
        EngagementId engagement,
        string? payloadId,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(payloadId) && Guid.TryParse(payloadId, out var named))
            return await payloads.FindAsync(named, engagement.Value, cancellationToken);

        var newest = await payloads.ListAsync(engagement.Value, cancellationToken);
        return newest.OrderByDescending(p => p.BuiltAt).FirstOrDefault();
    }
}
