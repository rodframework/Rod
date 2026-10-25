using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Http.HttpResults;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Deployment;
using Rod.CoreState.Sessions;

namespace Rod.Transport.Endpoints;

/// <summary>
/// The operator-facing engagement endpoints: create an engagement and mint a
/// deploy token for it, edit and list engagements (the list is the operator
/// UI's data source). DTOs live here, in transport, so the core stays serialization-
/// and protocol-free (AGENTS.md Sec 5).
/// </summary>
public static class EngagementEndpoints
{
    public static IEndpointRouteBuilder MapEngagementEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Operator-facing: every engagement route requires an authenticated
        // operator session (cookie auth wired via AddRodOperatorAuth). The
        // listing is the caller's own reach (owner or member, filtered in the
        // handler -- it spans engagements); creating is open to any
        // authenticated operator (the creator becomes the owner,
        // architecture.md Sec 3); the engagement-scoped routes carry the
        // membership gate as their write filter. The implant-facing
        // enrollment path is mapped separately and stays anonymous.
        var group = endpoints
            .MapGroup("/engagements")
            .RequireAuthorization();

        group.MapGet("/", ListEngagementsAsync).WithName(nameof(ListEngagementsAsync));
        group.MapPost("/", CreateEngagementAsync)
            .WithName(nameof(CreateEngagementAsync));
        group.MapPut("/{engagementId}", EditEngagementAsync)
            .AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(EditEngagementAsync));

        group.MapPost("/{engagementId}/deploy-tokens", MintDeployTokenAsync)
            .AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(MintDeployTokenAsync));

        group.MapPost("/{engagementId}/deploy-tokens/{tokenId}:revoke", RevokeDeployTokenAsync)
            .AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(RevokeDeployTokenAsync));

        group.MapPut("/{engagementId}/roe", ApplyRoeAsync)
            .AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(ApplyRoeAsync));

        return endpoints;
    }

    private static async Task<Results<Ok<List<EngagementResponse>>, UnauthorizedHttpResult>> ListEngagementsAsync(
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        IEngagementMembershipStore memberships,
        IOperatorRepository operators,
        IImplantRepository implants,
        ISessionRegistry sessions,
        CancellationToken cancellationToken)
    {
        var caller = user.TryGetOperatorId();
        if (caller is null)
            return TypedResults.Unauthorized();

        // The listing is the caller's own reach (architecture.md Sec 3): the
        // engagements they own plus the ones an owner granted them into. A
        // stranger's engagement does not appear -- the same concealment the
        // per-engagement routes keep, at the roster level.
        var reach = (await memberships.ListForOperatorAsync(caller.Value, cancellationToken))
            .ToDictionary(m => m.EngagementId, m => EngagementRoles.ToName(m.Role));
        var all = (await engagements.ListAsync(cancellationToken))
            .Where(e => e.OwnerId == caller.Value || reach.ContainsKey(e.Id))
            .ToList();

        // The owner handle lives on the Operator, not the engagement. Resolve it
        // per engagement with the tolerance every operator-facing read applies
        // (the bare id when the account no longer resolves) -- the same
        // convention the task and audit reads name their actors by, so the
        // roster never falls back to a fragment. The same loop
        // sizes each engagement's fleet -- active (non-retired) implants and how
        // many hold a live session -- off the same repositories the fleet table
        // reads, so the landing roster carries the posture without the operator
        // drilling in.
        var body = new List<EngagementResponse>(all.Count);
        foreach (var e in all)
        {
            var owner = await operators.FindAsync(e.OwnerId, cancellationToken);
            var enrolled = await implants.ListByEngagementAsync(e.Id, cancellationToken);
            var onlineIds = (await sessions.ListActiveAsync(e.Id, cancellationToken))
                .Select(s => s.ImplantId)
                .ToHashSet();
            var active = enrolled.Where(i => i.RetiredAt is null).ToList();
            body.Add(new EngagementResponse(
                e.Id.ToString(),
                e.Name,
                e.Description,
                e.OwnerId.ToString(),
                owner?.Handle ?? e.OwnerId.ToString(),
                e.OwnerId == caller.Value ? "owner" : reach[e.Id],
                e.CreatedAt,
                RoeProfileResponse.From(e.Roe),
                e.FrozenAt,
                e.RetiredAt,
                Summary: new EngagementFleetSummaryResponse(
                    active.Count,
                    active.Count(i => onlineIds.Contains(i.Id))),
                Range: e.Range));
        }

        return TypedResults.Ok(body);
    }

    private static async Task<Results<Created<EngagementResponse>, BadRequest<Problem>, UnauthorizedHttpResult>> CreateEngagementAsync(
        CreateEngagementRequest body,
        ClaimsPrincipal user,
        EngagementService service,
        IAuditStore audit,
        CancellationToken cancellationToken)
    {
        // The owner is the authenticated operator, resolved off the session
        // principal rather than named in the body (operator auth). The group already requires authorization,
        // so a present-but-missing claim is a defensive 401, not a normal path.
        var ownerId = user.TryGetOperatorId();
        if (ownerId is null)
            return TypedResults.Unauthorized();
        if (string.IsNullOrWhiteSpace(body.Name))
            return TypedResults.BadRequest(new Problem("Engagement name is required."));

        var created = await service.CreateEngagementAsync(
            new CreateEngagementCommand(ownerId.Value, body.Name, body.Description, body.Range),
            cancellationToken);

        var response = new EngagementResponse(
            created.EngagementId.ToString(),
            created.Name,
            created.Description,
            created.OwnerId.ToString(),
            created.OwnerHandle,
            "owner",
            created.CreatedAt,
            RoeProfileResponse.From(RoeProfile.Unrestricted),
            FrozenAt: null,
            RetiredAt: null,
            Range: created.Range);

        // The engagement's own creation is the trail's genesis link (architecture.md
        // Sec 11): attributed to the creating owner, carrying the
        // name in its payload and the new engagement id as its outcome. It is the
        // first event in this engagement's chain, so it follows the genesis hash.
        // A range engagement's genesis carries the mark: simulated evidence must
        // never read as a real engagement's, chain included.
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: created.EngagementId.Value,
                operatorId: created.OwnerId.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "create-engagement",
                kind: AuditEventKind.EngagementCreated,
                payload: created.Range ? $"{created.Name} [range]" : created.Name,
                output: null,
                outcome: created.EngagementId.ToString(),
                at: created.CreatedAt),
            cancellationToken);

        return TypedResults.Created($"/engagements/{response.EngagementId}", response);
    }

    private static async Task<IResult> EditEngagementAsync(
        string engagementId,
        EditEngagementRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        EngagementService service,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var idValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (string.IsNullOrWhiteSpace(body.Name))
            return Results.BadRequest(new Problem("Engagement name is required."));

        // Resolve first so an unknown id is a clean 404; after that the only
        // InvalidOperationException left is the aggregate refusing the edit.
        var existing = await engagements.FindAsync(new EngagementId(idValue), cancellationToken);
        if (existing is null)
            return Results.NotFound(new Problem($"Engagement {engagementId} does not exist."));

        EngagementEdited edited;
        try
        {
            edited = await service.EditEngagementAsync(
                new EditEngagementCommand(new EngagementId(idValue), body.Name, body.Description),
                cancellationToken);
        }
        catch (InvalidOperationException ex)
        {
            // The aggregate seals a retired engagement's record.
            return Results.Conflict(new Problem(ex.Message));
        }

        // The edit is recorded (architecture.md Sec 11): attributed to the
        // editing operator, the payload naming the new record's shape. The
        // description text itself stays out of the trail -- it is working
        // notes, not a fact about the target.
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: edited.Engagement.Id.Value,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "edit-engagement",
                kind: AuditEventKind.EngagementUpdated,
                payload: $"name={edited.Engagement.Name} description={(edited.Engagement.Description is null ? "cleared" : "set")}",
                output: null,
                outcome: edited.Engagement.Id.ToString(),
                at: clock.GetUtcNow()),
            cancellationToken);

        return Results.Ok(new EngagementResponse(
            edited.Engagement.Id.ToString(),
            edited.Engagement.Name,
            edited.Engagement.Description,
            edited.Engagement.OwnerId.ToString(),
            edited.OwnerHandle,
            edited.Engagement.OwnerId == operatorId.Value ? "owner" : "member",
            edited.Engagement.CreatedAt,
            RoeProfileResponse.From(edited.Engagement.Roe),
            edited.Engagement.FrozenAt,
            edited.Engagement.RetiredAt,
            Range: edited.Engagement.Range));
    }

    private static async Task<IResult> MintDeployTokenAsync(
        string engagementId,
        ClaimsPrincipal user,
        HttpContext context,
        EngagementService service,
        IAuditStore audit,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var idValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        // The mint scope rides an optional JSON body: a body-less post keeps
        // the single-use, one-hour default; a batch names how many implants the
        // token may enroll and how long the window stays open. The content-type
        // check (not ContentLength) gates the read, so a chunked body binds too.
        MintDeployTokenRequest? request = null;
        if (context.Request.HasJsonContentType())
        {
            try
            {
                request = await context.Request.ReadFromJsonAsync<MintDeployTokenRequest>(cancellationToken);
            }
            catch (System.Text.Json.JsonException)
            {
                return Results.BadRequest(new Problem("The mint request body is not valid JSON."));
            }
        }
        if (request?.MaxUses is < 1 or > 10_000)
            return Results.BadRequest(new Problem("maxUses must be between 1 and 10000."));
        if (request?.LifetimeSeconds is < 60 or > 2_592_000)
            return Results.BadRequest(new Problem("lifetimeSeconds must be between 60 and 2592000 (30 days)."));
        TimeSpan? lifetime = request?.LifetimeSeconds is { } seconds ? TimeSpan.FromSeconds(seconds) : null;

        try
        {
            var minted = await service.MintDeployTokenAsync(
                new MintDeployTokenCommand(new EngagementId(idValue), operatorId.Value, request?.MaxUses, lifetime),
                cancellationToken);

            var response = new DeployTokenResponse(
                minted.DeployTokenId.ToString(),
                minted.EngagementId.ToString(),
                minted.Secret,
                minted.IssuedBy.ToString(),
                minted.IssuedAt,
                minted.ExpiresAt,
                minted.MaxUses);

            // A deploy-token mint is recorded (architecture.md Sec 11):
            // attributed to the minting operator, the payload the token's
            // bounded-use/expiry shape, the outcome the new token id. The secret
            // itself is never recorded -- only the fact that a token was minted.
            await audit.AppendAsync(
                AuditEvent.Fact(
                    eventId: Guid.NewGuid(),
                    engagementId: minted.EngagementId.Value,
                    operatorId: minted.IssuedBy.Value,
                    implantId: Guid.Empty,
                    taskId: Guid.Empty,
                    verb: "mint-deploy-token",
                    kind: AuditEventKind.DeployTokenMinted,
                    payload: $"maxUses={minted.MaxUses} expiresAt={minted.ExpiresAt:O}",
                    output: null,
                    outcome: minted.DeployTokenId.ToString(),
                    at: minted.IssuedAt),
            cancellationToken);

            return Results.Ok(response);
        }
        catch (EngagementClosedException ex)
        {
            // The engagement is frozen for close-out or retired: it mints no
            // deployment tokens (architecture.md Sec 2 step 10).
            return Results.Conflict(new Problem(ex.Message));
        }
        catch (InvalidOperationException)
        {
            // Engagement id parsed but unknown.
            return Results.NotFound(new Problem($"Engagement {engagementId} does not exist."));
        }
    }

    private static async Task<IResult> RevokeDeployTokenAsync(
        string engagementId,
        string tokenId,
        ClaimsPrincipal user,
        IDeployTokenService tokens,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var idValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(tokenId, out var tokenValue))
            return Results.BadRequest(new Problem("Deploy token id is not a valid identifier."));

        // The revocation is idempotent and honest about it: revoking an
        // unknown (already revoked, spent, or never minted) id answers 404 so
        // a fat-fingered id does not read as success.
        if (!await tokens.RevokeAsync(new DeployTokenId(tokenValue), cancellationToken))
            return Results.NotFound(new Problem("Deploy token is not held (unknown, spent, or already revoked)."));

        // The revocation is recorded like every engagement fact (architecture.md
        // Sec 11): attributed to the acting operator, the outcome the revoked
        // token id -- the trail lines up with the mint and the build that
        // baked it.
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: idValue,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "revoke-deploy-token",
                kind: AuditEventKind.DeployTokenRevoked,
                payload: "revokedAt=" + clock.GetUtcNow().ToString("O"),
                output: null,
                outcome: tokenValue.ToString(),
                at: clock.GetUtcNow()),
            cancellationToken);

        return Results.Ok(new RevokedDeployTokenResponse(tokenValue.ToString()));
    }

    private static async Task<IResult> ApplyRoeAsync(
        string engagementId,
        ApplyRoeRequest body,
        ClaimsPrincipal user,
        EngagementService service,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        // The applying operator is the authenticated operator; the group
        // already requires authorization, so a present-but-missing claim is a
        // defensive 401, not a normal path.
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var idValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        try
        {
            // A target entry naming a network must parse as one: a mistyped
            // CIDR sitting in the profile would match nothing and silently
            // narrow the scope to zero -- refuse it here, named, instead.
            if (body.PermittedTargets is { } targetEntries)
            {
                foreach (var entry in targetEntries)
                {
                    if (!string.IsNullOrWhiteSpace(entry)
                        && !RoeProfile.IsValidTargetEntry(entry.Trim()))
                    {
                        return Results.BadRequest(new Problem(
                            $"ROE target entry '{entry.Trim()}' does not parse as a hostname, IP, or CIDR block."));
                    }
                }
            }

            var applied = await service.ApplyRoeAsync(
                new ApplyRoeCommand(
                    new EngagementId(idValue),
                    new RoeProfile(body.PermittedVerbs, body.PermittedImplants, body.PermittedTargets)),
                cancellationToken);

            // The scope change is recorded (architecture.md Sec 9, Sec 11):
            // attributed to the applying operator, the payload the profile's
            // shape, the outcome the engagement id. This is the record the
            // trail shows the scope in force at any moment; every refusal the
            // profile causes is a TaskRoeRefused event against it.
            await audit.AppendAsync(
                AuditEvent.Fact(
                    eventId: Guid.NewGuid(),
                    engagementId: applied.EngagementId.Value,
                    operatorId: operatorId.Value.Value,
                    implantId: Guid.Empty,
                    taskId: Guid.Empty,
                    verb: "apply-roe",
                    kind: AuditEventKind.RoeUpdated,
                    payload: Describe(applied.Profile),
                    output: null,
                    outcome: applied.EngagementId.ToString(),
                    at: clock.GetUtcNow()),
                cancellationToken);

            return Results.Ok(new EngagementScopedRoeResponse(
                applied.EngagementId.ToString(),
                RoeProfileResponse.From(applied.Profile)));
        }
        catch (InvalidOperationException)
        {
            // Engagement id parsed but unknown.
            return Results.NotFound(new Problem($"Engagement {engagementId} does not exist."));
        }
    }

    // One line describing the scope in force -- the audit payload for an ROE
    // update and the human-readable form of the profile.
    internal static string Describe(RoeProfile profile)
    {
        var verbs = profile.PermittedVerbs.Count == 0 ? "*" : string.Join(",", profile.PermittedVerbs);
        var implants = profile.PermittedImplants.Count == 0 ? "*" : string.Join(",", profile.PermittedImplants);
        var targets = profile.PermittedTargets.Count == 0 ? "*" : string.Join(",", profile.PermittedTargets);
        return $"permittedVerbs={verbs} permittedImplants={implants} permittedTargets={targets}";
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    // The owner is the authenticated operator; only the engagement name is
    // supplied by the caller. Range marks the engagement a simulated one
    // (range mode, architecture.md Sec 15.3): its fleet is the teamserver's
    // scripted beacons, and the mark rides the engagement's identity forever.
    public sealed record CreateEngagementRequest(string Name, string? Description = null, bool Range = false);

    // The edit replaces the working record whole: name and description. A null
    // description clears it; an empty name is rejected before the service is
    // reached.
    public sealed record EditEngagementRequest(string Name, string? Description = null);

    public sealed record EngagementResponse(
        string EngagementId,
        string Name,
        string? Description,
        string OwnerId,
        string OwnerHandle,
        string YourRole,
        DateTimeOffset CreatedAt,
        RoeProfileResponse Roe,
        DateTimeOffset? FrozenAt = null,
        DateTimeOffset? RetiredAt = null,
        EngagementFleetSummaryResponse? Summary = null,
        bool Range = false);

    /// <summary>
    /// The landing roster's fleet posture: active (non-retired) implants and
    /// how many of them hold a live session. Only the list carries it; the
    /// create and edit responses leave it unset.
    /// </summary>
    public sealed record EngagementFleetSummaryResponse(int ImplantCount, int OnlineCount);

    // The ROE scope request: three allow-lists, each empty (or omitted)
    // meaning unrestricted on that dimension.
    public sealed record ApplyRoeRequest(
        IReadOnlyList<string>? PermittedVerbs,
        IReadOnlyList<string>? PermittedImplants,
        IReadOnlyList<string>? PermittedTargets = null);

    public sealed record RoeProfileResponse(
        IReadOnlyList<string> PermittedVerbs,
        IReadOnlyList<string> PermittedImplants,
        IReadOnlyList<string> PermittedTargets)
    {
        public static RoeProfileResponse From(RoeProfile profile)
            => new(profile.PermittedVerbs, profile.PermittedImplants, profile.PermittedTargets);
    }

    public sealed record EngagementScopedRoeResponse(
        string EngagementId,
        RoeProfileResponse Roe);

    /// <summary>
    /// The optional mint scope: how many implants the token may enroll (each
    /// spend one use) and how long the mint stays redeemable. Absent values
    /// keep the single-use, one-hour default.
    /// </summary>
    public sealed record MintDeployTokenRequest(int? MaxUses, long? LifetimeSeconds);

    /// <summary>Result of revoking a deploy token: the id that stopped working.</summary>
    public sealed record RevokedDeployTokenResponse(string DeployTokenId);

    public sealed record DeployTokenResponse(
        string DeployTokenId,
        string EngagementId,
        string Secret,
        string IssuedBy,
        DateTimeOffset IssuedAt,
        DateTimeOffset ExpiresAt,
        int MaxUses);

}
