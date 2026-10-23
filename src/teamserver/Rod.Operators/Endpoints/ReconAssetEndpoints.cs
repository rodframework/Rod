using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Engagements;
using Rod.CoreState.Operators;
using Rod.CoreState.Recon;

namespace Rod.Operators.Endpoints;

/// <summary>
/// The recon-asset routes (architecture.md Sec 15.4): the engagement's
/// first-class target list. The workbench (Sec 11.4) captures findings as
/// artifacts -- evidence; this surface is where an address is promoted to
/// a tracked target the rest of the model can reference, a campaign's
/// recipient selection being the load-bearing link. Three actions:
///
/// <list type="bullet">
/// <item><c>GET /engagements/{id}/recon-assets</c> -- the target list,
/// the picker a campaign create reads from.</item>
/// <item><c>POST /engagements/{id}/recon-assets</c> -- record a target,
/// typed by hand or with the findings artifact it was lifted from.</item>
/// <item><c>DELETE /engagements/{id}/recon-assets/{assetId}</c> -- remove
/// one; refused while a campaign recipient still references it.</item>
/// </list>
///
/// Recording and deletion act on the engagement (write-gated, refused
/// while closed -- the workbench posture); the listing is a read. Every
/// change lands in the trail.
/// </summary>
public static class ReconAssetEndpoints
{
    public static IEndpointRouteBuilder MapReconAssetEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints
            .MapGroup("/engagements/{engagementId}/recon-assets")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));

        group.MapGet("/", ListReconAssetsAsync).WithName(nameof(ListReconAssetsAsync));
        group.MapPost("/", RecordReconAssetAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(RecordReconAssetAsync));
        group.MapDelete("/{assetId}", DeleteReconAssetAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(DeleteReconAssetAsync));
        return endpoints;
    }

    private static async Task<Results<Ok<ReconAssetResponse[]>, BadRequest<Problem>, NotFound<Problem>>> ListReconAssetsAsync(
        string engagementId,
        IEngagementRepository engagements,
        IReconAssetStore assets,
        CancellationToken cancellationToken)
    {
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return TypedResults.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (await engagements.FindAsync(engagement, cancellationToken) is null)
            return TypedResults.NotFound(new Problem("Engagement does not exist."));

        var rows = await assets.ListByEngagementAsync(engagement, cancellationToken);
        return TypedResults.Ok(rows.Select(ReconAssetResponse.Of).ToArray());
    }

    private static async Task<IResult> RecordReconAssetAsync(
        string engagementId,
        RecordReconAssetRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        IReconAssetStore assets,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        var engagementRow = await engagements.FindAsync(engagement, cancellationToken);
        if (engagementRow is null)
            return Results.NotFound(new Problem("Engagement does not exist."));
        if (engagementRow.IsClosed)
            return Results.Conflict(new Problem("The engagement is closed to new deployments."));

        var kind = ParseKind(body.Kind);
        if (kind is null)
            return Results.BadRequest(new Problem(
                "Kind must be one of 'email', 'domain', 'host', or 'address'."));

        var value = body.Value?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(value) || value.Length > MaxValueChars)
            return Results.BadRequest(new Problem($"Value must be 1-{MaxValueChars} characters."));
        if (!KindAccepts(kind.Value, value))
            return Results.BadRequest(new Problem(KindShapeMessage(kind.Value)));

        var displayName = string.IsNullOrWhiteSpace(body.DisplayName) ? null : body.DisplayName.Trim();
        if (displayName?.Length > MaxValueChars)
            return Results.BadRequest(new Problem($"The display name exceeds {MaxValueChars} characters."));

        var sourceArtifact = body.SourceArtifactId?.Trim().ToLowerInvariant();
        Guid? sourceArtifactId = null;
        if (sourceArtifact is { Length: > 0 })
        {
            if (!Guid.TryParse(sourceArtifact, out var artifactValue))
                return Results.BadRequest(new Problem("Source artifact id is not a valid identifier."));
            sourceArtifactId = artifactValue;
        }

        // One address is one target: the identity check answers 409 naming
        // the row that already carries it (the store's own check and the
        // durable twin's unique index close the same race from both ends).
        if (await assets.FindAsync(engagement, kind.Value, value, cancellationToken) is { } existing)
            return Results.Conflict(new Problem(
                $"{kind.Value} '{value}' is already on the target list as asset {existing.Id}."));

        var at = clock.GetUtcNow();
        var asset = new ReconAsset(
            ReconAssetId.New(), engagement, kind.Value, value, displayName,
            sourceArtifactId, operatorId.Value, at);
        if (!await assets.AddAsync(asset, cancellationToken))
            return Results.Conflict(new Problem(
                $"{kind.Value} '{value}' is already on the target list."));

        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "recon.asset",
                kind: AuditEventKind.ReconAssetRecorded,
                payload: $"{kind.Value.ToString().ToLowerInvariant()};{value}"
                    + (sourceArtifactId is { } artifact ? $" from=artifact:{artifact:N}" : ""),
                output: null,
                outcome: asset.Id.ToString(),
                at: at),
            cancellationToken);

        return Results.Created(
            $"/engagements/{engagement}/recon-assets/{asset.Id}",
            ReconAssetResponse.Of(asset));
    }

    private static async Task<IResult> DeleteReconAssetAsync(
        string engagementId,
        string assetId,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        IReconAssetStore assets,
        ICampaignStore campaigns,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!ReconAssetId.TryParse(assetId, out var asset))
            return Results.BadRequest(new Problem("Asset id is not a valid identifier."));

        var engagementRow = await engagements.FindAsync(engagement, cancellationToken);
        if (engagementRow is null)
            return Results.NotFound(new Problem("Engagement does not exist."));
        if (engagementRow.IsClosed)
            return Results.Conflict(new Problem("The engagement is closed to new deployments."));

        var row = await assets.FindAsync(asset, engagement, cancellationToken);
        if (row is null)
            return Results.NotFound(new Problem("Asset does not exist in this engagement."));

        // A target an engagement already aimed at stays on the books: the
        // campaign rows hold the selection as their record, so the delete
        // is refused while any recipient references the asset. The
        // composite foreign key is the same refusal's race backstop.
        var referencing = (await campaigns.ListByEngagementAsync(engagement, cancellationToken))
            .SelectMany(c => c.Recipients.Where(r => r.ReconAssetId == asset))
            .ToList();
        if (referencing.Count > 0)
            return Results.Conflict(new Problem(
                $"Asset {asset} is the recorded target of {referencing.Count} campaign recipient(s); a selected target stays on the list."));

        if (!await assets.RemoveAsync(asset, engagement, cancellationToken))
            return Results.NotFound(new Problem("Asset does not exist in this engagement."));

        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "recon.asset",
                kind: AuditEventKind.ReconAssetDeleted,
                payload: $"{row.Kind.ToString().ToLowerInvariant()};{row.Value}",
                output: null,
                outcome: row.Id.ToString(),
                at: clock.GetUtcNow()),
            cancellationToken);

        return Results.NoContent();
    }

    // One bound covers every kind: the email limit (320) is the longest of
    // the set, and a DNS name caps at 255 by its own protocol.
    private const int MaxValueChars = 320;

    private static ReconAssetKind? ParseKind(string? kind) => kind?.Trim().ToLowerInvariant() switch
    {
        "email" => ReconAssetKind.Email,
        "domain" => ReconAssetKind.Domain,
        "host" => ReconAssetKind.Host,
        "address" => ReconAssetKind.Address,
        _ => null,
    };

    // Shape per kind, as loose and honest as the workbench's target
    // grammar: an email is one @ with mailboxes either side, a domain or
    // host is a DNS label sequence, an address is an IP literal. No
    // resolution, no scheme, no path -- and deliberately no
    // mailbox-protocol parsing; the campaign create validates the
    // resolved address with the mail grammar when it matters.
    private static bool KindAccepts(ReconAssetKind kind, string value) => kind switch
    {
        ReconAssetKind.Email => IsEmailAddress(value),
        ReconAssetKind.Domain or ReconAssetKind.Host => IsDomainName(value),
        ReconAssetKind.Address => IPAddress.TryParse(value, out _),
        _ => false,
    };

    private static string KindShapeMessage(ReconAssetKind kind) => kind switch
    {
        ReconAssetKind.Email => "Value must be one email address.",
        ReconAssetKind.Domain => "Value must be a domain name.",
        ReconAssetKind.Host => "Value must be a hostname.",
        ReconAssetKind.Address => "Value must be an IP address.",
        _ => "Value does not fit the kind.",
    };

    private static bool IsEmailAddress(string value)
    {
        var at = value.IndexOf('@');
        return at > 0
            && at < value.Length - 1
            && value.IndexOf('@', at + 1) < 0
            && !value.Any(char.IsWhiteSpace);
    }

    // The workbench's target grammar (Sec 11.4), the one shared copy: a
    // DNS label sequence, nothing more.
    internal static bool IsDomainName(string target)
    {
        if (target.Length is 0 or > 253 || !target.Contains('.'))
            return false;
        foreach (var label in target.Split('.'))
        {
            if (label.Length is < 1 or > 63)
                return false;
            if (label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
                return false;
            if (label.StartsWith('-') || label.EndsWith('-'))
                return false;
        }
        return true;
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    public sealed record RecordReconAssetRequest(
        string? Kind,
        string? Value,
        string? DisplayName = null,
        string? SourceArtifactId = null);

    public sealed record ReconAssetResponse(
        string AssetId,
        string Kind,
        string Value,
        string? DisplayName,
        string? SourceArtifactId,
        string CreatedBy,
        DateTimeOffset CreatedAt)
    {
        public static ReconAssetResponse Of(ReconAsset asset) => new(
            asset.Id.ToString(),
            asset.Kind.ToString().ToLowerInvariant(),
            asset.Value,
            asset.DisplayName,
            asset.SourceArtifactId?.ToString("N"),
            asset.CreatedBy.ToString(),
            asset.CreatedAt);
    }
}
