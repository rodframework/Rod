using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.CoreState;
using Rod.CoreState.Operators;
using Rod.Transport.Range;
using System.Security.Claims;

namespace Rod.Transport.Endpoints;

/// <summary>
/// Range mode's operator surface (architecture.md Sec 15.3): spawn the
/// simulated fleet, read its posture, stop it. The routes mount only when the
/// deployment enables range mode (<c>Range:Enabled</c>) -- absent, the surface
/// does not exist, and spawning on an engagement that is not a range refuses
/// with guidance. The fleet is a first-class action-domain citizen: its
/// beacons appear on the roster, task through the same task log, and write
/// the same audit arcs as any implant, which is the point -- the operator's
/// console needs no range-specific view.
/// </summary>
public static class RangeEndpoints
{
    public static IEndpointRouteBuilder MapRangeEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints
            .MapGroup("/engagements/{engagementId}")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));

        group.MapPost("/range:spawn", SpawnAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(SpawnAsync));
        group.MapGet("/range", StatusAsync).WithName(nameof(StatusAsync));
        group.MapPost("/range:stop", StopAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(StopAsync));

        return endpoints;
    }

    private static async Task<IResult> SpawnAsync(
        string engagementId,
        RangeSpawnRequest body,
        ClaimsPrincipal user,
        RangeFleet fleet,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();

        if (body.Count is < 1 or > RangeFleet.MaxBeaconsPerSpawn)
            return Results.BadRequest(new Problem($"Count must be between 1 and {RangeFleet.MaxBeaconsPerSpawn}."));
        var sleep = body.SleepSeconds ?? 5;
        var jitter = body.JitterSeconds ?? 2;
        if (sleep is < 1 or > 3600)
            return Results.BadRequest(new Problem("SleepSeconds must be between 1 and 3600."));
        if (jitter is < 0 or > 60)
            return Results.BadRequest(new Problem("JitterSeconds must be between 0 and 60."));
        var goDark = body.GoDarkCount ?? 0;
        if (goDark < 0 || goDark > body.Count)
            return Results.BadRequest(new Problem("GoDarkCount must be between 0 and Count."));
        var prefix = string.IsNullOrWhiteSpace(body.Prefix) ? "range" : body.Prefix.Trim();
        if (prefix.Length > 32 || !prefix.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
            return Results.BadRequest(new Problem("Prefix must be letters, digits, and hyphens, at most 32 characters."));

        try
        {
            var status = await fleet.SpawnAsync(
                new RangeSpawnCommand(
                    new EngagementId(engagementValue),
                    operatorId.Value,
                    body.ListenerId,
                    body.Count,
                    sleep,
                    jitter,
                    goDark,
                    prefix,
                    body.Os ?? "linux",
                    body.Arch ?? "amd64",
                    body.DarkAfterSeconds,
                    body.DarkForSeconds),
                cancellationToken);
            return Results.Accepted($"/engagements/{engagementValue}/range", status);
        }
        catch (RangeException refusal)
        {
            return Results.BadRequest(new Problem(refusal.Message));
        }
    }

    private static IResult StatusAsync(string engagementId, RangeFleet fleet)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        return fleet.StatusOf(new EngagementId(engagementValue)) is { } status
            ? Results.Ok(status)
            : Results.NotFound(new Problem("This engagement fields no range fleet."));
    }

    private static async Task<IResult> StopAsync(
        string engagementId,
        ClaimsPrincipal user,
        RangeFleet fleet,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();

        var status = await fleet.StopAsync(new EngagementId(engagementValue), operatorId.Value, cancellationToken);
        return status is null
            ? Results.NotFound(new Problem("This engagement fields no range fleet."))
            : Results.Ok(status);
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    /// <summary>One spawn: the listener the fleet dials, the fleet's size and
    /// cadence, and the simulated host shape. GoDarkCount beacons (the last
    /// N of the fleet) go dark once and return as the same identities; the
    /// dark timings default to a scattered minute, and named values run
    /// deterministically -- a trainer scripting the moment a beacon
    /// drops.</summary>
    public sealed record RangeSpawnRequest(
        Guid ListenerId,
        int Count,
        double? SleepSeconds = null,
        double? JitterSeconds = null,
        int? GoDarkCount = null,
        string? Prefix = null,
        string? Os = null,
        string? Arch = null,
        double? DarkAfterSeconds = null,
        double? DarkForSeconds = null);
}
