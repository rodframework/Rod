using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Operators;
using Rod.Transport.Payloads;

namespace Rod.Transport.Endpoints;

/// <summary>
/// The background payload-build endpoints. <c>POST /engagements/{id}/payload-jobs</c>
/// accepts the same body the synchronous <c>POST /payloads</c> takes, validates
/// it the same way, and returns 202 with the queued job; the build then runs on
/// the job service's single worker and finishes into the payload store and the
/// audit trail exactly like a synchronous build. <c>GET</c> reads the
/// engagement's jobs (newest first) and one job's state, so the operator UI --
/// or any browser refresh of it -- observes progress and retrieves the
/// finished artifact without holding a request open for the toolchain.
/// </summary>
public static class PayloadJobEndpoints
{
    public static IEndpointRouteBuilder MapPayloadJobEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints
            .MapGroup("/engagements/{engagementId}/payload-jobs")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));

        group.MapPost("/", EnqueueBuildJobAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(EnqueueBuildJobAsync));
        group.MapGet("/", ListBuildJobsAsync).WithName(nameof(ListBuildJobsAsync));
        group.MapGet("/{jobId}", GetBuildJobAsync).WithName(nameof(GetBuildJobAsync));

        return endpoints;
    }

    private static async Task<IResult> EnqueueBuildJobAsync(
        string engagementId,
        PayloadEndpoints.BuildPayloadRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        IPayloadStore payloads,
        Rod.Transport.Listeners.IListenerRegistry listeners,
        Rod.CoreState.Pki.IImplantCertificateAuthority ca,
        Rod.CoreState.Deployment.IDeployTokenService tokens,
        TimeProvider clock,
        IAuditStore audit,
        PayloadBuildJobService jobs,
        Listeners.WireGuard.WireGuardOptions wireGuard,
        Listeners.WireGuard.WireGuardTunnelRegistry wireGuardTunnels,
        CancellationToken cancellationToken)
    {
        var requestedBy = user.TryGetOperatorId();
        if (requestedBy is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        // Same existence rule as the synchronous build: no artifacts against an
        // engagement with no record.
        var engagement = await engagements.FindAsync(new EngagementId(engagementValue), cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));

        var (parsed, error) = await PayloadBuildRequestParser.ParseAsync(
            body, new EngagementId(engagementValue), requestedBy.Value, listeners, ca, payloads, cancellationToken,
            wireGuard, wireGuardTunnels);
        if (error is not null)
            return Results.BadRequest(new Problem(error));

        // The enrollment credential mints at enqueue and rides the queued
        // request into the bake -- identical to the synchronous path, including
        // the per-artifact envelope key whenever a phase needs it: the AesGcm
        // enroll envelope or contact protection (the default).
        var (secret, tokenId) = await PayloadBuildTokenMinter.MintAsync(
            engagement!, body, tokens, clock, audit, cancellationToken);
        var request = parsed! with
        {
            TokenSecret = secret,
            MintedTokenId = tokenId.Value,
            TokenMaxUses = body.TokenMaxUses ?? 1,
        };
        if (request.Transport.Envelope == TransportEnvelope.AesGcm
            || request.Transport.ContactProtection
            // The loader's key pair is the stage seal, minted whatever the
            // envelope knobs say.
            || request.Kind == PayloadKind.Loader)
        {
            var (envelopeKeyId, envelopeKey) = AesGcmEnvelope.Mint();
            request = request with { EnvelopeKeyId = envelopeKeyId, EnvelopeKey = envelopeKey };
        }

        var job = jobs.Enqueue(request);
        return Results.Accepted(
            $"/engagements/{engagementId}/payload-jobs/{job.JobId}",
            PayloadJobResponse.Of(job));
    }

    private static async Task<IResult> ListBuildJobsAsync(
        string engagementId,
        IEngagementRepository engagements,
        PayloadBuildJobService jobs,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        var engagement = await engagements.FindAsync(new EngagementId(engagementValue), cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));

        return Results.Ok(jobs.List(engagementValue).Select(PayloadJobResponse.Of).ToArray());
    }

    private static async Task<IResult> GetBuildJobAsync(
        string engagementId,
        string jobId,
        IEngagementRepository engagements,
        PayloadBuildJobService jobs,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(jobId, out var jobValue))
            return Results.BadRequest(new Problem("Job id is not a valid identifier."));

        var engagement = await engagements.FindAsync(new EngagementId(engagementValue), cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));

        // The job lookup is scoped by engagement, so one engagement's job id is
        // not addressable from another -- the same scoping every store read
        // applies.
        var job = jobs.Find(engagementValue, jobValue);
        if (job is null)
            return Results.NotFound(new Problem("Build job does not exist."));

        return Results.Ok(PayloadJobResponse.Of(job));
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    public sealed record PayloadJobResponse(
        string JobId,
        string EngagementId,
        string State,
        string RequestedBy,
        DateTimeOffset RequestedAt,
        DateTimeOffset? StartedAt,
        DateTimeOffset? CompletedAt,
        string Class,
        string Unit,
        string Target,
        string Endpoint,
        string Mode,
        string? Error,
        PayloadEndpoints.BuildPayloadResponse? Artifact)
    {
        public static PayloadJobResponse Of(PayloadBuildJob job) => new(
            job.JobId.ToString(),
            job.EngagementId.ToString(),
            job.State.ToString().ToLowerInvariant(),
            job.RequestedBy.ToString(),
            job.RequestedAt,
            job.StartedAt,
            job.CompletedAt,
            job.Request.Class.ToString(),
            job.Request.Unit,
            $"{job.Request.Target.OperatingSystem}/{job.Request.Target.Architecture}",
            job.Request.Transport.Endpoint,
            job.Request.Mode,
            job.Error,
            job.Artifact);
    }

}
