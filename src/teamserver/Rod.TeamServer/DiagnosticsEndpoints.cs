using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.BuildPipeline.PayloadBuild;
using Rod.Capabilities.Core;
using Rod.Capabilities.Registry;
using Rod.CoreState.Live;
using Rod.CoreState.Operators;
using Rod.CoreState.Tasks;
using Rod.Operators.Live;
using Rod.Transport;

namespace Rod.TeamServer;

/// <summary>
/// The built-in diagnostics endpoint (architecture.md Sec 15.3, ADR-008): one
/// read of the deployment's own health -- beacon turnaround distribution, task
/// queue depth, connected operator streams, recent build durations, and the
/// loaded module set. No Prometheus, no exporter: everything here is an
/// in-process counter or an aggregate store read, per the deployment's
/// standing shape (teamserver + PostgreSQL, nothing beside them). Export, if
/// an engagement ever demands it, arrives as a module -- never as a standing
/// component.
/// </summary>
/// <remarks>
/// <para>
/// Mapped from the composition root, deliberately: the five dimensions live in
/// five different layers (transport's ingest, core state's task queue, the
/// operator layer's event bus, the build pipeline's ring, the capabilities
/// layer's registry), and transport -- which owns most operator endpoints --
/// cannot reference the outer layers that hold three of them
/// (architecture.md Sec 4.3's placement rule). The composition root sees every
/// layer, so it owns the aggregate read. Like the capability catalog, the
/// endpoint rides outside the versioned OpenAPI contract: this is the UI's
/// and the admin's operational face, not an SDK integration surface.
/// </para>
/// <para>
/// The read is the deployment admin's alone, the same claim the deployment
/// audit trail requires: every number crosses engagements by construction --
/// that is what a deployment aggregate is -- so a member scoped to one
/// engagement has no business reading it. The engagement-isolation red line
/// holds because the payload carries aggregates only: no engagement ids, no
/// implant names, no per-engagement breakdowns anywhere in the response.
/// </para>
/// </remarks>
public static class DiagnosticsEndpoints
{
    public static IEndpointRouteBuilder MapDiagnosticsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints
            .MapGroup("/diagnostics")
            .RequireAuthorization(policy => policy.RequireClaim(
                OperatorClaims.DeploymentRoleClaimType, DeploymentRoles.AdminName));
        group.MapGet("/", GetAsync).WithName(nameof(GetAsync));
        return endpoints;
    }

    private static async Task<IResult> GetAsync(
        BeaconDiagnostics beacons,
        ITaskRepository tasks,
        ILiveEventBus bus,
        BuildDiagnostics builds,
        ICapabilityRegistry capabilities,
        CancellationToken cancellationToken)
    {
        var taskCounts = await tasks.CountByStatusAsync(cancellationToken);
        return Results.Ok(new DiagnosticsResponse(
            Beacons: new BeaconSection(beacons.Snapshot()),
            TaskQueue: new TaskQueueSection(
                Queued: taskCounts.GetValueOrDefault(Rod.CoreState.Tasks.TaskStatus.Queued),
                Dispatched: taskCounts.GetValueOrDefault(Rod.CoreState.Tasks.TaskStatus.Dispatched),
                Completed: taskCounts.GetValueOrDefault(Rod.CoreState.Tasks.TaskStatus.Completed),
                Cancelled: taskCounts.GetValueOrDefault(Rod.CoreState.Tasks.TaskStatus.Cancelled)),
            OperatorStreams: new OperatorStreamsSection(
                // The null bus (a bare transport composition without the
                // operator layer) has no subscribers by definition.
                ConnectedStreams: bus is InMemoryLiveEventBus live ? live.ConnectedSubscribers : 0),
            Builds: builds.Snapshot(),
            Modules: await ModuleSection.OfAsync(capabilities, cancellationToken)));
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    public sealed record DiagnosticsResponse(
        BeaconSection Beacons,
        TaskQueueSection TaskQueue,
        OperatorStreamsSection OperatorStreams,
        BuildWindowSnapshot Builds,
        ModuleSection Modules);

    /// <summary>
    /// The beacon turnaround histogram: cumulative since process start,
    /// deployment-wide, one bucket per latency bound.
    /// </summary>
    public sealed record BeaconSection(IReadOnlyList<BeaconLatencyBucket> LatencyBuckets);

    /// <summary>
    /// Task counts by lifecycle status across the whole deployment -- the
    /// queue-depth number plus its neighbors, pure counts with no engagement
    /// dimension.
    /// </summary>
    public sealed record TaskQueueSection(long Queued, long Dispatched, long Completed, long Cancelled);

    /// <summary>How many operator event streams are connected right now.</summary>
    public sealed record OperatorStreamsSection(int ConnectedStreams);

    /// <summary>
    /// The loaded capability-module set: which modules stand behind which
    /// verbs, and how many registered verbs still ride the built-in
    /// placeholders. A module that failed to load never appears here -- the
    /// loader aborts startup on failure (fail-loudly), so the loaded set is
    /// exactly what booted.
    /// </summary>
    public sealed record ModuleSection(
        IReadOnlyList<LoadedModuleResponse> Loaded,
        int VerbsRegistered,
        int VerbsPlaceholder)
    {
        public static async Task<ModuleSection> OfAsync(
            ICapabilityRegistry registry,
            CancellationToken cancellationToken)
        {
            var descriptors = await registry.ListAsync(cancellationToken);
            var byModule = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            var placeholders = 0;
            foreach (var descriptor in descriptors)
            {
                var module = await registry.FindAsync(descriptor.Verb, cancellationToken);
                if (module is PlaceholderCapabilityModule)
                {
                    placeholders++;
                    continue;
                }
                var name = module!.Name ?? module.GetType().Name;
                if (!byModule.TryGetValue(name, out var verbs))
                    byModule[name] = verbs = new List<string>();
                verbs.Add(descriptor.Verb);
            }

            return new ModuleSection(
                byModule.Select(kv => new LoadedModuleResponse(kv.Key, kv.Value)).ToArray(),
                VerbsRegistered: descriptors.Count,
                VerbsPlaceholder: placeholders);
        }
    }

    /// <summary>One loaded module and the verbs it carries.</summary>
    public sealed record LoadedModuleResponse(string Name, IReadOnlyList<string> Verbs);
}
