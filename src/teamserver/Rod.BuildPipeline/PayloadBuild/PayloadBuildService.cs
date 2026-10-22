using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// The teamserver-side orchestrator that drives build units (architecture.md
/// Sec 6). On a payload request it resolves the language's build unit, generates
/// the per-implant material at request time (the key and the kill date are made
/// here so each artifact is unique -- Sec 6/Sec 5.1), assembles the
/// <see cref="BuildParams"/>, asks the unit to build, and runs the post-build
/// <see cref="PayloadTransformChain"/> over the result -- the transform seam
/// (Sec 6): the stored bytes are the transformed bytes, the fingerprint covers
/// them, and the applied transform names ride the artifact into the audit
/// trail. Returns the fingerprinted artifact for the transport layer to record.
///
/// Like <see cref="Rod.CoreState.Application.TaskService"/>, this service is
/// audit-agnostic by design: it produces the build, and the transport endpoint
/// composes the audit write (Sec 11). It depends only on core state and the
/// build contract, so the layer rule (BuildPipeline -> CoreState) is unchanged.
/// </summary>
public sealed class PayloadBuildService
{
    private readonly IBuildUnitRegistry _buildUnits;
    private readonly TimeProvider _clock;
    private readonly PayloadTransformChain _transforms;
    private readonly BuildDiagnostics? _diagnostics;

    // The ceiling on builds in flight. The background job queue is serial by
    // design, but the synchronous endpoint runs whatever arrives: N
    // concurrent requests would otherwise be N full tree copies and N cargo
    // processes. Past the gate a request waits its turn instead of exhausting
    // the host. An environment variable overrides the default; one keeps the
    // everything-serial shape. Instance-level, not static: the limit is one
    // deployment's (one host's) toolchain contention, and a process hosting
    // two independently wired stacks -- the test harnesses most visibly --
    // must not serialize one stack's builds behind the other's.
    private readonly SemaphoreSlim _buildGate = new(ResolveMaxConcurrentBuilds());

    private static int ResolveMaxConcurrentBuilds()
        => int.TryParse(Environment.GetEnvironmentVariable("ROD_BUILD_MAX_CONCURRENCY"), out var limit)
            && limit >= 1
            ? limit
            : 2;

    public PayloadBuildService(IBuildUnitRegistry buildUnits, TimeProvider clock)
        : this(buildUnits, clock, PayloadTransformChain.Empty)
    {
    }

    /// <summary>
    /// Constructs the service with a post-build transform chain (architecture.md
    /// Sec 6, the transform seam): the composition root passes the config-loaded
    /// chain; the simpler constructor keeps the empty default so direct
    /// constructions (the unit tests, bare hosts) see bytes exactly as the build
    /// unit produced them.
    /// </summary>
    public PayloadBuildService(
        IBuildUnitRegistry buildUnits,
        TimeProvider clock,
        PayloadTransformChain transforms)
    {
        _buildUnits = buildUnits;
        _clock = clock;
        _transforms = transforms;
    }

    /// <summary>
    /// The diagnostics-recording constructor (architecture.md Sec 15.3,
    /// ADR-008): the host's composition registers the shared
    /// <see cref="BuildDiagnostics"/> beside this service and passes it here;
    /// direct constructions keep the simpler shapes and record nothing.
    /// </summary>
    public PayloadBuildService(
        IBuildUnitRegistry buildUnits,
        TimeProvider clock,
        PayloadTransformChain transforms,
        BuildDiagnostics diagnostics)
        : this(buildUnits, clock, transforms)
    {
        _diagnostics = diagnostics;
    }

    /// <summary>
    /// Builds a payload for the request's engagement and class. The kill date is
    /// resolved at request time, so two builds of the same request still never
    /// share an artifact (the baked profile and the compiler see to that).
    /// Throws <see cref="InvalidOperationException"/> when no build unit is
    /// registered for the requested language.
    /// </summary>
    public async Task<BuildArtifact> BuildAsync(
        BuildRequest request,
        CancellationToken cancellationToken = default)
    {
        var unit = _buildUnits.Find(request.Language)
            ?? throw new InvalidOperationException(
                $"No build unit registered for language {request.Language}.");

        // One gate for both callers (the serial job queue and the synchronous
        // endpoint), so the host never runs an unbounded set of toolchains.
        _diagnostics?.Started();
        await _buildGate.WaitAsync(cancellationToken);
        try
        {
            // Duration prices the build and its transforms, not the wait for
            // the gate: queue delay shows up as in-flight, not as duration.
            var started = System.Diagnostics.Stopwatch.GetTimestamp();
            bool succeeded = false;
            try
            {
                var artifact = await BuildUngatedAsync(unit, request, cancellationToken);
                succeeded = true;
                return artifact;
            }
            finally
            {
                _diagnostics?.Record(
                    System.Diagnostics.Stopwatch.GetElapsedTime(started), succeeded);
            }
        }
        finally
        {
            _buildGate.Release();
        }
    }

    private async Task<BuildArtifact> BuildUngatedAsync(
        IBuildUnit unit,
        BuildRequest request,
        CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow();

        var @params = new BuildParams(
            request.EngagementId,
            request.RequestedBy,
            request.Class,
            request.Target,
            request.Transport,
            new BeaconProfile(
                request.Sleep, request.Jitter, ResolveKillDate(now, request.KillDate), request.Mode),
            request.TokenSecret,
            request.MintedTokenId,
            request.TokenMaxUses,
            request.EnvelopeKeyId,
            request.EnvelopeKey,
            request.Format,
            request.Kind,
            request.DeliversPayloadId);

        var built = await unit.BuildAsync(@params, cancellationToken);

        // The transform seam (architecture.md Sec 6): the chain runs over the
        // unit's output before the artifact is recorded, so the fingerprint
        // the operator sees and the trail stores cover exactly the bytes the
        // target will run. An empty chain passes the bytes through untouched.
        var (content, applied) = await _transforms.ApplyAsync(@params, built.Content, cancellationToken);
        if (applied.Count == 0)
            return built;

        return BuildArtifact.Of(unit.Language, built.ArtifactId, @params, content, built.ContentType, built.BuiltAt)
            with
        {
            Transforms = applied
        };
    }

    // The kill date is the artifact's optional time fuse: a pinned future date
    // wins, and an unset (or past) one means none -- the open-ended long-haul
    // posture. Public because a build's baked token defaults to the same
    // window: the credential lives exactly as long as the artifact it rides.
    public static DateTimeOffset? ResolveKillDate(DateTimeOffset now, DateTimeOffset? requested)
    {
        if (requested is { } pinned && pinned > now)
            return pinned;
        return null;
    }
}

/// <summary>
/// Request to build a payload. <see cref="EngagementId"/> scopes and
/// <see cref="RequestedBy"/> attributes the build; <see cref="Language"/> routes
/// to the build unit; <see cref="Class"/> is the implant class to generate.
/// <see cref="TokenSecret"/> is the enrollment credential the build bakes in
/// (the transport layer mints it and attaches it here); null leaves the
/// artifact credential-free. <see cref="TokenMaxUses"/> rides beside it as the
/// minted budget the library's build snapshot records. <see cref="EnvelopeKeyId"/>
/// and <see cref="EnvelopeKey"/> are the per-artifact AES-GCM envelope pair the
/// transport layer mints when the profile's envelope is AesGcm; null on every
/// other envelope. On a loader build the pair is the stage seal and mints
/// unconditionally. <see cref="Format"/> names the artifact form factor the
/// unit emits; it defaults to the single-file executable.
/// <see cref="Kind"/> names the delivery tier; <see cref="DeliversPayloadId"/>
/// names the stored payload a loader build delivers.
/// </summary>
public sealed record BuildRequest(
    EngagementId EngagementId,
    OperatorId RequestedBy,
    Language Language,
    ImplantClass Class,
    TargetProfile Target,
    TransportProfile Transport,
    TimeSpan Sleep,
    TimeSpan Jitter,
    DateTimeOffset? KillDate,
    string Mode = "poll",
    string? TokenSecret = null,
    Guid? MintedTokenId = null,
    int? TokenMaxUses = null,
    Guid? EnvelopeKeyId = null,
    byte[]? EnvelopeKey = null,
    ArtifactFormat Format = ArtifactFormat.SingleFileExe,
    PayloadKind Kind = PayloadKind.Implant,
    Guid? DeliversPayloadId = null);
