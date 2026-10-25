using System.Collections.Concurrent;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Deployment;
using Rod.CoreState.Engagements;
using Rod.CoreState.Listeners;

namespace Rod.Transport.Range;

/// <summary>A range refusal: operator-readable, mapped by the endpoints onto
/// the HTTP problem shape. Carries no state worth chaining.</summary>
public sealed class RangeException(string message) : Exception(message);

/// <summary>
/// The range engine (architecture.md Sec 15.3): the action domain's simulated
/// provider. One fleet per engagement at a time -- a spawn replaces whatever
/// fleet the engagement carried, the same authority every engagement-scoped
/// surface applies. The beacons are protocol-real clients of this same
/// process's listeners; the engine itself owns only their lifecycles and the
/// one credential they share. Everything the beacons produce -- roster rows,
/// sessions, task arcs, the audit chain -- comes from the real ingress paths,
/// never from a shortcut.
/// </summary>
public sealed class RangeFleet : IAsyncDisposable
{
    /// <summary>The enrollment budget's ceiling: one fleet's beacons all draw
    /// on one multi-use token, so the ceiling names the largest simulated
    /// fleet a single spawn may field.</summary>
    public const int MaxBeaconsPerSpawn = 2000;

    private static readonly TimeSpan TokenLifetime = TimeSpan.FromHours(24);

    private readonly IEngagementRepository _engagements;
    private readonly IListenerStore _listeners;
    private readonly IDeployTokenService _tokens;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;

    private readonly ConcurrentDictionary<Guid, Fleet> _fleets = new();

    public RangeFleet(
        IEngagementRepository engagements,
        IListenerStore listeners,
        IDeployTokenService tokens,
        IAuditStore audit,
        TimeProvider clock)
    {
        _engagements = engagements;
        _listeners = listeners;
        _tokens = tokens;
        _audit = audit;
        _clock = clock;
    }

    /// <summary>Spawns (or replaces) an engagement's fleet. The spawn is one
    /// operator action with one audit fact and one shared enrollment
    /// credential; the beacons enroll through the listener's real ingress
    /// like any deployment would.</summary>
    public async Task<RangeFleetStatus> SpawnAsync(RangeSpawnCommand command, CancellationToken cancellationToken)
    {
        var engagement = await _engagements.FindAsync(command.EngagementId, cancellationToken)
            ?? throw new RangeException("The engagement does not exist.");
        if (!engagement.Range)
            throw new RangeException(
                "This engagement is not a range; create it with range: true to field simulated beacons.");
        if (engagement.IsClosed)
            throw new RangeException("The engagement is closed; a range fleet needs an open engagement.");

        var listener = await _listeners.FindAsync(command.ListenerId, cancellationToken)
            ?? throw new RangeException("The listener does not exist.");
        if (listener.EngagementId != engagement.Id)
            throw new RangeException("The listener does not exist in this engagement.");
        if (!string.Equals(listener.Transport, "http", StringComparison.OrdinalIgnoreCase))
            throw new RangeException(
                "A range fleet contacts over the cleartext lab posture (plaintext framed bodies under the "
                + $"listener's own bind); '{listener.Transport}' is not that. Create an http listener for the range.");

        // A respawn replaces the standing fleet -- one fleet per engagement,
        // the shape every engagement-scoped surface holds.
        if (_fleets.TryGetValue(engagement.Id.Value, out var standing))
            await StopFleetAsync(standing, command.OperatorId, cancellationToken, audited: false);

        // One credential for the whole fleet: a multi-use deploy token, minted
        // through the same service a manual mint or a payload build rides --
        // the trail's mint fact attributes every simulated enrollment to this
        // spawn's operator.
        var now = _clock.GetUtcNow();
        var token = await _tokens.MintAsync(
            engagement.Id, command.OperatorId, now, command.Count, TokenLifetime, cancellationToken);
        await _audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Id.Value,
                operatorId: command.OperatorId.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "range-spawn",
                kind: AuditEventKind.RangeFleetSpawned,
                payload: $"listener={listener.Name} beacons={command.Count} prefix={command.Prefix} "
                    + $"sleep={command.SleepSeconds}s jitter={command.JitterSeconds}s "
                    + $"goDark={command.GoDarkCount} os={command.Os}/{command.Arch}",
                output: null,
                outcome: token.Id.ToString(),
                at: now),
            cancellationToken);

        var handler = new SocketsHttpHandler();
        var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        var fleet = new Fleet
        {
            EngagementId = engagement.Id.Value,
            Cancellation = new CancellationTokenSource(),
            Handler = handler,
            Http = http,
            Requested = command.Count,
            Prefix = command.Prefix,
            ListenerName = listener.Name,
            SpawnedAt = now,
            Beacons = new List<RangeBeacon>(command.Count),
        };
        var @base = DialBase(listener.BindAddress);

        // The dark legs' timing: named values run deterministically (a
        // trainer scripting the moment a beacon drops), the default scatters
        // both edges across a minute so a standing fleet churns naturally.
        var darkAfter = command.DarkAfterSeconds is { } after
            ? TimeSpan.FromSeconds(after)
            : TimeSpan.FromSeconds(20 + Random.Shared.Next(0, 40));
        var darkFor = command.DarkForSeconds is { } forSeconds
            ? TimeSpan.FromSeconds(forSeconds)
            : TimeSpan.FromSeconds(30 + Random.Shared.Next(0, 60));

        // The enrollment gate bounds the burst: a large fleet enrolls in
        // waves rather than as one simultaneous spike, the shape a real
        // deployment campaign's fetches take. The gate holds enrollments
        // only -- a beacon's contact lifetime never waits on it.
        var gate = new SemaphoreSlim(48);
        for (var i = 0; i < command.Count; i++)
        {
            var goDark = i >= command.Count - command.GoDarkCount;
            fleet.Beacons.Add(new RangeBeacon(
                fleet.Http,
                @base,
                token.Secret,
                hostname: $"{command.Prefix}-{i:d3}",
                os: command.Os,
                arch: command.Arch,
                sleepSeconds: command.SleepSeconds,
                jitterSeconds: command.JitterSeconds,
                goDarkAfter: goDark ? darkAfter : null,
                darkFor: goDark ? darkFor : TimeSpan.Zero));
        }

        foreach (var beacon in fleet.Beacons)
            fleet.Loops.Add(Task.Run(() => beacon.RunAsync(gate, fleet.Cancellation.Token), CancellationToken.None));

        _fleets[engagement.Id.Value] = fleet;
        return StatusOf(command.EngagementId)!;
    }

    /// <summary>The fleet's aggregate posture, or null when the engagement
    /// fields no fleet.</summary>
    public RangeFleetStatus? StatusOf(EngagementId engagement)
        => _fleets.TryGetValue(engagement.Value, out var fleet) ? Snapshot(fleet) : null;

    /// <summary>Stops the engagement's fleet: every beacon loop cancelled,
    /// the shared connection pool disposed, the stop audited to the acting
    /// operator.</summary>
    public async Task<RangeFleetStatus?> StopAsync(
        EngagementId engagement, OperatorId @operator, CancellationToken cancellationToken)
    {
        if (!_fleets.TryGetValue(engagement.Value, out var fleet))
            return null;
        var snapshot = await StopFleetAsync(fleet, @operator, cancellationToken, audited: true);
        _fleets.TryRemove(engagement.Value, out _);
        return snapshot;
    }

    private async Task<RangeFleetStatus> StopFleetAsync(
        Fleet fleet, OperatorId @operator, CancellationToken cancellationToken, bool audited)
    {
        fleet.Cancellation.Cancel();
        try
        {
            await Task.WhenAll(fleet.Loops).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);
        }
        catch (TimeoutException)
        {
            // A loop wedged past the grace period is abandoned; its beacon
            // reads Failed in the final snapshot and the pool disposal
            // severs whatever connection it held.
        }
        catch (Exception)
        {
            // Loop bodies capture their own failures into beacon state; a
            // cancellation that reached a loop between the gate and its run
            // surfaces here and is already the stop we asked for.
        }
        fleet.Http.Dispose();
        fleet.Handler.Dispose();
        fleet.Cancellation.Dispose();
        fleet.Stopped = true;

        if (audited)
        {
            var snapshot = Snapshot(fleet);
            await _audit.AppendAsync(
                AuditEvent.Fact(
                    eventId: Guid.NewGuid(),
                    engagementId: fleet.EngagementId,
                    operatorId: @operator.Value,
                    implantId: Guid.Empty,
                    taskId: Guid.Empty,
                    verb: "range-stop",
                    kind: AuditEventKind.RangeFleetStopped,
                    payload: $"beacons={snapshot.Requested} contacts={snapshot.Contacts} results={snapshot.Results}",
                    output: null,
                    outcome: fleet.ListenerName,
                    at: _clock.GetUtcNow()),
                cancellationToken);
            return snapshot;
        }
        return Snapshot(fleet);
    }

    private static RangeFleetStatus Snapshot(Fleet fleet)
    {
        var recentErrors = fleet.Beacons
            .Where(b => b.Error is not null)
            .Take(8)
            .Select(b => $"{b.Hostname}: {b.Error}")
            .ToList();
        return new RangeFleetStatus(
            fleet.Requested,
            fleet.Beacons.Count(b => b.ImplantId is not null),
            fleet.Beacons.Count(b => b.State == RangeBeaconState.Contacting),
            fleet.Beacons.Count(b => b.State == RangeBeaconState.Dark),
            fleet.Beacons.Count(b => b.State == RangeBeaconState.Stopped),
            fleet.Beacons.Count(b => b.State == RangeBeaconState.Failed),
            fleet.Beacons.Sum(b => b.Contacts),
            fleet.Beacons.Sum(b => b.Results),
            fleet.SpawnedAt,
            fleet.Prefix,
            recentErrors);
    }

    /// <summary>
    /// The dial base off a listener's bind: the beacon speaks to this
    /// process's own socket, not the public endpoint a redirector would
    /// front -- the range exercises the platform's full ingress path (the
    /// route, the gates, the audit), and the one leg it cannot exercise from
    /// in here is the network hop in front of the bind. A wildcard bind
    /// names no dialable address; the loopback it actually listens on does.
    /// </summary>
    private static Uri DialBase(string bindAddress)
    {
        var separator = bindAddress.LastIndexOf(':');
        if (separator <= 0)
            throw new RangeException($"The listener bind '{bindAddress}' is not a host:port shape.");
        var host = bindAddress[..separator];
        if (host is "0.0.0.0" or "::" or "+" or "*")
            host = "127.0.0.1";
        return new Uri($"http://{host}:{bindAddress[(separator + 1)..]}");
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var fleet in _fleets.Values)
            await StopFleetAsync(fleet, default, CancellationToken.None, audited: false);
        _fleets.Clear();
    }

    private sealed class Fleet
    {
        public required CancellationTokenSource Cancellation { get; init; }
        public required SocketsHttpHandler Handler { get; init; }
        public required HttpClient Http { get; set; }
        public required int Requested { get; init; }
        public required string Prefix { get; init; }
        public required string ListenerName { get; init; }
        public required DateTimeOffset SpawnedAt { get; init; }
        public required List<RangeBeacon> Beacons { get; init; }
        public List<Task> Loops { get; } = [];
        public bool Stopped;
        public Guid EngagementId;
    }
}

/// <summary>One spawn's shape, validated by the endpoints before the engine
/// sees it.</summary>
public sealed record RangeSpawnCommand(
    EngagementId EngagementId,
    OperatorId OperatorId,
    Guid ListenerId,
    int Count,
    double SleepSeconds,
    double JitterSeconds,
    int GoDarkCount,
    string Prefix,
    string Os,
    string Arch,
    double? DarkAfterSeconds = null,
    double? DarkForSeconds = null);

/// <summary>The fleet's aggregate posture, the status read's response.</summary>
public sealed record RangeFleetStatus(
    int Requested,
    int Enrolled,
    int Contacting,
    int Dark,
    int Stopped,
    int Failed,
    long Contacts,
    long Results,
    DateTimeOffset SpawnedAt,
    string Prefix,
    IReadOnlyList<string> RecentErrors);
