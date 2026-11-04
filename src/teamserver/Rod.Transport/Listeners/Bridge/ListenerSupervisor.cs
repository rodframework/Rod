using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Rod.Audit;
using Rod.CoreState.Listeners;
using Rod.Transport.Listeners.Streams;

namespace Rod.Transport.Listeners.Bridge;

// The supervisor (ADR-025): the process half of the externalized listener.
// One supervised listener is one bridge endpoint (the local socket the
// kernel serves) and one child process (the package's server, spawned with
// the socket's name in its environment). Lifecycle is process management,
// not protocol: spawn, restart on exit, exit code as the health signal.
//
// The crash isolation runs one way -- toward the kernel. A dead child
// marks its listener Unhealthy, appends the exit fact to the engagement's
// audit trail, and the backoff schedule respawns it; no session state
// lived in the child (the kernel held every session), so a restart loses
// nothing the next contact does not re-establish. A dead supervisor --
// the kernel itself stopping -- kills the child and closes the socket:
// the listener process never outlives the kernel that spawned it.

/// <summary>
/// One supervised listener: the monitor task, the stop that ends it, and
/// the socket it served. Dispose stops the process (the whole tree),
/// waits the monitor out, and closes the endpoint.
/// </summary>
internal sealed class SupervisedListener : IAsyncDisposable
{
    private readonly CancellationTokenSource _stop;
    private readonly ListenerBridgeEndpoint _endpoint;

    public SupervisedListener(
        Task monitor,
        CancellationTokenSource stop,
        ListenerBridgeEndpoint endpoint)
    {
        Monitor = monitor;
        _stop = stop;
        _endpoint = endpoint;
    }

    /// <summary>The supervision loop; completes when stopped.</summary>
    public Task Monitor { get; }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        try
        {
            await Monitor;
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException
            or System.Net.Sockets.SocketException)
        {
        }
        await _endpoint.DisposeAsync();
        _stop.Dispose();
    }
}

/// <summary>
/// Spawns and supervises listener processes: binds the bridge endpoint,
/// starts the package's process against it, and keeps the process alive
/// until the handle is disposed.
/// </summary>
internal sealed class ListenerSupervisor
{
    // The restart backoff schedule: each exit waits the next step, capped
    // at the last. A process that ran stable for the reset window starts
    // the schedule over -- a crash after an hour is a fresh incident, not
    // the tail of a crash loop.
    private static readonly TimeSpan[] RestartBackoff =
    [
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(10),
    ];
    private static readonly TimeSpan StableRunReset = TimeSpan.FromSeconds(60);

    // How long a peer may hold the connection open before saying which
    // carriage it speaks: an unbounded hello read would pin a handler on
    // every connection that connects and goes silent.
    private static readonly TimeSpan HelloTimeout = TimeSpan.FromSeconds(15);

    private readonly StreamBeaconBridge _contact;
    private readonly BridgeRouteForwarder _routes;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;
    private readonly ILogger<ListenerSupervisor> _logger;

    public ListenerSupervisor(
        StreamBeaconBridge contact,
        BridgeRouteForwarder routes,
        IAuditStore audit,
        TimeProvider clock,
        ILogger<ListenerSupervisor> logger)
    {
        _contact = contact;
        _routes = routes;
        _audit = audit;
        _clock = clock;
        _logger = logger;
    }

    /// <summary>
    /// Binds the listener's bridge endpoint and starts its process. The
    /// bind and the first spawn are awaited -- a refused socket or a
    /// package whose command will not start refuses the listener create
    /// -- and the returned handle carries the supervision from there: the
    /// monitor restarts the process on exit for as long as the handle
    /// lives.
    /// </summary>
    public async Task<SupervisedListener> StartAsync(
        Listener listener,
        ListenerPackageInfo package,
        IReadOnlyDictionary<string, string> parameters,
        ListenerBridgeOptions options)
    {
        var endpoint = ListenerBridgeEndpoint.Bind(listener.Id, options, _logger);
        SupervisedListener? supervised = null;
        try
        {
            var stop = new CancellationTokenSource();
            var accept = Task.Run(
                () => endpoint.AcceptAsync((stream, token) => ServePeerAsync(stream, listener, token), stop.Token),
                stop.Token);

            // The spawn contract: a command with a separator runs inside the
            // package directory (./server, bin/server); a bare name is the
            // deployment's own interpreter (python3, node) resolved from
            // PATH. The child inherits the kernel's environment plus the
            // bridge contract: the socket to dial, the listener's id, and
            // the medium parameters the operator set at creation.
            var process = Spawn(listener, package, parameters, endpoint.LocalName);

            supervised = new SupervisedListener(
                MonitorAsync(listener, package, parameters, endpoint, accept, process, stop.Token),
                stop,
                endpoint);
            return supervised;
        }
        catch
        {
            if (supervised is not null)
                await supervised.DisposeAsync();
            else
                await endpoint.DisposeAsync();
            throw;
        }
    }

    // The supervision loop: hold the process, read its exit, mark the
    // listener's health, answer with the backoff schedule. Runs from the
    // first spawn until the stop token fires.
    private async Task MonitorAsync(
        Listener listener,
        ListenerPackageInfo package,
        IReadOnlyDictionary<string, string> parameters,
        ListenerBridgeEndpoint endpoint,
        Task accept,
        Process process,
        CancellationToken stop)
    {
        var backoff = 0;
        while (true)
        {
            var started = _clock.GetUtcNow();
            int exitCode;
            try
            {
                using (process)
                {
                    exitCode = await WaitForExitAsync(process, stop).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }

            // The health signal (ADR-025): the exit code is the fact, the
            // listener's state is the badge, and the audit trail carries
            // both -- a platform action, attributed to the null operator
            // like every other platform fact.
            listener.MarkUnhealthy();
            await AppendExitFactAsync(listener, package, exitCode);
            _logger.LogWarning(
                "Listener {Name}'s process exited with code {ExitCode}; restarting in {Delay}.",
                listener.Name, exitCode, RestartBackoff[backoff]);

            try
            {
                await Task.Delay(RestartBackoff[backoff], stop);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            // A stable run starts the schedule over; a crash loop rides the
            // cap. The respawn returns the badge -- the roster reads
            // running again the moment the process is back -- and a respawn
            // that fails (a package that lost its command, an interpreter
            // removed) is an exit the schedule answers, not a crash of the
            // supervisor: the listener stays unhealthy and the backoff
            // gives the operator time to fix it.
            if (_clock.GetUtcNow() - started >= StableRunReset)
                backoff = 0;
            else
                backoff = Math.Min(backoff + 1, RestartBackoff.Length - 1);

            while (true)
            {
                try
                {
                    process = Spawn(listener, package, parameters, endpoint.LocalName);
                    listener.MarkRunning();
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(
                        ex, "Listener {Name}'s process could not be respawned from package {Package}.",
                        listener.Name, package.Name);
                }

                backoff = Math.Min(backoff + 1, RestartBackoff.Length - 1);
                try
                {
                    await Task.Delay(RestartBackoff[backoff], stop);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    private static Process Spawn(
        Listener listener,
        ListenerPackageInfo package,
        IReadOnlyDictionary<string, string> parameters,
        string localName)
    {
        var command = package.ProcessCommand.Contains('/') || package.ProcessCommand.Contains(Path.DirectorySeparatorChar)
            ? Path.Combine(package.RootDirectory, package.ProcessCommand)
            : package.ProcessCommand;

        var start = new ProcessStartInfo
        {
            FileName = command,
            WorkingDirectory = package.RootDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in package.ProcessArgs)
            start.ArgumentList.Add(argument);
        start.Environment["ROD_BRIDGE_SOCKET"] = localName;
        start.Environment["ROD_LISTENER_ID"] = listener.Id.Value.ToString("N");
        start.Environment["ROD_LISTENER_PARAMS"] = System.Text.Json.JsonSerializer.Serialize(
            parameters, System.Text.Json.JsonSerializerOptions.Web);

        var process = Process.Start(start)
            ?? throw new InvalidOperationException($"Failed to start listener process '{command}'.");
        // Drain the pipes so a chatty child never blocks on a full buffer;
        // the lines land in the kernel log beside the listener's name.
        process.OutputDataReceived += (_, line) =>
        {
            if (!string.IsNullOrWhiteSpace(line.Data))
                Console.WriteLine($"[listener:{listener.Name}] {line.Data}");
        };
        process.ErrorDataReceived += (_, line) =>
        {
            if (!string.IsNullOrWhiteSpace(line.Data))
                Console.Error.WriteLine($"[listener:{listener.Name}] {line.Data}");
        };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return process;
    }

    // WaitForExitAsync cancels the wait but leaves the process running, so
    // a cancelled wait is the supervisor stopping -- the child dies with
    // the kernel, the whole tree, the same teardown the conformance
    // harness gives its candidates. The exit code is the health signal:
    // read after the wait, carried by the fact and the log.
    private static async Task<int> WaitForExitAsync(Process process, CancellationToken stop)
    {
        try
        {
            await process.WaitForExitAsync(stop).ConfigureAwait(false);
            return process.ExitCode;
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // Already gone: the exit raced the stop.
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // The tree's root died while the kill was in flight: the
                // children the tree-kill did not reach go with the parent's
                // exit on the platform's own process-group teardown.
            }
            throw;
        }
    }

    // One peer: read the carriage byte, hand the stream to the carriage.
    // Every outcome closes the connection; the peer's next appearance
    // reconnects.
    private async Task ServePeerAsync(Stream stream, Listener listener, CancellationToken stoppingToken)
    {
        try
        {
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            bounded.CancelAfter(HelloTimeout);
            var hello = new byte[1];
            var read = 0;
            while (read < 1)
            {
                var chunk = await stream.ReadAsync(hello.AsMemory(read, 1 - read), bounded.Token);
                if (chunk <= 0)
                    return;
                read += chunk;
            }

            switch (hello[0])
            {
                case BridgeCarriage.Contact:
                    await _contact.HandleContactAsync(
                        stream, listener, stoppingToken, carrier: "bridge");
                    break;
                case BridgeCarriage.RouteForward:
                    await _routes.ServeAsync(stream, listener, stoppingToken);
                    break;
                default:
                    // An unknown carriage is the dropped connection -- the
                    // bridge refuses to guess.
                    break;
            }
        }
        catch (Exception ex) when (
            ex is IOException or OperationCanceledException or ObjectDisposedException
            or System.Net.Sockets.SocketException)
        {
            // The peer went or the listener stopped: the connection ends.
        }
        finally
        {
            await stream.DisposeAsync();
        }
    }

    private async Task AppendExitFactAsync(Listener listener, ListenerPackageInfo package, int exitCode)
    {
        try
        {
            await _audit.AppendAsync(AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: listener.EngagementId?.Value ?? Guid.Empty,
                operatorId: Guid.Empty,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "listener.process-exited",
                kind: AuditEventKind.ListenerProcessExited,
                payload: $"listener={listener.Name} package={package.Name}@{package.Version} exitCode={exitCode}",
                output: null,
                outcome: listener.Id.Value.ToString("N"),
                at: _clock.GetUtcNow()));
        }
        catch (Exception ex)
        {
            // The audit store refusing must not take the supervisor's loop
            // with it; the log carries the loss.
            _logger.LogError(ex, "The exit fact for listener {Name} could not be appended.", listener.Name);
        }
    }
}
