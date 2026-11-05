using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Rod.Audit;
using Rod.CoreState.Listeners;
using Rod.CoreState.Pki;
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
/// One supervised listener: the monitor task, the stop that ends it, the
/// socket it served, and the leaf it may have handed the process. Dispose
/// stops the process (the whole tree), waits the monitor out, closes the
/// endpoint, and clears the leaf.
/// </summary>
internal sealed class SupervisedListener : IAsyncDisposable
{
    private readonly CancellationTokenSource _stop;
    private readonly ListenerBridgeEndpoint _endpoint;
    private readonly string? _tlsPem;

    public SupervisedListener(
        Task monitor,
        CancellationTokenSource stop,
        ListenerBridgeEndpoint endpoint,
        string? tlsPem = null)
    {
        Monitor = monitor;
        _stop = stop;
        _endpoint = endpoint;
        _tlsPem = tlsPem;
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
        if (_tlsPem is not null)
        {
            try
            {
                File.Delete(_tlsPem);
            }
            catch (IOException)
            {
                // Already gone or unwritable: nothing to clear.
            }
        }
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
    private readonly IImplantCertificateAuthority _authority;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;
    private readonly ILogger<ListenerSupervisor> _logger;

    public ListenerSupervisor(
        StreamBeaconBridge contact,
        BridgeRouteForwarder routes,
        IImplantCertificateAuthority authority,
        IAuditStore audit,
        TimeProvider clock,
        ILogger<ListenerSupervisor> logger)
    {
        _contact = contact;
        _routes = routes;
        _authority = authority;
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
        CancellationTokenSource? stop = null;
        SupervisedListener? supervised = null;
        try
        {
            stop = new CancellationTokenSource();
            _ = Task.Run(
                () => endpoint.AcceptAsync((stream, token) => ServePeerAsync(stream, listener, token), stop.Token),
                stop.Token);

            // The medium's TLS posture decides whether the process fronts
            // TLS with a CA-issued leaf: written beside the bridge socket
            // (the kernel's user alone can read it) and named in the spawn
            // environment, so the leaf never rides the medium parameters
            // where an operator echo could log it.
            var tlsPem = ExportTlsPem(listener, package, options);

            // The spawn contract: a command with a separator runs inside the
            // package directory (./server, bin/server); a bare name is the
            // deployment's own interpreter (python3, node) resolved from
            // PATH. The child inherits the kernel's environment plus the
            // bridge contract: the socket to dial, the listener's id, the
            // medium parameters the operator set at creation, and -- when
            // the posture says so -- the leaf the front presents.
            var process = Spawn(listener, package, parameters, endpoint.LocalName, tlsPem);

            supervised = new SupervisedListener(
                MonitorAsync(listener, package, parameters, endpoint, process, stop.Token, tlsPem, options),
                stop,
                endpoint,
                tlsPem);
            return supervised;
        }
        catch
        {
            if (supervised is not null)
                await supervised.DisposeAsync();
            else
            {
                stop?.Cancel();
                stop?.Dispose();
                await endpoint.DisposeAsync();
            }
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
        Process process,
        CancellationToken stop,
        string? tlsPem,
        ListenerBridgeOptions options)
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
                    // A respawn re-exports the leaf: the rotation window may
                    // have passed while the process was down, and the file
                    // may have been swept -- the authority's cache keeps the
                    // common case a rewrite of the same bytes.
                    if (tlsPem is not null)
                        ExportTlsPem(listener, package, options, tlsPem);
                    process = Spawn(listener, package, parameters, endpoint.LocalName, tlsPem);
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
        string localName,
        string? tlsPem)
    {
        // The spawn contract's platform placeholders: a package that ships
        // one binary per (os, arch) cell -- the cross-compiled shapes -- names
        // them bin/{os}-{arch}/server and the supervisor resolves the cell it
        // runs on. The vocabulary is the cross-compile ecosystem's own
        // (linux/windows/darwin, amd64/arm64/386/arm); a command without a
        // placeholder is untouched.
        var commandRaw = ExpandSpawnPlaceholders(package.ProcessCommand);
        var command = commandRaw.Contains('/') || commandRaw.Contains(Path.DirectorySeparatorChar)
            ? Path.Combine(package.RootDirectory, commandRaw)
            : commandRaw;

        var start = new ProcessStartInfo
        {
            FileName = command,
            WorkingDirectory = package.RootDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in package.ProcessArgs)
            start.ArgumentList.Add(ExpandSpawnPlaceholders(argument));
        start.Environment["ROD_BRIDGE_SOCKET"] = localName;
        start.Environment["ROD_LISTENER_ID"] = listener.Id.Value.ToString("N");
        start.Environment["ROD_LISTENER_PARAMS"] = System.Text.Json.JsonSerializer.Serialize(
            parameters, System.Text.Json.JsonSerializerOptions.Web);
        if (tlsPem is not null)
            start.Environment["ROD_LISTENER_TLS_PEM"] = tlsPem;

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

    // The {os}/{arch} vocabulary the spawn contract expands: the Go-style
    // cross-compile spellings, because that ecosystem is where one package
    // per cell is routine. Documented in extending/listeners.md; a package
    // that never uses a placeholder never sees a value.
    private static string RuntimeOsToken
        => RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "windows"
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "darwin"
            : "linux";

    private static string RuntimeArchToken
        => RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "amd64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "386",
            Architecture.Arm => "arm",
            _ => RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(),
        };

    private static string ExpandSpawnPlaceholders(string value)
        => value
            .Replace("{os}", RuntimeOsToken, StringComparison.Ordinal)
            .Replace("{arch}", RuntimeArchToken, StringComparison.Ordinal);

    // One base64 PEM block, the 64-column wrap every reader expects.
    private static string PemOf(string label, byte[] der)
    {
        var base64 = Convert.ToBase64String(der);
        var lines = new List<string> { "-----BEGIN " + label + "-----" };
        for (var offset = 0; offset < base64.Length; offset += 64)
            lines.Add(base64[offset..Math.Min(offset + 64, base64.Length)]);
        lines.Add("-----END " + label + "-----");
        return string.Join("\n", lines);
    }

    // The TLS leaf a TLS-postured front presents: the same CA-issued,
    // SAN-named leaf the in-tree https termination loads in-process, handed
    // to the package as a PEM file the kernel's user alone reads. A zone
    // public endpoint names its host exactly (ServerLeaf.HostOf parses the
    // bare shape), so the DoH front's leaf carries the zone itself.
    private string? ExportTlsPem(
        Listener listener,
        ListenerPackageInfo package,
        ListenerBridgeOptions options,
        string? reusePath = null)
    {
        var postured = package.Tls switch
        {
            ListenerTlsPostures.Always => true,
            ListenerTlsPostures.Never => false,
            _ => listener.PublicEndpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase),
        };
        if (!postured)
            return null;

        var leaf = _authority.GetServerCertificate(ServerLeaf.HostOf(listener.PublicEndpoint));
        using var key = leaf.GetRSAPrivateKey()
            ?? throw new InvalidOperationException(
                $"The engagement CA's server leaf for listener '{listener.Name}' carries no RSA key to export.");
        var directory = Path.GetFullPath(options.SocketDirectory, AppContext.BaseDirectory);
        Directory.CreateDirectory(directory);
        var path = reusePath ?? Path.Combine(directory, $"{listener.Id.Value:N}-tls.pem");
        File.WriteAllText(path, PemOf("CERTIFICATE", leaf.RawData) + "\n" + key.ExportPkcs8PrivateKeyPem() + "\n");
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            try
            {
                File.SetUnixFileMode(path,
                    System.IO.UnixFileMode.UserRead | System.IO.UnixFileMode.UserWrite);
            }
            catch (IOException)
            {
                // Best effort beside the directory's own permissions, the
                // same posture the socket file keeps.
            }
        }
        return path;
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
