using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Rod.Transport.Listeners.Streams;

namespace Rod.Transport.Listeners.Bridge;

// The bridge endpoint's own socket half (ADR-025): one local socket per
// listener -- a Unix-domain socket on Linux and macOS, a named pipe on
// Windows -- permission-restricted to the kernel's user. No port, no
// network stack: the only peer that can reach it is a process the kernel
// itself spawned with the socket's name in its environment.
//
// One connection is one medium peer. The peer's first byte selects the
// carriage (BridgeCarriage): the rod.v1 contact stream -- the same
// delimited-message exchange the raw-TCP family runs, served by the same
// StreamBeaconBridge, so enrollment-as-frame, the sealed bodies, and the
// live sessions all cross unchanged -- or the route-forward carriage, the
// https shape's request/answer units dispatched by path. The endpoint
// knows nothing about either beyond the dispatch: it accepts, reads one
// byte, and hands the stream to the carriage that byte named.

/// <summary>
/// One listener's bound bridge socket and its accept loop. Bind is a
/// factory: the endpoint holds the socket open until disposed.
/// </summary>
internal sealed class ListenerBridgeEndpoint : IAsyncDisposable
{
    // The byte budget a Unix socket path has on the strictest platform
    // (Linux's sun_path): keep clear of it with a short fallback rather
    // than dying on a deep deployment directory.
    private const int MaxSocketPathBytes = 100;

    private readonly ILogger _logger;
    private readonly string? _socketPath;
    private Socket? _socket;

    private ListenerBridgeEndpoint(ILogger logger, string? socketPath, Socket socket)
    {
        _logger = logger;
        _socketPath = socketPath;
        _socket = socket;
    }

    /// <summary>
    /// What the environment variable <c>ROD_BRIDGE_SOCKET</c> carries for
    /// the listener process: the socket's filesystem path on Unix, the
    /// pipe's full name on Windows.
    /// </summary>
    public string LocalName { get; private set; } = "";

    /// <summary>
    /// Binds the listener's bridge socket. Throws <see cref="IOException"/>
    /// when the bind is refused -- a stale socket that cannot be cleared,
    /// or a filesystem that will not take one; the caller refuses the
    /// listener create rather than spawning a process with nothing to
    /// dial.
    /// </summary>
    public static ListenerBridgeEndpoint Bind(ListenerId id, ListenerBridgeOptions options, ILogger logger)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var pipeName = $"rod-bridge-{id.Value:N}";
            // The Windows half binds nothing up front: a named pipe server
            // creates instances on demand, so "binding" is naming. The
            // accept loop below creates and waits on instance after
            // instance; the pipe carries ACLs for the current user only
            // (PipeOptions.CurrentUserOnly), the named-pipe posture of the
            // Unix directory's user-only permissions.
            return new ListenerBridgeEndpoint(logger, socketPath: null, socket: null!)
            {
                LocalName = @"\\.\pipe\" + pipeName,
            };
        }

        var directory = Path.GetFullPath(options.SocketDirectory, AppContext.BaseDirectory);
        Directory.CreateDirectory(directory);
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            try
            {
                File.SetUnixFileMode(directory,
                    System.IO.UnixFileMode.UserRead | System.IO.UnixFileMode.UserWrite | System.IO.UnixFileMode.UserExecute);
            }
            catch (IOException)
            {
                // A filesystem that will not take the mode (a bind mount, a
                // foreign-format share): the socket still lives; the mode is
                // the defense-in-depth layer, not the only one.
            }
        }

        var path = Path.Combine(directory, $"{id.Value:N}.sock");
        if (System.Text.Encoding.UTF8.GetByteCount(path) > MaxSocketPathBytes)
            path = Path.Combine(Path.GetTempPath(), $"rod-bridge-{id.Value:N}.sock");

        // A stale socket file from an unclean shutdown would refuse the
        // bind; the kernel owns the name, so clearing it is ours.
        if (File.Exists(path))
            File.Delete(path);

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            socket.Bind(new UnixDomainSocketEndPoint(path));
            socket.Listen(64);
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                try
                {
                    File.SetUnixFileMode(path,
                        System.IO.UnixFileMode.UserRead | System.IO.UnixFileMode.UserWrite);
                }
                catch (IOException)
                {
                    // Same posture as the directory: best effort beside the
                    // socket's own reachability.
                }
            }
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        logger.LogInformation("Listener bridge {ListenerId} bound at {Path}.", id, path);
        return new ListenerBridgeEndpoint(logger, path, socket)
        {
            LocalName = path,
        };
    }

    /// <summary>
    /// Accepts peers and dispatches each to <paramref name="serve"/> -- one
    /// task per connection, the peer's carriage owning everything after the
    /// hello byte. Runs until the token cancels; the endpoint is disposed
    /// by the supervisor after.
    /// </summary>
    public async Task AcceptAsync(
        Func<Stream, CancellationToken, Task> serve,
        CancellationToken stoppingToken)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var name = LocalName[@"\\.\pipe\".Length..];
            while (!stoppingToken.IsCancellationRequested)
            {
                var pipe = new NamedPipeServerStream(
                    name,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                try
                {
                    await pipe.WaitForConnectionAsync(stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    pipe.Dispose();
                    return;
                }
                catch (IOException)
                {
                    // The instance died before anyone connected (a host
                    // tearing pipes down): retry with a fresh instance.
                    pipe.Dispose();
                    continue;
                }

                _ = ServePipeAsync(pipe, serve, stoppingToken);
            }
            return;
        }

        var bound = _socket!;
        while (!stoppingToken.IsCancellationRequested)
        {
            Socket peer;
            try
            {
                peer = await bound.AcceptAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (SocketException ex)
            {
                // The listening socket died under us ( disposal raced the
                // loop): the supervisor's cancellation closes the loop too.
                _logger.LogInformation(ex, "Bridge accept loop ended for {Path}.", _socketPath);
                return;
            }

            var stream = new NetworkStream(peer, ownsSocket: true);
            _ = Task.Run(() => serve(stream, stoppingToken), stoppingToken);
        }
    }

    // One named-pipe peer: serve it, then dispose the instance -- the next
    // WaitForConnection runs on a fresh one the accept loop already made.
    private async Task ServePipeAsync(
        NamedPipeServerStream pipe,
        Func<Stream, CancellationToken, Task> serve,
        CancellationToken stoppingToken)
    {
        try
        {
            await serve(pipe, stoppingToken);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
        {
            // The peer went: the connection ends.
        }
        finally
        {
            await pipe.DisposeAsync();
        }
    }

    public ValueTask DisposeAsync()
    {
        _socket?.Dispose();
        if (_socketPath is not null)
        {
            try
            {
                File.Delete(_socketPath);
            }
            catch (IOException)
            {
                // Already gone or unwritable: nothing to clear.
            }
        }
        return ValueTask.CompletedTask;
    }
}
