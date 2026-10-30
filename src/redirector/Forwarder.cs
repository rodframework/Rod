using System.Net;
using System.Net.Sockets;

namespace Rod.Redirector;

/// <summary>
/// The L4 TCP forwarder (architecture.md Sec 8, ADR 0011). Listens on one
/// endpoint; for each accepted connection, optionally checks the source IP
/// against an allow-list, connects the configured upstream, and splices the two
/// byte streams in both directions until the connection drains. The payload is
/// opaque -- never inspected, never altered -- so the mTLS beacon channel
/// (HTTP/2 + client cert) and the HTTPS enroll request pass through end to end,
/// and the redirector cannot read or alter sealed tasking (architecture.md
/// Sec 9, "Sealing" future).
///
/// Near-stateless: each connection is independent and shares no state with any
/// other. The only shared mutable state is the listening socket and the
/// cancellation that stops it.
/// </summary>
internal sealed class Forwarder : IRuleServer
{
    private readonly IPEndPoint _listen;
    private readonly string _upstreamHost;
    private readonly int _upstreamPort;
    private readonly CidrAllowList _allow;
    private readonly TextWriter _log;
    private TcpListener? _listener;

    public Forwarder(IPEndPoint listen, string upstreamHost, int upstreamPort, CidrAllowList allow, TextWriter log)
    {
        _listen = listen;
        _upstreamHost = upstreamHost;
        _upstreamPort = upstreamPort;
        _allow = allow;
        _log = log;
    }

    /// <summary>
    /// Binds the listening socket and returns the actual bound endpoint, which
    /// differs from the configured one when port 0 requested an ephemeral port.
    /// Separating bind from the accept loop lets a caller (and a test) connect as
    /// soon as the socket is open, without racing the accept loop's startup.
    /// </summary>
    public IPEndPoint Start()
    {
        _listener = new TcpListener(_listen);
        _listener.Start();
        return (IPEndPoint)_listener.LocalEndpoint;
    }

    /// <summary>
    /// Accepts and forwards connections until <paramref name="cancellationToken"/>
    /// cancels. Each connection is handled independently on the thread pool; this
    /// method returns only on cancellation (clean shutdown via Ctrl-C/SIGTERM).
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (_listener is null)
            throw new InvalidOperationException("Forwarder has not been started.");

        var bound = (IPEndPoint)_listener.LocalEndpoint;
        await _log.WriteLineAsync(
            $"rod-redirector: forwarding {Format(bound)} -> {_upstreamHost}:{_upstreamPort}")
            .ConfigureAwait(false);

        try
        {
            while (true)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                // Each connection is independent and near-stateless; handle it on
                // the thread pool. Its lifetime is governed by the connection
                // itself and by the cancellation that stops the forwarder. The
                // wrapper swallows connection-level errors so a faulted connection
                // never escapes as an unobserved task exception.
                _ = HandleAsync(client, cancellationToken);
            }
        }
        finally
        {
            _listener.Stop();
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken cancellationToken)
    {
        try
        {
            await HandleCoreAsync(client, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await _log.WriteLineAsync($"rod-redirector: connection error: {ex.Message}").ConfigureAwait(false);
        }
    }

    private async Task HandleCoreAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using var downstream = client;

        // The only filtering an opaque L4 forwarder can do: drop connections from
        // sources outside the allow-list before they reach the upstream. The
        // malleable User-Agent/URI routing of architecture.md Sec 7 is a
        // TLS-terminating-edge concern, not something this forwarder can see.
        if (downstream.Client.RemoteEndPoint is IPEndPoint source && !_allow.Allows(source.Address))
        {
            await _log.WriteLineAsync($"rod-redirector: denied {source.Address} (not in allow-list)").ConfigureAwait(false);
            Shutdown(downstream.Client);
            return;
        }

        TcpClient upstream;
        try
        {
            upstream = new TcpClient();
            await upstream.ConnectAsync(_upstreamHost, _upstreamPort, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            await _log.WriteLineAsync($"rod-redirector: upstream connect failed: {ex.Message}").ConfigureAwait(false);
            Shutdown(downstream.Client);
            return;
        }

        using var up = upstream;
        await using var downstreamStream = downstream.GetStream();
        await using var upstreamStream = up.GetStream();

        // Splice both directions. Each copy, on EOF, half-closes the peer's send
        // side so the reverse copy drains and then observes EOF; the connection
        // fully closes only when both directions are done. This carries
        // request/response (HTTP enroll) and bidirectional (mTLS beacon) traffic
        // correctly without terminating transport.
        var clientToUpstream = RelayAsync(downstreamStream, upstreamStream, up.Client, cancellationToken);
        var upstreamToClient = RelayAsync(upstreamStream, downstreamStream, downstream.Client, cancellationToken);
        await Task.WhenAll(clientToUpstream, upstreamToClient).ConfigureAwait(false);
    }

    private static async Task RelayAsync(
        NetworkStream source,
        NetworkStream destination,
        Socket destinationSocket,
        CancellationToken cancellationToken)
    {
        try
        {
            await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (IOException)
        {
            // The peer closed or reset; the half-close below is still the right
            // signal for the reverse direction.
        }
        catch (SocketException)
        {
            // Same as above -- connection tear-down during the copy.
        }

        // EOF (or error): tell the peer no more data will be sent on this
        // direction so its reverse copy can drain. Errors mean the socket is
        // already gone, which Shutdown swallows.
        Shutdown(destinationSocket);
    }

    private static void Shutdown(Socket socket)
    {
        try
        {
            socket.Shutdown(SocketShutdown.Send);
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static string Format(IPEndPoint ep) => $"{ep.Address}:{ep.Port}";
}
