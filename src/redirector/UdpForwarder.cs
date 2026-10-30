using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Rod.Redirector;

/// <summary>
/// The datagram carriage of the forwarding fleet (architecture.md Sec 8):
/// one UDP endpoint per rule, relaying datagrams between sources and the
/// upstream -- protocol-blind by the same discipline the TCP forwarder
/// keeps (it cannot parse DNS and must never learn to). UDP has no
/// connection, so sessions are synthesized per source address: each source
/// maps to its own upstream socket, which gives the upstream a stable
/// pseudo-connection (a DNS server's per-socket query pipeline), and the
/// mapping's idle sweep reclaims sockets whose quiet period says the
/// exchange is done.
/// </summary>
internal sealed class UdpForwarder : IRuleServer
{
    private readonly IPEndPoint _listen;
    private readonly string _upstreamHost;
    private readonly int _upstreamPort;
    private readonly CidrAllowList _allow;
    private readonly TextWriter _log;
    private readonly ConcurrentDictionary<IPEndPoint, SourceSession> _sessions = new();

    // How long a source's mapping lives after its last datagram. DNS
    // exchanges are seconds; minutes cover the slowest resolver retry
    // without pinning a socket per scanning source forever.
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(2);

    private UdpClient? _listener;

    public UdpForwarder(IPEndPoint listen, string upstreamHost, int upstreamPort, CidrAllowList allow, TextWriter log)
    {
        _listen = listen;
        _upstreamHost = upstreamHost;
        _upstreamPort = upstreamPort;
        _allow = allow;
        _log = log;
    }

    /// <summary>Binds the listening socket and returns the actual bound endpoint.</summary>
    public IPEndPoint Start()
    {
        _listener = new UdpClient(_listen);
        return (IPEndPoint)_listener.Client.LocalEndPoint!;
    }

    /// <summary>
    /// Relays until <paramref name="cancellationToken"/> cancels. The
    /// upstream resolution happens per session (a DNS name may re-resolve);
    /// a session whose upstream cannot resolve logs and drops that
    /// source's datagrams, not the whole rule.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (_listener is null)
            throw new InvalidOperationException("UdpForwarder has not been started.");

        var bound = (IPEndPoint)_listener.Client.LocalEndPoint!;
        await _log.WriteLineAsync(
            $"rod-redirector: relaying udp {Format(bound)} -> {_upstreamHost}:{_upstreamPort}");

        using var sweep = new CancellationTokenSource();
        var sweepTask = SweepAsync(sweep.Token);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                UdpReceiveResult received;
                try
                {
                    received = await _listener.ReceiveAsync(cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException)
                {
                    // The listener socket closed underneath; the rule's
                    // reconcile owns what happens next.
                    break;
                }

                // The only filtering a datagram relay can do, same as the
                // TCP spine's: drop sources outside the allow-list before
                // they synthesize a session.
                if (!AllowsSource(received.RemoteEndPoint))
                    continue;

                var session = _sessions.GetOrAdd(received.RemoteEndPoint, _ => new SourceSession());
                _ = session.RelayUpstreamAsync(_listener, received.Buffer, received.RemoteEndPoint,
                    _upstreamHost, _upstreamPort, cancellationToken);
            }
        }
        finally
        {
            sweep.Cancel();
            await sweepTask;
            foreach (var session in _sessions.Values)
                session.Dispose();
        }
    }

    // The only filtering a datagram relay can do, same as the TCP spine's:
    // drop sources outside the allow-list before they reach the upstream.
    private bool AllowsSource(IPEndPoint source)
        => _allow.Allows(source.Address);

    // Reclaims sources whose quiet period says the exchange is done. Cheap
    // and periodic: the map is bounded by the rule's active sources.
    private async Task SweepAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                var cutoff = DateTimeOffset.UtcNow - IdleTimeout;
                foreach (var (source, session) in _sessions)
                {
                    if (session.LastActivity < cutoff && _sessions.TryRemove(source, out var removed))
                        removed.Dispose();
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static string Format(IPEndPoint ep) => $"{ep.Address}:{ep.Port}";

    /// <summary>
    /// One source's synthesized session: its upstream socket, its last
    /// activity, and the receive loop that routes replies back. The loop's
    /// lifetime is the socket's; disposal tears both down together.
    /// </summary>
    private sealed class SourceSession : IDisposable
    {
        private readonly Lock _gate = new();
        private UdpClient? _upstream;
        private Task? _receiveLoop;
        private DateTimeOffset _lastActivity = DateTimeOffset.UtcNow;

        public DateTimeOffset LastActivity
        {
            get
            {
                lock (_gate)
                    return _lastActivity;
            }
        }

        public async Task RelayUpstreamAsync(
            UdpClient listener,
            byte[] datagram,
            IPEndPoint source,
            string upstreamHost,
            int upstreamPort,
            CancellationToken cancellationToken)
        {
            UdpClient upstream;
            Task? loopToAwait = null;
            lock (_gate)
            {
                _lastActivity = DateTimeOffset.UtcNow;
                if (_upstream is null)
                {
                    try
                    {
                        // Bound explicitly: an unbound UdpClient's receive
                        // throws rather than binding implicitly, and the
                        // send's own implicit bind would land on a port no
                        // receiver holds. The wildcard-any ephemeral port is
                        // the source's private channel to the upstream.
                        _upstream = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
                        _receiveLoop = ReceiveLoopAsync(_upstream, listener, source, cancellationToken);
                    }
                    catch (SocketException)
                    {
                        // No socket, no session; the source's next datagram
                        // retries.
                        _upstream?.Dispose();
                        _upstream = null;
                        return;
                    }
                }

                upstream = _upstream!;
                loopToAwait = _receiveLoop;
            }

            try
            {
                await upstream.SendAsync(datagram, datagram.Length, upstreamHost, upstreamPort);
            }
            catch (SocketException)
            {
                // An unresolvable or unreachable upstream drops this
                // datagram; the source retries by DNS's own discipline.
            }

            // Surface a faulted reply loop (its socket died) so it is not
            // left unobserved.
            if (loopToAwait is { IsFaulted: true })
                _ = loopToAwait.Exception;
        }

        private async Task ReceiveLoopAsync(
            UdpClient upstream,
            UdpClient listener,
            IPEndPoint source,
            CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var reply = await upstream.ReceiveAsync(cancellationToken);
                    lock (_gate)
                        _lastActivity = DateTimeOffset.UtcNow;
                    await listener.SendAsync(reply.Buffer, reply.Buffer.Length, source);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (SocketException)
            {
                // The upstream socket went away; the session's disposal or
                // the idle sweep collects it.
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                _upstream?.Dispose();
                _upstream = null;
            }
        }
    }
}
