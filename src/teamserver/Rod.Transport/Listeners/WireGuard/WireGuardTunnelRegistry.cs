using System.Collections.Concurrent;

namespace Rod.Transport.Listeners.WireGuard;

// The per-listener WireGuard tunnel state (architecture.md Sec 8, Sec 15.3
// ADR-004 as amended). One native router per bound wireguard listener, over
// the server's static X25519 key the deployment provisioned, and the peers
// that may open sessions on it -- the per-artifact public keys the build
// pipeline mints when a WireGuard-enabled profile builds against the
// listener. The registry serializes every native call per listener: the
// router is single-threaded state, and the listener's receive loop is the
// only writer the discipline needs.

/// <summary>
/// The wireguard listeners' tunnel state: router lifecycle, peer
/// registration, and the inject/send/tick calls the listener service and the
/// build pipeline share.
/// </summary>
public sealed class WireGuardTunnelRegistry : IAsyncDisposable
{
    private sealed record ListenerTunnels(WireGuardRouterHandle Router, object Gate)
    {
        ~ListenerTunnels() => Router.Dispose();
    }

    private readonly ConcurrentDictionary<ListenerId, ListenerTunnels> _listeners = new();

    /// <summary>
    /// Opens a listener's router over its server private key (32 bytes,
    /// base64 in the deployment's <c>WireGuard:ListenerKeys</c> section). An
    /// existing router under the id is replaced: the restore path re-opens
    /// what a restart closed, and the old router's sessions died with it.
    /// </summary>
    internal void OpenListener(ListenerId listener, ReadOnlySpan<byte> serverPrivate)
    {
        var router = WireGuardNative.RouterCreate(serverPrivate);
        _listeners[listener] = new ListenerTunnels(router, new object());
    }

    /// <summary>Closes a listener's router; its peers go with it.</summary>
    internal void CloseListener(ListenerId listener)
    {
        if (_listeners.TryRemove(listener, out var tunnels))
            tunnels.Router.Dispose();
    }

    /// <summary>
    /// Registers a peer's static public key (32 bytes) on a listener -- the
    /// per-artifact key half the build minted. Idempotent: a re-registration
    /// is a no-op, so a rebuild against the same listener never trips.
    /// </summary>
    internal void RegisterPeer(ListenerId listener, ReadOnlySpan<byte> peerPublic)
    {
        var tunnels = Tunnels(listener);
        lock (tunnels.Gate)
        {
            WireGuardNative.PeerAdd(tunnels.Router, peerPublic);
        }
    }

    /// <summary>
    /// Feeds one received datagram through the listener's router. A
    /// datagram that matches nothing answers empty -- the network's own
    /// shape for a stranger's packet.
    /// </summary>
    internal WireGuardInjected Inject(ListenerId listener, ReadOnlySpan<byte> datagram)
    {
        var tunnels = Tunnels(listener);
        lock (tunnels.Gate)
        {
            return WireGuardNative.Inject(tunnels.Router, datagram);
        }
    }

    /// <summary>
    /// Seals a response payload to a peer over the session its contact
    /// opened. No session (the peer never handshook) throws
    /// <see cref="WireGuardNative.WireGuardNoSessionException"/>: the
    /// discipline is the server-answers-only one.
    /// </summary>
    internal byte[] Send(ListenerId listener, ReadOnlySpan<byte> peerPublic, ReadOnlySpan<byte> payload)
    {
        var tunnels = Tunnels(listener);
        lock (tunnels.Gate)
        {
            return WireGuardNative.Send(tunnels.Router, peerPublic, payload);
        }
    }

    private ListenerTunnels Tunnels(ListenerId listener)
        => _listeners.TryGetValue(listener, out var tunnels)
            ? tunnels
            : throw new InvalidOperationException(
                $"Listener {listener} has no WireGuard router; its key is not provisioned.");

    public ValueTask DisposeAsync()
    {
        foreach (var listener in _listeners.Keys)
            CloseListener(listener);
        return ValueTask.CompletedTask;
    }
}
