using Rod.Transport.Listeners.WireGuard;
using Xunit;

namespace Rod.Integration.Tests;

// The managed face of the native WireGuard router, driven end to end
// against the real cdylib (src/native/wireguard, built with its
// test-client feature so the initiator side exists before the implant's
// own carriage does). The exchange these tests run is the one the
// transport serves: a handshake exchange opens the session, payloads cross
// as data packets, and the server answers within the contact.

public sealed class WireGuardNativeTests
{
    [Fact]
    public void HandshakeThenPayloadsCrossBothWays()
    {
        using var router = WireGuardNative.RouterCreate(WireGuardTestClient.SeededKey(9));
        using var client = WireGuardTestClient.Seeded(7, WireGuardTestClient.PublicOf(9));
        WireGuardNative.PeerAdd(router, client.PublicKey());

        // The handshake exchange precedes any payload.
        var initiation = client.Contact([]);
        var handshake = WireGuardNative.Inject(router, initiation);
        Assert.NotEmpty(handshake.Network);
        Assert.Empty(handshake.Tunnel);
        client.Receive(handshake.Network);

        // One contact in, one answer back -- and the carrier of the contact
        // is the peer a response seals to.
        var request = client.Contact("poll-body"u8.ToArray());
        var injected = WireGuardNative.Inject(router, request);
        Assert.Empty(injected.Network);
        Assert.Equal("poll-body"u8.ToArray(), injected.Tunnel);
        Assert.Equal(client.PublicKey(), injected.Peer);

        var answer = WireGuardNative.Send(router, injected.Peer!, "tasking-body"u8.ToArray());
        var received = client.Receive(answer);
        Assert.Equal("tasking-body"u8.ToArray(), received);
    }

    [Fact]
    public void AStrangersInitiationFindsNothing()
    {
        using var router = WireGuardNative.RouterCreate(WireGuardTestClient.SeededKey(9));
        using var stranger = WireGuardTestClient.Seeded(13, WireGuardTestClient.PublicOf(9));

        var initiation = stranger.Contact([]);
        var injected = WireGuardNative.Inject(router, initiation);
        Assert.Empty(injected.Network);
        Assert.Empty(injected.Tunnel);
        Assert.Null(injected.Peer);
    }

    [Fact]
    public void SendingBeforeAHandshakeRefuses()
    {
        using var router = WireGuardNative.RouterCreate(WireGuardTestClient.SeededKey(9));
        using var client = WireGuardTestClient.Seeded(7, WireGuardTestClient.PublicOf(9));
        WireGuardNative.PeerAdd(router, client.PublicKey());

        Assert.Throws<WireGuardNative.WireGuardNoSessionException>(
            () => WireGuardNative.Send(router, client.PublicKey(), "early"u8.ToArray()));
    }

    [Fact]
    public void APeerRemovedIsCutOff()
    {
        using var router = WireGuardNative.RouterCreate(WireGuardTestClient.SeededKey(9));
        using var client = WireGuardTestClient.Seeded(7, WireGuardTestClient.PublicOf(9));
        WireGuardNative.PeerAdd(router, client.PublicKey());

        client.Receive(WireGuardNative.Inject(router, client.Contact([])).Network);
        Assert.True(WireGuardNative.PeerRemove(router, client.PublicKey()));

        var again = client.Contact("again"u8.ToArray());
        var injected = WireGuardNative.Inject(router, again);
        Assert.Empty(injected.Network);
        Assert.Empty(injected.Tunnel);
    }
}
