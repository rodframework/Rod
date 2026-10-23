using System.Runtime.InteropServices;
using Rod.Transport.Listeners.WireGuard;
using Xunit;

namespace Rod.Integration.Tests;

// The managed face of the native WireGuard router, driven end to end
// against the real cdylib (src/native/wireguard, built with its
// test-client feature so the initiator side exists before the implant's
// own carriage does). The exchange these tests run is the one the
// transport will serve: a handshake exchange opens the session, payloads
// cross as data packets, and the server answers within the contact.

public sealed class WireGuardNativeTests
{
    static WireGuardNativeTests()
    {
        // The test assembly's own P/Invokes need the same library
        // resolution the transport assembly registered for itself.
        NativeLibrary.SetDllImportResolver(
            typeof(WireGuardNativeTests).Assembly,
            WireGuardNative.ResolveLibrary);
    }

    private static byte[] Key(byte seed)
    {
        var key = new byte[32];
        Array.Fill(key, seed);
        return key;
    }

    // The server's public key derives from its private half by the curve
    // itself -- the raw private bytes are never the public key, and a
    // client seeded with them fails the handshake's mac verification.
    private static byte[] ServerPublic()
        => WireGuardTestClient.PublicFromPrivate(Key(9));

    [Fact]
    public void HandshakeThenPayloadsCrossBothWays()
    {
        using var router = WireGuardNative.RouterCreate(Key(9));
        using var client = WireGuardTestClient.Create(Key(7), ServerPublic());
        WireGuardNative.PeerAdd(router, client.PublicKey());

        // The handshake exchange precedes any payload.
        var initiation = client.Contact([]);
        var handshake = WireGuardNative.Inject(router, initiation);
        Assert.NotEmpty(handshake.Network);
        Assert.Empty(handshake.Tunnel);
        client.Receive(handshake.Network);

        // One contact in, one answer back.
        var request = client.Contact("poll-body"u8.ToArray());
        var injected = WireGuardNative.Inject(router, request);
        Assert.Empty(injected.Network);
        Assert.Equal("poll-body"u8.ToArray(), injected.Tunnel);

        var answer = WireGuardNative.Send(router, client.PublicKey(), "tasking-body"u8.ToArray());
        var received = client.Receive(answer);
        Assert.Equal("tasking-body"u8.ToArray(), received);
    }

    [Fact]
    public void AStrangersInitiationFindsNothing()
    {
        using var router = WireGuardNative.RouterCreate(Key(9));
        using var stranger = WireGuardTestClient.Create(Key(13), ServerPublic());

        var initiation = stranger.Contact([]);
        var injected = WireGuardNative.Inject(router, initiation);
        Assert.Empty(injected.Network);
        Assert.Empty(injected.Tunnel);
    }

    [Fact]
    public void SendingBeforeAHandshakeRefuses()
    {
        using var router = WireGuardNative.RouterCreate(Key(9));
        using var client = WireGuardTestClient.Create(Key(7), ServerPublic());
        WireGuardNative.PeerAdd(router, client.PublicKey());

        Assert.Throws<WireGuardNative.WireGuardNoSessionException>(
            () => WireGuardNative.Send(router, client.PublicKey(), "early"u8.ToArray()));
    }

    [Fact]
    public void APeerRemovedIsCutOff()
    {
        using var router = WireGuardNative.RouterCreate(Key(9));
        using var client = WireGuardTestClient.Create(Key(7), ServerPublic());
        WireGuardNative.PeerAdd(router, client.PublicKey());

        client.Receive(WireGuardNative.Inject(router, client.Contact([])).Network);
        Assert.True(WireGuardNative.PeerRemove(router, client.PublicKey()));

        var again = client.Contact("again"u8.ToArray());
        var injected = WireGuardNative.Inject(router, again);
        Assert.Empty(injected.Network);
        Assert.Empty(injected.Tunnel);
    }

    /// <summary>
    /// The test-client exports of the cdylib: the implant's stand-in,
    /// driving the same poll discipline the real carriage will run.
    /// </summary>
    private sealed class WireGuardTestClient : IDisposable
    {
        private const string Library = "rod_wg";

        private WireGuardTestClient(IntPtr handle, byte[] privateKey)
        {
            _handle = handle;
            _privateKey = privateKey;
        }

        private readonly IntPtr _handle;
        private readonly byte[] _privateKey;
        private bool _disposed;

        public static byte[] PublicFromPrivate(byte[] privateKey)
        {
            var key = new byte[32];
            if (TestPublic(privateKey, key) != 0)
                throw new InvalidOperationException("The native test client refused the private key.");
            return key;
        }

        public static WireGuardTestClient Create(byte[] privateKey, byte[] serverPublic)
        {
            var handle = TestNew(privateKey, serverPublic);
            return handle == IntPtr.Zero
                ? throw new InvalidOperationException("The native test client refused the keys.")
                : new WireGuardTestClient(handle, privateKey);
        }

        public byte[] PublicKey()
        {
            var key = new byte[32];
            if (TestPublic(_privateKey, key) != 0)
                throw new InvalidOperationException("The native test client refused the private key.");
            return key;
        }

        public byte[] Contact(byte[] payload)
        {
            var datagram = new byte[65535];
            var status = TestContact(_handle, payload, (nuint)payload.Length,
                datagram, (nuint)datagram.Length, out var length);
            if (status != 0)
                throw new InvalidOperationException($"The native test client contact failed ({status}).");
            return datagram[..(int)length];
        }

        public byte[] Receive(byte[] datagram)
        {
            var payload = new byte[65535];
            var status = TestReceive(_handle, datagram, (nuint)datagram.Length,
                payload, (nuint)payload.Length, out var length);
            if (status != 0)
                throw new InvalidOperationException($"The native test client receive failed ({status}).");
            return payload[..(int)length];
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                TestFree(_handle);
                _disposed = true;
            }
        }

        [DllImport(Library, EntryPoint = "rod_wg_test_new")]
        private static extern IntPtr TestNew(byte[] privateKey, byte[] serverPublic);

        [DllImport(Library, EntryPoint = "rod_wg_test_public")]
        private static extern int TestPublic(byte[] privateKey, byte[] publicKeyOut);

        [DllImport(Library, EntryPoint = "rod_wg_test_contact")]
        private static extern int TestContact(
            IntPtr client, byte[] payload, nuint payloadLength,
            byte[] output, nuint outputCapacity, out nuint outputLength);

        [DllImport(Library, EntryPoint = "rod_wg_test_receive")]
        private static extern int TestReceive(
            IntPtr client, byte[] datagram, nuint datagramLength,
            byte[] output, nuint outputCapacity, out nuint outputLength);

        [DllImport(Library, EntryPoint = "rod_wg_test_free")]
        private static extern void TestFree(IntPtr client);
    }
}
