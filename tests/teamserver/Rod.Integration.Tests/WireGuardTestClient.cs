using System.Runtime.InteropServices;

namespace Rod.Integration.Tests;

// The test-client exports of the rod_wg cdylib (src/native/wireguard,
// built with its test-client feature): the implant's stand-in before the
// implant's own carriage exists, driving the same poll discipline the
// real carriage will run -- a handshake exchange first, payloads over the
// session after.

/// <summary>
/// A native WireGuard initiator for tests. The library resolution is the
/// transport assembly's (ROD_WG_LIB, the application directory, then the
/// repository's own build output).
/// </summary>
internal sealed class WireGuardTestClient : IDisposable
{
    private const string Library = "rod_wg";

    static WireGuardTestClient()
    {
        NativeLibrary.SetDllImportResolver(
            typeof(WireGuardTestClient).Assembly,
            Rod.Transport.Listeners.WireGuard.WireGuardNative.ResolveLibrary);
    }

    private WireGuardTestClient(IntPtr handle, byte[] privateKey)
    {
        _handle = handle;
        _privateKey = privateKey;
    }

    private readonly IntPtr _handle;
    private readonly byte[] _privateKey;
    private bool _disposed;

    /// <summary>
    /// A key pair from a seed byte: the private half is the seeded 32
    /// bytes, the public half derives by the curve.
    /// </summary>
    public static WireGuardTestClient Seeded(byte seed, byte[] serverPublic)
    {
        var key = SeededKey(seed);
        var handle = TestNew(key, serverPublic);
        return handle == IntPtr.Zero
            ? throw new InvalidOperationException("The native test client refused the keys.")
            : new WireGuardTestClient(handle, key);
    }

    /// <summary>The public key of the seeded private half.</summary>
    public static byte[] PublicOf(byte seed)
        => PublicFromPrivate(SeededKey(seed));

    public static byte[] SeededKey(byte seed)
    {
        var key = new byte[32];
        Array.Fill(key, seed);
        return key;
    }

    public static byte[] PublicFromPrivate(byte[] privateKey)
    {
        var key = new byte[32];
        if (TestPublic(privateKey, key) != 0)
            throw new InvalidOperationException("The native test client refused the private key.");
        return key;
    }

    public byte[] PublicKey() => PublicFromPrivate(_privateKey);

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
