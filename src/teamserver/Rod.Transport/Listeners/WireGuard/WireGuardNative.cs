using System.Reflection;
using System.Runtime.InteropServices;

namespace Rod.Transport.Listeners.WireGuard;

// The native seam of the optional WireGuard transport (architecture.md
// Sec 8, Sec 15.3 ADR-004 as amended): the router the cdylib under
// src/native/wireguard holds, reached through its small C ABI. The
// managed side owns the UDP socket and the frame paths; the native side
// owns the tunnel state, so no WireGuard cryptography exists in C# --
// the audited implementation (boringtun) stays the only crypto in the
// process. The library is absent by default: the transport is
// default-disabled, and a deployment that enables it ships the library
// beside the server binary (or names it with ROD_WG_LIB).

/// <summary>
/// The router handle: one listener's tunnel state over the server's
/// static X25519 key. Owned by the native allocator; released through
/// the ABI's free call.
/// </summary>
internal sealed class WireGuardRouterHandle : SafeHandle
{
    public WireGuardRouterHandle()
        : base(invalidHandleValue: IntPtr.Zero, ownsHandle: true)
    {
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        WireGuardNative.RouterFree(handle);
        return true;
    }
}

/// <summary>
/// One native router call's outcome: the network bytes to send back on
/// the socket and the inner payload a data packet carried, either
/// possibly empty.
/// </summary>
internal readonly record struct WireGuardInjected(byte[] Network, byte[] Tunnel, byte[]? Peer);

/// <summary>
/// The P/Invoke face of <c>rod_wg</c>. Calls are not thread-safe on one
/// handle: the listener's receive loop serializes them, which is the
/// only concurrency a UDP contact path needs.
/// </summary>
internal static class WireGuardNative
{
    /// <summary>The shared library name the DllImports resolve.</summary>
    private const string Library = "rod_wg";

    private const int MaxPacket = 65535;

    static WireGuardNative()
    {
        NativeLibrary.SetDllImportResolver(
            typeof(WireGuardNative).Assembly, ResolveLibrary);
    }

    // Resolution order: the environment override (a deployment that
    // keeps the library elsewhere), the application directory (the
    // publish shape), then the repository's own build output -- the
    // shape tests and local runs use, walking up from the app directory
    // to the repository root.
    internal static IntPtr ResolveLibrary(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != Library)
            return IntPtr.Zero;

        if (Environment.GetEnvironmentVariable("ROD_WG_LIB") is { Length: > 0 } named)
        {
            if (NativeLibrary.TryLoad(named, out var loaded))
                return loaded;
        }

        var candidates = new List<string>();
        foreach (var name in LibraryNames())
            candidates.Add(Path.Combine(AppContext.BaseDirectory, name));

        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (!dir.GetDirectories("src").Any(d => d.GetDirectories("native").Any()))
                continue;
            foreach (var name in LibraryNames())
                candidates.Add(Path.Combine(
                    dir.FullName, "src", "native", "wireguard", "target", "release", name));
            break;
        }

        return candidates.FirstOrDefault(File.Exists) is { Length: > 0 } existing
            ? NativeLibrary.Load(existing)
            : IntPtr.Zero;
    }

    private static string[] LibraryNames()
        => OperatingSystem.IsWindows()
            ? ["rod_wg.dll"]
            : OperatingSystem.IsMacOS()
                ? ["librod_wg.dylib"]
                : ["librod_wg.so"];

    /// <summary>
    /// Builds a router over the server's 32-byte static private key.
    /// </summary>
    public static WireGuardRouterHandle RouterCreate(ReadOnlySpan<byte> serverPrivate)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(serverPrivate.Length, 32);
        var handle = RouterNew(serverPrivate.ToArray(), 32);
        return handle.IsInvalid
            ? throw new InvalidOperationException(
                "The native WireGuard router refused the key; the library is stale or the key malformed.")
            : handle;
    }

    /// <summary>
    /// Derives the 32-byte static public key of an X25519 private key --
    /// the one curve operation the build path needs (minting an
    /// artifact's pair, reading a provisioned server key's public half),
    /// kept on the native side so no WireGuard cryptography exists in C#.
    /// </summary>
    public static byte[] PublicKey(ReadOnlySpan<byte> privateKey)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(privateKey.Length, 32);
        var key = new byte[32];
        var status = Public(privateKey.ToArray(), key);
        return status == WireGuardStatus.Ok
            ? key
            : throw new InvalidOperationException(
                $"The native WireGuard library refused the private key (status {status}).");
    }

    [DllImport(Library, EntryPoint = "rod_wg_public")]
    private static extern int Public(byte[] privateKey, byte[] publicKeyOut);

    /// <summary>Registers a peer by its 32-byte static public key.</summary>
    public static void PeerAdd(WireGuardRouterHandle router, ReadOnlySpan<byte> peerPublic)
    {
        var status = PeerAdd(router, peerPublic.ToArray(), 32);
        WireGuardStatus.ThrowIfError(status, "add the WireGuard peer");
    }

    /// <summary>Removes a peer; a missing peer reports false, no error.</summary>
    public static bool PeerRemove(WireGuardRouterHandle router, ReadOnlySpan<byte> peerPublic)
        => PeerRemove(router, peerPublic.ToArray(), 32) == 0;

    /// <summary>
    /// Feeds one received datagram through the router. A datagram that
    /// matches nothing returns empty outputs, not an error -- the
    /// network's own shape for a stranger's packet.
    /// </summary>
    public static WireGuardInjected Inject(WireGuardRouterHandle router, ReadOnlySpan<byte> datagram)
    {
        var network = new byte[MaxPacket];
        var tunnel = new byte[MaxPacket];
        var peer = new byte[32];
        var status = RouterInject(
            router,
            datagram.ToArray(), (nuint)datagram.Length,
            network, (nuint)network.Length, out var networkLength,
            tunnel, (nuint)tunnel.Length, out var tunnelLength,
            peer);
        WireGuardStatus.ThrowIfError(status, "inject the datagram");
        var carried = tunnel[..(int)tunnelLength];
        return new WireGuardInjected(
            network[..(int)networkLength],
            carried,
            // All zeroes means no peer: a handshake answer or a stranger's
            // drop, neither of which has an addressee to answer.
            carried.Length > 0 && peer.Any(b => b != 0) ? peer : null);
    }

    /// <summary>
    /// Seals one inner payload to a peer. Throws
    /// <see cref="WireGuardNoSessionException"/> when the peer has not
    /// completed a handshake: the server only answers, so there is no
    /// session to answer on until the peer's own contact opened one.
    /// </summary>
    public static byte[] Send(WireGuardRouterHandle router, ReadOnlySpan<byte> peerPublic, ReadOnlySpan<byte> payload)
    {
        var datagram = new byte[MaxPacket];
        var status = RouterSend(
            router, peerPublic.ToArray(), payload.ToArray(), (nuint)payload.Length,
            datagram, (nuint)datagram.Length, out var length);
        if (status == WireGuardStatus.NoSession)
            throw new WireGuardNoSessionException();
        WireGuardStatus.ThrowIfError(status, "seal the response");
        return datagram[..(int)length];
    }

    /// <summary>
    /// Drives a peer's timers; a tick with nothing to send returns an
    /// empty array. An unknown peer reports the same emptiness.
    /// </summary>
    public static byte[] Tick(WireGuardRouterHandle router, ReadOnlySpan<byte> peerPublic)
    {
        var datagram = new byte[MaxPacket];
        var status = RouterTick(router, peerPublic.ToArray(), datagram, (nuint)datagram.Length, out var length);
        if (status == WireGuardStatus.UnknownPeer)
            return [];
        WireGuardStatus.ThrowIfError(status, "tick the peer");
        return datagram[..(int)length];
    }

    private static class WireGuardStatus
    {
        public const int Ok = 0;
        public const int UnknownPeer = -1;
        public const int NoSession = -3;

        public static void ThrowIfError(int status, string action)
        {
            if (status == Ok)
                return;
            throw status switch
            {
                UnknownPeer => new InvalidOperationException(
                    $"The native WireGuard router does not know the peer ({action})."),
                NoSession => new WireGuardNoSessionException(),
                -4 => new InvalidOperationException(
                    $"The native WireGuard router's output buffer was too small ({action}); the caller sizes it for a datagram."),
                _ => new InvalidOperationException(
                    $"The native WireGuard router failed to {action} (status {status})."),
            };
        }
    }

    /// <summary>The send the poll discipline never makes: no session stands.</summary>
    internal sealed class WireGuardNoSessionException : Exception
    {
        public WireGuardNoSessionException()
            : base("The peer has not completed a WireGuard handshake; the server only answers, never opens.")
        {
        }
    }

    [DllImport(Library, EntryPoint = "rod_wg_new")]
    private static extern WireGuardRouterHandle RouterNew(byte[] serverPrivate, nuint len);

    [DllImport(Library, EntryPoint = "rod_wg_free")]
    internal static extern void RouterFree(IntPtr router);

    [DllImport(Library, EntryPoint = "rod_wg_peer_add")]
    private static extern int PeerAdd(WireGuardRouterHandle router, byte[] peerPublic, nuint len);

    [DllImport(Library, EntryPoint = "rod_wg_peer_remove")]
    private static extern int PeerRemove(WireGuardRouterHandle router, byte[] peerPublic, nuint len);

    [DllImport(Library, EntryPoint = "rod_wg_inject")]
    private static extern int RouterInject(
        WireGuardRouterHandle router,
        byte[] datagram, nuint datagramLength,
        byte[] networkOut, nuint networkCapacity, out nuint networkLength,
        byte[] tunnelOut, nuint tunnelCapacity, out nuint tunnelLength,
        byte[] peerOut);

    [DllImport(Library, EntryPoint = "rod_wg_send")]
    private static extern int RouterSend(
        WireGuardRouterHandle router,
        byte[] peerPublic,
        byte[] payload, nuint payloadLength,
        byte[] output, nuint outputCapacity, out nuint outputLength);

    [DllImport(Library, EntryPoint = "rod_wg_tick")]
    private static extern int RouterTick(
        WireGuardRouterHandle router,
        byte[] peerPublic,
        byte[] output, nuint outputCapacity, out nuint outputLength);
}
