using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Rod.CoreState;

namespace Rod.Transport.Endpoints;

// The session-key arm's server half (architecture.md Sec 9, session key
// agreement over the baked seal): a handshake that offers an ephemeral
// P-256 public key agrees a session's sealing keys with the implant, so the
// baked artifact key -- which a seized artifact surrenders -- no longer
// decrypts the traffic recorded around it. The agreement rides inside a
// body sealed under the baked key, so the exchange is authenticated by the
// credential the enrollment already bound; HKDF then takes the baked key as
// its salt, keeping it the session's root: possession of it still opens a
// NEW session (it is the enrollment identity), but never a recorded one.
//
// In-memory like the contact bindings and floors it sits beside (the same
// freshness boundary): a teamserver restart forgets the agreements, the
// implant's next R2 body turns away with a 401, and its fallback re-agrees
// under the baked key -- the same re-handshake a restart already demanded.

/// <summary>
/// The agreed sealing keys for one session, addressed by the session id the
/// HKDF schedule derives: the key the implant seals requests with, the key
/// the teamserver seals responses with, and the implant the agreement
/// belongs to (an R2 body whose inner handshake names another implant does
/// not authenticate). Registered as a singleton; holds only derived keys,
/// each worth no more than the session it seals.
/// </summary>
public sealed class SessionSealKeys
{
    /// <summary>
    /// One agreed session's keys. The session id is derived with them, so
    /// both sides know it without exchanging it, and the R2 body's prefix
    /// carries it where R1 carries the baked key id.
    /// </summary>
    public sealed record Entry(ImplantId Implant, Guid SessionId, byte[] RequestKey, byte[] ResponseKey);

    /// <summary>
    /// The uncompressed SEC1 point size on P-256: 0x04 || X || Y. The wire
    /// carries the point in this form because it is the one every stack's
    /// public-key export produces natively.
    /// </summary>
    public const int PublicKeyBytes = 65;

    /// <summary>The HKDF info label binding the schedule to its purpose.</summary>
    public static ReadOnlySpan<byte> InfoLabel => "rod-session-v1"u8;

    private readonly ConcurrentDictionary<Guid, Entry> _bySession = new();
    private readonly ConcurrentDictionary<ImplantId, Guid> _latest = new();

    /// <summary>
    /// Completes an agreement an implant's handshake offered: mints the
    /// server's ephemeral pair, derives the session keys from the ephemeral
    /// shared secret and the baked key, records them as the implant's
    /// current session (replacing any earlier agreement -- the newest
    /// handshake names the posture, the same rule the enroll-time binding
    /// follows), and returns the server's public half for the response. Null
    /// when the offered public key is not a P-256 point: the caller answers
    /// without the echo, and the implant keeps its baked-key seal.
    /// </summary>
    public (byte[] ServerPublic, Entry Entry)? Agree(
        ImplantId implant, Guid bakedKeyId, byte[] bakedKey, ReadOnlySpan<byte> implantPublic)
    {
        if (implantPublic.Length != PublicKeyBytes || implantPublic[0] != 0x04)
            return null;

        using var ours = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var theirs = ECDiffieHellman.Create();
        byte[] shared;
        try
        {
            theirs.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = implantPublic.Slice(1, 32).ToArray(),
                    Y = implantPublic.Slice(33, 32).ToArray(),
                },
            });
            shared = ours.DeriveRawSecretAgreement(theirs.PublicKey);
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (CryptographicException)
        {
            return null;
        }

        var okm = Derive(shared, bakedKey, bakedKeyId, implant);
        Array.Clear(shared, 0, shared.Length);
        var entry = new Entry(implant, new Guid(okm.AsSpan(0, 16)), okm[16..48], okm[48..80]);

        // Latest-wins with the replaced session's entry dropped, so the
        // store holds one entry per implant that agreed, never one per
        // agreement.
        if (_latest.TryGetValue(implant, out var previous) && previous != entry.SessionId)
            _bySession.TryRemove(previous, out _);
        _bySession[entry.SessionId] = entry;
        _latest[implant] = entry.SessionId;

        // The wire's uncompressed point: 0x04 || X(32) || Y(32), the export's
        // coordinates right-aligned to the field size the export pads to.
        var oursQ = ours.ExportParameters(includePrivateParameters: false).Q;
        var serverPublic = new byte[PublicKeyBytes];
        serverPublic[0] = 0x04;
        LeftAligned(oursQ.X, serverPublic.AsSpan(1, 32));
        LeftAligned(oursQ.Y, serverPublic.AsSpan(33, 32));
        return (serverPublic, entry);
    }

    // Copies a big-endian coordinate into its fixed 32-byte slot, left-padded
    // with zeros the way the point encoding expects.
    private static void LeftAligned(byte[]? coordinate, Span<byte> slot)
    {
        if (coordinate is not { Length: > 0 })
            return;
        var source = coordinate.AsSpan(Math.Max(0, coordinate.Length - slot.Length));
        source.CopyTo(slot.Slice(slot.Length - source.Length));
    }

    /// <summary>
    /// The session an R2 body's session id addresses, or null when no live
    /// agreement carries it (a restart, or a session this teamserver never
    /// agreed).
    /// </summary>
    public Entry? TryGet(Guid sessionId)
        => _bySession.TryGetValue(sessionId, out var entry) ? entry : null;

    /// <summary>
    /// The implant's current agreed session, or null when it never agreed
    /// one -- the gate an ordinary baked-key body checks: an implant holding
    /// session keys must not slip back to the seal its baked key opens.
    /// </summary>
    public Entry? TryLatest(ImplantId implant)
        => _latest.TryGetValue(implant, out var sessionId)
            ? _bySession.TryGetValue(sessionId, out var entry) ? entry : null
            : null;

    /// <summary>
    /// The key schedule both implant stacks reimplement: HKDF-SHA256 with
    /// the ephemeral shared secret as input keying material, the baked key
    /// as the salt (the root the session binds to), and the purpose label,
    /// baked key id, and implant id as the info -- so the keys name their
    /// session, their artifact, and their implant. Eighty bytes out: the
    /// session id, the request key, the response key.
    /// </summary>
    public static byte[] Derive(byte[] shared, byte[] bakedKey, Guid bakedKeyId, ImplantId implant)
    {
        var prk = HKDF.Extract(HashAlgorithmName.SHA256, shared, bakedKey);
        var info = new byte[InfoLabel.Length + 1 + 16 + 32];
        var position = 0;
        InfoLabel.CopyTo(info.AsSpan(position));
        position += InfoLabel.Length;
        info[position++] = 0;
        bakedKeyId.ToByteArray().AsSpan().CopyTo(info.AsSpan(position));
        position += 16;
        Encoding.UTF8.GetBytes(implant.ToString()).CopyTo(info.AsSpan(position));
        return HKDF.Expand(HashAlgorithmName.SHA256, prk, 80, info);
    }
}
