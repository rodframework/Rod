using System.Security.Cryptography;

namespace Rod.Transport.Payloads;

/// <summary>
/// The AES-GCM transport envelope (architecture.md Sec 7, the encrypted member
/// of the envelope family): the enroll body is a single base64 JSON string
/// wrapping <c>b"R1" || keyId(16) || nonce(12) || ciphertext || tag(16)</c>,
/// AES-256-GCM under a per-artifact key minted at build time. The key is baked
/// into the artifact (the implant encrypts with it) and recorded beside the
/// stored payload (the teamserver decrypts with it), so the pair lives exactly
/// as long as the payload: deleting the payload deletes the key, and that
/// artifact's envelopes become undecodable -- enroll included.
///
/// The key id rides the plaintext prefix because the enroll token travels
/// inside the ciphertext: the server must resolve the key before it can
/// validate anything. A leaked key id alone grants nothing -- the token inside
/// still scopes the enrollment. The "R1" magic names the shape and version so
/// a decoder can tell ciphertext from the plain base64 envelope without
/// guessing, and a future shape can coexist. Public because the wire layout is
/// the cross-component contract: the implant reimplements it verbatim, and the
/// tests encode with the same bytes the teamserver decodes.
///
/// The same key, in the same R1 shape but under purpose-specific AAD tags,
/// also seals the envelope contact bodies (architecture.md Sec 8): every
/// contact request and response is AES-GCM ciphertext under the artifact key,
/// so the cleartext-http posture carries confidential content, not just
/// authenticated content -- the Cobalt Strike metadata model. The DNS carriage
/// seals the same way but carries the raw R1 body (no base64 layer: its labels
/// are already base32, a text encoding inside another would double the
/// expansion) -- <see cref="WrapBody"/> and friends are that byte-level form.
/// </summary>
public static class AesGcmEnvelope
{
    /// <summary>Plaintext prefix: shape id and version, "R1".</summary>
    public static ReadOnlySpan<byte> Magic => "R1"u8;

    /// <summary>The GCM tag size in bytes.</summary>
    public const int TagBytes = 16;

    /// <summary>The nonce size in bytes (GCM standard 96-bit).</summary>
    public const int NonceBytes = 12;

    /// <summary>
    /// The additional-authenticated data binding the enroll envelope to its
    /// purpose, so a wrapped enroll body cannot be replayed as another
    /// protocol's ciphertext.
    /// </summary>
    public static ReadOnlySpan<byte> Aad => "rod-envelope-v1"u8;

    /// <summary>
    /// The AAD binding an implant's sealed contact request to its purpose
    /// (architecture.md Sec 8/9): the same per-artifact key envelopes the
    /// enroll body and the contact bodies, so the purpose tag is what keeps
    /// one direction's ciphertext from being replayed as the other's.
    /// </summary>
    public static ReadOnlySpan<byte> ContactRequestAad => "rod-contact-v1"u8;

    /// <summary>
    /// The response-side twin of <see cref="ContactRequestAad"/>: the
    /// teamserver seals every contact response under this tag, so a sealed
    /// request body cannot be reflected as a response and vice versa.
    /// </summary>
    public static ReadOnlySpan<byte> ContactResponseAad => "rod-contact-response-v1"u8;

    /// <summary>
    /// The AAD binding the socket family's sealed enroll exchange to its
    /// purpose (architecture.md Sec 8, enrollment over the stream contact):
    /// the same per-artifact key envelopes the enroll body and the contact
    /// bodies, so the purpose tag keeps one exchange's ciphertext from being
    /// replayed as another's.
    /// </summary>
    public static ReadOnlySpan<byte> EnrollRequestAad => "rod-enroll-v1"u8;

    /// <summary>The response-side twin of <see cref="EnrollRequestAad"/>.</summary>
    public static ReadOnlySpan<byte> EnrollResponseAad => "rod-enroll-response-v1"u8;

    /// <summary>
    /// The AAD binding the DNS carriage's poll answers to their purpose
    /// (architecture.md Sec 8): a key-named poll's TXT answer is sealed under
    /// this tag, so no other purpose's ciphertext (an enroll answer, a web
    /// contact body) can be reflected down the DNS wire as tasking.
    /// </summary>
    public static ReadOnlySpan<byte> DnsPollAad => "rod-dns-poll-v1"u8;

    /// <summary>
    /// The upstream twin for task results: a sealed result blob the implant
    /// chunks into <c>r.</c> queries is bound to this tag, so a sealed poll
    /// answer or channel blob cannot be replayed up as a result.
    /// </summary>
    public static ReadOnlySpan<byte> DnsResultAad => "rod-dns-result-v1"u8;

    /// <summary>
    /// The upstream twin for channel outputs: a sealed output blob the
    /// implant chunks into <c>c.</c> queries is bound to this tag, keeping it
    /// distinct from results and poll answers under the same key.
    /// </summary>
    public static ReadOnlySpan<byte> DnsChannelAad => "rod-dns-channel-v1"u8;

    /// <summary>
    /// The staged download's per-chunk tag (ADR-010): each <c>d.</c> answer a
    /// keyed artifact's staged transfer serves is a raw R1 body under this
    /// tag, so no other purpose's ciphertext rides the resolver chain as
    /// payload bytes, and a resumed transfer's chunks seal individually --
    /// placement does not wait for a whole sealed blob.
    /// </summary>
    public static ReadOnlySpan<byte> DnsStagedAad => "rod-dns-staged-v1"u8;

    /// <summary>
    /// The upstream exfil arm's blob tag (ADR-010, the upload arm): each
    /// <c>u.</c> upload stream a keyed artifact sends reassembles into one
    /// sealed ExfilChunk slice under this tag. The upload arm over DNS is
    /// sealed-only -- a plaintext reassembly is dropped rather than
    /// tolerated the way <c>r.</c>/<c>c.</c> do -- because MB-scale
    /// upstream runs would otherwise hand a forger the artifact store keyed
    /// by a task id the query name already leaks; the seal authenticates
    /// possession of the baked key before any byte places.
    /// </summary>
    public static ReadOnlySpan<byte> DnsExfilAad => "rod-dns-exfil-v1"u8;

    /// <summary>
    /// The AAD binding the loader tier's sealed payload fetch to its purpose:
    /// the fetch route serves the delivered payload as a raw R1 body under
    /// this tag, so no other purpose's ciphertext (a contact body, an enroll
    /// answer) can be reflected down the loader payload route and opened by
    /// a loader.
    /// </summary>
    public static ReadOnlySpan<byte> LoaderPayloadAad => "rod-loader-payload-v1"u8;

    /// <summary>The key size in bytes: AES-256.</summary>
    public const int KeyBytes = 32;

    /// <summary>Mints a fresh envelope key pair: its id and the key itself.</summary>
    public static (Guid KeyId, byte[] Key) Mint()
        => (Guid.NewGuid(), RandomNumberGenerator.GetBytes(KeyBytes));

    /// <summary>
    /// The baked form the artifact carries: standard base64 of
    /// <c>keyId || key</c>, decoded with one <c>Convert.FromBase64String</c> on
    /// the implant side.
    /// </summary>
    public static string Bake(Guid keyId, byte[] key)
    {
        var packed = new byte[16 + key.Length];
        keyId.ToByteArray().AsSpan().CopyTo(packed);
        key.AsSpan().CopyTo(packed.AsSpan(16));
        return Convert.ToBase64String(packed);
    }

    /// <summary>Splits the baked form back into its id and key.</summary>
    public static bool TryUnbake(string baked, out Guid keyId, out byte[] key)
    {
        keyId = default;
        key = Array.Empty<byte>();
        if (string.IsNullOrEmpty(baked))
            return false;
        byte[] packed;
        try
        {
            packed = Convert.FromBase64String(baked);
        }
        catch (FormatException)
        {
            return false;
        }
        if (packed.Length != 16 + KeyBytes)
            return false;
        keyId = new Guid(packed.AsSpan(0, 16).ToArray());
        key = packed.AsSpan(16).ToArray();
        return true;
    }

    /// <summary>
    /// Wraps plaintext as the full wire value (the JSON string's content):
    /// base64 of magic, key id, nonce, ciphertext, and tag. The
    /// <paramref name="aad"/> names the purpose the ciphertext is bound to --
    /// <see cref="Aad"/> for the enroll body, the contact tags for the
    /// contact bodies -- so one purpose's wrapped bytes never validate as
    /// another's.
    /// </summary>
    public static string Wrap(byte[] plaintext, Guid keyId, byte[] key, ReadOnlySpan<byte> aad)
        => Convert.ToBase64String(WrapBody(plaintext, keyId, key, aad));

    /// <summary>
    /// The byte-level form <see cref="Wrap"/> base64s: the raw
    /// <c>magic || keyId || nonce || ciphertext || tag</c> body. The DNS
    /// carriage carries this form (base32 labels around a base64 text would
    /// double the encoding expansion); every other purpose sends the string.
    /// </summary>
    public static byte[] WrapBody(byte[] plaintext, Guid keyId, byte[] key, ReadOnlySpan<byte> aad)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeyBytes);
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagBytes];
        using var aes = new AesGcm(key, TagBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        var body = new byte[2 + 16 + NonceBytes + ciphertext.Length + TagBytes];
        var position = 0;
        Magic.CopyTo(body.AsSpan(position));
        position += 2;
        keyId.ToByteArray().AsSpan().CopyTo(body.AsSpan(position));
        position += 16;
        nonce.AsSpan().CopyTo(body.AsSpan(position));
        position += NonceBytes;
        ciphertext.AsSpan().CopyTo(body.AsSpan(position));
        position += ciphertext.Length;
        tag.AsSpan().CopyTo(body.AsSpan(position));
        return body;
    }

    /// <summary>
    /// Unwraps a wire value produced by <see cref="Wrap"/> under the same
    /// <paramref name="aad"/>: authenticates the tag, checks the magic, and
    /// returns the plaintext -- or null on any mismatch (wrong key, tampered
    /// bytes, foreign shape, or a different purpose's ciphertext).
    /// </summary>
    public static byte[]? TryUnwrap(string wrapped, Guid keyId, byte[] key, ReadOnlySpan<byte> aad)
    {
        if (string.IsNullOrEmpty(wrapped))
            return null;
        byte[] body;
        try
        {
            body = Convert.FromBase64String(wrapped);
        }
        catch (FormatException)
        {
            return null;
        }
        return TryUnwrapBody(body, keyId, key, aad);
    }

    /// <summary>
    /// The byte-level form <see cref="TryUnwrap"/> decodes into: opens a raw
    /// R1 body under the same key id and <paramref name="aad"/>, or null on
    /// any mismatch. The DNS carriage's reassembled upstream blobs arrive in
    /// this form.
    /// </summary>
    public static byte[]? TryUnwrapBody(ReadOnlySpan<byte> body, Guid keyId, byte[] key, ReadOnlySpan<byte> aad)
    {
        if (key.Length != KeyBytes)
            return null;
        if (body.Length < 2 + 16 + NonceBytes + TagBytes)
            return null;
        if (!body.Slice(0, 2).SequenceEqual(Magic))
            return null;
        if (!new Guid(body.Slice(2, 16).ToArray()).Equals(keyId))
            return null;
        var nonce = body.Slice(2 + 16, NonceBytes).ToArray();
        var ciphertextLength = body.Length - 2 - 16 - NonceBytes - TagBytes;
        if (ciphertextLength < 0)
            return null;
        var ciphertext = body.Slice(2 + 16 + NonceBytes, ciphertextLength).ToArray();
        var tag = body.Slice(body.Length - TagBytes).ToArray();
        var plaintext = new byte[ciphertextLength];
        try
        {
            using var aes = new AesGcm(key, TagBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        catch (CryptographicException)
        {
            return null;
        }
        return plaintext;
    }

    /// <summary>
    /// Reads the key id off a wire value without a key, so the enroll decode
    /// can resolve the key first. Null when the value is not the R1 shape.
    /// </summary>
    public static Guid? TryReadKeyId(string wrapped)
    {
        if (string.IsNullOrEmpty(wrapped))
            return null;
        byte[] body;
        try
        {
            body = Convert.FromBase64String(wrapped);
        }
        catch (FormatException)
        {
            return null;
        }
        return TryReadKeyIdBody(body);
    }

    /// <summary>
    /// The byte-level form of <see cref="TryReadKeyId"/>: reads the key id off
    /// a raw R1 body, or null when the bytes are not the shape. The DNS
    /// carriage's discriminator between a sealed upstream blob and a plaintext
    /// one.
    /// </summary>
    public static Guid? TryReadKeyIdBody(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2 + 16 + NonceBytes + TagBytes)
            return null;
        if (!body.Slice(0, 2).SequenceEqual(Magic))
            return null;
        return new Guid(body.Slice(2, 16).ToArray());
    }
}
