using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Rod.Packaging;

/// <summary>
/// Ed25519 signing over the manifest's canonical form (architecture.md
/// Sec 15.2): every registry entry carries the publisher's public key and
/// the signature; the lock file pins the key per module name at first
/// install and <c>rod mod verify</c> re-proves installed trees offline.
/// Ed25519 over detached signatures is the shape the field's trust designs
/// converged on (minisign, TUF), and raw 32/64-byte keys and signatures
/// keep the contract language-neutral -- a Rust or Go verifier reads the
/// same bytes the CLI writes. Keys encode as base64 in small key files
/// whose first line names the format.
/// </summary>
public static class Ed25519
{
    public const string KeyFileMagic = "rod-signing-key-v1";

    public sealed record KeyPair(byte[] PublicKey, byte[] SecretKey);

    public static KeyPair GenerateKeyPair()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();
        var secret = (Ed25519PrivateKeyParameters)keyPair.Private;
        return new KeyPair(secret.GeneratePublicKey().GetEncoded(), secret.GetEncoded());
    }

    public static byte[] Sign(byte[] secretKey, byte[] message)
    {
        var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(secretKey, 0));
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }

    public static bool Verify(byte[] publicKey, byte[] signature, byte[] message)
    {
        if (publicKey.Length != 32 || signature.Length != 64)
            return false;
        var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        signer.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        signer.BlockUpdate(message, 0, message.Length);
        try
        {
            return signer.VerifySignature(signature);
        }
        catch (CryptoException)
        {
            return false;
        }
    }

    /// <summary>Derives the public half of a secret key -- the pair travels
    /// as one seed, and every consumer of the secret can state the identity
    /// it signs as.</summary>
    public static byte[] PublicFromSecret(byte[] secretKey)
        => new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(secretKey, 0)
            .GeneratePublicKey()
            .GetEncoded();

    /// <summary>The short stable identity of a public key -- the first 16
    /// bytes of its SHA-256, hex -- shown at search, info, install, and
    /// publish so an operator can eyeball trust decisions against what the
    /// publisher announced out of band.</summary>
    public static string Fingerprint(byte[] publicKey)
        => Convert.ToHexStringLower(SHA256.HashData(publicKey)[..16]);

    public static byte[] DecodeKey(string base64)
    {
        var bytes = Convert.FromBase64String(base64.Trim());
        if (bytes.Length != 32)
            throw new FormatException("an Ed25519 key is 32 bytes");
        return bytes;
    }
}

/// <summary>
/// The publisher's key files beside the module: <c>rod-module.key</c> (the
/// secret seed, never packed, never published) and <c>rod-module.pub</c>
/// (the public half that rides every registry entry). The pair is generated
/// by <c>rod mod init</c> and reused by every publish; losing the secret
/// key means a new identity, and the lock's pinning will say so loudly on
/// every install after.
/// </summary>
public static class KeyFiles
{
    public const string SecretFileName = "rod-module.key";
    public const string PublicFileName = "rod-module.pub";

    public static Ed25519.KeyPair Generate(string directory)
    {
        var pair = Ed25519.GenerateKeyPair();
        WriteSecret(Path.Combine(directory, SecretFileName), pair.SecretKey);
        File.WriteAllText(Path.Combine(directory, PublicFileName),
            Ed25519.KeyFileMagic + "\n" + Convert.ToBase64String(pair.PublicKey) + "\n");
        return pair;
    }

    public static byte[] LoadSecret(string path)
    {
        var lines = File.ReadAllLines(path);
        if (lines.Length < 2 || lines[0].Trim() != Ed25519.KeyFileMagic)
            throw new FormatException($"'{path}' is not a rod signing key file (first line must be {Ed25519.KeyFileMagic}).");
        return Ed25519.DecodeKey(lines[1]);
    }

    public static byte[] LoadPublic(string path)
    {
        var lines = File.ReadAllLines(path);
        if (lines.Length < 2 || lines[0].Trim() != Ed25519.KeyFileMagic)
            throw new FormatException($"'{path}' is not a rod public key file.");
        return Ed25519.DecodeKey(lines[1]);
    }

    private static void WriteSecret(string path, byte[] secretKey)
    {
        File.WriteAllText(path, Ed25519.KeyFileMagic + "\n" + Convert.ToBase64String(secretKey) + "\n");
        // Owner-only on the Unix-likes; best-effort, Windows ACLs are the
        // profile's own concern for a per-repository key.
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            try
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch (IOException)
            {
                // A key that stays world-readable is a warning-grade problem,
                // not a failed publish; the operator's filesystem wins.
            }
        }
    }
}
