using System.Security.Cryptography;

using Rod.Packaging;

namespace Rod.Cli.Tests;

public class SigningTests
{
    [Fact]
    public void KeyPairRoundTrips_SignVerifyTamper()
    {
        var pair = Ed25519.GenerateKeyPair();
        var message = System.Text.Encoding.UTF8.GetBytes("rod-module-manifest-v1\nname=demo\n");
        var signature = Ed25519.Sign(pair.SecretKey, message);

        Assert.True(Ed25519.Verify(pair.PublicKey, signature, message));

        var tampered = (byte[])message.Clone();
        tampered[^1] = (byte)(tampered[^1] ^ 1);
        Assert.False(Ed25519.Verify(pair.PublicKey, signature, tampered));

        var wrongKey = Ed25519.GenerateKeyPair();
        Assert.False(Ed25519.Verify(wrongKey.PublicKey, signature, message));
    }

    [Fact]
    public void TheSecretSeed_DerivesItsOwnPublicKey()
    {
        var pair = Ed25519.GenerateKeyPair();
        Assert.Equal(pair.PublicKey, Ed25519.PublicFromSecret(pair.SecretKey));
    }

    [Fact]
    public void Fingerprints_AreStableAndKeyDistinct()
    {
        var first = Ed25519.GenerateKeyPair();
        var second = Ed25519.GenerateKeyPair();
        Assert.Equal(Ed25519.Fingerprint(first.PublicKey), Ed25519.Fingerprint(first.PublicKey));
        Assert.NotEqual(Ed25519.Fingerprint(first.PublicKey), Ed25519.Fingerprint(second.PublicKey));
        Assert.Equal(32, Ed25519.Fingerprint(first.PublicKey).Length);
    }

    [Fact]
    public void KeyFiles_RoundTripThroughTheirFormat()
    {
        using var root = new TempRoot();
        var pair = KeyFiles.Generate(root.Path);

        Assert.Equal(pair.PublicKey, KeyFiles.LoadPublic(root["rod-module.pub"]));
        Assert.Equal(pair.SecretKey, KeyFiles.LoadSecret(root["rod-module.key"]));
        Assert.Equal(pair.PublicKey, Ed25519.PublicFromSecret(KeyFiles.LoadSecret(root["rod-module.key"])));
    }
}

public class PackagingTests
{
    [Fact]
    public async Task DeterministicZips_IdenticalTreesProduceIdenticalDigests()
    {
        using var root = new TempRoot();
        foreach (var name in new[] { "a", "b" })
        {
            Directory.CreateDirectory(root[name, "src"]);
            File.WriteAllText(root[name, ManifestToml.FileName], "placeholder manifest");
            File.WriteAllText(root[name, "src", "payload.cs"], "payload bytes");
        }

        var selectionA = ModulePackage.SelectFiles(root["a"], null);
        var selectionB = ModulePackage.SelectFiles(root["b"], null);
        var (_, digestA) = await ModulePackage.WriteZipAsync(selectionA, root["a.zip"]);
        var (_, digestB) = await ModulePackage.WriteZipAsync(selectionB, root["b.zip"]);

        Assert.Equal(digestA, digestB);
    }

    [Fact]
    public void Selection_HardExcludesNeverReachThePackage()
    {
        using var root = new TempRoot();
        Directory.CreateDirectory(root["src"]);
        Directory.CreateDirectory(root["bin"]);
        Directory.CreateDirectory(root["dist"]);
        File.WriteAllText(root[ManifestToml.FileName], "manifest");
        File.WriteAllText(root["src", "a.cs"], "a");
        File.WriteAllText(root["bin", "junk.dll"], "junk");
        File.WriteAllText(root["dist", "old.zip"], "old");
        File.WriteAllText(root["rod-module.key"], "secret");
        File.WriteAllText(root["src", "nested.key"], "secret");

        var selection = ModulePackage.SelectFiles(root.Path, null);
        Assert.Contains("rod-module.toml", selection.Files);
        Assert.Contains("src/a.cs", selection.Files);
        Assert.DoesNotContain(selection.Files, f => f.EndsWith(".key", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(selection.Files, f => f.Contains("bin/") || f.Contains("dist/"));
    }

    [Theory]
    [InlineData("**/bin/**", "bin/debug/x.dll", true)]
    [InlineData("**/bin/**", "src/bin.cs", false)]
    [InlineData("**/bin/**", "obj/debug/x.dll", false)]
    [InlineData("src/**", "src/deep/nested/a.cs", true)]
    [InlineData("src/**", "other/a.cs", false)]
    [InlineData("*.cs", "a.cs", true)]
    [InlineData("*.cs", "src/a.cs", false)]
    [InlineData("*.cs", "a.csproj", false)]
    [InlineData("**/*.key", "deep/dir/secret.key", true)]
    public void GlobSemantics_MatchDepthCorrectly(string pattern, string path, bool expected)
        => Assert.Equal(expected, ModulePackage.GlobMatches(pattern, path));

    [Fact]
    public void Extraction_RefusesZipSlip()
    {
        using var root = new TempRoot();
        var zipPath = root["evil.zip"];
        using (var archive = new System.IO.Compression.ZipArchive(File.Create(zipPath), System.IO.Compression.ZipArchiveMode.Create))
        {
            archive.CreateEntry("../../escaped.txt");
        }

        Assert.Throws<IOException>(() => ModulePackage.ExtractSafe(zipPath, root["out"]));
        Assert.False(File.Exists(root["..", "..", "escaped.txt"]));
    }
}
