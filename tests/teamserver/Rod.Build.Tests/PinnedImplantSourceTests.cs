using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using Rod.BuildPipeline.PayloadBuild;

namespace Rod.Build.Tests;

/// <summary>
/// The pinned-source contract's resolution half (architecture.md Sec 15.4):
/// the lock parse, the environment override, and the fetch-verify-unpack
/// path, driven end to end against a file:// asset base so no test touches
/// the network. These tests mutate the resolution's environment variables --
/// the same ones a build unit's default construction reads -- which is why
/// the assembly serializes its collections (xunit.runner.json).
/// </summary>
public sealed class PinnedImplantSourceTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rod-pin-" + Guid.NewGuid().ToString("N"));
    private readonly Dictionary<string, string?> _saved = new();

    public PinnedImplantSourceTests()
    {
        Directory.CreateDirectory(_root);
        foreach (var variable in new[]
                 {
                     PinnedImplantSource.LockFileVariable,
                     PinnedImplantSource.CacheRootVariable,
                     PinnedImplantSource.AssetBaseVariable,
                     PinnedImplantSource.RustTreeVariable,
                     PinnedImplantSource.GoTreeVariable,
                 })
        {
            _saved[variable] = Environment.GetEnvironmentVariable(variable);
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    public void Dispose()
    {
        foreach (var (variable, value) in _saved)
            Environment.SetEnvironmentVariable(variable, value);
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    [Fact]
    public void TheRepositoryLock_PinsBothLanguages()
    {
        foreach (var language in new[] { PinnedImplantSource.Rust, PinnedImplantSource.Go })
        {
            var pin = PinnedImplantSource.PinFor(language);
            Assert.NotNull(pin);
            Assert.StartsWith("v", pin!.Version);
            Assert.Equal(64, pin.Sha256.Length);
            Assert.True(pin.Sha256.All(char.IsAsciiHexDigit), $"{language} digest is hex");
        }
    }

    [Fact]
    public void AnEnvironmentCheckout_WinsImmediately()
    {
        var checkout = Path.Combine(_root, "checkout-rust");
        Directory.CreateDirectory(checkout);
        Environment.SetEnvironmentVariable(PinnedImplantSource.RustTreeVariable, checkout);
        Assert.Equal(checkout, PinnedImplantSource.LocateRustTree());
    }

    [Fact]
    public void AMissingEnvironmentCheckout_FailsLoudly()
    {
        Environment.SetEnvironmentVariable(PinnedImplantSource.GoTreeVariable, Path.Combine(_root, "absent"));
        var failure = Assert.Throws<InvalidOperationException>(PinnedImplantSource.LocateGoTree);
        Assert.Contains(PinnedImplantSource.GoTreeVariable, failure.Message);
    }

    [Fact]
    public void APinnedRelease_DownloadsVerifiesAndUnpacks()
    {
        var version = "v9.9.9-test.1";
        var (assetDirectory, sha256) = WriteFixtureAsset(PinnedImplantSource.Rust, version);
        UseFixturePin(WriteFixturePin(PinnedImplantSource.Rust, version, sha256), assetDirectory);

        var tree = PinnedImplantSource.EnsurePinnedTree(PinnedImplantSource.Rust);
        Assert.NotNull(tree);
        Assert.True(File.Exists(Path.Combine(tree!, "Cargo.toml")));
        // The proto sibling build.rs probes: copied from the repository's
        // own protos, so direct cargo runs in the cached tree resolve the
        // wire contract the way the staging copy does.
        Assert.True(File.Exists(Path.Combine(
            tree!, "..", "..", "..", "src", "teamserver", "Rod.Protocol", "protos", "rod.proto")));
        // A warm cache is an idempotent no-op returning the same tree.
        Assert.Equal(tree, PinnedImplantSource.EnsurePinnedTree(PinnedImplantSource.Rust));
    }

    [Fact]
    public void ADigestMismatch_IsRefused()
    {
        var version = "v9.9.9-test.2";
        var (assetDirectory, _) = WriteFixtureAsset(PinnedImplantSource.Go, version);
        UseFixturePin(WriteFixturePin(PinnedImplantSource.Go, version, new string('0', 64)), assetDirectory);

        var failure = Assert.Throws<InvalidOperationException>(
            () => PinnedImplantSource.EnsurePinnedTree(PinnedImplantSource.Go));
        Assert.Contains("hashes to", failure.Message);
    }

    [Fact]
    public void ALockWithoutTheLanguage_HasNoPin()
    {
        var lockPath = WriteFixturePin(PinnedImplantSource.Go, "v9.9.9-test.3", new string('1', 64));
        Environment.SetEnvironmentVariable(PinnedImplantSource.LockFileVariable, lockPath);
        Assert.Null(PinnedImplantSource.PinFor(PinnedImplantSource.Rust));
        Assert.Null(PinnedImplantSource.EnsurePinnedTree(PinnedImplantSource.Rust));
    }

    [Fact]
    public void AMalformedLock_FailsLoudly()
    {
        var lockPath = Path.Combine(_root, "broken-rod-implants.lock.json");
        File.WriteAllText(lockPath, "{ not json");
        Environment.SetEnvironmentVariable(PinnedImplantSource.LockFileVariable, lockPath);
        Assert.Throws<InvalidOperationException>(() => PinnedImplantSource.PinFor(PinnedImplantSource.Rust));
    }

    private static string WriteFixturePin(string language, string version, string sha256)
        => $$"""
             {
               "{{language}}": {
                 "repository": "http://example.invalid/rod-implant-{{language}}",
                 "version": "{{version}}",
                 "sha256": "{{sha256}}"
               }
             }
             """;

    private (string AssetDirectory, string Sha256) WriteFixtureAsset(string language, string version)
    {
        var stage = Path.Combine(_root, "stage-" + Guid.NewGuid().ToString("N"));
        var tree = Path.Combine(stage, "src", "implant", language);
        Directory.CreateDirectory(tree);
        File.WriteAllText(
            Path.Combine(tree, language == PinnedImplantSource.Rust ? "Cargo.toml" : "go.mod"),
            language == PinnedImplantSource.Rust ? "[package]\nname = \"rod-implant\"\n" : "module rodimplant\n");

        var assetDirectory = Path.Combine(_root, "assets-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(assetDirectory);
        var asset = Path.Combine(assetDirectory, $"rod-implant-{language}-src-{version}.tar.gz");
        using (var output = File.Create(asset))
        {
            using var gzip = new GZipStream(output, CompressionLevel.Optimal);
            TarFile.CreateFromDirectory(stage, gzip, includeBaseDirectory: false);
        }
        using var stream = File.OpenRead(asset);
        return (assetDirectory, Convert.ToHexString(SHA256.HashData(stream)));
    }

    private void UseFixturePin(string lockContent, string assetDirectory)
    {
        var lockPath = Path.Combine(_root, "fixture-rod-implants.lock.json");
        File.WriteAllText(lockPath, lockContent);
        Environment.SetEnvironmentVariable(PinnedImplantSource.LockFileVariable, lockPath);
        Environment.SetEnvironmentVariable(PinnedImplantSource.CacheRootVariable, Path.Combine(_root, "cache"));
        Environment.SetEnvironmentVariable(
            PinnedImplantSource.AssetBaseVariable,
            new Uri(assetDirectory).AbsoluteUri);
    }
}
