using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using Rod.BuildPipeline.PayloadBuild;

namespace Rod.Build.Tests;

/// <summary>
/// The official listener packages' pinned-source contract (ADR-025:
/// pinned by version like the implant trees): the lock parse, the
/// environment override, and the fetch-verify-unpack path, driven end to
/// end against a file:// asset base so no test touches the network. These
/// tests mutate the resolution's environment variables -- the same ones
/// the official-package e2e legs' resolution reads -- which is why the
/// assembly serializes its collections (xunit.runner.json).
/// </summary>
public sealed class PinnedListenerSourceTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rod-listener-pin-" + Guid.NewGuid().ToString("N"));
    private readonly Dictionary<string, string?> _saved = new();

    public PinnedListenerSourceTests()
    {
        Directory.CreateDirectory(_root);
        foreach (var variable in new[]
                 {
                     PinnedImplantSource.LockFileVariable,
                     PinnedImplantSource.CacheRootVariable,
                     PinnedImplantSource.AssetBaseVariable,
                     PinnedListenerSource.HttpsTreeVariable,
                     PinnedListenerSource.DohTreeVariable,
                     PinnedListenerSource.CacheRootVariable,
                     PinnedListenerSource.AssetBaseVariable,
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
    public void TheRepositoryLock_PinsBothPackages()
    {
        foreach (var name in new[] { PinnedListenerSource.Https, PinnedListenerSource.Doh })
        {
            var pin = PinnedListenerSource.PinFor(name);
            Assert.NotNull(pin);
            Assert.Equal("v1.0.0", pin!.Value.Version);
            Assert.StartsWith("https://github.com/rodframework/rod-listener-", pin.Value.Repository);
            Assert.Equal(64, pin.Value.Sha256.Length);
        }
    }

    [Fact]
    public void AnEnvironmentCheckout_WinsAndMustBeARealPackage()
    {
        var checkout = Path.Combine(_root, "rod-listener-https");
        Directory.CreateDirectory(checkout);
        File.WriteAllText(Path.Combine(checkout, PinnedListenerSource.ManifestName), "# not parsed here");

        Environment.SetEnvironmentVariable(PinnedListenerSource.HttpsTreeVariable, checkout);
        Assert.Equal(checkout, PinnedListenerSource.LocateHttpsPackage());

        var notAPackage = Path.Combine(_root, "empty");
        Directory.CreateDirectory(notAPackage);
        Environment.SetEnvironmentVariable(PinnedListenerSource.HttpsTreeVariable, notAPackage);
        Assert.Throws<InvalidOperationException>(() => PinnedListenerSource.LocateHttpsPackage());
    }

    [Fact]
    public void ThePinnedRelease_FetchesVerifiesAndUnpacks()
    {
        // A lock of our own, an asset of our own, a file:// base: the whole
        // fetch-verify-unpack path without the network.
        var source = Path.Combine(_root, "src");
        Directory.CreateDirectory(source);
        File.WriteAllText(Path.Combine(source, PinnedListenerSource.ManifestName), "# the package");
        File.WriteAllText(Path.Combine(source, "server"), "the built-by-consumer binary lands here later");

        var asset = Path.Combine(_root, "dist", "rod-listener-https-src-v9.9.9.tar.gz");
        Directory.CreateDirectory(Path.GetDirectoryName(asset)!);
        using (var output = File.Create(asset))
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize))
        {
            TarFile.CreateFromDirectory(source, gzip, includeBaseDirectory: false);
        }
        var sha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(asset)));

        var lockFile = Path.Combine(_root, "rod-implants.lock.json");
        File.WriteAllText(lockFile, $$"""
            {
              "listeners": {
                "https": {
                  "repository": "https://example.invalid/rod-listener-https",
                  "version": "v9.9.9",
                  "sha256": "{{sha}}"
                }
              }
            }
            """);
        Environment.SetEnvironmentVariable(PinnedImplantSource.LockFileVariable, lockFile);
        Environment.SetEnvironmentVariable(PinnedListenerSource.CacheRootVariable, Path.Combine(_root, "cache"));
        Environment.SetEnvironmentVariable(PinnedListenerSource.AssetBaseVariable, new Uri(_root + "/").AbsoluteUri + "dist");

        var resolved = PinnedListenerSource.ResolvePinned(PinnedListenerSource.Https);
        Assert.NotNull(resolved);
        Assert.True(File.Exists(Path.Combine(resolved!, PinnedListenerSource.ManifestName)));
        // <cache>/<name>/<version>: the pin cache's own layout.
        Assert.Equal("v9.9.9", Path.GetFileName(Path.GetFullPath(resolved).TrimEnd(Path.DirectorySeparatorChar)));
    }

    [Fact]
    public void ATamperedAsset_RefusesToUnpack()
    {
        var source = Path.Combine(_root, "tampered-src");
        Directory.CreateDirectory(source);
        File.WriteAllText(Path.Combine(source, PinnedListenerSource.ManifestName), "# the package");
        var asset = Path.Combine(_root, "dist-tampered", "rod-listener-doh-src-v9.9.9.tar.gz");
        Directory.CreateDirectory(Path.GetDirectoryName(asset)!);
        using (var output = File.Create(asset))
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize))
        {
            TarFile.CreateFromDirectory(source, gzip, includeBaseDirectory: false);
        }

        var lockFile = Path.Combine(_root, "rod-implants.lock.json");
        File.WriteAllText(lockFile, $$"""
            {
              "listeners": {
                "doh": {
                  "repository": "https://example.invalid/rod-listener-doh",
                  "version": "v9.9.9",
                  "sha256": "{{new string('0', 64)}}"
                }
              }
            }
            """);
        Environment.SetEnvironmentVariable(PinnedImplantSource.LockFileVariable, lockFile);
        Environment.SetEnvironmentVariable(PinnedListenerSource.CacheRootVariable, Path.Combine(_root, "cache-tampered"));
        Environment.SetEnvironmentVariable(PinnedListenerSource.AssetBaseVariable, new Uri(_root + "/").AbsoluteUri + "dist-tampered");

        Assert.Throws<InvalidOperationException>(() => PinnedListenerSource.ResolvePinned(PinnedListenerSource.Doh));
    }
}
