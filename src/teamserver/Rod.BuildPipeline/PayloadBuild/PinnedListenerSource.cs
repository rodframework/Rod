using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// Resolves the official listener packages' source trees through the same
/// pinned-source contract the implant trees ride (architecture.md Sec
/// 15.4, ADR-025: pinned by version like the implant trees): an explicit
/// environment checkout first (<see cref="HttpsTreeVariable"/> /
/// <see cref="DohTreeVariable"/>), then the co-located layouts a checkout
/// or a deployment carries (src/listener/&lt;name&gt;, a flat sibling
/// checkout, or the rod-ecosystem collection beside the platform), then the
/// pinned release the source lock names -- downloaded once, verified by
/// its sha256, unpacked into a cache every consumer shares. The resolved
/// directory is the package root (the tree carrying rod-module.toml);
/// consumers build it (build.sh) before packing it for install.
/// </summary>
/// <remarks>
/// The lock and the cache discipline are <see cref="PinnedImplantSource"/>'s
/// own -- same lock file, same walk-up-and-override resolution, same
/// staging-unpack race posture -- applied to the official packages the
/// e2e legs install through the module lifecycle.
/// </remarks>
public static class PinnedListenerSource
{
    public const string HttpsTreeVariable = "ROD_LISTENER_HTTPS_DIR";
    public const string DohTreeVariable = "ROD_LISTENER_DOH_DIR";
    public const string CacheRootVariable = "ROD_LISTENER_CACHE";
    public const string AssetBaseVariable = "ROD_LISTENER_ASSET_BASE";

    public const string Https = "https";
    public const string Doh = "doh";

    internal const string ManifestName = "rod-module.toml";

    // Parsed locks keyed by path, so a redirected implant lock
    // (ROD_IMPLANT_LOCK) re-reads rather than serving the cached one; the
    // listener pins ride the same file.
    private static readonly Dictionary<string, ImplantSourceLock?> ParsedLocks = new();

    private static readonly HttpClient Http = new();

    /// <summary>
    /// The https package's source root -- the official-package e2e legs'
    /// resolution. The full path: environment, co-located layouts, pin
    /// fetch; null when nothing resolves (the callers' skip paths).
    /// </summary>
    public static string? LocateHttpsPackage()
        => LocatePackage(Https, HttpsTreeVariable);

    /// <summary>The doh package's root, the twin of <see cref="LocateHttpsPackage"/>.</summary>
    public static string? LocateDohPackage()
        => LocatePackage(Doh, DohTreeVariable);

    /// <summary>
    /// The named package's pin -- its repository, version, and sha256 -- or
    /// null when the lock carries none.
    /// </summary>
    public static (string Repository, string Version, string Sha256)? PinFor(string name)
    {
        var pin = PinnedImplantSource.PinForListener(name);
        return pin is null ? null : (pin.Repository, pin.Version, pin.Sha256);
    }

    private static string? LocatePackage(string name, string treeVariable)
    {
        var fromEnvironment = EnvironmentTree(name, treeVariable);
        if (fromEnvironment is not null)
            return fromEnvironment;
        var coLocated = WalkUpCoLocatedPackage(name);
        if (coLocated is not null)
            return coLocated;
        return ResolvePinned(name);
    }

    // The pin leg alone: no environment, no walk-up -- the fetch-verify-
    // unpack path the full resolution falls through to. Internal for the
    // tests that drive it against a file:// base without a co-located
    // checkout on the host short-circuiting the walk-up.
    internal static string? ResolvePinned(string name)
    {
        var root = PinnedRoot(name);
        if (root is null)
            return null;
        EnsurePinned(root, name);
        return root;
    }

    // A set tree variable must point at an existing package root -- the
    // same loud-on-misconfiguration posture every source directory holds.
    private static string? EnvironmentTree(string name, string treeVariable)
    {
        var value = Environment.GetEnvironmentVariable(treeVariable);
        if (string.IsNullOrWhiteSpace(value))
            return null;
        if (!Directory.Exists(value) || !File.Exists(Path.Combine(value, ManifestName)))
            throw new InvalidOperationException(
                $"{treeVariable} points at '{value}', which is not the rod-listener-{name} package root "
                + "(the directory carrying rod-module.toml), or does not exist -- point it at a checkout "
                + "of the package, or unset it to fall back to the pinned release.");
        return value;
    }

    // The co-located layouts, walked up from the running assembly: a
    // deployment's src/listener/<name>, a flat sibling checkout, and the
    // rod-ecosystem collection layout the organization's checkouts keep.
    internal static string? WalkUpCoLocatedPackage(string name)
    {
        var packageDirectory = $"rod-listener-{name}";
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var candidate in new[]
                     {
                         Path.Combine(dir.FullName, "src", "listener", packageDirectory),
                         Path.Combine(dir.Parent?.FullName ?? "", packageDirectory),
                         Path.Combine(dir.Parent?.FullName ?? "", "rod-ecosystem", packageDirectory),
                     })
            {
                if (File.Exists(Path.Combine(candidate, ManifestName)))
                    return candidate;
            }
            dir = dir.Parent!;
        }
        return null;
    }

    private static void EnsurePinned(string root, string name)
    {
        if (File.Exists(Path.Combine(root, ManifestName)))
            return;
        var pin = PinnedImplantSource.PinForListener(name)
            ?? throw new InvalidOperationException(
                $"{PinnedImplantSource.LockFileName} pins no '{name}' listener package -- add the pin, or point "
                + "the package's tree variable at a local checkout.");
        var asset = Path.Combine(CacheRoot(), $".rod-listener-{name}-{pin.Version}.tar.gz");
        DownloadAsset(name, pin, asset);

        // Extract into a staging directory and move into place, so a half
        // unpacked tree never masquerades as a warm cache; a losing racer
        // deletes its staging and uses the winner's tree.
        var staging = root + ".staging-" + Guid.NewGuid().ToString("N");
        try
        {
            Directory.CreateDirectory(staging);
            using var compressed = File.OpenRead(asset);
            using var gzip = new GZipStream(compressed, CompressionMode.Decompress);
            TarFile.ExtractToDirectory(gzip, staging, overwriteFiles: false);
            Directory.CreateDirectory(Path.GetDirectoryName(root)!);
            try
            {
                Directory.Move(staging, root);
            }
            catch (IOException) when (File.Exists(Path.Combine(root, ManifestName)))
            {
            }
            catch (UnauthorizedAccessException) when (File.Exists(Path.Combine(root, ManifestName)))
            {
            }
        }
        finally
        {
            try
            {
                if (Directory.Exists(staging))
                    Directory.Delete(staging, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
            try
            {
                File.Delete(asset);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static void DownloadAsset(string name, ImplantSourcePin pin, string destination)
    {
        var assetName = $"rod-listener-{name}-src-{pin.Version}.tar.gz";
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var errors = new List<string>();
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                Fetch(AssetUrl(pin, assetName), destination);
                VerifySha256(destination, pin, assetName);
                return;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                errors.Add($"attempt {attempt}: {ex.Message}");
                if (attempt < 3)
                    Thread.Sleep(TimeSpan.FromSeconds(attempt * attempt));
            }
        }
        throw new InvalidOperationException(
            $"Could not fetch the pinned '{name}' listener source '{assetName}' ({pin.Repository} at {pin.Version}) "
            + $"after 3 attempts: {string.Join("; ", errors)}. Point {AssetBaseVariable} at a mirror, or the "
            + "package's tree variable at a local checkout, and retry.");
    }

    private static string AssetUrl(ImplantSourcePin pin, string name)
    {
        var configured = Environment.GetEnvironmentVariable(AssetBaseVariable);
        var baseUrl = string.IsNullOrWhiteSpace(configured)
            ? $"{pin.Repository}/releases/download/{pin.Version}"
            : configured.TrimEnd('/');
        return $"{baseUrl}/{name}";
    }

    private static void Fetch(string url, string destination)
    {
        // file:// bases serve offline verification and mirrors; everything
        // else goes through the shared client.
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.IsFile)
        {
            File.Copy(uri.LocalPath, destination, overwrite: true);
            return;
        }
        using var source = Http.GetStreamAsync(url).GetAwaiter().GetResult();
        using var target = File.Create(destination);
        source.CopyTo(target);
    }

    private static void VerifySha256(string path, ImplantSourcePin pin, string assetName)
    {
        string actual;
        using (var stream = File.OpenRead(path))
            actual = Convert.ToHexString(SHA256.HashData(stream));
        var expected = pin.Sha256.Trim();
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"The downloaded listener source asset '{assetName}' hashes to {actual}, but the lock pins "
                + $"{expected} -- the asset and {PinnedImplantSource.LockFileName} disagree.");
    }

    internal static string? PinnedRoot(string name)
    {
        var pin = PinnedImplantSource.PinForListener(name);
        return pin is null ? null : Path.Combine(CacheRoot(), name, pin.Version);
    }

    private static string CacheRoot()
    {
        var configured = Environment.GetEnvironmentVariable(CacheRootVariable);
        if (!string.IsNullOrWhiteSpace(configured))
            return configured;
        if (OperatingSystem.IsWindows())
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "rod",
                "listeners");
        var xdg = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
        var cacheHome = string.IsNullOrWhiteSpace(xdg)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache")
            : xdg;
        return Path.Combine(cacheHome, "rod", "listeners");
    }
}
