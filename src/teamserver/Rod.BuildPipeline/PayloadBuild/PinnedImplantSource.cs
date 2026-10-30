using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// One implant language's pin: the release repository, the version tag, and
/// the source asset's sha256 -- the whole coupling contract the platform
/// builds against (architecture.md Sec 15.4).
/// </summary>
internal sealed record ImplantSourcePin(string Repository, string Version, string Sha256);

/// <summary>
/// The parsed shape of rod-implants.lock.json, camelCase like the module
/// lock's conventions.
/// </summary>
internal sealed class ImplantSourceLock
{
    public ImplantSourcePin? Rust { get; init; }

    public ImplantSourcePin? Go { get; init; }
}

/// <summary>
/// Resolves the out-of-tree implant source trees through the pinned-source
/// contract (architecture.md Sec 15.4): an explicit environment checkout
/// first (<see cref="RustTreeVariable"/> / <see cref="GoTreeVariable"/>),
/// then the co-located layout a deployment extracts
/// (src/implant/&lt;lang&gt; beside src/teamserver -- the walk-up the build units
/// have always held), then the pinned release the source lock names --
/// downloaded once, verified by its sha256, and unpacked into a cache
/// (<see cref="CacheRootVariable"/>) every consumer shares.
/// </summary>
/// <remarks>
/// The lock is a checkout's fact, never a deployment's: it is read by
/// walking up from the running assembly, and a published teamserver carries
/// no lock -- an installed host resolves through its configured source
/// directories and never reaches for the network. A cold cache pays its
/// fetch at first use, with retries; <see cref="AssetBaseVariable"/>
/// redirects the fetch at a mirror or a file:// path, and the tree
/// variables point at a local checkout for the offline shape.
/// </remarks>
public static class PinnedImplantSource
{
    public const string LockFileName = "rod-implants.lock.json";
    public const string RustTreeVariable = "ROD_IMPLANT_RUST_DIR";
    public const string GoTreeVariable = "ROD_IMPLANT_GO_DIR";
    public const string CacheRootVariable = "ROD_IMPLANT_CACHE";
    public const string AssetBaseVariable = "ROD_IMPLANT_ASSET_BASE";
    public const string LockFileVariable = "ROD_IMPLANT_LOCK";

    internal const string Rust = "rust";
    internal const string Go = "go";

    private static readonly JsonSerializerOptions LockJson = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    // Parsed locks keyed by path, so a redirected lock (ROD_IMPLANT_LOCK)
    // re-reads rather than serving the cached one.
    private static readonly Dictionary<string, ImplantSourceLock?> ParsedLocks = new();

    private static readonly HttpClient Http = new();

    /// <summary>
    /// The Rust tree for consumers that need it now -- the conformance
    /// candidates, the integration legs. The full resolution, pin fetch
    /// included; null when nothing resolves (the callers' skip paths).
    /// </summary>
    public static string? LocateRustTree()
        => LocateTree(Rust, RustTreeVariable, needsProtoSibling: true);

    /// <summary>The Go tree, the twin of <see cref="LocateRustTree"/>.</summary>
    public static string? LocateGoTree()
        => LocateTree(Go, GoTreeVariable, needsProtoSibling: false);

    /// <summary>
    /// Ensures the pin cache holds the named release (fetching and verifying
    /// it when cold) and returns its tree path. Null when no lock pins the
    /// language. The build units call this lazily -- at first build, never
    /// at construction -- through <c>EnsurePinnedTreeFor</c>.
    /// </summary>
    public static string? EnsurePinnedTree(string language)
    {
        var root = PinnedRoot(language);
        if (root is null)
            return null;
        EnsurePinned(root, language);
        if (language == Rust)
            EnsureProtoSibling(root);
        return Path.Combine(root, "src", "implant", language);
    }

    // The build units' hook: fetch only when the unit's resolved source dir
    // IS the pin cache path and the cache is cold. Any other directory is a
    // plain misconfiguration -- the unit's own missing-tree failure stands.
    internal static void EnsurePinnedTreeFor(string language, string sourceDir)
    {
        var root = PinnedRoot(language);
        if (root is null)
            return;
        if (!SamePath(sourceDir, Path.Combine(root, "src", "implant", language)))
            return;
        EnsurePinned(root, language);
    }

    // The no-network resolution the build units' constructors use: the
    // environment checkout, the co-located layout, then the pin cache's
    // path -- computed, never fetched. A unit constructed over a cold cache
    // must still construct (a teamserver that never builds a payload never
    // needed the tree); its first build pays the fetch. A host with neither
    // lock nor tree falls back to the relative path the walk-up always
    // ended on, so the failure names the same shape it always did.
    internal static string ResolveSourceDir(string language, string treeVariable)
    {
        var fromEnvironment = EnvironmentTree(treeVariable);
        if (fromEnvironment is not null)
            return fromEnvironment;
        var coLocated = WalkUpCoLocatedTree(language);
        if (coLocated is not null)
            return coLocated;
        var root = PinnedRoot(language);
        if (root is not null)
            return Path.Combine(root, "src", "implant", language);
        return Path.Combine("..", "..", "..", "..", "..", "src", "implant", language);
    }

    private static string? LocateTree(string language, string treeVariable, bool needsProtoSibling)
    {
        var fromEnvironment = EnvironmentTree(treeVariable);
        if (fromEnvironment is not null)
            return fromEnvironment;
        var coLocated = WalkUpCoLocatedTree(language);
        if (coLocated is not null)
            return coLocated;
        var root = PinnedRoot(language);
        if (root is null)
            return null;
        EnsurePinned(root, language);
        if (needsProtoSibling)
            EnsureProtoSibling(root);
        return Path.Combine(root, "src", "implant", language);
    }

    // A set tree variable must point at an existing tree -- the same
    // loud-on-misconfiguration posture the configured source directories
    // hold in transport host composition.
    private static string? EnvironmentTree(string treeVariable)
    {
        var value = Environment.GetEnvironmentVariable(treeVariable);
        if (string.IsNullOrWhiteSpace(value))
            return null;
        if (!Directory.Exists(value))
            throw new InvalidOperationException(
                $"{treeVariable} points at '{value}', which does not exist -- point it at the implant tree "
                + $"(the directory holding its Cargo.toml or go.mod), or unset it to fall back to the pinned release.");
        return value;
    }

    // The co-located layout walk-up the build units have always held: a
    // directory carrying both the implant tree and the teamserver -- an
    // extracted rod-src.tar.gz on a deployment, a full platform checkout
    // anywhere else.
    internal static string? WalkUpCoLocatedTree(string language)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "src", "implant", language);
            if (Directory.Exists(candidate) && Directory.Exists(Path.Combine(dir.FullName, "src", "teamserver")))
                return candidate;
            dir = dir.Parent!;
        }
        return null;
    }

    // The proto tree's location: the walk-up the Rust unit's staging and
    // environment report both use, factored here so the pin cache's proto
    // sibling copies from the same place the unit stages from.
    internal static string? LocateProtoDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var protoDir = Path.Combine(dir.FullName, "src", "teamserver", "Rod.Protocol", "protos");
            if (Directory.Exists(protoDir))
                return protoDir;
            dir = dir.Parent!;
        }
        return null;
    }

    private static void EnsurePinned(string root, string language)
    {
        if (Directory.Exists(Path.Combine(root, "src", "implant", language)))
            return;
        var pin = PinFor(language)
            ?? throw new InvalidOperationException(
                $"rod-implants.lock.json pins no {language} implant -- add the pin, or point the tree "
                + $"variable at a local checkout.");
        var asset = Path.Combine(CacheRoot(), $".rod-implant-{language}-{pin.Version}.tar.gz");
        DownloadAsset(language, pin, asset);

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
            catch (IOException) when (Directory.Exists(Path.Combine(root, "src", "implant", language)))
            {
                // Another process won the race; its tree serves this one.
            }
            catch (UnauthorizedAccessException) when (Directory.Exists(Path.Combine(root, "src", "implant", language)))
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

    private static void DownloadAsset(string language, ImplantSourcePin pin, string destination)
    {
        var name = $"rod-implant-{language}-src-{pin.Version}.tar.gz";
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var errors = new List<string>();
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                Fetch(AssetUrl(pin, name), destination);
                VerifySha256(destination, pin);
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
            $"Could not fetch the pinned {language} implant source '{name}' ({pin.Repository} at {pin.Version}) "
            + $"after 3 attempts: {string.Join("; ", errors)}. Point {AssetBaseVariable} at a mirror, "
            + $"or the tree variable at a local checkout, and retry.");
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

    private static void VerifySha256(string path, ImplantSourcePin pin)
    {
        string actual;
        using (var stream = File.OpenRead(path))
            actual = Convert.ToHexString(SHA256.HashData(stream));
        var expected = pin.Sha256.Trim();
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"The downloaded implant source asset '{Path.GetFileName(path)}' hashes to {actual}, "
                + $"but the lock pins {expected} -- the asset and {LockFileName} disagree.");
    }

    // Direct cargo runs against the pinned Rust tree (the conformance
    // candidate, the e2e legs, the linkable core) resolve the proto the
    // way build.rs does -- ../../teamserver beside the crate -- so the
    // cache's extraction carries a copy of the platform's protos beside
    // the tree. The build unit needs no sibling; it stages its own copy.
    private static void EnsureProtoSibling(string root)
    {
        var target = Path.Combine(root, "src", "teamserver", "Rod.Protocol", "protos");
        if (File.Exists(Path.Combine(target, "rod.proto")))
            return;
        var source = LocateProtoDir();
        if (source is null)
            return;
        Directory.CreateDirectory(target);
        foreach (var file in Directory.EnumerateFiles(source))
            File.Copy(file, Path.Combine(target, Path.GetFileName(file)), overwrite: true);
    }

    // The cache root an extraction lands under: <cache>/<language>/<version>.
    internal static string? PinnedRoot(string language)
    {
        var pin = PinFor(language);
        return pin is null ? null : Path.Combine(CacheRoot(), language, pin.Version);
    }

    internal static ImplantSourcePin? PinFor(string language)
    {
        var path = LockPath();
        if (path is null)
            return null;
        lock (ParsedLocks)
        {
            if (!ParsedLocks.TryGetValue(path, out var parsed))
            {
                try
                {
                    using var stream = File.OpenRead(path);
                    parsed = JsonSerializer.Deserialize<ImplantSourceLock>(stream, LockJson);
                }
                catch (JsonException ex)
                {
                    throw new InvalidOperationException(
                        $"{LockFileName} at '{path}' is not valid JSON: {ex.Message}", ex);
                }
                ParsedLocks[path] = parsed;
            }
            return language switch
            {
                Rust => parsed?.Rust,
                Go => parsed?.Go,
                _ => throw new ArgumentOutOfRangeException(nameof(language)),
            };
        }
    }

    private static string? LockPath()
    {
        var configured = Environment.GetEnvironmentVariable(LockFileVariable);
        if (!string.IsNullOrWhiteSpace(configured))
            return File.Exists(configured) ? configured : null;
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, LockFileName);
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent!;
        }
        return null;
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
                "implants");
        var xdg = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
        var cacheHome = string.IsNullOrWhiteSpace(xdg)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache")
            : xdg;
        return Path.Combine(cacheHome, "rod", "implants");
    }

    private static bool SamePath(string left, string right)
        => string.Equals(
            Path.GetFullPath(left),
            Path.GetFullPath(right),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
}
