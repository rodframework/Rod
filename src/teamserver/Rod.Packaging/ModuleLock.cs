using System.Text.Json;
using System.Text.Json.Serialization;

namespace Rod.Packaging;

/// <summary>
/// The install root's lock file (<c>rod.modules.lock.json</c>): the record
/// of what <c>rod mod install</c> landed and the pinned trust that let it
/// land -- per module, the version, the package digest, the publisher's
/// public key and fingerprint, and the signature, plus the registry the
/// module came from. First install of a name pins its key (trust on first
/// use, the fingerprint printed at install and search for out-of-band
/// comparison); any later version arriving under a different key fails the
/// install loudly instead of quietly re-trusting. <c>rod mod verify</c>
/// re-proves every installed tree against this record with no network.
/// </summary>
public sealed record ModuleLock
{
    public const string FileName = "rod.modules.lock.json";

    public string? Registry { get; init; }
    public IReadOnlyList<TrustedKey> TrustedKeys { get; init; } = [];
    public IReadOnlyList<LockedModule> Modules { get; init; } = [];

    public sealed record TrustedKey(string Name, string Fingerprint, string PublicKey);

    public sealed record LockedModule
    {
        public required string Name { get; init; }
        public required string Version { get; init; }
        public required string Entry { get; init; }
        /// <summary>Path of the installed package tree, relative to the
        /// install root, '/'-separated.</summary>
        public required string Path { get; init; }
        public required string Url { get; init; }
        public required string Sha256 { get; init; }
        public required string Signature { get; init; }
        public required string PublicKey { get; init; }
        public required string Fingerprint { get; init; }
        public required string Installed { get; init; }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true,
    };

    public static ModuleLock Load(string path)
    {
        if (!File.Exists(path))
            return new ModuleLock();
        var lockFile = JsonSerializer.Deserialize<ModuleLock>(File.ReadAllText(path), JsonOptions);
        return lockFile ?? new ModuleLock();
    }

    public string Save()
    {
        var normalized = this with
        {
            TrustedKeys = TrustedKeys.OrderBy(k => k.Name, StringComparer.Ordinal).ToList(),
            Modules = Modules.OrderBy(m => m.Name, StringComparer.Ordinal).ToList(),
        };
        return JsonSerializer.Serialize(normalized, JsonOptions) + "\n";
    }

    public static void Save(string path, ModuleLock lockFile)
        => File.WriteAllText(path, lockFile.Save());

    public TrustedKey? TrustedKeyFor(string name)
        => TrustedKeys.FirstOrDefault(k => string.Equals(k.Name, name, StringComparison.OrdinalIgnoreCase));

    public LockedModule? Module(string name)
        => Modules.FirstOrDefault(m => string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase));
}

/// <summary>An installation root: the directory holding the lock file and
/// the <c>modules/</c> tree installed packages land under
/// (<c>modules/&lt;name&gt;/&lt;version&gt;/</c>).</summary>
public static class InstallRoot
{
    public const string ModulesFolder = "modules";

    public static string LockPath(string root) => Path.Combine(root, ModuleLock.FileName);

    public static string ModulePath(string root, string name, string version)
        => Path.Combine(root, ModulesFolder, name, version);
}
