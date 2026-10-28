using System.Diagnostics;
using Rod.Packaging;

namespace Rod.Cli.Registry;

/// <summary>
/// Where a registry reference resolves to: a local directory (a checkout
/// of rod-registry -- what a publisher pushes to and what tests drive) or
/// a git URL, cloned shallow into a cache under <c>ROD_HOME</c> (default
/// <c>~/.rod</c>) and refreshed on each command. The static git index
/// needs no server precisely because the client can treat "update the
/// catalog" as "git fetch" (architecture.md Sec 15.2). Writes only ever
/// target a local directory: publishing against a remote means publishing
/// into your checkout and sending the pull request -- the governance step
/// the git shape gets for free.
/// </summary>
public sealed class RegistryStore
{
    public const string ModulesFolder = "modules";
    public const string RegistryReadme = """
        # rod-registry

        The module index (architecture.md Sec 15.2): one JSON file per
        module under `modules/`, contributed by pull request, no server.
        Add or update an entry with `rod mod publish --registry .` from a
        module checkout, then commit and open the pull request. Entries
        carry the publisher's Ed25519 public key and signature; operators
        pin them in their lock file at first install.

        Governance: the canonical rod-registry lives under the GitHub
        organization (ADR-011) -- pull-request review in, merge rights
        held by the organization. Third-party taps are legitimate
        registries of their own; this one is the default.
        """;

    private RegistryStore(string root)
    {
        Root = root;
    }

    public string Root { get; }
    public bool IsLocal { get; private set; }

    // createIfLocal is publish's posture: a fresh local directory becomes a
    // new registry, scaffolded on first write. Search and install pass
    // false so a mistyped path is an error, not a silently empty catalog.
    public static RegistryStore Open(string reference, bool createIfLocal = false)
    {
        if (Directory.Exists(reference))
            return new RegistryStore(Path.GetFullPath(reference)) { IsLocal = true };

        var looksLikeUrl = reference.StartsWith("git@", StringComparison.Ordinal)
            || reference.EndsWith(".git", StringComparison.OrdinalIgnoreCase)
            || reference.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || reference.StartsWith("file://", StringComparison.OrdinalIgnoreCase);
        if (!looksLikeUrl && createIfLocal)
        {
            Directory.CreateDirectory(reference);
            return new RegistryStore(Path.GetFullPath(reference)) { IsLocal = true };
        }

        if (!looksLikeUrl)
            throw new DirectoryNotFoundException(
                $"'{reference}' is neither an existing registry directory nor a git URL.");

        return new RegistryStore(CloneOrUpdate(reference)) { IsLocal = false };
    }

    public IReadOnlyList<RegistryEntry> LoadAll()
    {
        var entries = new List<RegistryEntry>();
        var folder = Path.Combine(Root, ModulesFolder);
        if (!Directory.Exists(folder))
            return entries;

        foreach (var file in Directory.GetFiles(folder, "*.json").OrderBy(p => p, StringComparer.Ordinal))
        {
            // The all-entries roll-up (registry.json) is a name list, not an
            // entry; skip it by name.
            if (Path.GetFileName(file).Equals("registry.json", StringComparison.OrdinalIgnoreCase))
                continue;
            var entry = RegistryJson.LoadEntry(file);
            if (entry is null)
                continue;
            entries.Add(entry);
        }
        return entries;
    }

    public RegistryEntry? Find(string name)
        => LoadAll().FirstOrDefault(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Upserts a version into the module's entry file, creating
    /// the file and the registry scaffold when the registry is fresh.
    /// Publishing the same version with the same digest is idempotent; the
    /// same version with a different digest is an error that names the fix
    /// (bump the version) -- an index where one version number means two
    /// different packages is not an index.</summary>
    public RegistryEntry UpsertVersion(
        string name,
        RegistryEntry template,
        RegistryVersion version,
        TextWriter output)
    {
        if (!IsLocal)
            throw new InvalidOperationException(
                "publishing targets a local registry checkout; clone it and pass the directory.");

        var folder = Path.Combine(Root, ModulesFolder);
        Directory.CreateDirectory(folder);
        var readmePath = Path.Combine(Root, "README.md");
        if (!File.Exists(readmePath))
            File.WriteAllText(readmePath, RegistryReadme + "\n");

        var entryPath = Path.Combine(folder, name + ".json");
        RegistryEntry entry;
        if (File.Exists(entryPath))
        {
            entry = RegistryJson.LoadEntry(entryPath)
                ?? throw new IOException($"'{entryPath}' is not a readable registry entry.");
            var existing = entry.Versions.FirstOrDefault(v => v.Version == version.Version);
            if (existing is not null)
            {
                if (!string.Equals(existing.Sha256, version.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException(
                        $"version {version.Version} of '{name}' is already indexed with a different package; " +
                        "bump module.version before publishing again.");
                output.WriteLine($"registry: {name}@{version.Version} already indexed with this digest; entry unchanged.");
                return entry;
            }
            entry = entry with { Versions = entry.Versions.Append(version).ToList() };
        }
        else
        {
            entry = template with { Name = name, Versions = [version] };
        }

        File.WriteAllText(entryPath, RegistryJson.SaveEntry(entry));
        WriteRollUp();
        return entry;
    }

    // The all-entries roll-up the server-side browser reads over https
    // (ADR-023): one registry.json beside the per-module files, a sorted
    // name list -- small on purpose, the entries stay authoritative in
    // their own files.
    private void WriteRollUp()
    {
        var names = Directory.GetFiles(Path.Combine(Root, ModulesFolder), "*.json")
            .Where(f => !Path.GetFileName(f).Equals("registry.json", StringComparison.OrdinalIgnoreCase))
            .Select(f => RegistryJson.LoadEntry(f)?.Name)
            .Where(n => !string.IsNullOrEmpty(n))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();
        var rollUp = Path.Combine(Root, ModulesFolder, "registry.json");
        File.WriteAllText(rollUp, System.Text.Json.JsonSerializer.Serialize(names, RegistryJson.Options) + "\n");
    }

    private static string CloneOrUpdate(string url)
    {
        var home = Environment.GetEnvironmentVariable("ROD_HOME");
        if (string.IsNullOrWhiteSpace(home))
        {
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            home = Path.Combine(string.IsNullOrEmpty(profile) ? Path.GetTempPath() : profile, ".rod");
        }

        var cache = Path.Combine(home, "registry-cache");
        Directory.CreateDirectory(cache);
        var digest = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(url));
        var key = Convert.ToHexStringLower(digest)[..12];
        var destination = Path.Combine(cache, key);

        if (Directory.Exists(destination) && Directory.EnumerateFileSystemEntries(destination).Any())
        {
            RunGit($"-C \"{destination}\" fetch --depth 1", quiet: true);
            RunGit($"-C \"{destination}\" reset --hard FETCH_HEAD", quiet: true);
        }
        else
        {
            if (Directory.Exists(destination))
                Directory.Delete(destination, recursive: false);
            RunGit($"clone --depth 1 \"{url}\" \"{destination}\"");
        }
        return destination;
    }

    private static void RunGit(string arguments, bool quiet = false)
    {
        var info = new ProcessStartInfo("git", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = quiet,
            CreateNoWindow = true,
        };
        using var process = Process.Start(info)
            ?? throw new InvalidOperationException("git is not available; the static index needs it.");
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            var error = quiet ? "" : process.StandardError.ReadToEnd();
            throw new InvalidOperationException($"git {arguments.Split(' ')[0]} failed ({process.ExitCode}). {error.Trim()}");
        }
    }
}
