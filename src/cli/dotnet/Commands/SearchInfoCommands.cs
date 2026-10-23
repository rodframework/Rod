using Rod.Cli.Registry;

namespace Rod.Cli.Commands;

/// <summary>
/// <c>rod mod search</c>: the catalog's decision surface (the benchmark
/// note's adopt list) -- name, entry kind, latest version, and the OPSEC
/// marks beside every result, so an operator screens what a module does to
/// the target before fetching anything.
/// </summary>
public static class SearchCommand
{
    public static int Run(string[] args, TextWriter output)
    {
        var parsed = ParsedArgs.Parse(args,
            valueOptions: new HashSet<string> { "registry" },
            flags: new HashSet<string> { "json" },
            verb: "search");

        var registry = RegistrySource.Resolve(parsed, Environment.CurrentDirectory);
        var entries = RegistryStore.Open(registry).LoadAll()
            .OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (parsed.Positional.Count > 1)
            throw new CliError("rod mod search takes at most one search term.");

        if (parsed.Positional.Count == 1)
        {
            var term = parsed.Positional[0];
            entries = entries.Where(e => Matches(e, term)).ToList();
        }

        if (entries.Count == 0)
        {
            output.WriteLine(parsed.Positional.Count == 1
                ? $"no module matches '{parsed.Positional[0]}'."
                : "the registry is empty.");
            return RodCli.ExitOk;
        }

        if (parsed.Has("json"))
        {
            output.WriteLine(System.Text.Json.JsonSerializer.Serialize(entries, RegistryJson.Options));
            return RodCli.ExitOk;
        }

        foreach (var entry in entries)
        {
            var latest = entry.Versions.FirstOrDefault();
            var opsec = entry.Opsec.LandsOnDisk ? "disk" : "mem-only";
            var description = (entry.Description ?? "").Trim();
            output.WriteLine($"{entry.Name,-24} {entry.Entry,-10} {latest?.Version ?? "-",10} {opsec,-9} {description}");
            if (entry.Attack.Count > 0)
                output.WriteLine($"{"",-24} {"",-10} {"",-10} {"",-9} {string.Join(" ", entry.Attack)}");
        }
        return RodCli.ExitOk;
    }

    internal static bool Matches(RegistryEntry entry, string term)
    {
        var fields = new List<string> { entry.Name }
            .Concat(new[] { entry.Description ?? "", entry.License })
            .Concat(entry.Attack)
            .Concat(entry.Versions.SelectMany(v => v.Verbs ?? []).Select(v => v.Name));
        return fields.Any(field => field.Contains(term, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// <c>rod mod info</c>: one module's full registry record -- catalog
/// metadata, compatibility, every indexed version with its digest and key
/// fingerprint. The fingerprint is the out-of-band comparison point for a
/// trust decision the lock file then pins.
/// </summary>
public static class InfoCommand
{
    public static int Run(string[] args, TextWriter output)
    {
        var parsed = ParsedArgs.Parse(args,
            valueOptions: new HashSet<string> { "registry" },
            flags: new HashSet<string>(),
            verb: "info");

        if (parsed.Positional.Count != 1)
            throw new CliError("rod mod info needs <name>[@version].");

        var registry = RegistrySource.Resolve(parsed, Environment.CurrentDirectory);
        var store = RegistryStore.Open(registry);
        var (name, wanted) = ModuleRef.Parse(parsed.Positional[0]);

        var entry = store.Find(name)
            ?? throw new CliError($"'{name}' is not in the registry.");

        var versions = entry.Versions
            .OrderByDescending(v => SemVer.TryParse(v.Version, out var parsedVersion) ? parsedVersion : new SemVer(0, 0, 0, null))
            .ToList();
        if (versions.Count == 0)
            throw new CliError($"'{name}' has no indexed versions.");

        var version = wanted is null
            ? versions[0]
            : versions.FirstOrDefault(v => v.Version == wanted)
              ?? throw new CliError($"'{name}' has no version {wanted}; indexed: {string.Join(", ", versions.Select(v => v.Version))}.");

        output.WriteLine($"{entry.Name} ({version.Version}) -- entry kind {entry.Entry}, license {entry.License}");
        if (!string.IsNullOrEmpty(entry.Description))
            output.WriteLine($"  {entry.Description}");
        if (!string.IsNullOrEmpty(entry.Homepage))
            output.WriteLine($"  homepage: {entry.Homepage}");
        output.WriteLine($"  opsec: {(entry.Opsec.LandsOnDisk ? "lands on disk" : "memory only")}");
        if (!string.IsNullOrEmpty(entry.Opsec.Notes))
            output.WriteLine($"    {entry.Opsec.Notes}");
        if (entry.Attack.Count > 0)
            output.WriteLine($"  ATT&CK: {string.Join(" ", entry.Attack)}");
        output.WriteLine($"  min teamserver: {version.Compatibility.Teamserver}");
        foreach (var target in version.Compatibility.Targets)
            output.WriteLine($"    {target.ImplantClass}/{target.Platform}/{target.Arch}");
        if ((version.Verbs?.Count ?? 0) > 0)
        {
            output.WriteLine("  verbs:");
            foreach (var verb in version.Verbs!)
                output.WriteLine(verb.Teamserver is null
                    ? $"    {verb.Name}@{verb.Version}"
                    : $"    {verb.Name}@{verb.Version} (teamserver >= {verb.Teamserver})");
        }
        if ((version.Assets?.Count ?? 0) > 0)
            output.WriteLine($"  assets: {string.Join(", ", version.Assets!)}");
        output.WriteLine($"  signed by: {version.Fingerprint}");
        output.WriteLine($"  package:   {version.Url}");
        output.WriteLine($"  sha256:    {version.Sha256}");
        if (versions.Count > 1)
            output.WriteLine($"  other versions: {string.Join(", ", versions.Where(v => v.Version != version.Version).Select(v => v.Version))}");
        return RodCli.ExitOk;
    }
}

/// <summary>Shared registry-reference resolution: the flag wins, then the
/// lock file's remembered registry, then a usage error telling the
/// operator which of the two to provide.</summary>
internal static class RegistrySource
{
    public static string Resolve(ParsedArgs parsed, string installRoot)
    {
        var flagged = parsed.Value("registry");
        if (!string.IsNullOrWhiteSpace(flagged))
            return flagged;

        var lockFile = ModuleLock.Load(InstallRoot.LockPath(installRoot));
        if (!string.IsNullOrWhiteSpace(lockFile.Registry))
            return lockFile.Registry!;

        throw new CliError("no registry: pass --registry or install once to remember it in the lock file.");
    }
}

/// <summary>A <c>name</c> or <c>name@version</c> reference.</summary>
internal readonly record struct ModuleRef(string Name, string? Version)
{
    public static ModuleRef Parse(string text)
    {
        var at = text.LastIndexOf('@');
        return at <= 0
            ? new ModuleRef(text, null)
            : new ModuleRef(text[..at], text[(at + 1)..]);
    }
}
