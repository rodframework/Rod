using System.Text.Json;
using Rod.Cli.Manifest;

namespace Rod.Cli.Commands;

/// <summary>
/// One technique row of the generated coverage matrix: the id, the catalog's
/// display metadata when it has any (a module may declare a technique the
/// kernel's catalog carries no metadata for -- the id is the identity), and
/// the carriers on both sides of the ecosystem.
/// </summary>
internal sealed record CoverageTechnique(
    string Id,
    string? Name,
    IReadOnlyList<string> Tactics,
    IReadOnlyList<string> KernelVerbs,
    IReadOnlyList<CoverageCarrier> Modules);

/// <summary>A module's verb row as the matrix carries it.</summary>
internal sealed record CoverageCarrier(string Module, string Verb, string Version);

/// <summary>
/// <c>rod mod coverage</c>: the repository-side face of ADR-007's advancement
/// mechanism. Sweeps a tree for module manifests, validates every one, and
/// renders the ATT&CK coverage matrix their declarations (plus, with
/// <c>--catalog</c>, the kernel's own verb mapping) produce -- the artifact a
/// module pull request's coverage claim is checked against and the section the
/// release notes carry, generated from the declarations instead of
/// hand-written.
/// </summary>
/// <remarks>
/// The catalog is a file contract, the same <c>attack-coverage.json</c> the
/// teamserver embeds: nothing here references the teamserver, and the CLI's
/// no-in-house-references rule holds. Without <c>--catalog</c> the matrix
/// renders the swept modules alone -- the shape an ecosystem sweep over
/// out-of-tree sources takes.
/// </remarks>
internal static class CoverageCommand
{
    public static int Run(string[] args, TextWriter output)
    {
        var parsed = ParsedArgs.Parse(args,
            valueOptions: new HashSet<string> { "path", "catalog" },
            flags: new HashSet<string> { "json" },
            verb: "coverage");

        var root = Path.GetFullPath(parsed.Value("path") ?? Environment.CurrentDirectory);
        if (!Directory.Exists(root))
            throw new CliError($"--path '{root}' is not a directory.");

        var manifests = Sweep(root);
        if (manifests.Count == 0)
            throw new CliError($"no {ManifestToml.FileName} under '{root}'.");

        var catalog = parsed.Value("catalog") is { } catalogPath
            ? AttackCatalog.Load(catalogPath)
            : null;

        var techniques = Join(manifests, catalog);
        if (parsed.Has("json"))
        {
            output.WriteLine(JsonSerializer.Serialize(new
            {
                attackVersion = catalog?.AttackVersion,
                modules = manifests
                    .Select(m => new { name = m.Manifest.Name, version = m.Manifest.Version.ToString() })
                    .OrderBy(m => m.name, StringComparer.Ordinal)
                    .ToList(),
                techniques,
            }, JsonOptions));
            return RodCli.ExitOk;
        }

        output.WriteLine("# ATT&CK coverage");
        output.WriteLine();
        output.WriteLine(catalog is null
            ? $"{manifests.Count} modules swept; no catalog -- the kernel's own verb mapping is not folded in."
            : $"ATT&CK version {catalog.AttackVersion} per the catalog; {manifests.Count} modules swept.");
        output.WriteLine();
        output.WriteLine("| Technique | Name | Tactics | Kernel verbs | Modules |");
        output.WriteLine("|---|---|---|---|---|");
        foreach (var technique in techniques)
        {
            var kernelVerbs = string.Join(", ", technique.KernelVerbs);
            var modules = string.Join(", ", technique.Modules.Select(c => $"{c.Module} ({c.Verb})"));
            output.WriteLine(
                $"| {technique.Id} | {technique.Name ?? ""} | {string.Join(", ", technique.Tactics)} | {kernelVerbs} | {modules} |");
        }
        return RodCli.ExitOk;
    }

    /// <summary>Finds every manifest under the root, never descending into the
    /// directories builds and packages produce (a module tree carries several)
    /// or hidden directories, and validates each one -- an invalid manifest
    /// fails the sweep, because a coverage matrix over unvalidated
    /// declarations is a guess, not a report.</summary>
    private static List<(string Path, ModuleManifest Manifest)> Sweep(string root)
    {
        var skipped = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "bin", "obj", "dist", "target", "node_modules" };

        var found = new List<(string Path, ModuleManifest Manifest)>();
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
            {
                if (File.Exists(entry))
                {
                    if (!string.Equals(Path.GetFileName(entry), ManifestToml.FileName, StringComparison.OrdinalIgnoreCase))
                        continue;
                    var (manifest, errors) = ManifestToml.LoadFile(entry);
                    if (manifest is null || errors.Count > 0)
                        throw new CliError(
                            $"{Path.GetRelativePath(root, entry)} is invalid:\n  {string.Join("\n  ", errors)}");
                    found.Add((entry, manifest));
                    continue;
                }

                var name = Path.GetFileName(entry);
                if (name.StartsWith('.') || skipped.Contains(name))
                    continue;
                pending.Push(entry);
            }
        }

        return found
            .OrderBy(m => m.Manifest.Name, StringComparer.Ordinal)
            .ThenBy(m => m.Manifest.Version.ToString(), StringComparer.Ordinal)
            .ToList();
    }

    private sealed class Row
    {
        public string? Name;
        public readonly List<string> Tactics = [];
        public readonly List<string> KernelVerbs = [];
        public readonly List<CoverageCarrier> Modules = [];
    }

    /// <summary>Joins the module declarations and (when present) the kernel
    /// mapping into one technique-indexed table.</summary>
    private static IReadOnlyList<CoverageTechnique> Join(
        IReadOnlyList<(string Path, ModuleManifest Manifest)> manifests,
        AttackCatalog? catalog)
    {
        var rows = new SortedDictionary<string, Row>(StringComparer.Ordinal);

        Row RowFor(string id) => rows.TryGetValue(id, out var row) ? row : rows[id] = new Row();

        if (catalog is not null)
        {
            foreach (var (verb, ids) in catalog.Verbs)
            {
                foreach (var id in ids)
                {
                    var row = RowFor(id);
                    row.KernelVerbs.Add(verb);
                    if (catalog.Techniques.TryGetValue(id, out var technique))
                    {
                        row.Name ??= technique.Name;
                        row.Tactics.AddRange(technique.Tactics);
                    }
                }
            }
        }

        foreach (var (_, manifest) in manifests)
        {
            foreach (var verb in manifest.Verbs)
            {
                foreach (var id in verb.Techniques ?? [])
                    RowFor(id).Modules.Add(new CoverageCarrier(manifest.Name, verb.Name, verb.Version.ToString()));
            }
        }

        return rows
            .Select(pair => new CoverageTechnique(
                pair.Key,
                pair.Value.Name,
                [.. pair.Value.Tactics.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(t => t, StringComparer.Ordinal)],
                [.. pair.Value.KernelVerbs.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(v => v, StringComparer.Ordinal)],
                [.. pair.Value.Modules.OrderBy(c => c.Module, StringComparer.Ordinal).ThenBy(c => c.Verb, StringComparer.Ordinal)]))
            .ToList();
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>The kernel's <c>attack-coverage.json</c> as a file contract:
    /// the attack version stamp, the verb-to-technique mapping, and the
    /// display metadata for the techniques that mapping references.</summary>
    private sealed record AttackCatalog(
        string AttackVersion,
        IReadOnlyDictionary<string, IReadOnlyList<string>> Verbs,
        IReadOnlyDictionary<string, (string Name, IReadOnlyList<string> Tactics)> Techniques)
    {
        private sealed record CatalogFile(
            string? AttackVersion,
            Dictionary<string, string[]>? Verbs,
            Dictionary<string, TechniqueFile>? Techniques);

        private sealed record TechniqueFile(string? Name, string[]? Tactics);

        public static AttackCatalog Load(string path)
        {
            if (!File.Exists(path))
                throw new CliError($"--catalog '{path}' does not exist.");
            var file = JsonSerializer.Deserialize<CatalogFile>(
                    File.ReadAllText(path),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip })
                ?? throw new CliError($"--catalog '{path}' is empty.");
            if (string.IsNullOrWhiteSpace(file.AttackVersion))
                throw new CliError($"--catalog '{path}' has no attackVersion.");

            var techniques = new Dictionary<string, (string Name, IReadOnlyList<string> Tactics)>(StringComparer.OrdinalIgnoreCase);
            foreach (var (id, technique) in file.Techniques ?? [])
            {
                if (technique?.Name is not { Length: > 0 })
                    throw new CliError($"--catalog '{path}': technique '{id}' has no name.");
                techniques[id] = (technique.Name, technique.Tactics ?? []);
            }

            var verbs = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var (verb, ids) in file.Verbs ?? [])
                verbs[verb] = ids;

            return new AttackCatalog(file.AttackVersion, verbs, techniques);
        }
    }
}
