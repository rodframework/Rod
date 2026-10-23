using System.Text.RegularExpressions;

namespace Rod.Cli.Manifest;

/// <summary>
/// The entry kind a module ships as (architecture.md Sec 15.2): a
/// server-side capability module, an implant-side handler module, a build
/// unit, or a pure asset module (script and template files the teamserver
/// serves, no code). The kind decides how an installed package is consumed,
/// not how it travels -- one manifest shape, one registry, one CLI.
/// </summary>
public enum ModuleEntryKind
{
    Server,
    Implant,
    BuildUnit,
    Assets,
}

public static class ModuleEntryKindNames
{
    public static bool TryParse(string text, out ModuleEntryKind kind)
    {
        switch (text)
        {
            case "server": kind = ModuleEntryKind.Server; return true;
            case "implant": kind = ModuleEntryKind.Implant; return true;
            case "build-unit": kind = ModuleEntryKind.BuildUnit; return true;
            case "assets": kind = ModuleEntryKind.Assets; return true;
            default: kind = default; return false;
        }
    }

    public static string ToString(ModuleEntryKind kind) => kind switch
    {
        ModuleEntryKind.Server => "server",
        ModuleEntryKind.Implant => "implant",
        ModuleEntryKind.BuildUnit => "build-unit",
        ModuleEntryKind.Assets => "assets",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };
}

/// <summary>A row of the manifest's compatibility matrix: which implant
/// class, on which platform and arch, the module's execution half serves.</summary>
public sealed record TargetMatrix(string ImplantClass, string Platform, string Arch);

/// <summary>The manifest's OPSEC metadata: what running the module leaves on
/// the target (architecture.md Sec 15.2 -- "lands on disk" / "memory only"
/// carried into the catalog, not left to prose).</summary>
public sealed record OpsecMetadata(bool LandsOnDisk, string? Notes);

/// <summary>Which files <c>rod mod publish</c> packs; empty include means
/// everything under the module directory minus the excludes.</summary>
public sealed record PackageRules(IReadOnlyList<string> Include, IReadOnlyList<string> Exclude);

/// <summary>
/// One verb row of the manifest's version matrix (architecture.md Sec 15.2,
/// the contract trilogy's third contract): the verb this module registers,
/// its module-scoped version, an optional per-verb teamserver floor, and the
/// verb's ATT&CK techniques (ADR-007) -- the authoritative per-verb
/// declaration the teamserver's coverage matrix renders; the module-level
/// <c>[attack]</c> list is its validated roll-up. A verb row is what lets a
/// module iterate one verb without republishing the whole package's
/// semantics -- the row version is the iteration record the registry catalog
/// reads and install checks.
/// </summary>
public sealed record VerbDeclaration(
    string Name,
    SemVer Version,
    SemVer? TeamserverMin,
    IReadOnlyList<string>? Techniques = null)
{
    public sealed override string ToString()
        => TeamserverMin is { } floor
            ? $"{Name}@{Version} (teamserver >= {floor})"
            : $"{Name}@{Version}";
}

/// <summary>
/// One asset row of the manifest (architecture.md Sec 15.1, Sec 15.2): a
/// named file an asset module carries -- a browser hook script, a phishing
/// template, any content the teamserver serves without executing. The name
/// is the logical address a consumer resolves (<c>module/asset</c>); the
/// path is the file's location inside the package, and the file's bytes
/// ride the canonical form through the per-file digest lines like every
/// other payload.
/// </summary>
public sealed record AssetDeclaration(string Name, string Path);

/// <summary>
/// The parsed <c>rod-module.toml</c> (ADR-009): the self-describing module
/// contract shared by all the entry kinds. This model is the authority for
/// the canonical form that gets signed -- every field it carries participates
/// in the signature, so a package cannot lie about its metadata.
/// </summary>
public sealed record ModuleManifest
{
    public required string Name { get; init; }
    public required SemVer Version { get; init; }
    public required ModuleEntryKind Entry { get; init; }
    public required string License { get; init; }
    public string? Description { get; init; }
    public string? Homepage { get; init; }
    public required SemVer TeamserverMin { get; init; }
    public IReadOnlyList<TargetMatrix> Targets { get; init; } = [];
    public required OpsecMetadata Opsec { get; init; }
    public IReadOnlyList<string> Techniques { get; init; } = [];
    public IReadOnlyList<VerbDeclaration> Verbs { get; init; } = [];
    public IReadOnlyList<AssetDeclaration> Assets { get; init; } = [];
    public PackageRules? Package { get; init; }

    private static readonly Regex NamePattern = new("^[a-z0-9][a-z0-9-]{0,63}$", RegexOptions.Compiled);
    private static readonly Regex TechniquePattern = new("^T\\d{4}(\\.\\d{3})?$", RegexOptions.Compiled);

    // The verb grammar Sec 10 names: namespace.action, each segment lowercase
    // kebab with underscores allowed (the reference set carries
    // lateral.exec_remote), matching what the plugin loader admits.
    private static readonly Regex VerbPattern = new("^[a-z0-9][a-z0-9_-]*\\.[a-z0-9][a-z0-9_-]*$", RegexOptions.Compiled);

    /// <summary>The name rule shared by the manifest validator and the
    /// scaffold: kebab-case, single segment, at most 64 characters.</summary>
    public static bool ValidName(string name) => NamePattern.IsMatch(name);

    /// <summary>
    /// Field-level validation, reported as human-readable errors. The rules
    /// that matter for trust: single-line fields only (they feed the
    /// canonical form line-per-field), a kebab-case name, and ATT&CK
    /// technique ids in their canonical shape.
    /// </summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (!NamePattern.IsMatch(Name))
            errors.Add($"module.name '{Name}' must be kebab-case: lowercase letters, digits, hyphens, at most 64 characters.");
        if (!SemVer.TryParse(Version.ToString(), out _))
            errors.Add($"module.version '{Version}' is not a SemVer version.");
        if (License.Length == 0)
            errors.Add("module.license is required; use an SPDX identifier.");
        foreach (var (field, value) in new[] { ("module.license", License), ("module.description", Description ?? ""), ("module.homepage", Homepage ?? ""), ("opsec.notes", Opsec.Notes ?? "") })
        {
            if (value.Contains('\n') || value.Contains('\r'))
                errors.Add($"{field} must be a single line (it participates in the signed canonical form).");
        }

        for (var i = 0; i < Targets.Count; i++)
        {
            var target = Targets[i];
            if (target.ImplantClass.Length == 0 || target.Platform.Length == 0 || target.Arch.Length == 0)
                errors.Add($"compatibility.targets[{i}] must carry non-empty implant-class, platform, and arch.");
            foreach (var part in new[] { target.ImplantClass, target.Platform, target.Arch })
            {
                if (part.Contains('\n') || part.Contains('\r') || part.Contains('/'))
                    errors.Add($"compatibility.targets[{i}] fields must be single-line and contain no '/'.");
            }
        }

        for (var i = 0; i < Techniques.Count; i++)
        {
            if (!TechniquePattern.IsMatch(Techniques[i]))
                errors.Add($"attack.techniques[{i}] '{Techniques[i]}' is not an ATT&CK technique id (T#### or T####.###).");
        }

        // The module-level [attack] list is the display roll-up of the verb
        // rows' declarations (ADR-007): once any verb row declares its own
        // techniques, a non-empty module-level list must agree with the
        // union exactly, so the registry catalog and the coverage matrix can
        // never read two different stories. Rows that declare none keep the
        // older summary-only shape working, and a verbless manifest (a build
        // unit) keeps its module-level list to itself.
        if (Techniques.Count > 0 && Verbs.Any(v => v.Techniques is { Count: > 0 }))
        {
            var declared = Techniques.Distinct().OrderBy(t => t, StringComparer.Ordinal).ToArray();
            var union = Verbs.SelectMany(v => v.Techniques ?? [])
                .Distinct()
                .OrderBy(t => t, StringComparer.Ordinal)
                .ToArray();
            if (!declared.SequenceEqual(union))
                errors.Add(
                    "attack.techniques must be exactly the union of the verbs' techniques "
                    + $"(it is the roll-up): declared [{string.Join(",", declared)}], "
                    + $"verb rows carry [{string.Join(",", union)}].");
        }

        var seenVerbs = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < Verbs.Count; i++)
        {
            var verb = Verbs[i];
            if (!VerbPattern.IsMatch(verb.Name))
                errors.Add($"verbs[{i}] '{verb.Name}' is not a namespaced verb (namespace.action, lowercase segments).");
            else if (!seenVerbs.Add(verb.Name))
                errors.Add($"verbs[{i}] '{verb.Name}' is declared twice.");
            for (var t = 0; t < (verb.Techniques?.Count ?? 0); t++)
            {
                if (!TechniquePattern.IsMatch(verb.Techniques![t]))
                    errors.Add($"verbs[{i}].techniques[{t}] '{verb.Techniques[t]}' is not an ATT&CK technique id (T#### or T####.###).");
            }
        }

        // The asset rows (the module layer's content seam, Sec 15.1): logical
        // kebab names a consumer resolves as module/asset, and package-relative
        // paths that stay inside the package -- the same no-escape rule the
        // installer's extraction and the teamserver's asset host enforce on
        // their sides of the file contract.
        var seenAssets = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < Assets.Count; i++)
        {
            var asset = Assets[i];
            if (!NamePattern.IsMatch(asset.Name))
                errors.Add($"assets[{i}] '{asset.Name}' must be kebab-case: lowercase letters, digits, hyphens, at most 64 characters.");
            else if (!seenAssets.Add(asset.Name))
                errors.Add($"assets[{i}] '{asset.Name}' is declared twice.");
            if (asset.Path.Length == 0 || asset.Path.Contains('\\') || Path.IsPathRooted(asset.Path)
                || asset.Path.Split('/').Any(segment => segment is ".." or ""))
                errors.Add($"assets[{i}] '{asset.Name}' path '{asset.Path}' must be a package-relative path with '/' separators and no '..' segments.");
            else if (asset.Path == ManifestToml.FileName)
                errors.Add($"assets[{i}] '{asset.Name}' cannot point at the manifest itself.");
        }
        if (Entry == ModuleEntryKind.Assets && Assets.Count == 0)
            errors.Add("an assets module declares no [[assets]] rows; add one per carried file.");

        return errors;
    }
}
