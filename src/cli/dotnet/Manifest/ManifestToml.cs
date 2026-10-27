using System.Text;
using Tomlyn;
using Tomlyn.Serialization;

namespace Rod.Cli.Manifest;

/// <summary>
/// Reads and writes <c>rod-module.toml</c>. Reading deserializes into a
/// typed document shape and maps it onto the manifest model with
/// field-level error reporting -- an operator's first <c>rod mod</c>
/// failure should name the key, not the parser offset. Tomlyn 2.x maps
/// properties by their exact declared name only, so every property of the
/// document shape carries <see cref="TomlPropertyNameAttribute"/>, kebab
/// TOML keys included; unknown keys are ignored, so a manifest written for
/// a newer CLI still parses. Writing is a hand-rolled emitter for the
/// scaffold template only: manifests are authored, never rewritten by the
/// tooling, so round-trip fidelity is not a requirement and the emitter
/// stays deliberately small.
/// </summary>
public static class ManifestToml
{
    public const string FileName = "rod-module.toml";

    private sealed class Document
    {
        [TomlPropertyName("module")]
        public ModuleSection? Module { get; set; }

        [TomlPropertyName("compatibility")]
        public CompatibilitySection? Compatibility { get; set; }

        [TomlPropertyName("opsec")]
        public OpsecSection? Opsec { get; set; }

        [TomlPropertyName("attack")]
        public AttackSection? Attack { get; set; }

        [TomlPropertyName("conformance")]
        public ConformanceSection? Conformance { get; set; }

        [TomlPropertyName("package")]
        public PackageSection? Package { get; set; }

        [TomlPropertyName("verbs")]
        public List<VerbRow>? Verbs { get; set; }

        [TomlPropertyName("assets")]
        public List<AssetRow>? Assets { get; set; }
    }

    private sealed class ModuleSection
    {
        [TomlPropertyName("name")] public string? Name { get; set; }
        [TomlPropertyName("version")] public string? Version { get; set; }
        [TomlPropertyName("entry")] public string? Entry { get; set; }
        [TomlPropertyName("license")] public string? License { get; set; }
        [TomlPropertyName("description")] public string? Description { get; set; }
        [TomlPropertyName("homepage")] public string? Homepage { get; set; }
    }

    private sealed class CompatibilitySection
    {
        [TomlPropertyName("teamserver")] public string? Teamserver { get; set; }
        [TomlPropertyName("requires")] public List<string>? Requires { get; set; }
        [TomlPropertyName("targets")] public List<TargetRow>? Targets { get; set; }
    }

    private sealed class ConformanceSection
    {
        [TomlPropertyName("tier")] public long? Tier { get; set; }
        [TomlPropertyName("harness")] public string? Harness { get; set; }
        [TomlPropertyName("date")] public string? Date { get; set; }
        [TomlPropertyName("clauses")] public List<string>? Clauses { get; set; }
    }

    private sealed class TargetRow
    {
        [TomlPropertyName("implant-class")] public string? ImplantClass { get; set; }
        [TomlPropertyName("platform")] public string? Platform { get; set; }
        [TomlPropertyName("arch")] public string? Arch { get; set; }
    }

    private sealed class OpsecSection
    {
        [TomlPropertyName("lands-on-disk")] public bool? LandsOnDisk { get; set; }
        [TomlPropertyName("notes")] public string? Notes { get; set; }
    }

    private sealed class AttackSection
    {
        [TomlPropertyName("techniques")] public List<string>? Techniques { get; set; }
    }

    private sealed class PackageSection
    {
        [TomlPropertyName("include")] public List<string>? Include { get; set; }
        [TomlPropertyName("exclude")] public List<string>? Exclude { get; set; }
    }

    private sealed class VerbRow
    {
        [TomlPropertyName("name")] public string? Name { get; set; }
        [TomlPropertyName("version")] public string? Version { get; set; }
        [TomlPropertyName("teamserver")] public string? Teamserver { get; set; }
        [TomlPropertyName("techniques")] public List<string>? Techniques { get; set; }
    }

    private sealed class AssetRow
    {
        [TomlPropertyName("name")] public string? Name { get; set; }
        [TomlPropertyName("path")] public string? Path { get; set; }
    }

    /// <summary>Parses manifest text; syntax errors and semantic errors come
    /// back together so one command run shows everything wrong with the file.</summary>
    public static IReadOnlyList<string> Load(string text, out ModuleManifest? manifest)
    {
        manifest = null;
        var errors = new List<string>();

        Document? document;
        try
        {
            document = TomlSerializer.Deserialize<Document>(text, new TomlSerializerOptions());
        }
        catch (TomlException failure)
        {
            return [failure.Message];
        }
        if (document is null)
            return ["the manifest did not deserialize."];

        var module = document.Module;
        var compatibility = document.Compatibility;
        var opsec = document.Opsec;

        string? name = TrimOrNull(module?.Name);
        string? versionText = TrimOrNull(module?.Version);
        string? entryText = TrimOrNull(module?.Entry);
        string? license = TrimOrNull(module?.License);
        if (name is null) errors.Add("module.name is missing.");
        if (versionText is null) errors.Add("module.version is missing.");
        if (entryText is null) errors.Add("module.entry is missing (server, implant, build-unit, or assets).");
        if (license is null) errors.Add("module.license is missing; use an SPDX identifier.");

        string? teamserverText = TrimOrNull(compatibility?.Teamserver);
        if (teamserverText is null)
            errors.Add("compatibility.teamserver is missing (the minimum teamserver version).");

        var landsOnDisk = opsec?.LandsOnDisk;
        if (landsOnDisk is null)
            errors.Add("opsec.lands-on-disk is missing (boolean): state honestly what running the module leaves on the target.");

        if (errors.Count > 0)
            return errors;

        if (!SemVer.TryParse(versionText!, out var version))
            errors.Add($"module.version '{versionText}' is not a SemVer version (M.m.p[-pre]).");
        if (!ModuleEntryKindNames.TryParse(entryText!, out var entry))
            errors.Add($"module.entry '{entryText}' is not one of: server, implant, build-unit, or assets.");
        if (!SemVer.TryParse(teamserverText!, out var teamserverMin))
            errors.Add($"compatibility.teamserver '{teamserverText}' is not a SemVer version.");

        var targets = (compatibility?.Targets ?? []).Select(row => new TargetMatrix(
            TrimOrNull(row.ImplantClass) ?? "",
            TrimOrNull(row.Platform) ?? "",
            TrimOrNull(row.Arch) ?? "")).ToList();

        // The capability requirements (ADR-017): trims and drops empties the
        // way the technique list does; the closed-vocabulary check is the
        // validator's, so one load reports every wrong name at once.
        var requires = (compatibility?.Requires ?? [])
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => r.Trim())
            .ToList();

        // The conformance report (build units): a section any field of which
        // is set must be whole -- a partial report is a claim missing its
        // proof shape, not a report.
        ConformanceReport? conformance = null;
        var conformanceSection = document.Conformance;
        if (conformanceSection is { } section
            && (section.Tier is not null || section.Harness is not null || section.Date is not null || section.Clauses is not null))
        {
            if (section.Tier is null)
                errors.Add("conformance.tier is missing (0, 1, or 2).");
            if (TrimOrNull(section.Harness) is null)
                errors.Add("conformance.harness is missing (the harness generation the run used).");
            if (TrimOrNull(section.Date) is null)
                errors.Add("conformance.date is missing (the run's date, YYYY-MM-DD).");
            if (errors.Count == 0)
            {
                if (!SemVer.TryParse(section.Harness!.Trim(), out var harness))
                {
                    errors.Add($"conformance.harness '{section.Harness}' is not a SemVer version.");
                }
                else
                {
                    conformance = new ConformanceReport(
                        (int)section.Tier!,
                        harness,
                        section.Date!.Trim(),
                        (section.Clauses ?? [])
                            .Where(c => !string.IsNullOrWhiteSpace(c))
                            .Select(c => c.Trim())
                            .ToList());
                }
            }
        }

        var techniques = (document.Attack?.Techniques ?? [])
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t.Trim().ToUpperInvariant())
            .ToList();

        PackageRules? package = null;
        var include = document.Package?.Include;
        var exclude = document.Package?.Exclude;
        if (include is { Count: > 0 } || exclude is { Count: > 0 })
            package = new PackageRules(include ?? [], exclude ?? []);

        // The verb rows (the version matrix): each carries its own version
        // and an optional per-verb teamserver floor. A row that fails to
        // parse names its own error rather than failing the whole load.
        var verbs = new List<VerbDeclaration>();
        for (var i = 0; i < (document.Verbs?.Count ?? 0); i++)
        {
            var row = document.Verbs![i];
            var verbName = TrimOrNull(row.Name);
            if (verbName is null)
            {
                errors.Add($"verbs[{i}].name is missing (namespace.action).");
                continue;
            }

            if (!SemVer.TryParse(TrimOrNull(row.Version) ?? "", out var verbVersion))
            {
                errors.Add($"verbs[{i}] '{verbName}' needs a SemVer version.");
                continue;
            }

            SemVer? verbFloor = null;
            var floorText = TrimOrNull(row.Teamserver);
            if (floorText is not null)
            {
                if (!SemVer.TryParse(floorText, out var parsedFloor))
                {
                    errors.Add($"verbs[{i}] '{verbName}' carries an unparseable teamserver floor '{floorText}'.");
                    continue;
                }
                verbFloor = parsedFloor;
            }

            // The row's techniques are the authoritative per-verb ATT&CK
            // declaration (ADR-007); they normalize like the module-level list.
            var verbTechniques = (row.Techniques ?? [])
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Select(t => t.Trim().ToUpperInvariant())
                .ToList();

            verbs.Add(new VerbDeclaration(verbName, verbVersion, verbFloor, verbTechniques));
        }

        // The asset rows: logical name plus package-relative path. Like a
        // verb row, a row that fails to parse names itself rather than
        // failing the whole load.
        var assets = new List<AssetDeclaration>();
        for (var i = 0; i < (document.Assets?.Count ?? 0); i++)
        {
            var row = document.Assets![i];
            var assetName = TrimOrNull(row.Name);
            var assetPath = TrimOrNull(row.Path);
            if (assetName is null || assetPath is null)
            {
                errors.Add($"assets[{i}] needs both a name and a path.");
                continue;
            }
            assets.Add(new AssetDeclaration(assetName, assetPath));
        }

        if (errors.Count > 0)
            return errors;

        manifest = new ModuleManifest
        {
            Name = name!,
            Version = version,
            Entry = entry,
            License = license!,
            Description = TrimOrNull(module?.Description),
            Homepage = TrimOrNull(module?.Homepage),
            TeamserverMin = teamserverMin,
            Targets = targets,
            Requires = requires,
            Conformance = conformance,
            // Non-null here: a null lands-on-disk added an error above, and
            // any error returns before the manifest is built.
            Opsec = new OpsecMetadata(landsOnDisk!.Value, TrimOrNull(opsec?.Notes)),
            Techniques = techniques,
            Verbs = verbs,
            Assets = assets,
            Package = package,
        };
        errors.AddRange(manifest.Validate());
        return errors;
    }

    public static (ModuleManifest Manifest, IReadOnlyList<string> Errors) LoadFile(string path)
    {
        var errors = Load(File.ReadAllText(path), out var manifest);
        return manifest is null
            ? (null!, errors.Count > 0 ? errors : [$"'{path}' did not produce a manifest."])
            : (manifest, errors);
    }

    /// <summary>Renders the scaffold manifest <c>rod mod init</c> writes:
    /// every field present, the optional ones commented out, the OPSEC and
    /// license fields carrying honest defaults an author must look at.</summary>
    public static string RenderTemplate(
        string name,
        SemVer version,
        ModuleEntryKind entry,
        string license,
        SemVer teamserverMin,
        bool landsOnDisk,
        string? description)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# The module manifest (architecture.md Sec 15.2, ADR-009): the");
        sb.AppendLine("# self-describing contract every rod module ships. `rod mod publish`");
        sb.AppendLine("# signs this file's canonical form; `rod mod install` verifies it.");
        sb.AppendLine();
        sb.AppendLine("[module]");
        sb.AppendLine($"name = {Quote(name)}");
        sb.AppendLine($"version = {Quote(version.ToString())}");
        sb.AppendLine($"entry = {Quote(ModuleEntryKindNames.ToString(entry))}  # server | implant | build-unit | assets");
        sb.AppendLine($"license = {Quote(license)}  # SPDX identifier; publish refuses UNLICENSED");
        sb.AppendLine($"description = {Quote(description ?? "")}");
        sb.AppendLine();
        sb.AppendLine("[compatibility]");
        sb.AppendLine($"teamserver = {Quote(teamserverMin.ToString())}  # minimum teamserver version");
        sb.AppendLine("# Wire capabilities the hosting implant must support (the closed");
        sb.AppendLine("# vocabulary: plugin-loader, exfil-chunks, staged-uploads). The");
        sb.AppendLine("# implant's handshake advertisement is the runtime truth; this row");
        sb.AppendLine("# is the store's static filter.");
        sb.AppendLine("# requires = [\"plugin-loader\"]");
        sb.AppendLine();
        sb.AppendLine("[opsec]");
        sb.AppendLine($"lands-on-disk = {landsOnDisk.ToString().ToLowerInvariant()}  # what running the module leaves on the target");
        sb.AppendLine();
        sb.AppendLine("[attack]");
        sb.AppendLine("techniques = []  # the roll-up of the verb rows' techniques, e.g. [\"T1082\"]");
        sb.AppendLine();

        if (entry == ModuleEntryKind.BuildUnit)
        {
            // The conformance report is the build unit's half of the
            // compatibility collapse: what its candidate proved against the
            // harness, signed with the package so a store badge is a
            // publisher's signature-bound claim.
            sb.AppendLine("# The conformance report (build units): what a harness run proved --");
            sb.AppendLine("# the tier achieved, the harness generation, the date, the clauses.");
            sb.AppendLine("# It rides the signed canonical form and the registry catalog.");
            sb.AppendLine("# [conformance]");
            sb.AppendLine("# tier = 0  # 0 (interop), 1 (hardening), or 2 (optional features)");
            sb.AppendLine("# harness = \"1.0.0\"");
            sb.AppendLine("# date = \"2026-01-15\"");
            sb.AppendLine("# clauses = [\"enroll.public-key-and-token\", \"handshake.first-frame-ok\", \"task.round-trip\"]");
            sb.AppendLine();
        }

        if (entry == ModuleEntryKind.Assets)
        {
            // The asset rows: one per carried file, the logical name a
            // consumer resolves as module/asset bound to the package-relative
            // path. The rows ride the signed canonical form like verb rows.
            sb.AppendLine("[[assets]]");
            sb.AppendLine($"name = {Quote(name)}");
            sb.AppendLine($"path = {Quote($"assets/{name}.txt")}");
            sb.AppendLine();
        }
        else
        {
            sb.AppendLine("# The verb version matrix (one row per verb the module registers): the");
            sb.AppendLine("# module-scoped version each verb iterates under, an optional per-verb");
            sb.AppendLine("# teamserver floor, and the verb's ATT&CK techniques (ADR-007) -- the");
            sb.AppendLine("# authoritative declaration the coverage matrix renders. The rows ride");
            sb.AppendLine("# the signed canonical form.");
            sb.AppendLine();
            sb.AppendLine("[[verbs]]");
            sb.AppendLine($"name = \"{name}.run\"");
            sb.AppendLine("version = \"0.1.0\"");
            sb.AppendLine("# teamserver = \"1.0.0\"  # optional per-verb floor");
            sb.AppendLine("# techniques = [\"T1082\"]  # this verb's ATT&CK techniques");
            sb.AppendLine();
        }
        sb.AppendLine("# Optional packaging rules; uncomment to narrow what publish packs.");
        sb.AppendLine("# [package]");
        sb.AppendLine("# include = [\"src/**\"]");
        sb.AppendLine("# exclude = [\"**/bin/**\", \"**/obj/**\"]");
        sb.AppendLine();
        sb.AppendLine("# Optional implant-side matrix; server-entry modules leave it empty.");
        sb.AppendLine("# [[compatibility.targets]]");
        sb.AppendLine("# implant-class = \"implant\"");
        sb.AppendLine("# platform = \"linux\"");
        sb.AppendLine("# arch = \"amd64\"");
        return sb.ToString();
    }

    internal static string Quote(string value)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (char.IsControl(c))
                        sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else
                        sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    private static string? TrimOrNull(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
