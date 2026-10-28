using System.Text.RegularExpressions;

namespace Rod.Packaging;

/// <summary>
/// The entry kind a module ships as (architecture.md Sec 15.2): a
/// server-side capability module, a portable implant-side plugin package, an
/// implant-native extension compiled into a build, a build unit, or a pure
/// asset module (script and template files the teamserver serves, no code).
/// The kind decides how an installed package is consumed, not how it
/// travels -- one manifest shape, one registry, one CLI.
/// </summary>
public enum ModuleEntryKind
{
    Server,
    Plugin,
    Extension,
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
            case "plugin": kind = ModuleEntryKind.Plugin; return true;
            case "extension": kind = ModuleEntryKind.Extension; return true;
            case "build-unit": kind = ModuleEntryKind.BuildUnit; return true;
            case "assets": kind = ModuleEntryKind.Assets; return true;
            default: kind = default; return false;
        }
    }

    public static string ToString(ModuleEntryKind kind) => kind switch
    {
        ModuleEntryKind.Server => "server",
        ModuleEntryKind.Plugin => "plugin",
        ModuleEntryKind.Extension => "extension",
        ModuleEntryKind.BuildUnit => "build-unit",
        ModuleEntryKind.Assets => "assets",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };
}

/// <summary>
/// The loader ABI names a plugin artifact may declare (ADR-020): the loading
/// contract the artifact was built against, not the implant that hosts it.
/// <c>exec-v1</c> is the out-of-process stdio loader (a self-contained
/// executable run per exchange), <c>native-v1</c> the in-process
/// <c>rod_plugin_*</c> C ABI (a library the implant maps and calls);
/// <c>coff-v1</c> and <c>wasm-v1</c> are reserved -- the names exist so the
/// manifests, the registry, and the catalog can speak about the tiers
/// before any reference implant ships their loaders. <see cref="Loadable"/>
/// names the ABIs the in-tree reference loaders accept today; publishing an
/// artifact under a reserved ABI is refused until its loader lands.
/// </summary>
public static class PluginAbis
{
    public const string Exec = "exec-v1";
    public const string Native = "native-v1";
    public const string Coff = "coff-v1";
    public const string Wasm = "wasm-v1";

    /// <summary>Every ABI name the grammar knows, loadable or reserved.</summary>
    public static readonly IReadOnlyList<string> Known = [Exec, Native, Coff, Wasm];

    /// <summary>The ABIs with a reference loader shipped today.</summary>
    public static readonly IReadOnlyList<string> Loadable = [Exec, Native];

    public static bool IsKnown(string name)
        => Known.Contains(name, StringComparer.Ordinal);

    public static bool IsLoadable(string name)
        => Loadable.Contains(name, StringComparer.Ordinal);
}

/// <summary>
/// The wire capability names the module contract's compatibility rows draw
/// from (architecture.md Sec 15.2, ADR-017): a plugin declares what the
/// hosting implant must support, an implant's conformance report proves
/// what its candidate passed. The names are the wire tiers' own features
/// (extending/implants.md), a closed vocabulary so a store filter compares
/// like against like -- it grows additively with the tiers, and an unknown
/// name is a refused manifest, never a silent mismatch. This copy and the
/// runtime gate in Rod.CoreState state the set independently (the contract
/// library cannot take a kernel reference); a test pins them equal.
/// </summary>
public static class WireCapabilities
{
    /// <summary>The ABI family prefix: every loader capability name starts
    /// with this and an ABI id.</summary>
    public const string PluginLoaderPrefix = "plugin-loader/";

    /// <summary>The out-of-process loader ABI (self-contained executable,
    /// stdio protocol).</summary>
    public const string PluginLoaderExec = PluginLoaderPrefix + "exec-v1";

    /// <summary>The in-process loader ABI (<c>rod_plugin_*</c> C symbol
    /// family).</summary>
    public const string PluginLoaderNative = PluginLoaderPrefix + "native-v1";

    /// <summary>The COFF/BOF loader ABI. Reserved.</summary>
    public const string PluginLoaderCoff = PluginLoaderPrefix + "coff-v1";

    /// <summary>The wasm loader ABI. Reserved.</summary>
    public const string PluginLoaderWasm = PluginLoaderPrefix + "wasm-v1";

    /// <summary>Bulk output through ExfilChunk frames (Tier 2).</summary>
    public const string ExfilChunks = "exfil-chunks";

    /// <summary>Downstream bulk through StagedPull/StagedChunk (Tier 2).</summary>
    public const string StagedUploads = "staged-uploads";

    /// <summary>The names a manifest's <c>requires</c> may carry: the
    /// task-path capabilities a plugin's verbs can depend on. A plugin
    /// cannot own a live channel (the loader refuses channel verbs), so
    /// the interactive-channel tier is deliberately absent.</summary>
    public static readonly IReadOnlyList<string> Requirable =
        [PluginLoaderExec, PluginLoaderNative, PluginLoaderCoff, PluginLoaderWasm, ExfilChunks, StagedUploads];

    public static bool IsRequirable(string name)
        => Requirable.Contains(name, StringComparer.Ordinal);

    /// <summary>Whether <paramref name="name"/> names a loader ABI (any
    /// generation): the loader family's requirement rows.</summary>
    public static bool IsPluginLoaderAbi(string name)
        => name.StartsWith(PluginLoaderPrefix, StringComparison.Ordinal);
}

/// <summary>
/// One row of the manifest's compatibility matrix: which implant class, on
/// which platform and arch, the module's execution half serves. The optional
/// <see cref="BuildUnit"/> row names the build unit an extension targets
/// (with <see cref="UnitRange"/> as its version floor) -- the declaration an
/// extension's targeting hangs on, absent for portable plugins and
/// server-entry modules whose halves carry no build-time coupling.
/// </summary>
public sealed record TargetMatrix(
    string ImplantClass,
    string Platform,
    string Arch,
    string? BuildUnit = null,
    SemVer? UnitRange = null);

/// <summary>The manifest's OPSEC metadata: what running the module leaves on
/// the target (architecture.md Sec 15.2 -- "lands on disk" / "memory only"
/// carried into the catalog, not left to prose).</summary>
public sealed record OpsecMetadata(bool LandsOnDisk, string? Notes);

/// <summary>Which files <c>rod mod publish</c> packs; empty include means
/// everything under the module directory minus the excludes.</summary>
public sealed record PackageRules(IReadOnlyList<string> Include, IReadOnlyList<string> Exclude);

/// <summary>
/// The descriptor vocabulary a manifest's verb rows draw from: the category,
/// parameter-kind, and output-kind names, each the lowercase spelling of the
/// teamserver's own enumeration (<c>CapabilityCategory</c>,
/// <c>VerbParameterKind</c>, <c>VerbOutputKind</c> in Rod.Capabilities).
/// The sets live here once and every consumer reads them -- the rod CLI
/// validates manifests against this library, and the teamserver loads
/// manifests through it; a test pins them equal to the teamserver's
/// descriptor enumerations, and an unknown name is a refused manifest,
/// never a silent mismatch.
/// </summary>
public static class ManifestVocabularies
{
    /// <summary>The capability categories a verb row may declare.</summary>
    public static readonly IReadOnlyList<string> Categories =
    [
        "core", "recon", "lateral", "persist", "collect", "exfil",
        "tunnel", "module", "browser", "evasion", "exploit",
    ];

    /// <summary>The parameter kinds a verb row's parameters may carry.</summary>
    public static readonly IReadOnlyList<string> ParameterKinds =
    [
        "string", "text", "number", "boolean", "enum", "file", "array",
    ];

    /// <summary>The output taxonomy kinds a verb row may declare.</summary>
    public static readonly IReadOnlyList<string> OutputKinds =
    [
        "text", "enumeration", "process-list", "file-list",
        "credential", "file", "screenshot",
    ];

    public static bool IsCategory(string name) => Categories.Contains(name, StringComparer.Ordinal);
    public static bool IsParameterKind(string name) => ParameterKinds.Contains(name, StringComparer.Ordinal);
    public static bool IsOutputKind(string name) => OutputKinds.Contains(name, StringComparer.Ordinal);
}

/// <summary>
/// One declared parameter of a verb row (architecture.md Sec 15.2, the
/// contract trilogy's first contract as manifest data, ADR-018): the field
/// the operator UI renders generically, in declaration order. The manifest
/// spelling of the teamserver's <c>VerbParameter</c>; the serialization
/// defaults (<c>required</c>, <c>trailing</c>, <c>inline</c> absent meaning
/// false, false, true) normalize at parse so the canonical form is a
/// function of the declared fields, not the syntax that carried them.
/// </summary>
public sealed record VerbParameterDeclaration(
    string Name,
    string Label,
    string Kind,
    bool Required = false,
    string? Help = null,
    string? Placeholder = null,
    IReadOnlyList<string>? Choices = null,
    bool Trailing = false,
    bool Inline = true);

/// <summary>
/// A verb row's declared output (the trilogy's second contract as manifest
/// data): the taxonomy kind that routes results to the generic panels plus
/// one sentence on what they hold. The manifest spelling of the
/// teamserver's <c>VerbOutput</c>.
/// </summary>
public sealed record VerbOutputDeclaration(string Kind, string? Help = null);

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
/// <remarks>
/// A row that carries <see cref="Category"/> is a **descriptor row** (ADR-018):
/// it declares the verb's whole server-side half as manifest data -- the
/// category, the per-verb OPSEC attribute flags (<see cref="Opsec"/>), the
/// parameter schema (<see cref="Parameters"/>), and the output declaration
/// (<see cref="Output"/>) -- so a novel namespace opens its issuance gate
/// with zero .NET code. A row without one is a version row only: the
/// server-side half lives in an assembly the operator lists separately.
/// The two shapes never mix their fields: descriptor fields without a
/// category are a refused manifest, naming the row.
/// </remarks>
public sealed record VerbDeclaration(
    string Name,
    SemVer Version,
    SemVer? TeamserverMin,
    IReadOnlyList<string>? Techniques = null,
    string? Category = null,
    IReadOnlyDictionary<string, bool>? Opsec = null,
    IReadOnlyList<VerbParameterDeclaration>? Parameters = null,
    VerbOutputDeclaration? Output = null)
{
    /// <summary>True when the row carries its server-side descriptor.</summary>
    public bool IsDescriptor => Category is not null;

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
/// One <c>[[plugin.artifacts]]</c> row of a plugin-entry manifest (ADR-020):
/// the prebuilt execution half for one platform and arch, and the loader ABI
/// it was built against. The pair a plugin package ships per target -- the
/// server stages the platform-matched artifact through the module family,
/// and the ABI name is the compatibility claim the runtime gate and the
/// registry filter read. The artifact's bytes ride the canonical form
/// through the per-file digest lines like every other payload.
/// </summary>
public sealed record PluginArtifact(string Platform, string Arch, string Path, string Abi);

/// <summary>
/// The <c>[unit]</c> table of a build-unit manifest (ADR-021): the external
/// build contract's own face -- the unit id the build pipeline routes
/// requests by (an open vocabulary; the in-tree units claim <c>rod-rust</c>
/// and <c>rod-go</c>, a community unit claims any kebab id), the command the
/// pipeline spawns with the build request, and an optional wall-clock
/// timeout. One implementation, any toolchain: a new language registers a
/// build unit without the teamserver compiling a line of its code.
/// </summary>
public sealed record UnitDefinition(string Id, string Command, int? TimeoutMinutes = null);

/// <summary>
/// The manifest's conformance report (ADR-017): what a build unit's
/// candidate proved against the conformance harness -- the tier achieved,
/// the harness generation, the run's date, and the clauses that passed.
/// The report is the build-unit half of the compatibility collapse: an
/// operator matches a plugin's <c>requires</c> against what an implant
/// proved, so compatibility is checked module-to-contract and
/// implant-to-contract, never module-to-implant. It rides the signed
/// canonical form: a publisher's self-claim, but a signature-bound one a
/// tampered registry index cannot forge.
/// </summary>
public sealed record ConformanceReport(
    int Tier,
    SemVer Harness,
    string Date,
    IReadOnlyList<string> Clauses)
{
    public sealed override string ToString()
        => $"tier {Tier} (harness {Harness}, {Date})";
}

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
    public IReadOnlyList<string> Requires { get; init; } = [];
    public ConformanceReport? Conformance { get; init; }
    public required OpsecMetadata Opsec { get; init; }
    public IReadOnlyList<string> Techniques { get; init; } = [];
    public IReadOnlyList<VerbDeclaration> Verbs { get; init; } = [];
    public IReadOnlyList<AssetDeclaration> Assets { get; init; } = [];
    public IReadOnlyList<PluginArtifact> PluginArtifacts { get; init; } = [];
    public UnitDefinition? Unit { get; init; }
    public PackageRules? Package { get; init; }

    private static readonly Regex NamePattern = new("^[a-z0-9][a-z0-9-]{0,63}$", RegexOptions.Compiled);
    private static readonly Regex TechniquePattern = new("^T\\d{4}(\\.\\d{3})?$", RegexOptions.Compiled);
    private static readonly Regex IsoDatePattern = new("^\\d{4}-\\d{2}-\\d{2}$", RegexOptions.Compiled);

    // A harness clause name (enroll.public-key-and-token and its kin): a
    // single lowercase token, so the canonical form's comma-joined clause
    // line stays unambiguous.
    private static readonly Regex ClausePattern = new("^[a-z0-9][a-z0-9._-]*$", RegexOptions.Compiled);

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

        // The capability requirements (ADR-017): names from the closed wire
        // vocabulary only, on the entries that carry a runtime-hosted
        // execution half. A build unit is the implant itself, an assets
        // module runs nothing on a target, and an extension compiles into
        // the implant (its half needs no loader), so a requirement there
        // names nothing real. The runtime check is the implant's own
        // handshake advertisement; this row is the store's static filter.
        var seenRequires = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < Requires.Count; i++)
        {
            if (!WireCapabilities.IsRequirable(Requires[i]))
                errors.Add(
                    $"compatibility.requires[{i}] '{Requires[i]}' is not a wire capability a module may require; "
                    + $"the vocabulary is: {string.Join(", ", WireCapabilities.Requirable)}.");
            else if (!seenRequires.Add(Requires[i]))
                errors.Add($"compatibility.requires[{i}] '{Requires[i]}' is declared twice.");
        }
        if (seenRequires.Count > 0 && Entry is ModuleEntryKind.BuildUnit or ModuleEntryKind.Assets or ModuleEntryKind.Extension)
            errors.Add(
                "compatibility.requires constrains an implant hosting this module's execution half; "
                + $"a {ModuleEntryKindNames.ToString(Entry)} module carries none.");

        // A plugin's requirement rows are its artifacts' ABI set stated as a
        // static filter: the union is a function of the artifact rows, so the
        // manifest is refused when the two stories differ -- a requirement
        // the artifacts do not back, or a loader an artifact needs that the
        // rows stay silent about.
        if (Entry == ModuleEntryKind.Plugin)
        {
            // The artifact rows carry bare ABI ids; the requirement rows
            // carry the family-prefixed capability names -- the union
            // compares in the requirement rows' spelling.
            var artifactAbis = PluginArtifacts
                .Select(a => WireCapabilities.PluginLoaderPrefix + a.Abi)
                .Distinct().OrderBy(a => a, StringComparer.Ordinal).ToArray();
            var declared = Requires.Where(WireCapabilities.IsPluginLoaderAbi).Distinct().OrderBy(r => r, StringComparer.Ordinal).ToArray();
            if (!artifactAbis.SequenceEqual(declared))
                errors.Add(
                    "compatibility.requires must be exactly the union of the plugin artifacts' ABIs "
                    + $"(the rows are the store's static filter): declared [{string.Join(",", declared)}], "
                    + $"artifacts carry [{string.Join(",", artifactAbis)}].");
        }

        // The extension half of the targeting rows (ADR-022): an extension is
        // compiled into a build by the unit that owns it, so its targets name
        // the build unit (and optionally its version floor) -- a manifest
        // that targets no unit is a portable plugin mis-declared as an
        // extension, and the build-time gate has nothing to hang on.
        if (Entry == ModuleEntryKind.Extension)
        {
            if (Targets.Count == 0)
                errors.Add("an extension declares no [[compatibility.targets]]; every row must name the build-unit it compiles into.");
            for (var i = 0; i < Targets.Count; i++)
            {
                if (Targets[i].BuildUnit is not { } unit)
                    errors.Add($"compatibility.targets[{i}] carries no build-unit; an extension targets the build unit that compiles it in.");
                else if (!ValidName(unit))
                    errors.Add($"compatibility.targets[{i}].build-unit '{unit}' must be kebab-case: lowercase letters, digits, hyphens, at most 64 characters.");
            }
        }

        // The external build contract's face (ADR-021): a [unit] table rides
        // a build-unit manifest only, and a build-unit manifest must carry
        // one -- an external unit without its id and command is a package
        // the pipeline cannot spawn.
        if (Unit is { } unitDefinition)
        {
            if (Entry != ModuleEntryKind.BuildUnit)
                errors.Add(
                    "[unit] declares the external build command; "
                    + $"a {ModuleEntryKindNames.ToString(Entry)} module carries none.");
            else
            {
                if (!ValidName(unitDefinition.Id))
                    errors.Add($"unit.id '{unitDefinition.Id}' must be kebab-case: lowercase letters, digits, hyphens, at most 64 characters.");
                if (unitDefinition.Command.Length == 0 || unitDefinition.Command.Contains('\n') || unitDefinition.Command.Contains('\r'))
                    errors.Add("unit.command is required and must be a single line (it participates in the signed canonical form).");
                if (unitDefinition.TimeoutMinutes is <= 0)
                    errors.Add($"unit.timeout-minutes '{unitDefinition.TimeoutMinutes}' must be a positive number of minutes.");
            }
        }
        else if (Entry == ModuleEntryKind.BuildUnit)
        {
            errors.Add("a build-unit manifest carries no [unit] table; the id and the command are the pipeline's spawn contract.");
        }

        // The plugin artifact rows (ADR-020): one prebuilt execution half per
        // platform and arch, its loader ABI from the closed vocabulary. The
        // path rule is the asset rows' own (package-relative, no escape), and
        // a platform may carry one artifact -- two rows for one platform is
        // a staging ambiguity, not a choice.
        if (Entry == ModuleEntryKind.Plugin && PluginArtifacts.Count == 0)
            errors.Add("a plugin module declares no [[plugin.artifacts]] rows; add one per platform and arch it ships.");
        var seenArtifacts = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < PluginArtifacts.Count; i++)
        {
            var artifact = PluginArtifacts[i];
            if (artifact.Platform.Length == 0 || artifact.Arch.Length == 0)
                errors.Add($"plugin.artifacts[{i}] must carry non-empty platform and arch.");
            foreach (var part in new[] { artifact.Platform, artifact.Arch })
            {
                if (part.Contains('\n') || part.Contains('\r') || part.Contains('/'))
                    errors.Add($"plugin.artifacts[{i}] fields must be single-line and contain no '/'.");
            }
            if (!PluginAbis.IsKnown(artifact.Abi))
                errors.Add(
                    $"plugin.artifacts[{i}] abi '{artifact.Abi}' is not a loader ABI; "
                    + $"the vocabulary is: {string.Join(", ", PluginAbis.Known)}.");
            if (artifact.Path.Length == 0 || artifact.Path.Contains('\\') || Path.IsPathRooted(artifact.Path)
                || artifact.Path.Split('/').Any(segment => segment is ".." or ""))
                errors.Add($"plugin.artifacts[{i}] path '{artifact.Path}' must be a package-relative path with '/' separators and no '..' segments.");
            else if (artifact.Path == ManifestToml.FileName)
                errors.Add($"plugin.artifacts[{i}] cannot point at the manifest itself.");
            if (!seenArtifacts.Add($"{artifact.Platform}/{artifact.Arch}"))
                errors.Add($"plugin.artifacts[{i}] declares platform '{artifact.Platform}' arch '{artifact.Arch}' twice; one artifact per target.");
        }

        if (Conformance is { } report)
        {
            if (Entry != ModuleEntryKind.BuildUnit)
                errors.Add(
                    "[conformance] reports what a build unit's candidate proved against the harness; "
                    + $"a {ModuleEntryKindNames.ToString(Entry)} module carries none.");
            if (report.Tier is < 0 or > 2)
                errors.Add($"conformance.tier '{report.Tier}' must be 0, 1, or 2.");
            if (!IsoDatePattern.IsMatch(report.Date) || !DateOnly.TryParse(report.Date, out _))
                errors.Add($"conformance.date '{report.Date}' must be an ISO date (YYYY-MM-DD).");
            var seenClauses = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < report.Clauses.Count; i++)
            {
                if (!ClausePattern.IsMatch(report.Clauses[i]))
                    errors.Add($"conformance.clauses[{i}] '{report.Clauses[i]}' must be a single lowercase token (the harness's clause names).");
                else if (!seenClauses.Add(report.Clauses[i]))
                    errors.Add($"conformance.clauses[{i}] '{report.Clauses[i]}' is declared twice.");
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

            AppendDescriptorErrors(verb, i, errors);
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

    /// <summary>
    /// Validates one verb row's descriptor half (ADR-018): a row that
    /// declares a category is a descriptor row and its schema must be one
    /// the operator UI can render -- the same invariants the teamserver's
    /// registry enforces at registration, stated here so a bad manifest is
    /// refused at publish, before it ships. A row carrying descriptor fields
    /// without a category is the mixed shape the loading paths refuse:
    /// named, so the author sees the anchor the row is missing.
    /// </summary>
    private void AppendDescriptorErrors(VerbDeclaration verb, int index, List<string> errors)
    {
        var hasDescriptorFields = verb.Opsec is not null || verb.Parameters is not null || verb.Output is not null;
        if (verb.Category is null)
        {
            if (hasDescriptorFields)
                errors.Add(
                    $"verbs[{index}] '{verb.Name}' carries descriptor fields but no category; a row that declares its " +
                    "server-side half names the category (the anchor that makes it a descriptor row).");
            return;
        }

        if (!ManifestVocabularies.IsCategory(verb.Category))
            errors.Add(
                $"verbs[{index}] '{verb.Name}' category '{verb.Category}' is not a capability category; "
                + $"the vocabulary is: {string.Join(", ", ManifestVocabularies.Categories)}.");

        // The per-verb OPSEC attribute flags: free-form keys the operator UI
        // badges, so the shape rules are the canonical form's own (single
        // line, no commas), nothing more -- the vocabulary stays open the way
        // the descriptor's attribute dictionary is.
        foreach (var flag in verb.Opsec ?? EmptyFlags)
        {
            if (flag.Key.Length == 0 || flag.Key.Contains('\n') || flag.Key.Contains('\r') || flag.Key.Contains(','))
                errors.Add($"verbs[{index}] '{verb.Name}' opsec flag '{flag.Key}' must be a single line with no commas.");
        }

        if (verb.Output is { } output)
        {
            if (!ManifestVocabularies.IsOutputKind(output.Kind))
                errors.Add(
                    $"verbs[{index}] '{verb.Name}' output-kind '{output.Kind}' is not an output kind; "
                    + $"the vocabulary is: {string.Join(", ", ManifestVocabularies.OutputKinds)}.");
            if ((output.Help ?? "").Contains('\n') || (output.Help ?? "").Contains('\r'))
                errors.Add($"verbs[{index}] '{verb.Name}' output-help must be a single line (it participates in the signed canonical form).");
        }

        // The parameter schema: the UI renders it verbatim, so the registry's
        // own rendering invariants (unique names, a label, a choice set on
        // enums, trailing only last) refuse the manifest here, at publish,
        // with the row named.
        var names = new HashSet<string>(StringComparer.Ordinal);
        for (var p = 0; p < (verb.Parameters?.Count ?? 0); p++)
        {
            var parameter = verb.Parameters![p];
            if (string.IsNullOrWhiteSpace(parameter.Name))
                errors.Add($"verbs[{index}].parameters[{p}].name is required.");
            else if (!names.Add(parameter.Name))
                errors.Add($"verbs[{index}] declares the parameter '{parameter.Name}' twice.");
            if (string.IsNullOrWhiteSpace(parameter.Label))
                errors.Add($"verbs[{index}] parameter '{parameter.Name}' needs a label.");
            if (!ManifestVocabularies.IsParameterKind(parameter.Kind))
                errors.Add(
                    $"verbs[{index}] parameter '{parameter.Name}' kind '{parameter.Kind}' is not a parameter kind; "
                    + $"the vocabulary is: {string.Join(", ", ManifestVocabularies.ParameterKinds)}.");

            foreach (var (field, value) in new[]
                     {
                         ("label", parameter.Label),
                         ("help", parameter.Help ?? ""),
                         ("placeholder", parameter.Placeholder ?? ""),
                     })
            {
                if (value.Contains('\n') || value.Contains('\r'))
                    errors.Add($"verbs[{index}] parameter '{parameter.Name}' {field} must be a single line (it participates in the signed canonical form).");
            }

            if (parameter.Kind == "enum" && (parameter.Choices is not { Count: > 0 }))
                errors.Add($"verbs[{index}] parameter '{parameter.Name}' is an enum and needs at least one choice.");
            var seenChoices = new HashSet<string>(StringComparer.Ordinal);
            foreach (var choice in parameter.Choices ?? [])
            {
                if (choice.Length == 0 || choice.Contains('\n') || choice.Contains('\r') || choice.Contains(','))
                    errors.Add($"verbs[{index}] parameter '{parameter.Name}' choice '{choice}' must be a single line with no commas.");
                else if (!seenChoices.Add(choice))
                    errors.Add($"verbs[{index}] parameter '{parameter.Name}' carries the choice '{choice}' twice.");
            }

            if (parameter.Trailing && p != (verb.Parameters?.Count ?? 0) - 1)
                errors.Add($"verbs[{index}] parameter '{parameter.Name}' is trailing but not last; only the final parameter may take the raw remainder.");
        }
    }

    private static readonly IReadOnlyDictionary<string, bool> EmptyFlags =
        new Dictionary<string, bool>();
}
