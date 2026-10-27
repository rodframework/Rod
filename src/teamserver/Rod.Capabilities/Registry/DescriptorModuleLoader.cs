using Microsoft.Extensions.Configuration;
using Rod.Capabilities.Modules;
using Tomlyn;
using Tomlyn.Serialization;

namespace Rod.Capabilities.Registry;

/// <summary>
/// Loads config-listed descriptor modules from the
/// <c>Capabilities:DescriptorModules</c> configuration list (architecture.md
/// Sec 15.2, ADR-018) -- the zero-.NET loading path beside
/// <see cref="CapabilityModuleLoader"/>: each entry is a module directory
/// whose <c>rod-module.toml</c> verb rows carry their whole server-side half
/// as manifest data (category, OPSEC flags, parameter schema, output
/// declaration), so a novel namespace opens its issuance gate with no
/// assembly at all. The server-side twin of the plugin seam's language
/// freedom: any text editor is the toolchain.
/// </summary>
/// <remarks>
/// <para>
/// The seam is files, exactly the shape <see cref="ModuleAssetStore"/> reads
/// for asset modules: an operator drops a directory (an installed package,
/// a checked-out module, a hand-written manifest) and lists it. Only the
/// manifest fields the host registers are read; the full manifest grammar --
/// packaging, signing, the registry catalog -- stays the CLI's
/// (architecture.md Sec 15.2), and the signed chain an installed module rode
/// re-proves its bytes offline through <c>rod mod verify</c>. A module listed
/// here must be whole: every verb row carries its category (a descriptor
/// row), because a module that gates some of its verbs and not others is the
/// "registered but not what the operator deployed" state a red team cannot
/// afford. Version-only rows belong to a module whose server half is an
/// assembly, listed under <c>Capabilities:Modules</c> instead.
/// </para>
/// <para>
/// Failures are loud, matching the assembly loader: a listed directory that
/// is missing, a manifest that does not parse, an unknown category, kind, or
/// output-kind name, a row without its descriptor, or a parameter schema the
/// registry's own validation refuses each abort startup. Last registration
/// wins, so a later list entry replaces an earlier one's verbs -- the
/// authority rule every module seam applies.
/// </para>
/// </remarks>
public static class DescriptorModuleLoader
{
    /// <summary>The configuration key the descriptor module directory list
    /// lives under.</summary>
    public const string DescriptorModulesSectionKey = "Capabilities:DescriptorModules";

    /// <summary>
    /// Loads and registers every descriptor module listed under
    /// <c>Capabilities:DescriptorModules</c> in <paramref name="configuration"/>.
    /// A missing section is an empty list -- the same open-not-on default
    /// every module seam keeps until an operator opts in.
    /// </summary>
    public static async Task LoadAsync(
        IConfiguration configuration,
        ICapabilityRegistry registry,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(registry);

        var entries = configuration.GetSection(DescriptorModulesSectionKey).Get<string[]?>() ?? Array.Empty<string>();
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry))
                throw new InvalidOperationException(
                    $"An entry in '{DescriptorModulesSectionKey}' is empty; each entry must be a module directory path.");

            await LoadModuleAsync(Rooted(entry.Trim()), registry, cancellationToken);
        }
    }

    // A relative entry names a directory beside the binary (the shape the
    // shipped configuration and the teamserver's deploy step produce); an
    // absolute one names any directory on the host -- the same rooting rule
    // the asset store applies.
    private static string Rooted(string path)
        => Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);

    /// <summary>
    /// Parses one module directory's manifest and registers a module per
    /// descriptor row. Public so tests and tooling can exercise a single
    /// directory without building a whole configuration; the composition
    /// root calls <see cref="LoadAsync"/>.
    /// </summary>
    public static async Task LoadModuleAsync(
        string directory,
        ICapabilityRegistry registry,
        CancellationToken cancellationToken = default)
    {
        var manifestPath = Path.Combine(directory, ManifestFileName);
        if (!File.Exists(manifestPath))
            throw new InvalidOperationException(
                $"Descriptor module directory '{directory}' carries no {ManifestFileName}; an entry in " +
                $"'{DescriptorModulesSectionKey}' must name a module directory.");

        Document? parsed;
        try
        {
            parsed = TomlSerializer.Deserialize<Document>(
                File.ReadAllText(manifestPath), new TomlSerializerOptions());
        }
        catch (TomlException failure)
        {
            throw new InvalidOperationException(
                $"Descriptor module manifest '{manifestPath}' does not parse: {failure.Message}.");
        }
        var document = parsed ?? throw new InvalidOperationException(
            $"Descriptor module manifest '{manifestPath}' did not deserialize.");

        var name = (document.Module?.Name ?? "").Trim();
        var requires = (document.Compatibility?.Requires ?? [])
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => r.Trim())
            .ToList();
        var rows = document.Verbs ?? [];

        if (name.Length == 0)
            throw new InvalidOperationException(
                $"Descriptor module manifest '{manifestPath}' carries no [module] name; the catalog and the " +
                "module.load requirement gate resolve modules by name.");
        if (rows.Count == 0)
            throw new InvalidOperationException(
                $"Descriptor module '{name}' ({manifestPath}) declares no [[verbs]] rows; a descriptor module " +
                "registers the verbs its rows describe.");

        foreach (var row in rows)
            await registry.RegisterAsync(ToModule(manifestPath, name, requires, row), cancellationToken);
    }

    // One verb row becomes one registration -- the same one-descriptor shape
    // the placeholder load and the assembly loader register, so a module
    // with several verbs replaces (or opens) each verb it declares.
    private static ICapabilityModule ToModule(
        string manifestPath, string name, IReadOnlyList<string> requires, VerbRow row)
    {
        var verb = (row.Name ?? "").Trim();
        if (verb.Length == 0)
            throw new InvalidOperationException(
                $"Descriptor module '{name}' ({manifestPath}) carries a [[verbs]] row without a name.");

        var categoryText = (row.Category ?? "").Trim();
        if (categoryText.Length == 0)
            throw new InvalidOperationException(
                $"Descriptor module '{name}' ({manifestPath}): verb '{verb}' carries no category. A module listed " +
                $"under '{DescriptorModulesSectionKey}' must be whole -- every row declares its server-side half " +
                "(a descriptor row); version-only rows belong to an assembly module listed under Capabilities:Modules.");

        if (!TryParseName<CapabilityCategory>(categoryText, out var category))
            throw new InvalidOperationException(
                $"Descriptor module '{name}' ({manifestPath}): verb '{verb}' category '{categoryText}' is not a " +
                "capability category.");

        var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var flag in row.Opsec ?? new Dictionary<string, bool>())
            attributes[flag.Key.Trim()] = flag.Value ? "true" : "false";

        var parameters = new List<VerbParameter>();
        foreach (var parameter in row.Parameters ?? [])
            parameters.Add(ToParameter(manifestPath, name, verb, parameter));

        VerbOutput? output = null;
        var outputKind = (row.OutputKind ?? "").Trim();
        if (outputKind.Length > 0)
        {
            if (!TryParseName(outputKind, out VerbOutputKind kind))
                throw new InvalidOperationException(
                    $"Descriptor module '{name}' ({manifestPath}): verb '{verb}' output-kind '{outputKind}' is not " +
                    "an output kind.");
            output = new VerbOutput(kind, NullOrTrimmed(row.OutputHelp));
        }

        var version = (row.Version ?? "").Trim();
        var techniques = (row.Techniques ?? [])
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t.Trim().ToUpperInvariant())
            .ToList();

        return new ManifestDescriptorModule(
            CapabilityDescriptor.Of(
                verb,
                category,
                version.Length > 0 ? version : "0.0",
                attributes,
                parameters,
                output,
                techniques),
            name,
            requires);
    }

    private static VerbParameter ToParameter(string manifestPath, string name, string verb, ParameterRow parameter)
    {
        var parameterName = (parameter.Name ?? "").Trim();
        if (!TryParseName((parameter.Kind ?? "").Trim(), out VerbParameterKind kind))
            throw new InvalidOperationException(
                $"Descriptor module '{name}' ({manifestPath}): verb '{verb}' parameter '{parameterName}' kind " +
                $"'{parameter.Kind}' is not a parameter kind.");

        return new VerbParameter(
            parameterName,
            (parameter.Label ?? "").Trim(),
            kind,
            parameter.Required ?? false,
            NullOrTrimmed(parameter.Help),
            NullOrTrimmed(parameter.Placeholder),
            (parameter.Choices ?? []).Where(c => !string.IsNullOrWhiteSpace(c)).Select(c => c.Trim()).ToList(),
            parameter.Trailing ?? false,
            parameter.Inline ?? true);
    }

    // The manifest names vocabulary members in lowercase kebab (the CLI's
    // grammar); the enums name them in PascalCase. Matching ignores case and
    // separators, so "process-list" resolves VerbOutputKind.ProcessList --
    // the two spellings of one closed set, pinned equal by a CLI test.
    private static bool TryParseName<T>(string text, out T value) where T : struct, Enum
    {
        var normalized = text.Replace("-", "").Replace("_", "");
        foreach (var candidate in Enum.GetNames<T>())
        {
            if (candidate.Replace("_", "").Equals(normalized, StringComparison.OrdinalIgnoreCase))
                return Enum.TryParse<T>(candidate, out value);
        }

        value = default;
        return false;
    }

    private static string? NullOrTrimmed(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private const string ManifestFileName = "rod-module.toml";

    // The manifest subset the host registers: the module's name and
    // requirement rows plus each verb row's descriptor half. The full
    // grammar stays the CLI's (architecture.md Sec 15.2); unknown keys are
    // ignored, so a manifest written for a newer toolchain still loads.
    private sealed class Document
    {
        [TomlPropertyName("module")]
        public ModuleSection? Module { get; set; }

        [TomlPropertyName("compatibility")]
        public CompatibilitySection? Compatibility { get; set; }

        [TomlPropertyName("verbs")]
        public List<VerbRow>? Verbs { get; set; }
    }

    private sealed class ModuleSection
    {
        [TomlPropertyName("name")] public string? Name { get; set; }
    }

    private sealed class CompatibilitySection
    {
        [TomlPropertyName("requires")] public List<string>? Requires { get; set; }
    }

    private sealed class VerbRow
    {
        [TomlPropertyName("name")] public string? Name { get; set; }
        [TomlPropertyName("version")] public string? Version { get; set; }
        [TomlPropertyName("techniques")] public List<string>? Techniques { get; set; }
        [TomlPropertyName("category")] public string? Category { get; set; }
        [TomlPropertyName("opsec")] public Dictionary<string, bool>? Opsec { get; set; }
        [TomlPropertyName("output-kind")] public string? OutputKind { get; set; }
        [TomlPropertyName("output-help")] public string? OutputHelp { get; set; }
        [TomlPropertyName("parameters")] public List<ParameterRow>? Parameters { get; set; }
    }

    private sealed class ParameterRow
    {
        [TomlPropertyName("name")] public string? Name { get; set; }
        [TomlPropertyName("label")] public string? Label { get; set; }
        [TomlPropertyName("kind")] public string? Kind { get; set; }
        [TomlPropertyName("required")] public bool? Required { get; set; }
        [TomlPropertyName("help")] public string? Help { get; set; }
        [TomlPropertyName("placeholder")] public string? Placeholder { get; set; }
        [TomlPropertyName("choices")] public List<string>? Choices { get; set; }
        [TomlPropertyName("trailing")] public bool? Trailing { get; set; }
        [TomlPropertyName("inline")] public bool? Inline { get; set; }
    }
}

/// <summary>
/// The module a manifest's descriptor row becomes (architecture.md Sec 15.2,
/// ADR-018): the descriptor, the published name, and the requirement rows,
/// all read from the manifest -- a registration-only module with no code
/// behind it, indistinguishable from an assembly module at the registry,
/// the catalog, and the runtime gates.
/// </summary>
public sealed class ManifestDescriptorModule : ICapabilityModule
{
    public ManifestDescriptorModule(
        CapabilityDescriptor descriptor,
        string? name = null,
        IReadOnlyList<string>? requires = null)
    {
        Descriptor = descriptor;
        Name = name;
        Requires = requires;
    }

    public CapabilityDescriptor Descriptor { get; }

    public string? Name { get; }

    public IReadOnlyList<string>? Requires { get; }
}
