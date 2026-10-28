using Microsoft.Extensions.Configuration;
using Rod.Capabilities.Modules;
using Rod.Packaging;

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
/// a checked-out module, a hand-written manifest) and lists it. The manifest
/// parses through Rod.Packaging, the one implementation of the grammar the
/// rod CLI also parses with -- the host never states the contract twice.
/// Only the manifest fields the host registers are read; the signed chain
/// an installed module rode re-proves its bytes offline through
/// <c>rod mod verify</c>. A module listed here must be whole: every verb row
/// carries its category (a descriptor row), because a module that gates some
/// of its verbs and not others is the "registered but not what the operator
/// deployed" state a red team cannot afford. Version-only rows belong to a
/// module whose server half is an assembly, listed under
/// <c>Capabilities:Modules</c> instead.
/// </para>
/// <para>
/// Failures are loud, matching the assembly loader: a listed directory that
/// is missing, a manifest that does not parse or validate, an unknown
/// category, kind, or output-kind name, a row without its descriptor, or a
/// parameter schema the registry's own validation refuses each abort
/// startup. Last registration wins, so a later list entry replaces an
/// earlier one's verbs -- the authority rule every module seam applies.
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
        var manifestPath = Path.Combine(directory, ManifestToml.FileName);
        if (!File.Exists(manifestPath))
            throw new InvalidOperationException(
                $"Descriptor module directory '{directory}' carries no {ManifestToml.FileName}; an entry in " +
                $"'{DescriptorModulesSectionKey}' must name a module directory.");

        var (manifest, errors) = ManifestToml.LoadFile(manifestPath);
        if (manifest is null)
            throw new InvalidOperationException(
                $"Descriptor module manifest '{manifestPath}' does not parse: {string.Join(" ", errors)}");

        if (manifest.Verbs.Count == 0)
            throw new InvalidOperationException(
                $"Descriptor module '{manifest.Name}' ({manifestPath}) declares no [[verbs]] rows; a descriptor module " +
                "registers the verbs its rows describe.");

        foreach (var row in manifest.Verbs)
            await registry.RegisterAsync(ToModule(manifestPath, manifest.Name, manifest.Requires, row), cancellationToken);
    }

    // One verb row becomes one registration -- the same one-descriptor shape
    // the placeholder load and the assembly loader register, so a module
    // with several verbs replaces (or opens) each verb it declares.
    private static ICapabilityModule ToModule(
        string manifestPath, string name, IReadOnlyList<string> requires, VerbDeclaration row)
    {
        if (row.Category is not { } categoryText)
            throw new InvalidOperationException(
                $"Descriptor module '{name}' ({manifestPath}): verb '{row.Name}' carries no category. A module listed " +
                $"under '{DescriptorModulesSectionKey}' must be whole -- every row declares its server-side half " +
                "(a descriptor row); version-only rows belong to an assembly module listed under Capabilities:Modules.");

        if (!TryParseName<CapabilityCategory>(categoryText, out var category))
            throw new InvalidOperationException(
                $"Descriptor module '{name}' ({manifestPath}): verb '{row.Name}' category '{categoryText}' is not a " +
                "capability category.");

        var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var flag in row.Opsec ?? EmptyFlags)
            attributes[flag.Key.Trim()] = flag.Value ? "true" : "false";

        var parameters = new List<VerbParameter>();
        foreach (var parameter in row.Parameters ?? [])
            parameters.Add(ToParameter(manifestPath, name, row.Name, parameter));

        VerbOutput? output = null;
        if (row.Output is { } declaredOutput)
        {
            if (!TryParseName(declaredOutput.Kind, out VerbOutputKind kind))
                throw new InvalidOperationException(
                    $"Descriptor module '{name}' ({manifestPath}): verb '{row.Name}' output-kind '{declaredOutput.Kind}' is not an " +
                    "output kind.");
            output = new VerbOutput(kind, declaredOutput.Help);
        }

        return new ManifestDescriptorModule(
            CapabilityDescriptor.Of(
                row.Name,
                category,
                row.Version.ToString(),
                attributes,
                parameters,
                output,
                row.Techniques?.ToList() ?? []),
            name,
            requires);
    }

    private static VerbParameter ToParameter(string manifestPath, string name, string verb, VerbParameterDeclaration parameter)
    {
        if (!TryParseName(parameter.Kind, out VerbParameterKind kind))
            throw new InvalidOperationException(
                $"Descriptor module '{name}' ({manifestPath}): verb '{verb}' parameter '{parameter.Name}' kind " +
                $"'{parameter.Kind}' is not a parameter kind.");

        return new VerbParameter(
            parameter.Name,
            parameter.Label,
            kind,
            parameter.Required,
            parameter.Help,
            parameter.Placeholder,
            parameter.Choices?.ToList() ?? [],
            parameter.Trailing,
            parameter.Inline);
    }

    // The manifest names vocabulary members in lowercase kebab (Rod.Packaging's
    // grammar); the enums name them in PascalCase. Matching ignores case and
    // separators, so "process-list" resolves VerbOutputKind.ProcessList --
    // the two spellings of one closed set, pinned equal by a test.
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

    private static readonly IReadOnlyDictionary<string, bool> EmptyFlags =
        new Dictionary<string, bool>();
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
