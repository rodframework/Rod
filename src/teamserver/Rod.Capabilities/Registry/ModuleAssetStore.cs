using Microsoft.Extensions.Configuration;
using Rod.CoreState.Assets;
using Rod.Packaging;

namespace Rod.Capabilities.Registry;

/// <summary>
/// Loads config-listed asset modules from the <c>Capabilities:AssetModules</c>
/// configuration list (architecture.md Sec 15.1) -- the content half of the
/// module layer, the same one path the in-tree reference asset modules and an
/// operator's external ones ride. Each entry is a module directory: it must
/// carry a <c>rod-module.toml</c> whose <c>[module]</c> name and
/// <c>[[assets]]</c> rows name what the directory provides, and every listed
/// asset file is read at startup and indexed by (module name, asset name).
/// </summary>
/// <remarks>
/// <para>
/// The seam is deliberately files, not code: a hook script chases browser
/// versions and a template pack chases the SMTP ecosystem, churn an operator
/// absorbs by dropping a directory and listing it -- no build, no assembly,
/// exactly what the module layer exists to absorb. Only the manifest fields
/// the host needs are read (module name, asset name, asset path); the full
/// manifest grammar stays the CLI's (architecture.md Sec 15.2), and the
/// signed chain an installed module rode re-proves its bytes offline through
/// <c>rod mod verify</c> -- deployment trust is the same trust the assembly
/// loader extends to a dll beside the binary.
/// </para>
/// <para>
/// Failures are loud, matching <see cref="CapabilityModuleLoader"/>: a
/// listed directory that is missing, a manifest that does not parse, an
/// asset path that escapes the module directory, or an asset file that is
/// absent each abort startup. A missing section is an empty store -- the
/// open-not-on default every host keeps until an operator opts in. A module
/// name declared by two listed directories resolves last-listed-wins, the
/// authority rule every module seam applies.
/// </para>
/// </remarks>
public sealed class ModuleAssetStore : IModuleAssetStore
{
    /// <summary>The configuration key the asset module directory list lives under.</summary>
    public const string AssetModulesSectionKey = "Capabilities:AssetModules";

    // "module\nasset" -> bytes+path, case-insensitive to match the registry's
    // own verb lookups: names are kebab-case by the manifest's grammar, and
    // case is not identity. The separator cannot occur in a kebab name.
    private readonly Dictionary<string, ModuleAsset> _assets = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Loads every asset module listed under <c>Capabilities:AssetModules</c>
    /// in <paramref name="configuration"/>. A missing section yields the
    /// empty store; anything listed but broken throws.
    /// </summary>
    public static ModuleAssetStore Load(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var store = new ModuleAssetStore();
        var entries = configuration.GetSection(AssetModulesSectionKey).Get<string[]?>() ?? Array.Empty<string>();
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry))
                throw new InvalidOperationException(
                    $"An entry in '{AssetModulesSectionKey}' is empty; each entry must be a module directory path.");

            store.LoadModule(Rooted(entry.Trim()));
        }
        return store;
    }

    // A relative entry names a directory beside the binary (the shape the
    // shipped configuration and the teamserver's deploy step produce); an
    // absolute one names any directory on the host.
    private static string Rooted(string path)
        => Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);

    public bool TryRead(string moduleName, string assetName, out ModuleAsset asset)
        => _assets.TryGetValue(moduleName + "\n" + assetName, out asset!);

    private void LoadModule(string directory)
    {
        var manifestPath = Path.Combine(directory, ManifestToml.FileName);
        if (!File.Exists(manifestPath))
            throw new InvalidOperationException(
                $"Asset module directory '{directory}' carries no {ManifestToml.FileName}; an entry in '{AssetModulesSectionKey}' must name a module directory.");

        // The same parse every consumer of the manifest performs --
        // Rod.Packaging's one implementation of the grammar, full
        // validation included, so the host's read cannot drift from the
        // CLI's.
        var (manifest, errors) = ManifestToml.LoadFile(manifestPath);
        if (manifest is null)
            throw new InvalidOperationException(
                $"Asset module manifest '{manifestPath}' does not parse: {string.Join(" ", errors)}");

        var name = manifest.Name;
        var rows = manifest.Assets;

        if (rows.Count == 0)
            throw new InvalidOperationException(
                $"Asset module '{name}' ({manifestPath}) declares no [[assets]] rows; a content module names every file it serves.");

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            var assetName = row.Name;
            var assetPath = row.Path;

            // The no-escape rule the manifest validator and the installer's
            // extraction both hold: an asset stays inside its module tree.
            if (assetPath.Contains('\\') || Path.IsPathRooted(assetPath)
                || assetPath.Split('/').Any(segment => segment is ".." or ""))
                throw new InvalidOperationException(
                    $"Asset '{name}/{assetName}' path '{assetPath}' must be a module-relative path with '/' separators and no '..' segments.");
            if (!seen.Add(assetName))
                throw new InvalidOperationException(
                    $"Asset module '{name}' declares the asset '{assetName}' twice.");

            var file = Path.Combine(directory, assetPath.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(file))
                throw new InvalidOperationException(
                    $"Asset module '{name}' declares '{assetName}' at '{assetPath}', but the file is missing from '{directory}'.");

            _assets[name + "\n" + assetName] = new ModuleAsset(File.ReadAllBytes(file), assetPath);
        }
    }
}
