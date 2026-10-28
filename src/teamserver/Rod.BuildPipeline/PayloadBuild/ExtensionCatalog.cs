using System.Text.RegularExpressions;
using Rod.CoreState.Implants;
using Rod.Packaging;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// One extension an artifact compiles in (ADR-022): the installed package's
/// name, its directory on this host, and the verbs its manifest registers --
/// the overlay a build unit consumes and the bake advertises.
/// </summary>
public sealed record ExtensionOverlay(
    string Name,
    string Directory,
    IReadOnlyList<string> Verbs);

/// <summary>
/// The installed-extension catalog (ADR-022): the build-time half of the
/// extension seam. Extension packages -- implant-native crates a build unit
/// compiles into the artifact, with the implant's own internals in reach --
/// are listed under <c>Build:Extensions</c> exactly the way descriptor
/// modules are listed under <c>Capabilities:DescriptorModules</c>: an
/// explicit config list of installed package directories, each carrying a
/// manifest whose entry is <c>extension</c> and whose target rows name the
/// build units it compiles into. A build request that names extensions
/// resolves them here; the targeting rows are the hard gate (an extension
/// that does not target the request's unit is refused, named), and the verb
/// guards mirror the runtime plugin loader's own: the namespace grammar, no
/// channel verb, and no verb a kernel already owns.
/// </summary>
public sealed class ExtensionCatalog
{
    /// <summary>The configuration key the installed extension directory list
    /// lives under.</summary>
    public const string ExtensionsSectionKey = "Build:Extensions";

    private static readonly Regex VerbPattern = new("^[a-z0-9][a-z0-9_-]*\\.[a-z0-9][a-z0-9_-]*$", RegexOptions.Compiled);

    private readonly Dictionary<string, InstalledExtension> _extensions =
        new(StringComparer.OrdinalIgnoreCase);

    private sealed record InstalledExtension(ModuleManifest Manifest, string Directory);

    private ExtensionCatalog()
    {
    }

    /// <summary>
    /// Loads every extension listed under <c>Build:Extensions</c> in
    /// <paramref name="directories"/>. A missing or empty list is the empty
    /// catalog -- the open-not-on default; anything listed but broken throws,
    /// naming the package and the field.
    /// </summary>
    public static ExtensionCatalog Load(IEnumerable<string> directories)
    {
        var catalog = new ExtensionCatalog();
        foreach (var entry in directories)
        {
            if (string.IsNullOrWhiteSpace(entry))
                throw new InvalidOperationException(
                    $"An entry in '{ExtensionsSectionKey}' is empty; each entry must be an extension package directory.");

            var directory = Path.GetFullPath(entry.Trim());
            var manifestPath = Path.Combine(directory, ManifestToml.FileName);
            if (!File.Exists(manifestPath))
                throw new InvalidOperationException(
                    $"Extension package directory '{directory}' carries no {ManifestToml.FileName}; an entry in " +
                    $"'{ExtensionsSectionKey}' must name an extension package.");

            var (manifest, errors) = ManifestToml.LoadFile(manifestPath);
            if (manifest is null)
                throw new InvalidOperationException(
                    $"Extension manifest '{manifestPath}' does not parse: {string.Join(" ", errors)}");

            if (manifest.Entry != ModuleEntryKind.Extension)
                throw new InvalidOperationException(
                    $"'{directory}' is a {ModuleEntryKindNames.ToString(manifest.Entry)} package; " +
                    "Build:Extensions lists extension packages only.");

            if (manifest.Verbs.Count == 0)
                throw new InvalidOperationException(
                    $"Extension '{manifest.Name}' ({manifestPath}) declares no [[verbs]] rows; an extension " +
                    "compiles in the verbs its rows register.");

            // The verb guards the runtime plugin loader holds, stated here so
            // a bad extension refuses at resolve time -- before anything
            // compiles -- with the row named.
            foreach (var verb in manifest.Verbs)
            {
                if (!VerbPattern.IsMatch(verb.Name))
                    throw new InvalidOperationException(
                        $"Extension '{manifest.Name}': verb '{verb.Name}' is not a namespaced verb (namespace.action).");
                if (IsChannelVerb(verb.Name))
                    throw new InvalidOperationException(
                        $"Extension '{manifest.Name}': verb '{verb.Name}' is a channel verb; a compiled-in " +
                        "extension cannot own a live channel.");
                if (IsKernelVerb(verb.Name))
                    throw new InvalidOperationException(
                        $"Extension '{manifest.Name}': verb '{verb.Name}' is compiled into this artifact and " +
                        "stays compiled; an extension cannot replace a kernel verb.");
            }

            catalog._extensions[manifest.Name] = new InstalledExtension(manifest, directory);
        }
        return catalog;
    }

    /// <summary>The empty catalog: no request may name an extension.</summary>
    public static ExtensionCatalog Empty { get; } = new();

    /// <summary>Every installed extension, name-sorted -- the picker's
    /// source.</summary>
    public IReadOnlyList<(string Name, string Directory, ModuleManifest Manifest)> All
        => _extensions.Values
            .Select(held => (held.Manifest.Name, held.Directory, held.Manifest))
            .OrderBy(held => held.Name, StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// Resolves the named extensions for a build by <paramref name="unitId"/>:
    /// the hard targeting gate (ADR-022) plus the duplicate-verb check across
    /// extensions -- two crates answering one verb is a staging ambiguity,
    /// not a choice. Throws <see cref="InvalidOperationException"/> naming the
    /// first refusal.
    /// </summary>
    public IReadOnlyList<ExtensionOverlay> Resolve(IReadOnlyList<string> names, string unitId)
    {
        if (names.Count == 0)
            return Array.Empty<ExtensionOverlay>();

        var overlays = new List<ExtensionOverlay>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var verbs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var name in names)
        {
            if (!_extensions.TryGetValue(name, out var held))
                throw new InvalidOperationException(
                    $"No installed extension named '{name}'; list its package directory under " +
                    $"'{ExtensionsSectionKey}' first.");

            var target = held.Manifest.Targets.FirstOrDefault(t =>
                string.Equals(t.BuildUnit, unitId, StringComparison.OrdinalIgnoreCase));
            if (target is null)
                throw new InvalidOperationException(
                    $"Extension '{name}' targets [{string.Join(", ", held.Manifest.Targets.Select(t => t.BuildUnit ?? "?"))}] " +
                    $"and does not compile into unit '{unitId}'.");

            foreach (var verb in held.Manifest.Verbs)
            {
                if (!verbs.Add(verb.Name))
                    throw new InvalidOperationException(
                        $"Extensions '{name}' and an earlier one both register verb '{verb.Name}'; " +
                        "one verb, one extension.");
            }

            overlays.Add(new ExtensionOverlay(
                held.Manifest.Name,
                held.Directory,
                held.Manifest.Verbs.Select(v => v.Name).ToList()));
            seen.Add(held.Manifest.Name);
        }
        return overlays;
    }

    // The channel verbs the session layer owns (the live-channel machinery a
    // plugin or extension cannot reach): the same three CoreState's channel
    // gate carries.
    private static bool IsChannelVerb(string verb)
        => verb is "shell.interact" or "tunnel.forward" or "tunnel.socks";

    // The kernel's own verb surface: any verb any class gate carries, plus
    // the ungated set (the module family included -- module.load/unload/list
    // are the loader's own), which an extension cannot shadow any more than
    // a plugin can.
    private static bool IsKernelVerb(string verb)
        => Enum.GetValues<ImplantClass>()
               .SelectMany(ImplantClassCapabilities.For)
               .Concat(ImplantClassCapabilities.Ungated)
               .Contains(verb);
}
