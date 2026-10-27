using System.Text.Json;

namespace Rod.Architecture.Tests;

/// <summary>
/// Encodes the in-tree module host rules (architecture.md Sec 15.1,
/// ADR-001, ADR-018): the reference modules under <c>modules/</c> are pure
/// descriptor manifests -- their verb rows carry the whole server-side half
/// -- and reach the process through exactly the path an operator's external
/// module takes: the directory listed under
/// <c>Capabilities:DescriptorModules</c>, read by the descriptor loader.
/// The rules must hold: the tree ships no server-module assemblies (the
/// .NET halves are gone and no dual shape grows back); every in-tree verb
/// row carries its category (a listed module is whole); the shipped
/// configuration lists exactly the in-tree descriptor modules, so what
/// ships, loads; and the tree carries at least one, so the in-tree path is
/// exercised, not merely permitted. The asset-module rules ride beside
/// them, unchanged by ADR-018: content ships as file trees under
/// <c>Capabilities:AssetModules</c>.
/// </summary>
public class ModuleBoundaryTests
{
    private static readonly string RepoRoot = FindRepoRoot(new DirectoryInfo(AppContext.BaseDirectory));

    private static string FindRepoRoot(DirectoryInfo start)
    {
        DirectoryInfo? dir = start;
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src"))
                && Directory.Exists(Path.Combine(dir.FullName, "tests")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not locate the repo root from the test assembly.");
    }

    // Descriptor modules (the server halves, ADR-018) and asset modules
    // (the content halves, Sec 15.1) are both directories under modules/
    // carrying a rod-module.toml, told apart by the entry kind. Recognized
    // by a manifest line scan, deliberately -- the architecture tests read
    // the tree, they do not link the tooling.
    private static readonly string[] DescriptorModuleDirectories = Directory
        .GetDirectories(Path.Combine(RepoRoot, "modules"))
        .Where(directory => File.Exists(Path.Combine(directory, "rod-module.toml"))
            && !File.ReadAllLines(Path.Combine(directory, "rod-module.toml"))
                .Any(line => line.Trim().Equals("entry = \"assets\"", StringComparison.OrdinalIgnoreCase)))
        .OrderBy(directory => directory)
        .ToArray();

    private static readonly string[] AssetModuleDirectories = Directory
        .GetDirectories(Path.Combine(RepoRoot, "modules"))
        .Where(directory => File.Exists(Path.Combine(directory, "rod-module.toml"))
            && File.ReadAllLines(Path.Combine(directory, "rod-module.toml"))
                .Any(line => line.Trim().Equals("entry = \"assets\"", StringComparison.OrdinalIgnoreCase)))
        .OrderBy(directory => directory)
        .ToArray();

    private static JsonDocument ShippedSettings()
        => JsonDocument.Parse(
            File.ReadAllText(Path.Combine(
                RepoRoot, "src", "teamserver", "Rod.TeamServer", "appsettings.json")),
            new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });

    // The tree ships no server-module assemblies: the thirteen .NET halves
    // were pure descriptors and migrated to their manifests (ADR-018), and
    // no dual shape -- a manifest beside the assembly it replaced -- grows
    // back. An external assembly module remains legal; it just ships
    // outside this tree, and the config-listed assembly path
    // (Capabilities:Modules) stays the seam it loads through.
    [Fact]
    public void TheTree_ShipsNoServerModuleAssemblies()
    {
        var offenders = new List<string>();
        foreach (var directory in Directory.GetDirectories(Path.Combine(RepoRoot, "modules")))
        {
            var module = Path.GetFileName(directory);
            foreach (var file in Directory.GetFiles(directory, "*", SearchOption.TopDirectoryOnly))
            {
                var extension = Path.GetExtension(file);
                if (extension is ".cs" or ".csproj" or ".dll")
                    offenders.Add($"{module}/{Path.GetFileName(file)}");
            }
        }

        Assert.True(offenders.Count == 0,
            "modules/ ships server-module assemblies; the server halves are pure descriptor " +
            "manifests (ADR-018): " + string.Join(", ", offenders));
    }

    // The assembly list the shipped configuration carries is empty to match:
    // a stale entry would abort startup on an assembly the tree no longer
    // builds (the what-ships-loads rule), and an in-tree assembly listed
    // here would be the dual shape the rule above refuses.
    [Fact]
    public void ShippedConfig_ListsNoAssemblyModules()
    {
        using var document = ShippedSettings();
        var listed = document.RootElement
            .GetProperty("Capabilities").GetProperty("Modules")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.True(listed.Count == 0,
            "The shipped Capabilities:Modules list carries assembly entries while modules/ ships " +
            $"no assemblies: [{string.Join(", ", listed)}].");
    }

    // What ships, loads: every descriptor module under modules/ is named in
    // the shipped Capabilities:DescriptorModules list (the in-tree set rides
    // the operator's config path by default), and every named entry
    // corresponds to a module that exists -- a removed or renamed module
    // leaves no stale entry behind that would abort startup.
    [Fact]
    public void ShippedConfig_ListsExactlyTheInTreeDescriptorModules()
    {
        using var document = ShippedSettings();
        var listed = document.RootElement
            .GetProperty("Capabilities").GetProperty("DescriptorModules")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();
        var inTree = DescriptorModuleDirectories
            .Select(directory => "modules/" + Path.GetFileName(directory))
            .ToList();

        Assert.True(!listed.Except(inTree).Any() && !inTree.Except(listed).Any(),
            "The shipped Capabilities:DescriptorModules list and the descriptor modules under modules/ disagree: "
            + $"shipped [{string.Join(", ", listed)}] vs tree [{string.Join(", ", inTree)}].");
    }

    // A module listed under the descriptor path must be whole (the loader's
    // own refusal, pinned at the tree level): every [[verbs]] row in an
    // in-tree descriptor module carries its category, so no half-describe
    // module ships -- a row without one would gate its siblings' verbs and
    // silently skip its own.
    [Fact]
    public void DescriptorModules_DeclareWholeVerbRows()
    {
        foreach (var directory in DescriptorModuleDirectories)
        {
            var module = Path.GetFileName(directory);
            var manifest = File.ReadAllLines(Path.Combine(directory, "rod-module.toml"));

            var rows = 0;
            for (var i = 0; i < manifest.Length; i++)
            {
                if (!manifest[i].Trim().Equals("[[verbs]]", StringComparison.OrdinalIgnoreCase))
                    continue;
                rows++;
                var category = ReadKeyValue(manifest, i + 1, "category");
                Assert.False(category is null,
                    $"{module}'s [[verbs]] row at line {i + 1} carries no category; a descriptor " +
                    "module's every row declares its server-side half.");
            }

            Assert.True(rows > 0, $"{module} declares no [[verbs]] rows.");
        }
    }

    // The host is real only while it hosts something: an empty modules/
    // tree would pass every rule above while exercising none of them.
    [Fact]
    public void TheTree_CarriesAtLeastOneDescriptorModule()
    {
        Assert.True(DescriptorModuleDirectories.Length > 0,
            "modules/ holds no descriptor module; the descriptor-module loader would be dead code.");
    }

    // The same what-ships-loads rule for the content half: every asset module
    // under modules/ is named in the shipped Capabilities:AssetModules list
    // (the in-tree set rides the operator's config path by default), and
    // every named entry corresponds to an asset module that exists -- a
    // removed module must not leave a stale entry that aborts startup, and a
    // new module that is not listed is content the shipped server cannot
    // serve. Entries are module directory paths relative to the application
    // base, so "modules/<name>" is the in-tree spelling.
    [Fact]
    public void ShippedConfig_ListsExactlyTheInTreeAssetModules()
    {
        using var document = ShippedSettings();
        var listed = document.RootElement
            .GetProperty("Capabilities").GetProperty("AssetModules")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();
        var inTree = AssetModuleDirectories
            .Select(directory => "modules/" + Path.GetFileName(directory))
            .ToList();

        Assert.True(!listed.Except(inTree).Any() && !inTree.Except(listed).Any(),
            "The shipped Capabilities:AssetModules list and the asset modules under modules/ disagree: "
            + $"shipped [{string.Join(", ", listed)}] vs tree [{string.Join(", ", inTree)}].");
    }

    // A declared asset must be present in the tree it ships in, and its path
    // must stay inside the module directory -- the no-escape rule the host,
    // the manifest validator, and the installer each enforce on their side.
    // One fact over the whole set (small by design): the shipped-config rule
    // above holds the set and the shipped list to the same shape.
    [Fact]
    public void AssetModules_DeclareFilesThatExistInside()
    {
        foreach (var directory in AssetModuleDirectories)
        {
            var name = Path.GetFileName(directory);
            var manifest = File.ReadAllLines(Path.Combine(directory, "rod-module.toml"));

            var declared = new List<(string Name, string Path)>();
            for (var i = 0; i < manifest.Length; i++)
            {
                if (!manifest[i].Trim().Equals("[[assets]]", StringComparison.OrdinalIgnoreCase))
                    continue;
                var assetName = ReadKeyValue(manifest, i + 1, "name");
                var assetPath = ReadKeyValue(manifest, i + 1, "path");
                if (assetName is null || assetPath is null)
                    continue; // the host and the CLI both refuse this loudly at load
                declared.Add((assetName, assetPath));
            }

            Assert.True(declared.Count > 0, $"{name} declares no [[assets]] rows.");
            foreach (var (assetName, assetPath) in declared)
            {
                Assert.False(
                    assetPath.Contains('\\') || Path.IsPathRooted(assetPath)
                        || assetPath.Split('/').Any(segment => segment is ".." or ""),
                    $"{name}'s asset '{assetName}' carries the escaping path '{assetPath}'.");
                Assert.True(
                    File.Exists(Path.Combine(directory, assetPath.Replace('/', Path.DirectorySeparatorChar))),
                    $"{name} declares '{assetName}' at '{assetPath}', but the file is missing.");
            }
        }
    }

    // The content half's own liveness rule: an empty asset-module set would
    // pass the shipped-config and declaration rules while exercising none
    // of the seam, exactly as an empty modules/ tree would for descriptors.
    [Fact]
    public void TheTree_CarriesAtLeastOneAssetModule()
    {
        Assert.True(AssetModuleDirectories.Length > 0,
            "modules/ holds no asset module; the asset-module host would be dead code.");
    }

    // The kernel half of the layering: a kernel assembly embeds no script or
    // template assets -- content that chases browser versions or the SMTP
    // ecosystem belongs in the module layer (Sec 15.1), and an embedded
    // resource is how it used to ship. Kernel data files (the ATT&CK
    // catalog's JSON) are not content assets and stay.
    [Fact]
    public void KernelAssemblies_EmbedNoScriptOrTemplateAssets()
    {
        var offenders = new List<string>();
        foreach (var projectFile in Directory.GetFiles(
                     Path.Combine(RepoRoot, "src", "teamserver"), "*.csproj", SearchOption.AllDirectories))
        {
            var project = Path.GetFileNameWithoutExtension(projectFile)!;
            foreach (var element in System.Xml.Linq.XDocument.Load(projectFile).Descendants()
                         .Where(e => e.Name.LocalName == "EmbeddedResource"))
            {
                var include = (string?)element.Attribute("Include")?.Value ?? "";
                var extension = Path.GetExtension(include).ToLowerInvariant();
                if (extension is ".js" or ".html" or ".htm" or ".txt" or ".md")
                    offenders.Add($"{project}: {include}");
            }
        }

        Assert.True(offenders.Count == 0,
            "Kernel projects embed script/template assets; they ship as asset modules under modules/: "
            + string.Join(", ", offenders));
    }

    // Reads `key = "value"` from the lines after a table header, before the
    // next table starts.
    private static string? ReadKeyValue(string[] lines, int start, string key)
    {
        for (var i = start; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.StartsWith('['))
                return null;
            if (line.StartsWith(key + " =", StringComparison.OrdinalIgnoreCase)
                && line.Length > key.Length + 3)
            {
                var value = line[(key.Length + 3)..].Trim();
                return value.StartsWith('"') && value.EndsWith('"') && value.Length >= 2
                    ? value[1..^1]
                    : null;
            }
        }
        return null;
    }
}
