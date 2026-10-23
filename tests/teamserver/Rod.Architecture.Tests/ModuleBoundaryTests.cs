using System.Text.Json;
using System.Xml.Linq;

namespace Rod.Architecture.Tests;

/// <summary>
/// Encodes the in-tree module host rules (architecture.md Sec 15.1, ADR-001):
/// reference modules live under <c>modules/</c> as separate assemblies that
/// reach the process through exactly the path an operator's external module
/// takes -- an assembly beside the binary plus an entry under
/// <c>Capabilities:Modules</c> -- so the tree eats its own dogfood and the
/// seams stay the public contract. Three rules must hold: a server module
/// references the contract project (<c>Rod.Capabilities</c>) and nothing else
/// in-house; no kernel project compile-references a module (the composition
/// root deploys modules, it never references them); and the shipped
/// configuration lists every in-tree module, so what ships, loads. A fourth
/// keeps the host honest: the tree carries at least one reference module, so
/// the in-tree path is exercised, not merely permitted.
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

    // Server module assemblies live at modules/<name>/<Name>.csproj; the
    // module-owned test projects under modules/<name>/tests/ are not module
    // assemblies (they ride along with the module, loading nothing at
    // runtime), so only the top-level project of each module counts.
    private static readonly string[] ServerModuleProjects = Directory
        .GetDirectories(Path.Combine(RepoRoot, "modules"))
        .SelectMany(directory => Directory.GetFiles(directory, "*.csproj"))
        .OrderBy(p => p)
        .ToArray();

    public static IEnumerable<object[]> ServerModuleProjectCases =>
        ServerModuleProjects.Select(p => new object[] { p });

    // Asset modules (Sec 15.1's content half) are directories, not
    // assemblies: a rod-module.toml whose entry kind is "assets" plus the
    // declared files. Recognized by a manifest line scan, deliberately --
    // the architecture tests read the tree, they do not link the tooling.
    private static readonly string[] AssetModuleDirectories = Directory
        .GetDirectories(Path.Combine(RepoRoot, "modules"))
        .Where(directory => File.Exists(Path.Combine(directory, "rod-module.toml"))
            && File.ReadAllLines(Path.Combine(directory, "rod-module.toml"))
                .Any(line => line.Trim().Equals("entry = \"assets\"", StringComparison.OrdinalIgnoreCase)))
        .OrderBy(directory => directory)
        .ToArray();

    private static string[] ReadProjectReferences(string projectFile)
        => XDocument.Load(projectFile).Descendants()
            .Where(e => e.Name.LocalName == "ProjectReference")
            .Select(e => (string?)e.Attribute("Include")?.Value)
            .Where(include => include is not null)
            .Select(include => include!.Replace('\\', '/'))
            .ToArray();

    // A server module couples to the module seam and to nothing else in-house:
    // Rod.Capabilities carries the contract, and any wider reference would
    // weld the module into the kernel -- exactly what the module layer exists
    // to avoid.
    [Theory]
    [MemberData(nameof(ServerModuleProjectCases))]
    public void ServerModules_ReferenceTheContractOnly(string projectFile)
    {
        var project = Path.GetFileNameWithoutExtension(projectFile)!;
        var targets = ReadProjectReferences(projectFile)
            .Select(Path.GetFileNameWithoutExtension)
            .OrderBy(t => t)
            .ToArray();

        var forbidden = targets.Where(t => t != "Rod.Capabilities").ToArray();
        Assert.True(forbidden.Length == 0,
            $"{project} references {string.Join(", ", forbidden)}; a server module may reference " +
            "Rod.Capabilities (the contract) and nothing else in-house.");
    }

    // The dogfood rule: in-tree modules load through the external path, so no
    // kernel project may reference one -- a compile-time edge would make the
    // module a layer participant and quietly retire the loading path the
    // ecosystem depends on. (ProjectReferenceTests would also fail the added
    // edge through its allowed-references matrix; this test names the rule.)
    [Fact]
    public void KernelProjects_NeverReferenceServerModules()
    {
        var violators = new List<string>();
        foreach (var projectFile in Directory.GetFiles(
                     Path.Combine(RepoRoot, "src", "teamserver"), "*.csproj", SearchOption.AllDirectories))
        {
            var project = Path.GetFileNameWithoutExtension(projectFile)!;
            foreach (var include in ReadProjectReferences(projectFile))
            {
                if (include.Contains("/modules/", StringComparison.Ordinal))
                    violators.Add($"{project} -> {include}");
            }
        }

        Assert.True(violators.Count == 0,
            "Kernel projects must not reference in-tree modules (they load through the " +
            "config-listed path): " + string.Join(", ", violators));
    }

    // What ships, loads: every module under modules/ is named in the shipped
    // appsettings.json so the in-tree set rides the operator's config path by
    // default -- and every named entry corresponds to a module that exists,
    // so a removed or renamed module leaves no stale entry behind that would
    // abort startup.
    [Fact]
    public void ShippedConfig_ListsExactlyTheInTreeServerModules()
    {
        var settingsPath = Path.Combine(
            RepoRoot, "src", "teamserver", "Rod.TeamServer", "appsettings.json");
        using var document = JsonDocument.Parse(
            File.ReadAllText(settingsPath),
            new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });

        var listed = document.RootElement
            .GetProperty("Capabilities").GetProperty("Modules")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        // The assembly token follows the last comma, mirroring the loader's
        // own split of a "Namespace.Type, AssemblyName" entry.
        var listedAssemblies = listed
            .Select(entry => entry[(entry.LastIndexOf(',') + 1)..].Trim())
            .OrderBy(a => a)
            .ToList();
        var moduleAssemblies = ServerModuleProjects
            .Select(Path.GetFileNameWithoutExtension)
            .OrderBy(a => a)
            .ToList();

        Assert.True(!listedAssemblies.Except(moduleAssemblies).Any()
                    && !moduleAssemblies.Except(listedAssemblies).Any(),
            "The shipped Capabilities:Modules list and the modules under modules/ disagree: " +
            $"shipped [{string.Join(", ", listedAssemblies)}] vs tree [{string.Join(", ", moduleAssemblies)}].");
    }

    // The host is real only while it hosts something: an empty modules/ tree
    // would pass every rule above while exercising none of them.
    [Fact]
    public void TheTree_CarriesAtLeastOneServerModule()
    {
        Assert.True(ServerModuleProjects.Length > 0,
            "modules/ holds no server module; the in-tree module host would be dead code.");
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
        var settingsPath = Path.Combine(
            RepoRoot, "src", "teamserver", "Rod.TeamServer", "appsettings.json");
        using var document = JsonDocument.Parse(
            File.ReadAllText(settingsPath),
            new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });

        var listed = document.RootElement
            .TryGetProperty("Capabilities", out var capabilities)
            && capabilities.TryGetProperty("AssetModules", out var assetModules)
            ? assetModules.EnumerateArray().Select(e => e.GetString()!).ToList()
            : [];
        var inTree = AssetModuleDirectories
            .Select(directory => "modules/" + Path.GetFileName(directory))
            .ToList();

        Assert.True(!listed.Except(inTree).Any() && !inTree.Except(listed).Any(),
            "The shipped Capabilities:AssetModules list and the asset modules under modules/ disagree: " +
            $"shipped [{string.Join(", ", listed)}] vs tree [{string.Join(", ", inTree)}].");
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
    // of the seam, exactly as an empty modules/ tree would for assemblies.
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
            foreach (var element in XDocument.Load(projectFile).Descendants()
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
