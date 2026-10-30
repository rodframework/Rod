using System.Text.Json;

namespace Rod.Architecture.Tests;

/// <summary>
/// Encodes the module host rules (architecture.md Sec 15.1, ADR-018,
/// ADR-024) as they stand since the reference set left the platform tree:
/// the official modules live in their own repositories and arrive through
/// the ecosystem -- the registry install a deployment consumes -- so this
/// tree carries no module trees at all, and the shipped configuration
/// lists none (a deployment pins its installed set; what ships, loads).
/// The rules must hold: the tree carries no module directories (an
/// in-tree set is the shape the split retired, and it must not grow
/// back); the shipped assembly list is empty to match; and the shipped
/// descriptor and asset lists are empty, so a fresh deployment starts
/// from the default registry instead of a stale in-tree set.
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

    private static JsonDocument ShippedSettings()
        => JsonDocument.Parse(
            File.ReadAllText(Path.Combine(
                RepoRoot, "src", "teamserver", "Rod.TeamServer", "appsettings.json")),
            new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });

    // The platform tree carries no module trees: the reference set split
    // into its rod-<kind>-<name> repositories (ADR-024), and modules
    // arrive through the ecosystem -- the registry an operator installs
    // from, the store the console writes. A directory under modules/ is
    // the in-tree shape the split retired; finding one means a module
    // landed on the wrong side of the kernel/module boundary.
    [Fact]
    public void TheTree_CarriesNoModuleTrees()
    {
        var modulesRoot = Path.Combine(RepoRoot, "modules");

        Assert.False(Directory.Exists(modulesRoot),
            "modules/ exists: the reference set lives in its own repositories (ADR-024); " +
            "a module belongs in the ecosystem, not the platform tree.");
    }

    // The tree ships no server-module assemblies either: the .NET halves
    // were pure descriptors and migrated to their manifests (ADR-018),
    // and no dual shape -- a manifest beside the assembly it replaced --
    // grows back. An external assembly module remains legal; it ships in
    // its own repository, and the config-listed assembly path
    // (Capabilities:Modules) stays the seam it loads through.
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
            "The shipped Capabilities:Modules list carries assembly entries while the tree ships " +
            $"no module trees at all: [{string.Join(", ", listed)}].");
    }

    // What ships, loads: the shipped descriptor list is empty to match
    // the tree -- a stale entry would abort startup on a directory the
    // tree no longer carries, and the official set installs from the
    // default registry (Modules:Registry) instead of riding the
    // configuration.
    [Fact]
    public void ShippedConfig_ListsNoDescriptorModules()
    {
        using var document = ShippedSettings();
        var listed = document.RootElement
            .GetProperty("Capabilities").GetProperty("DescriptorModules")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.True(listed.Count == 0,
            "The shipped Capabilities:DescriptorModules list carries entries; a deployment " +
            $"lists its installed set, and the tree carries none: [{string.Join(", ", listed)}].");
    }

    // The same what-ships-loads rule for the content half: the shipped
    // asset list is empty, and the official asset packages install from
    // the default registry like every other entry.
    [Fact]
    public void ShippedConfig_ListsNoAssetModules()
    {
        using var document = ShippedSettings();
        var listed = document.RootElement
            .GetProperty("Capabilities").GetProperty("AssetModules")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.True(listed.Count == 0,
            "The shipped Capabilities:AssetModules list carries entries; the tree carries " +
            $"no module trees at all: [{string.Join(", ", listed)}].");
    }

    // The shipped configuration names the default registry the console
    // browses and the store it installs into (ADR-023): a fresh
    // deployment installs the official set from its console on day one,
    // and the marketplace acceptance this tree carries (the integration
    // suite's round trips) rides exactly these two keys.
    [Fact]
    public void ShippedConfig_NamesTheDefaultStoreAndRegistry()
    {
        using var document = ShippedSettings();
        var modules = document.RootElement.GetProperty("Modules");

        Assert.Equal("modules-store", modules.GetProperty("Store").GetString());
        Assert.Equal(
            "https://rodframework.github.io/rod-registry",
            modules.GetProperty("Registry").GetString());
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
            "Kernel projects embed script/template assets; they ship as ecosystem asset modules: "
            + string.Join(", ", offenders));
    }
}
