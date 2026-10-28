using System.Xml.Linq;

namespace Rod.Architecture.Tests;

/// <summary>
/// Guards the layer dependency matrix at the project-file level
/// (architecture.md Sec 4.1, AGENTS.md Sec 5). The namespace-based contacts
/// <see cref="LayerDependencyTests"/> inspect usage, so a forbidden csproj
/// reference that no code uses yet would pass them. This test reads the actual
/// ProjectReference edges and compares them against the allowed matrix, so a
/// dead reference fails the moment it is added.
/// </summary>
public class ProjectReferenceTests
{
    private static readonly string RepoRoot = FindRepoRoot(new DirectoryInfo(AppContext.BaseDirectory));

    // Walks up from the test assembly's bin dir to the repo root -- the directory
    // holding both src/ and tests/ -- so the glob below sees every project, not
    // just the ones beside the test. Tolerates the test project changing depth.
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

    private static readonly string[] TeamserverProjects = Directory
        .GetFiles(Path.Combine(RepoRoot, "src", "teamserver"), "*.csproj", SearchOption.AllDirectories)
        .OrderBy(p => p)
        .ToArray();

    private static readonly string[] TeamserverProjectNames = TeamserverProjects
        .Select(p => Path.GetFileNameWithoutExtension(p)!)
        .ToArray();

    // Allowed ProjectReference targets per in-house project, mirroring
    // LayerDependencyTests. Every teamserver project must have a row: a new layer
    // without one fails, so its dependency rule has to be declared up front.
    private static readonly IReadOnlyDictionary<string, string[]> AllowedReferences =
        new Dictionary<string, string[]>
        {
            ["Rod.Audit"] = [],
            ["Rod.CoreState"] = [],
            ["Rod.Protocol"] = [],
            ["Rod.Packaging"] = [],
            ["Rod.BuildPipeline"] = ["Rod.CoreState"],
            ["Rod.Capabilities"] = ["Rod.CoreState", "Rod.Audit"],
            ["Rod.Operators"] = ["Rod.CoreState", "Rod.Audit"],
            ["Rod.Persistence"] = ["Rod.CoreState", "Rod.Audit"],
            ["Rod.Transport"] = ["Rod.CoreState", "Rod.Protocol", "Rod.Audit", "Rod.BuildPipeline"],
            // Composition root: it wires every layer, so any teamserver project is
            // fair game -- but nothing outside src/teamserver is.
            ["Rod.TeamServer"] = TeamserverProjectNames,
        };

    public static IEnumerable<object[]> ProjectFileCases =>
        TeamserverProjects.Select(p => new object[] { p });

    [Theory]
    [MemberData(nameof(ProjectFileCases))]
    public void ProjectReferences_MatchTheLayerDependencyMatrix(string projectFile)
    {
        var project = Path.GetFileNameWithoutExtension(projectFile)!;
        Assert.True(AllowedReferences.TryGetValue(project, out var allowed),
            $"{project} has no row in the allowed-reference matrix; declare its dependency rule.");

        var doc = XDocument.Load(projectFile);

        // The referenced project's name is the file name of the Include path
        // (csproj files use backslashes even on Unix, hence the normalize).
        var targets = doc.Descendants()
            .Where(e => e.Name.LocalName == "ProjectReference")
            .Select(e => (string?)e.Attribute("Include")?.Value)
            .Where(include => include is not null)
            .Select(include => Path.GetFileNameWithoutExtension(include!.Replace('\\', '/')))
            .OrderBy(t => t)
            .ToArray();

        var forbidden = targets.Where(t => !allowed!.Contains(t)).ToArray();
        Assert.True(forbidden.Length == 0,
            $"{project} has forbidden ProjectReference(s): {string.Join(", ", forbidden)} " +
            $"(allowed: {string.Join(", ", allowed)})");
    }

    // The missing half of the Protocol layer rule: the contract project depends
    // on nothing in-house, and the csproj must say so -- not merely have no code
    // using another layer's namespaces.
    [Fact]
    public void Protocol_HasNoInHouseProjectReferences()
    {
        var projectFile = Path.Combine(RepoRoot, "src", "teamserver", "Rod.Protocol", "Rod.Protocol.csproj");
        var references = XDocument.Load(projectFile).Descendants()
            .Where(e => e.Name.LocalName == "ProjectReference")
            .Select(e => (string?)e.Attribute("Include")?.Value)
            .ToArray();

        Assert.True(references.Length == 0,
            "Rod.Protocol depends on nothing in-house; remove its ProjectReference(s).");
    }
}
