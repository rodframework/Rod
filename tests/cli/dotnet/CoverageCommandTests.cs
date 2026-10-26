namespace Rod.Cli.Tests;

/// <summary>
/// <c>rod mod coverage</c> (ADR-007's repository-side face): the matrix a
/// module tree's declarations produce, the kernel fold-in, the degradation
/// for catalog-less techniques, and the sweep's validation gate -- including
/// over this repository's own in-tree modules, which is the CI check that an
/// in-tree coverage declaration stays honest.
/// </summary>
public class CoverageCommandTests
{
    private static string RepoRoot()
    {
        // The same walk InTreeAndSpawnTests uses: from the assembly to the
        // directory carrying the solution file.
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Rod.slnx")))
            directory = directory.Parent;
        return directory?.FullName
            ?? throw new InvalidOperationException("could not locate the repo root from the test assembly.");
    }

    [Fact]
    public void TheInTreeModules_SweepAndRender_WithTheKernelFoldedIn()
    {
        var run = CliRun.Run("mod", "coverage",
            "--path", Path.Combine(RepoRoot(), "modules"),
            "--catalog", Path.Combine(RepoRoot(), "src", "teamserver", "Rod.CoreState", "Implants", "attack-coverage.json"));

        Assert.True(run.Code == 0, run.Error);
        Assert.Contains("# ATT&CK coverage", run.Output);
        // Every manifest under modules/ rides the sweep, asset modules
        // included: the count is the swept tree, not the verb-carrying
        // subset.
        Assert.Contains("7 modules swept", run.Output);

        // The reference module's declaration rides beside the kernel's own
        // mapping of the same verb: one row, both carriers.
        Assert.Contains(
            "| T1082 | System Information Discovery | discovery | recon.hostenum | hostenum (recon.hostenum) |",
            run.Output);
    }

    [Fact]
    public void ATechniqueTheCatalogLacks_RendersByIdAlone()
    {
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        var toml = File.ReadAllText(Path.Combine(module, "rod-module.toml"))
            .Replace("techniques = []", "techniques = [\"T1615\"]");
        toml += """
            [[verbs]]
            name = "demo-sweep.deep"
            version = "1.0.0"
            techniques = ["T1615"]
            """;
        File.WriteAllText(Path.Combine(module, "rod-module.toml"), toml);

        // Build output directories never ride the sweep: a manifest dropped
        // under dist/ (invalid, on purpose) changes nothing.
        Directory.CreateDirectory(Path.Combine(module, "dist", "stale"));
        File.WriteAllText(Path.Combine(module, "dist", "stale", "rod-module.toml"), "not = valid");

        var run = CliRun.Run("mod", "coverage", "--path", module);
        Assert.True(run.Code == 0, run.Error);
        Assert.Contains("| T1615 |  |  |  | demo-sweep (demo-sweep.deep) |", run.Output);
    }

    [Fact]
    public void AnInvalidManifest_FailsTheSweep_NamingTheFile()
    {
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        File.WriteAllText(
            Path.Combine(module, "rod-module.toml"),
            File.ReadAllText(Path.Combine(module, "rod-module.toml"))
                .Replace("techniques = []", "techniques = [\"NOSUCH\"]"));

        var run = CliRun.Run("mod", "coverage", "--path", module);
        Assert.Equal(RodCli.ExitUsage, run.Code);
        Assert.Contains("rod-module.toml is invalid", run.Error);
        Assert.Contains("NOSUCH", run.Error);
    }

    [Fact]
    public void JsonOutput_CarriesTheVersionStamp_AndBothCarrierSides()
    {
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        var toml = File.ReadAllText(Path.Combine(module, "rod-module.toml"))
            .Replace("techniques = []", "techniques = [\"T1082\"]");
        toml += """
            [[verbs]]
            name = "demo-sweep.deep"
            version = "1.0.0"
            techniques = ["T1082"]
            """;
        File.WriteAllText(Path.Combine(module, "rod-module.toml"), toml);

        var run = CliRun.Run("mod", "coverage",
            "--path", module,
            "--catalog", Path.Combine(RepoRoot(), "src", "teamserver", "Rod.CoreState", "Implants", "attack-coverage.json"),
            "--json");
        Assert.True(run.Code == 0, run.Error);

        using var document = System.Text.Json.JsonDocument.Parse(run.Output);
        var json = document.RootElement;
        Assert.Equal("15", json.GetProperty("attackVersion").GetString());
        var t1082 = json.GetProperty("techniques").EnumerateArray()
            .Single(t => t.GetProperty("id").GetString() == "T1082");
        Assert.Equal("System Information Discovery", t1082.GetProperty("name").GetString());
        Assert.Equal("recon.hostenum", t1082.GetProperty("kernelVerbs")[0].GetString());
        var carrier = t1082.GetProperty("modules").EnumerateArray().Single();
        Assert.Equal("demo-sweep", carrier.GetProperty("module").GetString());
        Assert.Equal("demo-sweep.deep", carrier.GetProperty("verb").GetString());
    }
}
