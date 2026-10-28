using System.Diagnostics;
using Rod.Conformance;
using Xunit.Abstractions;

namespace Rod.Conformance.Tests;

/// <summary>
/// The plugin tier's conformance clauses (extending/implants.md, Tier 2;
/// ADR-020): the exec-v1 fixture module staged through module.load, its
/// verb answering the marker, and the ABI 2 artifact run returning
/// byte-for-byte through the exfil arm -- proven against the real reference
/// implant over the live rig, the same battery `rod conform --plugin`
/// drives for a community candidate.
/// </summary>
public class PluginClauseTests(ITestOutputHelper _output)
{
    /// <summary>Builds the exec-v1 fixture module's release binary (the
    /// conform crate beside the reference modules), caching it in the
    /// shared target dir the implant builds use.</summary>
    private static string BuildFixturePlugin()
    {
        var tree = ReferenceImplantCandidate.LocateRustTree()
            ?? throw new InvalidOperationException("the Rust tree walked up to nothing");
        var crate = Path.GetFullPath(Path.Combine(tree, "modules", "conform"));
        var binary = Path.Combine(crate, "target", "release", "rod-module-conform");
        if (File.Exists(binary))
            return binary;

        var start = new ProcessStartInfo
        {
            FileName = "cargo",
            WorkingDirectory = crate,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("build");
        start.ArgumentList.Add("--release");
        using var build = Process.Start(start)
            ?? throw new InvalidOperationException("Failed to start cargo (is it on PATH?).");
        var stdout = build.StandardOutput.ReadToEnd();
        var stderr = build.StandardError.ReadToEnd();
        build.WaitForExit();
        if (build.ExitCode != 0)
            throw new InvalidOperationException($"cargo build failed for the fixture plugin:\n{stdout}\n{stderr}");
        return binary;
    }

    [Fact]
    public async Task TheReferenceImplant_PassesThePluginClauses()
    {
        var plugin = await File.ReadAllBytesAsync(BuildFixturePlugin());

        await using var rig = await ConformanceRig.StartAsync();
        using var reference = ReferenceImplantCandidate.Build();
        var report = await rig.RunAsync(reference, plugin);

        _output.WriteLine(report.ToString());
        Assert.True(report.Failed.Count == 0,
            "the reference implant passed every clause:\n" + report);
        var load = Assert.Single(report.Clauses, c => c.Clause == ConformanceRig.PluginLoadClause);
        Assert.True(load.Passed, load.Detail);
        var artifact = Assert.Single(report.Clauses, c => c.Clause == ConformanceRig.PluginArtifactClause);
        Assert.True(artifact.Passed, artifact.Detail);
    }

    [Fact]
    public async Task WithoutTheFixture_ThePluginClausesStaySilent()
    {
        // The clauses are opt-in: a Tier 0 candidate (the minimal implant)
        // runs the battery without them, so the ladder stays the author's
        // climb.
        await using var rig = await ConformanceRig.StartAsync();
        using var minimal = new MinimalImplant(new ImplantDefects());
        var report = await rig.RunAsync(minimal);

        Assert.DoesNotContain(report.Clauses, c => c.Clause == ConformanceRig.PluginLoadClause);
        Assert.DoesNotContain(report.Clauses, c => c.Clause == ConformanceRig.PluginArtifactClause);
        Assert.True(report.Failed.Count == 0, report.ToString());
    }
}
