using Rod.Conformance;
using Xunit.Abstractions;

namespace Rod.Conformance.Tests;

/// <summary>
/// The plugin tier's conformance clauses against the Go reference implant
/// (extending/implants.md, Tier 2; ADR-020): the same exec-v1 fixture the
/// Rust lane stages, a different host language -- the proof that the
/// plugin contract is implementable across hosts, which is the tier's
/// reason to exist. The two plugin clauses are the assertion; the Tier 0
/// clauses are pinned alongside so a wire regression cannot hide behind a
/// green plugin pair. The signature clause is deliberately not asserted:
/// tasking verification is Tier 1, the implant author's choice, and the Go
/// reference has not adopted it -- a choice the ladder documents.
/// </summary>
public class GoImplantPluginClauseTests(ITestOutputHelper _output)
{
    [GoFact]
    public async Task TheGoImplant_PassesThePluginClauses()
    {
        var plugin = await File.ReadAllBytesAsync(FixturePlugin.Build());

        await using var rig = await ConformanceRig.StartAsync();
        using var candidate = GoImplantCandidate.Build();
        var report = await rig.RunAsync(candidate, plugin);

        _output.WriteLine(report.ToString());
        var load = Assert.Single(report.Clauses, c => c.Clause == ConformanceRig.PluginLoadClause);
        Assert.True(load.Passed, load.Detail);
        var artifact = Assert.Single(report.Clauses, c => c.Clause == ConformanceRig.PluginArtifactClause);
        Assert.True(artifact.Passed, artifact.Detail);

        // The Tier 0 clauses hold for any conforming candidate; pinning
        // them keeps a wire regression from hiding behind the plugin pair.
        foreach (var clause in new[]
        {
            ConformanceRig.EnrollClause,
            ConformanceRig.HandshakeClause,
            ConformanceRig.RoundTripClause,
            ConformanceRig.ChunkClause,
        })
        {
            var pinned = Assert.Single(report.Clauses, c => c.Clause == clause);
            Assert.True(pinned.Passed, pinned.Detail);
        }
    }
}
