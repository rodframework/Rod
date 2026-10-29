namespace Rod.Conformance.Tests;

/// <summary>
/// The clause-name freeze pin (ADR-019, executed at v1.0.0): the harness's
/// clause names are the contract -- they ride signed manifests, registry
/// entries, and store views, so a rename or removal breaks published
/// packages. The battery grows additively (new clauses arrive with new
/// tiers), so this pins the frozen names exist under their exact spelling,
/// not that the set is closed.
/// </summary>
public class ClauseNameTests
{
    [Fact]
    public void TheFrozenClauseNames_AreTheConstantsVerbatim()
    {
        Assert.Equal("enroll.public-key-and-token", ConformanceRig.EnrollClause);
        Assert.Equal("handshake.first-frame-ok", ConformanceRig.HandshakeClause);
        Assert.Equal("task.round-trip", ConformanceRig.RoundTripClause);
        Assert.Equal("chunk.discipline", ConformanceRig.ChunkClause);
        Assert.Equal("signature.verification", ConformanceRig.SignatureClause);
        Assert.Equal("kill-date.refusal", ConformanceRig.KillDateClause);
        Assert.Equal("plugin.load-exec-v1", ConformanceRig.PluginLoadClause);
        Assert.Equal("plugin.artifact-return", ConformanceRig.PluginArtifactClause);
    }
}
