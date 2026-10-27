using Rod.CoreState.Implants;

namespace Rod.CoreState.Tests;

/// <summary>
/// Checks of <see cref="WireCapabilities"/> -- the closed vocabulary a module's
/// requirement rows draw from (architecture.md Sec 15.2, ADR-017) and the
/// coverage rule the runtime requirement gate matches against a session's
/// handshake advertisement. Each tier's task-path face is the verb whose
/// reference handler carries its frames, so advertising the verb claims the
/// capability.
/// </summary>
public class WireCapabilitiesTests
{
    [Theory]
    [InlineData("module.load,shell.exec", WireCapabilities.PluginLoader, true)]
    [InlineData("shell.exec", WireCapabilities.PluginLoader, false)]
    [InlineData("MODULE.LOAD", WireCapabilities.PluginLoader, true)]
    [InlineData("file.pull", WireCapabilities.ExfilChunks, true)]
    [InlineData("shell.exec", WireCapabilities.ExfilChunks, false)]
    [InlineData("file.push", WireCapabilities.StagedUploads, true)]
    [InlineData("file.pull", WireCapabilities.StagedUploads, false)]
    [InlineData("shell.exec", "cha-cha-20", false)]
    public void Covers_MatchesTheTierSTaskPathVerb(string advertised, string name, bool expected)
    {
        Assert.Equal(expected, WireCapabilities.Covers(advertised.Split(','), name));
    }

    [Fact]
    public void Requirable_IsTheClosedVocabulary()
    {
        Assert.Equal(
            new[] { "plugin-loader", "exfil-chunks", "staged-uploads" },
            WireCapabilities.Requirable);
        Assert.True(WireCapabilities.IsRequirable("plugin-loader"));
        Assert.False(WireCapabilities.IsRequirable("channels"));
    }
}
