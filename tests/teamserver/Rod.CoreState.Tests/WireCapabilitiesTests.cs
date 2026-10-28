using Rod.CoreState.Implants;

namespace Rod.CoreState.Tests;

/// <summary>
/// Checks of <see cref="WireCapabilities"/> -- the closed vocabulary a module's
/// requirement rows draw from (architecture.md Sec 15.2, ADR-017) and the
/// coverage rule the runtime requirement gate matches against a session's
/// handshake advertisement. Each tier's task-path face is the verb whose
/// reference handler carries its frames, so advertising the verb claims the
/// capability. The loader family is ABI-suffixed (ADR-020): every ABI of the
/// family shares the loading verb as its task-path face.
/// </summary>
public class WireCapabilitiesTests
{
    [Theory]
    [InlineData("plugin-loader/exec-v1,shell.exec", WireCapabilities.PluginLoaderExec, true)]
    [InlineData("plugin-loader/native-v1,module.load", WireCapabilities.PluginLoaderNative, true)]
    [InlineData("plugin-loader/coff-v1", WireCapabilities.PluginLoaderCoff, true)]
    [InlineData("module.load,shell.exec", WireCapabilities.PluginLoaderExec, false)]
    [InlineData("shell.exec", WireCapabilities.PluginLoaderExec, false)]
    [InlineData("PLUGIN-LOADER/EXEC-V1", WireCapabilities.PluginLoaderExec, true)]
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
            new[]
            {
                "plugin-loader/exec-v1", "plugin-loader/native-v1",
                "plugin-loader/coff-v1", "plugin-loader/wasm-v1",
                "exfil-chunks", "staged-uploads",
            },
            WireCapabilities.Requirable);
        Assert.True(WireCapabilities.IsRequirable("plugin-loader/exec-v1"));
        Assert.False(WireCapabilities.IsRequirable("plugin-loader"));
        Assert.False(WireCapabilities.IsRequirable("channels"));
    }

    [Fact]
    public void TheLoaderAbis_AreTheFamilySSuffixedNames()
    {
        Assert.True(WireCapabilities.IsPluginLoaderAbi(WireCapabilities.PluginLoaderExec));
        Assert.True(WireCapabilities.IsPluginLoaderAbi("plugin-loader/native-v9"));
        Assert.False(WireCapabilities.IsPluginLoaderAbi("plugin-loader"));
        Assert.False(WireCapabilities.IsPluginLoaderAbi("exfil-chunks"));
    }
}
