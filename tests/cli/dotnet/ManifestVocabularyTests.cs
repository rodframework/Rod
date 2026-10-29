using Rod.Packaging;

namespace Rod.Cli.Tests;

/// <summary>
/// The manifest vocabulary freeze pins (ADR-019, executed at v1.0.0): the
/// loader ABI names, the wire-capability spellings, the entry kinds, and
/// the descriptor vocabularies all cross the signed canonical form and the
/// registry index, so a rename breaks published packages. Every one of
/// these sets grows additively by design, so each pin asserts the frozen
/// names exist under their exact spelling -- growth is free, a rename or
/// removal is not. The entry-kind set alone is exact: a new entry kind is
/// a new tier, never a casual addition.
/// </summary>
public class ManifestVocabularyTests
{
    [Fact]
    public void TheLoaderAbiNames_AreTheConstantsVerbatim()
    {
        Assert.Equal("exec-v1", PluginAbis.Exec);
        Assert.Equal("native-v1", PluginAbis.Native);
        Assert.Equal("coff-v1", PluginAbis.Coff);
        Assert.Equal("wasm-v1", PluginAbis.Wasm);

        // The loadable/reserved split: wasm stays reserved until its
        // loader ships, and publishing under a reserved name is refused.
        Assert.Equal(["exec-v1", "native-v1", "coff-v1"], PluginAbis.Loadable);
    }

    [Fact]
    public void TheRequirableCapabilitySpellings_AreFrozen()
    {
        var requirable = WireCapabilities.Requirable;
        Assert.Contains("plugin-loader/exec-v1", requirable);
        Assert.Contains("plugin-loader/native-v1", requirable);
        Assert.Contains("plugin-loader/coff-v1", requirable);
        Assert.Contains("plugin-loader/wasm-v1", requirable);
        Assert.Contains("exfil-chunks", requirable);
        Assert.Contains("staged-uploads", requirable);
    }

    [Fact]
    public void TheEntryKindNames_AreTheExactFrozenSet()
    {
        var names = new[]
        {
            ModuleEntryKindNames.ToString(ModuleEntryKind.Server),
            ModuleEntryKindNames.ToString(ModuleEntryKind.Plugin),
            ModuleEntryKindNames.ToString(ModuleEntryKind.Extension),
            ModuleEntryKindNames.ToString(ModuleEntryKind.BuildUnit),
            ModuleEntryKindNames.ToString(ModuleEntryKind.Assets),
        };

        // Compared sorted: the set is the contract, not the enum's
        // declaration order.
        Assert.Equal(
            ["assets", "build-unit", "extension", "plugin", "server"],
            names.Order(StringComparer.Ordinal).ToArray());
        foreach (var name in names)
            Assert.True(ModuleEntryKindNames.TryParse(name, out _), $"round-trip parse of '{name}'");
    }

    [Fact]
    public void TheDescriptorVocabularies_CarryTheFrozenNames()
    {
        foreach (var category in (string[])
                 ["core", "recon", "lateral", "persist", "collect", "exfil", "tunnel", "module", "browser", "evasion", "exploit"])
            Assert.Contains(category, ManifestVocabularies.Categories);

        foreach (var kind in (string[])["string", "text", "number", "boolean", "enum", "file", "array"])
            Assert.Contains(kind, ManifestVocabularies.ParameterKinds);

        foreach (var kind in (string[])
                 ["text", "enumeration", "process-list", "file-list", "credential", "file", "screenshot"])
            Assert.Contains(kind, ManifestVocabularies.OutputKinds);
    }
}
