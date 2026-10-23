using Microsoft.Extensions.Configuration;
using Rod.Capabilities.Registry;

namespace Rod.Capabilities.Tests;

/// <summary>
/// The asset-module host (architecture.md Sec 15.1): the content half of the
/// module layer loads from the <c>Capabilities:AssetModules</c> list -- one
/// directory per module, manifest-named, asset-row-declared -- and resolves
/// bytes by module name plus asset name. The loading contract pinned here
/// mirrors what the assembly loader's tests pin for its half: a missing
/// section is the empty store, anything listed but broken aborts, and the
/// last listed module wins a name collision -- the authority rule every
/// module seam applies.
/// </summary>
public class ModuleAssetStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rod-assets-" + Guid.NewGuid().ToString("N"));

    private string Dir(string name) => Path.Combine(_root, name);

    private IConfiguration Config(params string[] directories)
    {
        var settings = new Dictionary<string, string?>();
        for (var i = 0; i < directories.Length; i++)
            settings[$"{ModuleAssetStore.AssetModulesSectionKey}:{i}"] = directories[i];
        return new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
    }

    private void Manifest(string directory, string text)
    {
        Directory.CreateDirectory(Dir(directory));
        File.WriteAllText(Path.Combine(Dir(directory), "rod-module.toml"), text);
    }

    private void AssetFile(string directory, string relative, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.Combine(Dir(directory), relative))!);
        File.WriteAllText(Path.Combine(Dir(directory), relative), content);
    }

    /// <summary>Writes a module directory: the manifest naming it, plus one
    /// file per asset row.</summary>
    private void Module(string directory, string name, params (string Asset, string Path, string Content)[] assets)
    {
        var rows = string.Join("\n\n", assets.Select(a => $"""
            [[assets]]
            name = "{a.Asset}"
            path = "{a.Path}"
            """));
        Manifest(directory, $"""
            [module]
            name = "{name}"

            [compatibility]
            teamserver = "1.0.0"

            {rows}
            """);
        foreach (var asset in assets)
            AssetFile(directory, asset.Path, asset.Content);
    }

    [Fact]
    public void AMissingSection_LoadsTheEmptyStore()
    {
        var store = ModuleAssetStore.Load(Config());

        Assert.False(store.TryRead("browser-hook", "hook", out _));
    }

    [Fact]
    public void AListedModule_LoadsItsAssetsByName()
    {
        Module("browserhook", "browser-hook",
            ("hook", "assets/hook.js", "// hook"),
            ("legacy", "assets/old.js", "// old"));

        var store = ModuleAssetStore.Load(Config(Dir("browserhook")));

        Assert.True(store.TryRead("browser-hook", "hook", out var hook));
        Assert.Equal("// hook", System.Text.Encoding.UTF8.GetString(hook.Content));
        Assert.Equal("assets/hook.js", hook.Path);
        Assert.True(store.TryRead("browser-hook", "legacy", out _));
        Assert.False(store.TryRead("browser-hook", "absent", out _));
        Assert.False(store.TryRead("other-module", "hook", out _));
    }

    [Fact]
    public void NameCollisions_ResolveLastListedWins()
    {
        Module("first", "browser-hook", ("hook", "assets/hook.js", "// first"));
        Module("second", "browser-hook", ("hook", "assets/hook.js", "// second"));

        var store = ModuleAssetStore.Load(Config(Dir("first"), Dir("second")));
        Assert.True(store.TryRead("browser-hook", "hook", out var hook));
        Assert.Equal("// second", System.Text.Encoding.UTF8.GetString(hook.Content));

        // The order is the authority: reversed, the other module wins.
        var reversed = ModuleAssetStore.Load(Config(Dir("second"), Dir("first")));
        Assert.True(reversed.TryRead("browser-hook", "hook", out var other));
        Assert.Equal("// first", System.Text.Encoding.UTF8.GetString(other.Content));
    }

    [Fact]
    public void AMissingDirectory_Aborts()
    {
        var failure = Assert.Throws<InvalidOperationException>(
            () => ModuleAssetStore.Load(Config(Dir("nowhere"))));
        Assert.Contains("rod-module.toml", failure.Message);
    }

    [Fact]
    public void AManifestWithoutModuleName_Aborts()
    {
        Manifest("anonymous", """
            [module]
            version = "1.0.0"

            [[assets]]
            name = "hook"
            path = "assets/hook.js"
            """);

        var failure = Assert.Throws<InvalidOperationException>(
            () => ModuleAssetStore.Load(Config(Dir("anonymous"))));
        Assert.Contains("no [module] name", failure.Message);
    }

    [Fact]
    public void AManifestWithoutAssetRows_Aborts()
    {
        Manifest("empty", """
            [module]
            name = "empty"

            [compatibility]
            teamserver = "1.0.0"
            """);

        var failure = Assert.Throws<InvalidOperationException>(
            () => ModuleAssetStore.Load(Config(Dir("empty"))));
        Assert.Contains("no [[assets]] rows", failure.Message);
    }

    [Fact]
    public void AnAssetRowWithoutItsFile_Aborts()
    {
        Manifest("liar", """
            [module]
            name = "liar"

            [[assets]]
            name = "hook"
            path = "assets/hook.js"
            """);

        var failure = Assert.Throws<InvalidOperationException>(
            () => ModuleAssetStore.Load(Config(Dir("liar"))));
        Assert.Contains("the file is missing", failure.Message);
    }

    [Fact]
    public void AnEscapingAssetPath_Aborts()
    {
        Module("escape", "escape", ("hook", "../outside.js", "// out"));

        var failure = Assert.Throws<InvalidOperationException>(
            () => ModuleAssetStore.Load(Config(Dir("escape"))));
        Assert.Contains("no '..' segments", failure.Message);
    }

    [Fact]
    public void ADuplicateAssetName_Aborts()
    {
        Manifest("twice", """
            [module]
            name = "twice"

            [[assets]]
            name = "hook"
            path = "assets/one.js"

            [[assets]]
            name = "hook"
            path = "assets/two.js"
            """);
        AssetFile("twice", "assets/one.js", "// one");
        AssetFile("twice", "assets/two.js", "// two");

        var failure = Assert.Throws<InvalidOperationException>(
            () => ModuleAssetStore.Load(Config(Dir("twice"))));
        Assert.Contains("'hook' twice", failure.Message);
    }

    [Fact]
    public void AnEmptyEntry_Aborts()
    {
        var settings = new Dictionary<string, string?>
        {
            [$"{ModuleAssetStore.AssetModulesSectionKey}:0"] = " ",
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

        Assert.Throws<InvalidOperationException>(() => ModuleAssetStore.Load(configuration));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }
}
