using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.Build.Tests;

/// <summary>
/// The extension seam's build-time half (ADR-022): the catalog's loading
/// gates (whole extension manifests, the verb guards the runtime loader
/// holds) and the hard targeting rule -- an extension that does not name
/// the request's build unit is refused, named, before anything compiles.
/// </summary>
public class ExtensionCatalogTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rod-ext-catalog-" + Guid.NewGuid().ToString("N"));

    private string Package(string name, string targetsUnit = "rod-rust", string verb = null!)
    {
        var directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        verb ??= $"{name.Replace("-", "")}.run";
        File.WriteAllText(Path.Combine(directory, "rod-module.toml"), $"""
            [module]
            name = "{name}"
            version = "0.1.0"
            entry = "extension"
            license = "Apache-2.0"

            [compatibility]
            teamserver = "1.0.0"

            [opsec]
            lands-on-disk = false

            [[compatibility.targets]]
            implant-class = "implant"
            platform = "linux"
            arch = "amd64"
            build-unit = "{targetsUnit}"

            [[verbs]]
            name = "{verb}"
            version = "0.1.0"
            category = "recon"
            output-kind = "text"
            """);
        Directory.CreateDirectory(Path.Combine(directory, "src"));
        File.WriteAllText(Path.Combine(directory, "Cargo.toml"), $"""
            [package]
            name = "rod-ext-{name}"
            version = "0.1.0"
            edition = "2021"

            [lib]
            crate-type = ["rlib"]
            """);
        return directory;
    }

    [Fact]
    public void TheTargetingRows_AreTheHardGate()
    {
        var go = Package("go-only-ext", targetsUnit: "rod-go");
        var catalog = ExtensionCatalog.Load([go]);

        // The extension names the Go unit: a rust build is refused, naming
        // the unit it does target.
        var refusal = Assert.Throws<InvalidOperationException>(
            () => catalog.Resolve(["go-only-ext"], BuildUnitIds.Rust));
        Assert.Contains("rod-go", refusal.Message);
        Assert.Contains(BuildUnitIds.Rust, refusal.Message);

        var overlays = catalog.Resolve(["go-only-ext"], BuildUnitIds.Go);
        var overlay = Assert.Single(overlays);
        Assert.Equal("go-only-ext", overlay.Name);
        Assert.Equal(go, overlay.Directory);
        Assert.Equal(["goonlyext.run"], overlay.Verbs);
    }

    [Fact]
    public void AnUnknownName_IsRefusedWithTheConfigKey()
    {
        var catalog = ExtensionCatalog.Load([]);

        var refusal = Assert.Throws<InvalidOperationException>(
            () => catalog.Resolve(["no-such"], BuildUnitIds.Rust));
        Assert.Contains("no-such", refusal.Message);
        Assert.Contains(ExtensionCatalog.ExtensionsSectionKey, refusal.Message);
    }

    [Fact]
    public void TwoExtensionsClaimingOneVerb_IsAStagingAmbiguity()
    {
        Package("first-ext", verb: "recon.clash");
        Package("second-ext", verb: "recon.clash");
        var catalog = ExtensionCatalog.Load([
            Path.Combine(_root, "first-ext"),
            Path.Combine(_root, "second-ext"),
        ]);

        var refusal = Assert.Throws<InvalidOperationException>(
            () => catalog.Resolve(["first-ext", "second-ext"], BuildUnitIds.Rust));
        Assert.Contains("recon.clash", refusal.Message);
    }

    [Fact]
    public void TheVerbGuards_MirrorTheRuntimeLoaderS()
    {
        // A channel verb and a kernel verb are both refused at load time,
        // named with the rule -- the same guards plugins.rs holds, stated
        // here so a bad package never reaches a compiler.
        Package("channel-ext", verb: "tunnel.socks");
        var channel = Assert.Throws<InvalidOperationException>(
            () => ExtensionCatalog.Load([Path.Combine(_root, "channel-ext")]));
        Assert.Contains("channel verb", channel.Message);

        Package("kernel-ext", verb: "shell.exec");
        var kernel = Assert.Throws<InvalidOperationException>(
            () => ExtensionCatalog.Load([Path.Combine(_root, "kernel-ext")]));
        Assert.Contains("stays compiled", kernel.Message);
    }

    [Fact]
    public void AManifestOfAnotherEntryKind_IsRefusedAtLoad()
    {
        var directory = Path.Combine(_root, "server-pkg");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "rod-module.toml"), """
            [module]
            name = "server-pkg"
            version = "0.1.0"
            entry = "server"
            license = "Apache-2.0"

            [compatibility]
            teamserver = "1.0.0"

            [opsec]
            lands-on-disk = false

            [[verbs]]
            name = "recon.sweep"
            version = "0.1.0"
            category = "recon"
            output-kind = "text"
            """);

        var refusal = Assert.Throws<InvalidOperationException>(
            () => ExtensionCatalog.Load([directory]));
        Assert.Contains("server", refusal.Message);
    }

    [Fact]
    public async Task TheServiceRefusesExtensionNames_WithNoCatalogConfigured()
    {
        // The catalog-less service constructor: a request naming extensions
        // is refused rather than silently trimmed -- the operator asked for
        // a compiled-in capability and must learn it never happened.
        var registry = new InMemoryBuildUnitRegistry();
        registry.Register(new StubBuildUnit());
        var service = new PayloadBuildService(registry, TimeProvider.System);
        var request = new BuildRequest(
            EngagementId.New(), OperatorId.New(), "stub-go", ImplantClass.Implant,
            new TargetProfile("linux", "amd64"),
            new TransportProfile("http://c2.example.test", "/beacon"),
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10), null)
        {
            Extensions = ["anything"],
        };

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.BuildAsync(request));
        Assert.Contains("Build:Extensions", refusal.Message);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }
}
