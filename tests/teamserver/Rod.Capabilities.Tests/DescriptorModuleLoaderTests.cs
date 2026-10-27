using Microsoft.Extensions.Configuration;
using Rod.Capabilities.Registry;

namespace Rod.Capabilities.Tests;

/// <summary>
/// The descriptor-module loader (architecture.md Sec 15.2, ADR-018): the
/// zero-.NET path beside the assembly loader. Verb rows that carry their
/// category register as manifest-declared descriptors -- the catalog
/// schema, the OPSEC badges, and the module.load requirement gate all read
/// what the manifest declared, no assembly anywhere. The loading contract
/// pinned here mirrors what the asset store's and the assembly loader's
/// tests pin for their halves: a missing section loads nothing, anything
/// listed but broken aborts loudly, and last registration wins.
/// </summary>
public class DescriptorModuleLoaderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rod-descriptors-" + Guid.NewGuid().ToString("N"));

    private string Dir(string name) => Path.Combine(_root, name);

    private IConfiguration Config(params string[] directories)
    {
        var settings = new Dictionary<string, string?>();
        for (var i = 0; i < directories.Length; i++)
            settings[$"{DescriptorModuleLoader.DescriptorModulesSectionKey}:{i}"] = directories[i];
        return new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
    }

    private void Manifest(string directory, string text)
    {
        Directory.CreateDirectory(Dir(directory));
        File.WriteAllText(Path.Combine(Dir(directory), "rod-module.toml"), text);
    }

    // The zero-.NET module the happy path loads: a novel namespace, an
    // OPSEC flag pair, a schema the UI renders, a structured output kind,
    // and a requirement row the module.load gate reads.
    private const string SweepManifest = """
        [module]
        name = "sweep"

        [compatibility]
        teamserver = "1.0.0"
        requires = ["plugin-loader"]

        [[verbs]]
        name = "sweep.discover"
        version = "0.3.0"
        category = "recon"
        opsec = { "touches-network" = true, "writes-to-disk" = false }
        techniques = ["T1046"]
        output-kind = "enumeration"
        output-help = "One JSON finding per line."

          [[verbs.parameters]]
          name = "host"
          label = "Host"
          kind = "string"
          required = true
          placeholder = "10.0.0.7"

          [[verbs.parameters]]
          name = "ports"
          label = "Port range"
          kind = "enum"
          choices = ["fast", "full"]
          trailing = true
        """;

    [Fact]
    public async Task AManifestDeclaredModule_RegistersWithoutAnyAssembly()
    {
        Manifest("sweep", SweepManifest);
        var registry = await RodCapabilitiesHost.BuildDefaultRegistryAsync();

        await DescriptorModuleLoader.LoadAsync(Config(Dir("sweep")), registry);

        var found = await registry.FindAsync("sweep.discover");
        Assert.NotNull(found);
        Assert.Equal("sweep", found!.Name);
        Assert.Equal(["plugin-loader"], found.Requires);

        var descriptor = found.Descriptor;
        Assert.Equal(CapabilityCategory.Recon, descriptor.Category);
        Assert.Equal("0.3.0", descriptor.Version);
        Assert.Equal("true", descriptor.Attributes["touches-network"]);
        Assert.Equal("false", descriptor.Attributes["writes-to-disk"]);
        Assert.Equal(["T1046"], descriptor.Techniques);
        Assert.Equal(VerbOutputKind.Enumeration, descriptor.Output!.Kind);
        Assert.Equal("One JSON finding per line.", descriptor.Output.Help);

        Assert.Equal(2, descriptor.Parameters!.Count);
        var host = descriptor.Parameters[0];
        Assert.Equal("host", host.Name);
        Assert.Equal(VerbParameterKind.String, host.Kind);
        Assert.True(host.Required);
        Assert.Equal("10.0.0.7", host.Placeholder);
        var ports = descriptor.Parameters[1];
        Assert.Equal(VerbParameterKind.Enum, ports.Kind);
        Assert.Equal(["fast", "full"], ports.Choices);
        Assert.True(ports.Trailing);
    }

    [Fact]
    public async Task AMissingSection_LoadsNothing()
    {
        var registry = await RodCapabilitiesHost.BuildDefaultRegistryAsync();
        var before = (await registry.ListAsync()).Count;

        await DescriptorModuleLoader.LoadAsync(Config(), registry);

        Assert.Equal(before, (await registry.ListAsync()).Count);
    }

    [Fact]
    public async Task AListedModule_ReplacesThePlaceholderForItsVerb()
    {
        // hostenum's placeholder: a manifest-listed registration wins the
        // verb, the same last-wins authority an assembly module rides.
        Manifest("sweep", SweepManifest.Replace("sweep.discover", "recon.hostenum"));
        var registry = await RodCapabilitiesHost.BuildDefaultRegistryAsync();

        await DescriptorModuleLoader.LoadAsync(Config(Dir("sweep")), registry);

        var found = await registry.FindAsync("recon.hostenum");
        Assert.NotNull(found);
        Assert.Equal("sweep", found!.Name);
        Assert.Equal(VerbOutputKind.Enumeration, found.Descriptor.Output!.Kind);
    }

    [Fact]
    public async Task TheLastNameWins_AVerbTwoModulesDeclare()
    {
        Manifest("first", SweepManifest.Replace("name = \"sweep\"", "name = \"first\""));
        Manifest("second", SweepManifest.Replace("name = \"sweep\"", "name = \"second\""));
        var registry = new InMemoryCapabilityRegistry();

        await DescriptorModuleLoader.LoadAsync(Config(Dir("first"), Dir("second")), registry);

        Assert.Equal("second", (await registry.FindAsync("sweep.discover"))!.Name);
        Assert.Equal("second", (await registry.FindByNameAsync("second"))!.Name);
    }

    [Fact]
    public async Task BrokenModules_AbortLoudlyWithTheCause()
    {
        var registry = new InMemoryCapabilityRegistry();

        // A directory with no manifest at all.
        Directory.CreateDirectory(Dir("empty"));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => DescriptorModuleLoader.LoadAsync(Config(Dir("empty")), registry));

        // A manifest that does not parse.
        Manifest("broken", "not toml at all [");
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => DescriptorModuleLoader.LoadAsync(Config(Dir("broken")), registry));

        // No module name.
        Manifest("nameless", SweepManifest.Replace("name = \"sweep\"", ""));
        var nameless = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DescriptorModuleLoader.LoadAsync(Config(Dir("nameless")), registry));
        Assert.Contains("no [module] name", nameless.Message);

        // No verb rows.
        Manifest("rowless", """
            [module]
            name = "sweep"

            [compatibility]
            teamserver = "1.0.0"
            """);
        var rowless = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DescriptorModuleLoader.LoadAsync(Config(Dir("rowless")), registry));
        Assert.Contains("declares no [[verbs]] rows", rowless.Message);
    }

    [Fact]
    public async Task AVersionOnlyRow_IsRefusedAsTheHalfLoadedShape()
    {
        // A module listed under the descriptor path must be whole: a row
        // without its category gates nothing while its sibling rows gate
        // their verbs -- the "registered but not what the operator
        // deployed" state a red team cannot afford.
        Manifest("half", SweepManifest.Replace("category = \"recon\"", ""));
        var registry = new InMemoryCapabilityRegistry();

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DescriptorModuleLoader.LoadAsync(Config(Dir("half")), registry));
        Assert.Contains("no category", failure.Message);
    }

    [Fact]
    public async Task UnknownVocabularyNames_AbortWithTheFieldNamed()
    {
        var registry = new InMemoryCapabilityRegistry();

        Manifest("category", SweepManifest.Replace("category = \"recon\"", "category = \"reconnaissance\""));
        var category = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DescriptorModuleLoader.LoadAsync(Config(Dir("category")), registry));
        Assert.Contains("category 'reconnaissance' is not a capability category", category.Message);

        Manifest("kind", SweepManifest.Replace("kind = \"string\"", "kind = \"hostname\""));
        var kind = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DescriptorModuleLoader.LoadAsync(Config(Dir("kind")), registry));
        Assert.Contains("kind 'hostname' is not a parameter kind", kind.Message);

        Manifest("output", SweepManifest.Replace("output-kind = \"enumeration\"", "output-kind = \"portscan\""));
        var output = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DescriptorModuleLoader.LoadAsync(Config(Dir("output")), registry));
        Assert.Contains("output-kind 'portscan' is not an output kind", output.Message);
    }

    [Fact]
    public async Task AnUnrenderableSchema_IsRefusedByTheRegistryItself()
    {
        // The loader hands the parsed schema to the registry, whose own
        // registration gate refuses what the UI cannot render -- the same
        // refusal an assembly module's malformed descriptor meets. Here the
        // FIRST parameter takes trailing while a second follows it.
        Manifest("trailing", SweepManifest.Replace("placeholder = \"10.0.0.7\"", "placeholder = \"10.0.0.7\"\n          trailing = true"));
        var registry = new InMemoryCapabilityRegistry();

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DescriptorModuleLoader.LoadAsync(Config(Dir("trailing")), registry));
        Assert.Contains("trailing but not last", failure.Message);
    }

    [Fact]
    public async Task AnUnknownRequirementRow_IsRefusedByTheRegistryItself()
    {
        Manifest("requires", SweepManifest.Replace("requires = [\"plugin-loader\"]", "requires = [\"cha-cha-20\"]"));
        var registry = new InMemoryCapabilityRegistry();

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => DescriptorModuleLoader.LoadAsync(Config(Dir("requires")), registry));
        Assert.Contains("not a wire capability", failure.Message);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }
}
