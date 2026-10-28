using Rod.Capabilities.Core;
using Rod.Capabilities.Modules;
using Rod.Capabilities.Registry;

namespace Rod.Capabilities.Tests;

/// <summary>
/// Registry behavior for the capabilities layer (architecture.md Sec 10.2, /// architecture.md Sec 10). <see cref="InMemoryCapabilityRegistry"/> indexes
/// modules by their descriptor's verb (case-insensitive), lists descriptors in
/// registration order, and lets a later registration replace an earlier one so
/// an out-of-tree module loaded after the core stubs becomes the authority for
/// its verb.
/// </summary>
public class CapabilityRegistryTests
{
    [Fact]
    public async Task Register_ThenFind_ReturnsTheModule()
    {
        var registry = new InMemoryCapabilityRegistry();
        var module = new Stub(CoreCapabilities.ShellExec);

        await registry.RegisterAsync(module);

        var found = await registry.FindAsync(CoreCapabilities.ShellExec);
        Assert.Same(module, found);
    }

    [Fact]
    public async Task Find_UnknownVerb_ReturnsNull()
    {
        var registry = new InMemoryCapabilityRegistry();

        var found = await registry.FindAsync("does.not.exist");

        Assert.Null(found);
    }

    [Fact]
    public async Task Find_IsCaseInsensitive()
    {
        // Capability verbs are namespace.action identifiers, not display
        // strings; a caller must not be told the verb is unknown because of
        // casing.
        var registry = new InMemoryCapabilityRegistry();
        await registry.RegisterAsync(new Stub(CoreCapabilities.ShellExec));

        var found = await registry.FindAsync("SHELL.EXEC");

        Assert.NotNull(found);
        Assert.Equal(CoreCapabilities.ShellExec, found!.Descriptor.Verb);
    }

    [Fact]
    public async Task List_ReflectsRegistrationOrder()
    {
        var registry = new InMemoryCapabilityRegistry();
        var first = new Stub("recon.portscan");
        var second = new Stub("lateral.move");
        var third = new Stub("persist.install");

        await registry.RegisterAsync(first);
        await registry.RegisterAsync(second);
        await registry.RegisterAsync(third);

        var verbs = (await registry.ListAsync()).Select(d => d.Verb).ToArray();
        Assert.Equal(new[] { "recon.portscan", "lateral.move", "persist.install" }, verbs);
    }

    [Fact]
    public async Task Register_ForAnExistingVerb_ReplacesIt()
    {
        // An out-of-tree module loaded after the core placeholder must win for
        // its verb: the last registration is the single authority.
        var registry = new InMemoryCapabilityRegistry();
        var placeholder = new Stub("shell.exec");
        var real = new Stub("shell.exec");

        await registry.RegisterAsync(placeholder);
        await registry.RegisterAsync(real);

        var found = await registry.FindAsync("shell.exec");
        Assert.Same(real, found);
        // The list is deduplicated by verb, so the replaced verb appears once.
        var listed = (await registry.ListAsync()).Where(d => d.Verb == "shell.exec").ToArray();
        Assert.Single(listed);
    }

    [Fact]
    public async Task Register_AnUnknownRequirementName_IsRefusedWithTheVocabulary()
    {
        // ADR-017: the requirement rows match against a closed vocabulary, so
        // a typo is a loud registration failure -- never a silent mismatch the
        // runtime gate would skip.
        var registry = new InMemoryCapabilityRegistry();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => registry.RegisterAsync(new Stub("recon.sweep") { Requires = ["plugin-loaders"] }));

        Assert.Contains("plugin-loaders", ex.Message);
        Assert.Contains("plugin-loader", ex.Message);
    }

    [Fact]
    public async Task FindByName_MatchesThePublishedName_CaseInsensitively_LastWins()
    {
        var registry = new InMemoryCapabilityRegistry();
        var named = new Stub("collect.hives") { Name = "hives", Requires = ["plugin-loader/exec-v1"] };
        await registry.RegisterAsync(named);
        await registry.RegisterAsync(new Stub("shell.exec"));

        var found = await registry.FindByNameAsync("HIVES");

        Assert.Same(named, found);
        Assert.Equal(new[] { "plugin-loader/exec-v1" }, found!.Requires);
        Assert.Null(await registry.FindByNameAsync("nothing"));
    }

    [Fact]
    public async Task ListModules_CarriesTheModuleLevelMetadata()
    {
        var registry = new InMemoryCapabilityRegistry();
        var named = new Stub("collect.hives") { Name = "hives", Requires = ["plugin-loader/exec-v1"] };
        await registry.RegisterAsync(named);
        await registry.RegisterAsync(new Stub("shell.exec"));

        var modules = await registry.ListModulesAsync();

        Assert.Equal(2, modules.Count);
        var hives = Assert.Single(modules, m => m.Name == "hives");
        Assert.Equal(new[] { "plugin-loader/exec-v1" }, hives.Requires);
        Assert.Null(Assert.Single(modules, m => m.Descriptor.Verb == "shell.exec").Requires);
    }

    // A tiny module whose descriptor is fixed at construction, so the tests above
    // can register arbitrary verbs without pulling in real tradecraft.
    private sealed class Stub : ICapabilityModule
    {
        public CapabilityDescriptor Descriptor { get; }

        public string? Name { get; init; }

        public IReadOnlyList<string>? Requires { get; init; }

        public Stub(string verb)
            => Descriptor = CapabilityDescriptor.Of(verb, CapabilityCategory.Core, "1.0");
    }
}
