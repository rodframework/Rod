using Rod.CoreState.Implants;
using Rod.Capabilities.Core;
using Rod.Capabilities.Evasion;
using Rod.Capabilities.Exploit;
using Rod.Capabilities.Modules;
using Rod.Capabilities.Registry;
using Task = System.Threading.Tasks.Task;

namespace Rod.Capabilities.Tests;

/// <summary>
/// Resolver-level acceptance: the capability-registry-backed
/// <see cref="ITaskCapabilityResolver"/> admits a verb the per-class reduced set
/// does not when a module is registered for it (architecture.md Sec 10.2/10.3).
/// The class table stays the primary authority; the registry opens the
/// contract-and-dispatch-only path for evasion and exploit.
/// </summary>
public class CapabilityRegistryTaskResolverTests
{
    [Fact]
    public async Task IsDispatchable_TrueForAVerbInTheClassSet()
    {
        // A class-gated verb is always dispatchable: the class table is checked
        // first and short-circuits before the registry is consulted.
        var resolver = new CapabilityRegistryTaskResolver(new InMemoryCapabilityRegistry());

        Assert.True(resolver.IsDispatchable(ImplantClass.Implant, "shell.exec"));
        Assert.True(resolver.IsDispatchable(ImplantClass.Pivot, "tunnel.socks"));
    }

    [Fact]
    public async Task IsDispatchable_FalseForAnUnknownVerb()
    {
        // No module registered, and the verb is not in any class set: the gate
        // refuses it, so a nonsense verb never reaches the queue.
        var resolver = new CapabilityRegistryTaskResolver(new InMemoryCapabilityRegistry());

        Assert.False(resolver.IsDispatchable(ImplantClass.Implant, "does.not.exist"));
    }

    [Fact]
    public async Task IsDispatchable_AdmitsAnEvasionVerbOnceRegistered()
    {
        // The built-in load registers a placeholder for every framework verb,
        // including the evasion verbs (architecture.md Sec 10.2). A placeholder is
        // a registered module, so it satisfies the gate: the evasion verb is no
        // longer refused before dispatch, even on a reduced class.
        var registry = new InMemoryCapabilityRegistry();
        await registry.RegisterAsync(
            new PlaceholderCapabilityModule(
                CapabilityDescriptor.Of(EvasionCapabilities.Avoid, CapabilityCategory.Evasion, "1.0")));
        var resolver = new CapabilityRegistryTaskResolver(registry);

        Assert.True(resolver.IsDispatchable(ImplantClass.Pivot, EvasionCapabilities.Avoid));
        Assert.True(resolver.IsDispatchable(ImplantClass.WebShell, EvasionCapabilities.Avoid));
    }

    [Fact]
    public async Task IsDispatchable_AdmitsAnExploitVerbRegisteredByAnOutOfTreeModule()
    {
        // An operator-supplied, out-of-tree module (here a fixed-result stand-in)
        // registered for an exploit verb is the authority for it, and the resolver
        // admits the verb -- the "registered capability module reached" half of
        // the acceptance criteria at the resolver level.
        var registry = new InMemoryCapabilityRegistry();
        await registry.RegisterAsync(new FixedModule(ExploitCapabilities.Invoke));
        var resolver = new CapabilityRegistryTaskResolver(registry);

        Assert.True(resolver.IsDispatchable(ImplantClass.Implant, ExploitCapabilities.Invoke));
    }

    [Fact]
    public async Task IsDispatchable_RefusesAClassGatedVerbOutsideItsClass()
    {
        // A verb another class's set carries stays gated to that class even
        // with a module registered: the registry widens the gate for ungated
        // verbs only, never re-gates a class-gated one (architecture.md Sec
        // 5.2/10.3). Without this, every registered framework verb would be
        // dispatchable on every class and the reduced sets would gate nothing.
        var registry = new InMemoryCapabilityRegistry();
        await registry.RegisterAsync(
            new PlaceholderCapabilityModule(
                CapabilityDescriptor.Of("recon.ps", CapabilityCategory.Recon, "1.0")));
        await registry.RegisterAsync(
            new PlaceholderCapabilityModule(
                CapabilityDescriptor.Of("shell.exec", CapabilityCategory.Core, "1.0")));
        var resolver = new CapabilityRegistryTaskResolver(registry);

        Assert.False(resolver.IsDispatchable(ImplantClass.WebShell, "recon.ps"));
        Assert.False(resolver.IsDispatchable(ImplantClass.Pivot, "shell.exec"));
        Assert.False(resolver.IsDispatchable(ImplantClass.Ephemeral, "persist.install"));
    }

    [Fact]
    public async Task IsDispatchable_AdmitsANewUngatedVerbFromAnOutOfTreeModule()
    {
        // A brand-new verb no class set gates is the module seam's extension
        // path: registering a module for it makes it dispatchable without a
        // schema change (architecture.md Sec 10.2).
        var registry = new InMemoryCapabilityRegistry();
        await registry.RegisterAsync(new FixedModule("custom.thing"));
        var resolver = new CapabilityRegistryTaskResolver(registry);

        Assert.True(resolver.IsDispatchable(ImplantClass.WebShell, "custom.thing"));
    }

    [Fact]
    public async Task IsDispatchable_ClassTableAdmitsEvenWhenNoModuleRegistered()
    {
        // The class table is primary: a verb it admits is dispatchable even with
        // an empty registry, so the registry only ever widens the gate, never
        // narrows it.
        var resolver = new CapabilityRegistryTaskResolver(new InMemoryCapabilityRegistry());

        Assert.True(resolver.IsDispatchable(ImplantClass.Implant, "recon.portscan"));
    }

    [Fact]
    public async Task ModuleRequires_AnswersTheNamedModuleSRows()
    {
        // ADR-017's runtime half: the resolver is the task path's one look at
        // the requirement rows -- the named module's declaration, null for an
        // unknown name or a module that declares none.
        var registry = new InMemoryCapabilityRegistry();
        await registry.RegisterAsync(new FixedModule("collect.hives") { Name = "hives", Requires = ["plugin-loader/exec-v1"] });
        var resolver = new CapabilityRegistryTaskResolver(registry);

        Assert.Equal(new[] { "plugin-loader/exec-v1" }, resolver.ModuleRequires("hives"));
        Assert.Null(resolver.ModuleRequires("nothing"));
        Assert.Null(resolver.ModuleRequires("shell.exec"));
    }

    // A module whose descriptor is fixed, standing in for an operator-supplied
    // out-of-tree exploit module without writing real tradecraft.
    private sealed class FixedModule : ICapabilityModule
    {
        public CapabilityDescriptor Descriptor { get; }

        public string? Name { get; init; }

        public IReadOnlyList<string>? Requires { get; init; }

        public FixedModule(string verb)
            => Descriptor = CapabilityDescriptor.Of(verb, CapabilityCategory.Exploit, "1.0");
    }
}
