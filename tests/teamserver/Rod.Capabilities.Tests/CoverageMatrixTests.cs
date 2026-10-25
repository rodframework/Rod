using Rod.Capabilities.Core;
using Rod.Capabilities.Coverage;
using Rod.Capabilities.Modules;
using Rod.Capabilities.Recon;
using Rod.Capabilities.Registry;
using Rod.CoreState.Implants;

namespace Rod.Capabilities.Tests;

/// <summary>
/// Checks of the coverage matrix (architecture.md Sec 15.3, ADR-007): the
/// technique x platform x status join over the mapping, the registry, and the
/// class set, with the gap rows reading as the work queue. The matrix reports
/// the running deployment -- a technique appears exactly when a verb the
/// process can task maps to it.
/// </summary>
public class CoverageMatrixTests
{
    private sealed class Stub : ICapabilityModule
    {
        public Stub(CapabilityDescriptor descriptor, string? name = null)
        {
            Descriptor = descriptor;
            Name = name;
        }

        public CapabilityDescriptor Descriptor { get; }

        public string? Name { get; }
    }

    private static async Task<CoverageMatrix> BuildAsync(
        InMemoryCapabilityRegistry registry,
        string? tactic = null,
        string? platform = null)
    {
        var resolver = new CapabilityRegistryVerbTechniqueResolver(registry);
        return await CoverageMatrixBuilder.BuildAsync(registry, resolver, tactic, platform);
    }

    private static async Task<InMemoryCapabilityRegistry> RegistryWithHostenumAsync()
    {
        var registry = await RodCapabilitiesHost.BuildDefaultRegistryAsync();
        await registry.RegisterAsync(new Stub(
            CapabilityDescriptor.Of(ReconCapabilities.HostEnum, CapabilityCategory.Recon, "1.1",
                techniques: ["T1082"]),
            name: "hostenum"));
        return registry;
    }

    [Fact]
    public async Task Rows_CarryTheKernelMapping_WithStatusesAndCarriers()
    {
        var matrix = await BuildAsync(await RegistryWithHostenumAsync());

        // A module-backed verb: the reference module replaces the placeholder,
        // so T1082's carrier names the verb, the module, and the implant class.
        var t1082 = Assert.Single(matrix.Rows, r => r.TechniqueId == "T1082");
        var carrier = Assert.Single(t1082.Carriers);
        Assert.Equal(ReconCapabilities.HostEnum, carrier.Verb);
        Assert.Equal(CoverageStatus.Module, carrier.Status);
        Assert.Equal("hostenum", carrier.Module);
        Assert.Equal(["implant"], carrier.ImplantClasses);
        Assert.Equal(["linux", "windows"], t1082.Platforms);

        // A compiled-core verb: core status, gated classes, both platforms.
        // The ephemeral class carries shell.exec alone (its one-liner
        // footprint), so the transfer verbs are the full class's.
        var t1105 = Assert.Single(matrix.Rows, r => r.TechniqueId == "T1105");
        var push = Assert.Single(t1105.Carriers, c => c.Verb == CoreCapabilities.FilePush);
        Assert.Equal(CoverageStatus.Core, push.Status);
        Assert.Null(push.Module);
        Assert.Equal(["implant"], push.ImplantClasses);

        // A placeholder-only verb: the work-queue row.
        var t1046 = Assert.Single(matrix.Rows, r => r.TechniqueId == "T1046");
        var portscan = Assert.Single(t1046.Carriers, c => c.Verb == ReconCapabilities.PortScan);
        Assert.Equal(CoverageStatus.Gap, portscan.Status);

        // Two verbs mapping to one technique share the row.
        Assert.Equal(2, t1046.Carriers.Count);

        // The browser class runs in the browser, not on an OS.
        var t1185 = Assert.Single(matrix.Rows, r => r.TechniqueId == "T1185");
        Assert.Equal(["browser"], t1185.Platforms);
    }

    [Fact]
    public async Task Rows_AUngatedVerb_CarriesNoPlatform()
    {
        var matrix = await BuildAsync(await RegistryWithHostenumAsync());

        // The evasion verbs belong to no class: their reach is decided per
        // deployment, so the honest platform set is empty and only the tactic
        // filter finds them.
        var t1562 = Assert.Single(matrix.Rows, r => r.TechniqueId == "T1562");
        var avoid = Assert.Single(t1562.Carriers);
        Assert.Equal(["ungated"], avoid.ImplantClasses);
        Assert.Empty(t1562.Platforms);
    }

    [Fact]
    public async Task Rows_WithoutTheModule_TheGapShows()
    {
        // The bare default registry (no modules loaded): hostenum reverts to
        // its placeholder, and T1082's carrier reads as the work queue.
        var matrix = await BuildAsync(await RodCapabilitiesHost.BuildDefaultRegistryAsync());
        var carrier = Assert.Single(matrix.Rows.Single(r => r.TechniqueId == "T1082").Carriers);
        Assert.Equal(CoverageStatus.Gap, carrier.Status);
    }

    [Fact]
    public async Task Rows_ExcludeVerbsTheProcessCannotTask()
    {
        // The matrix reports the running deployment: a kernel mapping for a
        // verb nothing registers never appears, and unmapped verbs (proc.kill)
        // appear nowhere.
        var matrix = await BuildAsync(await RegistryWithHostenumAsync());
        Assert.DoesNotContain(matrix.Rows, r => r.Carriers.Any(c => c.Verb == "never.registered"));
        Assert.DoesNotContain(matrix.Rows, r => r.Carriers.Any(c => c.Verb == CoreCapabilities.ProcKill));
    }

    [Fact]
    public async Task Build_FiltersByTactic()
    {
        var matrix = await BuildAsync(await RegistryWithHostenumAsync(), tactic: "discovery");

        Assert.All(matrix.Rows, r => Assert.Contains("discovery", r.Tactics));
        Assert.Contains(matrix.Rows, r => r.TechniqueId == "T1082");
        Assert.DoesNotContain(matrix.Rows, r => r.TechniqueId == "T1105");

        // Case-insensitive, and the facets still describe the whole matrix.
        var same = await BuildAsync(await RegistryWithHostenumAsync(), tactic: "Discovery");
        Assert.Equal(matrix.Rows.Select(r => r.TechniqueId), same.Rows.Select(r => r.TechniqueId));
        Assert.Contains(matrix.Tactics, t => t == "execution");
    }

    [Fact]
    public async Task Build_FiltersByPlatform()
    {
        var matrix = await BuildAsync(await RegistryWithHostenumAsync(), platform: "browser");

        // Only rows a browser-class carrier reaches survive; a technique both
        // an implant verb and a browser verb carry (T1113) keeps its wider
        // platform set -- the filter selected the row, not the platforms.
        Assert.All(matrix.Rows, r => Assert.Contains("browser", r.Platforms));
        Assert.Equal(["browser"], matrix.Rows.Single(r => r.TechniqueId == "T1185").Platforms);
        Assert.Contains(matrix.Rows, r => r.TechniqueId == "T1185");
        Assert.DoesNotContain(matrix.Rows, r => r.TechniqueId == "T1082");
        Assert.Contains(matrix.Platforms, p => p == "linux");
    }

    [Fact]
    public async Task Build_FiltersCompose()
    {
        var matrix = await BuildAsync(await RegistryWithHostenumAsync(), tactic: "command-and-control", platform: "windows");

        Assert.All(matrix.Rows, r =>
        {
            Assert.Contains("command-and-control", r.Tactics);
            Assert.Contains("windows", r.Platforms);
        });
        Assert.Contains(matrix.Rows, r => r.TechniqueId == "T1105");
        // Tunneling is implant-gated on both OSes, so it survives the windows filter.
        Assert.Contains(matrix.Rows, r => r.TechniqueId == "T1090.001");
    }

    [Fact]
    public async Task Build_AnUnknownFilterValue_FiltersToNothing()
    {
        var matrix = await BuildAsync(await RegistryWithHostenumAsync(), tactic: "no-such-tactic");
        Assert.Empty(matrix.Rows);
        Assert.NotEmpty(matrix.Tactics); // the facets survive the filter
    }

    [Fact]
    public async Task Rows_AModuleDeclaredTechniqueTheCatalogLacks_RendersByIdAlone()
    {
        // Coverage advances without a kernel edit: a module's declaration is
        // the whole entry for its verb, and it may name a technique the
        // kernel's data file carries no display metadata for. The row must
        // appear -- the id is the identity -- not vanish because the catalog
        // has nothing to say about it.
        var registry = await RodCapabilitiesHost.BuildDefaultRegistryAsync();
        await registry.RegisterAsync(new Stub(
            CapabilityDescriptor.Of("sweep.discover", CapabilityCategory.Recon, "1.0",
                techniques: ["T1615"]),
            name: "sweep"));

        var matrix = await BuildAsync(registry);

        var row = Assert.Single(matrix.Rows, r => r.TechniqueId == "T1615");
        Assert.Equal("", row.Name);
        Assert.Empty(row.Tactics);
        var carrier = Assert.Single(row.Carriers);
        Assert.Equal(CoverageStatus.Module, carrier.Status);
        Assert.Equal("sweep", carrier.Module);
    }
}
