using Microsoft.Extensions.DependencyInjection;
using Rod.Capabilities;
using Rod.Capabilities.Coverage;
using Rod.Capabilities.Modules;
using Rod.Capabilities.Registry;
using Rod.CoreState.Implants;

namespace Rod.Integration.Tests;

/// <summary>
/// The reference set's loading acceptance (architecture.md Sec 15.1,
/// ADR-018): the official modules are pure descriptor manifests -- their
/// verb rows carry the whole server-side half -- and load through exactly
/// the path an operator's external module takes: a
/// <c>Capabilities:DescriptorModules</c> config entry naming the
/// directory. The set now installs from the organization's registry
/// (the reference-set fixture), so the directories listed are the store
/// trees an operator's own install produces; no test or kernel code
/// compiles against anything the modules ship. The coverage sweep the
/// release notes ride pins here too, over the same installed store.
/// </summary>
[Collection("reference-set")]
public class ReferenceSetLoadingTests(ReferenceSetFixture fixture)
{
    // The plugin pairs, verb to module name: the reference set rides the
    // v4 plugin tier (ADR-020), and every package's requirement rows are
    // its artifact ABI union -- one exec-shape artifact each, so one
    // loader row each.
    private static readonly (string Verb, string Module)[] PluginPairs =
    [
        ("recon.hostenum", "hostenum"),
        ("recon.domainenum", "domainenum"),
        ("persist.runkeys", "runkeys"),
        ("persist.services", "services"),
        ("persist.wmi", "wmi"),
        ("persist.hijack", "hijack"),
        ("collect.hives", "hives"),
        ("collect.dpapi", "dpapi"),
        ("evasion.avoid", "avoid"),
        ("collect.browser", "browser"),
        ("evasion.unload", "unload"),
        ("collect.lsasecrets", "lsasecrets"),
        ("collect.credman", "credman"),
    ];

    [Fact]
    public async Task ReferenceSetDescriptorModules_LoadThroughTheConfigListedPath()
    {
        // The section the shipped appsettings.json carries, resolved at
        // the installed store trees: the same loader, the same config
        // list, the same last-registration-wins replacement an
        // operator's external module rides.
        var directories = fixture.DescriptorDirectories();
        Assert.True(directories.Count >= 13, "the reference set shrank below the thirteen descriptor modules.");

        var index = 0;
        var (client, host, _) = AuthenticatedHost.Create(
            extendConfig: settings =>
            {
                foreach (var directory in directories)
                    settings[$"Capabilities:DescriptorModules:{index++}"] = directory;
            },
            configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config));
        using (client)
        using (host)
        {
            var registry = host.Services.GetRequiredService<ICapabilityRegistry>();

            // hostenum replaces its verb's placeholder: the manifest-listed
            // registration won, and the descriptor the row declared -- the
            // output kind, the techniques -- is what the registry holds.
            var hostenum = await registry.FindAsync("recon.hostenum");
            Assert.NotNull(hostenum);
            Assert.Equal("hostenum", hostenum!.Name);
            Assert.Equal(VerbOutputKind.Enumeration, hostenum.Descriptor.Output!.Kind);
            Assert.Equal(["T1082"], hostenum.Descriptor.Techniques);

            // Every plugin-tier package's requirement rows are its artifacts'
            // ABI union (ADR-020), and the store's static filter reads them
            // off the loaded rows: one exec-shape artifact per package, so
            // one loader row per verb, across every family.
            foreach (var (verb, module) in PluginPairs)
            {
                var found = await registry.FindAsync(verb);
                Assert.NotNull(found);
                Assert.Equal(module, found!.Name);
                Assert.Equal(["plugin-loader/exec-v1"], found.Requires);
            }

            // domainenum was a verb no placeholder served -- a new verb
            // registered through the module seam, not a replacement of one.
            // v1.1 widened the declaration to the authenticated half's
            // account and group discovery techniques, so the pin covers
            // both halves.
            var domainenum = await registry.FindAsync("recon.domainenum");
            Assert.NotNull(domainenum);
            Assert.Equal("domainenum", domainenum!.Name);
            Assert.Equal(
                new[] { "T1018", "T1482", "T1087.002", "T1069.002" },
                domainenum.Descriptor.Techniques);
            Assert.Equal(CapabilityCategory.Recon, domainenum.Descriptor.Category);

            // The widened declaration renders in the coverage matrix
            // (ADR-007): the authenticated half's techniques appear as rows
            // carried by this module's verb, not gaps -- the
            // registry-backed resolver is the same one the /capabilities
            // endpoint serves, so this is the shipped view.
            var techniques = host.Services.GetRequiredService<IVerbTechniqueResolver>();
            var matrix = await CoverageMatrixBuilder.BuildAsync(registry, techniques);
            foreach (var id in new[] { "T1087.002", "T1069.002" })
            {
                var row = Assert.Single(matrix.Rows, r => r.TechniqueId == id);
                var carrier = Assert.Single(row.Carriers);
                Assert.Equal("recon.domainenum", carrier.Verb);
                Assert.Equal(CoverageStatus.Module, carrier.Status);
                Assert.Equal("domainenum", carrier.Module);
            }
        }
    }

    [Fact]
    public async Task EveryReferenceSetDescriptorModule_IsWholeAndSensitiveRowsStillCarryTheirFlags()
    {
        // The whole set loads clean together -- every row carries its
        // category (the loader's wholeness refusal never fired) -- and the
        // sensitive family keeps the flags the registry-backed
        // sensitive-verb policy keys on (Sec 10.4): the evasion rows carry
        // modifies-defenses, so they stay out of unattended firing.
        var index = 0;
        var (client, host, _) = AuthenticatedHost.Create(
            extendConfig: settings =>
            {
                foreach (var directory in fixture.DescriptorDirectories())
                    settings[$"Capabilities:DescriptorModules:{index++}"] = directory;
            },
            configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config));
        using (client)
        using (host)
        {
            var registry = host.Services.GetRequiredService<ICapabilityRegistry>();
            var policy = new CapabilityRegistrySensitiveVerbPolicy(registry);

            foreach (var verb in new[] { "evasion.avoid", "evasion.unload" })
            {
                var found = await registry.FindAsync(verb);
                Assert.NotNull(found);
                Assert.Equal("true", found!.Descriptor.Attributes["modifies-defenses"]);
                Assert.True(policy.IsSensitive(verb));
            }
        }
    }

    [Fact]
    public async Task TheInstalledReferenceSet_SweepsAndRenders_WithTheKernelFoldedIn()
    {
        // The coverage sweep over the installed store (the tree the
        // release notes' matrix sweeps): every manifest in the store
        // validates, asset modules included in the count, and the kernel
        // catalog folds into the same rows the shipped faces render.
        var catalog = Path.Combine(
            FindRepoRoot(), "src", "teamserver", "Rod.CoreState", "Implants", "attack-coverage.json");
        var output = new StringWriter();
        var error = new StringWriter();
        var code = await Rod.Cli.RodCli.RunAsync(
            ["mod", "coverage", "--path", Path.Combine(fixture.Store, "modules"), "--catalog", catalog],
            output, error);
        Assert.True(code == Rod.Cli.RodCli.ExitOk, $"rod mod coverage failed:\n{error}");

        var rendered = output.ToString();
        Assert.Contains("16 modules swept", rendered);

        // The extension tier's first real entry rides the sweep like every
        // verb-carrying module: T1057's row carries procwatch beside
        // whatever the kernel maps to the technique.
        Assert.Contains("procwatch (recon.procwatch)", rendered);

        // The reference module's declaration rides beside the kernel's own
        // mapping of the same verb: one row, both carriers.
        Assert.Contains(
            "| T1082 | System Information Discovery | discovery | recon.hostenum | hostenum (recon.hostenum) |",
            rendered);
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Rod.slnx")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not locate the repo root from the test assembly.");
    }

    // The assembly path's liveness: the loader for external .NET modules
    // (Capabilities:Modules) stays the seam it always was, pinned with a
    // fixture type this test assembly carries -- the reference set no
    // longer rides it, so without a fixture the path would be dead weight.
    private sealed class FixtureAssemblyModule : ICapabilityModule
    {
        public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
            "fixture.assembly", CapabilityCategory.Core, "0.1");
    }

    [Fact]
    public async Task AnAssemblyModule_StillLoadsThroughItsOwnConfigListedPath()
    {
        var (client, host, _) = AuthenticatedHost.Create(
            extendConfig: settings => settings["Capabilities:Modules:0"] =
                "Rod.Integration.Tests.ReferenceSetLoadingTests+FixtureAssemblyModule, Rod.Integration.Tests",
            configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config));
        using (client)
        using (host)
        {
            var registry = host.Services.GetRequiredService<ICapabilityRegistry>();

            var found = await registry.FindAsync("fixture.assembly");

            Assert.NotNull(found);
            Assert.IsType<FixtureAssemblyModule>(found);
        }
    }
}
