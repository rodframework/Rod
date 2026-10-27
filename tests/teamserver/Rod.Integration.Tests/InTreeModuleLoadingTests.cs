using Microsoft.Extensions.DependencyInjection;
using Rod.Capabilities;
using Rod.Capabilities.Coverage;
using Rod.Capabilities.Modules;
using Rod.Capabilities.Registry;
using Rod.CoreState.Implants;

namespace Rod.Integration.Tests;

/// <summary>
/// The in-tree module acceptance (architecture.md Sec 15.1, ADR-018): the
/// reference modules under <c>modules/</c> are pure descriptor manifests --
/// their verb rows carry the whole server-side half -- and load through
/// exactly the path an external module takes: a
/// <c>Capabilities:DescriptorModules</c> config entry naming the directory.
/// The test host configures the same section the shipped appsettings.json
/// carries, resolved against the repository's own module trees (the stand-in
/// for the deploy step, which copies each manifest under
/// <c>modules/&lt;name&gt;/</c> beside the binary); no test or kernel code
/// compiles against anything the modules ship.
/// </summary>
public class InTreeModuleLoadingTests
{
    private static readonly string RepoRoot = FindRepoRoot(new DirectoryInfo(AppContext.BaseDirectory));

    private static string FindRepoRoot(DirectoryInfo start)
    {
        DirectoryInfo? dir = start;
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src"))
                && Directory.Exists(Path.Combine(dir.FullName, "tests")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not locate the repo root from the test assembly.");
    }

    // Every in-tree descriptor module directory, discovered by shape: a
    // manifest under modules/ whose entry kind is not "assets" (the asset
    // modules ride their own section, Capabilities:AssetModules). The same
    // recognition the architecture tests use, and the same set the shipped
    // config lists.
    private static IReadOnlyList<string> DescriptorModuleDirectories() =>
        Directory.GetDirectories(Path.Combine(RepoRoot, "modules"))
            .Where(d => File.Exists(Path.Combine(d, "rod-module.toml"))
                && !File.ReadAllLines(Path.Combine(d, "rod-module.toml"))
                    .Any(line => line.Trim().Equals("entry = \"assets\"", StringComparison.OrdinalIgnoreCase)))
            .OrderBy(d => d, StringComparer.Ordinal)
            .ToArray();

    [Fact]
    public async Task InTreeDescriptorModules_LoadThroughTheConfigListedPath()
    {
        // The section the shipped appsettings.json carries, resolved at the
        // repository trees: the same loader, the same config list, the same
        // last-registration-wins replacement an operator's external module
        // rides. Nothing about the modules being in-tree changes the path.
        var directories = DescriptorModuleDirectories();
        Assert.True(directories.Count >= 13, "the in-tree descriptor module set shrank below the thirteen shipped modules.");

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
            Assert.Equal(["plugin-loader"], hostenum.Requires);
            Assert.Equal(VerbOutputKind.Enumeration, hostenum.Descriptor.Output!.Kind);
            Assert.Equal(["T1082"], hostenum.Descriptor.Techniques);

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
    public async Task EveryInTreeDescriptorModule_IsWholeAndSensitiveRowsStillCarryTheirFlags()
    {
        // The whole set loads clean together -- every row carries its
        // category (the loader's wholeness refusal never fired) -- and the
        // sensitive family keeps the flags the registry-backed
        // sensitive-verb policy keys on (Sec 10.4): the evasion rows carry
        // modifies-defenses, so they stay out of unattended firing now that
        // the .NET halves are gone.
        var index = 0;
        var (client, host, _) = AuthenticatedHost.Create(
            extendConfig: settings =>
            {
                foreach (var directory in DescriptorModuleDirectories())
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

    // The assembly path's liveness: the loader for external .NET modules
    // (Capabilities:Modules) stays the seam it always was, pinned with a
    // fixture type this test assembly carries -- the in-tree set no longer
    // rides it, so without a fixture the path would be dead weight.
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
                "Rod.Integration.Tests.InTreeModuleLoadingTests+FixtureAssemblyModule, Rod.Integration.Tests",
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
