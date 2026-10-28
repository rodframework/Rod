using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Capabilities;
using Rod.Capabilities.Registry;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Tasks;
using Rod.Transport.Endpoints;
using static Rod.Integration.Tests.EngagementSetup;
using Task = System.Threading.Tasks.Task;

namespace Rod.Integration.Tests;

/// <summary>
/// The manifest-declared descriptor acceptance (todo's polyglot on-ramp,
/// architecture.md Sec 15.2, ADR-018): a module the framework never
/// anticipated -- a verb namespace no class table carries, no built-in
/// placeholder, nothing in the UI's vocabulary -- opens its issuance gate
/// and renders its task form from <b>manifest data alone</b>. The module
/// is a hand-written rod-module.toml in a temporary directory, listed
/// under <c>Capabilities:DescriptorModules</c>: zero .NET code ships, the
/// descriptor rows are the whole server-side half, and the catalog, the
/// task gate, and the structured-output panels read exactly what the
/// manifest declared -- zero framework changes, the acceptance bar the
/// contract trilogy set.
/// </summary>
public class ManifestDeclaredDescriptorTests : IDisposable
{
    // The probe namespace: nothing in the framework, the class tables, or
    // the built-in registry speaks it, and nothing in this file compiles a
    // module for it -- the manifest below is the module's entire half.
    private const string ScanVerb = "probe.scan";
    private const string ModuleName = "probe";

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), "rod-probe-" + Guid.NewGuid().ToString("N"));

    private void WriteManifest()
    {
        Directory.CreateDirectory(_directory);
        File.WriteAllText(Path.Combine(_directory, "rod-module.toml"), $$"""
            # A novel-namespace module whose whole server-side half is this
            # file (ADR-018): the descriptor rows below are all the
            # teamserver reads -- no assembly, no .NET anywhere.

            [module]
            name = "{{ModuleName}}"
            version = "0.4.0"
            entry = "server"
            license = "Apache-2.0"
            description = "A manifest-declared sweep module."

            [compatibility]
            teamserver = "1.0.0"
            requires = ["plugin-loader/exec-v1"]

            [opsec]
            lands-on-disk = false

            [[verbs]]
            name = "{{ScanVerb}}"
            version = "0.4.0"
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
              name = "range"
              label = "Port range"
              kind = "string"
              required = true
              placeholder = "1-1024"
            """);
    }

    private (HttpClient Client, IHost Host) CreateClient()
    {
        WriteManifest();
        var (client, host, _) = AuthenticatedHost.Create(
            extendConfig: settings => settings["Capabilities:DescriptorModules:0"] = _directory,
            configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config),
            mapEndpoints: endpoints => endpoints.MapCapabilityEndpoints());
        AuthenticatedHost.LoginAsync(client).GetAwaiter().GetResult();
        return (client, host);
    }

    private static async Task<(string EngagementId, string ImplantId)> EngageAsync(HttpClient client, IHost host)
    {
        var engagementId = await CreateEngagementAsync(client);
        var implant = await EnrollImplantAsync(host, new EngagementId(Guid.Parse(engagementId)));
        return (engagementId, implant.Id.ToString());
    }

    [Fact]
    public async Task ANovelNamespace_OpensItsGateAndRendersItsForm_FromManifestDataAlone()
    {
        var (client, host) = CreateClient();
        using (client)
        using (host)
        {
            var (engagementId, implantId) = await EngageAsync(client, host);

            // The catalog carries everything the UI renders the task form
            // from (the generic form builder reads exactly this DTO shape,
            // so this is the rendering contract pinned): the fields in
            // declaration order with their kinds, the OPSEC badges, the
            // output declaration, the module name, and the requirement rows
            // the loadable-set filter matches.
            var descriptors = await client.GetFromJsonAsync<Rod.Capabilities.Endpoints.CapabilityEndpoints.CapabilityDescriptorResponse[]>("/capabilities");
            var scan = Assert.Single(descriptors!, d => d.Verb == ScanVerb);
            Assert.Equal("Recon", scan.Category);
            Assert.Equal("probe", scan.Module);
            Assert.Equal(["plugin-loader/exec-v1"], scan.Requires);
            Assert.Equal("true", scan.Attributes["touches-network"]);
            Assert.Equal(["T1046"], scan.Techniques);
            Assert.NotNull(scan.Output);
            Assert.Equal("Enumeration", scan.Output!.Kind);

            Assert.NotNull(scan.Parameters);
            Assert.Equal(2, scan.Parameters!.Count);
            Assert.Equal("host", scan.Parameters[0].Name);
            Assert.Equal("String", scan.Parameters[0].Kind);
            Assert.True(scan.Parameters[0].Required);
            Assert.Equal("10.0.0.7", scan.Parameters[0].Placeholder);
            Assert.Equal("range", scan.Parameters[1].Name);

            // The issuance gate is open: the novel verb tasks over the
            // ordinary operator route, arguments built the way the
            // schema-driven form builds them, with no assembly anywhere in
            // the process carrying this namespace.
            var issued = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new TaskEndpoints.IssueTaskRequest(ImplantId: implantId, Verb: ScanVerb, Arguments: "10.0.0.7 1-1024"));
            issued.EnsureSuccessStatusCode();
            var task = await issued.Content.ReadFromJsonAsync<TaskEndpoints.TaskResponse>();

            // The structured-output half of the trilogy holds for a
            // manifest-declared kind too: the enumeration output lands in
            // the topology panel, parsed from the declared kind, never from
            // a verb name anyone was told about.
            var repository = host.Services.GetRequiredService<ITaskRepository>();
            var clock = host.Services.GetRequiredService<TimeProvider>();
            var stored = await repository.FindAsync(new TaskId(Guid.Parse(task!.TaskId)));
            stored!.MarkDispatched(clock.GetUtcNow());
            await repository.SaveAsync(stored);
            var service = host.Services.GetRequiredService<Rod.CoreState.Application.TaskService>();
            await service.RecordResultAsync(
                new TaskId(Guid.Parse(task.TaskId)),
                "{\"host\":\"10.0.0.7\",\"port\":443,\"state\":\"open\",\"service\":\"https\"}",
                TaskOutcome.Succeeded);

            var topology = await client.GetFromJsonAsync<TopologyEndpoints.TopologyResponse>(
                $"/engagements/{engagementId}/topology");
            var https = Assert.Single(topology!.Observations, o => o.Host == "10.0.0.7" && o.Port == 443);
            Assert.Equal(ScanVerb, https.Verb);
        }
    }

    [Fact]
    public async Task TheRequirementRows_ReachTheModuleLoadGate_FromManifestDataAlone()
    {
        // ADR-017's runtime half reads the by-name lookup's Requires; for a
        // manifest-declared module those rows are manifest data, carried
        // from the descriptor-module loader through the registry-backed
        // resolver the live task path holds.
        var (client, host) = CreateClient();
        using (client)
        using (host)
        {
            var registry = host.Services.GetRequiredService<ICapabilityRegistry>();
            var byName = await registry.FindByNameAsync(ModuleName);

            Assert.NotNull(byName);
            Assert.Equal(["plugin-loader/exec-v1"], byName!.Requires);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }
}
