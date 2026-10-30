using System.Net;
using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Capabilities;
using Rod.Persistence;
using Rod.TeamServer;
using Rod.Transport;
using Task = System.Threading.Tasks.Task;

namespace Rod.Integration.Tests;

/// <summary>
/// The built-in diagnostics endpoint (architecture.md Sec 15.3, ADR-008): one
/// deployment-admin read over the five dimensions -- beacon turnaround
/// distribution, task queue depth, connected operator streams, recent build
/// durations, and the loaded module set. These tests pin the endpoint's three
/// standing rules: the deployment admin's alone (a member is forbidden, an
/// anonymous request challenged), aggregates only (every section reads the
/// whole deployment with no engagement dimension), and outside the versioned
/// OpenAPI contract (the UI's and the admin's face, not an SDK surface -- the
/// same placement the capability catalog took).
/// </summary>
[Collection("reference-set")]
public class DiagnosticsEndpointsTests(ReferenceSetFixture fixture)
{

    // The full composition the endpoint needs: the capabilities layer's
    // registry beside the operator/transport/auth core, the diagnostics
    // endpoint mapped the way the teamserver host maps it.
    private static (HttpClient Client, IHost Host) AdminClient(
        Action<Dictionary<string, string?>>? extendConfig = null)
    {
        var (client, host, _) = AuthenticatedHost.Create(
            extendConfig: extendConfig,
            configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config),
            mapEndpoints: endpoints => endpoints.MapDiagnosticsEndpoints());
        AuthenticatedHost.LoginAsync(client).GetAwaiter().GetResult();
        return (client, host);
    }

    [Fact]
    public async Task Diagnostics_IsRejectedAnonymously()
    {
        var (client, host, _) = AuthenticatedHost.Create(
            configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config),
            mapEndpoints: endpoints => endpoints.MapDiagnosticsEndpoints());
        using var _ = host;

        var response = await client.GetAsync("/diagnostics");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Diagnostics_IsForbiddenToAMember()
    {
        var (_, host, _) = AuthenticatedHost.Create(
            configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config),
            mapEndpoints: endpoints => endpoints.MapDiagnosticsEndpoints());
        using var _ = host;

        // The aggregates cross every engagement by construction, so a member
        // scoped to one engagement has no business reading them -- the same
        // claim the deployment audit trail requires.
        await AuthenticatedHost.RegisterOperatorAsync(host, "diagnostics-member", "member-p@ss!");
        var memberClient = AuthenticatedHost.CreateClient(host);
        await AuthenticatedHost.LoginAsync(memberClient, "diagnostics-member", "member-p@ss!");

        var response = await memberClient.GetAsync("/diagnostics");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Diagnostics_ReportsTheFiveSections_AsDeploymentAggregates()
    {
        var (client, host) = AdminClient();
        using (client)
        using (host)
        {
            var report = await client.GetFromJsonAsync<JsonNode>("/diagnostics");
            Assert.NotNull(report);

            // Beacon turnaround: the fixed bucket ladder, all zeros on a host
            // that has seen no beacon -- the shape is the contract, not the
            // traffic.
            var buckets = report!["beacons"]!["latencyBuckets"]!.AsArray();
            Assert.NotEmpty(buckets);
            Assert.Contains(buckets, b => (string?)b!["label"] == "<= 1ms");

            // Task queue: all four lifecycle counts present.
            var queue = report["taskQueue"]!;
            Assert.NotNull(queue["queued"]);
            Assert.NotNull(queue["dispatched"]);
            Assert.NotNull(queue["completed"]);
            Assert.NotNull(queue["cancelled"]);

            // Operator streams and builds: the counters exist and read zero
            // on an idle host.
            Assert.Equal(0, (int)report["operatorStreams"]!["connectedStreams"]!);
            Assert.Equal(0, (int)report["builds"]!["total"]!);

            // Modules: a host with no config-listed modules carries only the
            // built-in placeholders.
            var modules = report["modules"]!;
            Assert.Empty(modules["loaded"]!.AsArray());
            Assert.True((int)modules["verbsRegistered"]! > 0);
            Assert.Equal((int)modules["verbsRegistered"]!, (int)modules["verbsPlaceholder"]!);
        }
    }

    [Fact]
    public async Task Diagnostics_CountsAConnectedOperatorStream_WhileItIsOpen()
    {
        var (client, host) = AdminClient();
        using (host)
        {
            using (client)
            {
                var engagementId = await EngagementSetup.CreateEngagementAsync(client, "Operation pulse");

                var request = new HttpRequestMessage(HttpMethod.Get,
                    $"/engagements/{engagementId}/events");
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
                using var stream = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
                Assert.Equal(HttpStatusCode.OK, stream.StatusCode);

                // The subscription registers server-side as the endpoint
                // starts enumerating; poll until it shows.
                await UntilAsync(async () =>
                {
                    var report = await client.GetFromJsonAsync<JsonNode>("/diagnostics");
                    return (int)report!["operatorStreams"]!["connectedStreams"]! >= 1;
                });
            }

            // The SSE stream died with the client above; a fresh client over
            // the still-running host sees the count fall back to zero.
            var fresh = AuthenticatedHost.CreateClient(host);
            await AuthenticatedHost.LoginAsync(fresh);
            await UntilAsync(async () =>
            {
                var report = await fresh.GetFromJsonAsync<JsonNode>("/diagnostics");
                return (int)report!["operatorStreams"]!["connectedStreams"]! == 0;
            });
        }
    }

    [Fact]
    public async Task Diagnostics_ReportsTheLoadedModuleSet()
    {
        // The exact section the shipped appsettings.json carries: the
        // installed hostenum package from the reference-set store (a pure
        // descriptor manifest, ADR-018), through the same path an
        // operator's installed set takes, so the diagnostics module
        // section reads the real loading state, not a fixture's.
        var hostenumDirectory = fixture.ModuleDirectory("hostenum");
        var (client, host) = AdminClient(extendConfig: settings =>
            settings["Capabilities:DescriptorModules:0"] = hostenumDirectory);
        using (client)
        using (host)
        {
            var report = await client.GetFromJsonAsync<JsonNode>("/diagnostics");
            var loaded = report!["modules"]!["loaded"]!.AsArray();

            var hostenum = loaded.SingleOrDefault(m => (string?)m!["name"] == "hostenum");
            Assert.NotNull(hostenum);
            Assert.Contains("recon.hostenum",
                hostenum!["verbs"]!.AsArray().Select(v => (string?)v));

            // One verb moved off the placeholders: registered = placeholder +
            // module-carried.
            var registered = (int)report["modules"]!["verbsRegistered"]!;
            var placeholder = (int)report["modules"]!["verbsPlaceholder"]!;
            Assert.Equal(registered - 1, placeholder);
        }
    }

    [Fact]
    public async Task TheVersionedContract_CarriesNoDiagnosticsPath()
    {
        // ADR-006's contract is the SDK integration surface; ADR-008's
        // diagnostics is the UI's and the admin's operational face. The
        // OpenAPI test host never maps the endpoint, so the committed spec
        // carries no /diagnostics path -- pinned here so moving the endpoint
        // into the contract is a deliberate act, not a mapping accident.
        var (client, host, _) = AuthenticatedHost.Create();
        using var _ = host;
        await AuthenticatedHost.LoginAsync(client);

        var document = await client.GetFromJsonAsync<JsonNode>("/openapi/v1.json");

        Assert.DoesNotContain(document!["paths"]!.AsObject().Select(p => p.Key),
            path => path.StartsWith("/diagnostics", StringComparison.Ordinal));
    }

    // The Postgres leg: the queue-depth aggregate must translate through EF
    // Core onto Npgsql, so one read runs against the real engine (empty
    // counts are fine -- the query itself is the thing under test). Skips,
    // not fails, when Docker is unavailable, the suite's standing posture.
    [Fact]
    public async Task Diagnostics_ReadsTaskCountsThroughPostgres()
    {
        var postgres = new PostgresFixture();
        await postgres.InitializeAsync();
        try
        {
            if (!postgres.IsAvailable)
                return;

            var config = AuthenticatedHost.BuildConfig(extend: dict =>
                dict["ConnectionStrings:Postgres"] = postgres.ConnectionString);

            var host = TransportHost.CreateHostBuilder(
                    configuration: config,
                    configureServices: services => AuthenticatedHost.ComposeServices(
                        services, config, extra: s => s.AddRodCapabilities(config).AddRodPersistence(config)),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(
                        endpoints, extra: e => e.MapDiagnosticsEndpoints()))
                .ConfigureWebHost(webBuilder => webBuilder.UseTestServer())
                .Build();

            var factory = host.Services.GetRequiredService<IDbContextFactory<RodPersistenceDbContext>>();
            await using (var db = await factory.CreateDbContextAsync())
            {
                await db.Database.MigrateAsync();
            }
            await host.StartAsync();

            var server = host.Services.GetRequiredService<IServer>() as TestServer
                ?? throw new InvalidOperationException("TestServer was not registered.");
            using var client = new HttpClient(new CookieHandler(server.CreateHandler()))
            {
                BaseAddress = new Uri("http://localhost"),
            };
            await AuthenticatedHost.LoginAsync(client);

            var report = await client.GetFromJsonAsync<JsonNode>("/diagnostics");

            Assert.NotNull(report);
            Assert.Equal(0, (int)report!["taskQueue"]!["queued"]!);
        }
        finally
        {
            await postgres.DisposeAsync();
        }
    }

    // Polls a condition with a bounded wait: the SSE subscription registers
    // as the endpoint starts enumerating, which races the first read.
    private static async Task UntilAsync(Func<Task<bool>> condition)
    {
        for (var round = 0; round < 100; round++)
        {
            if (await condition())
                return;
            await Task.Delay(10);
        }
        Assert.Fail("The condition did not hold within the bounded wait.");
    }
}
