using System.Net.Http.Json;
using Xunit.Abstractions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.Transport.Range;

namespace Rod.Integration.Tests;

/// <summary>
/// Range mode's acceptance (architecture.md Sec 15.3): the fake implants run
/// the real protocol end to end -- enroll through the listener's real
/// ingress, the envelope POST cycle with canonical tasking verification, and
/// results that land in the same task log and audit arcs any implant's do --
/// and a 500-beacon fleet simulates under load against one teamserver.
/// </summary>
public class RangeModeTests(ITestOutputHelper output)
{
    private void Phase(string name) => output.WriteLine($"[{DateTimeOffset.UtcNow:HH:mm:ss.fff}] {name}");

    [Fact]
    public async Task AFleet_EnrollsTasksAndChurns_ThroughTheRealProtocol()
    {
        await using var env = await TestEnv.StartAsync();
        var fleet = await env.SpawnAsync(new RangeEndpoints.RangeSpawnRequest(
            ListenerId: env.ListenerId,
            Count: 12,
            SleepSeconds: 1,
            JitterSeconds: 0.5,
            GoDarkCount: 2,
            Prefix: "fleet",
            DarkAfterSeconds: 2,
            DarkForSeconds: 2));

        // Enrollment through the listener's real ingress: roster rows with
        // the simulated host facts, not rows an API carved out of thin air.
        await WaitUntilAsync(async () => fleet.Enrolled == 12, TimeSpan.FromSeconds(30));
        var implants = await env.Http.GetFromJsonAsync<ImplantEndpoints.ImplantResponse[]>(
            $"/engagements/{env.EngagementId}/implants");
        Assert.Equal(12, implants!.Length);
        Assert.All(implants, i => Assert.StartsWith("fleet-", i.Hostname ?? "", StringComparison.Ordinal));
        Assert.All(implants, i => Assert.Equal("linux", i.Os));
        Assert.All(implants, i => Assert.True(i.IsOnline));

        // Tasking through the operator surface, answered by the script, the
        // result landing through the same ingest path any result rides.
        var target = implants.First(i => i.IsOnline);
        var task = await IssueTaskAsync(env, target.ImplantId, "shell.exec", "whoami");
        var completed = await WaitTaskAsync(env, task, TimeSpan.FromSeconds(30));
        Assert.Equal("Succeeded", completed.Outcome);
        Assert.Contains("simulated range shell output", completed.Output);

        // The dark leg: the two churn beacons drop (the roster's online set
        // loses them) and come back as the same identities.
        await WaitUntilAsync(async () => fleet.Dark == 2, TimeSpan.FromSeconds(20));
        await WaitUntilAsync(async () => fleet.Contacting == 12, TimeSpan.FromSeconds(20));

        // beacon.sleep retunes the beacon's own cadence.
        var retune = await IssueTaskAsync(env, target.ImplantId, "beacon.sleep", "3");
        var retuned = await WaitTaskAsync(env, retune, TimeSpan.FromSeconds(30));
        Assert.Equal("Succeeded", retuned.Outcome);

        // An unadvertised verb refuses with the real implant's grammar.
        var refused = await IssueTaskAsync(env, target.ImplantId, "proc.kill", "4242");
        var refusal = await WaitTaskAsync(env, refused, TimeSpan.FromSeconds(30));
        Assert.Equal("Failed", refusal.Outcome);
        Assert.Contains("no handler for the verb", refusal.Output);

        // Stop retires the loops, and the evidence stays: the report carries
        // the range banner and the spawn/stop facts.
        var stopped = await env.Http.PostAsync($"{env.Base}/engagements/{env.EngagementId}/range:stop", null);
        stopped.EnsureSuccessStatusCode();
        var report = await env.Http.GetStringAsync(
            $"/engagements/{env.EngagementId}/report?format=markdown");
        Assert.Contains("range engagement", report, StringComparison.Ordinal);
        Assert.Contains("range-spawn", report, StringComparison.Ordinal);
        Assert.Contains("range-stop", report, StringComparison.Ordinal);
        Assert.Contains("shell.exec", report, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FiveHundredBeacons_SimulateUnderLoad_AgainstOneTeamserver()
    {
        await using var env = await TestEnv.StartAsync();
        var fleet = await env.SpawnAsync(new RangeEndpoints.RangeSpawnRequest(
            ListenerId: env.ListenerId,
            Count: 500,
            SleepSeconds: 2,
            JitterSeconds: 1));

        Phase("spawn issued");
        // 500 enrollments through the real ingress, in bounded waves.
        var progressWatch = DateTimeOffset.UtcNow;
        await WaitUntilAsync(async () =>
        {
            if (DateTimeOffset.UtcNow - progressWatch >= TimeSpan.FromSeconds(10))
            {
                progressWatch = DateTimeOffset.UtcNow;
                Phase($"waiting: enrolled={fleet.Enrolled} contacting={fleet.Contacting}");
            }
            return fleet.Enrolled == 500;
        }, TimeSpan.FromSeconds(180));
        Phase("all 500 enrolled");
        var implants = await env.Http.GetFromJsonAsync<ImplantEndpoints.ImplantResponse[]>(
            $"/engagements/{env.EngagementId}/implants");
        Assert.Equal(500, implants!.Length);
        Phase("roster read");

        // The fleet is under sustained contact, not merely enrolled: the
        // contact counter climbs while the roster holds its online set.
        var sample = fleet.Contacts;
        Assert.True(sample > 0, "the fleet had not completed a contact cycle");
        await Task.Delay(TimeSpan.FromSeconds(5));
        Assert.True(fleet.Contacts > sample, "the fleet's contact counter stopped climbing");
        Phase($"contacts {sample} -> {fleet.Contacts}");
        Assert.Contains(implants, i => i.IsOnline);

        // Tasking answers inside the crowd: one beacon completes a shell
        // round trip while the other 499 keep polling.
        var target = implants.First(i => i.IsOnline);
        var task = await IssueTaskAsync(env, target.ImplantId, "shell.exec", "id");
        var completed = await WaitTaskAsync(env, task, TimeSpan.FromSeconds(45));
        Assert.Equal("Succeeded", completed.Outcome);
        Phase("task completed");

        var stopped = await env.Http.PostAsync($"{env.Base}/engagements/{env.EngagementId}/range:stop", null);
        stopped.EnsureSuccessStatusCode();
        Phase("stopped");
    }

    private static async Task<string> IssueTaskAsync(
        TestEnv env, string implantId, string verb, string arguments)
    {
        var response = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks",
            new TaskEndpoints.IssueTaskRequest(implantId, verb, arguments));
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<TaskBody>();
        return body!.TaskId;
    }

    private static async Task<TaskBody> WaitTaskAsync(TestEnv env, string taskId, TimeSpan deadline)
    {
        var end = DateTimeOffset.UtcNow + deadline;
        while (DateTimeOffset.UtcNow < end)
        {
            var body = await env.Http.GetFromJsonAsync<TaskBody>(
                $"/engagements/{env.EngagementId}/tasks/{taskId}");
            if (body!.Status == "Completed")
                return body;
            await Task.Delay(250);
        }
        throw new TimeoutException($"task {taskId} did not complete within {deadline}.");
    }

    private static async Task WaitUntilAsync(Func<Task<bool>> condition, TimeSpan deadline)
    {
        var end = DateTimeOffset.UtcNow + deadline;
        while (DateTimeOffset.UtcNow < end)
        {
            if (await condition())
                return;
            await Task.Delay(250);
        }
        throw new TimeoutException($"condition not met within {deadline}.");
    }

    private sealed record TaskBody
    {
        public string TaskId { get; set; } = "";
        public string Status { get; set; } = "";
        public string? Outcome { get; set; }
        public string? Output { get; set; }
    }

    /// <summary>
    /// A real-Kestrel host with range mode enabled: the fleet's beacons dial
    /// the engagement's own http listener over real loopback sockets, and the
    /// test drives the operator surface over the same sockets.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public required IHost Host { get; init; }
        public required HttpClient Http { get; init; }
        public required string Base { get; init; }
        public required string EngagementId { get; init; }
        public required Guid ListenerId { get; init; }
        public required RangeFleet Fleet { get; init; }

        public static async Task<TestEnv> StartAsync()
        {
            var httpPort = TestSupport.GetFreeTcpPort();
            var listenerPort = TestSupport.GetFreeTcpPort();
            var config = AuthenticatedHost.BuildConfig(settings =>
            {
                settings["Range:Enabled"] = "true";
            });

            IHost host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
                    .UseRodListeners(new List<Rod.Transport.Listeners.ListenerConfig>())
                    .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(httpPort)))
                .Build();
            await host.StartAsync();

            var http = new HttpClient(new CookieHandler(new HttpClientHandler()))
            {
                BaseAddress = new Uri($"http://127.0.0.1:{httpPort}"),
            };
            await AuthenticatedHost.LoginAsync(http);

            // The range engagement and the http-family listener it fleets on,
            // both through the operator surface the way a trainer would.
            var engagement = await http.PostAsJsonAsync("/engagements",
                new EngagementEndpoints.CreateEngagementRequest("Operation Range Walk", Range: true));
            engagement.EnsureSuccessStatusCode();
            var engagementId = (await engagement.Content.ReadFromJsonAsync<
                EngagementEndpoints.EngagementResponse>())!.EngagementId;

            var listener = await http.PostAsJsonAsync(
                $"/engagements/{engagementId}/listeners",
                new ListenerEndpoints.CreateListenerRequest(
                    "range-front", "http", $"127.0.0.1:{listenerPort}", ""));
            listener.EnsureSuccessStatusCode();
            var listenerId = (await listener.Content.ReadFromJsonAsync<
                ListenerEndpoints.ListenerResponse>())!.Id;

            return new TestEnv
            {
                Host = host,
                Http = http,
                Base = $"http://127.0.0.1:{httpPort}",
                EngagementId = engagementId,
                ListenerId = Guid.Parse(listenerId),
                Fleet = host.Services.GetRequiredService<RangeFleet>(),
            };
        }

        /// <summary>Spawns through the HTTP surface, then returns a live view
        /// over the engine's status (the same snapshot the status route
        /// reads, without the polling chatter).</summary>
        public async Task<FleetView> SpawnAsync(RangeEndpoints.RangeSpawnRequest request)
        {
            var spawn = await Http.PostAsJsonAsync(
                $"/engagements/{EngagementId}/range:spawn", request);
            spawn.EnsureSuccessStatusCode();
            return new FleetView(this);
        }

        public sealed class FleetView(TestEnv env)
        {
            public int Enrolled => Snapshot().Enrolled;
            public int Contacting => Snapshot().Contacting;
            public int Dark => Snapshot().Dark;
            public long Contacts => Snapshot().Contacts;

            private RangeFleetStatus Snapshot()
                => env.Fleet.StatusOf(new Rod.CoreState.EngagementId(Guid.Parse(env.EngagementId)))
                    ?? throw new InvalidOperationException("the fleet vanished before the test read it.");
        }

        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            await Host.StopAsync();
            Host.Dispose();
        }
    }
}
