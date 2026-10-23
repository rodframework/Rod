using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.Capabilities;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;
using static Rod.Integration.Tests.EngagementSetup;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance for the browser-hook serving edge (architecture.md Sec 5.2,
/// Sec 8): the mint renders the hook asset module's script with a bake and
/// stores it as a served payload record; the public route serves it scoped by the
/// ingress listener's engagement, gated by the unguessable id, with a
/// first-touch audit per fetch; revocation stops the serving and kills the
/// baked credential. The end-to-end tasking arc these routes feed lives in
/// <see cref="BrowserHookEndToEndTests"/>; this file pins the operator and
/// serving surfaces themselves.
/// </summary>
public class BrowserHookTests
{
    [Fact]
    public async Task MintHook_RendersStoresAndAnswersTheServingUrl()
    {
        await using var env = await HookTestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);
        var listenerId = await env.CreateEngagementListenerAsync(engagementId, "http://c2.example.test");

        var minted = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/hooks",
            new MintHookRequest(ListenerId: listenerId, SleepSeconds: 15, JitterSeconds: 2, Envelope: "aesgcm", TokenMaxUses: 10, KillDate: null));
        minted.EnsureSuccessStatusCode();
        var hook = await minted.Content.ReadFromJsonAsync<MintHookResponse>();
        Assert.NotNull(hook);
        Assert.Equal("aesgcm", hook!.Envelope);
        Assert.Equal(15, hook.SleepSeconds);
        Assert.Equal(10, hook.TokenMaxUses);
        Assert.Equal($"http://c2.example.test/implants/hooks/{hook.HookId}", hook.Url);
        Assert.Equal($"<script src=\"{hook.Url}\"></script>", hook.Snippet);
        Assert.Equal($"{hook.Url}/page", hook.TestPageUrl);

        // The rendered artifact is the template plus this bake: the bake's
        // facts are in the served bytes and the placeholder is gone.
        var payloads = env.Host.Services.GetRequiredService<IPayloadStore>();
        var record = await payloads.FindByIdAsync(Guid.Parse(hook.HookId));
        Assert.NotNull(record);
        Assert.Equal("Browser", record!.Class);
        Assert.Equal("javascript", record.Language);
        Assert.Equal("application/javascript", record.ContentType);
        Assert.NotNull(record.TokenId);
        Assert.NotNull(record.EnvelopeKeyId);
        Assert.NotNull(record.EnvelopeKey);
        var script = System.Text.Encoding.UTF8.GetString(record.Content);
        Assert.DoesNotContain("__ROD_BAKE_JSON__", script);
        Assert.Contains("http://c2.example.test/implants/enroll", script);
        Assert.Contains("http://c2.example.test/implants/beacon", script);
        Assert.Contains("browser.fingerprint", script);

        // The mint is on the engagement's trail.
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        var mintFact = (await audit.ListAsync(Guid.Parse(engagementId)))
            .FirstOrDefault(e => e.Kind == AuditEventKind.HookMinted);
        Assert.NotNull(mintFact);
        Assert.Equal(hook.HookId, mintFact!.Outcome);
    }

    [Fact]
    public async Task HookRoute_ServesOnTheEngagementListener_AuditsEveryFetch_AndRefusesTheOperatorFront()
    {
        await using var env = await HookTestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);
        var listenerId = await env.CreateEngagementListenerAsync(engagementId, "http://c2.example.test");

        var minted = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/hooks",
            new MintHookRequest(ListenerId: listenerId));
        minted.EnsureSuccessStatusCode();
        var hook = await minted.Content.ReadFromJsonAsync<MintHookResponse>();
        Assert.NotNull(hook);

        // The unguessable id is the credential: a plain GET with no header
        // or token serves the script off the engagement's own listener.
        var fetched = await env.Implant.GetAsync($"/implants/hooks/{hook!.HookId}");
        fetched.EnsureSuccessStatusCode();
        Assert.Equal("application/javascript", fetched.Content.Headers.ContentType?.MediaType);
        Assert.Equal("no-store", fetched.Headers.GetValues("Cache-Control").FirstOrDefault());
        var bytes = await fetched.Content.ReadAsByteArrayAsync();
        Assert.NotEmpty(bytes);

        // The test page renders the script tag that pulls the hook in.
        var page = await env.Implant.GetAsync($"/implants/hooks/{hook.HookId}/page");
        page.EnsureSuccessStatusCode();
        var html = await page.Content.ReadAsStringAsync();
        Assert.Contains($"<script src=\"http://c2.example.test/implants/hooks/{hook.HookId}\"></script>", html);

        // Every fetch is the first-touch attribution record.
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        var facts = (await audit.ListAsync(Guid.Parse(engagementId)))
            .Where(e => e.Kind == AuditEventKind.HookFetched)
            .ToArray();
        Assert.Equal(2, facts.Length);
        Assert.Contains(facts, f => f.Payload.Contains("page=script"));
        Assert.Contains(facts, f => f.Payload.Contains("page=test-page"));

        // The operator front (the shared tier) carries no hook ingress, and
        // an unknown id is indistinguishable from a revoked one.
        Assert.Equal(HttpStatusCode.NotFound,
            (await env.Http.GetAsync($"/implants/hooks/{hook.HookId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await env.Implant.GetAsync($"/implants/hooks/{Guid.NewGuid():N}")).StatusCode);
    }

    [Fact]
    public async Task HookRoutes_AnswerTheCorsHeader_OnlyWhenABrowserAsked()
    {
        await using var env = await HookTestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);
        var listenerId = await env.CreateEngagementListenerAsync(engagementId, "http://c2.example.test");

        var minted = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/hooks",
            new MintHookRequest(ListenerId: listenerId));
        minted.EnsureSuccessStatusCode();
        var hook = await minted.Content.ReadFromJsonAsync<MintHookResponse>();
        Assert.NotNull(hook);

        // A browser's cross-origin fetch sends Origin; the answer carries
        // the wildcard the hook needs to read its own contacts.
        using var browserAsk = new HttpRequestMessage(HttpMethod.Get, $"/implants/hooks/{hook!.HookId}");
        browserAsk.Headers.Add("Origin", "https://victim.example");
        var browserAnswer = await env.Implant.SendAsync(browserAsk);
        browserAnswer.EnsureSuccessStatusCode();
        Assert.True(browserAnswer.Headers.TryGetValues("Access-Control-Allow-Origin", out var aco) && aco.Contains("*"));

        // A non-browser client sends no Origin and gets no CORS decoration:
        // the implant wire fingerprint is unchanged.
        var plainAnswer = await env.Implant.GetAsync($"/implants/hooks/{hook.HookId}");
        plainAnswer.EnsureSuccessStatusCode();
        Assert.False(plainAnswer.Headers.TryGetValues("Access-Control-Allow-Origin", out _));

        // The enroll route the hook rides answers the same posture.
        using var enrollAsk = new HttpRequestMessage(HttpMethod.Post, "/implants/enroll")
        {
            Content = new StringContent("{\"deployTokenSecret\":\"none\"}"),
        };
        enrollAsk.Headers.Add("Origin", "https://victim.example");
        var enrollAnswer = await env.Implant.SendAsync(enrollAsk);
        Assert.True(enrollAnswer.Headers.TryGetValues("Access-Control-Allow-Origin", out var aco2) && aco2.Contains("*"));
        var enrollPlain = await env.Implant.PostAsync("/implants/enroll", new StringContent("{\"deployTokenSecret\":\"none\"}"));
        Assert.False(enrollPlain.Headers.TryGetValues("Access-Control-Allow-Origin", out _));
    }

    [Fact]
    public async Task RevokeHook_StopsServing_AndTakesTheRecordWithIt()
    {
        await using var env = await HookTestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);
        var listenerId = await env.CreateEngagementListenerAsync(engagementId, "http://c2.example.test");

        var minted = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/hooks",
            new MintHookRequest(ListenerId: listenerId));
        minted.EnsureSuccessStatusCode();
        var hook = await minted.Content.ReadFromJsonAsync<MintHookResponse>();
        Assert.NotNull(hook);

        // The bake's credential rides the script the route serves.
        var script = await env.Implant.GetStringAsync($"/implants/hooks/{hook!.HookId}");
        Assert.Contains("\"token\":\"", script);

        var revoked = await env.Http.DeleteAsync($"/engagements/{engagementId}/hooks/{hook.HookId}");
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        // The serving route is gone and the record with it.
        Assert.Equal(HttpStatusCode.NotFound,
            (await env.Implant.GetAsync($"/implants/hooks/{hook.HookId}")).StatusCode);
        var payloads = env.Host.Services.GetRequiredService<IPayloadStore>();
        Assert.Null(await payloads.FindByIdAsync(Guid.Parse(hook.HookId)));

        // The roster no longer lists it.
        var roster = await env.Http.GetFromJsonAsync<HookResponse[]>($"/engagements/{engagementId}/hooks");
        Assert.Empty(roster!);
    }

    [Fact]
    public async Task MintHook_RefusesListenersTheHookCannotRide()
    {
        await using var env = await HookTestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);

        // A foreign engagement's listener: the hook would bake a URL whose
        // socket refuses its own enrollment scope.
        var otherEngagement = await CreateEngagementAsync(env.Http);
        var foreignListener = await env.CreateEngagementListenerAsync(otherEngagement, "http://other.example.test");
        var refused = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/hooks",
            new MintHookRequest(ListenerId: foreignListener));
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

        // A listener id that names nothing.
        var unknown = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/hooks",
            new MintHookRequest(ListenerId: Guid.NewGuid().ToString()));
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
    }

    [Fact]
    public async Task MintHook_WithoutAnAssetModule_RefusesLoudlyAndMintsNothing()
    {
        // The host that lists no asset module (open is not on): the mint
        // answers 503 naming the config section -- the deployment fix -- and
        // spends nothing: no hook record, no audit fact exists for the
        // refused mint.
        await using var env = await HookTestEnv.StartAsync(withAssetModule: false);
        var engagementId = await CreateEngagementAsync(env.Http);
        var listenerId = await env.CreateEngagementListenerAsync(engagementId, "http://c2.example.test");

        var minted = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/hooks",
            new MintHookRequest(ListenerId: listenerId));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, minted.StatusCode);
        var problem = await minted.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Contains("Capabilities:AssetModules", problem.GetProperty("title").GetString());

        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        Assert.DoesNotContain(await audit.ListAsync(Guid.Parse(engagementId)),
            e => e.Kind == AuditEventKind.HookMinted);
    }

    private static string FindRepoRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent!)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src"))
                && Directory.Exists(Path.Combine(directory.FullName, "modules")))
                return directory.FullName;
        }
        throw new InvalidOperationException("Could not locate the repo root from the test assembly.");
    }

    /// <summary>
    /// A real-Kestrel host with runtime listener management (the operator
    /// front as the shared tier), plus one engagement-scoped http listener
    /// created per test through the API -- the socket the hook routes serve
    /// on, the shape a production engagement fronts with a redirector.
    /// </summary>
    private sealed class HookTestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;

        /// <summary>The engagement listener's bind socket, where implant ingress lives.</summary>
        public HttpClient Implant { get; private set; } = null!;

        /// <param name="withAssetModule">
        /// Whether the config lists the in-tree browserhook module under
        /// Capabilities:AssetModules. The default true is every other test's
        /// seam shape; the mint-refusal test runs the open-not-on default.
        /// </param>
        public static async Task<HookTestEnv> StartAsync(bool withAssetModule = true)
        {
            var env = new HookTestEnv();

            // The seam's config path: the mint renders whatever asset module
            // the deployment lists -- here the in-tree browserhook module,
            // loaded through Capabilities:AssetModules exactly as the shipped
            // configuration lists it, never referenced by the test code.
            var operatorBind = $"127.0.0.1:{TestSupport.GetFreeTcpPort()}";
            var config = AuthenticatedHost.BuildConfig(extend: settings =>
            {
                if (withAssetModule)
                    settings["Capabilities:AssetModules:0"] = Path.Combine(FindRepoRoot(), "modules", "browserhook");
            });
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(
                        services, config, extra: s => s.AddRodCapabilities(config)),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder.UseRodListeners(new List<ListenerConfig>
                {
                    new(
                        Name: "operator-http",
                        Transport: "http",
                        BindAddress: operatorBind,
                        PublicEndpoint: "http://localhost:5080"),
                }))
                .Build();
            await env.Host.StartAsync();

            env.Http = new HttpClient(new CookieHandler(new HttpClientHandler()))
            {
                BaseAddress = new Uri($"http://{operatorBind}"),
            };
            await AuthenticatedHost.LoginAsync(env.Http);
            return env;
        }

        /// <summary>
        /// Creates an engagement-scoped http listener through the API and
        /// points <see cref="Implant"/> at its bind socket.
        /// </summary>
        public async Task<string> CreateEngagementListenerAsync(string engagementId, string publicEndpoint)
        {
            var created = await Http.PostAsJsonAsync(
                $"/engagements/{engagementId}/listeners",
                new ListenerEndpoints.CreateListenerRequest(
                    Name: "hook-front-" + Guid.NewGuid().ToString("N")[..6],
                    Transport: "http",
                    BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
                    PublicEndpoint: publicEndpoint));
            created.EnsureSuccessStatusCode();
            var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
            Assert.NotNull(listener);
            Implant?.Dispose();
            Implant = new HttpClient { BaseAddress = new Uri($"http://{listener!.BindAddress}") };
            return listener.Id;
        }

        public async ValueTask DisposeAsync()
        {
            Http?.Dispose();
            Implant?.Dispose();
            if (Host is not null)
                await Host.StopAsync();
            Host?.Dispose();
        }
    }
}
