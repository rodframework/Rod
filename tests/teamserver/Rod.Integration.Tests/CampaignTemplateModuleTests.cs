using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Rod.BuildPipeline.PayloadBuild;
using Rod.Capabilities;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;

namespace Rod.Integration.Tests;

/// <summary>
/// The campaign's half of the asset seam (architecture.md Sec 11.5, Sec
/// 15.1): a campaign may take its message template by reference --
/// <c>module/asset</c> -- resolved from the listed asset modules at
/// creation and stored resolved on the campaign row, so what will be sent
/// is on the row and the send engine never knows a module was involved.
/// The merge grammar itself stays the kernel's contract either way
/// (<see cref="Rod.CoreState.Campaigns.CampaignLimits"/>).
/// </summary>
public class CampaignTemplateModuleTests
{
    private static string ModuleRoot()
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
    /// The in-memory host with the in-tree lure-templates module listed, the
    /// stub build unit the campaign's build-profile validation needs, and a
    /// seeded engagement listener -- the same parts the campaign walk's
    /// harness composes, with the asset seam added.
    /// </summary>
    private static async Task<(HttpClient Client, IHost Host, string EngagementId, string ListenerId)> NewAsync(
        Action<Dictionary<string, string?>>? extendConfig = null)
    {
        var registry = new InMemoryBuildUnitRegistry();
        registry.Register(new CampaignStubBuildUnit());
        var (client, host, _) = AuthenticatedHost.Create(
            configureServices: services =>
                services.Replace(ServiceDescriptor.Singleton<IBuildUnitRegistry>(registry)),
            extendConfig: settings =>
            {
                settings["Capabilities:AssetModules:0"] = Path.Combine(ModuleRoot(), "modules", "lure-templates");
                extendConfig?.Invoke(settings);
            },
            configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config));
        await AuthenticatedHost.LoginAsync(client);

        var created = await client.PostAsJsonAsync("/engagements", new { name = "template-refs" });
        created.EnsureSuccessStatusCode();
        var engagement = await created.Content.ReadFromJsonAsync<EngagementBody>();
        Assert.True(EngagementId.TryParse(engagement!.EngagementId, out var engagementId));

        var listenerId = ListenerId.New();
        var listeners = host.Services.GetRequiredService<IListenerRegistry>();
        await listeners.RegisterAsync(Listener.Define(
            listenerId, "lure-front", "http", "127.0.0.1:8443",
            "http://lure.example.test", DateTimeOffset.UtcNow, engagementId));
        return (client, host, engagement.EngagementId, listenerId.ToString());
    }

    private static CampaignEndpoints.CreateCampaignRequest Request(
        string listenerId, CampaignEndpoints.CampaignTemplateRequest template) => new(
        Name: "template-ref",
        ListenerId: listenerId,
        Relay: new CampaignEndpoints.CampaignRelayRequest(Host: "127.0.0.1", Port: 25, Tls: "none"),
        From: "billing@lure.example.test",
        Template: template,
        Recipients: [new CampaignEndpoints.CampaignRecipientRequest("target@example.test", "Target")],
        Build: new PayloadEndpoints.BuildPayloadRequest(
            Language: "go",
            Class: "Implant",
            TargetOs: null,
            TargetArch: null,
            ListenerId: listenerId));

    [Fact]
    public async Task AReferencedTemplate_ResolvesAtCreation_AndStoresResolved()
    {
        var (client, host, engagementId, listenerId) = await NewAsync();
        using (client)
        using (host)
        {
            var created = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/campaigns",
                Request(listenerId, new CampaignEndpoints.CampaignTemplateRequest(
                    Subject: null, Body: null, Ref: "lure-templates/document-review")));
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);

            // The row carries the resolved text -- what will be sent, no
            // trace of the module left to resolve later.
            var campaign = await created.Content.ReadFromJsonAsync<CampaignEndpoints.CampaignResponse>();
            Assert.NotNull(campaign);
            Assert.Equal("draft", campaign!.State);
            var audit = host.Services.GetRequiredService<Rod.Audit.IAuditStore>();
            var fact = (await audit.ListAsync(Guid.Parse(engagementId)))
                .Single(e => e.Kind == Rod.Audit.AuditEventKind.CampaignStateChanged);
            Assert.Contains("template=lure-templates/document-review", fact.Payload);
        }
    }

    [Fact]
    public async Task AReferencedHtmlTemplate_StoresTheHtmlFlag()
    {
        var (client, host, engagementId, listenerId) = await NewAsync();
        using (client)
        using (host)
        {
            var created = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/campaigns",
                Request(listenerId, new CampaignEndpoints.CampaignTemplateRequest(
                    Subject: null, Body: null, Ref: "lure-templates/security-notice")));
            created.EnsureSuccessStatusCode();
            var detail = await created.Content.ReadFromJsonAsync<CampaignEndpoints.CampaignResponse>();
            Assert.NotNull(detail);
            Assert.True(detail!.BodyIsHtml);
        }
    }

    [Theory]
    [InlineData("lure-templates/absent")]
    [InlineData("no-such-module/document-review")]
    public async Task AnUnknownReference_IsRefusedNamingTheSeam(string reference)
    {
        var (client, host, engagementId, listenerId) = await NewAsync();
        using (client)
        using (host)
        {
            var refused = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/campaigns",
                Request(listenerId, new CampaignEndpoints.CampaignTemplateRequest(
                    Subject: null, Body: null, Ref: reference)));
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            var problem = await refused.Content.ReadFromJsonAsync<ProblemBody>();
            Assert.Contains("Capabilities:AssetModules", problem!.Error);
        }
    }

    [Theory]
    [InlineData("bare-name")]
    [InlineData("one/two/three")]
    [InlineData("trailing/")]
    public async Task AMalformedReference_IsRefusedNamingTheGrammar(string reference)
    {
        var (client, host, engagementId, listenerId) = await NewAsync();
        using (client)
        using (host)
        {
            var refused = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/campaigns",
                Request(listenerId, new CampaignEndpoints.CampaignTemplateRequest(
                    Subject: null, Body: null, Ref: reference)));
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            var problem = await refused.Content.ReadFromJsonAsync<ProblemBody>();
            Assert.Contains("must be 'module/asset'", problem!.Error);
        }
    }

    [Fact]
    public async Task AReferenceAlongsideInlineText_IsRefused()
    {
        var (client, host, engagementId, listenerId) = await NewAsync();
        using (client)
        using (host)
        {
            var refused = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/campaigns",
                Request(listenerId, new CampaignEndpoints.CampaignTemplateRequest(
                    Subject: "Both", Body: null, Ref: "lure-templates/document-review")));
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            var problem = await refused.Content.ReadFromJsonAsync<ProblemBody>();
            Assert.Contains("both a module reference and inline text", problem!.Error);
        }
    }

    [Fact]
    public async Task AnAssetThatIsNotATemplate_IsRefusedNamingTheShape()
    {
        // A module whose declared asset skips the file contract (no Subject
        // line): the seam's parse refusal, not a module-loading failure.
        var root = Path.Combine(Path.GetTempPath(), "rod-lure-shape-" + Guid.NewGuid().ToString("N"));
        var module = Path.Combine(root, "brokentemplates");
        Directory.CreateDirectory(Path.Combine(module, "assets"));
        File.WriteAllText(Path.Combine(module, "rod-module.toml"), """
            [module]
            name = "broken-templates"
            version = "1.0.0"
            entry = "assets"
            license = "Apache-2.0"

            [compatibility]
            teamserver = "1.0.0"

            [opsec]
            lands-on-disk = false

            [[assets]]
            name = "not-a-template"
            path = "assets/blob.txt"
            """);
        File.WriteAllText(Path.Combine(module, "assets", "blob.txt"), "just some text, no shape at all");

        try
        {
            var (client, host, engagementId, listenerId) = await NewAsync(
                settings => settings["Capabilities:AssetModules:1"] = module);
            using (client)
            using (host)
            {
                var refused = await client.PostAsJsonAsync(
                    $"/engagements/{engagementId}/campaigns",
                    Request(listenerId, new CampaignEndpoints.CampaignTemplateRequest(
                        Subject: null, Body: null, Ref: "broken-templates/not-a-template")));
                Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
                var problem = await refused.Content.ReadFromJsonAsync<ProblemBody>();
                Assert.Contains("not a campaign template", problem!.Error);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed record ProblemBody(string? Error);
    private sealed record EngagementBody(string EngagementId, string Name);
}
