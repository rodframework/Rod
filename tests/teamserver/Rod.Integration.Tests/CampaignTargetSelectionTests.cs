using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Rod.Operators.Endpoints;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;
using Rod.CoreState;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState.Listeners;
using Rod.Transport.Campaigns;

namespace Rod.Integration.Tests;

/// <summary>
/// The unified entity model's target link (architecture.md Sec 15.4): a
/// recon asset from the engagement's target list is directly selectable
/// as a campaign target -- the selection resolves at creation (the row
/// carries the address it will mail, plus the reference that records
/// where the target came from), and an asset a campaign already selected
/// stays on the list while the referencing row lives.
/// </summary>
public class CampaignTargetSelectionTests
{
    private sealed record Harness(
        HttpClient Client,
        IHost Host,
        string Engagement,
        string ListenerId);

    private static async Task<Harness> NewAsync()
    {
        var registry = new InMemoryBuildUnitRegistry();
        registry.Register(new CampaignStubBuildUnit());
        var (client, host, _) = AuthenticatedHost.Create(configureServices: services =>
            services.Replace(ServiceDescriptor.Singleton<IBuildUnitRegistry>(registry)));
        await AuthenticatedHost.LoginAsync(client);

        var created = await client.PostAsJsonAsync("/engagements", new { name = "selection" });
        created.EnsureSuccessStatusCode();
        var engagement = (await created.Content.ReadFromJsonAsync<EngagementBody>())!.EngagementId;

        var listenerId = ListenerId.New();
        var listeners = host.Services.GetRequiredService<IListenerRegistry>();
        await listeners.RegisterAsync(Listener.Define(
            listenerId, "lure-front", "http", "127.0.0.1:8443",
            "http://lure.example.test", DateTimeOffset.UtcNow,
            EngagementId.TryParse(engagement, out var parsed) ? parsed : default));
        return new Harness(client, host, engagement, listenerId.ToString());
    }

    private static CampaignEndpoints.CreateCampaignRequest Body(
        Harness h, List<CampaignEndpoints.CampaignRecipientRequest> recipients) => new(
        Name: "target-selection",
        ListenerId: h.ListenerId,
        Relay: new CampaignEndpoints.CampaignRelayRequest(Host: "127.0.0.1", Port: 25, Tls: "none"),
        From: "billing@lure.example.test",
        Template: new CampaignEndpoints.CampaignTemplateRequest(
            Subject: "Renewal", Body: "Open {{link}}", BodyIsHtml: false),
        Recipients: recipients,
        Build: new PayloadEndpoints.BuildPayloadRequest(
            Language: "go",
            Class: "Implant",
            TargetOs: null,
            TargetArch: null,
            ListenerId: h.ListenerId));

    private static async Task<ReconAssetEndpoints.ReconAssetResponse> RecordAsync(
        HttpClient client, string engagement, string kind, string value, string? displayName = null)
    {
        var recorded = await client.PostAsJsonAsync(
            $"/engagements/{engagement}/recon-assets",
            new ReconAssetEndpoints.RecordReconAssetRequest(kind, value, displayName));
        recorded.EnsureSuccessStatusCode();
        return (await recorded.Content.ReadFromJsonAsync<ReconAssetEndpoints.ReconAssetResponse>())!;
    }

    [Fact]
    public async Task AssetBackedRecipient_ResolvesAddressAndName_AtCreation()
    {
        var h = await NewAsync();
        using (h.Client)
        using (h.Host)
        {
            var asset = await RecordAsync(h.Client, h.Engagement, "email",
                "vp@example.com", "The Vice President");

            var created = await h.Client.PostAsJsonAsync(
                $"/engagements/{h.Engagement}/campaigns",
                Body(h, [new CampaignEndpoints.CampaignRecipientRequest(
                    Email: null, Name: null, ReconAssetId: asset.AssetId)]));
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            var campaign = await created.Content.ReadFromJsonAsync<CampaignEndpoints.CampaignResponse>();
            Assert.NotNull(campaign);

            // The selection resolved: the row mails the asset's address,
            // the merge name defaults to the asset's display name, and the
            // reference rides the row as the record of selection.
            var recipient = Assert.Single(campaign!.Recipients!);
            Assert.Equal("vp@example.com", recipient.Email);
            Assert.Equal("The Vice President", recipient.Name);
            Assert.Equal(asset.AssetId, recipient.ReconAssetId);

            // The trail names how many targets came off the list.
            var detail = await h.Client.GetFromJsonAsync<CampaignEndpoints.CampaignResponse>(
                $"/engagements/{h.Engagement}/campaigns/{campaign.CampaignId}");
            Assert.NotNull(detail);
            Assert.Equal(asset.AssetId, Assert.Single(detail!.Recipients!).ReconAssetId);
        }
    }

    [Fact]
    public async Task TypedName_OverridesTheAssetsDisplayName()
    {
        var h = await NewAsync();
        using (h.Client)
        using (h.Host)
        {
            var asset = await RecordAsync(h.Client, h.Engagement, "email",
                "named@example.com", "The Asset Name");

            var created = await h.Client.PostAsJsonAsync(
                $"/engagements/{h.Engagement}/campaigns",
                Body(h, [new CampaignEndpoints.CampaignRecipientRequest(
                    Email: null, Name: "Typed Name", ReconAssetId: asset.AssetId)]));
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            var campaign = await created.Content.ReadFromJsonAsync<CampaignEndpoints.CampaignResponse>();
            Assert.Equal("Typed Name", Assert.Single(campaign!.Recipients!).Name);
        }
    }

    [Fact]
    public async Task NonEmailAsset_AsTarget_IsRefused()
    {
        var h = await NewAsync();
        using (h.Client)
        using (h.Host)
        {
            var asset = await RecordAsync(h.Client, h.Engagement, "host", "mail.example.com");

            var created = await h.Client.PostAsJsonAsync(
                $"/engagements/{h.Engagement}/campaigns",
                Body(h, [new CampaignEndpoints.CampaignRecipientRequest(
                    Email: null, Name: null, ReconAssetId: asset.AssetId)]));
            Assert.Equal(HttpStatusCode.UnprocessableEntity, created.StatusCode);
            var problem = await created.Content.ReadFromJsonAsync<ProblemBody>();
            Assert.NotNull(problem!.Error);
            Assert.Contains("not an email target", problem.Error);
        }
    }

    [Fact]
    public async Task ForeignAsset_AsTarget_IsRefused()
    {
        var h = await NewAsync();
        using (h.Client)
        using (h.Host)
        {
            // The same operator's other engagement owns the asset; a
            // foreign engagement's target list is indistinguishable from
            // an absent one (architecture.md Sec 3).
            var other = await SecondEngagementAsync(h);
            var asset = await RecordAsync(h.Client, other, "email", "foreign@example.com");

            var created = await h.Client.PostAsJsonAsync(
                $"/engagements/{h.Engagement}/campaigns",
                Body(h, [new CampaignEndpoints.CampaignRecipientRequest(
                    Email: null, Name: null, ReconAssetId: asset.AssetId)]));
            Assert.Equal(HttpStatusCode.NotFound, created.StatusCode);
        }
    }

    [Fact]
    public async Task RecipientEntry_MustNameExactlyOneSource()
    {
        var h = await NewAsync();
        using (h.Client)
        using (h.Host)
        {
            var asset = await RecordAsync(h.Client, h.Engagement, "email", "both@example.com");

            var both = await h.Client.PostAsJsonAsync(
                $"/engagements/{h.Engagement}/campaigns",
                Body(h, [new CampaignEndpoints.CampaignRecipientRequest(
                    Email: "typed@example.com", Name: null, ReconAssetId: asset.AssetId)]));
            Assert.Equal(HttpStatusCode.BadRequest, both.StatusCode);

            var neither = await h.Client.PostAsJsonAsync(
                $"/engagements/{h.Engagement}/campaigns",
                Body(h, [new CampaignEndpoints.CampaignRecipientRequest(Email: null, Name: "no address")]));
            Assert.Equal(HttpStatusCode.BadRequest, neither.StatusCode);
        }
    }

    [Fact]
    public async Task AssetAndTypedCopy_OfTheSameMailbox_IsTheDuplicateItIs()
    {
        var h = await NewAsync();
        using (h.Client)
        using (h.Host)
        {
            var asset = await RecordAsync(h.Client, h.Engagement, "email", "dupe@example.com");

            var created = await h.Client.PostAsJsonAsync(
                $"/engagements/{h.Engagement}/campaigns",
                Body(h,
                [
                    new CampaignEndpoints.CampaignRecipientRequest(Email: "dupe@example.com"),
                    new CampaignEndpoints.CampaignRecipientRequest(Email: null, ReconAssetId: asset.AssetId),
                ]));
            // One mailbox, one lure: the selection resolves into the same
            // duplicate check the typed list always ran.
            Assert.Equal(HttpStatusCode.BadRequest, created.StatusCode);
        }
    }

    [Fact]
    public async Task DeleteRefused_WhileACampaignRecipientSelectsTheAsset()
    {
        var h = await NewAsync();
        using (h.Client)
        using (h.Host)
        {
            var selected = await RecordAsync(h.Client, h.Engagement, "email", "kept@example.com");
            var unselected = await RecordAsync(h.Client, h.Engagement, "email", "dropped@example.com");

            var created = await h.Client.PostAsJsonAsync(
                $"/engagements/{h.Engagement}/campaigns",
                Body(h, [new CampaignEndpoints.CampaignRecipientRequest(
                    Email: null, ReconAssetId: selected.AssetId)]));
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);

            // The selected target stays on the books: the recipient row's
            // reference is the record of the engagement aiming at it.
            var refused = await h.Client.DeleteAsync(
                $"/engagements/{h.Engagement}/recon-assets/{selected.AssetId}");
            Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);

            var freed = await h.Client.DeleteAsync(
                $"/engagements/{h.Engagement}/recon-assets/{unselected.AssetId}");
            Assert.Equal(HttpStatusCode.NoContent, freed.StatusCode);
        }
    }

    // A second engagement under the same operator: the isolation foil.
    private static async Task<string> SecondEngagementAsync(Harness h)
    {
        var created = await h.Client.PostAsJsonAsync("/engagements", new { name = "foreign" });
        created.EnsureSuccessStatusCode();
        return (await created.Content.ReadFromJsonAsync<EngagementBody>())!.EngagementId;
    }

    private sealed record EngagementBody(string EngagementId);
    private sealed record ProblemBody(string? Error);
}
