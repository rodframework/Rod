using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.CoreState;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Deployment;
using Rod.CoreState.Implants;
using Rod.Transport.Endpoints;

namespace Rod.Integration.Tests;

/// <summary>
/// The provenance-chain read (architecture.md Sec 15.4): an implant's
/// detail shows the chain it stands in -- the derivation ancestry
/// root-first, the children it derived, and the delivery campaign whose
/// lure it followed with the recipient arc and the target-selection
/// reference the row carries. An ordinary enrollment shows no campaign
/// leg at all.
/// </summary>
public class ImplantProvenanceTests
{
    private static async Task<(HttpClient Client, IHost Host, EngagementId Engagement)> NewAsync()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        await AuthenticatedHost.LoginAsync(client);

        var created = await client.PostAsJsonAsync("/engagements", new { name = "provenance" });
        created.EnsureSuccessStatusCode();
        var engagement = await created.Content.ReadFromJsonAsync<EngagementBody>();
        Assert.True(EngagementId.TryParse(engagement!.EngagementId, out var engagementId));
        return new(client, host, engagementId);
    }

    private static async Task<string> EnrollAsync(HttpClient client, EngagementId engagement, string? parent = null)
    {
        var minted = await client.PostAsJsonAsync($"/engagements/{engagement}/deploy-tokens", new { });
        minted.EnsureSuccessStatusCode();
        var token = await minted.Content.ReadFromJsonAsync<TokenBody>();

        var response = await client.PostAsJsonAsync("/implants/enroll",
            new EnrollmentEndpoints.EnrollRequest(DeployTokenSecret: token!.Secret, Class: null,
                PublicKey: null, ParentImplantId: parent));
        response.EnsureSuccessStatusCode();
        var enrolled = await response.Content.ReadFromJsonAsync<EnrollmentEndpoints.EnrollmentResponse>();
        Assert.NotNull(enrolled?.ImplantId);
        return enrolled!.ImplantId!;
    }

    private static async Task<ImplantEndpoints.ImplantDetailResponse> DetailAsync(
        HttpClient client, EngagementId engagement, string implantId)
    {
        var detail = await client.GetFromJsonAsync<ImplantEndpoints.ImplantDetailResponse>(
            $"/engagements/{engagement}/implants/{implantId}");
        Assert.NotNull(detail);
        return detail!;
    }

    [Fact]
    public async Task Detail_ShowsTheDerivationChain_RootFirst()
    {
        var (client, host, engagement) = await NewAsync();
        using (client)
        using (host)
        {
            var root = await EnrollAsync(client, engagement);
            var middle = await EnrollAsync(client, engagement, root);
            var leaf = await EnrollAsync(client, engagement, middle);

            var detail = await DetailAsync(client, engagement, leaf);

            // The leaf's own row rides the listing's projection.
            Assert.Equal(leaf, detail.Implant.ImplantId);
            Assert.Equal(middle, detail.Implant.ParentImplantId);

            // The ancestry reads root-first: how the fleet's reach grew
            // into this implant.
            Assert.Equal(2, detail.Provenance.Ancestors.Count);
            Assert.Equal(root, detail.Provenance.Ancestors[0].ImplantId);
            Assert.Equal(middle, detail.Provenance.Ancestors[1].ImplantId);
            Assert.Null(detail.Provenance.Campaign);

            // The middle implant is both a child of the root and the
            // parent of the leaf -- both halves of the tree on one read.
            var middleDetail = await DetailAsync(client, engagement, middle);
            var child = Assert.Single(middleDetail.Provenance.Children);
            Assert.Equal(leaf, child.ImplantId);
            Assert.Equal(root, Assert.Single(middleDetail.Provenance.Ancestors).ImplantId);
            Assert.Empty(detail.Provenance.Children);
        }
    }

    [Fact]
    public async Task Detail_OfAPlainEnrollment_CarriesNoCampaignLeg()
    {
        var (client, host, engagement) = await NewAsync();
        using (client)
        using (host)
        {
            var implant = await EnrollAsync(client, engagement);
            var detail = await DetailAsync(client, engagement, implant);
            Assert.Null(detail.Provenance.Campaign);
            Assert.Empty(detail.Provenance.Ancestors);
            Assert.Empty(detail.Provenance.Children);
        }
    }

    [Fact]
    public async Task Detail_OfACampaignEnrollment_ShowsTheWholeLureArc()
    {
        var (client, host, engagement) = await NewAsync();
        using (client)
        using (host)
        {
            // The target off the engagement's list, selected into the
            // campaign the way the unified model's link carries it.
            var assets = host.Services.GetRequiredService<CoreState.Recon.IReconAssetStore>();
            var asset = new CoreState.Recon.ReconAsset(
                CoreState.ReconAssetId.New(), engagement, CoreState.Recon.ReconAssetKind.Email,
                "vp@example.com", "The Vice President", null,
                AuthenticatedHost.GetOperatorId(host), DateTimeOffset.UtcNow);
            Assert.True(await assets.AddAsync(asset));

            var recipient = new CampaignRecipient(
                CampaignRecipientId.New(), "vp@example.com", "The Vice President", Guid.NewGuid(),
                reconAssetId: asset.Id);
            var campaign = new Campaign(
                CampaignId.New(), engagement, "renewal-push",
                AuthenticatedHost.GetOperatorId(host), DateTimeOffset.UtcNow,
                "relay.example", 587, CampaignRelayTls.StartTls, null, null,
                "sender@example.com", "Subject", "Open {{link}}", false, "{}",
                Guid.NewGuid(), [recipient]);
            var campaigns = host.Services.GetRequiredService<ICampaignStore>();
            await campaigns.SaveAsync(campaign);
            await campaigns.LaunchAsync(campaign.Id, engagement, DateTimeOffset.UtcNow);

            // The per-recipient credential, bound the way the send engine
            // binds it, then redeemed by the artifact that followed the
            // lure.
            var minted = await client.PostAsJsonAsync($"/engagements/{engagement}/deploy-tokens", new { });
            minted.EnsureSuccessStatusCode();
            var token = await minted.Content.ReadFromJsonAsync<TokenBody>();
            Assert.True(await campaigns.NoteBuildingAsync(
                campaign.Id, recipient.Id, new DeployTokenId(Guid.Parse(token!.DeployTokenId)), Guid.NewGuid()));

            var implantId = await EngagementSetup.EnrollAsync(client, token.Secret);

            var detail = await DetailAsync(client, engagement, implantId);
            Assert.NotNull(detail.Provenance.Campaign);
            var leg = detail.Provenance.Campaign!;
            Assert.Equal(campaign.Id.ToString(), leg.CampaignId);
            Assert.Equal("renewal-push", leg.CampaignName);
            Assert.Equal("launched", leg.CampaignState);
            Assert.Equal(recipient.Id.ToString(), leg.RecipientId);
            Assert.Equal("vp@example.com", leg.Email);
            Assert.Equal("The Vice President", leg.Name);
            // The executed binding stamps on both rows of the link.
            Assert.NotNull(leg.ExecutedAt);
            Assert.Equal(asset.Id.ToString(), leg.ReconAssetId);

            // And the recipient row itself carries the enrollment binding.
            var readBack = (await campaigns.FindAsync(campaign.Id, engagement))!.FindRecipient(recipient.Id);
            Assert.NotNull(readBack);
            Assert.Equal(implantId, readBack!.EnrolledImplantId?.ToString("N"));
        }
    }

    [Fact]
    public async Task Detail_OfAForeignImplant_IsNotFound()
    {
        var (client, host, engagement) = await NewAsync();
        using (client)
        using (host)
        {
            var implant = await EnrollAsync(client, engagement);

            var created = await client.PostAsJsonAsync("/engagements", new { name = "other" });
            created.EnsureSuccessStatusCode();
            var other = (await created.Content.ReadFromJsonAsync<EngagementBody>())!.EngagementId;

            var response = await client.GetAsync($"/engagements/{other}/implants/{implant}");
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
    }

    private sealed record EngagementBody(string EngagementId);
    private sealed record TokenBody(string DeployTokenId, string Secret);
}
