using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.Operators.Endpoints;
using Rod.CoreState.Recon;

namespace Rod.Integration.Tests;

/// <summary>
/// The recon-asset surface (architecture.md Sec 15.4): the engagement's
/// target list -- recording is the curatorial act that makes an address
/// referenceable, identity is (kind, value) within the engagement, and
/// the trail carries every change. The delete-refusal half (an asset a
/// campaign already selected) lives in the target-selection tests, where
/// a campaign exists to do the selecting.
/// </summary>
public class ReconAssetEndpointTests
{
    private static async Task<(HttpClient Client, IHost Host, string Engagement)> NewAsync()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        await AuthenticatedHost.LoginAsync(client);

        var created = await client.PostAsJsonAsync("/engagements", new { name = "assets" });
        created.EnsureSuccessStatusCode();
        var engagement = await created.Content.ReadFromJsonAsync<EngagementBody>();
        Assert.NotNull(engagement);
        return new(client, host, engagement!.EngagementId);
    }

    private static async Task<ReconAssetEndpoints.ReconAssetResponse> RecordAsync(
        HttpClient client, string engagement, string kind, string value,
        string? displayName = null, string? sourceArtifactId = null)
    {
        var recorded = await client.PostAsJsonAsync(
            $"/engagements/{engagement}/recon-assets",
            new ReconAssetEndpoints.RecordReconAssetRequest(kind, value, displayName, sourceArtifactId));
        Assert.Equal(HttpStatusCode.Created, recorded.StatusCode);
        var asset = await recorded.Content.ReadFromJsonAsync<ReconAssetEndpoints.ReconAssetResponse>();
        Assert.NotNull(asset);
        return asset!;
    }

    [Fact]
    public async Task Record_AndList_TheTargetListCarriesIt()
    {
        var (client, host, engagement) = await NewAsync();
        using (client)
        using (host)
        {
            var asset = await RecordAsync(client, engagement, "email", "Target@Example.com", "The Target");

            // Value normalizes to the target list's own casing rule.
            Assert.Equal("target@example.com", asset.Value);
            Assert.Equal("email", asset.Kind);
            Assert.Equal("The Target", asset.DisplayName);
            Assert.Null(asset.SourceArtifactId);

            var listed = await client.GetFromJsonAsync<ReconAssetEndpoints.ReconAssetResponse[]>(
                $"/engagements/{engagement}/recon-assets");
            Assert.NotNull(listed);
            var row = Assert.Single(listed!, a => a.AssetId == asset.AssetId);
            Assert.Equal("target@example.com", row.Value);

            // The recording is a fact on the engagement's trail.
            var audit = host.Services.GetRequiredService<IAuditStore>();
            var facts = await audit.ListAsync(Guid.Parse(engagement));
            var recorded = Assert.Single(facts, f => f.Kind == AuditEventKind.ReconAssetRecorded);
            Assert.Contains("email;target@example.com", recorded.Payload);
            Assert.Equal(asset.AssetId, recorded.Outcome);
        }
    }

    [Fact]
    public async Task Record_WithSourceArtifact_TheProvenanceRides()
    {
        var (client, host, engagement) = await NewAsync();
        using (client)
        using (host)
        {
            var artifact = Guid.NewGuid().ToString("N");
            var asset = await RecordAsync(client, engagement, "host", "mail.example.com",
                sourceArtifactId: artifact);
            Assert.Equal(artifact, asset.SourceArtifactId);

            var audit = host.Services.GetRequiredService<IAuditStore>();
            var facts = await audit.ListAsync(Guid.Parse(engagement));
            var recorded = Assert.Single(facts, f => f.Kind == AuditEventKind.ReconAssetRecorded);
            Assert.Contains($"from=artifact:{artifact}", recorded.Payload);
        }
    }

    [Fact]
    public async Task Record_SameIdentityTwice_IsRefused()
    {
        var (client, host, engagement) = await NewAsync();
        using (client)
        using (host)
        {
            await RecordAsync(client, engagement, "email", "once@example.com");
            var second = await client.PostAsJsonAsync(
                $"/engagements/{engagement}/recon-assets",
                new ReconAssetEndpoints.RecordReconAssetRequest("email", "ONCE@example.com"));
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        }
    }

    [Fact]
    public async Task Record_BadKindOrShape_IsRefused()
    {
        var (client, host, engagement) = await NewAsync();
        using (client)
        using (host)
        {
            var badKind = await client.PostAsJsonAsync(
                $"/engagements/{engagement}/recon-assets",
                new ReconAssetEndpoints.RecordReconAssetRequest("netblock", "10.0.0.0/8"));
            Assert.Equal(HttpStatusCode.BadRequest, badKind.StatusCode);

            // A host value that is not a hostname: the shape check is
            // per-kind, not a shared "looks like a string".
            var badShape = await client.PostAsJsonAsync(
                $"/engagements/{engagement}/recon-assets",
                new ReconAssetEndpoints.RecordReconAssetRequest("host", "not a host"));
            Assert.Equal(HttpStatusCode.BadRequest, badShape.StatusCode);

            var badAddress = await client.PostAsJsonAsync(
                $"/engagements/{engagement}/recon-assets",
                new ReconAssetEndpoints.RecordReconAssetRequest("address", "mail.example.com"));
            Assert.Equal(HttpStatusCode.BadRequest, badAddress.StatusCode);
        }
    }

    [Fact]
    public async Task Delete_RemovesTheTarget_AndRefusesWhenAbsent()
    {
        var (client, host, engagement) = await NewAsync();
        using (client)
        using (host)
        {
            var asset = await RecordAsync(client, engagement, "email", "gone@example.com");

            var deleted = await client.DeleteAsync($"/engagements/{engagement}/recon-assets/{asset.AssetId}");
            Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
            var again = await client.DeleteAsync($"/engagements/{engagement}/recon-assets/{asset.AssetId}");
            Assert.Equal(HttpStatusCode.NotFound, again.StatusCode);

            var audit = host.Services.GetRequiredService<IAuditStore>();
            var facts = await audit.ListAsync(Guid.Parse(engagement));
            Assert.Contains(facts, f => f.Kind == AuditEventKind.ReconAssetDeleted
                && f.Outcome == asset.AssetId);
        }
    }

    [Fact]
    public async Task List_ScopesByEngagement()
    {
        var (client, host, engagement) = await NewAsync();
        using (client)
        using (host)
        {
            await RecordAsync(client, engagement, "email", "scoped@example.com");

            // A second engagement sees none of the first one's targets.
            var created = await client.PostAsJsonAsync("/engagements", new { name = "other" });
            created.EnsureSuccessStatusCode();
            var other = (await created.Content.ReadFromJsonAsync<EngagementBody>())!.EngagementId;
            var listed = await client.GetFromJsonAsync<ReconAssetEndpoints.ReconAssetResponse[]>(
                $"/engagements/{other}/recon-assets");
            Assert.NotNull(listed);
            Assert.Empty(listed!);
        }
    }

    private sealed record EngagementBody(string EngagementId);
}
