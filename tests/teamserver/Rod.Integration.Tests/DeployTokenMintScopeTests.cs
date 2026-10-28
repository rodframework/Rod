using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Rod.Audit;
using Rod.Transport.Endpoints;
using static Rod.Integration.Tests.EngagementSetup;
using Rod.BuildPipeline.PayloadBuild;

namespace Rod.Integration.Tests;

/// <summary>
/// The mint scope on the wire: the optional JSON body sizes a batch token and
/// the response carries the scope back, a body-less post keeps the single-use
/// default, and out-of-range values are refused loudly rather than clamped.
/// </summary>
public class DeployTokenMintScopeTests
{
    [Fact]
    public async Task Batch_Scope_Rides_The_Optional_Body()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var minted = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/deploy-tokens",
                new EngagementEndpoints.MintDeployTokenRequest(MaxUses: 3, LifetimeSeconds: 8 * 3600));
            Assert.Equal(HttpStatusCode.OK, minted.StatusCode);
            var token = await minted.Content.ReadFromJsonAsync<EngagementEndpoints.DeployTokenResponse>();
            Assert.Equal(3, token!.MaxUses);
            Assert.Equal(token.IssuedAt.AddHours(8), token.ExpiresAt);

            var plain = await client.PostAsync($"/engagements/{engagementId}/deploy-tokens", null);
            Assert.Equal(HttpStatusCode.OK, plain.StatusCode);
            var single = await plain.Content.ReadFromJsonAsync<EngagementEndpoints.DeployTokenResponse>();
            Assert.Equal(1, single!.MaxUses);
        }
    }

    [Fact]
    public async Task Out_Of_Range_Scope_Is_Refused()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var noUses = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/deploy-tokens",
                new EngagementEndpoints.MintDeployTokenRequest(MaxUses: 0, LifetimeSeconds: null));
            Assert.Equal(HttpStatusCode.BadRequest, noUses.StatusCode);

            var noWindow = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/deploy-tokens",
                new EngagementEndpoints.MintDeployTokenRequest(MaxUses: null, LifetimeSeconds: 1));
            Assert.Equal(HttpStatusCode.BadRequest, noWindow.StatusCode);
        }
    }

    [Fact]
    public async Task ABuild_MintsAndReportsItsBakedToken_WhichRevokes()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            // The build mints its own enrollment credential and bakes it in;
            // the response reports the token's id -- enough to revoke, never
            // enough to reuse. The front is a named listener: the API takes
            // a typed endpoint for the DNS family's dial alone.
            var front = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/listeners",
                new ListenerEndpoints.CreateListenerRequest(
                    Name: "build-front", Transport: "tcp",
                    BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
                    PublicEndpoint: "c2.example.test:443"));
            front.EnsureSuccessStatusCode();
            var frontId = (await front.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>())!.Id;
            var built = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust, Class: "Implant", TargetOs: "linux", TargetArch: "amd64",
                    ListenerId: frontId, UriPath: "/beacon",
                    SleepSeconds: 30, JitterSeconds: 10, KillDate: null));
            built.EnsureSuccessStatusCode();
            var artifact = await built.Content.ReadFromJsonAsync<PayloadEndpoints.BuildPayloadResponse>();
            Assert.False(string.IsNullOrWhiteSpace(artifact!.TokenId));

            // The mint is on the trail with the baked shape named.
            var audit = host.Services.GetRequiredService<IAuditStore>();
            var trail = await audit.ListAsync(Guid.Parse(engagementId));
            Assert.Contains(trail, e =>
                e.Kind == AuditEventKind.DeployTokenMinted && e.Payload.Contains("bakedIntoPayload"));

            // Revocation is the leak answer for a baked credential: the id
            // stops working, the second attempt honestly 404s, and the
            // revocation lands on the trail.
            var revoked = await client.PostAsync(
                $"/engagements/{engagementId}/deploy-tokens/{artifact.TokenId}:revoke", null);
            Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
            var revokedAgain = await client.PostAsync(
                $"/engagements/{engagementId}/deploy-tokens/{artifact.TokenId}:revoke", null);
            Assert.Equal(HttpStatusCode.NotFound, revokedAgain.StatusCode);

            trail = await audit.ListAsync(Guid.Parse(engagementId));
            Assert.Contains(trail, e =>
                e.Kind == AuditEventKind.DeployTokenRevoked && e.Outcome == artifact.TokenId);
        }
    }

}
