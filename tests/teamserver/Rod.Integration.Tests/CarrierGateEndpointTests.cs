using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.CoreState;
using Rod.Transport.Endpoints;
using static Rod.Integration.Tests.EngagementSetup;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance for the issuance-time carrier gate (architecture.md Sec 8,
/// Sec 10.3): an enrollment stamped with its build's baked carrier set -- the
/// enroll path derives it off the payload record the redeemed token resolves
/// -- refuses a channel verb no baked carrier could ever claim, instead of
/// queueing it for a stream the artifact will never dial. The payload records
/// here stand in for the build pipeline's; the enrollment reads them exactly
/// the way it reads a real build's.
/// </summary>
public class CarrierGateEndpointTests
{
    [Fact]
    public async Task ChannelVerb_IsIssued_ForAPollWebBuild()
    {
        // The store-and-forward discipline is not a bake-time choice: every
        // poll-mode web artifact advertises the capability, so the channel
        // verbs are issuable against its cadence without any stream.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var (secret, tokenId) = await MintDeployTokenAsync(client, engagementId);
            await SavePayloadAsync(host, tokenId, engagementId,
                endpoint: "https://front.example.com:8443");
            var implantId = await EnrollAsync(client, secret);

            var issued = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = implantId, Verb = "shell.interact", Arguments = "" });

            issued.EnsureSuccessStatusCode();
        }
    }

    [Fact]
    public async Task ChannelVerb_IsIssued_ForADnsOnlyBuild()
    {
        // The DNS carrier serves store-and-forward channels (architecture.md
        // Sec 10.3): an artifact whose every dial is the DNS TXT carrier
        // still claims the channel verbs -- input rides the TXT answers,
        // output chunks up as queries.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var (secret, tokenId) = await MintDeployTokenAsync(client, engagementId);
            await SavePayloadAsync(host, tokenId, engagementId,
                endpoint: "dns://10.0.0.1:53/c2.example.test");
            var implantId = await EnrollAsync(client, secret);

            var issued = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = implantId, Verb = "shell.interact", Arguments = "" });

            issued.EnsureSuccessStatusCode();
        }
    }

    [Fact]
    public async Task ChannelVerb_IsIssued_ForAStreamModeWebBuild()
    {
        // The web posture's interactive tier: a stream-mode build against a
        // web front dials the WebSocket beacon hanging off the same front,
        // so the baked mode stamps the native carrier and the channel verb
        // is claimable.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var (secret, tokenId) = await MintDeployTokenAsync(client, engagementId);
            await SavePayloadAsync(host, tokenId, engagementId,
                endpoint: "https://front.example.com:8443", mode: "stream");
            var implantId = await EnrollAsync(client, secret);

            var issued = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = implantId, Verb = "shell.interact", Arguments = "" });

            issued.EnsureSuccessStatusCode();
        }
    }

    [Fact]
    public async Task ChannelVerb_IsIssued_WhenNoBuildProfileResolved()
    {
        // A manually minted token names no payload, so the carrier set stays
        // undeclared: the permissive shape, where the dispatch-time claim
        // evaluation alone decides -- the behavior that predates the stamp.
        var (client, _, _) = AuthenticatedHost.Create();
        using (client)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var (secret, _) = await MintDeployTokenAsync(client, engagementId);
            var implantId = await EnrollAsync(client, secret);

            var issued = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = implantId, Verb = "shell.interact", Arguments = "" });

            issued.EnsureSuccessStatusCode();
        }
    }

    private static async Task<(string Secret, Guid TokenId)> MintDeployTokenAsync(
        HttpClient client,
        string engagementId)
    {
        var response = await client.PostAsync($"/engagements/{engagementId}/deploy-tokens", content: null);
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<EngagementEndpoints.DeployTokenResponse>();
        return (token!.Secret, Guid.Parse(token.DeployTokenId));
    }

    // The enroll-side derivation reads the payload record the token resolves
    // (Endpoint, the build profile's mode and fallbacks); the fields it does
    // not read are filler.
    private static async Task SavePayloadAsync(
        IHost host,
        Guid tokenId,
        string engagementId,
        string endpoint,
        string? mode = null)
    {
        var payloads = host.Services.GetRequiredService<IPayloadStore>();
        await payloads.SaveAsync(new PayloadRecord(
            PayloadId: Guid.NewGuid(),
            EngagementId: Guid.Parse(engagementId),
            Class: "Implant",
            UnitId: "rod-dotnet",
            ContentType: "application/octet-stream",
            Fingerprint: "sha256:" + new string('a', 64),
            Content: Array.Empty<byte>(),
            Size: 0,
            BuiltAt: DateTimeOffset.UtcNow,
            Endpoint: endpoint,
            TokenId: tokenId,
            Build: mode is null
                ? null
                : new PayloadBuildProfile
                {
                    Mode = mode,
                }));
    }
}
