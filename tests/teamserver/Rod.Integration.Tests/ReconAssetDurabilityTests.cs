using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Rod.CoreState;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Recon;
using Rod.Persistence;
using Rod.Transport.Endpoints;
using Rod.Transport;

namespace Rod.Integration.Tests;

/// <summary>
/// The durable half of the recon-asset target link (architecture.md
/// Sec 15.4): the target list and the campaign rows that reference it
/// survive a restart over Postgres, and the composite foreign keys the
/// unified entity model rides on hold at the database itself -- an asset
/// delete with a referencing recipient is refused, and a recipient
/// citing another engagement's asset cannot be written at all.
/// </summary>
public sealed class ReconAssetDurabilityTests : IClassFixture<PostgresFixture>
{
    private readonly PostgresFixture _postgres;

    public ReconAssetDurabilityTests(PostgresFixture postgres)
        => _postgres = postgres;

    [Fact]
    public async Task AssetsAndTheirCampaignReferences_SurviveRestart_WhenPostgresWired()
    {
        if (!_postgres.IsAvailable)
            return; // No Docker here; skip, not fail.

        EngagementId engagement;
        ReconAssetId assetId;
        CampaignId campaignId;
        CampaignRecipientId recipientId;

        // --- Host A: record a target, select it into a campaign. ---
        await using (var envA = await TestEnv.StartAsync(_postgres))
        {
            await LoginAsync(envA.Http);
            engagement = await CreateEngagementAsync(envA.Http);

            var assets = envA.Host.Services.GetRequiredService<IReconAssetStore>();
            var asset = new ReconAsset(
                ReconAssetId.New(), engagement, ReconAssetKind.Email,
                "durable@example.com", "The Durable Target", null,
                envA.OperatorId, DateTimeOffset.UtcNow);
            Assert.True(await assets.AddAsync(asset));
            assetId = asset.Id;

            var recipient = new CampaignRecipient(
                CampaignRecipientId.New(), "durable@example.com", "The Durable Target",
                Guid.NewGuid(), reconAssetId: assetId);
            var campaign = new Campaign(
                CampaignId.New(), engagement, "durable-run", envA.OperatorId,
                DateTimeOffset.UtcNow,
                "relay.example", 587, CampaignRelayTls.StartTls, null, null,
                "sender@example.com", "Subject", "Open {{link}}", false, "{}",
                Guid.NewGuid(), [recipient]);
            await envA.Host.Services.GetRequiredService<ICampaignStore>().SaveAsync(campaign);
            campaignId = campaign.Id;
            recipientId = recipient.Id;
        }

        // --- Host B: fresh teamserver, same Postgres. The target list and
        //     the selection both read back. ---
        await using (var envB = await TestEnv.StartAsync(_postgres))
        {
            await LoginAsync(envB.Http);

            var assets = envB.Host.Services.GetRequiredService<IReconAssetStore>();
            var readBack = await assets.FindAsync(assetId, engagement);
            Assert.NotNull(readBack);
            Assert.Equal("durable@example.com", readBack!.Value);

            var campaignRow = await envB.Host.Services.GetRequiredService<ICampaignStore>()
                .FindAsync(campaignId, engagement);
            Assert.NotNull(campaignRow);
            var row = campaignRow!.FindRecipient(recipientId);
            Assert.NotNull(row);
            Assert.Equal(assetId, row!.ReconAssetId);

            // The delete-refusal holds over the durable link: the
            // endpoint's pre-check walks the campaigns, the composite
            // foreign key is the constraint behind it.
            await LoginAsync(envB.Http);
            var refused = await envB.Http.DeleteAsync(
                $"/engagements/{engagement}/recon-assets/{assetId}");
            Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        }
    }

    [Fact]
    public async Task Recipient_CitingAForeEngagementsAsset_IsRefusedByTheConstraint()
    {
        if (!_postgres.IsAvailable)
            return; // No Docker here; skip, not fail.

        await using var env = await TestEnv.StartAsync(_postgres);
        await LoginAsync(env.Http);
        var operatorId = env.OperatorId;

        // Two engagements, one asset on the first.
        var engagementA = await CreateEngagementAsync(env.Http);
        var engagementB = await CreateEngagementAsync(env.Http);
        var assets = env.Host.Services.GetRequiredService<IReconAssetStore>();
        var asset = new ReconAsset(
            ReconAssetId.New(), engagementA, ReconAssetKind.Email,
            "foreign@example.com", null, null, operatorId, DateTimeOffset.UtcNow);
        Assert.True(await assets.AddAsync(asset));

        // A campaign on engagement B tries to select engagement A's
        // target. The application layer would refuse it; the point here
        // is that the composite foreign key refuses it even when the
        // application does not -- the isolation lives in the constraint.
        var crossEngagement = new Campaign(
            CampaignId.New(), engagementB, "cross-aim", operatorId, DateTimeOffset.UtcNow,
            "relay.example", 587, CampaignRelayTls.StartTls, null, null,
            "sender@example.com", "Subject", "Open {{link}}", false, "{}",
            Guid.NewGuid(),
            [new CampaignRecipient(
                CampaignRecipientId.New(), "foreign@example.com", null, Guid.NewGuid(),
                reconAssetId: asset.Id)]);

        await Assert.ThrowsAsync<Microsoft.EntityFrameworkCore.DbUpdateException>(
            () => env.Host.Services.GetRequiredService<ICampaignStore>().SaveAsync(crossEngagement));
    }

    private static async Task LoginAsync(HttpClient client)
        => await Rod.Integration.Tests.AuthenticatedHost.LoginAsync(client);

    private static async Task<EngagementId> CreateEngagementAsync(HttpClient client)
    {
        var created = await client.PostAsJsonAsync("/engagements", new { name = "durable-assets" });
        created.EnsureSuccessStatusCode();
        var body = await created.Content.ReadFromJsonAsync<EngagementBody>();
        Assert.True(EngagementId.TryParse(body!.EngagementId, out var engagement));
        return engagement;
    }

    private sealed record EngagementBody(string EngagementId);

    // The durability harness every Postgres-wired test class carries: a
    // real Kestrel on a free port over the fixture's database, the schema
    // applied before the hosted services start, and the same retry the
    // core-state durability tests keep for a transient first connection.
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;
        public OperatorId OperatorId { get; private set; }

        public static async Task<TestEnv> StartAsync(PostgresFixture postgres)
        {
            var env = new TestEnv();
            var httpPort = TestSupport.GetFreeTcpPort();

            var config = AuthenticatedHost.BuildConfig(
                extend: dict => dict["ConnectionStrings:Postgres"] = postgres.ConnectionString);

            env.Host = TransportHost.CreateHostBuilder(
                    configuration: config,
                    configureServices: services => AuthenticatedHost.ComposeServices(
                        services, config, extra: s => s.AddRodPersistence(config)),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints))
                .ConfigureWebHost(webBuilder => webBuilder
                    .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(httpPort)))
                .Build();

            try
            {
                await EnsureSchemaAsync(env.Host);
            }
            catch (Exception ex) when (ex is NpgsqlException or InvalidOperationException)
            {
                await Task.Delay(TimeSpan.FromSeconds(2));
                await EnsureSchemaAsync(env.Host);
            }
            await env.Host.StartAsync();

            env.OperatorId = AuthenticatedHost.GetOperatorId(env.Host);
            env.Http = new HttpClient(new CookieHandler(new HttpClientHandler { UseProxy = false }))
            {
                BaseAddress = new Uri($"http://127.0.0.1:{httpPort}"),
            };
            return env;
        }

        private static async Task EnsureSchemaAsync(IHost host)
        {
            var factory = host.Services.GetRequiredService<IDbContextFactory<RodPersistenceDbContext>>();
            await using var db = await factory.CreateDbContextAsync();
            await db.Database.MigrateAsync();
        }

        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            await Host.StopAsync();
            Host.Dispose();
        }
    }
}
