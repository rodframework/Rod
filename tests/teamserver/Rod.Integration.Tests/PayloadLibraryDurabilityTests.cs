using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Rod.Audit;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.Persistence;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Task = System.Threading.Tasks.Task;

namespace Rod.Integration.Tests;

/// <summary>
/// Durability for the built-payload library: a stored payload, its
/// sealed-contact key binding, and its bake-time snapshot survive a
/// teamserver restart when the Postgres adapter is wired -- the gap the
/// in-memory default left, where a Postgres deployment kept every other
/// engagement state but lost the payloads on reboot. Mirrors the
/// CoreStateDurabilityTests shape: host A writes against a live container,
/// host B starts over the same database. Skips (not fails) when Docker is
/// absent.
/// </summary>
[Collection("postgres")]
public sealed class PayloadLibraryDurabilityTests : IClassFixture<PostgresFixture>
{
    private readonly PostgresFixture _postgres;

    public PayloadLibraryDurabilityTests(PostgresFixture postgres)
        => _postgres = postgres;

    [Fact]
    public async Task PayloadLibrary_SurvivesRestart_WhenPostgresWired()
    {
        if (!_postgres.IsAvailable)
        {
            // No Docker in this environment; skip, not fail.
            return;
        }

        Guid engagement;
        var payloadId = Guid.NewGuid();
        var envelopeKeyId = Guid.NewGuid();
        var tokenId = Guid.NewGuid();
        var delivered = Guid.NewGuid();
        var content = new byte[] { 0x7f, 0x45, 0x4c, 0x46, 0x01, 0x02 };
        var envelopeKey = new byte[32];
        new Random(42).NextBytes(envelopeKey);

        await using (var envA = await TestEnv.StartAsync(_postgres))
        {
            var created = await envA.Http.PostAsJsonAsync("/engagements",
                new EngagementEndpoints.CreateEngagementRequest(Name: "Operation Smokeshow"));
            created.EnsureSuccessStatusCode();
            var body = await created.Content.ReadFromJsonAsync<EngagementEndpoints.EngagementResponse>();
            engagement = Guid.Parse(body!.EngagementId);

            var payloads = envA.Host.Services.GetRequiredService<IPayloadStore>();
            await payloads.SaveAsync(new PayloadRecord(
                payloadId,
                engagement,
                Class: "implant",
                UnitId: BuildUnitIds.Rust,
                ContentType: "application/octet-stream",
                Fingerprint: "sha256:abc123",
                Content: content,
                Size: content.Length,
                BuiltAt: DateTimeOffset.UtcNow,
                Target: "linux/amd64",
                Endpoint: "https://front.example",
                TokenId: tokenId,
                EnvelopeKeyId: envelopeKeyId,
                EnvelopeKey: envelopeKey,
                Build: new PayloadBuildProfile
                {
                    Mode = "poll",
                    SleepSeconds = 30,
                    JitterSeconds = 10,
                    Envelope = "aesgcm",
                    FallbackEndpoints = ["https://two.example", "https://three.example"],
                },
                DeliversPayloadId: delivered));
        }

        // --- Host B: a fresh teamserver over the same Postgres. ---
        await using var envB = await TestEnv.StartAsync(_postgres);
        var store = envB.Host.Services.GetRequiredService<IPayloadStore>();

        // The scoped fetch round-trips the whole record: bytes, key pair,
        // and the bake snapshot's nested list included.
        var fetched = await store.FindAsync(payloadId, engagement);
        Assert.NotNull(fetched);
        Assert.Equal(content, fetched!.Content);
        Assert.Equal("linux/amd64", fetched.Target);
        Assert.Equal("https://front.example", fetched.Endpoint);
        Assert.Equal(envelopeKeyId, fetched.EnvelopeKeyId);
        Assert.Equal(envelopeKey, fetched.EnvelopeKey);
        Assert.Equal(delivered, fetched.DeliversPayloadId);
        Assert.NotNull(fetched.Build);
        Assert.Equal("poll", fetched.Build!.Mode);
        Assert.Equal(30, fetched.Build.SleepSeconds);
        Assert.Equal(["https://two.example", "https://three.example"], fetched.Build.FallbackEndpoints);

        // The two key-resolution lookups the enroll path rides.
        Assert.Equal(payloadId, (await store.FindByEnvelopeKeyAsync(envelopeKeyId))!.PayloadId);
        Assert.Equal(payloadId, (await store.FindByTokenAsync(tokenId))!.PayloadId);

        // The library listing sees it; a foreign engagement does not.
        Assert.Single(await store.ListAsync(engagement));
        Assert.Null(await store.FindAsync(payloadId, Guid.NewGuid()));

        // The deletion removes the row and with it the key binding -- the
        // artifact's envelopes stop being decodable, the documented lifetime.
        Assert.True(await store.RemoveAsync(payloadId, engagement));
        Assert.Null(await store.FindAsync(payloadId, engagement));
        Assert.Null(await store.FindByEnvelopeKeyAsync(envelopeKeyId));
        Assert.False(await store.RemoveAsync(payloadId, engagement));
    }

    // The same host shape CoreStateDurabilityTests keeps: an authenticated
    // Kestrel teamserver wired for Postgres, schema applied the operator way.
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
            await AuthenticatedHost.LoginAsync(env.Http);
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
            Http?.Dispose();
            if (Host is not null)
                await Host.StopAsync();
            Host?.Dispose();
        }
    }
}
