using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Operators;
using Rod.Transport.Listeners;
using Rod.Transport.Payloads;

namespace Rod.Integration.Tests;

/// <summary>
/// The loader tier's request gates (architecture.md Sec 6): the parser holds
/// the tier to the shape its crate can honor -- a stored implant of this
/// engagement as the delivery, a cleartext http front (any host shape --
/// dialer carries no TLS and no resolver), a Linux amd64/arm64 target, the
/// in-tree Rust unit. Registry- and store-seeded (no toolchain runs here);
/// each refusal names the fix the same way the route will at runtime.
/// </summary>
public class LoaderBuildParserTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    private sealed record ParserHarness(
        IHost Host,
        EngagementId Engagement,
        IListenerRegistry Registry,
        IPayloadStore Payloads,
        Rod.CoreState.Pki.IImplantCertificateAuthority Ca) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Host.Dispose();
            await ValueTask.CompletedTask;
        }
    }

    private static async Task<ParserHarness> SetupAsync()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        {
            var engagements = host.Services.GetRequiredService<IEngagementRepository>();
            var engagementId = EngagementId.New();
            await engagements.SaveAsync(Engagement.Create(engagementId, "loader-parser", OperatorId.New(), Now));

            var registry = host.Services.GetRequiredService<IListenerRegistry>();
            var engagement = engagementId;
            await registry.RegisterAsync(Listener.Define(
                ListenerId.New(), "loader-http", "http",
                "10.0.0.9:8080", "10.0.0.9:8080", Now, engagement));
            await registry.RegisterAsync(Listener.Define(
                ListenerId.New(), "loader-https", "https",
                "10.0.0.9:8443", "10.0.0.9:8443", Now, engagement));
            await registry.RegisterAsync(Listener.Define(
                ListenerId.New(), "loader-named", "http",
                "10.0.0.9:8081", "front.example.test", Now, engagement));

            var payloads = host.Services.GetRequiredService<IPayloadStore>();
            var stageId = Guid.NewGuid();
            await payloads.SaveAsync(new PayloadRecord(
                stageId, engagementId.Value, "Implant", "Rust",
                "application/octet-stream", "stage-fingerprint", [1, 2, 3], 3, Now));
            var loaderId = Guid.NewGuid();
            await payloads.SaveAsync(new PayloadRecord(
                loaderId, engagementId.Value, "Implant", "Rust",
                "application/octet-stream", "loader-fingerprint", [4], 1, Now,
                DeliversPayloadId: stageId));

            return new ParserHarness(
                host, engagementId, registry, payloads,
                host.Services.GetRequiredService<Rod.CoreState.Pki.IImplantCertificateAuthority>());
        }
    }

    private static async Task<(Rod.BuildPipeline.PayloadBuild.BuildRequest? Request, string? Error)> ParseAsync(
        ParserHarness h,
        string listenerName,
        string? stagePayloadId,
        string? targetOs = null,
        string? targetArch = null,
        string? language = null)
    {
        Listener listener = (await h.Registry.ListAsync(CancellationToken.None)).First(l => l.Name == listenerName);
        return await PayloadBuildRequestParser.ParseAsync(
            new Rod.Transport.Endpoints.PayloadEndpoints.BuildPayloadRequest(
                Unit: "rod-rust",
                Class: null,
                TargetOs: targetOs,
                TargetArch: targetArch,
                ListenerId: listener.Id.ToString(),
                Kind: "loader",
                DeliversPayloadId: stagePayloadId),
            h.Engagement,
            OperatorId.New(),
            h.Registry,
            h.Ca,
            h.Payloads,
            CancellationToken.None);
    }

    private static async Task<Guid> StoredImplantIdAsync(ParserHarness h)
        => (await h.Payloads.ListAsync(h.Engagement.Value, CancellationToken.None))
            .First(p => p.DeliversPayloadId is null).PayloadId;

    private static async Task<Guid> StoredLoaderIdAsync(ParserHarness h)
        => (await h.Payloads.ListAsync(h.Engagement.Value, CancellationToken.None))
            .First(p => p.DeliversPayloadId is not null).PayloadId;

    [Fact]
    public async Task ALoaderAgainstAnIpv4HttpFront_BakesWithItsDelivery()
    {
        await using var h = await SetupAsync();
        var stageId = await StoredImplantIdAsync(h);

        var (request, error) = await ParseAsync(h, "loader-http", stageId.ToString());

        Assert.Null(error);
        Assert.Equal(PayloadKind.Loader, request!.Kind);
        Assert.Equal(stageId, request.DeliversPayloadId);
    }

    [Fact]
    public async Task AnHttpsFront_IsRefusedWithTheDialShapeNamed()
    {
        await using var h = await SetupAsync();
        var stageId = await StoredImplantIdAsync(h);

        var (request, error) = await ParseAsync(h, "loader-https", stageId.ToString());

        Assert.Null(request);
        Assert.Contains("cleartext http front", error);
    }

    [Fact]
    public async Task AHostnameFront_BakesWithItsDelivery()
    {
        await using var h = await SetupAsync();
        var stageId = await StoredImplantIdAsync(h);

        var (request, error) = await ParseAsync(h, "loader-named", stageId.ToString());

        Assert.Null(error);
        Assert.Equal(PayloadKind.Loader, request!.Kind);
    }

    [Fact]
    public async Task AStageOutsideTheEngagement_DoesNotExist()
    {
        await using var h = await SetupAsync();

        var (request, error) = await ParseAsync(h, "loader-http", Guid.NewGuid().ToString());

        Assert.Null(request);
        Assert.Contains("does not name a payload", error);
    }

    [Fact]
    public async Task AStageNamingALoader_IsRefused()
    {
        await using var h = await SetupAsync();
        var loader = await StoredLoaderIdAsync(h);

        var (request, error) = await ParseAsync(h, "loader-http", loader.ToString());

        Assert.Null(request);
        Assert.Contains("not another loader", error);
    }

    [Fact]
    public async Task AWindowsTarget_IsRefusedWithTheMemfdShapeNamed()
    {
        await using var h = await SetupAsync();
        var stageId = await StoredImplantIdAsync(h);

        var (request, error) = await ParseAsync(h, "loader-http", stageId.ToString(), targetOs: "windows");

        Assert.Null(request);
        Assert.Contains("memfd", error);
    }
}
