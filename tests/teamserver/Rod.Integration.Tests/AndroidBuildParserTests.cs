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
/// The android build's format gates (architecture.md Sec 6, Sec 12.2): an
/// android target deploys through the carrier library or its package, and
/// those two shapes belong to android alone. Registry-seeded, no toolchain
/// runs here -- the parser is the gate under test, each refusal naming the
/// fix the same way the route will at runtime.
/// </summary>
public class AndroidBuildParserTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    private sealed record ParserHarness(
        IHost Host,
        EngagementId Engagement,
        IListenerRegistry Registry,
        Rod.Audit.IPayloadStore Payloads,
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
            await engagements.SaveAsync(Engagement.Create(engagementId, "android-parser", OperatorId.New(), Now));

            var registry = host.Services.GetRequiredService<IListenerRegistry>();
            await registry.RegisterAsync(Listener.Define(
                ListenerId.New(), "android-http", "http",
                "10.0.2.2:8080", "10.0.2.2:8080", Now, engagementId));

            return new ParserHarness(
                host, engagementId, registry,
                host.Services.GetRequiredService<Rod.Audit.IPayloadStore>(),
                host.Services.GetRequiredService<Rod.CoreState.Pki.IImplantCertificateAuthority>());
        }
    }

    private static async Task<(Rod.BuildPipeline.PayloadBuild.BuildRequest? Request, string? Error)> ParseAsync(
        ParserHarness h,
        string? targetOs,
        string? format,
        string? kind = null)
    {
        Listener listener = (await h.Registry.ListAsync(CancellationToken.None)).First(l => l.Name == "android-http");
        return await PayloadBuildRequestParser.ParseAsync(
            new Rod.Transport.Endpoints.PayloadEndpoints.BuildPayloadRequest(
                Unit: null,
                Class: null,
                TargetOs: targetOs,
                TargetArch: null,
                ListenerId: listener.Id.ToString(),
                Format: format,
                Kind: kind),
            h.Engagement,
            OperatorId.New(),
            h.Registry,
            h.Ca,
            h.Payloads,
            CancellationToken.None);
    }

    [Fact]
    public async Task AnAndroidTarget_AcceptsTheCarrierPair()
    {
        await using var h = await SetupAsync();

        foreach (var format in new[] { "so", "apk" })
        {
            var (request, error) = await ParseAsync(h, "android", format);
            Assert.Null(error);
            Assert.Equal(
                format == "so" ? ArtifactFormat.SharedObject : ArtifactFormat.Apk,
                request!.Format);
            Assert.Equal("android", request.Target.OperatingSystem);
        }
    }

    [Fact]
    public async Task AnAndroidTargetWithAnExecutableFormat_IsRefused()
    {
        await using var h = await SetupAsync();

        var (request, error) = await ParseAsync(h, "android", "exe");

        Assert.Null(request);
        Assert.Contains("build format 'so' or 'apk'", error);
    }

    [Fact]
    public async Task AnAndroidTargetWithNoFormat_IsRefusedWithThePairNamed()
    {
        await using var h = await SetupAsync();

        var (request, error) = await ParseAsync(h, "android", null);

        Assert.Null(request);
        Assert.Contains("build format 'so' or 'apk'", error);
    }

    [Fact]
    public async Task TheCarrierShapes_OffAndroid_AreRefused()
    {
        await using var h = await SetupAsync();

        var apk = await ParseAsync(h, "linux", "apk");
        Assert.Null(apk.Request);
        Assert.Contains("android carrier package", apk.Error);

        var so = await ParseAsync(h, "windows", "so");
        Assert.Null(so.Request);
        Assert.Contains("android carrier library", so.Error);
    }

    [Fact]
    public async Task ALoaderOnAndroid_IsRefusedAsTheMemfdShape()
    {
        await using var h = await SetupAsync();

        var (request, error) = await ParseAsync(h, "android", null, kind: "loader");

        Assert.Null(request);
        Assert.Contains("Linux memfd shape", error);
    }
}
