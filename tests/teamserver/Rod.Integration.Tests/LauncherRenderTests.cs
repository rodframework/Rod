using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Deployment;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;
using Rod.Transport.Listeners.ShellCatch;
using static Rod.Integration.Tests.EngagementSetup;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance for the standalone launcher render (architecture.md Sec 8):
/// the same paste-ready payload fetch one-liners the shell console's upgrade
/// produces, without a caught shell to grow from. The render resolves the
/// engagement's web front and newest payload (or the ones the operator
/// named), mints the deployment credential under the requested policy, and
/// answers with every downloader family -- the credential present in each
/// command exactly once.
/// </summary>
public class LauncherRenderTests
{
    [Fact]
    public async Task Render_AnswersThePreferredFrontAndNewestPayload()
    {
        await using var env = await TestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);
        var engagement = new EngagementId(Guid.Parse(engagementId));

        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-http",
                Transport: "http",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: "http://stage.example.test"));
        created.EnsureSuccessStatusCode();

        // Two builds, so "newest stands in" is a real choice and not the only
        // row in the store.
        var payloads = env.Host.Services.GetRequiredService<IPayloadStore>();
        var older = Guid.NewGuid();
        var newest = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await payloads.SaveAsync(Payload(older, engagement, now.AddMinutes(-5)));
        await payloads.SaveAsync(Payload(newest, engagement, now));

        var rendered = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers", new { });
        rendered.EnsureSuccessStatusCode();
        var body = await rendered.Content.ReadFromJsonAsync<LauncherRenderDto>();
        Assert.NotNull(body);
        Assert.Equal(newest.ToString("N"), body!.PayloadId);
        Assert.Equal($"http://stage.example.test/implants/payloads/{newest:N}", body.Url);
        Assert.False(string.IsNullOrEmpty(body.TokenSecret));
        Assert.Contains(body.Launchers, l => l.Id == "unix-curl" && l.Command.Contains(body.Url));
        Assert.Contains(body.Launchers, l => l.Id == "unix-wget");
        // The newest payload's own families: its target is linux, so the
        // PowerShell spelling stays out of the answer.
        Assert.DoesNotContain(body.Launchers, l => l.Id == "windows-powershell");
        Assert.All(body.Launchers, l => Assert.Contains(body.TokenSecret, l.Command));
    }

    [Fact]
    public async Task Render_HonorsTheNamedChoiceAndCredentialPolicy()
    {
        await using var env = await TestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);
        var engagement = new EngagementId(Guid.Parse(engagementId));

        // Two fronts, so the named listener resolution is a real choice: the
        // named redirector wins over the https front the preference would
        // otherwise pick.
        var httpsPort = TestSupport.GetFreeTcpPort();
        var frontPort = TestSupport.GetFreeTcpPort();
        var fronts = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-https",
                Transport: "https",
                BindAddress: $"127.0.0.1:{httpsPort}",
                PublicEndpoint: "https://hardened.example.test"));
        fronts.EnsureSuccessStatusCode();
        var redirector = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "front-http",
                Transport: "http",
                BindAddress: $"127.0.0.1:{frontPort}",
                PublicEndpoint: "http://front.example.test"));
        redirector.EnsureSuccessStatusCode();
        var frontListener = await redirector.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();

        var payloads = env.Host.Services.GetRequiredService<IPayloadStore>();
        var named = Guid.NewGuid();
        await payloads.SaveAsync(Payload(named, engagement, DateTimeOffset.UtcNow));

        // The wide credential: unlimited uses, a two-hour window -- the
        // many-host deployment posture.
        var rendered = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers",
            new
            {
                PayloadId = named.ToString(),
                ListenerId = frontListener!.Id,
                MaxUses = 0,
                LifetimeMinutes = 120,
            });
        rendered.EnsureSuccessStatusCode();
        var body = await rendered.Content.ReadFromJsonAsync<LauncherRenderDto>();
        Assert.NotNull(body);
        Assert.Equal($"http://front.example.test/implants/payloads/{named:N}", body!.Url);
        Assert.True(body.TokenExpiresAt > DateTimeOffset.UtcNow.AddMinutes(115));

        // The minted credential verifies against the token store: it is a
        // real deploy token under the requested policy, not a render-only
        // string.
        var tokens = env.Host.Services.GetRequiredService<IDeployTokenService>();
        var verified = await tokens.VerifyAsync(body.TokenSecret, DateTimeOffset.UtcNow);
        Assert.Equal(engagement, verified.EngagementId);

        // A nonsensical policy is refused rather than silently narrowed.
        var badPolicy = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers",
            new { MaxUses = -1 });
        Assert.Equal(HttpStatusCode.BadRequest, badPolicy.StatusCode);

        // A listener name that matches no web front of this engagement is
        // refused too.
        var badListener = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers",
            new { ListenerId = Guid.NewGuid().ToString() });
        Assert.Equal(HttpStatusCode.BadRequest, badListener.StatusCode);
    }

    [Fact]
    public async Task Renders_AreKeptAsRows_AndDeleteClosesTheWholeLifecycle()
    {
        await using var env = await TestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);
        var engagement = new EngagementId(Guid.Parse(engagementId));

        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-http",
                Transport: "http",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: "http://stage.example.test"));
        created.EnsureSuccessStatusCode();
        var frontListener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();

        var payloads = env.Host.Services.GetRequiredService<IPayloadStore>();
        var payloadId = Guid.NewGuid();
        await payloads.SaveAsync(Payload(payloadId, engagement, DateTimeOffset.UtcNow));

        // The render: kept as a row, answering with the full kept shape.
        var rendered = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers", new { });
        rendered.EnsureSuccessStatusCode();
        var row = await rendered.Content.ReadFromJsonAsync<LauncherRowDto>();
        Assert.NotNull(row);
        Assert.False(string.IsNullOrEmpty(row!.LauncherId));
        Assert.Equal(frontListener!.Name, row.FrontName);
        Assert.False(string.IsNullOrEmpty(row.TokenSecret));
        Assert.Contains(row.Launchers, l => l.Id == "unix-curl" && l.Command.Contains(row.Url));

        // The listing holds what was cut -- the same row, the commands
        // re-rendered from the stored url and secret. The payload reads in
        // the library's own vocabulary: the fingerprint the Payloads tab
        // shows, not the bare artifact id.
        var listed = await env.Http.GetFromJsonAsync<LauncherRowDto[]>(
            $"/engagements/{engagementId}/launchers");
        var kept = Assert.Single(listed!);
        Assert.Equal(row.LauncherId, kept.LauncherId);
        Assert.Equal("sha256:test", kept.PayloadFingerprint);
        Assert.Contains(kept.Launchers, l => l.Command.Contains(kept.TokenSecret));

        // Provenance names the cutting operator by handle, resolved on the
        // read -- the member role cannot walk the operator roster to do it.
        Assert.Equal(AuthenticatedHost.Handle, row.CreatedByHandle);
        Assert.Equal(AuthenticatedHost.Handle, kept.CreatedByHandle);

        // A deleted payload drops the join: the row still names the id it
        // delivered, and the fingerprint reads null.
        Assert.True(await payloads.RemoveAsync(payloadId, engagement.Value));
        var listedAfterPayloadDelete = await env.Http.GetFromJsonAsync<LauncherRowDto[]>(
            $"/engagements/{engagementId}/launchers");
        Assert.Null(Assert.Single(listedAfterPayloadDelete!).PayloadFingerprint);
        await payloads.SaveAsync(Payload(payloadId, engagement, DateTimeOffset.UtcNow));

        // Delete closes the whole lifecycle, not just the row: the credential
        // dies wherever a copy of the command carries it, then the row goes.
        var deleted = await env.Http.DeleteAsync(
            $"/engagements/{engagementId}/launchers/{row.LauncherId}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        var tokens = env.Host.Services.GetRequiredService<IDeployTokenService>();
        await Assert.ThrowsAsync<DeployTokenRedeemException>(
            () => tokens.VerifyAsync(row.TokenSecret, DateTimeOffset.UtcNow));
        var listedAfterDelete = await env.Http.GetFromJsonAsync<LauncherRowDto[]>(
            $"/engagements/{engagementId}/launchers");
        Assert.Empty(listedAfterDelete!);

        var deleteAgain = await env.Http.DeleteAsync(
            $"/engagements/{engagementId}/launchers/{row.LauncherId}");
        Assert.Equal(HttpStatusCode.NotFound, deleteAgain.StatusCode);
    }

    [Fact]
    public async Task TheRevokeEndpoint_IsTheSurgicalForm_ThatKeepsTheRow()
    {
        await using var env = await TestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);
        var engagement = new EngagementId(Guid.Parse(engagementId));

        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-http",
                Transport: "http",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: "http://stage.example.test"));
        created.EnsureSuccessStatusCode();

        var payloads = env.Host.Services.GetRequiredService<IPayloadStore>();
        var payloadId = Guid.NewGuid();
        await payloads.SaveAsync(Payload(payloadId, engagement, DateTimeOffset.UtcNow));

        var rendered = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers", new { });
        rendered.EnsureSuccessStatusCode();
        var row = await rendered.Content.ReadFromJsonAsync<LauncherRowDto>();

        // The surgical revoke kills the credential and marks the row; the row
        // stays, and a second pull of the handle is refused.
        var revoke = await env.Http.PostAsync(
            $"/engagements/{engagementId}/launchers/{row!.LauncherId}:revoke", content: null);
        revoke.EnsureSuccessStatusCode();
        var tokens = env.Host.Services.GetRequiredService<IDeployTokenService>();
        await Assert.ThrowsAsync<DeployTokenRedeemException>(
            () => tokens.VerifyAsync(row.TokenSecret, DateTimeOffset.UtcNow));
        var listedAfterRevoke = await env.Http.GetFromJsonAsync<LauncherRowDto[]>(
            $"/engagements/{engagementId}/launchers");
        Assert.NotNull(Assert.Single(listedAfterRevoke!).RevokedAt);

        var revokeAgain = await env.Http.PostAsync(
            $"/engagements/{engagementId}/launchers/{row.LauncherId}:revoke", content: null);
        Assert.Equal(HttpStatusCode.BadRequest, revokeAgain.StatusCode);

        // Deleting a revoked row is pure removal: no credential left to kill.
        var deleted = await env.Http.DeleteAsync(
            $"/engagements/{engagementId}/launchers/{row.LauncherId}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        var listedAfterDelete = await env.Http.GetFromJsonAsync<LauncherRowDto[]>(
            $"/engagements/{engagementId}/launchers");
        Assert.Empty(listedAfterDelete!);
    }

    private static PayloadRecord Payload(
        Guid id, EngagementId engagement, DateTimeOffset builtAt, string? target = "linux-x64",
        Guid? tokenId = null)
        => new(
            id, engagement.Value, "Implant", "dotnet", "application/octet-stream",
            "sha256:test", [1, 2, 3], 3, builtAt, Target: target, TokenId: tokenId);

    [Fact]
    public async Task Render_FiltersTheFamiliesToThePayloadsOwnOS()
    {
        await using var env = await TestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);
        var engagement = new EngagementId(Guid.Parse(engagementId));

        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-http",
                Transport: "http",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: "http://stage.example.test"));
        created.EnsureSuccessStatusCode();

        var payloads = env.Host.Services.GetRequiredService<IPayloadStore>();
        var linux = Guid.NewGuid();
        var windows = Guid.NewGuid();
        var untargeted = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await payloads.SaveAsync(Payload(linux, engagement, now, "linux/amd64"));
        await payloads.SaveAsync(Payload(windows, engagement, now, "windows/amd64"));
        await payloads.SaveAsync(Payload(untargeted, engagement, now, target: null));

        // A Linux payload offers the Unix families alone: a PowerShell fetch
        // would spend the credential on bytes it cannot run, and vice versa
        // -- a Windows payload answers the PowerShell family alone.
        var linuxRender = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers", new { PayloadId = linux.ToString() });
        linuxRender.EnsureSuccessStatusCode();
        var linuxBody = await linuxRender.Content.ReadFromJsonAsync<LauncherRenderDto>();
        Assert.NotNull(linuxBody);
        Assert.Contains(linuxBody!.Launchers, l => l.Id == "unix-curl");
        Assert.DoesNotContain(linuxBody.Launchers, l => l.Id == "windows-powershell");

        var windowsRender = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers", new { PayloadId = windows.ToString() });
        windowsRender.EnsureSuccessStatusCode();
        var windowsBody = await windowsRender.Content.ReadFromJsonAsync<LauncherRenderDto>();
        Assert.NotNull(windowsBody);
        var sole = Assert.Single(windowsBody!.Launchers);
        Assert.Equal("windows-powershell", sole.Id);

        // A payload whose record carries no target (the pre-target-field
        // shape) keeps every family: the shell the operator pastes into is
        // the only clue, so the guess stays the operator's.
        var untargetedRender = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers", new { PayloadId = untargeted.ToString() });
        untargetedRender.EnsureSuccessStatusCode();
        var untargetedBody = await untargetedRender.Content.ReadFromJsonAsync<LauncherRenderDto>();
        Assert.NotNull(untargetedBody);
        Assert.Contains(untargetedBody!.Launchers, l => l.Id == "unix-curl");
        Assert.Contains(untargetedBody.Launchers, l => l.Id == "windows-powershell");
    }

    [Fact]
    public async Task APayloadWhoseBakedCredentialIsDead_IsRefusedForRender()
    {
        await using var env = await TestEnv.StartAsync();
        var engagementId = await CreateEngagementAsync(env.Http);
        var engagement = new EngagementId(Guid.Parse(engagementId));

        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-http",
                Transport: "http",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: "http://stage.example.test"));
        created.EnsureSuccessStatusCode();

        // A payload whose baked enrollment credential was revoked: the fetch
        // would spend its freshly minted download credential on an artifact
        // that can never enroll, so the render refuses it -- named and as
        // the unnamed newest-build stand-in alike.
        var tokens = env.Host.Services.GetRequiredService<IDeployTokenService>();
        var engagements = env.Host.Services.GetRequiredService<IEngagementRepository>();
        var owner = (await engagements.FindAsync(engagement))!.OwnerId;
        var minted = await tokens.MintAsync(
            engagement, owner, DateTimeOffset.UtcNow,
            maxUses: 1, lifetime: TimeSpan.FromHours(1));
        Assert.True(await tokens.RevokeAsync(minted.Id));

        var payloads = env.Host.Services.GetRequiredService<IPayloadStore>();
        var dead = Guid.NewGuid();
        await payloads.SaveAsync(Payload(dead, engagement, DateTimeOffset.UtcNow, tokenId: minted.Id.Value));

        var refused = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers",
            new { PayloadId = dead.ToString() });
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        var text = await refused.Content.ReadAsStringAsync();
        Assert.Contains("can never enroll", text);

        var refusedAsNewest = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/launchers", new { });
        Assert.Equal(HttpStatusCode.BadRequest, refusedAsNewest.StatusCode);
        text = await refusedAsNewest.Content.ReadAsStringAsync();
        Assert.Contains("can never enroll", text);
    }

    [Fact]
    public void Render_AnswersTheDiskFamiliesAndTheInMemoryFamily()
    {
        // The unfiltered renderer (a payload with no recorded target): the
        // disk trio is the universal fallback, and every artifact the Rust
        // unit builds is a plain ELF that runs from an anonymous fd -- the
        // disk-or-memory choice is the operator's at paste time, not a
        // build-time axis. The credential rides each command exactly once.
        var rendered = ShellUpgradeLaunchers.Render(
            "http://stage.example.test/implants/payloads/abc", "secret");

        Assert.Contains(rendered, l => l.Id == "unix-curl");
        // Every fetch family must carry the URL it fetches -- a downloader
        // without one fails silently on the target (-q and friends).
        Assert.Contains(rendered, l => l.Id == "unix-wget"
            && l.Command.Contains("http://stage.example.test/implants/payloads/abc")
            && l.Command.Contains("-O /tmp/.rod-payload"));
        Assert.Contains(rendered, l => l.Id == "windows-powershell");

        var memfd = Assert.Single(rendered, l => l.Id == "unix-python-memfd");
        Assert.Equal("linux", memfd.Os);
        // The memfd acquisition must survive pre-3.8 pythons: prefer
        // os.memfd_create, fall back to the raw syscall through ctypes.
        Assert.Contains("getattr(os,'memfd_create',None)", memfd.Command);
        Assert.Contains("__import__('ctypes').CDLL(None).syscall", memfd.Command);
        Assert.Contains("/proc/self/fd", memfd.Command);
        Assert.Contains("secret", memfd.Command);
        Assert.All(rendered, l => Assert.Contains("secret", l.Command));
    }

    [Fact]
    public void Render_AnHttpsFrontCarriesEachFamilysVerificationBypass()
    {
        // The engagement CA terminates the front's TLS, and no stock
        // target-side toolchain trusts it (the implant pins the CA it
        // baked; curl and friends verify against system stores) -- so the
        // https spellings must render runnable: each family carries its
        // own no-verify flag, cleartext fronts none.
        var https = ShellUpgradeLaunchers.Render(
            "https://stage.example.test/implants/payloads/abc", "secret");
        Assert.Contains(https, l => l.Id == "unix-curl" && l.Command.Contains("-kfsSL"));
        Assert.Contains(https, l => l.Id == "unix-wget" && l.Command.Contains("--no-check-certificate"));
        Assert.Contains(https, l => l.Id == "windows-powershell"
            && l.Command.Contains("ServerCertificateValidationCallback"));
        Assert.Contains(https, l => l.Id == "unix-python-memfd"
            && l.Command.Contains("ssl._create_unverified_context()")
            && l.Command.Contains("urlopen(q,context=c)"));

        var http = ShellUpgradeLaunchers.Render(
            "http://stage.example.test/implants/payloads/abc", "secret");
        Assert.Contains(http, l => l.Id == "unix-curl" && l.Command.Contains("-fsSL")
            && !l.Command.Contains("-k"));
        Assert.Contains(http, l => l.Id == "unix-wget" && !l.Command.Contains("--no-check-certificate"));
        Assert.Contains(http, l => l.Id == "unix-python-memfd" && !l.Command.Contains("unverified"));
    }

    private sealed record LauncherRenderDto(
        string PayloadId,
        string Url,
        string TokenSecret,
        DateTimeOffset TokenExpiresAt,
        IReadOnlyList<LauncherDto> Launchers);

    // The kept-row shape: the render answer and the listing rows share it.
    // The fingerprint is the library's identifier for the delivered payload,
    // joined at read time; null once that payload is deleted.
    private sealed record LauncherRowDto(
        string LauncherId,
        string PayloadId,
        string? PayloadFingerprint,
        string Url,
        string FrontName,
        string FrontEndpoint,
        string TokenSecret,
        int MaxUses,
        DateTimeOffset ExpiresAt,
        DateTimeOffset CreatedAt,
        string CreatedBy,
        string CreatedByHandle,
        DateTimeOffset? RevokedAt,
        int? TokenRemainingUses,
        DateTimeOffset? TokenExpiresAt,
        IReadOnlyList<LauncherDto> Launchers);

    private sealed record LauncherDto(string Id, string Os, string Command);

    /// <summary>
    /// A real teamserver with the operator API and no startup stream
    /// listener -- the launcher route is engagement-scoped API surface, so
    /// the harness mirrors the shellcatch one.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;

        public static async Task<TestEnv> StartAsync()
        {
            var env = new TestEnv();
            var httpPort = TestSupport.GetFreeTcpPort();

            var config = AuthenticatedHost.BuildConfig();
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
                    .UseRodListeners(new List<ListenerConfig>())
                    .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(httpPort)))
                .Build();
            await env.Host.StartAsync();

            env.Http = new HttpClient(new CookieHandler(new HttpClientHandler()))
            {
                BaseAddress = new Uri($"http://127.0.0.1:{httpPort}"),
            };
            await AuthenticatedHost.LoginAsync(env.Http);
            return env;
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
