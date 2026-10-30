using System.Net;
using System.Text;
using System.Net.Http.Json;
using System.Net.Sockets;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.CoreState;
using Rod.CoreState.ShellSessions;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;
using Rod.Transport.Listeners.ShellCatch;
using static Rod.Integration.Tests.EngagementSetup;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: the shellcatch transport (architecture.md Sec 8) catches the
/// shells an operator's one-liners dial home. A connection speaking no Rod
/// protocol is accepted and held as a shell session scoped by its
/// engagement-bound listener; the first output the peer sends is
/// fingerprinted server-side; operator input flows down the socket; the
/// ending is attributed to who ended it (Lost when the peer goes away,
/// Closed when an operator asks). The fingerprint rules and the output
/// log's cursor contract are pinned directly alongside.
/// </summary>
public class ShellCatchTests
{
    [Fact]
    public void Fingerprinter_ReadsTheClassicBanners()
    {
        Assert.Equal(ShellOsGuess.UnixShell, ShellFingerprinter.Guess("user@target:~$ "));
        Assert.Equal(ShellOsGuess.UnixShell, ShellFingerprinter.Guess(
            "Welcome to Ubuntu 22.04 LTS\n\nroot@web01:~# "));
        Assert.Equal(ShellOsGuess.WindowsCmd, ShellFingerprinter.Guess(
            "\nMicrosoft Windows [Version 10.0.19045.4291]\n(c) Microsoft Corporation. All rights reserved.\n\nC:\\Users\\ops>"));
        Assert.Equal(ShellOsGuess.WindowsPowerShell, ShellFingerprinter.Guess(
            "Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nPS C:\\Users\\ops>"));
        Assert.Equal(ShellOsGuess.WindowsPowerShell, ShellFingerprinter.Guess("PS C:\\Users\\ops> "));
        Assert.Equal(ShellOsGuess.Unknown, ShellFingerprinter.Guess(""));
        Assert.Equal(ShellOsGuess.Unknown, ShellFingerprinter.Guess("just some text with no rule match"));
    }

    [Fact]
    public async Task OutputLog_CursorsBySequence_AndWaitsForAdvance()
    {
        var at = DateTimeOffset.UnixEpoch;
        var log = new ShellOutputLog();

        Assert.Equal(0, log.LatestSequence);
        Assert.Empty(log.ReadSince(0));

        var first = log.Append("hello", at);
        var second = log.Append("world", at.AddSeconds(1));
        Assert.Equal(1, first.Sequence);
        Assert.Equal(2, second.Sequence);
        Assert.Equal(2, log.LatestSequence);
        Assert.Equal(new[] { second }, log.ReadSince(1), ShellOutputChunkEqualityComparer.Instance);
        Assert.Empty(log.ReadSince(2));

        // A reader at the tip waits, then sees the next append.
        var waiting = log.WaitForAdvanceAsync(2, Timeout());
        Assert.False(waiting.IsCompleted);
        log.Append("more", at.AddSeconds(2));
        var advanced = await waiting;
        Assert.Equal(3, advanced);
    }

    [Fact]
    public async Task ShellCatchListener_HoldsAFingerprintedShell_AndMarksItLostWhenThePeerLeaves()
    {
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-shellcatch",
                Transport: "shellcatch",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"10.0.0.5:{port}"));
        created.EnsureSuccessStatusCode();
        var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.NotNull(listener);
        Assert.Equal("running", listener!.State);

        var hub = env.Host.Services.GetRequiredService<ShellCatchHub>();
        var sessions = env.Host.Services.GetRequiredService<IShellSessionRegistry>();

        // The one-liner's shape: connect, speak shell -- no handshake, no
        // protocol, just the banner a Unix shell prints.
        using var peer = new TcpClient();
        await peer.ConnectAsync(IPAddress.Loopback, port);
        await peer.GetStream().WriteAsync("user@target:~$ "u8.ToArray());

        var shell = await WaitForAsync(
            () => Task.FromResult(FindPeer(hub, peer)),
            found => found is not null, "the listener to catch the shell");
        var sessionId = shell!.Session.Id;

        // The banner is fingerprinted server-side and lands on the output
        // log the console reads.
        await WaitForAsync(
            () => sessions.FindAsync(sessionId),
            session => session?.Os == ShellOsGuess.UnixShell,
            "the banner to be fingerprinted");
        var caught = hub.Find(sessionId);
        Assert.NotNull(caught);
        Assert.Contains("user@target:~$", string.Concat(caught!.Output.ReadSince(0).Select(c => c.Text)));

        // The session registry scopes the catch to the engagement the
        // listener belongs to.
        var listed = await sessions.ListByEngagementAsync(
            new EngagementId(Guid.Parse(engagementId)));
        Assert.Contains(listed, s => s.Id == sessionId);
        Assert.Equal(ShellSessionStatus.Live, listed.Single(s => s.Id == sessionId).Status);

        // The peer going away ends the shell as Lost, and the hub holds
        // live sockets only.
        peer.Close();
        await WaitForAsync(
            () => sessions.FindAsync(sessionId),
            session => session?.Status == ShellSessionStatus.Lost,
            "the lost shell to be swept");
        Assert.Null(hub.Find(sessionId));
    }

    [Fact]
    public async Task OperatorClose_MarksTheShellClosed_InsteadOfLost()
    {
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-shellcatch",
                Transport: "shellcatch",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"10.0.0.5:{port}"));
        created.EnsureSuccessStatusCode();

        var hub = env.Host.Services.GetRequiredService<ShellCatchHub>();
        var sessions = env.Host.Services.GetRequiredService<IShellSessionRegistry>();

        using var peer = new TcpClient();
        await peer.ConnectAsync(IPAddress.Loopback, port);
        var shell = await WaitForAsync(
            () => Task.FromResult(FindPeer(hub, peer)),
            found => found is not null, "the listener to catch the shell");

        shell!.CloseByOperator();
        await WaitForAsync(
            () => sessions.FindAsync(shell.Session.Id),
            session => session?.Status == ShellSessionStatus.Closed,
            "the closed shell to be recorded");
    }

    [Fact]
    public async Task OperatorInput_FlowsDownTheSocket()
    {
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-shellcatch",
                Transport: "shellcatch",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"10.0.0.5:{port}"));
        created.EnsureSuccessStatusCode();

        var hub = env.Host.Services.GetRequiredService<ShellCatchHub>();

        using var peer = new TcpClient();
        await peer.ConnectAsync(IPAddress.Loopback, port);
        var shell = await WaitForAsync(
            () => Task.FromResult(FindPeer(hub, peer)),
            found => found is not null, "the listener to catch the shell");

        Assert.True(await shell!.WriteInputAsync("id\n", Timeout()));

        var buffer = new byte[64];
        var read = await peer.GetStream().ReadAsync(buffer, Timeout());
        Assert.Equal("id\n", System.Text.Encoding.UTF8.GetString(buffer, 0, read));
    }

    [Fact]
    public async Task ShellRoutes_ListReadInputClose_OverTheOperatorApi()
    {
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);
        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-shellcatch",
                Transport: "shellcatch",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"10.0.0.5:{port}"));
        created.EnsureSuccessStatusCode();

        using var peer = new TcpClient();
        await peer.ConnectAsync(IPAddress.Loopback, port);
        await peer.GetStream().WriteAsync("user@target:~$ "u8.ToArray());

        var peerPort = PeerPort(peer);
        ShellDto[] listed;
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
        do
        {
            listed = await env.Http.GetFromJsonAsync<ShellDto[]>(
                $"/engagements/{engagementId}/shells") ?? [];
            await Task.Delay(50);
        }
        while (!listed.Any(s => IsPeer(s, peerPort))
            && DateTime.UtcNow < deadline);
        var shell = Assert.Single(listed, s => IsPeer(s, peerPort));
        Assert.Equal("live", shell.Status);
        var sessionId = shell.SessionId;

        // The output read returns the banner chunks with a cursor; a read
        // caught up to the tip returns the same latest sequence without
        // waiting for more (chunks exist, so no long poll).
        ShellOutputDto? output;
        do
        {
            output = await env.Http.GetFromJsonAsync<ShellOutputDto>(
                $"/engagements/{engagementId}/shells/{sessionId}/output?after=0");
            await Task.Delay(50);
        }
        while ((output?.Chunks.Count ?? 0) == 0 && DateTime.UtcNow < deadline);
        Assert.NotNull(output);
        Assert.Contains("user@target:~$", string.Concat(output!.Chunks.Select(c => c.Text)));

        // Operator input rides the operator API down the socket, verbatim:
        // the line arrives with its own newline the way the console sends it.
        var sent = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/shells/{sessionId}:input",
            new ShellInputDto("whoami\n"));
        sent.EnsureSuccessStatusCode();
        var received = new StringBuilder();
        var buffer = new byte[64];
        while (received.Length == 0 || !received.ToString().EndsWith("\n"))
        {
            var read = await peer.GetStream().ReadAsync(buffer, Timeout());
            received.Append(System.Text.Encoding.UTF8.GetString(buffer, 0, read));
        }
        Assert.Equal("whoami\n", received.ToString());

        // The close route ends the shell as an operator action.
        var closed = await env.Http.PostAsync(
            $"/engagements/{engagementId}/shells/{sessionId}:close", content: null);
        Assert.Equal(HttpStatusCode.Accepted, closed.StatusCode);

        var sessions = env.Host.Services.GetRequiredService<IShellSessionRegistry>();
        await WaitForAsync(
            () => sessions.FindAsync(ShellSessionId.TryParse(sessionId, out var id) ? id : default),
            session => session?.Status == ShellSessionStatus.Closed,
            "the operator close to be honored");
    }

    [Fact]
    public async Task ShellRoutes_RefuseAForeignEngagement()
    {
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);
        var otherEngagementId = await CreateEngagementAsync(env.Http);
        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-shellcatch",
                Transport: "shellcatch",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"10.0.0.5:{port}"));
        created.EnsureSuccessStatusCode();

        using var peer = new TcpClient();
        await peer.ConnectAsync(IPAddress.Loopback, port);
        var peerPort = PeerPort(peer);

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
        ShellDto[] listed;
        do
        {
            listed = await env.Http.GetFromJsonAsync<ShellDto[]>(
                $"/engagements/{engagementId}/shells") ?? [];
            await Task.Delay(50);
        }
        while (!listed.Any(s => IsPeer(s, peerPort)) && DateTime.UtcNow < deadline);
        var sessionId = Assert.Single(listed, s => IsPeer(s, peerPort)).SessionId;

        // A foreign engagement's roster is empty and its scoped reads
        // refuse the session as unknown -- engagement isolation reads the
        // same here as everywhere else.
        var foreignList = await env.Http.GetFromJsonAsync<ShellDto[]>(
            $"/engagements/{otherEngagementId}/shells");
        Assert.Empty(foreignList!);
        var foreignOutput = await env.Http.GetAsync(
            $"/engagements/{otherEngagementId}/shells/{sessionId}/output");
        Assert.Equal(HttpStatusCode.NotFound, foreignOutput.StatusCode);
    }

    [Fact]
    public async Task SessionEncoding_RepointsBothDirections()
    {
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);
        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-shellcatch",
                Transport: "shellcatch",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"10.0.0.5:{port}"));
        created.EnsureSuccessStatusCode();

        using var peer = new TcpClient();
        await peer.ConnectAsync(IPAddress.Loopback, port);
        var peerPort = PeerPort(peer);

        ShellDto[] listed;
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
        do
        {
            listed = await env.Http.GetFromJsonAsync<ShellDto[]>(
                $"/engagements/{engagementId}/shells") ?? [];
            await Task.Delay(50);
        }
        while (!listed.Any(s => IsPeer(s, peerPort))
            && DateTime.UtcNow < deadline);
        var sessionId = Assert.Single(listed, s => IsPeer(s, peerPort)).SessionId;

        // A legacy-code-page shell mojibakes under the default UTF-8 decode:
        // these are the GBK bytes of the characters under test.
        byte[] gbkZhong = [0xD6, 0xD0]; // "zhong" (middle)
        byte[] gbkHao = [0xBA, 0xC3];   // "hao" (good)
        byte[] gbkWen = [0xCE, 0xC4];   // "wen" (text)

        // Default decode: the GBK pair reads as replacement characters, so
        // the mojibake a GBK target shows under UTF-8 is pinned here.
        await peer.GetStream().WriteAsync(gbkZhong);
        var mojibake = await ReadOutputAsync(env.Http, engagementId, sessionId, deadline);
        Assert.Contains('\uFFFD', mojibake);
        Assert.DoesNotContain("\u4E2D", mojibake); // the real "zhong" never lands

        // The roster names the default; the switch names the new codec and
        // the roster follows it.
        var beforeSwitch = await env.Http.GetFromJsonAsync<ShellDto[]>(
            $"/engagements/{engagementId}/shells") ?? [];
        Assert.Equal("utf-8", Assert.Single(beforeSwitch, s => s.SessionId == sessionId).Encoding);
        var switched = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/shells/{sessionId}:encoding",
            new ShellEncodingDto("gbk"));
        Assert.Equal(HttpStatusCode.OK, switched.StatusCode);
        var afterSwitch = await env.Http.GetFromJsonAsync<ShellDto[]>(
            $"/engagements/{engagementId}/shells") ?? [];
        Assert.Equal("gbk", Assert.Single(afterSwitch, s => s.SessionId == sessionId).Encoding);

        // Bytes after the switch decode as the characters they carry...
        await peer.GetStream().WriteAsync(gbkHao);
        var decoded = await ReadOutputAsync(env.Http, engagementId, sessionId, deadline);
        Assert.Contains("\u597D", decoded); // "hao" -- the decoded character

        // ...and input encodes back the same way: the peer reads the GBK
        // bytes of the character the operator submitted as text.
        var sent = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/shells/{sessionId}:input",
            new ShellInputDto("\u6587")); // "wen"
        sent.EnsureSuccessStatusCode();
        var received = new byte[2];
        await peer.GetStream().ReadExactlyAsync(received);
        Assert.Equal(gbkWen, received);

        // An unoffered name is refused outright.
        var refused = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/shells/{sessionId}:encoding",
            new ShellEncodingDto("ebcdic"));
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
    }

    // Drains the output log to its tip and returns everything readable.
    private static async Task<string> ReadOutputAsync(
        HttpClient http, string engagementId, string sessionId, DateTime deadline)
    {
        var text = new StringBuilder();
        long cursor = 0;
        while (DateTime.UtcNow < deadline)
        {
            var output = await http.GetFromJsonAsync<ShellOutputDto>(
                $"/engagements/{engagementId}/shells/{sessionId}/output?after={cursor}");
            if (output is { Chunks.Count: > 0 })
            {
                cursor = output.LatestSequence;
                text.Append(string.Concat(output.Chunks.Select(c => c.Text)));
                if (output.Chunks.Count < 512) break; // caught up to the tip
            }
            else
            {
                break; // long poll answered empty: quiet
            }
        }
        return text.ToString();
    }

    private sealed record ShellDto(
        string SessionId, string Status, string Os, string RemoteAddress, string? Encoding);

    private sealed record ShellOutputDto(long LatestSequence, IReadOnlyList<ShellChunkDto> Chunks);

    private sealed record ShellChunkDto(long Sequence, DateTimeOffset At, string Text);

    private sealed record ShellInputDto(string Text);

    private sealed record ShellEncodingDto(string Encoding);

    [Fact]
    public async Task UpgradeRoute_RendersFetchAndRunLaunchers_AgainstTheEngagementsWebListener()
    {
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);
        var engagement = new EngagementId(Guid.Parse(engagementId));

        // The web front the payload fetch rides, plus the catcher.
        var httpPort = TestSupport.GetFreeTcpPort();
        var webListener = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-http",
                Transport: "http",
                BindAddress: $"127.0.0.1:{httpPort}",
                PublicEndpoint: "http://stage.example.test"));
        webListener.EnsureSuccessStatusCode();
        var catchPort = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-shellcatch",
                Transport: "shellcatch",
                BindAddress: $"127.0.0.1:{catchPort}",
                PublicEndpoint: $"10.0.0.5:{catchPort}"));
        created.EnsureSuccessStatusCode();

        // A built payload in the store, so the render has something
        // to grow into without paying for a real build here.
        var payloads = env.Host.Services.GetRequiredService<Rod.Audit.IPayloadStore>();
        var payloadId = Guid.NewGuid();
        await payloads.SaveAsync(new Rod.Audit.PayloadRecord(
            payloadId, engagement.Value, "Implant", "dotnet", "application/octet-stream",
            "sha256:test", [1, 2, 3], 3, DateTimeOffset.UtcNow, Target: "linux-x64"));

        using var peer = new TcpClient();
        await peer.ConnectAsync(IPAddress.Loopback, catchPort);
        var peerPort = PeerPort(peer);
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
        ShellDto[] listed;
        do
        {
            listed = await env.Http.GetFromJsonAsync<ShellDto[]>(
                $"/engagements/{engagementId}/shells") ?? [];
            await Task.Delay(50);
        }
        while (!listed.Any(s => IsPeer(s, peerPort)) && DateTime.UtcNow < deadline);
        var sessionId = Assert.Single(listed, s => IsPeer(s, peerPort)).SessionId;

        var upgrade = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/shells/{sessionId}:upgrade",
            new { });
        upgrade.EnsureSuccessStatusCode();
        var rendered = await upgrade.Content.ReadFromJsonAsync<ShellUpgradeDto>();
        Assert.NotNull(rendered);
        Assert.Equal(payloadId.ToString("N"), rendered!.PayloadId);
        Assert.Equal(
            $"http://stage.example.test/implants/payloads/{payloadId:N}",
            rendered.Url);
        Assert.False(string.IsNullOrEmpty(rendered.TokenSecret));
        // The payload's own families: a linux target offers the Unix fetches
        // alone -- the PowerShell spelling would spend the single-use
        // credential on bytes it cannot run.
        Assert.Contains(rendered.Launchers, l => l.Id == "unix-curl" && l.Command.Contains(rendered.Url));
        Assert.Contains(rendered.Launchers, l => l.Id == "unix-wget");
        Assert.DoesNotContain(rendered.Launchers, l => l.Id == "windows-powershell");
        Assert.All(rendered.Launchers, l => Assert.Contains(rendered.TokenSecret, l.Command));
    }

    private sealed record ShellUpgradeDto(
        string PayloadId,
        string Url,
        string TokenSecret,
        DateTimeOffset TokenExpiresAt,
        IReadOnlyList<ShellLauncherDto> Launchers);

    private sealed record ShellLauncherDto(string Id, string Os, string Command);

    // A caught shell is identified by the peer's own ephemeral port, never
    // by roster cardinality: under a loaded parallel suite a stray
    // connection can land on the catch port too (the free-port picker's
    // TOCTOU), and only this peer's session matters.
    private static int PeerPort(TcpClient peer)
        => ((IPEndPoint)peer.Client.LocalEndPoint!).Port;

    private static bool IsPeer(ShellDto shell, int peerPort)
        => shell.RemoteAddress.EndsWith($":{peerPort}");

    private static CaughtShell? FindPeer(ShellCatchHub hub, TcpClient peer)
        => hub.List().FirstOrDefault(s => s.RemoteAddress.EndsWith($":{PeerPort(peer)}"));

    private static async Task<T> WaitForAsync<T>(
        Func<Task<T>> probe, Func<T, bool> done, string expectation, TimeSpan? budget = null)
    {
        var deadline = DateTime.UtcNow + (budget ?? TimeSpan.FromSeconds(15));
        while (DateTime.UtcNow < deadline)
        {
            var value = await probe();
            if (done(value))
                return value;
            await Task.Delay(50);
        }

        throw new TimeoutException($"Timed out waiting for {expectation}.");
    }

    // The read/write deadlines for the socket round trips; one shared shape
    // keeps the waits honest without sprinkling raw timeouts through the
    // tests.
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(15)).Token;

    private sealed class ShellOutputChunkEqualityComparer : IEqualityComparer<ShellOutputChunk>
    {
        public static readonly ShellOutputChunkEqualityComparer Instance = new();

        public bool Equals(ShellOutputChunk? x, ShellOutputChunk? y) => x == y;
        public int GetHashCode(ShellOutputChunk obj) => obj.GetHashCode();
    }

    /// <summary>
    /// A real teamserver with the operator API and no startup stream
    /// listener -- the shellcatch listener under test is created at runtime
    /// through the engagement-scoped API, the tier it belongs to. Mirrors
    /// the stream listener harness.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public Microsoft.Extensions.Hosting.IHost Host { get; private set; } = null!;
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
