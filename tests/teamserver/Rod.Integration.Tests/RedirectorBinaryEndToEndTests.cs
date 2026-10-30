using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Transport;

namespace Rod.Integration.Tests;

/// <summary>
/// The control plane's acceptance walk (docs/todo.md, the item's own AC):
/// a real redirector binary enrolls against a real teamserver, a front
/// attached through the operator API provisions it with the forwarding rule
/// over the control channel, and a contact through the front reaches the
/// listener's bind -- proved by a TLS handshake completing end to end, the
/// runbook's own verification probe. Rotation (identity persistence and
/// reconnect) is the second half: the binary restarts without the
/// credential and reconnects from its state file.
/// </summary>
public class RedirectorBinaryEndToEndTests : IAsyncLifetime
{
    private IHost _host = null!;
    private HttpClient _client = null!;
    private Guid _engagementId;
    private string _redirectorDll = null!;
    private string _workDir = null!;

    private const int PollMs = 200;

    public async Task InitializeAsync()
    {
        var httpPort = TestSupport.GetFreeTcpPort();
        var config = AuthenticatedHost.BuildConfig();
        _host = TransportHost.CreateHostBuilder(
                configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                configuration: config)
            .ConfigureWebHost(webBuilder => webBuilder.UseRodListeners(
            [
                // The shared tier carries the control channel (a deployment-
                // scoped surface, never an engagement's), and wiring it the
                // real way also arms the Kestrel reloader the runtime
                // listener create below needs.
                new Rod.Transport.Listeners.ListenerConfig(
                    "operator-http", "http", $"127.0.0.1:{httpPort}", $"http://127.0.0.1:{httpPort}"),
            ]))
            .Build();
        await _host.StartAsync();

        _client = new HttpClient(new CookieHandler(new HttpClientHandler { UseProxy = false }))
        {
            BaseAddress = new Uri($"http://127.0.0.1:{httpPort}"),
        };
        await AuthenticatedHost.LoginAsync(_client);
        _engagementId = (await EngagementSetup.CreateOwnedEngagementAsync(_host)).Value;

        _redirectorDll = Path.Combine(FindRepoRoot(), "src/redirector/bin/Debug/net10.0/rod-redirector.dll");
        // Always build: this test project does not reference the redirector,
        // so nothing else guarantees the dll reflects the current tree.
        await RunAsync("dotnet", $"build \"{Path.Combine(FindRepoRoot(), "src/redirector/Rod.Redirector.csproj")}\" -c Debug", FindRepoRoot());

        _workDir = Path.Combine(Path.GetTempPath(), $"rod-redirector-e2e-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_workDir);
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
        if (Directory.Exists(_workDir))
            Directory.Delete(_workDir, recursive: true);
    }

    [Fact]
    public async Task EnrolledNode_ServesAttachedFronts_AndReconnectsFromState()
    {
        // One https listener on a real socket: the bind the pushed rule
        // splices to.
        var bindPort = TestSupport.GetFreeTcpPort();
        var created = await ReadJsonAsync(await _client.PostAsJsonAsync(
            $"/engagements/{_engagementId}/listeners",
            new { name = "e2e-ingress", transport = "https", bindAddress = $"127.0.0.1:{bindPort}", publicEndpoint = $"https://127.0.0.1:{bindPort}" }));
        var listenerId = created.GetProperty("id").GetString()!;

        var minted = await ReadJsonAsync(await _client.PostAsJsonAsync(
            "/redirectors/credentials", new { name = "edge-e2e" }));
        var secret = minted.GetProperty("secret").GetString()!;
        var statePath = Path.Combine(_workDir, "state.json");

        var frontPort = TestSupport.GetFreeTcpPort();
        using (var process = StartRedirector($"-control ws://127.0.0.1:{_client.BaseAddress!.Port}/redirectors/control -credential {secret} -state {statePath}"))
        {
            // Enrolled and online.
            await WaitUntilAsync(async () =>
            {
                var roster = await ReadJsonAsync(await _client.GetAsync("/redirectors"));
                return roster.EnumerateArray().Any(n => n.GetProperty("name").GetString() == "edge-e2e"
                    && n.GetProperty("online").GetBoolean());
            });

            // Attach the front; the rule lands on the node's open control
            // socket and the forwarder binds.
            var attached = await _client.PostAsJsonAsync(
                $"/engagements/{_engagementId}/listeners/{listenerId}/fronts",
                new
                {
                    nodeId = (await ReadJsonAsync(await _client.GetAsync("/redirectors")))
                    .EnumerateArray().Single(n => n.GetProperty("name").GetString() == "edge-e2e")
                    .GetProperty("id").GetString(),
                    listenEndpoint = $"127.0.0.1:{frontPort}",
                    publicEndpoint = $"127.0.0.1:{frontPort}",
                    primary = true
                });
            var attachBody = await attached.Content.ReadAsStringAsync();
            Assert.True(
                attached.IsSuccessStatusCode,
                $"front attach answered {attached.StatusCode}: {attachBody}");

            await WaitUntilAsync(() => PortAcceptsAsync(frontPort));

            // The contact through the front: a TLS handshake completing
            // through the node's port proves the splice reached the
            // listener's bind and carried bytes both ways -- the runbook's
            // openssl probe, executed.
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, frontPort);
            using var ssl = new SslStream(
                tcp.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync("localhost");
            Assert.True(ssl.IsAuthenticated);

            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
        }

        // The identity persisted: a restart with no credential reconnects
        // from the state file and re-receives its rules (the front serves
        // again without any attach).
        Assert.True(File.Exists(statePath));
        using (var restarted = StartRedirector($"-control ws://127.0.0.1:{_client.BaseAddress!.Port}/redirectors/control -state {statePath}"))
        {
            await WaitUntilAsync(() => PortAcceptsAsync(frontPort));
            restarted.Kill(entireProcessTree: true);
            await restarted.WaitForExitAsync();
        }
    }

    [Fact]
    public async Task DnsFront_ServesDatagramsThroughTheNode()
    {
        // The datagram leg of the control plane: a dns listener fronted by
        // the enrolled node answers a query that arrives through the node's
        // UDP port -- the record-type cover (an A query under the zone
        // answers an address), read here as the query id echoing back with
        // no error, the same probe a resolver would run.
        var dnsPort = TestSupport.GetFreeTcpPort();
        var created = await ReadJsonAsync(await _client.PostAsJsonAsync(
            $"/engagements/{_engagementId}/listeners",
            new
            {
                name = "dns-ingress",
                transport = "dns",
                bindAddress = $"127.0.0.1:{dnsPort}",
                publicEndpoint = "zone.example.test",
            }));
        var listenerId = created.GetProperty("id").GetString()!;

        var minted = await ReadJsonAsync(await _client.PostAsJsonAsync(
            "/redirectors/credentials", new { name = "edge-dns" }));
        var statePath = Path.Combine(_workDir, "dns-state.json");
        var frontPort = TestSupport.GetFreeTcpPort();
        using var process = StartRedirector(
            $"-control ws://127.0.0.1:{_client.BaseAddress!.Port}/redirectors/control -credential {minted.GetProperty("secret").GetString()} -state {statePath}");
        try
        {
            await WaitUntilAsync(async () =>
            {
                var roster = await ReadJsonAsync(await _client.GetAsync("/redirectors"));
                return roster.EnumerateArray().Any(n => n.GetProperty("name").GetString() == "edge-dns"
                    && n.GetProperty("online").GetBoolean());
            });

            var attached = await _client.PostAsJsonAsync(
                $"/engagements/{_engagementId}/listeners/{listenerId}/fronts",
                new
                {
                    nodeId = (await ReadJsonAsync(await _client.GetAsync("/redirectors")))
                        .EnumerateArray().Single(n => n.GetProperty("name").GetString() == "edge-dns")
                        .GetProperty("id").GetString(),
                    listenEndpoint = $"127.0.0.1:{frontPort}",
                    publicEndpoint = "127.0.0.1",
                    primary = true,
                });
            Assert.True(attached.IsSuccessStatusCode, await attached.Content.ReadAsStringAsync());

            await WaitUntilAsync(() => UdpAnswersAsync(frontPort));
        }
        finally
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
        }
    }

    /// <summary>
    /// One A-record cover query through the node's UDP port: a well-formed
    /// DNS query for a name under the zone, answered -- the id echoing back
    /// with no error proves the datagram reached the listener and its
    /// answer returned through the relay.
    /// </summary>
    private static async Task<bool> UdpAnswersAsync(int port)
    {
        try
        {
            using var dns = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
            var query = BuildAQuery(id, "probe.zone.example.test");
            await dns.SendAsync(query, query.Length, "127.0.0.1", port);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var answer = (await dns.ReceiveAsync(timeout.Token)).Buffer;
            return answer.Length >= 12
                && answer[0] == (byte)(id >> 8) && answer[1] == (byte)id
                && (answer[3] & 0x0F) == 0;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return false;
        }
    }

    // A minimal DNS wire query: header, one question, name as labels.
    private static byte[] BuildAQuery(ushort id, string name)
    {
        using var buffer = new MemoryStream();
        buffer.Write([(byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        foreach (var label in name.Split('.'))
        {
            buffer.Write([(byte)label.Length]);
            buffer.Write(System.Text.Encoding.ASCII.GetBytes(label));
        }

        buffer.Write([(byte)0, 0, 1, 0, 1]); // root label, type A, class IN
        return buffer.ToArray();
    }

    private Process StartRedirector(string arguments)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"{_redirectorDll} {arguments}",
                WorkingDirectory = _workDir,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            },
        };
        process.ErrorDataReceived += (_, e) => { if (e.Data is { Length: > 0 }) _output.AppendLine(e.Data); };
        process.Start();
        process.BeginErrorReadLine();
        return process;
    }

    private readonly StringBuilder _output = new();

    private async Task WaitUntilAsync(Func<Task<bool>> condition, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(30));
        while (DateTime.UtcNow < deadline)
        {
            if (await condition())
                return;
            await Task.Delay(PollMs);
        }

        Assert.Fail($"Condition not met within the timeout. Redirector output:\n{_output}");
    }

    private static async Task<bool> PortAcceptsAsync(int port)
    {
        try
        {
            using var probe = new TcpClient();
            await probe.ConnectAsync(IPAddress.Loopback, port);
            return probe.Connected;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        response.EnsureSuccessStatusCode();
        return JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());
    }

    private static async Task RunAsync(string fileName, string arguments, string workingDirectory)
    {
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            WorkingDirectory = workingDirectory,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            CreateNoWindow = true,
        }) ?? throw new InvalidOperationException($"{fileName} failed to start");
        await process.WaitForExitAsync();
        Assert.Equal(0, process.ExitCode);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Rod.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}
