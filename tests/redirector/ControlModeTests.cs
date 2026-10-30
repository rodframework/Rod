using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Rod.Redirector;

namespace Rod.Redirector.Tests;

/// <summary>
/// The enrolled mode's local halves: the rule-driven forwarder set
/// reconciles pushed rules (start, stop, restart-on-change), and the node
/// identity persists exactly the pair enrollment minted.
/// </summary>
public class ControlModeTests
{
    private static async Task<int> GetFreePortAsync()
    {
        using var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    private static ForwardingRuleWire TcpRule(string id, int listenPort, int upstreamPort)
        => new(id, "tcp", "127.0.0.1", listenPort, "127.0.0.1", upstreamPort, null);

    [Fact]
    public async Task ForwarderSet_ReconcilesPushedRules()
    {
        var upstreamA = await GetFreePortAsync();
        var upstreamB = await GetFreePortAsync();
        var frontA = await GetFreePortAsync();
        var frontB = await GetFreePortAsync();

        await using var set = new ForwarderSet(TextWriter.Null);
        await set.ApplyAsync(new[]
        {
            TcpRule("a", frontA, upstreamA),
            TcpRule("b", frontB, upstreamB),
        });
        Assert.Equal(2, set.RunningCount);
        await AssertPortAcceptsAsync(frontA);
        await AssertPortAcceptsAsync(frontB);

        // A re-push of the same rules touches nothing.
        await set.ApplyAsync(new[]
        {
            TcpRule("a", frontA, upstreamA),
            TcpRule("b", frontB, upstreamB),
        });
        Assert.Equal(2, set.RunningCount);

        // A changed rule restarts on its own bind; a gone rule stops; a rule
        // the build cannot carry skips without hurting the rest.
        var frontA2 = await GetFreePortAsync();
        await set.ApplyAsync(new[]
        {
            TcpRule("a", frontA2, upstreamB),
            new ForwardingRuleWire("q", "quic", "127.0.0.1", await GetFreePortAsync(), "127.0.0.1", 443, null),
        });
        Assert.Equal(1, set.RunningCount);
        await AssertPortAcceptsAsync(frontA2);
        await AssertPortRefusesAsync(frontA);
        await AssertPortRefusesAsync(frontB);
    }

    [Fact]
    public async Task ForwarderSet_CarriesTheDatagramRelay()
    {
        // A UDP echo upstream and a udp rule: datagrams through the rule's
        // port relay both directions, protocol-blind.
        using var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var upstreamEndpoint = (IPEndPoint)upstream.Client.LocalEndPoint!;
        var echo = Task.Run(async () =>
        {
            while (true)
            {
                var received = await upstream.ReceiveAsync();
                await upstream.SendAsync(received.Buffer, received.RemoteEndPoint);
            }
        });

        await using var set = new ForwarderSet(TextWriter.Null);
        var front = await GetFreePortAsync();
        await set.ApplyAsync(new[]
        {
            new ForwardingRuleWire("u", "udp", "127.0.0.1", front,
                "127.0.0.1", upstreamEndpoint.Port, null),
        });
        Assert.Equal(1, set.RunningCount);

        using var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var payload = "dns-shaped-bytes"u8.ToArray();
        await client.SendAsync(payload, payload.Length, "127.0.0.1", front);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var replyTask = client.ReceiveAsync(timeout.Token);
        // UdpClient's CancellationToken overload wraps the result.
        var reply = await replyTask;
        Assert.Equal(payload, reply.Buffer);
    }

    [Fact]
    public async Task NodeState_RoundTripsAndToleratesCorruption()
    {
        var path = Path.Combine(Path.GetTempPath(), $"rod-node-state-{Guid.NewGuid():N}.json");
        try
        {
            Assert.Null(NodeState.Load(path));

            new NodeState("node-1", "secret-1").Save(path);
            var loaded = NodeState.Load(path);
            Assert.Equal("node-1", loaded!.NodeId);
            Assert.Equal("secret-1", loaded.NodeSecret);

            File.WriteAllText(path, "{ not json");
            Assert.Null(NodeState.Load(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Config_EnrolledModeRejectsManualFlagsAndBadUrls()
    {
        var mixed = Assert.Throws<ExitProgramException>(
            () => RedirectorConfig.Parse(["-control", "ws://x/redirectors/control", "-listen", "0.0.0.0:443"]));
        Assert.Equal(2, mixed.ExitCode);

        var badScheme = Assert.Throws<ExitProgramException>(
            () => RedirectorConfig.Parse(["-control", "http://x/redirectors/control"]));
        Assert.Equal(2, badScheme.ExitCode);

        var enrolled = RedirectorConfig.Parse(
        [
            "-control", "wss://teamserver:5080/redirectors/control",
            "-credential", "c", "-state", "s.json",
        ]);
        Assert.True(enrolled.HasControl);
        Assert.Equal("s.json", enrolled.StatePath);

        var manual = RedirectorConfig.Parse(["-listen", "127.0.0.1:8080", "-upstream", "10.0.0.5:8443"]);
        Assert.False(manual.HasControl);
    }

    [Fact]
    public async Task RunAsync_ReconnectsWithMintedIdentityAfterEnrollLinkDrops()
    {
        // A fresh-enrolled node whose control link drops must come back with
        // hello (the persisted node secret), never a second enroll: the
        // credential is spent, and a re-enroll answers "spent" -- which the
        // client reads as a terminal refusal and retires the process.
        var port = await GetFreePortAsync();
        using var server = new HttpListener();
        server.Prefixes.Add($"http://127.0.0.1:{port}/");
        server.Start();

        var statePath = Path.Combine(Path.GetTempPath(), $"rod-node-state-{Guid.NewGuid():N}.json");
        await using var forwarders = new ForwarderSet(TextWriter.Null);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var client = new ControlClient(
            new Uri($"ws://127.0.0.1:{port}/control"), "credential", statePath, forwarders, TextWriter.Null);
        var runTask = Task.Run(() => client.RunAsync(cts.Token), cts.Token);

        try
        {
            // Link 1: answer the enroll, then hang up -- the "teamserver
            // restart" shape. A clean close (not an abort: the managed
            // HttpListener's Abort is not observable from the peer on
            // Linux) walks the same reconnect path a dropped link does.
            var link1 = await AcceptControlLinkAsync(server);
            Assert.Equal("enroll", link1.Message.RootElement.GetProperty("type").GetString());
            await SendControlMessageAsync(link1.Socket,
                $$"""{"type":"enrolled","nodeId":"node-9","nodeSecret":"secret-9"}""");
            await link1.Socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "restart", CancellationToken.None);

            // Link 2: the first message must be hello carrying the minted
            // identity; a client that re-enrolled instead would surface as
            // "enroll" here and shortly after as a refusal.
            var link2 = await AcceptControlLinkAsync(server);
            Assert.Equal("hello", link2.Message.RootElement.GetProperty("type").GetString());
            Assert.Equal("node-9", link2.Message.RootElement.GetProperty("nodeId").GetString());
            Assert.Equal("secret-9", link2.Message.RootElement.GetProperty("nodeSecret").GetString());
            await SendControlMessageAsync(link2.Socket, """{"type":"welcome"}""");

            // Steady state reached: a clean stop must exit 0, not retire.
            cts.Cancel();
            var exitCode = await runTask;
            Assert.Equal(0, exitCode);
        }
        finally
        {
            cts.Cancel();
            await runTask;
            File.Delete(statePath);
            server.Stop();
        }
    }

    private static async Task<(System.Net.WebSockets.WebSocket Socket, JsonDocument Message)>
        AcceptControlLinkAsync(HttpListener server)
    {
        var context = await server.GetContextAsync();
        var socket = (await context.AcceptWebSocketAsync(null)).WebSocket;
        var message = await ReceiveControlMessageAsync(socket);
        return (socket, message);
    }

    private static async Task<JsonDocument> ReceiveControlMessageAsync(System.Net.WebSockets.WebSocket socket)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        while (true)
        {
            var received = await socket.ReceiveAsync(new ArraySegment<byte>(chunk), CancellationToken.None);
            if (received.MessageType == WebSocketMessageType.Close)
                Assert.Fail("The control link closed before sending a message.");
            buffer.Write(chunk, 0, received.Count);
            if (received.EndOfMessage)
                return JsonDocument.Parse(Encoding.UTF8.GetString(buffer.ToArray()));
        }
    }

    private static Task SendControlMessageAsync(System.Net.WebSockets.WebSocket socket, string json)
        => socket.SendAsync(Encoding.UTF8.GetBytes(json), WebSocketMessageType.Text, true, CancellationToken.None);

    private static async Task AssertPortAcceptsAsync(int port)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        Assert.True(client.Connected);
    }

    private static async Task AssertPortRefusesAsync(int port)
    {
        // A stopped listener refuses new connections; give the unbind a
        // moment to land before asking.
        await Task.Delay(200);
        using var client = new TcpClient();
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, port);
            Assert.Fail($"Port {port} still accepts connections.");
        }
        catch (SocketException)
        {
        }
    }
}
