using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.CoreState;
using Rod.CoreState.Listeners;
using Rod.CoreState.Redirectors;
using Rod.Transport;
using Rod.Transport.Redirectors;

namespace Rod.Integration.Tests;

/// <summary>
/// The redirector control channel end to end (architecture.md Sec 8): enroll
/// once against a pre-provisioned credential, reconnect with the minted node
/// secret, heartbeat the fleet record, and receive the full-state rule push
/// derived from listener fronts.
/// </summary>
public class RedirectorControlChannelTests : IAsyncLifetime
{
    private IHost _host = null!;
    private HttpClient _client = null!;
    private OperatorId _operatorId;
    private IRedirectorFleet _fleet = null!;
    private TestServer _server = null!;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task InitializeAsync()
    {
        (_client, _host, _operatorId) = AuthenticatedHost.Create();
        await AuthenticatedHost.LoginAsync(_client);
        _fleet = _host.Services.GetRequiredService<IRedirectorFleet>();
        _server = _host.Services.GetRequiredService<IServer>() as TestServer
            ?? throw new InvalidOperationException("TestServer was not registered.");
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }

    private Task<WebSocket> ConnectAsync()
        => _server.CreateWebSocketClient()
            .ConnectAsync(new Uri("http://localhost/redirectors/control"), CancellationToken.None);

    private static async Task SendAsync(WebSocket socket, object message)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message, Json);
        await socket.SendAsync(bytes, WebSocketMessageType.Text, true, CancellationToken.None);
    }

    private static async Task<JsonElement> ReceiveAsync(WebSocket socket)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        while (true)
        {
            var received = await socket.ReceiveAsync(chunk, CancellationToken.None);
            if (received.MessageType == WebSocketMessageType.Close)
                throw new InvalidOperationException("The socket closed before a message arrived.");
            buffer.Write(chunk, 0, received.Count);
            if (received.EndOfMessage)
                return JsonSerializer.Deserialize<JsonElement>(buffer.ToArray());
        }
    }

    [Fact]
    public async Task Enroll_MintsTheNodeAndItsSecret()
    {
        var credential = await _fleet.MintCredentialAsync("edge-fra-1", _operatorId, DateTimeOffset.UtcNow);

        using var socket = await ConnectAsync();
        await SendAsync(socket, new { type = "enroll", credential = credential.Secret, version = "1.0.0", commit = "abc123" });
        var enrolled = await ReceiveAsync(socket);

        Assert.Equal("enrolled", enrolled.GetProperty("type").GetString());
        var nodeId = enrolled.GetProperty("nodeId").GetString();
        var nodeSecret = enrolled.GetProperty("nodeSecret").GetString();
        Assert.False(string.IsNullOrEmpty(nodeId));
        Assert.False(string.IsNullOrEmpty(nodeSecret));
        Assert.Equal(0, enrolled.GetProperty("rules").GetProperty("rules").GetArrayLength());

        Assert.True(RedirectorNodeId.TryParse(nodeId, out var parsedId));
        var node = await _fleet.FindAsync(parsedId);
        Assert.NotNull(node);
        Assert.Equal("edge-fra-1", node!.Name);
        Assert.Equal("1.0.0", node.ReportedVersion);
    }

    [Fact]
    public async Task Enroll_RefusedReasonsCrossTheWire()
    {
        using var bogus = await ConnectAsync();
        await SendAsync(bogus, new { type = "enroll", credential = "not-a-credential" });
        Assert.Equal("unknown", (await ReceiveAsync(bogus)).GetProperty("reason").GetString());

        var credential = await _fleet.MintCredentialAsync("edge", _operatorId, DateTimeOffset.UtcNow);
        using var first = await ConnectAsync();
        await SendAsync(first, new { type = "enroll", credential = credential.Secret });
        var enrolled = await ReceiveAsync(first);
        Assert.Equal("enrolled", enrolled.GetProperty("type").GetString());

        // Single-use: a replay of a spent credential names its reason.
        using var replay = await ConnectAsync();
        await SendAsync(replay, new { type = "enroll", credential = credential.Secret });
        Assert.Equal("spent", (await ReceiveAsync(replay)).GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Hello_ReconnectsWithTheNodeSecret()
    {
        var credential = await _fleet.MintCredentialAsync("edge-fra-1", _operatorId, DateTimeOffset.UtcNow);
        RedirectorNodeId nodeId;
        string nodeSecret;
        using (var socket = await ConnectAsync())
        {
            await SendAsync(socket, new { type = "enroll", credential = credential.Secret });
            var enrolled = await ReceiveAsync(socket);
            nodeId = RedirectorNodeId.TryParse(enrolled.GetProperty("nodeId").GetString()!, out var parsed) ? parsed : throw new InvalidOperationException("bad node id");
            nodeSecret = enrolled.GetProperty("nodeSecret").GetString()!;
        }

        using var reconnected = await ConnectAsync();
        await SendAsync(reconnected, new { type = "hello", nodeId = nodeId.ToString(), nodeSecret });
        var welcome = await ReceiveAsync(reconnected);
        Assert.Equal("welcome", welcome.GetProperty("type").GetString());
        Assert.Equal(0, welcome.GetProperty("rules").GetProperty("rules").GetArrayLength());

        // A wrong secret reads as unknown; a retired node as retired.
        using var wrong = await ConnectAsync();
        await SendAsync(wrong, new { type = "hello", nodeId = nodeId.ToString(), nodeSecret = "wrong" });
        Assert.Equal("unknown", (await ReceiveAsync(wrong)).GetProperty("reason").GetString());

        await _fleet.RetireAsync(nodeId, DateTimeOffset.UtcNow);
        using var retired = await ConnectAsync();
        await SendAsync(retired, new { type = "hello", nodeId = nodeId.ToString(), nodeSecret });
        Assert.Equal("retired", (await ReceiveAsync(retired)).GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Heartbeat_TouchesTheFleetRecord()
    {
        var credential = await _fleet.MintCredentialAsync("edge-fra-1", _operatorId, DateTimeOffset.UtcNow);
        using var socket = await ConnectAsync();
        await SendAsync(socket, new { type = "enroll", credential = credential.Secret });
        var enrolled = await ReceiveAsync(socket);

        await SendAsync(socket, new { type = "heartbeat", version = "1.1.0", commit = "def456" });
        await SendAsync(socket, new { type = "ack", digest = enrolled.GetProperty("rules").GetProperty("digest").GetString() });

        // The endpoint touches the record from its receive loop, a task
        // this assertion does not wait for: poll until both stamps land
        // rather than racing the loop's scheduling.
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        string? version = null;
        string? commit = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            var node = (await _fleet.ListNodesAsync()).Single();
            version = node.ReportedVersion;
            commit = node.ReportedCommit;
            if (version == "1.1.0" && commit == "def456")
                break;
            await Task.Delay(20);
        }
        Assert.Equal("1.1.0", version);
        Assert.Equal("def456", commit);
    }

    [Fact]
    public async Task Rules_PushDerivedFromListenerFronts()
    {
        var credential = await _fleet.MintCredentialAsync("edge-fra-1", _operatorId, DateTimeOffset.UtcNow);
        using var socket = await ConnectAsync();
        await SendAsync(socket, new { type = "enroll", credential = credential.Secret });
        var enrolled = await ReceiveAsync(socket);
        var nodeId = RedirectorNodeId.TryParse(enrolled.GetProperty("nodeId").GetString()!, out var parsed) ? parsed : throw new InvalidOperationException("bad node id");

        // A front attached to an engagement listener becomes one forwarding
        // rule: the node's listen endpoint spliced to the listener's bind.
        var definitions = _host.Services.GetRequiredService<IListenerStore>();
        var listenerId = Guid.NewGuid();
        await definitions.SaveAsync(new ListenerDefinition(
            listenerId,
            new EngagementId(Guid.NewGuid()),
            "https-ingress",
            "https",
            "10.0.0.5:8443",
            "203.0.113.10:443",
            DateTimeOffset.UtcNow,
            Fronts: new List<ListenerFront>
            {
                new(Guid.NewGuid(), nodeId, "0.0.0.0:443", "203.0.113.10:443", "198.51.100.0/24", DateTimeOffset.UtcNow),
            }));

        var hub = _host.Services.GetRequiredService<RedirectorControlHub>();
        await hub.PushRulesAsync(nodeId);

        var push = await ReceiveAsync(socket);
        Assert.Equal("rules", push.GetProperty("type").GetString());
        var rule = push.GetProperty("rules").GetProperty("rules")[0];
        Assert.Equal("tcp", rule.GetProperty("transport").GetString());
        Assert.Equal("0.0.0.0", rule.GetProperty("listenHost").GetString());
        Assert.Equal(443, rule.GetProperty("listenPort").GetInt32());
        Assert.Equal(8443, rule.GetProperty("upstreamPort").GetInt32());
        Assert.Equal("198.51.100.0/24", rule.GetProperty("allowList").GetString());
        Assert.False(string.IsNullOrEmpty(push.GetProperty("rules").GetProperty("digest").GetString()));
    }
}
