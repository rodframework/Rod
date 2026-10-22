using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.CoreState;
using Rod.CoreState.Implants;
using Rod.CoreState.Pki;
using Rod.Transport;
using Rod.Transport.Listeners;
using Rod.V1;
using Task = System.Threading.Tasks.Task;
using static Rod.Integration.Tests.TestSupport;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: an implant written from the contract doc completes a contact
/// and a task over the raw-TCP listener (architecture.md Sec 8) -- the
/// socket for segment networks that allow sockets but no HTTP shape. It
/// carries the same rod.v1 frames as the envelope in one self-delimited
/// message per direction, through the shared frame paths: a result captured
/// over a socket is indistinguishable in core state, the audit trail, and
/// the live bus from one captured over the WebSocket beacon. The identity is the
/// certificate-less posture -- the implant id in the handshake, the DNS
/// tradeoff extended to a handshake-capable transport -- and dispatched
/// tasking keeps the full Sec 9 signature, verified here the way an implant
/// verifies it.
/// </summary>
public class StreamContactTests
{
    [Fact]
    public async Task Implant_ContactsOverRawTcp_AndCompletesATask()
    {
        var port = TestSupport.GetFreeTcpPort();
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            "test-tcp", "tcp", $"127.0.0.1:{port}", $"10.0.0.5:{port}"));

        await ContactAndCompleteATaskAsync(
            env,
            endpoint: $"10.0.0.5:{port}",
            expectedTransport: "tcp",
            connect: async () =>
            {
                var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, port);
                return client.GetStream();
            });
    }

    // The shared acceptance arc: handshake over the transport, listener
    // listing reflects the entry, a shell.exec task dispatches into a
    // contact response with a verifiable signature, and the reported result
    // completes the task with the standard audit arc.
    private static async Task ContactAndCompleteATaskAsync(
        TestEnv env,
        string endpoint,
        string expectedTransport,
        Func<Task<System.IO.Stream>> connect)
    {
        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        var authority = env.Host.Services.GetRequiredService<IImplantCertificateAuthority>();
        var clock = env.Host.Services.GetRequiredService<TimeProvider>();

        var now = clock.GetUtcNow();
        var engagement = await EngagementSetup.CreateOwnedEngagementAsync(env.Host);
        var implant = Implant.Enroll(
            ImplantId.New(), engagement, now.AddDays(30), ImplantClass.Implant, now);
        await implants.SaveAsync(implant);

        // The listener entry is registered and running, with the endpoint
        // implants dial decoupled from the bind the way every transport's
        // entry is. Read through the registry: these listeners ride the
        // startup configuration, and the engagement-scoped listing does not
        // (and must not) surface that tier. The registration lands with the
        // socket bind, so wait for it rather than racing the host's start.
        var registry = env.Host.Services.GetRequiredService<IListenerRegistry>();
        Listener? entry = null;
        await WaitUntilAsync(async () =>
        {
            entry = (await registry.ListAsync()).SingleOrDefault(l =>
                string.Equals(l.Transport, expectedTransport, StringComparison.OrdinalIgnoreCase));
            return entry is not null;
        });
        Assert.NotNull(entry);
        Assert.Equal(ListenerState.Running, entry.State);
        Assert.Equal(endpoint, entry.PublicEndpoint);
        await AuthenticatedHost.LoginAsync(env.Http);

        // Contact one: the handshake opens the session. The implant
        // advertises the replay-nonce arm like the reference implant, and the
        // response echoes it.
        var opened = await ContactAsync(connect, Handshake(implant));
        var openedResponse = HandshakeResponse.Parser.ParseFrom(opened[0].Payload);
        Assert.Equal(HandshakeStatus.Ok, openedResponse.Status);
        Assert.True(openedResponse.ReplayNonces);
        Assert.Single(opened);

        // The operator tasks the implant over the API like any other.
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "id" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();
        Assert.NotNull(issuedBody);

        // Contact two: the handshake refreshes the session and the queued
        // task rides the response. The tasking is signed by the CA -- an
        // implant verifies it exactly like a stream-delivered task, the
        // signature posture is the transport-independent half.
        var dispatched = await ContactAsync(connect, Handshake(implant));
        var dispatchedResponse = HandshakeResponse.Parser.ParseFrom(dispatched[0].Payload);
        Assert.Equal(HandshakeStatus.Ok, dispatchedResponse.Status);
        Assert.Equal(2, dispatched.Count);
        var request = TaskRequest.Parser.ParseFrom(dispatched[1].Payload);
        Assert.Equal(issuedBody!.TaskId, request.TaskId);
        Assert.Equal("shell.exec", request.Verb);
        Assert.Equal("id", request.Arguments);

        using var ca = authority.GetCaCertificate();
        using var publicKey = ca.GetRSAPublicKey()!;
        var nonce = request.TaskNonce == 0 ? null : (ulong?)request.TaskNonce;
        Assert.True(publicKey.VerifyData(
            TaskingCanonical.Bytes(implant.Id.ToString(), request.TaskId, request.Verb, request.Arguments, nonce),
            request.Signature.ToByteArray(),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));

        // Contact three: the implant reports the result and the task
        // completes with the standard audit arc -- indistinguishable from a
        // stream-delivered task in the trail.
        var reported = await ContactAsync(
            connect,
            Handshake(implant),
            new Frame
            {
                Payload = ByteString.CopyFrom(new TaskResult
                {
                    TaskId = request.TaskId,
                    Outcome = TaskOutcome.Succeeded,
                    Output = "uid=0",
                }.ToByteArray()),
                Kind = FrameKind.TaskResult,
            });
        var reportedResponse = HandshakeResponse.Parser.ParseFrom(reported[0].Payload);
        Assert.Equal(HandshakeStatus.Ok, reportedResponse.Status);

        await WaitUntilAsync(async () =>
            (await env.Http.GetFromJsonAsync<TaskBody>(
                $"/engagements/{implant.EngagementId}/tasks/{request.TaskId}"))!.Status == "Completed");

        var fetched = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{request.TaskId}");
        Assert.NotNull(fetched);
        Assert.Equal("Succeeded", fetched!.Outcome);
        Assert.Equal("uid=0", fetched.Output);
        Assert.Equal(
            new[] { "TaskIssued", "TaskDispatched", "TaskCompleted" },
            fetched.Audit.Select(e => e.Kind).ToArray());
    }

    // The download arm's cross-message budget (ADR-010's download half): a
    // staged payload larger than one response body is served as budgeted
    // slices that span contacts through the resume discipline -- the mirror
    // of the upload arm's per-contact slicing. A demand's answer ends short
    // of terminal at the budget, the next demand proves its held bytes, and
    // the run completes from the seam. The wire stays honest throughout:
    // every response message fits the envelope body cap, so no carriage's
    // read budget is ever asked to exceed it.
    [Fact]
    public async Task StagedDownload_PastTheBodyBudget_SpansContactsThroughResume()
    {
        // 10 MiB: past the 6 MiB per-contact run budget (two contacts) and
        // past the raw-TCP client's former 8 MiB read cap in the unsplit
        // shape -- the regression this test pins.
        var content = RandomNumberGenerator.GetBytes(10 * 1024 * 1024);
        var expectedHash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

        var port = TestSupport.GetFreeTcpPort();
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            "test-tcp", "tcp", $"127.0.0.1:{port}", $"10.0.0.5:{port}"));

        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        var registry = env.Host.Services.GetRequiredService<IListenerRegistry>();
        await WaitUntilAsync(async () =>
            (await registry.ListAsync()).Any(l => l.Transport == "tcp" && l.State == ListenerState.Running));

        var now = env.Host.Services.GetRequiredService<TimeProvider>().GetUtcNow();
        var engagement = await EngagementSetup.CreateOwnedEngagementAsync(env.Host);
        var implant = Implant.Enroll(
            ImplantId.New(), engagement, now.AddDays(30), ImplantClass.Implant, now);
        await implants.SaveAsync(implant);
        await AuthenticatedHost.LoginAsync(env.Http);

        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "file.push", Arguments = "/tmp/rod-span", Content = content });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();
        Assert.NotNull(issuedBody);

        async Task<System.IO.Stream> Connect()
        {
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            return client.GetStream();
        }

        // The task arrives marked staged on the first contact that claims it.
        var claimed = await ContactAsync(Connect, Handshake(implant, "file.push"));
        Assert.Equal(HandshakeStatus.Ok, HandshakeResponse.Parser.ParseFrom(claimed[0].Payload).Status);
        var request = TaskRequest.Parser.ParseFrom(claimed[1].Payload);
        Assert.Equal(issuedBody!.TaskId, request.TaskId);
        Assert.True(request.HasStagedBytes);
        Assert.Equal((ulong)content.Length, request.StagedBytes);

        // The first demand's answer carries the budgeted slice -- the 6 MiB
        // per-contact run budget at the 512 KiB chunk cut -- and ends short
        // of terminal: the run spans contacts from here.
        var (firstRun, _) = await DemandAsync(Connect, implant, request.TaskId, offset: null, prefix: null);
        Assert.Equal(12, firstRun.Count);
        Assert.Equal(6 * 1024 * 1024, firstRun.Sum(c => c.Data.Length));
        Assert.All(firstRun, c => Assert.False(c.Terminal));

        var held = new List<byte>(6 * 1024 * 1024);
        foreach (var chunk in firstRun)
            held.AddRange(chunk.Data);

        // Contacts onward: demand from the proven seam until the terminal
        // chunk lands. Every response message stays under the body cap.
        StagedChunk last;
        do
        {
            var (run, _) = await DemandAsync(
                Connect, implant, request.TaskId,
                offset: (ulong)held.Count, prefix: SHA256.HashData(held.ToArray()));
            Assert.Equal((ulong)held.Count, run[0].Offset);
            foreach (var chunk in run)
                held.AddRange(chunk.Data);
            last = run[^1];
        } while (!last.Terminal);

        // 10 MiB crossed in budgeted slices -- more than one contact's
        // share -- and the reassembled bytes are the staged artifact.
        Assert.Equal(content.Length, held.Count);
        Assert.Equal(content, held.ToArray());

        // The completing result carries the payload hash: the both-side arm
        // records Succeeded only when the served bytes match the held ones.
        await ContactAsync(
            Connect,
            Handshake(implant, "file.push"),
            new Frame
            {
                Payload = ByteString.CopyFrom(new TaskResult
                {
                    TaskId = request.TaskId,
                    Outcome = TaskOutcome.Succeeded,
                    Output = $"/tmp/rod-span: {content.Length} bytes written",
                    PayloadSha256 = expectedHash,
                }.ToByteArray()),
                Kind = FrameKind.TaskResult,
            });

        TaskBody? fetched = null;
        await WaitUntilAsync(async () => (fetched = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{request.TaskId}")) is { Status: "Completed" });
        Assert.NotNull(fetched);
        Assert.Equal("Succeeded", fetched!.Outcome);
    }

    // One staged demand contact: the request message carries the handshake
    // and the pull at its seam; the response's chunk run drains whole, and
    // the raw body length is asserted against the envelope cap every time.
    private static async Task<(List<StagedChunk> Run, byte[] Body)> DemandAsync(
        Func<Task<System.IO.Stream>> connect,
        Implant implant,
        string taskId,
        ulong? offset,
        byte[]? prefix)
    {
        var pull = new StagedPull { TaskId = taskId };
        if (offset is { } at)
        {
            pull.Offset = at;
            pull.PrefixSha256 = ByteString.CopyFrom(prefix!);
        }
        using var stream = await connect();
        await WriteMessageAsync(stream, EncodeFrames(new[]
        {
            Handshake(implant, "file.push"),
            new Frame
            {
                Payload = ByteString.CopyFrom(pull.ToByteArray()),
                Kind = FrameKind.StagedPull,
            },
        }));
        var body = await ReadMessageAsync(stream);
        Assert.True(body.Length < 16 * 1024 * 1024, $"response body {body.Length} exceeds the envelope cap");
        var frames = ParseFrames(body);
        Assert.Equal(HandshakeStatus.Ok, HandshakeResponse.Parser.ParseFrom(frames[0].Payload).Status);
        var run = frames.Skip(1)
            .Select(f => StagedChunk.Parser.ParseFrom(f.Payload))
            .ToList();
        Assert.NotEmpty(run);
        return (run, body);
    }

    // One contact: connect, send the request message (the handshake frame
    // first, then any upstream frames), read the response message, close.
    // One connection is one poll contact -- the cadence every stream
    // listener serves.
    private static async Task<List<Frame>> ContactAsync(
        Func<Task<System.IO.Stream>> connect, params Frame[] upstream)
    {
        using var stream = await connect();
        await WriteMessageAsync(stream, EncodeFrames(upstream));
        var body = await ReadMessageAsync(stream);
        return ParseFrames(body);
    }

    private static Frame Handshake(Implant implant, params string[] capabilities)
    {
        var request = new HandshakeRequest
        {
            Version = new ProtocolVersion { Major = 1, Minor = 0 },
            ImplantId = implant.Id.ToString(),
            ReplayNonces = true,
        };
        if (capabilities.Length == 0)
            request.Capabilities.Add("shell.exec");
        else
            request.Capabilities.Add(capabilities);
        return new Frame { Payload = ByteString.CopyFrom(request.ToByteArray()) };
    }

    // --- The wire codec, written from the contract doc (extending/implants.md):
    // one message each way -- a varint byte length, then that many bytes of
    // varint-length-delimited Frames (the envelope's body shape).

    private static async Task<byte[]> ReadMessageAsync(System.IO.Stream stream)
    {
        long length = 0;
        var shift = 0;
        while (true)
        {
            var one = new byte[1];
            if (await stream.ReadAsync(one) <= 0)
                throw new EndOfStreamException();
            length |= (long)(one[0] & 0x7f) << shift;
            if ((one[0] & 0x80) == 0)
                break;
            shift += 7;
        }

        var body = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await stream.ReadAsync(body.AsMemory(offset));
            if (read <= 0)
                throw new EndOfStreamException();
            offset += read;
        }
        return body;
    }

    private static async Task WriteMessageAsync(System.IO.Stream stream, byte[] body)
    {
        var prefix = new byte[5];
        var value = (ulong)body.Length;
        var index = 0;
        while (value >= 0x80)
        {
            prefix[index++] = (byte)(value | 0x80);
            value >>= 7;
        }
        prefix[index++] = (byte)value;

        await stream.WriteAsync(prefix.AsMemory(0, index));
        await stream.WriteAsync(body);
        await stream.FlushAsync();
    }

    private static byte[] EncodeFrames(IReadOnlyList<Frame> frames)
    {
        using var buffer = new MemoryStream();
        foreach (var frame in frames)
        {
            var payload = frame.ToByteArray();
            WriteVarint(buffer, (ulong)payload.Length);
            buffer.Write(payload);
        }
        return buffer.ToArray();
    }

    private static List<Frame> ParseFrames(byte[] body)
    {
        var frames = new List<Frame>();
        var offset = 0;
        while (offset < body.Length)
        {
            var length = 0UL;
            var shift = 0;
            while (true)
            {
                var b = body[offset++];
                length |= (ulong)(b & 0x7f) << shift;
                if ((b & 0x80) == 0)
                    break;
                shift += 7;
            }
            frames.Add(Frame.Parser.ParseFrom(body.AsSpan((int)offset, (int)length).ToArray()));
            offset += (int)length;
        }
        return frames;
    }

    private static void WriteVarint(MemoryStream buffer, ulong value)
    {
        while (value >= 0x80)
        {
            buffer.WriteByte((byte)(value | 0x80));
            value >>= 7;
        }
        buffer.WriteByte((byte)value);
    }

    private sealed class TaskIssuedBody
    {
        public string TaskId { get; set; } = "";
    }

    private sealed class TaskBody
    {
        public string Status { get; set; } = "";
        public string? Output { get; set; }
        public string? Outcome { get; set; }
        public AuditBody[] Audit { get; set; } = Array.Empty<AuditBody>();
    }

    private sealed class AuditBody
    {
        public string Kind { get; set; } = "";
    }

    private sealed class ListenerBody
    {
        public string Transport { get; set; } = "";
        public string State { get; set; } = "";
        public string PublicEndpoint { get; set; } = "";
    }

    /// <summary>
    /// A real Kestrel teamserver serving the operator API, plus one stream
    /// listener entry (named pipe or raw TCP) owned by its hosted service.
    /// Mirrors the DNS listener harness.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;
        public int HttpPort { get; private set; }

        public static async Task<TestEnv> StartAsync(ListenerConfig streamListener)
        {
            var env = new TestEnv();
            env.HttpPort = TestSupport.GetFreeTcpPort();

            var config = AuthenticatedHost.BuildConfig();
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
                    .UseRodListeners(new List<ListenerConfig> { streamListener })
                    .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(env.HttpPort)))
                .Build();
            await env.Host.StartAsync();

            env.Http = new HttpClient(new CookieHandler(new HttpClientHandler()))
            {
                BaseAddress = new Uri($"http://127.0.0.1:{env.HttpPort}"),
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
