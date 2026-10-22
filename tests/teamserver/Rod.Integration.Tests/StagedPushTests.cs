using System.Net.Http.Json;
using System.Security.Cryptography;
using Google.Protobuf;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Pki;
using Rod.Transport;
using Rod.V1;
using Task = System.Threading.Tasks.Task;
using static Rod.Integration.Tests.TestSupport;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance for staged uploads (architecture.md Sec 10, the per-verb typed
/// arm): a payload too large for the task arguments string is staged as a
/// task-bound artifact at issuance, its sha256 rides the signed arguments, and
/// the implant demands and reassembles the chunk run over the tasking channel
/// -- the mirror of exfil chunking in the other direction. Drives the full
/// slice end to end through a real Kestrel endpoint with a 10 MiB
/// payload: the AC is that the file lands whole on the target through the
/// tasking channel.
/// </summary>
public class StagedPushTests
{
    [Fact]
    public async Task TenMiBUpload_LandsWhole_ThroughTheTaskingChannel()
    {
        var content = RandomNumberGenerator.GetBytes(10 * 1024 * 1024);
        var expectedHash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

        await using var env = await TestEnv.StartAsync();
        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        var clock = env.Host.Services.GetRequiredService<TimeProvider>();

        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        // Open the beacon stream and complete the handshake first.
        using var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);

        // The operator issues the push with the payload as content, not as an
        // arguments string. The target path is the whole argument; the server
        // appends the sha256 token and stages the bytes.
        var targetPath = Path.Combine(Path.GetTempPath(), "rod-staged-" + Guid.NewGuid().ToString("N") + ".bin");
        await AuthenticatedHost.LoginAsync(env.Http);
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "file.push", Arguments = targetPath, Content = content });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();
        Assert.NotNull(issuedBody);
        Assert.EndsWith("sha256:" + expectedHash, issuedBody!.Arguments);

        // The task arrives marked staged: the typed arm's advisory size on the
        // TaskRequest, the binding hash inside the signed arguments.
        using var readDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var request = TaskRequest.Parser.ParseFrom(await beacon.ReceiveSingleFrameAsync());
        Assert.Equal(issuedBody.TaskId, request.TaskId);
        Assert.True(request.HasStagedBytes);
        Assert.Equal((ulong)content.Length, request.StagedBytes);
        Assert.EndsWith("sha256:" + expectedHash, request.Arguments);

        // The implant demands the payload and reassembles the chunk run the
        // server answers with -- 10 MiB at the 512 KiB chunk budget is twenty
        // chunks, terminal on the last.
        await beacon.SendFramesAsync(new[] { new Frame
        {
            Payload = ByteString.CopyFrom(new StagedPull { TaskId = request.TaskId }.ToByteArray()),
            Kind = FrameKind.StagedPull,
        } });

        var payload = new List<byte>();
        StagedChunk chunk;
        do
        {
            chunk = StagedChunk.Parser.ParseFrom(await beacon.ReceiveSingleFrameAsync());
            Assert.Equal(request.TaskId, chunk.TaskId);
            payload.AddRange(chunk.Data);
        } while (!chunk.Terminal);

        Assert.Equal(content.Length, payload.Count);
        Assert.Equal(content, payload.ToArray());

        // The implant reports the write; the task completes and the trail
        // carries the full arc plus the staged artifact's attach.
        await beacon.SendFramesAsync(new[] { ResultFrame(request.TaskId,
            $"wrote {content.Length} bytes to {targetPath}") });

        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        await WaitUntilAsync(async () =>
            (await audit.ForTaskAsync(Guid.Parse(request.TaskId))).Count == 4);

        var fetched = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{request.TaskId}");
        Assert.NotNull(fetched);
        Assert.Equal("Completed", fetched!.Status);
        Assert.Equal("Succeeded", fetched.Outcome);
        Assert.Equal(4, fetched.Audit.Length);
        Assert.Contains(fetched.Audit, e => e.Kind == nameof(AuditEventKind.ArtifactAttached));

        var artifacts = await env.Http.GetFromJsonAsync<ArtifactListBody>(
            $"/engagements/{implant.EngagementId}/tasks/{request.TaskId}/artifacts");
        Assert.NotNull(artifacts);
        var staged = artifacts!.Items.Single(a => a.Name == "staged-" + Guid.Parse(request.TaskId).ToString("N"));
        Assert.Equal(content.Length, staged.Size);
    }


    // The resume arm's acceptance (architecture.md Sec 15.3, ADR-010): a
    // stream that dies mid-run costs the unserved remainder, not the payload
    // -- the reconnect demands from the proven seam -- and the completing
    // result carries the payload hash the server verifies against the
    // artifact it served.
    [Fact]
    public async Task InterruptedRun_ResumesToMatchingBothSideHashes()
    {
        // 1.5 MiB: three chunks at the 512 KiB budget, so a drop after the
        // first chunk leaves a proven seam to resume from.
        var content = RandomNumberGenerator.GetBytes((int)(1.5 * 1024 * 1024));
        var expectedHash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

        await using var env = await TestEnv.StartAsync();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        var targetPath = Path.Combine(Path.GetTempPath(), "rod-staged-" + Guid.NewGuid().ToString("N") + ".bin");
        await AuthenticatedHost.LoginAsync(env.Http);
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "file.push", Arguments = targetPath, Content = content });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        using var first = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await first.ReceiveHandshakeAsync()).Status);

        var request = TaskRequest.Parser.ParseFrom(await first.ReceiveSingleFrameAsync());
        Assert.Equal(issuedBody!.TaskId, request.TaskId);
        Assert.True(request.HasStagedBytes);

        await first.SendFramesAsync(new[] { new Frame
        {
            Payload = ByteString.CopyFrom(new StagedPull { TaskId = request.TaskId }.ToByteArray()),
            Kind = FrameKind.StagedPull,
        } });

        // One chunk crosses before the stream dies: the client holds exactly
        // those bytes, and the rest of the run is lost with the socket.
        var held = StagedChunk.Parser.ParseFrom(await first.ReceiveSingleFrameAsync());
        Assert.Equal(0UL, held.Offset);
        Assert.False(held.Terminal);
        first.Dispose();

        // The reconnect demands from the seam: the held bytes named by
        // offset and proved by hash, on a stream that never saw the task.
        using var resumed = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await resumed.ReceiveHandshakeAsync()).Status);
        await resumed.SendFramesAsync(new[] { new Frame
        {
            Payload = ByteString.CopyFrom(new StagedPull
            {
                TaskId = request.TaskId,
                Offset = (ulong)held.Data.Length,
                PrefixSha256 = ByteString.CopyFrom(SHA256.HashData(held.Data.ToByteArray())),
            }.ToByteArray()),
            Kind = FrameKind.StagedPull,
        } });

        var payload = new List<byte>(held.Data);
        StagedChunk chunk;
        var firstOfRun = true;
        do
        {
            chunk = StagedChunk.Parser.ParseFrom(await resumed.ReceiveSingleFrameAsync());
            Assert.Equal(request.TaskId, chunk.TaskId);
            if (firstOfRun)
            {
                // The run answered from the seam, not the whole payload: its
                // first chunk names the honored offset.
                Assert.Equal((ulong)held.Data.Length, chunk.Offset);
                firstOfRun = false;
            }
            payload.AddRange(chunk.Data);
        } while (!chunk.Terminal);

        var reassembled = payload.ToArray();
        Assert.Equal(content, reassembled);
        Assert.Equal(expectedHash, Convert.ToHexString(SHA256.HashData(reassembled)).ToLowerInvariant());

        // The completing result carries the implant's computed hash: the
        // server verifies it against the artifact it served -- Succeeded
        // means both sides held the same bytes.
        await resumed.SendFramesAsync(new[] { new Frame
        {
            Payload = ByteString.CopyFrom(new TaskResult
            {
                TaskId = request.TaskId,
                Outcome = TaskOutcome.Succeeded,
                Output = $"{targetPath}: {content.Length} bytes written",
                PayloadSha256 = expectedHash,
            }.ToByteArray()),
            Kind = FrameKind.TaskResult,
        } });

        TaskBody? fetched = null;
        await WaitUntilAsync(async () => (fetched = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{request.TaskId}")) is { Status: "Completed" });
        Assert.NotNull(fetched);
        Assert.Equal("Succeeded", fetched!.Outcome);
    }

    // The both-side half's refusal: a staged result claiming a hash the
    // served artifact does not match records the task failed, whatever the
    // outcome byte said.
    [Fact]
    public async Task MismatchedPayloadHash_RecordsTheTaskFailed()
    {
        var content = RandomNumberGenerator.GetBytes(2048);

        await using var env = await TestEnv.StartAsync();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        await AuthenticatedHost.LoginAsync(env.Http);
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "file.push", Arguments = "/tmp/rod-x", Content = content });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        using var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);
        var request = TaskRequest.Parser.ParseFrom(await beacon.ReceiveSingleFrameAsync());
        await beacon.SendFramesAsync(new[] { new Frame
        {
            Payload = ByteString.CopyFrom(new TaskResult
            {
                TaskId = request.TaskId,
                Outcome = TaskOutcome.Succeeded,
                Output = "lying success",
                PayloadSha256 = new string('a', 64),
            }.ToByteArray()),
            Kind = FrameKind.TaskResult,
        } });

        var fetched = default(TaskBody);
        await WaitUntilAsync(async () => (fetched = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{request.TaskId}")) is { Status: "Completed" });
        Assert.NotNull(fetched);
        Assert.Equal("Failed", fetched!.Outcome);
        Assert.Contains("staged payload hash mismatch", fetched.Output);
    }

    private static Frame ResultFrame(string taskId, string output)
        => new()
        {
            Payload = ByteString.CopyFrom(new TaskResult
            {
                TaskId = taskId,
                Outcome = TaskOutcome.Succeeded,
                Output = output,
            }.ToByteArray()),
            Kind = FrameKind.TaskResult,
        };

    // Polls until condition is true or the timeout elapses; the audit append
    // runs on the stream thread, asynchronously to the HTTP readback.

    private sealed class TaskIssuedBody
    {
        public string TaskId { get; set; } = "";
        public string Arguments { get; set; } = "";
    }

    private sealed class TaskBody
    {
        public string TaskId { get; set; } = "";
        public string Status { get; set; } = "";
        public string? Outcome { get; set; }
        public string? Output { get; set; }
        public AuditBody[] Audit { get; set; } = Array.Empty<AuditBody>();
    }

    private sealed class AuditBody
    {
        public string Kind { get; set; } = "";
    }

    private sealed class ArtifactListBody
    {
        public ArtifactBody[] Items { get; set; } = Array.Empty<ArtifactBody>();
    }

    private sealed class ArtifactBody
    {
        public string Name { get; set; } = "";
        public long Size { get; set; }
    }

    /// <summary>
    /// A real Kestrel teamserver with the implant endpoint bound, plus a
    /// plain-HTTP operator API. Mirrors the task round-trip harness.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;
        public int HttpPort { get; private set; }

        public static async Task<TestEnv> StartAsync()
        {
            var env = new TestEnv();
            env.HttpPort = TestSupport.GetFreeTcpPort();

            var config = AuthenticatedHost.BuildConfig();
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
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
