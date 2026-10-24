using System.Net.Http.Json;
using Google.Protobuf;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.V1;
using static Rod.Integration.Tests.TestSupport;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: task an implant, see its output, and an audit event.
/// Drives the full slice end to end through a real Kestrel endpoint -- the
/// operator POSTs a <c>shell.exec</c> task over HTTP, the WebSocket beacon
/// pushes it to the implant, the implant writes back a result, and the
/// operator reads the captured output alongside the audit event the capture
/// appended. The task state lives in core, the audit event in the audit
/// layer, and the beacon stream is where both meet on a completed task
/// (architecture.md Sec 10.3/11).
/// </summary>
public class TaskRoundTripTests
{
    [Fact]
    public async Task ShellExec_Task_RoundTrips_AndIsAudited()
    {
        await using var env = await TestEnv.StartAsync();
        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        var clock = env.Host.Services.GetRequiredService<TimeProvider>();

        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        // Open the beacon stream and complete the handshake first.
        using var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);

        // Operator tasks the implant over HTTP. The operator session is the gate;
        // the issuer is the logged-in operator, not a body field.
        await AuthenticatedHost.LoginAsync(env.Http);
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "whoami" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();
        Assert.NotNull(issuedBody);
        Assert.Equal("shell.exec", issuedBody!.Verb);

        // The server pushes the task downstream; the implant reads it.
        var request = TaskRequest.Parser.ParseFrom(await beacon.ReceiveSingleFrameAsync());
        Assert.Equal(issuedBody.TaskId, request.TaskId);
        Assert.Equal("shell.exec", request.Verb);
        Assert.Equal("whoami", request.Arguments);

        // The implant runs the verb and writes back a result.
        var result = new TaskResult
        {
            TaskId = request.TaskId,
            Outcome = TaskOutcome.Succeeded,
            Output = "red-team\\operator",
        };
        await beacon.SendFramesAsync(new[] { ResultFrame(result) });

        // Give the server a beat to capture the result and append the audit event
        // (both happen on the stream thread before the next dispatch round). A
        // task now produces a three-event arc: TaskIssued, TaskDispatched,
        // TaskCompleted, so wait for all three before readback.
        await WaitUntilAsync(async () => (await audit.ForTaskAsync(Guid.Parse(request.TaskId))).Count == 3);

        // The operator reads the task back: captured output plus the task's audit
        // arc -- issued, dispatched, then completed (architecture.md Sec 11).
        var fetched = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{request.TaskId}");
        Assert.NotNull(fetched);
        Assert.Equal("Completed", fetched!.Status);
        Assert.Equal("red-team\\operator", fetched.Output);
        Assert.Equal("Succeeded", fetched.Outcome);
        Assert.Equal(3, fetched.Audit.Length);
        Assert.Equal("TaskIssued", fetched.Audit[0].Kind);
        Assert.Equal("TaskDispatched", fetched.Audit[1].Kind);
        Assert.Equal("TaskCompleted", fetched.Audit[2].Kind);
        Assert.Equal("shell.exec", fetched.Audit[2].Verb);
        Assert.Equal("whoami", fetched.Audit[2].Payload);
        Assert.Equal("red-team\\operator", fetched.Audit[2].Output);
        Assert.Equal("Succeeded", fetched.Audit[2].Outcome);

        // The engagement trail now carries the handshake, the three task events,
        // and (in other scenarios) more -- it is no longer a single entry. The
        // full-lifecycle trail is asserted in OperationalEventLogTests.
        var trail = await audit.ListAsync(implant.EngagementId.Value);
        Assert.Contains(trail, e => e.Kind == AuditEventKind.TaskCompleted);
        // The task arc is attributed to the authenticated operator, not any
        // client-supplied identity.
        Assert.Contains(trail, e => e.Kind == AuditEventKind.TaskIssued && e.OperatorId == env.OperatorId.Value);
    }

    [Fact]
    public async Task TaskReads_NameTheIssuingOperatorByHandle()
    {
        await using var env = await TestEnv.StartAsync();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        // A queued task is enough -- the reads under test are the listings
        // and the detail, not the completion arc.
        await AuthenticatedHost.LoginAsync(env.Http);
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "whoami" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();
        Assert.NotNull(issuedBody);

        // The engagement-wide listing, the per-implant listing, and the
        // detail agree: the row names the issuing operator by handle,
        // resolved on the read -- the member role cannot walk the operator
        // roster to do it client-side.
        var engagementPage = await env.Http.GetFromJsonAsync<TaskEndpoints.TaskListResponse>(
            $"/engagements/{implant.EngagementId}/tasks");
        var engagementRow = Assert.Single(engagementPage!.Items, t => t.TaskId == issuedBody!.TaskId);
        Assert.Equal(AuthenticatedHost.Handle, engagementRow.IssuedByHandle);

        var implantPage = await env.Http.GetFromJsonAsync<TaskEndpoints.TaskListResponse>(
            $"/engagements/{implant.EngagementId}/implants/{implant.Id}/tasks");
        var implantRow = Assert.Single(implantPage!.Items, t => t.TaskId == issuedBody.TaskId);
        Assert.Equal(AuthenticatedHost.Handle, implantRow.IssuedByHandle);

        var detail = await env.Http.GetFromJsonAsync<TaskEndpoints.TaskResponse>(
            $"/engagements/{implant.EngagementId}/tasks/{issuedBody.TaskId}");
        Assert.Equal(AuthenticatedHost.Handle, detail!.IssuedByHandle);

        // A member beside the engagement's lead: the reads must name whoever
        // actually issued the task, not the session that opened the
        // engagement, and the member's own session resolves the same way.
        await AuthenticatedHost.RegisterOperatorAsync(env.Host, "runner", "runner-p@ss!");
        var added = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/members", new { handle = "runner", role = "writer" });
        added.EnsureSuccessStatusCode();

        // A real-socket client for the member's own session, the same shape
        // the env's lead client takes.
        var member = new HttpClient(new CookieHandler(new HttpClientHandler()))
        {
            BaseAddress = new Uri($"http://127.0.0.1:{env.HttpPort}"),
        };
        using (member)
        {
            await AuthenticatedHost.LoginAsync(member, "runner", "runner-p@ss!");
            var memberIssued = await member.PostAsJsonAsync(
                $"/engagements/{implant.EngagementId}/tasks",
                new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "id" });
            memberIssued.EnsureSuccessStatusCode();
            var memberBody = await memberIssued.Content.ReadFromJsonAsync<TaskIssuedBody>();
            Assert.NotNull(memberBody);

            var memberPage = await member.GetFromJsonAsync<TaskEndpoints.TaskListResponse>(
                $"/engagements/{implant.EngagementId}/tasks");
            Assert.Equal("runner",
                Assert.Single(memberPage!.Items, t => t.TaskId == memberBody!.TaskId).IssuedByHandle);
        }
    }

    [Fact]
    public async Task RetransmittedResult_IsIgnored_AndTheStreamStaysOpen()
    {
        await using var env = await TestEnv.StartAsync();
        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        var clock = env.Host.Services.GetRequiredService<TimeProvider>();

        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        using var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);

        await AuthenticatedHost.LoginAsync(env.Http);
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "id" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var request = TaskRequest.Parser.ParseFrom(await beacon.ReceiveSingleFrameAsync());

        // The implant's result arrives twice (a retransmission after a drop):
        // the first capture completes the task, the second must be ignored, not
        // tear the session down.
        var result = new TaskResult
        {
            TaskId = request.TaskId,
            Outcome = TaskOutcome.Succeeded,
            Output = "uid=0",
        };
        await beacon.SendFramesAsync(new[] { ResultFrame(result) });
        await beacon.SendFramesAsync(new[] { ResultFrame(result) });

        await WaitUntilAsync(async () => (await audit.ForTaskAsync(Guid.Parse(request.TaskId))).Count == 3);

        // The duplicate produced no second TaskCompleted event, and the stream is
        // still alive: the next issued task is dispatched downstream.
        Assert.Equal(1, (await audit.ForTaskAsync(Guid.Parse(request.TaskId))).Count(e => e.Kind == AuditEventKind.TaskCompleted));

        var secondIssued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "id -u" });
        secondIssued.EnsureSuccessStatusCode();
        var secondBody = await secondIssued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var secondRequest = TaskRequest.Parser.ParseFrom(await beacon.ReceiveSingleFrameAsync());
        Assert.Equal(secondBody!.TaskId, secondRequest.TaskId);
    }

    [Fact]
    public async Task ForeignImplantResult_ForAnotherEngagementsTask_IsIgnored()
    {
        await using var env = await TestEnv.StartAsync();
        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        var clock = env.Host.Services.GetRequiredService<TimeProvider>();

        // Two implants in two engagements. The victim holds the task; the
        // impostor is a fully authenticated session of its own -- the strongest
        // position a forged result can come from.
        var victim = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);
        var impostor = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        using var victimBeacon = await WsBeaconClient.ConnectAsync(env.HttpPort, victim.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await victimBeacon.ReceiveHandshakeAsync()).Status);
        using var impostorBeacon = await WsBeaconClient.ConnectAsync(env.HttpPort, impostor.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await impostorBeacon.ReceiveHandshakeAsync()).Status);

        // The operator tasks the victim; the victim's stream claims the task
        // (it is now Dispatched to the victim).
        await AuthenticatedHost.LoginAsync(env.Http);
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{victim.EngagementId}/tasks",
            new { ImplantId = victim.Id.ToString(), Verb = "shell.exec", Arguments = "whoami" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var request = TaskRequest.Parser.ParseFrom(await victimBeacon.ReceiveSingleFrameAsync());
        Assert.Equal(issuedBody!.TaskId, request.TaskId);

        // The impostor answers first with a forged result for the victim's task
        // id. Ownership must hold on the result path the way it already holds
        // on exfil, staged-pull, and channel output: a session can only
        // complete its own (or a fronted Pivot child's) task, never another
        // engagement's.
        await impostorBeacon.SendFramesAsync(new[]
        {
            ResultFrame(new TaskResult
            {
                TaskId = request.TaskId,
                Outcome = TaskOutcome.Succeeded,
                Output = "forged",
            }),
        });

        // The victim's real answer follows immediately: whichever frame the
        // server processes first, only the victim's may complete the task, so
        // the final record discriminates the guard without racing the stream.
        await victimBeacon.SendFramesAsync(new[]
        {
            ResultFrame(new TaskResult
            {
                TaskId = request.TaskId,
                Outcome = TaskOutcome.Succeeded,
                Output = "uid=0",
            }),
        });

        await WaitUntilAsync(async () => (await audit.ForTaskAsync(Guid.Parse(request.TaskId))).Count == 3);

        var fetched = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{victim.EngagementId}/tasks/{request.TaskId}");
        Assert.NotNull(fetched);
        Assert.Equal("Completed", fetched!.Status);
        Assert.Equal("uid=0", fetched.Output);
        Assert.Equal(1, fetched.Audit.Count(e => e.Kind == "TaskCompleted"));
        Assert.Equal("uid=0", fetched.Audit.Single(e => e.Kind == "TaskCompleted").Output);
    }


    private static Frame ResultFrame(TaskResult result)
        => new() { Payload = ByteString.CopyFrom(result.ToByteArray()) };

    // Polls until condition is true or the timeout elapses. The capture/audit
    // append runs on the stream thread, asynchronously to the HTTP readback, so
    // the readback needs to wait for it rather than race it.

    // Minimal DTOs for the JSON round-trip; the transport owns the wire shape.
    private sealed class TaskIssuedBody
    {
        public string TaskId { get; set; } = "";
        public string Verb { get; set; } = "";
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
        public string Verb { get; set; } = "";
        public string Payload { get; set; } = "";
        public string? Output { get; set; }
        public string Outcome { get; set; } = "";
    }

    /// <summary>
    /// A real Kestrel teamserver with the plain-HTTP operator API and the
    /// WebSocket beacon riding the same listener family.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;
        public OperatorId OperatorId { get; private set; }
        public int HttpPort { get; private set; }

        public static async Task<TestEnv> StartAsync()
        {
            var env = new TestEnv();
            env.HttpPort = TestSupport.GetFreeTcpPort();

            // Compose the operator + auth layers so the operator API requires a
            // cookie session; the operator id is the seeded one, read back from
            // the host.
            var config = AuthenticatedHost.BuildConfig();
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
                    .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(env.HttpPort)))
                .Build();
            await env.Host.StartAsync();
            env.OperatorId = AuthenticatedHost.GetOperatorId(env.Host);

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
