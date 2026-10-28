using System.Net;
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
using Rod.CoreState.Operators;
using Rod.CoreState.Pki;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.V1;
using static Rod.Integration.Tests.EngagementSetup;
using static Rod.Integration.Tests.TestSupport;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: every per-engagement action produces an attributed,
/// immutable event in the engagement trail (architecture.md Sec 11). Drives the
/// full operational lifecycle -- engagement created, deploy token minted, implant
/// enrolled, session opened, task issued/dispatched/completed, payload built,
/// implant retired -- and asserts each landed as an attributed, hash-chained
/// event on the per-engagement trail, readable through the audit endpoint. The
/// chain verifies end to end (tamper-evidence by construction). Every operator
/// action is attributed to the authenticated operator; with a single seeded
/// operator the owner, the task issuer, the builder, and the retireer are the
/// same identity, recorded by the server off the session principal.
/// </summary>
public class OperationalEventLogTests
{
    [Fact]
    public async Task EveryAction_ProducesAnAttributedImmutableEvent()
    {
        await using var env = await TestEnv.StartAsync();
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        await AuthenticatedHost.LoginAsync(env.Http);

        // The single seeded operator is every actor in this lifecycle -- the
        // server records that identity off the session, not the request body.
        var owner = env.OperatorId;

        // 1. Engagement created -> EngagementCreated (genesis link).
        var created = await env.Http.PostAsJsonAsync("/engagements",
            new EngagementEndpoints.CreateEngagementRequest(Name: "Operation Smokeshow"));
        created.EnsureSuccessStatusCode();
        var engagement = await created.Content.ReadFromJsonAsync<EngagementEndpoints.EngagementResponse>();
        var engagementId = Guid.Parse(engagement!.EngagementId);

        // 2. Deploy token minted -> DeployTokenMinted.
        var minted = await env.Http.PostAsync($"/engagements/{engagementId}/deploy-tokens", content: null);
        minted.EnsureSuccessStatusCode();
        var token = await minted.Content.ReadFromJsonAsync<EngagementEndpoints.DeployTokenResponse>();
        Assert.Equal(owner.Value, Guid.Parse(token!.IssuedBy));

        // 3. Implant enrolled (implant-initiated, attributed to the token issuer)
        //    -> ImplantEnrolled. The engagement binding is checked by the trail
        //    assertions below (the ImplantEnrolled/SessionOpened events carry the
        //    engagement id the token resolved to).
        var implantId = await EnrollImplantAsync(env.Http, token.Secret);

        // 4. Session opened over the beacon stream -> SessionOpened, plus a task's
        //    issued/dispatched/completed arc -> TaskIssued, TaskDispatched,
        //    TaskCompleted. The token issuer deployed the implant, so the
        //    implant-initiated events attribute to that operator.
        using var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implantId);
        Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);

        var taskIssuer = env.OperatorId;
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/tasks",
            new { ImplantId = implantId, Verb = "shell.exec", Arguments = "whoami" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var request = TaskRequest.Parser.ParseFrom(await beacon.ReceiveSingleFrameAsync());

        await beacon.SendFramesAsync(new[] { ResultFrame(new TaskResult
        {
            TaskId = request.TaskId,
            Outcome = TaskOutcome.Succeeded,
            Output = "red-team\\operator",
        }) });

        // Wait for the completion to land on the trail before readback.
        await WaitUntilAsync(async () => (await audit.ForTaskAsync(Guid.Parse(request.TaskId))).Count == 3);

        // 5. Payload built -> PayloadBuilt.
        var front = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "build-front", Transport: "tcp",
                BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
                PublicEndpoint: "c2.example.test:443"));
        front.EnsureSuccessStatusCode();
        var frontId = (await front.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>())!.Id;
        var build = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Unit: null,
                Class: null,
                TargetOs: "linux",
                TargetArch: "amd64",
                ListenerId: frontId,
                UriPath: "/beacon",
                SleepSeconds: 30,
                JitterSeconds: 10,
                KillDate: null));
        build.EnsureSuccessStatusCode();

        // 6. Implant retired -> ImplantRetired.
        var retire = await env.Http.PostAsync(
            $"/engagements/{engagementId}/implants/{implantId}:retire",
            content: null);
        Assert.Equal(HttpStatusCode.OK, retire.StatusCode);

        // --- Read the whole trail back through the per-engagement audit endpoint
        //     and assert every action produced an attributed event, in order, and
        //     the hash chain verifies. ---
        var trailResponse = await env.Http.GetFromJsonAsync<AuditEndpoints.AuditListResponse>(
            $"/engagements/{engagementId}/audit");
        Assert.NotNull(trailResponse);

        // A build mints and bakes its own enrollment credential, so this walk's
        // trail carries two DeployTokenMinted facts -- the manual mint and the
        // baked one. The readback keys by first-of-kind and the baked shape is
        // asserted explicitly below.
        var byKind = trailResponse!.Items
            .GroupBy(e => e.Kind)
            .ToDictionary(g => g.Key, g => g.First());
        // Every lifecycle kind is present.
        Assert.Contains("EngagementCreated", byKind.Keys);
        Assert.Contains("DeployTokenMinted", byKind.Keys);
        Assert.Contains("ImplantEnrolled", byKind.Keys);
        Assert.Contains("SessionOpened", byKind.Keys);
        Assert.Contains("TaskIssued", byKind.Keys);
        Assert.Contains("TaskDispatched", byKind.Keys);
        Assert.Contains("TaskCompleted", byKind.Keys);
        Assert.Contains("PayloadBuilt", byKind.Keys);
        Assert.Contains("ImplantRetired", byKind.Keys);

        // The build's minted credential is on the trail with the baked shape
        // named, attributed to the owner (who authorizes the deployment
        // channel) while the build fact attributes to its requester.
        var mints = trailResponse.Items.Where(e => e.Kind == "DeployTokenMinted").ToArray();
        Assert.Equal(2, mints.Length);
        Assert.Contains(mints, e => e.Payload.Contains("bakedIntoPayload"));
        Assert.All(mints, e => Assert.Equal(owner.Value, e.OperatorId));

        // Each event carries the correct attribution.
        Assert.Equal(owner.Value, byKind["EngagementCreated"].OperatorId);
        Assert.Equal(owner.Value, byKind["DeployTokenMinted"].OperatorId);
        // The build fact attributes to the requesting operator (the owner
        // here); the baked mint's attribution is asserted above with the mints.
        Assert.Equal(owner.Value, byKind["PayloadBuilt"].OperatorId);
        // Enrollment is implant-initiated -> attributed to the token issuer (owner).
        Assert.Equal(owner.Value, byKind["ImplantEnrolled"].OperatorId);
        Assert.Equal(Guid.Parse(implantId), byKind["ImplantEnrolled"].ImplantId);
        // Session open attributes to the deploying operator (owner).
        Assert.Equal(owner.Value, byKind["SessionOpened"].OperatorId);
        Assert.Equal(Guid.Parse(implantId), byKind["SessionOpened"].ImplantId);
        // Task issued by taskIssuer; dispatched to the implant; completed.
        Assert.Equal(taskIssuer.Value, byKind["TaskIssued"].OperatorId);
        Assert.Equal(taskIssuer.Value, byKind["TaskDispatched"].OperatorId);
        Assert.Equal(taskIssuer.Value, byKind["TaskCompleted"].OperatorId);
        Assert.Equal(Guid.Parse(issuedBody!.TaskId), byKind["TaskIssued"].TaskId);
        // Retirement attributes to the retiring operator (owner).
        Assert.Equal(owner.Value, byKind["ImplantRetired"].OperatorId);

        // The trail is ordered oldest-first and the hash chain verifies -- no
        // tampering, no gaps (the append-only, tamper-evident contract).
        var trail = await audit.ListAsync(engagementId);
        Assert.Null(AuditChain.VerifyTrail(trail));
        Assert.Equal(trail.Select(e => e.EventId), trail.OrderBy(e => e.At).Select(e => e.EventId));

        // Cross-engagement isolation: a foreign engagement id is concealed
        // like a missing one (architecture.md Sec 3) -- the route answers
        // the same 404 whether the engagement is absent or merely hidden.
        var foreign = await env.Http.GetAsync($"/engagements/{Guid.NewGuid()}/audit");
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
    }

    [Fact]
    public async Task AuditEndpoint_Returns400_ForMalformedEngagementId()
    {
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var response = await env.Http.GetAsync($"/engagements/not-a-guid/audit");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static Frame HandshakeFrame(string implantId, int major, int minor)
    {
        var request = new HandshakeRequest
        {
            Version = new ProtocolVersion { Major = major, Minor = minor },
            ImplantId = implantId,
            Capabilities = { "shell.exec" },
        };
        return new Frame { Payload = ByteString.CopyFrom(request.ToByteArray()) };
    }

    private static Frame ResultFrame(TaskResult result)
        => new() { Payload = ByteString.CopyFrom(result.ToByteArray()) };

    private static HandshakeResponse ParseResponse(Frame frame)
        => HandshakeResponse.Parser.ParseFrom(frame.Payload);

    [Fact]
    public async Task AuditListing_ResolvesTheActingOperatorToAHandle()
    {
        // The operator reads the trail to see who acted; a bare guid cannot
        // be mapped back to an account without another query. The listing
        // resolves each event's operator to their handle ("system" for the
        // unattributed events), the same enrichment the timeline applies.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var created = await client.PostAsJsonAsync("/engagements",
                new EngagementEndpoints.CreateEngagementRequest(Name: "Operation Handlebar"));
            created.EnsureSuccessStatusCode();
            var engagement = await created.Content.ReadFromJsonAsync<EngagementEndpoints.EngagementResponse>();

            var page = await client.GetFromJsonAsync<AuditEndpoints.AuditListResponse>(
                $"/engagements/{engagement!.EngagementId}/audit");
            Assert.NotNull(page);
            var genesis = Assert.Single(page!.Items, e => e.Kind == nameof(AuditEventKind.EngagementCreated));
            Assert.Equal(AuthenticatedHost.Handle, genesis.OperatorHandle);
        }
    }

    private sealed class TaskIssuedBody
    {
        public string TaskId { get; set; } = "";
        public string Verb { get; set; } = "";
    }

    /// <summary>
    /// A real Kestrel teamserver with the implant endpoint bound, plus a
    /// plain-HTTP operator API. Mirrors the TaskRoundTripTests harness. The
    /// operator + auth layers are composed so the API requires a cookie session.
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
