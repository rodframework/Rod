using System.Net;
using System.Net.Sockets;
using System.Text;
using Google.Protobuf;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Implants;
using Rod.CoreState.Engagements;
using Rod.CoreState.Sessions;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;
using Rod.Transport.Listeners.WireGuard;
using Rod.Transport.Payloads;
using Rod.V1;

namespace Rod.Integration.Tests;

// The wireguard transport's acceptance point (architecture.md Sec 8,
// Sec 15.3 ADR-004 as amended): a real hosted listener on a real UDP
// socket, driven by the native test client through the same poll
// discipline the implant's carriage will run -- a handshake exchange,
// then one envelope contact per cycle, the contact body the same frames
// the HTTP envelope route carries. The happy path proves the whole
// carriage: the contact's handshake opens the session, the presence stamp
// records "wireguard" as the carrier, and the answer rides the session
// back. The refusal path proves the conservative half: a stranger's peer
// key never reaches the contact composition at all.

public sealed class WireGuardContactTests
{
    private const string ListenerName = "test-wireguard";
    private const string EnrollListenerName = "test-wireguard-enroll";

    private sealed class WireGuardTestEnv : IAsyncDisposable
    {
        public IHost Host = null!;
        public int Port;
        public WireGuardTunnelRegistry Tunnels = null!;
        public Listener Listener = null!;

        public static async Task<WireGuardTestEnv> StartAsync()
        {
            var env = new WireGuardTestEnv();
            env.Port = FreePort();
            var httpPort = FreePort();

            // The deployment shape the transport ships with: enabled in
            // configuration, the listener's server key provisioned under its
            // name, the native library beside the binaries. The enrollment
            // test's runtime-created entry reads its key from the same
            // section, provisioned ahead of the create the way a deployment
            // provisions it.
            var serverKey = WireGuardTestClient.SeededKey(21);
            var enrollServerKey = WireGuardTestClient.SeededKey(22);
            var config = AuthenticatedHost.BuildConfig(settings =>
            {
                settings["WireGuard:Enabled"] = "true";
                settings[$"WireGuard:ListenerKeys:{ListenerName}"] = Convert.ToBase64String(serverKey);
                settings[$"WireGuard:ListenerKeys:{EnrollListenerName}"] =
                    Convert.ToBase64String(enrollServerKey);
            });

            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
                    .UseRodListeners(new List<ListenerConfig>
                    {
                        new(ListenerName, "wireguard", $"127.0.0.1:{env.Port}", $"127.0.0.1:{env.Port}"),
                    })
                    .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(httpPort)))
                .Build();
            await env.Host.StartAsync();

            env.Tunnels = env.Host.Services.GetRequiredService<WireGuardTunnelRegistry>();
            var listeners = env.Host.Services.GetRequiredService<IListenerRegistry>();

            // The hosted service registers itself once its socket binds --
            // start returning does not wait for that, so poll for it, the
            // same waiting shape the provider's own bind-timeout runs.
            Listener? registered = null;
            for (var attempt = 0; attempt < 50; attempt++)
            {
                registered = (await listeners.ListAsync()).FirstOrDefault(l => l.Name == ListenerName);
                if (registered is not null)
                    break;
                await Task.Delay(100);
            }
            env.Listener = registered ?? throw new TimeoutException("The wireguard listener never registered its socket.");
            return env;
            throw new TimeoutException("The wireguard listener never registered its socket.");
        }

        public async ValueTask DisposeAsync()
        {
            await Host.StopAsync();
            Host.Dispose();
        }
    }

    [Fact]
    public async Task AContactHandshakesAndStampsItsCarrier()
    {
        await using var env = await WireGuardTestEnv.StartAsync();
        using var client = WireGuardTestClient.Seeded(7, WireGuardTestClient.PublicOf(21));
        env.Tunnels.RegisterPeer(env.Listener.Id, client.PublicKey());

        // An enrolled implant the contact will speak for.
        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        var engagementId = await EngagementSetup.CreateOwnedEngagementAsync(env.Host);
        var implant = Implant.Enroll(
            ImplantId.New(), engagementId, DateTimeOffset.UtcNow.AddDays(30),
            ImplantClass.Implant, DateTimeOffset.UtcNow);
        await implants.SaveAsync(implant);

        // The handshake exchange opens the tunnel session.
        var initiation = client.Contact([]);
        var answer = await UdpExchangeAsync(env.Port, initiation);
        client.Receive(answer);

        // One contact: the envelope body of a handshake frame for the
        // enrolled implant, the same frames the HTTP route carries.
        var contact = BuildContact(implant.Id.ToString());
        var datagram = client.Contact(contact);
        var response = await UdpExchangeAsync(env.Port, datagram);
        var payload = client.Receive(response);

        var frames = EnvelopeFraming.Parse(payload);
        var handshake = HandshakeRequest.Parser.ParseFrom(frames[0].Payload);
        Assert.NotEmpty(handshake.ImplantId);

        // The carrier the session records is the wireguard stamp, and the
        // session stands active for the implant.
        var sessions = env.Host.Services.GetRequiredService<ISessionRegistry>();
        var active = await sessions.GetActiveAsync(implant.Id);
        Assert.NotNull(active);
        Assert.Equal("wireguard", active.LastCarrier);
    }

    [Fact]
    public async Task AStrangersDatagramNeverReachesTheContactPath()
    {
        await using var env = await WireGuardTestEnv.StartAsync();
        using var stranger = WireGuardTestClient.Seeded(13, WireGuardTestClient.PublicOf(21));

        // The stranger is not a registered peer: its handshake initiation
        // draws no answer at all.
        var initiation = stranger.Contact([]);
        var response = await UdpTryExchangeAsync(env.Port, initiation);
        Assert.Null(response);
    }

    // The enrollment exchange on the tunnel (Sec 8, the stream carriage's
    // own full-independence step on the datagram discipline): the opening
    // datagram carries one EnrollRequest frame sealed under the artifact
    // key with the enroll purpose tag, answered by one EnrollResponse
    // frame sealed the same way -- and the ordinary handshake that follows
    // rides the next contact, sealed under the key the enrollment bound.
    [Fact]
    public async Task AnEnrollDatagramEnrollsItsImplantThroughTheTunnel()
    {
        await using var env = await WireGuardTestEnv.StartAsync();

        // The engagement-scoped listener, created at runtime the way an
        // engagement's ingress is: a shared-tier front refuses implant
        // ingress outright, so the enrollment names its own entry -- with
        // its server key provisioned under its name in the same deployment
        // section the startup entry's key rides.
        var engagement = await EngagementSetup.CreateOwnedEngagementAsync(env.Host);
        var port = FreePort();
        var manager = env.Host.Services.GetRequiredService<ListenerManager>();
        var listener = await manager.CreateAsync(new ListenerConfig(
            EnrollListenerName, "wireguard", $"127.0.0.1:{port}", $"127.0.0.1:{port}", engagement));

        // The keyed artifact a WireGuard build mints: the envelope key and
        // the token bound to it, seeded store-direct (the build pipeline's
        // mint is its own acceptance; this suite drives the wire).
        var clock = env.Host.Services.GetRequiredService<TimeProvider>();
        var operatorRepository = env.Host.Services
            .GetRequiredService<Rod.CoreState.Operators.IOperatorRepository>();
        var owner = await operatorRepository.FindByHandleAsync(AuthenticatedHost.Handle)
            ?? throw new InvalidOperationException("The seeded operator was not found.");
        var tokens = env.Host.Services
            .GetRequiredService<Rod.CoreState.Deployment.IDeployTokenService>();
        var token = await tokens.MintAsync(engagement, owner.Id, clock.GetUtcNow());
        var (keyId, key) = AesGcmEnvelope.Mint();
        var payloads = env.Host.Services.GetRequiredService<Rod.Audit.IPayloadStore>();
        await payloads.SaveAsync(new Rod.Audit.PayloadRecord(
            Guid.NewGuid(), engagement.Value, "implant", "rust", "application/octet-stream",
            "wireguard-enroll", Array.Empty<byte>(), 0, clock.GetUtcNow(),
            TokenId: token.Id.Value, EnvelopeKeyId: keyId, EnvelopeKey: key));

        using var client = WireGuardTestClient.Seeded(31, WireGuardTestClient.PublicOf(22));
        env.Tunnels.RegisterPeer(listener.Id, client.PublicKey());

        // The tunnel handshake opens the session the contacts ride.
        client.Receive(await UdpExchangeAsync(port, client.Contact([])));

        // One enroll datagram: the EnrollRequest frame alone, sealed under
        // the enroll purpose tag without a counter -- the one-shot exchange.
        var enrollBody = EnvelopeFraming.Encode(new[]
        {
            new Frame
            {
                Kind = FrameKind.EnrollRequest,
                Payload = ByteString.CopyFrom(new Rod.V1.EnrollRequest
                {
                    DeployTokenSecret = token.Secret,
                    Hostname = "wg-host01",
                }.ToByteArray()),
            },
        });
        var sealedEnroll = Encoding.UTF8.GetBytes(
            AesGcmEnvelope.Wrap(enrollBody, keyId, key, AesGcmEnvelope.EnrollRequestAad));
        var enrollAnswer = client.Receive(await UdpExchangeAsync(port, client.Contact(sealedEnroll)));

        var plain = AesGcmEnvelope.TryUnwrap(
            Encoding.UTF8.GetString(enrollAnswer), keyId, key, AesGcmEnvelope.EnrollResponseAad);
        Assert.NotNull(plain);
        var answerFrames = EnvelopeFraming.Parse(plain!);
        var enrolled = Rod.V1.EnrollResponse.Parser.ParseFrom(answerFrames[0].Payload);
        Assert.Equal(FrameKind.EnrollResponse, answerFrames[0].Kind);
        Assert.Equal(EnrollStatus.Ok, enrolled.Status);
        Assert.False(string.IsNullOrWhiteSpace(enrolled.ImplantId));
        Assert.Equal(engagement.ToString(), enrolled.EngagementId);

        // The contact that follows is the ordinary one: the handshake opens
        // the session sealed under the key the enrollment bound, the
        // counter riding the sealed body, and the carrier stamps
        // wireguard.
        var contactBody = BuildContact(enrolled.ImplantId);
        var counter = new byte[8];
        counter[7] = 1;
        var sealedContact = Encoding.UTF8.GetBytes(AesGcmEnvelope.Wrap(
            counter.Concat(contactBody).ToArray(), keyId, key, AesGcmEnvelope.ContactRequestAad));
        var contactAnswer = client.Receive(await UdpExchangeAsync(port, client.Contact(sealedContact)));

        var contactPlain = AesGcmEnvelope.TryUnwrap(
            Encoding.UTF8.GetString(contactAnswer), keyId, key, AesGcmEnvelope.ContactResponseAad);
        Assert.NotNull(contactPlain);
        var handshake = HandshakeResponse.Parser.ParseFrom(EnvelopeFraming.Parse(contactPlain!)[0].Payload);
        Assert.Equal(HandshakeStatus.Ok, handshake.Status);
        Assert.Equal(engagement.ToString(), handshake.EngagementId);

        var sessions = env.Host.Services.GetRequiredService<ISessionRegistry>();
        Assert.True(Rod.CoreState.ImplantId.TryParse(enrolled.ImplantId, out var implantId));
        var active = await sessions.GetActiveAsync(implantId);
        Assert.NotNull(active);
        Assert.Equal("wireguard", active.LastCarrier);
    }

    // The build half's rules (Sec 15.3 ADR-004 as amended), driven directly
    // through the shared parser: a wireguard listener bakes the wg:// dial
    // with the minted pair, the deployment's readiness names its refusals,
    // and the carrier's limits (Rust reference, poll-only) are refused with
    // the fix rather than baked.
    [Fact]
    public async Task AWireGuardBuildMintsItsPairAndRefusesWhatItCannotServe()
    {
        var options = new WireGuardOptions
        {
            Enabled = true,
            ListenerKeys = new Dictionary<string, string>
            {
                [ListenerName] = Convert.ToBase64String(WireGuardTestClient.SeededKey(21)),
            },
        };
        await using var tunnels = new WireGuardTunnelRegistry();
        var engagement = Rod.CoreState.EngagementId.New(); var registry = new InMemoryListenerRegistry();
        var listener = Listener.Define(
            ListenerId.New(), ListenerName, "wireguard",
            "127.0.0.1:51820", "10.0.0.7:51820", DateTimeOffset.UtcNow, engagement);
        await registry.RegisterAsync(listener);
        // The router the build's peer registration lands on -- the same key
        // the options provision, so the listener is the deployment's shape.
        tunnels.OpenListener(listener.Id, WireGuardTestClient.SeededKey(21));

        var ca = new Rod.CoreState.Pki.DevCertificateAuthority();
        var payloads = new Rod.Audit.InMemoryPayloadStore();
        var request = new PayloadEndpoints.BuildPayloadRequest(
            Unit: "rod-rust", Class: null, TargetOs: null, TargetArch: null,
            ListenerId: listener.Id.ToString(), Mode: "poll");

        var (parsed, error) = await PayloadBuildRequestParser.ParseAsync(
            request, engagement, Rod.CoreState.OperatorId.New(), registry,
            ca!, payloads, CancellationToken.None, options, tunnels);
        Assert.Null(error);
        Assert.Equal("wg://10.0.0.7:51820", parsed!.Transport.Endpoint);
        Assert.NotNull(parsed.WireGuardPrivateKey);
        Assert.Equal(32, parsed.WireGuardPrivateKey!.Length);
        // The baked server half is the provisioned key's public counterpart,
        // derived where the curve lives -- the native library.
        Assert.Equal(WireGuardTestClient.PublicOf(21), parsed.WireGuardServerPublicKey);
        Assert.NotNull(parsed.WireGuardArtifactPublicKey);

        // A non-Rust build is refused: the carriage ships in the reference
        // implant, and another language's artifact would bake a dial it
        // cannot serve.
        var (goUnit, goError) = await PayloadBuildRequestParser.ParseAsync(
            request with { Unit = BuildUnitIds.Go }, engagement, Rod.CoreState.OperatorId.New(),
            registry, ca!, payloads, CancellationToken.None, options, tunnels);
        Assert.NotNull(goError);
        Assert.Contains("rod-rust", goError, StringComparison.OrdinalIgnoreCase);
        Assert.Null(goUnit);

        // The carrier is one-answer-one-poll: a stream-mode bake is refused
        // with the fix, the DNS family's own rule.
        var (stream, streamError) = await PayloadBuildRequestParser.ParseAsync(
            request with { Mode = "stream" }, engagement, Rod.CoreState.OperatorId.New(),
            registry, ca!, payloads, CancellationToken.None, options, tunnels);
        Assert.NotNull(streamError);
        Assert.Contains("one-answer-one-poll", streamError, StringComparison.OrdinalIgnoreCase);

        // The validation shape mints nothing: a stored build profile parsed
        // at creation time resolves the dial and checks the deployment
        // without registering a peer whose private half is discarded.
        var (validation, validationError) = await PayloadBuildRequestParser.ParseAsync(
            request, engagement, Rod.CoreState.OperatorId.New(), registry,
            ca!, payloads, CancellationToken.None, options, tunnels, mintWireGuard: false);
        Assert.Null(validationError);
        Assert.Equal("wg://10.0.0.7:51820", validation!.Transport.Endpoint);
        Assert.Null(validation.WireGuardPrivateKey);

        // A disabled transport refuses the build with the deployment fix:
        // the conservative default an unregistered name keeps everywhere.
        var (disabled, disabledError) = await PayloadBuildRequestParser.ParseAsync(
            request, engagement, Rod.CoreState.OperatorId.New(), registry,
            ca!, payloads, CancellationToken.None);
        Assert.NotNull(disabledError);
        Assert.Contains("not enabled", disabledError, StringComparison.OrdinalIgnoreCase);
        Assert.Null(disabled);
    }

    /// <summary>
    /// One envelope contact body: the delimited frame sequence the HTTP
    /// route also carries, opening with the handshake for the named
    /// implant.
    /// </summary>
    private static byte[] BuildContact(string implantId)
    {
        var request = new HandshakeRequest
        {
            ImplantId = implantId,
            Version = new ProtocolVersion { Major = 1, Minor = 0 },
        };
        var frame = new Frame { Payload = ByteString.CopyFrom(request.ToByteArray()) };
        return EnvelopeFraming.Encode(new[] { frame });
    }

    private static async Task<byte[]?> UdpTryExchangeAsync(int port, byte[] datagram)
    {
        using var udp = new UdpClient();
        udp.Connect(IPAddress.Loopback, port);
        await udp.SendAsync(datagram, datagram.Length);
        var task = await Task.WhenAny(udp.ReceiveAsync(), Task.Delay(TimeSpan.FromSeconds(2)));
        return task is Task<UdpReceiveResult> received ? (await received).Buffer : null;
    }

    private static async Task<byte[]> UdpExchangeAsync(int port, byte[] datagram)
    {
        var answer = await UdpTryExchangeAsync(port, datagram)
            ?? throw new TimeoutException("The wireguard listener did not answer.");
        return answer;
    }

    private static int FreePort()
    {
        using var probe = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.Client.LocalEndPoint!).Port;
    }
}
