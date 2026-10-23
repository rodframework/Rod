using System.Net;
using System.Net.Sockets;
using Google.Protobuf;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.CoreState;
using Rod.CoreState.Implants;
using Rod.CoreState.Engagements;
using Rod.CoreState.Sessions;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;
using Rod.Transport.Listeners.WireGuard;
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
            // name, the native library beside the binaries.
            var serverKey = WireGuardTestClient.SeededKey(21);
            var config = AuthenticatedHost.BuildConfig(settings =>
            {
                settings["WireGuard:Enabled"] = "true";
                settings[$"WireGuard:ListenerKeys:{ListenerName}"] = Convert.ToBase64String(serverKey);
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
