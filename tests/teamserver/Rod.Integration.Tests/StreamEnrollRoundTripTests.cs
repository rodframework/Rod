using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Transport.Endpoints;
using Rod.Transport.Payloads;
using Rod.V1;
// The domain entity shares its name with the BCL Task, and both namespaces
// define a TaskOutcome; pin the BCL Task and reach the wire outcome by name.
using Task = System.Threading.Tasks.Task;
using TaskOutcome = Rod.V1.TaskOutcome;
using static Rod.Integration.Tests.EngagementSetup;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance for enrollment over the stream contact (architecture.md
/// Sec 8, the same full-independence step the deleted QUIC family took):
/// the raw-TCP listener's opening message may carry an EnrollRequest ahead
/// of its handshake, so a no-egress segment can enroll its first implant
/// over the socket it already reaches. A from-scratch TCP implant -- a
/// plain socket, the stream contact framing, and the protobuf messages --
/// drives the whole exchange: enroll, then the ordinary handshake, then
/// tasking and results on the poll cadence one-connection-one-contact
/// serves.
/// </summary>
public class StreamEnrollRoundTripTests
{
    // The build story (architecture.md Sec 8, enrollment over the stream
    // contact): the socket family's listener is enroll-nameable, the
    // parser baking the transport's own dial -- tcp://host:port for the
    // raw socket -- with the beacon deriving from it. The carrier is
    // poll-only, so a stream-mode bake is refused with the fix. Registry-
    // seeded (no socket binds), so it runs wherever the parser does.
    [Fact]
    public async Task ABuildNamingTheSocketFamilyAsItsEnroll_BakesTheSocketDial()
    {
        var (client, host, operatorId) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var registry = host.Services.GetRequiredService<Rod.Transport.Listeners.IListenerRegistry>();
            var engagement = new Rod.CoreState.EngagementId(Guid.Parse(engagementId));
            var tcp = Rod.Transport.Listeners.Listener.Define(
                Rod.Transport.Listeners.ListenerId.New(), "parser-tcp", "tcp",
                "127.0.0.1:9444", "10.0.0.5:9444", DateTimeOffset.UtcNow, engagement);
            await registry.RegisterAsync(tcp);
            var dns = Rod.Transport.Listeners.Listener.Define(
                Rod.Transport.Listeners.ListenerId.New(), "parser-dns", "dns",
                "10.0.0.6:53", "c2.example.test", DateTimeOffset.UtcNow, engagement);
            await registry.RegisterAsync(dns);

            var payloads = host.Services.GetRequiredService<Rod.Audit.IPayloadStore>();
            var ca = host.Services.GetRequiredService<Rod.CoreState.Pki.IImplantCertificateAuthority>();

            var tcpPoll = await PayloadBuildRequestParser.ParseAsync(
                EnrollRequest(tcp.Id.ToString(), mode: "poll"), engagement, operatorId, registry, ca, payloads,
                CancellationToken.None);
            Assert.Null(tcpPoll.Error);
            Assert.Equal("tcp://10.0.0.5:9444", tcpPoll.Request!.Transport.Endpoint);
            Assert.Equal("poll", tcpPoll.Request.Mode);

            // The DNS family's enroll arm (Sec 8, enrollment over DNS): the
            // baked endpoint is the listener's own bind as the resolver plus
            // its zone -- the lightweight implant a DNS-only target runs.
            var dnsPoll = await PayloadBuildRequestParser.ParseAsync(
                EnrollRequest(dns.Id.ToString(), mode: "poll"), engagement, operatorId, registry, ca, payloads,
                CancellationToken.None);
            Assert.Null(dnsPoll.Error);
            Assert.Equal("dns://10.0.0.6:53/c2.example.test", dnsPoll.Request!.Transport.Endpoint);

            // The socket family's stream mode (Sec 8): the same dial bakes
            // under either mode -- the client the mode picks holds the live
            // session or cycles the connection.
            var streamMode = await PayloadBuildRequestParser.ParseAsync(
                EnrollRequest(tcp.Id.ToString(), mode: "stream"), engagement, operatorId, registry, ca, payloads,
                CancellationToken.None);
            Assert.Null(streamMode.Error);
            Assert.Equal("tcp://10.0.0.5:9444", streamMode.Request!.Transport.Endpoint);
            Assert.Equal("stream", streamMode.Request.Mode);

            // The DNS family's own mode gate (Sec 8): the carrier is
            // one-answer-one-poll, so a stream-mode bake is refused with the
            // fix -- the datagram poll has no stream to hold.
            var dnsStream = await PayloadBuildRequestParser.ParseAsync(
                EnrollRequest(dns.Id.ToString(), mode: "stream"), engagement, operatorId, registry, ca, payloads,
                CancellationToken.None);
            Assert.NotNull(dnsStream.Error);
            Assert.Contains("one-answer-one-poll", dnsStream.Error!, StringComparison.OrdinalIgnoreCase);
        }
    }

    static Rod.Transport.Endpoints.PayloadEndpoints.BuildPayloadRequest EnrollRequest(
        string listenerId, string? mode = null)
        => new(
            Unit: null,
            Class: null,
            TargetOs: null,
            TargetArch: null,
            Endpoint: null,
            UriPath: null,
            SleepSeconds: null,
            JitterSeconds: null,
            KillDate: null,
            ListenerId: listenerId,
            Mode: mode);

    [Fact]
    public async Task TheTcpListener_CarriesEnrollThenContact_OnOneConnection()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var token = await MintDeployTokenAsync(client, engagementId);

            var port = GetFreeTcpPort();
            var created = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/listeners",
                new ListenerEndpoints.CreateListenerRequest(
                    Name: "runtime-tcp",
                    Transport: "tcp",
                    BindAddress: $"127.0.0.1:{port}",
                    PublicEndpoint: $"10.0.0.5:{port}"));
            created.EnsureSuccessStatusCode();
            var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
            Assert.NotNull(listener);
            Assert.Equal("running", listener!.State);

            // The implant's own keypair: only the public half crosses the
            // exchange, and the issued leaf must bind it (architecture.md
            // Sec 9).
            using var implantKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

            using var session = await StreamImplant.ConnectAsync(port);
            var enroll = await session.EnrollExchangeAsync(new Rod.V1.EnrollRequest
            {
                DeployTokenSecret = token,
                PublicKey = ByteString.CopyFrom(implantKey.ExportSubjectPublicKeyInfo()),
                Hostname = "tcp-host01",
                KillDate = DateTimeOffset.UtcNow.AddDays(7).ToString("O"),
            });

            Assert.Equal(EnrollStatus.Ok, enroll.Status);
            Assert.False(string.IsNullOrWhiteSpace(enroll.ImplantId));
            Assert.Equal(engagementId, enroll.EngagementId);
            // No transport leaf is minted (the certificate posture retired
            // with the mTLS family); the accepted public key rode the frame
            // exchange and the CA chain is the answer's substance.
            Assert.True(enroll.LeafCertificate.IsEmpty);
            Assert.NotEmpty(enroll.CaChain);

            // A manually minted token names no build, so the answer carries
            // no per-artifact contact key.
            Assert.False(enroll.HasEnvelopeKeyId);

            // The host facts crossed the frame exchange: the roster's implant
            // is the one the enroll issued, with the reported hostname.
            var implants = await client.GetFromJsonAsync<ImplantEndpoints.ImplantResponse[]>(
                $"/engagements/{engagementId}/implants");
            var recorded = Assert.Single(implants!);
            Assert.Equal(enroll.ImplantId, recorded!.ImplantId);
            Assert.Equal("tcp-host01", recorded.Hostname);

            // Tasking queued before the contact rides its response: the
            // poll shape -- nothing is pushed, the exchange carries what
            // accumulated.
            var marker = "rod-tcp-enroll-marker-" + Guid.NewGuid().ToString("N")[..8];
            var issued = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = enroll.ImplantId, Verb = "shell.exec", Arguments = $"echo {marker}" });
            issued.EnsureSuccessStatusCode();
            var issuedBody = await issued.Content.ReadFromJsonAsync<IssuedBody>();

            // The ordinary handshake follows on the same connection, and the
            // contact response carries the queued task.
            var response = await session.ContactAsync(enroll.ImplantId);
            Assert.Equal(HandshakeStatus.Ok, response.Handshake.Status);
            var request = TaskRequest.Parser.ParseFrom(response.Frames[1].Payload);
            Assert.Equal(issuedBody!.TaskId, request.TaskId);
            Assert.Equal("shell.exec", request.Verb);
            Assert.NotEmpty(request.Signature.ToByteArray());

            // The result rides the next connection's contact -- one
            // connection is one contact, the poll cadence the stream
            // listeners serve.
            using var next = await StreamImplant.ConnectAsync(port);
            var result = await next.ContactAsync(
                enroll.ImplantId, Frames.Result(request.TaskId, TaskOutcome.Succeeded, marker));
            Assert.Equal(HandshakeStatus.Ok, result.Handshake.Status);

            var task = await WaitUntilAsync(async () =>
            {
                var fetched = await client.GetFromJsonAsync<TaskBody>(
                    $"/engagements/{engagementId}/tasks/{issuedBody.TaskId}");
                return fetched?.Status == "Completed" ? fetched : null;
            });
            Assert.Contains(marker, task!.Output);
        }
    }

    // The socket family's stream mode (architecture.md Sec 8): a handshake
    // advertising the live capability switches the connection from the poll
    // exchange to the held live session -- the same runner the WebSocket
    // beacon runs. The proof is the push:
    // a task queued after the handshake arrives as its own message with no
    // request preceding it, and the result frame sent back completes the
    // task on the held connection.
    [Fact]
    public async Task TheTcpListener_HoldsALiveSession_WhenTheHandshakeAdvertisesIt()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var token = await MintDeployTokenAsync(client, engagementId);

            var port = GetFreeTcpPort();
            var created = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/listeners",
                new ListenerEndpoints.CreateListenerRequest(
                    Name: "runtime-tcp-live",
                    Transport: "tcp",
                    BindAddress: $"127.0.0.1:{port}",
                    PublicEndpoint: $"10.0.0.5:{port}"));
            created.EnsureSuccessStatusCode();

            using var implantKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var enrollSession = await StreamImplant.ConnectAsync(port);
            var enroll = await enrollSession.EnrollExchangeAsync(new Rod.V1.EnrollRequest
            {
                DeployTokenSecret = token,
                PublicKey = ByteString.CopyFrom(implantKey.ExportSubjectPublicKeyInfo()),
                Hostname = "tcp-live-host01",
            });
            Assert.Equal(EnrollStatus.Ok, enroll.Status);
            enrollSession.Dispose();

            // The live connection: handshake with the capability advertised,
            // answered by the handshake response as its own message.
            using var session = await StreamImplant.ConnectAsync(port);
            var handshake = await session.LiveHandshakeAsync(enroll.ImplantId);
            Assert.Equal(HandshakeStatus.Ok, handshake.Status);

            // A task queued AFTER the session opened: the poll shape cannot
            // deliver it (nothing of ours is in flight), so the frame that
            // arrives below is the push -- the held session's defining
            // property.
            var marker = "rod-tcp-live-marker-" + Guid.NewGuid().ToString("N")[..8];
            var issued = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = enroll.ImplantId, Verb = "shell.exec", Arguments = $"echo {marker}" });
            issued.EnsureSuccessStatusCode();
            var issuedBody = await issued.Content.ReadFromJsonAsync<IssuedBody>();

            var pushed = await session.ReadFramesAsync().WaitAsync(TimeSpan.FromSeconds(5));
            var request = TaskRequest.Parser.ParseFrom(Assert.Single(pushed).Payload);
            Assert.Equal(issuedBody!.TaskId, request.TaskId);
            Assert.Equal("shell.exec", request.Verb);
            Assert.NotEmpty(request.Signature.ToByteArray());

            // The result frame rides the held connection as its own message;
            // the task completes off it.
            await session.SendFramesAsync(Frames.Result(request.TaskId, TaskOutcome.Succeeded, marker));
            var task = await WaitUntilAsync(async () =>
            {
                var fetched = await client.GetFromJsonAsync<TaskBody>(
                    $"/engagements/{engagementId}/tasks/{issuedBody.TaskId}");
                return fetched?.Status == "Completed" ? fetched : null;
            });
            Assert.Contains(marker, task!.Output);
        }
    }

    // The scope rule the stream listener enforces directly (architecture.md
    // Sec 8): a token minted for another engagement is refused whole and
    // unspent -- the listener knows its own engagement. The refused token
    // still enrolls its own engagement over the web route afterwards.
    [Fact]
    public async Task TheTcpEnroll_RefusesAForeignEngagementsToken_Unspent()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var homeId = await CreateEngagementAsync(client);
            var foreignEngagement = await client.PostAsJsonAsync("/engagements",
                new EngagementEndpoints.CreateEngagementRequest(Name: "Operation Foreign Stream"));
            foreignEngagement.EnsureSuccessStatusCode();
            var foreign = await foreignEngagement.Content
                .ReadFromJsonAsync<EngagementEndpoints.EngagementResponse>();
            var foreignToken = await MintDeployTokenAsync(client, foreign!.EngagementId);

            var port = GetFreeTcpPort();
            var created = await client.PostAsJsonAsync(
                $"/engagements/{homeId}/listeners",
                new ListenerEndpoints.CreateListenerRequest(
                    Name: "runtime-tcp",
                    Transport: "tcp",
                    BindAddress: $"127.0.0.1:{port}",
                    PublicEndpoint: $"10.0.0.5:{port}"));
            created.EnsureSuccessStatusCode();

            using var session = await StreamImplant.ConnectAsync(port);
            var enroll = await session.EnrollExchangeAsync(
                new Rod.V1.EnrollRequest { DeployTokenSecret = foreignToken });
            Assert.Equal(EnrollStatus.BadToken, enroll.Status);

            // Unspent: the same token enrolls its own engagement over the
            // web route afterwards.
            var webEnroll = await client.PostAsJsonAsync("/implants/enroll",
                new EnrollmentEndpoints.EnrollRequest(DeployTokenSecret: foreignToken, Class: null));
            Assert.Equal(HttpStatusCode.OK, webEnroll.StatusCode);
        }
    }

    // A free TCP port below the Linux ephemeral range: a bind there is a
    // reservation, not a race.
    private static int GetFreeTcpPort()
    {
        for (var attempt = 0; attempt < 200; attempt++)
        {
            var port = Random.Shared.Next(20_000, 32_760);
            try
            {
                using var probe = new TcpListener(IPAddress.Loopback, port);
                probe.Start();
                return port;
            }
            catch (SocketException)
            {
                // Taken; the next candidate.
            }
        }
        throw new InvalidOperationException("No free TCP port inside the probed range.");
    }

    private static async Task<T?> WaitUntilAsync<T>(Func<Task<T?>> probe, TimeSpan? timeout = null)
        where T : class
    {
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (DateTimeOffset.UtcNow < deadline)
        {
            var found = await probe();
            if (found is not null)
                return found;
            await Task.Delay(50);
        }
        throw new TimeoutException("The condition never held inside the window.");
    }

    private sealed class IssuedBody
    {
        public string TaskId { get; set; } = "";
    }

    private sealed class TaskBody
    {
        public string Status { get; set; } = "";
        public string? Output { get; set; }
    }

    // The frame shapes a from-scratch implant sends.
    private static class Frames
    {
        public static Frame Result(string taskId, TaskOutcome outcome, string output) => new()
        {
            Kind = FrameKind.TaskResult,
            Payload = ByteString.CopyFrom(new TaskResult
            {
                TaskId = taskId,
                Outcome = outcome,
                Output = output,
            }.ToByteArray()),
        };
    }

    // The from-scratch raw-TCP implant: the stream contact framing over a
    // plain socket, nothing else -- the client an implant author of any
    // language writes from the contract doc (extending/implants.md).
    private sealed class StreamImplant : IDisposable
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;

        private StreamImplant(TcpClient client)
        {
            _client = client;
            _stream = client.GetStream();
        }

        public static async Task<StreamImplant> ConnectAsync(int port)
        {
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            return new StreamImplant(client);
        }

        // The opening enroll exchange: a kind-bearing EnrollRequest frame
        // answered by an EnrollResponse frame on the same connection.
        public async Task<Rod.V1.EnrollResponse> EnrollExchangeAsync(Rod.V1.EnrollRequest request)
        {
            await WriteMessageAsync(new Frame
            {
                Kind = FrameKind.EnrollRequest,
                Payload = ByteString.CopyFrom(request.ToByteArray()),
            });
            var answer = ParseFrames(await ReadMessageAsync());
            Assert.Single(answer);
            Assert.Equal(FrameKind.EnrollResponse, answer[0].Kind);
            return Rod.V1.EnrollResponse.Parser.ParseFrom(answer[0].Payload);
        }

        // One contact: the handshake (plus any result frames) sent, the
        // handshake response (plus any queued tasking) read back -- one
        // message each way, the poll shape the stream listeners serve.
        public async Task<(HandshakeResponse Handshake, IReadOnlyList<Frame> Frames)> ContactAsync(
            string implantId, params Frame[] extra)
        {
            var handshake = new HandshakeRequest
            {
                Version = new ProtocolVersion { Major = 1, Minor = 0 },
                ImplantId = implantId,
                ReplayNonces = true,
            };
            handshake.Capabilities.Add("shell.exec");
            var frames = new List<Frame>(1 + extra.Length)
            {
                new Frame { Payload = ByteString.CopyFrom(handshake.ToByteArray()) },
            };
            frames.AddRange(extra);
            await WriteMessageAsync([.. frames]);

            var inbound = ParseFrames(await ReadMessageAsync());
            Assert.NotEmpty(inbound);
            return (HandshakeResponse.Parser.ParseFrom(inbound[0].Payload), inbound);
        }

        // The stream mode's opening handshake: the same shape with the live
        // capability advertised, so the server holds the connection as a
        // live session instead of one poll exchange. The handshake response
        // rides as its own message; everything after it is the session.
        public async Task<HandshakeResponse> LiveHandshakeAsync(string implantId)
        {
            var handshake = new HandshakeRequest
            {
                Version = new ProtocolVersion { Major = 1, Minor = 0 },
                ImplantId = implantId,
                ReplayNonces = true,
            };
            handshake.Capabilities.Add("shell.exec");
            handshake.Capabilities.Add("channels.live");
            await WriteMessageAsync(new Frame { Payload = ByteString.CopyFrom(handshake.ToByteArray()) });

            var inbound = ParseFrames(await ReadMessageAsync());
            Assert.NotEmpty(inbound);
            return HandshakeResponse.Parser.ParseFrom(inbound[0].Payload);
        }

        /// <summary>One live-session message out: the frames, varint-length-prefixed.</summary>
        public Task SendFramesAsync(params Frame[] frames) => WriteMessageAsync(frames);

        /// <summary>One live-session message in: the frames the server pushed.</summary>
        public async Task<IReadOnlyList<Frame>> ReadFramesAsync() => ParseFrames(await ReadMessageAsync());

        // One message out: the varint length prefix, then exactly that many
        // body bytes of delimited frames.
        private async Task WriteMessageAsync(params Frame[] frames)
        {
            var body = new MemoryStream();
            foreach (var frame in frames)
            {
                var marshaled = frame.ToByteArray();
                WriteVarint(body, marshaled.Length);
                body.Write(marshaled);
            }
            var prefix = new MemoryStream();
            WriteVarint(prefix, (int)body.Length);
            var message = prefix.ToArray();
            await _stream.WriteAsync(message);
            await _stream.WriteAsync(body.ToArray());
            await _stream.FlushAsync();
        }

        // One message in: the varint length prefix, then exactly that many
        // body bytes.
        private async Task<byte[]> ReadMessageAsync()
        {
            long length = 0;
            var shift = 0;
            while (true)
            {
                var read = _stream.ReadByte();
                if (read < 0)
                    throw new EndOfStreamException();
                length |= (long)(read & 0x7f) << shift;
                if ((read & 0x80) == 0)
                    break;
                shift += 7;
                if (shift > 28)
                    throw new IOException("Contact length prefix is a malformed varint.");
            }

            var body = new byte[length];
            var offset = 0;
            while (offset < length)
            {
                var chunk = await _stream.ReadAsync(body.AsMemory(offset));
                if (chunk <= 0)
                    throw new EndOfStreamException();
                offset += chunk;
            }
            return body;
        }

        private static List<Frame> ParseFrames(byte[] body)
        {
            var frames = new List<Frame>();
            var position = 0;
            while (position < body.Length)
            {
                uint length = 0;
                var shift = 0;
                while (true)
                {
                    if (position >= body.Length)
                        throw new IOException("Frame length prefix ran past the body.");
                    var b = body[position++];
                    length |= (uint)(b & 0x7f) << shift;
                    if ((b & 0x80) == 0)
                        break;
                    shift += 7;
                }
                var frame = new Frame();
                frame.MergeFrom(body.AsSpan((int)position, (int)length).ToArray());
                position += (int)length;
                frames.Add(frame);
            }
            return frames;
        }

        private static void WriteVarint(MemoryStream sink, int value)
        {
            uint v = (uint)value;
            while (v >= 0x80)
            {
                sink.WriteByte((byte)(v | 0x80));
                v >>= 7;
            }
            sink.WriteByte((byte)v);
        }

        public void Dispose()
        {
            _stream.Dispose();
            _client.Dispose();
        }
    }
}
