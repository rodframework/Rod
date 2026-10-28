using System.Net;
using System.Net.Http.Json;
using Google.Protobuf;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.CoreState;
using Rod.CoreState.Tasks;
using Rod.Transport.Endpoints;
using Rod.V1;
// The domain entity shares its name with the BCL Task, and both namespaces
// define a TaskOutcome; pin the BCL Task and reach the wire outcome by name.
using Task = System.Threading.Tasks.Task;
using TaskOutcome = Rod.V1.TaskOutcome;
using static Rod.Integration.Tests.EngagementSetup;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance for the WebSocket beacon stream (architecture.md Sec 8, the
/// web posture's interactive tier): the same session every live carriage runs,
/// over a WebSocket on the plain-HTTP listener family, with the envelope's
/// own handshake and frame grammar. A from-scratch WebSocket implant -- no
/// protocol library, just the socket and the protobuf messages -- enrolls,
/// handshakes, receives a pushed task the moment it is queued, reports its
/// result, and holds the live channel an operator types into
/// (architecture.md Sec 10.3).
/// </summary>
public class WebSocketBeaconRoundTripTests
{
    [Fact]
    public async Task FromScratchImplant_HandshakesReceivesPushedTaskingAndReports()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var (secret, _) = await MintDeployTokenAsync(client, engagementId);
            var implantId = await EnrollAsync(client, secret);

            using var implant = await WsImplant.ConnectAsync(host, implantId);
            var handshake = await implant.ReceiveHandshakeAsync();
            Assert.Equal(HandshakeStatus.Ok, handshake.Status);
            Assert.Equal(1, handshake.Version.Major);

            // The push shape: the task arrives on the open stream the moment
            // the operator queues it -- no poll, no waiting interval.
            var marker = "rod-ws-marker-" + Guid.NewGuid().ToString("N")[..8];
            var issued = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = implantId, Verb = "shell.exec", Arguments = $"echo {marker}" });
            issued.EnsureSuccessStatusCode();
            var issuedBody = await issued.Content.ReadFromJsonAsync<IssuedBody>();

            var request = TaskRequest.Parser.ParseFrom(await implant.ReceiveSingleFrameAsync());
            Assert.Equal(issuedBody!.TaskId, request.TaskId);
            Assert.Equal("shell.exec", request.Verb);
            Assert.NotEmpty(request.Signature.ToByteArray());

            var completed = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks/{issuedBody.TaskId}/input",
                new { Data = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("ignored")) });
            // A one-shot task takes no live input: the verb check refuses it,
            // not the transport.
            Assert.Equal(HttpStatusCode.UnprocessableEntity, completed.StatusCode);

            await implant.SendFramesAsync(new[] { Frames.Result(
                request.TaskId, TaskOutcome.Succeeded, marker) });

            var task = await WaitUntilAsync(async () =>
            {
                var fetched = await client.GetFromJsonAsync<TaskBody>(
                    $"/engagements/{engagementId}/tasks/{issuedBody.TaskId}");
                return fetched?.Status == "Completed" ? fetched : null;
            });
            Assert.Contains(marker, task!.Output);
        }
    }

    [Fact]
    public async Task FromScratchImplant_HoldsTheInteractiveChannel()
    {
        // The point of the stream on the web posture: the channel verbs run
        // live. An operator's typing reaches the implant as a ChannelInput
        // frame on this socket, and the implant's output streams back.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var (secret, _) = await MintDeployTokenAsync(client, engagementId);
            var implantId = await EnrollAsync(client, secret);

            using var implant = await WsImplant.ConnectAsync(host, implantId);
            Assert.Equal(HandshakeStatus.Ok, (await implant.ReceiveHandshakeAsync()).Status);

            var issued = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = implantId, Verb = "shell.interact", Arguments = "" });
            issued.EnsureSuccessStatusCode();
            var issuedBody = await issued.Content.ReadFromJsonAsync<IssuedBody>();
            Assert.NotNull(issuedBody);

            var request = TaskRequest.Parser.ParseFrom(await implant.ReceiveSingleFrameAsync());
            Assert.Equal(ChannelVerbs.ShellInteract, request.Verb);
            // The operator types; the frame crosses the stream.
            var typed = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks/{issuedBody!.TaskId}/input",
                new { Data = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("whoami\n")) });
            typed.EnsureSuccessStatusCode();

            var input = ChannelInput.Parser.ParseFrom(await implant.ReceiveSingleFrameAsync(
                expectKind: FrameKind.ChannelInput));
            Assert.Equal(issuedBody.TaskId, input.TaskId);
            Assert.Equal("whoami\n", input.Data.ToStringUtf8());

            // The implant streams its shell's output back over the channel.
            await implant.SendFramesAsync(new[] { Frames.ChannelOut(
                request.TaskId, "root\n") });

            var task = await WaitUntilAsync(async () =>
            {
                var fetched = await client.GetFromJsonAsync<TaskBody>(
                    $"/engagements/{engagementId}/tasks/{issuedBody.TaskId}");
                return fetched?.Output?.Contains("root") == true ? fetched : null;
            });
            Assert.Equal("Dispatched", task!.Status);
        }
    }

    [Fact]
    public async Task FromScratchImplant_HandshakesSealedUnderTheArtifactKey()
    {
        // The default build shape: contacts sealed under the per-artifact
        // key. The harness stands in a payload record carrying the key, the
        // enroll binds it, and the WebSocket handshake rides as the sealed
        // envelope's first message -- the acceptance shape the https front
        // bakes.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var (secret, tokenId) = await MintDeployTokenAsync(client, engagementId);

            var key = new byte[32];
            var keyId = Guid.NewGuid();
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                rng.GetBytes(key);
            var payloads = host.Services.GetRequiredService<Rod.Audit.IPayloadStore>();
            await payloads.SaveAsync(new Rod.Audit.PayloadRecord(
                PayloadId: Guid.NewGuid(),
                EngagementId: Guid.Parse(engagementId),
                Class: "Implant",
                UnitId: "rod-dotnet",
                ContentType: "application/octet-stream",
                Fingerprint: "sha256:" + new string('a', 64),
                Content: Array.Empty<byte>(),
                Size: 0,
                BuiltAt: DateTimeOffset.UtcNow,
                TokenId: tokenId,
                EnvelopeKeyId: keyId,
                EnvelopeKey: key));

            var implantId = await EnrollAsync(client, secret);
            using var implant = await WsImplant.ConnectSealedAsync(host, implantId, keyId, key);
            var handshake = await implant.ReceiveHandshakeAsync();
            Assert.Equal(HandshakeStatus.Ok, handshake.Status);

            // The session pushes sealed tasking whole.
            var issued = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = implantId, Verb = "shell.exec", Arguments = "echo sealed-ws" });
            issued.EnsureSuccessStatusCode();
            var request = TaskRequest.Parser.ParseFrom(await implant.ReceiveSingleFrameAsync());
            Assert.Equal("shell.exec", request.Verb);
        }
    }

    private static async Task<(string Secret, Guid TokenId)> MintDeployTokenAsync(
        HttpClient client, string engagementId)
    {
        var response = await client.PostAsync($"/engagements/{engagementId}/deploy-tokens", content: null);
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<EngagementEndpoints.DeployTokenResponse>();
        return (token!.Secret, Guid.Parse(token.DeployTokenId));
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

    // The from-scratch WebSocket implant: the envelope's varint frame codec
    // over the socket's messages, nothing else. Optionally sealed under the
    // per-artifact key with the same wire shapes the built artifact bakes.
    private sealed class WsImplant : IDisposable
    {
        private readonly System.Net.WebSockets.WebSocket _ws;
        private (Guid KeyId, byte[] Key)? _seal;
        private long _counter;

        private WsImplant(System.Net.WebSockets.WebSocket ws) => _ws = ws;

        public static async Task<WsImplant> ConnectAsync(IHost host, string implantId)
        {
            var (implant, _) = await ConnectCoreAsync(host, implantId, seal: null);
            return implant;
        }

        public static async Task<WsImplant> ConnectSealedAsync(
            IHost host, string implantId, Guid keyId, byte[] key)
            => (await ConnectCoreAsync(host, implantId, (keyId, key))).Item1;

        private static async Task<(WsImplant, System.Net.WebSockets.WebSocket)> ConnectCoreAsync(
            IHost host, string implantId, (Guid KeyId, byte[] Key)? seal)
        {
            var server = host.GetTestServer();
            var wsClient = server.CreateWebSocketClient();
            var ws = await wsClient.ConnectAsync(
                new Uri(server.BaseAddress, WebSocketBeaconEndpoints.Route), CancellationToken.None);
            var implant = new WsImplant(ws) { _seal = seal };

            // The implant speaks first: the handshake frame -- the envelope's
            // request-body shape, sealed when the bake carried a key.
            var handshake = new HandshakeRequest
            {
                Version = new ProtocolVersion { Major = 1 },
                ImplantId = implantId,
                Capabilities = { "shell.exec", ChannelVerbs.ShellInteract },
            };
            await implant.SendFramesAsync(new[] { new Frame
            {
                Payload = ByteString.CopyFrom(handshake.ToByteArray()),
            } });
            return (implant, ws);
        }

        public async Task<HandshakeResponse> ReceiveHandshakeAsync()
            => HandshakeResponse.Parser.ParseFrom(await ReceiveSingleFrameAsync());

        public async Task<byte[]> ReceiveSingleFrameAsync(FrameKind expectKind = FrameKind.Unspecified)
        {
            var frames = Parse(await ReceiveMessageAsync());
            Assert.Single(frames);
            if (expectKind != FrameKind.Unspecified)
                Assert.Equal(expectKind, frames[0].Kind);
            return frames[0].Payload.ToByteArray();
        }

        public async Task SendFramesAsync(IReadOnlyList<Frame> frames)
        {
            var encoded = Encode(frames);
            byte[] payload;
            System.Net.WebSockets.WebSocketMessageType type;
            if (_seal is { } seal)
            {
                var plaintext = new byte[8 + encoded.Length];
                System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(plaintext, ++_counter);
                encoded.AsSpan().CopyTo(plaintext.AsSpan(8));
                payload = System.Text.Encoding.UTF8.GetBytes(Rod.Transport.Payloads.AesGcmEnvelope.Wrap(
                    plaintext, seal.KeyId, seal.Key, Rod.Transport.Payloads.AesGcmEnvelope.ContactRequestAad));
                type = System.Net.WebSockets.WebSocketMessageType.Text;
            }
            else
            {
                payload = encoded;
                type = System.Net.WebSockets.WebSocketMessageType.Binary;
            }
            await _ws.SendAsync(payload, type, endOfMessage: true, CancellationToken.None);
        }

        public void Dispose() => _ws.Dispose();

        private async Task<byte[]> ReceiveMessageAsync()
        {
            var buffer = new byte[16 * 1024];
            using var message = new MemoryStream();
            while (true)
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var received = await _ws.ReceiveAsync(new ArraySegment<byte>(buffer), timeout.Token);
                if (received.MessageType == System.Net.WebSockets.WebSocketMessageType.Close)
                    throw new InvalidOperationException("The stream closed under the test.");
                message.Write(buffer, 0, received.Count);
                if (received.EndOfMessage)
                {
                    var body = message.ToArray();
                    if (_seal is { } seal)
                    {
                        var text = System.Text.Encoding.UTF8.GetString(body).Trim();
                        body = Rod.Transport.Payloads.AesGcmEnvelope.TryUnwrap(
                            text, seal.KeyId, seal.Key, Rod.Transport.Payloads.AesGcmEnvelope.ContactResponseAad)
                            ?? throw new InvalidOperationException("A sealed message did not verify.");
                    }
                    return body;
                }
            }
        }

        // The envelope codec: the protobuf canonical delimited-stream shape --
        // an unsigned varint length before each marshaled Frame.

        private static byte[] Encode(IReadOnlyList<Frame> frames)
        {
            var body = new MemoryStream();
            foreach (var frame in frames)
            {
                var marshaled = frame.ToByteArray();
                WriteVarint(body, marshaled.Length);
                body.Write(marshaled);
            }
            return body.ToArray();
        }

        private static List<Frame> Parse(byte[] body)
        {
            var frames = new List<Frame>();
            var position = 0;
            while (position < body.Length)
            {
                uint length = 0;
                var shift = 0;
                int delimiter;
                for (delimiter = 0; delimiter < 5; delimiter++)
                {
                    var b = body[position + delimiter];
                    length |= (uint)(b & 0x7f) << shift;
                    if ((b & 0x80) == 0)
                        break;
                    shift += 7;
                }
                position += delimiter + 1;
                frames.Add(Frame.Parser.ParseFrom(body, position, (int)length));
                position += (int)length;
            }
            return frames;
        }

        private static void WriteVarint(MemoryStream target, int value)
        {
            uint remaining = (uint)value;
            while (remaining >= 0x80)
            {
                target.WriteByte((byte)(remaining | 0x80));
                remaining >>= 7;
            }
            target.WriteByte((byte)remaining);
        }
    }

    // The upstream frame builders the from-scratch implant sends after its
    // handshake.
    private static class Frames
    {
        public static Frame Result(string taskId, TaskOutcome outcome, string output)
            => new()
            {
                Kind = FrameKind.TaskResult,
                Payload = ByteString.CopyFrom(new TaskResult
                {
                    TaskId = taskId,
                    Outcome = outcome,
                    Output = output,
                }.ToByteArray()),
            };

        public static Frame ChannelOut(string taskId, string output)
            => new()
            {
                Kind = FrameKind.ChannelOutput,
                Payload = ByteString.CopyFrom(new ChannelOutput
                {
                    TaskId = taskId,
                    Data = ByteString.CopyFromUtf8(output),
                }.ToByteArray()),
            };
    }
}
