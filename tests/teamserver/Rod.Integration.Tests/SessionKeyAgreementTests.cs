using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Google.Protobuf;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.CoreState;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.Transport.Payloads;
using Rod.V1;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance for the session-key arm over the baked seal (architecture.md
/// Sec 9, the queue's seized-config item): an implant whose handshake offers
/// an ephemeral P-256 public agrees a session's sealing keys with the
/// teamserver, and everything after the agreement -- both directions, every
/// contact -- seals under them. The acceptance bar is the item's own
/// criterion: a captured artifact's baked key no longer opens the traffic it
/// recorded before capture, while the key keeps its enrollment-identity
/// role (it can open a NEW session, never a recorded one).
/// </summary>
public class SessionKeyAgreementTests
{
    [Fact]
    public void KeySchedule_MatchesThePinnedVector()
    {
        // The schedule is the cross-stack contract: this vector is computed
        // independently (RFC 5869 HKDF-SHA256 over the fixed inputs) and the
        // Rust and Go trees assert the same bytes, so a drift in any one
        // stack's derivation fails its own suite before it reaches the wire.
        var shared = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var baked = Enumerable.Range(33, 32).Select(i => (byte)i).ToArray();
        var keyId = new Guid("00112233-4455-6677-8899-aabbccddeeff");
        var implant = new ImplantId(Guid.Parse("0123456789abcdef0123456789abcdef"));

        var okm = SessionSealKeys.Derive(shared, baked, keyId, implant);

        Assert.Equal(
            "496c8c72ce8d921c696e21bbe304ff87ddf6e2449a5e1b9e155e86a433b9b7b465f6276977aefcdb3b286031976aacea846cbaefb2225216df7de958d5508dd9afc339e90d1c342a8aaa9aead24290a6",
            Convert.ToHexStringLower(okm));
        // The slices the R2 body routes and seals by: session id, request
        // key, response key.
        Assert.Equal("496c8c72ce8d921c696e21bbe304ff87", Convert.ToHexStringLower(okm.AsSpan(0, 16)));
        Assert.Equal("ddf6e2449a5e1b9e155e86a433b9b7b465f6276977aefcdb3b286031976aacea", Convert.ToHexStringLower(okm.AsSpan(16, 32)));
        Assert.Equal("846cbaefb2225216df7de958d5508dd9afc339e90d1c342a8aaa9aead24290a6", Convert.ToHexStringLower(okm.AsSpan(48, 32)));
    }

    [Fact]
    public async Task Agreement_RoundTrips_AndSealsTaskingUnderSessionKeys()
    {
        await using var env = await TestEnv.StartAsync();
        var (engagementId, secret, bakedKey) = await env.MintSealedArtifactShapeAsync();
        using var client = await SessionScratch.EnrollAsync(
            $"http://127.0.0.1:{env.HttpPort}", env.EnrollUrl, secret, bakedKey);

        // The agreement contact: the offer rides the handshake and nothing
        // else does. The answer carries the server's ephemeral, the store
        // holds the agreed session, and its id is not the baked key id --
        // the keys name a session, not the artifact.
        var agreement = await client.AgreementContactAsync();
        Assert.Equal(HandshakeStatus.Ok, agreement.Status);
        Assert.Equal(SessionSealKeys.PublicKeyBytes, agreement.SessionPublic.Length);

        var sessionKeys = env.Host.Services.GetRequiredService<SessionSealKeys>();
        Assert.True(ImplantId.TryParse(client.ImplantId, out var implantId));
        var entry = sessionKeys.TryLatest(implantId);
        Assert.NotNull(entry);
        Assert.Equal(entry!.SessionId, client.Session!.Value.SessionId);
        Assert.NotEqual(client.BakedKeyId, entry.SessionId);

        // A task round-trips under the session keys: the tasking rides the
        // R2 response, the result rides the next R2 request.
        var (taskId, _) = await env.IssueTaskAsync(
            engagementId, client.ImplantId, "shell.exec", "echo rod-session");
        var second = await client.SessionContactAsync();
        Assert.True(second.Count >= 2, "expected the handshake response plus a task");
        var request = TaskRequest.Parser.ParseFrom(second[1].Payload);
        Assert.Equal(taskId, request.TaskId);
        var third = await client.SessionContactAsync(new[] { TaskResultFrame(
            request.TaskId, Rod.V1.TaskOutcome.Succeeded, "rod-session\n") });
        Assert.Single(third);
        var task = await env.GetTaskAsync(engagementId, taskId);
        Assert.Equal("Succeeded", task!.Outcome);
    }

    [Fact]
    public async Task CapturedBakedKey_NoLongerOpensTheRecordedPath()
    {
        // The item's acceptance criterion, both halves: the recorded R2
        // bodies do not open under the baked key (the seized-config class --
        // possession of the artifact's key decrypted its own recorded
        // traffic), and a baked-key body the key holder forges after the
        // agreement is the refused downgrade.
        await using var env = await TestEnv.StartAsync();
        var (_, secret, bakedKey) = await env.MintSealedArtifactShapeAsync();
        using var client = await SessionScratch.EnrollAsync(
            $"http://127.0.0.1:{env.HttpPort}", env.EnrollUrl, secret, bakedKey);
        await client.AgreementContactAsync();

        // The recorded half: an R2 body the session produced does not
        // verify under the baked key, in either direction's purpose tag --
        // the key the capture surrenders is cryptographically elsewhere.
        await client.SessionContactAsync();
        var recorded = client.LastSessionBody!;
        Assert.True(AesGcmEnvelope.TryUnbake(bakedKey, out var keyId, out var key));
        Assert.Null(AesGcmEnvelope.TryUnwrap(
            System.Text.Encoding.UTF8.GetString(recorded), keyId, key, AesGcmEnvelope.ContactRequestAad));
        Assert.Null(AesGcmEnvelope.TryUnwrap(
            System.Text.Encoding.UTF8.GetString(recorded), keyId, key, AesGcmEnvelope.ContactResponseAad));

        // The forged half: a body sealed under the baked key with a counter
        // far above the floor (so only the downgrade gate can refuse it) is
        // a 401, offer-less -- while the same possession re-run as an
        // agreement offer opens a NEW session instead, the root-identity
        // half the arm keeps.
        var forged = await client.RawBakedContactAsync(1_000_000, offer: false);
        Assert.Equal(HttpStatusCode.Unauthorized, forged.StatusCode);
        var reAgreement = await client.AgreementContactAsync();
        Assert.Equal(HandshakeStatus.Ok, reAgreement.Status);
        Assert.Equal(SessionSealKeys.PublicKeyBytes, reAgreement.SessionPublic.Length);

        // And the re-agreement rolled the session: the new keys differ, the
        // old session id no longer routes, and traffic continues under the
        // new ones.
        var after = await client.SessionContactAsync();
        Assert.Equal(HandshakeStatus.Ok, HandshakeResponse.Parser.ParseFrom(after[0].Payload).Status);
        var sessionKeys = env.Host.Services.GetRequiredService<SessionSealKeys>();
        Assert.True(ImplantId.TryParse(client.ImplantId, out var implantId));
        Assert.Equal(client.Session!.Value.SessionId, sessionKeys.TryLatest(implantId)!.SessionId);
    }

    [Fact]
    public async Task UnknownSessionBody_IsRefusedUntilReAgreement()
    {
        // The restart shape: an R2 body naming a session this teamserver
        // never agreed (its store is in-memory, the same freshness boundary
        // the floors keep) is a 401, and the implant's fallback -- a fresh
        // agreement under the baked key -- restores the session.
        await using var env = await TestEnv.StartAsync();
        var (_, secret, bakedKey) = await env.MintSealedArtifactShapeAsync();
        using var client = await SessionScratch.EnrollAsync(
            $"http://127.0.0.1:{env.HttpPort}", env.EnrollUrl, secret, bakedKey);
        await client.AgreementContactAsync();

        var stranger = await client.RawSessionContactAsync(
            Guid.NewGuid(), 1, new HandshakeRequest
            {
                Version = new ProtocolVersion { Major = 1, Minor = 0 },
                ImplantId = client.ImplantId,
            });
        Assert.Equal(HttpStatusCode.Unauthorized, stranger.StatusCode);

        var resumed = await client.AgreementContactAsync();
        Assert.Equal(HandshakeStatus.Ok, resumed.Status);
        var after = await client.SessionContactAsync();
        Assert.Equal(HandshakeStatus.Ok, HandshakeResponse.Parser.ParseFrom(after[0].Payload).Status);
    }

    [Fact]
    public async Task ContractViolations_OfferOnSessionBodyAndOfferWithFrames_AreRefused()
    {
        await using var env = await TestEnv.StartAsync();
        var (_, secret, bakedKey) = await env.MintSealedArtifactShapeAsync();
        using var client = await SessionScratch.EnrollAsync(
            $"http://127.0.0.1:{env.HttpPort}", env.EnrollUrl, secret, bakedKey);
        await client.AgreementContactAsync();

        // An offer riding a session body is the refused contract violation:
        // the agreement rides the baked-key handshake contact only.
        var onSession = await client.PostSessionFramesAsync(offer: true);
        Assert.Equal(HttpStatusCode.Unauthorized, onSession.StatusCode);

        // An agreement contact carrying frames beyond its handshake is the
        // same refusal: the exchange answers alone, so nothing the baked key
        // could open ever rides it.
        var withFrames = await client.PostAgreementAsync(
            extraFrames: new[] { TaskResultFrame(
                "00000000000000000000000000000000", Rod.V1.TaskOutcome.Succeeded, "rides-along") });
        Assert.Equal(HttpStatusCode.Unauthorized, withFrames.StatusCode);
    }

    [Fact]
    public async Task ReplayedSessionBody_FallsAtTheSameFloor()
    {
        // The counter discipline is the session body's own: a replayed R2
        // body, verbatim, turns away at the floor the baked-key contacts
        // already kept -- the arm changes the keys, not the freshness rule.
        await using var env = await TestEnv.StartAsync();
        var (_, secret, bakedKey) = await env.MintSealedArtifactShapeAsync();
        using var client = await SessionScratch.EnrollAsync(
            $"http://127.0.0.1:{env.HttpPort}", env.EnrollUrl, secret, bakedKey);
        await client.AgreementContactAsync();
        await client.SessionContactAsync();

        var replay = await client.PostRawAsync(client.LastSessionBody!);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);

        // The cadence continues under the session keys after the refusal.
        var after = await client.SessionContactAsync();
        Assert.Equal(HandshakeStatus.Ok, HandshakeResponse.Parser.ParseFrom(after[0].Payload).Status);
    }

    /// <summary>
    /// The from-scratch client of the arm: the sealed posture's twin of the
    /// envelope tests' scratch implant, plus the agreement state machine --
    /// the ephemeral offer, the HKDF derivation against the echoed server
    /// public, and the R2 bodies the agreed session seals.
    /// </summary>
    private sealed class SessionScratch : IDisposable
    {
        private readonly HttpClient _http = new();
        private readonly string _beaconUrl;

        public string ImplantId { get; private set; } = string.Empty;
        public string EngagementId { get; private set; } = string.Empty;
        public (Guid KeyId, byte[] Key) Baked { get; private set; }
        public Guid BakedKeyId => Baked.KeyId;

        public (Guid SessionId, byte[] RequestKey, byte[] ResponseKey)? Session { get; private set; }

        public byte[]? LastSessionBody { get; private set; }

        private long _counter;
        private ECDiffieHellman? _ephemeral;

        private SessionScratch(string beaconUrl)
        {
            _beaconUrl = beaconUrl;
        }

        public static async Task<SessionScratch> EnrollAsync(
            string front, string enrollUrl, string secret, string bakedKey)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var enroll = new HttpClient();
            using var response = await enroll.PostAsJsonAsync(enrollUrl, new
            {
                deployTokenSecret = secret,
                publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
            });
            response.EnsureSuccessStatusCode();
            var body = await response.Content.ReadFromJsonAsync<EnrollBody>();
            Assert.NotNull(body);
            Assert.True(AesGcmEnvelope.TryUnbake(bakedKey, out var bakedKeyId, out var bakedKeyBytes));
            return new SessionScratch($"{front}/implants/beacon")
            {
                ImplantId = body!.ImplantId,
                EngagementId = body.EngagementId,
                Baked = (bakedKeyId, bakedKeyBytes),
            };
        }

        /// <summary>
        /// The agreement contact, raw: the handshake with its ephemeral offer
        /// (and any contract-violating extras the caller probes with), sealed
        /// under the baked key.
        /// </summary>
        public async Task<HttpResponseMessage> PostAgreementAsync(Frame[]? extraFrames = null)
        {
            _ephemeral?.Dispose();
            _ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var point = _ephemeral.ExportParameters(includePrivateParameters: false).Q;
            var offered = new byte[SessionSealKeys.PublicKeyBytes];
            offered[0] = 0x04;
            LeftAligned(point.X, offered.AsSpan(1, 32));
            LeftAligned(point.Y, offered.AsSpan(33, 32));

            var frames = new List<Frame>
            {
                new Frame
                {
                    Payload = ByteString.CopyFrom(new HandshakeRequest
                    {
                        Version = new ProtocolVersion { Major = 1, Minor = 0 },
                        ImplantId = ImplantId,
                        SessionPublic = ByteString.CopyFrom(offered),
                    }.ToByteArray()),
                },
            };
            if (extraFrames is not null)
                frames.AddRange(extraFrames);

            return await PostSealedBakedAsync(frames.ToArray());
        }

        /// <summary>
        /// The agreement contact: the offer rides alone, the echoed server
        /// public derives the session keys.
        /// </summary>
        public async Task<HandshakeResponse> AgreementContactAsync()
        {
            using var sent = await PostAgreementAsync();
            sent.EnsureSuccessStatusCode();
            var inbound = ParseFrames(OpenBaked(await sent.Content.ReadAsByteArrayAsync()));
            var answer = HandshakeResponse.Parser.ParseFrom(inbound[0].Payload);
            if (answer.Status == HandshakeStatus.Ok && answer.SessionPublic.Length == SessionSealKeys.PublicKeyBytes)
            {
                using var server = ECDiffieHellman.Create();
                var serverPoint = answer.SessionPublic.ToByteArray();
                server.ImportParameters(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = serverPoint.AsSpan(1, 32).ToArray(),
                        Y = serverPoint.AsSpan(33, 32).ToArray(),
                    },
                });
                var shared = _ephemeral!.DeriveRawSecretAgreement(server.PublicKey);
                var okm = SessionSealKeys.Derive(shared, Baked.Key, Baked.KeyId, new ImplantId(Guid.Parse(ImplantId)));
                Session = (new Guid(okm.AsSpan(0, 16)), okm[16..48], okm[48..80]);
                _ephemeral.Dispose();
                _ephemeral = null;
            }
            return answer;
        }

        /// <summary>One session-sealed contact, raw: the caller reads the status.</summary>
        public async Task<HttpResponseMessage> PostSessionFramesAsync(bool offer, Frame[]? frames = null)
        {
            var handshake = new HandshakeRequest
            {
                Version = new ProtocolVersion { Major = 1, Minor = 0 },
                ImplantId = ImplantId,
            };
            if (offer)
                handshake.SessionPublic = ByteString.CopyFrom(new byte[SessionSealKeys.PublicKeyBytes]);
            var outbound = new List<Frame> { new() { Payload = ByteString.CopyFrom(handshake.ToByteArray()) } };
            if (frames is not null)
                outbound.AddRange(frames);

            var session = Session!.Value;
            var body = AesGcmEnvelope.WrapSession(
                SealedBody(++_counter, outbound), session.SessionId, session.RequestKey,
                AesGcmEnvelope.ContactRequestAad);
            LastSessionBody = System.Text.Encoding.UTF8.GetBytes(body);
            return await _http.PostAsync(
                _beaconUrl,
                new StringContent(body, System.Text.Encoding.UTF8, "text/plain"));
        }

        /// <summary>One ordinary contact under the agreed session keys.</summary>
        public async Task<List<Frame>> SessionContactAsync(Frame[]? frames = null)
        {
            using var sent = await PostSessionFramesAsync(offer: false, frames);
            var session = Session!.Value;

            // The fallback signal: the session this body named is gone, the
            // client's cue to offer a fresh agreement on its next cycle.
            if (sent.StatusCode == HttpStatusCode.Unauthorized)
            {
                Session = null;
                return new List<Frame>();
            }
            sent.EnsureSuccessStatusCode();
            var responseText = System.Text.Encoding.UTF8.GetString(
                await sent.Content.ReadAsByteArrayAsync()).Trim();
            var plain = AesGcmEnvelope.TryUnwrapSession(
                responseText, session.SessionId, session.ResponseKey, AesGcmEnvelope.ContactResponseAad);
            Assert.NotNull(plain);
            return ParseFrames(plain!);
        }

        /// <summary>A forged baked-key body: the bytes a captured key's holder makes.</summary>
        public async Task<HttpResponseMessage> RawBakedContactAsync(long counter, bool offer)
        {
            var handshake = new HandshakeRequest
            {
                Version = new ProtocolVersion { Major = 1, Minor = 0 },
                ImplantId = ImplantId,
            };
            if (offer)
                handshake.SessionPublic = ByteString.CopyFrom(new byte[SessionSealKeys.PublicKeyBytes]);
            using var content = new StringContent(
                AesGcmEnvelope.Wrap(
                    SealedBody(counter, new[] { new Frame { Payload = ByteString.CopyFrom(handshake.ToByteArray()) } }),
                    Baked.KeyId, Baked.Key, AesGcmEnvelope.ContactRequestAad),
                System.Text.Encoding.UTF8,
                "text/plain");
            return await _http.PostAsync(_beaconUrl, content);
        }

        /// <summary>An R2 body under a session id the caller names.</summary>
        public async Task<HttpResponseMessage> RawSessionContactAsync(
            Guid sessionId, long counter, HandshakeRequest handshake)
        {
            using var content = new StringContent(
                AesGcmEnvelope.WrapSession(
                    SealedBody(counter, new[] { new Frame { Payload = ByteString.CopyFrom(handshake.ToByteArray()) } }),
                    sessionId, Session!.Value.RequestKey, AesGcmEnvelope.ContactRequestAad),
                System.Text.Encoding.UTF8,
                "text/plain");
            return await _http.PostAsync(_beaconUrl, content);
        }

        public Task<HttpResponseMessage> PostRawAsync(byte[] body)
            => _http.PostAsync(_beaconUrl, new ByteArrayContent(body));

        private async Task<HttpResponseMessage> PostSealedBakedAsync(Frame[] frames)
        {
            var body = AesGcmEnvelope.Wrap(
                SealedBody(++_counter, frames), Baked.KeyId, Baked.Key, AesGcmEnvelope.ContactRequestAad);
            return await _http.PostAsync(
                _beaconUrl,
                new StringContent(body, System.Text.Encoding.UTF8, "text/plain"));
        }

        private byte[] OpenBaked(byte[] response)
        {
            var text = System.Text.Encoding.UTF8.GetString(response).Trim();
            var plain = AesGcmEnvelope.TryUnwrap(text, Baked.KeyId, Baked.Key, AesGcmEnvelope.ContactResponseAad);
            Assert.NotNull(plain);
            return plain!;
        }

        private byte[] SealedBody(long counter, IReadOnlyList<Frame> frames)
        {
            var encoded = Encode(frames);
            var plain = new byte[8 + encoded.Length];
            BinaryPrimitives.WriteInt64BigEndian(plain, counter);
            encoded.CopyTo(plain, 8);
            return plain;
        }

        private static void LeftAligned(byte[]? coordinate, Span<byte> slot)
        {
            if (coordinate is not { Length: > 0 })
                return;
            var source = coordinate.AsSpan(Math.Max(0, coordinate.Length - slot.Length));
            source.CopyTo(slot.Slice(slot.Length - source.Length));
        }

        public void Dispose() => _http.Dispose();

        private sealed class EnrollBody
        {
            public string ImplantId { get; set; } = string.Empty;
            public string EngagementId { get; set; } = string.Empty;
        }
    }

    // The varint-length-delimited frame codec the contract specifies -- the
    // same hand-rolled shape the other scratch clients keep.

    private static Frame TaskResultFrame(string taskId, Rod.V1.TaskOutcome outcome, string output)
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

    /// <summary>
    /// A real Kestrel teamserver: the envelope and enroll routes plus the
    /// operator API, with a logged-in operator client -- the same shape the
    /// envelope contact tests boot.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;
        public int HttpPort { get; private set; }
        public string EnrollUrl => $"http://127.0.0.1:{HttpPort}/implants/enroll";

        private string? _engagementId;

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
            await AuthenticatedHost.LoginAsync(env.Http);
            return env;
        }

        /// <summary>
        /// Creates a fresh engagement in the shape a pipeline build leaves
        /// behind: a deploy token minted for the artifact and a payload
        /// record carrying the token id beside a freshly minted envelope
        /// key, so an enrollment that redeems the token binds to the key.
        /// </summary>
        public async Task<(string EngagementId, string Secret, string BakedKey)> MintSealedArtifactShapeAsync()
        {
            var engagement = await Http.PostAsJsonAsync("/engagements",
                new { name = "session-" + Guid.NewGuid().ToString("N")[..8] });
            engagement.EnsureSuccessStatusCode();
            var created = await engagement.Content.ReadFromJsonAsync<EngagementBody>();
            Assert.NotNull(created);
            _engagementId = created!.EngagementId;
            var engagementId = Guid.Parse(_engagementId);

            var owner = (await Host.Services.GetRequiredService<Rod.CoreState.Engagements.IEngagementRepository>()
                .FindAsync(new EngagementId(engagementId)))!.OwnerId;
            var (keyId, key) = Rod.Transport.Payloads.AesGcmEnvelope.Mint();
            var tokens = Host.Services.GetRequiredService<Rod.CoreState.Deployment.IDeployTokenService>();
            var token = await tokens.MintAsync(
                new EngagementId(engagementId), owner, DateTimeOffset.UtcNow, 1, TimeSpan.FromHours(1));
            await Host.Services.GetRequiredService<IPayloadStore>().SaveAsync(new PayloadRecord(
                Guid.NewGuid(), engagementId, "Implant", "DotNet", "application/octet-stream",
                new string('a', 64), Array.Empty<byte>(), 0, DateTimeOffset.UtcNow,
                TokenId: token.Id.Value, EnvelopeKeyId: keyId, EnvelopeKey: key));

            return (_engagementId, token.Secret, Rod.Transport.Payloads.AesGcmEnvelope.Bake(keyId, key));
        }

        public async Task<(string TaskId, string Verb)> IssueTaskAsync(
            string engagementId, string implantId, string verb, string arguments)
        {
            var issued = await Http.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = implantId, Verb = verb, Arguments = arguments });
            issued.EnsureSuccessStatusCode();
            var body = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();
            Assert.NotNull(body);
            return (body!.TaskId, body.Verb);
        }

        public async Task<TaskBody?> GetTaskAsync(string engagementId, string taskId)
            => await Http.GetFromJsonAsync<TaskBody?>(
                $"/engagements/{engagementId}/tasks/{taskId}");

        public async ValueTask DisposeAsync()
        {
            Http?.Dispose();
            if (Host is not null)
                await Host.StopAsync();
            Host?.Dispose();
        }

        private sealed class EngagementBody
        {
            public string EngagementId { get; set; } = "";
        }

        private sealed class TaskIssuedBody
        {
            public string TaskId { get; set; } = "";
            public string Verb { get; set; } = "";
        }

        public sealed class TaskBody
        {
            public string Status { get; set; } = "";
            public string? Output { get; set; }
            public string? Outcome { get; set; }
        }
    }

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

    private static List<Frame> ParseFrames(byte[] body)
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
