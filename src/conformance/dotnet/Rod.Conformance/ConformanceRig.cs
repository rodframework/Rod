using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Pki;
using Rod.CoreState.Sessions;
using Rod.CoreState.Deployment;
using Rod.CoreState.Tasks;
using Rod.Audit;
using Rod.Transport;
using Rod.V1;
using Task = System.Threading.Tasks.Task;

namespace Rod.Conformance;

// The Tier 0 conformance harness (architecture.md Sec 8, the implant-reach
// contract): a rig that drives a candidate implant against a live teamserver
// and reports pass/fail per contract clause -- enroll shapes, handshake order,
// result/chunk discipline, signature verification, kill-date refusal
// (extending/implants.md). Pointing it at the reference implant passes;
// pointing it at a deliberately broken one fails with the violated clause
// named.

/// <summary>
/// Where a candidate phase points: the enroll URL to dial (the contact route
/// derives off the same front), the credential to redeem, and -- for the
/// kill-date phase -- the baked kill date the candidate must refuse to
/// outlive.
/// </summary>
public sealed record ConformanceTarget(
    string EnrollUrl,
    string DeployToken,
    DateTimeOffset? KillDate = null)
{
    /// <summary>The contact route hanging off the enroll URL's own front --
    /// the single-front shape every candidate dials.</summary>
    public string BeaconUrl
    {
        get
        {
            var front = new Uri(EnrollUrl);
            return $"{front.Scheme}://{front.Authority}/implants/beacon";
        }
    }
}

/// <summary>
/// The implant under test. A candidate may be an in-process loop (the rig's
/// own deliberately broken implants) or a spawned process (the reference
/// implant); the rig starts it per phase against a fresh target and stops it
/// between phases. <see cref="HasExited"/> reports whether the candidate has
/// stopped itself -- the observable half of the kill-date refusal clause.
/// The signature-verification phase probes over a live session, so a
/// candidate that speaks only the envelope is named there rather than probed.
/// </summary>
public interface IImplantCandidate : IDisposable
{
    /// <summary>Launch the candidate against the target; returns once started.</summary>
    Task StartAsync(ConformanceTarget target);

    /// <summary>Stop the candidate. Idempotent.</summary>
    Task StopAsync();

    /// <summary>True when the candidate stopped on its own (not via StopAsync).</summary>
    bool HasExited { get; }
}

/// <summary>One contract clause and how the candidate fared against it.</summary>
public sealed record ConformanceClause(string Clause, bool Passed, string Detail);

/// <summary>The per-clause outcome of one harness run.</summary>
public sealed record ConformanceReport(IReadOnlyList<ConformanceClause> Clauses)
{
    /// <summary>The clauses that failed, for the caller to name.</summary>
    public IReadOnlyList<ConformanceClause> Failed
        => Clauses.Where(c => !c.Passed).ToArray();

    public override string ToString()
        => string.Join(Environment.NewLine,
            Clauses.Select(c => $"{(c.Passed ? "PASS" : "FAIL")}  {c.Clause}: {c.Detail}"));
}

/// <summary>
/// One live teamserver plus the hostile tasking probe, and the clause battery
/// that drives a candidate against them. The main host is a real Kestrel
/// teamserver (plain HTTP: enroll, the envelope beacon, the WebSocket
/// stream); the probe is a second plain-HTTP endpoint serving the envelope
/// route that feeds an enrolled implant crafted tasking -- unsigned, wrongly
/// signed, signed for another implant, a correctly signed control, and a
/// replay of it -- and records what came back. The signature clause reads
/// the probe: a conforming implant refuses the hostile four and runs the
/// control.
/// </summary>
public sealed class ConformanceRig : IAsyncDisposable
{
    // The clause names are the contract; tests assert against them verbatim.
    public const string EnrollClause = "enroll.public-key-and-token";
    public const string HandshakeClause = "handshake.first-frame-ok";
    public const string RoundTripClause = "task.round-trip";
    public const string ChunkClause = "chunk.discipline";
    public const string SignatureClause = "signature.verification";
    public const string KillDateClause = "kill-date.refusal";

    private static readonly TimeSpan ObserveDeadline = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan KillDateGrace = TimeSpan.FromSeconds(8);

    private readonly IHost _host;
    private readonly WebApplication _probe;
    private readonly TaskingProbe _taskingProbe;
    private readonly IImplantRepository _implants;
    private readonly ISessionRegistry _sessions;
    private readonly EngagementService _engagements;
    private readonly TaskService _taskService;
    private readonly IArtifactStore _artifacts;
    private readonly ITaskRepository _taskRecords;
    private readonly OperatorId _operator;

    public int EnrollPort { get; }
    public int ProbePort { get; }
    public string EnrollUrl => $"http://127.0.0.1:{EnrollPort}/implants/enroll";
    public string ProbeEnrollUrl => $"http://127.0.0.1:{ProbePort}/implants/enroll";

    private ConformanceRig(
        IHost host, WebApplication probe, TaskingProbe taskingProbe,
        int enrollPort, int probePort)
    {
        _host = host;
        _probe = probe;
        _taskingProbe = taskingProbe;
        _implants = host.Services.GetRequiredService<IImplantRepository>();
        _sessions = host.Services.GetRequiredService<ISessionRegistry>();
        _engagements = host.Services.GetRequiredService<EngagementService>();
        _taskService = host.Services.GetRequiredService<TaskService>();
        _artifacts = host.Services.GetRequiredService<IArtifactStore>();
        _taskRecords = host.Services.GetRequiredService<ITaskRepository>();
        _operator = host.Services.GetRequiredService<IOperatorRepository>()
            .FindByHandleAsync("conformance").GetAwaiter().GetResult()!.Id;
        EnrollPort = enrollPort;
        ProbePort = probePort;
    }

    public static async Task<ConformanceRig> StartAsync()
    {
        var enrollPort = GetFreeTcpPort();
        var probePort = GetFreeTcpPort();
        var enrollUrl = $"http://127.0.0.1:{enrollPort}/implants/enroll";

        // The live teamserver: the transport core on a real Kestrel host --
        // plain HTTP carrying enroll, the envelope beacon, and the WebSocket
        // stream on one listener. The harness observes outcomes through the
        // core services the operator API drives. Both hosts here run with
        // their console logging cleared: a rig run's observable is the
        // per-clause report, and the standalone runner prints exactly that
        // and nothing else on stdout.
        var host = TransportHost.CreateHostBuilder().ConfigureWebHost(web => web
                .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(enrollPort)))
            .ConfigureLogging(logging => logging.ClearProviders())
            .Build();

        // The harness's operator identity: tasking must attribute to someone.
        {
            var operators = host.Services.GetRequiredService<IOperatorRepository>();
            await operators.SaveAsync(Operator.Register(
                OperatorId.New(), "conformance", DateTimeOffset.UtcNow,
                DeploymentRole.Member));
        }
        await host.StartAsync();

        // The rig fronts are plain HTTP, so no candidate pins a CA; the
        // authority here exists for the tasking probe's signatures.
        var ca = host.Services.GetRequiredService<IImplantCertificateAuthority>();

        // The hostile tasking probe: a second plain-HTTP endpoint playing a
        // front. It forwards the enroll route to the live rig verbatim -- the
        // candidate enrolls for real through the front it keeps dialing --
        // and answers the contact route itself, feeding crafted tasking one
        // contact at a time and recording the results. The identity posture
        // under test is the tasking signature, which travels inside the
        // frames; a candidate that dials one front for everything (the only
        // shape a build bakes now) still runs the whole clause through it.
        var taskingProbe = new TaskingProbe(ca);
        var probe = Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder();
        probe.Logging.ClearProviders();
        probe.Services.AddSingleton(taskingProbe);
        probe.WebHost.ConfigureKestrel(kestrel => kestrel.ListenLocalhost(probePort));
        var probeApp = probe.Build();
        probeApp.MapPost("/implants/enroll", async (HttpContext http) =>
        {
            using var body = new MemoryStream();
            await http.Request.Body.CopyToAsync(body);
            using var client = new HttpClient();
            using var forwarded = new ByteArrayContent(body.ToArray());
            forwarded.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(
                http.Request.ContentType ?? "application/json");
            using var answer = await client.PostAsync(enrollUrl, forwarded);
            http.Response.StatusCode = (int)answer.StatusCode;
            await answer.Content.CopyToAsync(http.Response.Body);
        });
        probeApp.MapPost("/implants/beacon", async (HttpContext http) =>
        {
            using var body = new MemoryStream();
            await http.Request.Body.CopyToAsync(body);
            var inbound = EnvelopeProbeCodec.Parse(body.ToArray());
            var session = taskingProbe.SessionFor(inbound);
            var outbound = session.Handle(inbound);
            await http.Response.Body.WriteAsync(EnvelopeProbeCodec.Encode(outbound));
        });
        await probeApp.StartAsync();

        return new ConformanceRig(host, probeApp, taskingProbe, enrollPort, probePort);
    }

    /// <summary>
    /// Runs the clause battery against one candidate, in three phases: the
    /// live server (enroll, handshake, tasking, chunking), the probe
    /// (signature verification), and a past kill date (self-termination
    /// before any contact).
    /// </summary>
    public async Task<ConformanceReport> RunAsync(IImplantCandidate candidate)
    {
        var clauses = new List<ConformanceClause>();

        // ---- Phase 1: the live teamserver.
        var engagement = await MintEngagementTokenAsync();
        try
        {
            await candidate.StartAsync(new ConformanceTarget(
                EnrollUrl, engagement.Token));

            var enrolled = await UntilAsync(ObserveDeadline, async () =>
                (await _implants.ListByEngagementAsync(engagement.EngagementId)).Count > 0);
            clauses.Add(new ConformanceClause(EnrollClause, enrolled,
                enrolled ? "enrolled with an ECDSA P-256 SPKI public key via the one-use token"
                         : "no enrollment appeared in the engagement within the deadline"));

            var online = await UntilAsync(ObserveDeadline, async () =>
                (await _sessions.ListActiveAsync(engagement.EngagementId)).Count > 0);
            clauses.Add(new ConformanceClause(HandshakeClause, online,
                online ? "the first frame was a handshake and the session opened"
                         : "no session opened: the server never accepted a handshake-first contact"));

            if (!online)
            {
                // Without a session there is nothing downstream to observe;
                // name the cascade rather than waiting out every deadline.
                clauses.Add(new ConformanceClause(RoundTripClause, false, "no live session (handshake refused)"));
                clauses.Add(new ConformanceClause(ChunkClause, false, "no live session (handshake refused)"));
            }
            else
            {
                var implant = (await _implants.ListByEngagementAsync(engagement.EngagementId))[0].Id;

                var marker = "rod-conformance-" + Guid.NewGuid().ToString("N")[..8];
                var issued = await _taskService.IssueAsync(new IssueTaskCommand(
                    engagement.EngagementId, implant, _operator, "shell.exec", $"echo {marker}"));
                var completed = await UntilAsync(ObserveDeadline, async () =>
                {
                    var task = await _taskRecords.FindAsync(issued.TaskId);
                    return task is { Status: Rod.CoreState.Tasks.TaskStatus.Completed }
                        && task.Outcome == Rod.CoreState.Tasks.TaskOutcome.Succeeded
                        && task.Output?.Contains(marker) == true;
                });
                clauses.Add(new ConformanceClause(RoundTripClause, completed,
                    completed ? "a shell.exec task completed with its own marker in the output"
                             : "the shell.exec task did not complete Succeeded with the marker in its output"));

                var content = RandomNumberGenerator.GetBytes(1536 * 1024);
                var path = Path.Combine(Path.GetTempPath(),
                    "rod-conformance-pull-" + Guid.NewGuid().ToString("N") + ".bin");
                await File.WriteAllBytesAsync(path, content);
                try
                {
                    var pull = await _taskService.IssueAsync(new IssueTaskCommand(
                        engagement.EngagementId, implant, _operator, "file.pull", path));
                    var artifact = await UntilAsync(ObserveDeadline, async () =>
                    {
                        var stored = (await _artifacts.ForTaskAsync(pull.TaskId.Value))
                            .FirstOrDefault(a => a.Name == Path.GetFileName(path));
                        return stored is { Content.Length: > 0 } && stored.Content.AsSpan().SequenceEqual(content);
                    });
                    clauses.Add(new ConformanceClause(ChunkClause, artifact,
                        artifact ? "the file.pull artifact reassembled byte-for-byte in strict sequence"
                                 : "the exfil chunk run never reassembled into the byte-equal artifact (sequence discipline violated, or no chunks arrived)"));
                }
                finally
                {
                    try { File.Delete(path); } catch { }
                }
            }
        }
        finally
        {
            await candidate.StopAsync();
        }

        // ---- Phase 2: the hostile tasking probe.
        {
            var probeEngagement = await MintEngagementTokenAsync();
            _taskingProbe.Reset();
            try
            {
                // The candidate's whole dial is the probe front: enrollment
                // forwards to the live rig, contacts feed the hostile probe.
                await candidate.StartAsync(new ConformanceTarget(
                    ProbeEnrollUrl, probeEngagement.Token));
                var verdict = await _taskingProbe.AwaitVerdictAsync(ObserveDeadline);
                clauses.Add(new ConformanceClause(SignatureClause, verdict.Passed, verdict.Detail));
            }
            finally
            {
                await candidate.StopAsync();
            }
        }

        // ---- Phase 3: the past kill date.
        var killEngagement = await MintEngagementTokenAsync();
        try
        {
            await candidate.StartAsync(new ConformanceTarget(
                EnrollUrl, killEngagement.Token,
                KillDate: DateTimeOffset.UtcNow.AddHours(-1)));
            await Task.Delay(KillDateGrace);
            var ranAnyway =
                (await _implants.ListByEngagementAsync(killEngagement.EngagementId)).Count > 0;
            var stayed = !ranAnyway && candidate.HasExited;
            clauses.Add(new ConformanceClause(KillDateClause, stayed,
                stayed ? "refused to run past the baked kill date: no enrollment, no contact, exited"
                         : "the candidate ran past its kill date (enrolled or stayed alive anyway)"));
        }
        finally
        {
            await candidate.StopAsync();
        }

        return new ConformanceReport(clauses);
    }

    public async ValueTask DisposeAsync()
    {
        await _probe.DisposeAsync();
        await _host.StopAsync();
        _host.Dispose();
    }

    private async Task<(EngagementId EngagementId, string Token)> MintEngagementTokenAsync()
    {
        var created = await _engagements.CreateEngagementAsync(
            new CreateEngagementCommand(_operator, "conformance-" + Guid.NewGuid().ToString("N")[..8]));
        var minted = await _engagements.MintDeployTokenAsync(
            new MintDeployTokenCommand(created.EngagementId, _operator));
        return (created.EngagementId, minted.Secret);
    }

    private static async Task<bool> UntilAsync(TimeSpan deadline, Func<Task<bool>> condition)
    {
        var end = DateTimeOffset.UtcNow + deadline;
        while (DateTimeOffset.UtcNow < end)
        {
            if (await condition())
                return true;
            await Task.Delay(250);
        }
        return false;
    }

    private static int GetFreeTcpPort()
    {
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}

/// <summary>The probe's verdict on the signature clause.</summary>
public sealed record SignatureVerdict(bool Passed, string Detail);

/// <summary>
/// Records the crafted tasking outcomes: for each of unsigned, wrongly
/// signed, and signed-for-another-implant, a conforming implant reports the
/// task Failed and runs nothing; for the correctly signed control it runs
/// the command. A candidate that skips verification executes the crafted
/// tasking and is named by which case betrayed it.
/// </summary>
internal sealed class TaskingProbe
{
    private static readonly TimeSpan ResultWait = TimeSpan.FromSeconds(20);

    private readonly IImplantCertificateAuthority _ca;
    private readonly object _gate = new();
    private readonly Dictionary<string, Rod.V1.TaskOutcome> _results = new();
    // Whether the probed candidate negotiated the replay-nonce arm: the
    // replay case's expectation depends on it (refusal when negotiated;
    // the duplicate simply runs again in the pre-arm posture, which the tier
    // ladder makes the implant author's choice, not a failure).
    private bool _negotiated;

    internal TaskingProbe(IImplantCertificateAuthority ca)
    {
        _ca = ca;
    }

    /// <summary>Clears the recorded results for a fresh candidate phase.</summary>
    public void Reset()
    {
        lock (_gate)
        {
            _results.Clear();
            _negotiated = false;
            _sessions.Clear();
        }
    }

    internal byte[] SignFor(
        string implantId, string taskId, string verb, string arguments, ulong? nonce)
        => _ca.SignTasking(implantId, taskId, verb, arguments, nonce);

    /// <summary>
    /// Waits for every crafted task's outcome (or the deadline), then renders
    /// the verdict naming the first betraying case.
    /// </summary>
    public async Task<SignatureVerdict> AwaitVerdictAsync(TimeSpan deadline)
    {
        var end = DateTimeOffset.UtcNow + deadline;
        while (DateTimeOffset.UtcNow < end)
        {
            lock (_gate)
            {
                if (_results.Count == 5)
                    return Verdict();
            }
            await Task.Delay(250);
        }
        lock (_gate)
            return Verdict();
    }

    private SignatureVerdict Verdict()
    {
        var cases = new (string Kind, Rod.V1.TaskOutcome Expected)[]
        {
            ("unsigned tasking", Rod.V1.TaskOutcome.Failed),
            ("wrongly signed tasking", Rod.V1.TaskOutcome.Failed),
            ("tasking signed for another implant", Rod.V1.TaskOutcome.Failed),
            ("correctly signed control", Rod.V1.TaskOutcome.Succeeded),
            // Refusing the duplicate is only demanded of a candidate that
            // negotiated the replay-nonce arm; without it the duplicate is the
            // pre-arm posture the ladder leaves optional.
            ("replayed tasking", _negotiated ? Rod.V1.TaskOutcome.Failed : Rod.V1.TaskOutcome.Succeeded),
        };
        foreach (var (kind, expected) in cases)
        {
            if (!_results.TryGetValue(kind, out var outcome))
                return new SignatureVerdict(false, $"no result arrived for the {kind} probe");
            if (outcome != expected)
                return new SignatureVerdict(false,
                    expected == Rod.V1.TaskOutcome.Failed
                        ? $"executed the {kind}: it reported {outcome} instead of refusing it"
                        : $"refused the {kind}: it reported {outcome} instead of running it");
        }
        return new SignatureVerdict(true, _negotiated
            ? "refused unsigned, wrongly signed, cross-implant, and replayed tasking; ran the signed control"
            : "refused unsigned, wrongly signed, and cross-implant tasking; ran the signed control (no replay-nonce arm negotiated)");
    }

    /// <summary>
    /// The per-candidate session the envelope probe holds: one crafted case
    /// rides each contact's response, each awaited for its result on a later
    /// request; the replay case re-delivers the control frame verbatim once
    /// its result has been observed.
    /// </summary>
    public ProbeSession SessionFor(IReadOnlyList<Frame> inbound)
    {
        lock (_gate)
        {
            foreach (var frame in inbound)
            {
                HandshakeRequest handshake;
                try
                {
                    handshake = HandshakeRequest.Parser.ParseFrom(frame.Payload);
                }
                catch (InvalidProtocolBufferException)
                {
                    continue;
                }
                if (_sessions.TryGetValue(handshake.ImplantId, out var existing))
                    return existing;
                var session = new ProbeSession(this, handshake.ImplantId, handshake.ReplayNonces);
                _sessions[handshake.ImplantId] = session;
                return session;
            }
            // A contact with no readable handshake names no session; the
            // empty answers are the outcome.
            return new ProbeSession(this, string.Empty, false);
        }
    }

    internal void Record(string kind, Rod.V1.TaskOutcome outcome)
    {
        lock (_gate)
            _results[kind] = outcome;
    }

    internal void NoteNegotiated(bool negotiated)
    {
        lock (_gate)
            _negotiated = negotiated;
    }

    private readonly Dictionary<string, ProbeSession> _sessions = new();
}

/// <summary>One candidate's walk through the crafted cases, one per contact.</summary>
internal sealed class ProbeSession
{
    private static readonly string[] Cases =
        ["unsigned tasking", "wrongly signed tasking", "tasking signed for another implant",
         "correctly signed control", "replayed tasking"];

    private readonly TaskingProbe _probe;
    private readonly string _implantId;
    private readonly bool _negotiated;
    private readonly Dictionary<string, TaskRequest> _delivered = new();
    private TaskRequest? _control;
    private int _caseIndex;
    // The case whose result this contact cycle awaits: the replay re-delivers
    // the control's frame verbatim, so matching by task id alone would
    // overwrite the control's own verdict with the replay's refusal.
    private (string Kind, string TaskId)? _awaited;

    internal ProbeSession(TaskingProbe probe, string implantId, bool negotiated)
    {
        _probe = probe;
        _implantId = implantId;
        _negotiated = negotiated;
        _probe.NoteNegotiated(negotiated);
    }

    /// <summary>One contact: record any awaited results, answer the next case.</summary>
    public List<Frame> Handle(IReadOnlyList<Frame> inbound)
    {
        var outbound = new List<Frame>();

        // Every contact opens with the handshake; echo OK and mirror the
        // replay-nonce negotiation so a strict candidate stays strict against
        // the probe too.
        foreach (var frame in inbound)
        {
            try
            {
                var handshake = HandshakeRequest.Parser.ParseFrom(frame.Payload);
                outbound.Add(new Frame
                {
                    Payload = ByteString.CopyFrom(new HandshakeResponse
                    {
                        Status = HandshakeStatus.Ok,
                        Version = new ProtocolVersion { Major = 1, Minor = 0 },
                        EngagementId = string.Empty,
                        ReplayNonces = _negotiated,
                    }.ToByteArray()),
                });
                break;
            }
            catch (InvalidProtocolBufferException)
            {
                // Not the handshake; keep looking.
            }
        }

        // Results for the case this cycle awaits.
        foreach (var frame in inbound)
        {
            TaskResult result;
            try
            {
                result = TaskResult.Parser.ParseFrom(frame.Payload);
            }
            catch (InvalidProtocolBufferException)
            {
                continue;
            }
            if (_awaited is { } awaited && awaited.TaskId == result.TaskId)
            {
                _probe.Record(awaited.Kind, result.Outcome);
                _awaited = null;
            }
        }

        // The next crafted case, replay included, rides this response.
        if (_caseIndex < Cases.Length)
        {
            var kind = Cases[_caseIndex];
            TaskRequest request;
            if (kind == "replayed tasking")
            {
                // The control's result must have landed before its frame is
                // worth replaying; otherwise wait for the next contact.
                if (_control is null)
                    return outbound;
                request = _control;
            }
            else
            {
                request = new TaskRequest
                {
                    TaskId = Guid.NewGuid().ToString(),
                    Verb = "shell.exec",
                    Arguments = "echo probe-" + Guid.NewGuid().ToString("N")[..8],
                };
                if (_negotiated)
                    request.TaskNonce = (ulong)(1000 + _caseIndex);
                switch (kind)
                {
                    case "wrongly signed tasking":
                        request.Signature = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(256));
                        break;
                    case "tasking signed for another implant":
                        // Validly signed by the real CA, but over a tuple naming a
                        // different implant: the verifier's own id must reject it.
                        request.Signature = ByteString.CopyFrom(_probe.SignFor(
                            Guid.NewGuid().ToString(), request.TaskId, request.Verb, request.Arguments,
                            _negotiated ? request.TaskNonce : null));
                        break;
                    case "correctly signed control":
                        request.Signature = ByteString.CopyFrom(_probe.SignFor(
                            _implantId, request.TaskId, request.Verb, request.Arguments,
                            _negotiated ? request.TaskNonce : null));
                        _control = request;
                        break;
                }
            }

            _delivered[kind] = request;
            _caseIndex++;
            _awaited = (kind, request.TaskId);
            outbound.Add(new Frame { Payload = ByteString.CopyFrom(request.ToByteArray()) });
        }

        return outbound;
    }
}

/// <summary>The envelope codec the probe's HTTP surface speaks.</summary>
internal static class EnvelopeProbeCodec
{
    public static byte[] Encode(IReadOnlyList<Frame> frames)
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
}
