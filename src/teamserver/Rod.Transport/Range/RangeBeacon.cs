using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Rod.Transport.Endpoints;
using Rod.V1;

namespace Rod.Transport.Range;

// One scripted range beacon (architecture.md Sec 15.3): a protocol-real
// implant client -- the same enroll, handshake, tasking-verification, and
// result grammar the reference implant speaks -- driven by a canned script
// instead of a target's filesystem. The wire is real end to end (the frames,
// the signatures, the audit arcs a contact produces); only the payload
// behind each verb is simulated, and every answer says so.

/// <summary>The verbs the script answers; everything else refuses with the
/// same grammar the real implant's refusal uses.</summary>
internal static class RangeScript
{
    public static readonly IReadOnlyList<string> Capabilities =
        ["shell.exec", "fs.list", "proc.list", "recon.hostenum", "beacon.sleep"];

    /// <summary>Answers one verified task. The outputs are plausible-shaped
    /// and clearly simulated -- structured enough that the generic panels
    /// (the file table, the process table, the topology) exercise their
    /// parsing, honest enough that no transcript mistakes them for target
    /// output.</summary>
    public static (TaskOutcome Outcome, string Output, double? SleepSeconds) Answer(
        string hostname,
        string os,
        string arch,
        TaskRequest request)
    {
        switch (request.Verb)
        {
            case "shell.exec":
                return (TaskOutcome.Succeeded,
                    $"{hostname}:~$ {request.Arguments}\n(simulated range shell output)\n",
                    null);
            case "fs.list":
                return (TaskOutcome.Succeeded, string.Join("\n",
                    $"{{\"name\":\"etc\",\"dir\":true,\"size\":4096}}",
                    $"{{\"name\":\"home\",\"dir\":true,\"size\":4096}}",
                    $"{{\"name\":\"rod-range.txt\",\"size\":{hostname.Length},\"mtime\":\"2026-01-01T00:00:00Z\"}}",
                    string.Empty),
                    null);
            case "proc.list":
                return (TaskOutcome.Succeeded, string.Join("\n",
                    "{\"pid\":1,\"image\":\"systemd\",\"ppid\":0,\"user\":\"root\"}",
                    $"{{\"pid\":4242,\"image\":\"rod-range-beacon\",\"ppid\":1,\"user\":\"range\"}}",
                    string.Empty),
                    null);
            case "recon.hostenum":
                return (TaskOutcome.Succeeded,
                    $"{{\"host\":\"{hostname}\",\"os\":\"{os}\",\"arch\":\"{arch}\"}}\n",
                    null);
            case "beacon.sleep":
                if (request.Arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries) is not { Length: > 0 } words
                    || !double.TryParse(words[0], out var seconds) || seconds < 0 || seconds > 86400)
                    return (TaskOutcome.Failed, $"invalid sleep interval: {request.Arguments}", null);
                return (TaskOutcome.Succeeded, $"sleep adjusted to {seconds}s (range beacon)", seconds);
            default:
                return (TaskOutcome.Failed, $"no handler for the verb: {request.Verb}", null);
        }
    }
}

/// <summary>Where one beacon is in its lifecycle, as the status read
/// reports it.</summary>
internal enum RangeBeaconState
{
    Pending,
    Enrolling,
    Contacting,
    Dark,
    Stopped,
    Failed,
}

/// <summary>
/// One scripted beacon: enroll (Tier 0 half one), then the envelope POST
/// cycle (half two) at its cadence until stopped. Tasking verification is
/// the real client rule -- RSASSA-PSS over the canonical tuple against the
/// enrollment CA chain, with the replay-nonce floor -- so a range exercises
/// the platform's signing path, not a bypass of it.
/// </summary>
internal sealed class RangeBeacon
{
    private readonly HttpClient _http;
    private readonly Uri _base;
    private readonly string _tokenSecret;
    private readonly double _sleepSeconds;
    private readonly double _jitterSeconds;
    private readonly TimeSpan? _goDarkAfter;
    private readonly TimeSpan _darkFor;

    private readonly TaskNonceFloor _nonces = new();
    private readonly object _gate = new();
    private string? _implantId;
    private X509Certificate2[] _cas = [];
    private bool _nonceArm;

    public RangeBeacon(
        HttpClient http,
        Uri @base,
        string tokenSecret,
        string hostname,
        string os,
        string arch,
        double sleepSeconds,
        double jitterSeconds,
        TimeSpan? goDarkAfter = null,
        TimeSpan darkFor = default)
    {
        _http = http;
        _base = @base;
        _tokenSecret = tokenSecret;
        Hostname = hostname;
        Os = os;
        Arch = arch;
        _sleepSeconds = sleepSeconds;
        _jitterSeconds = jitterSeconds;
        _goDarkAfter = goDarkAfter;
        _darkFor = darkFor;
    }

    public string Hostname { get; }
    public string Os { get; }
    public string Arch { get; }

    public RangeBeaconState State { get; private set; } = RangeBeaconState.Pending;
    public string? ImplantId => _implantId;
    public long Contacts { get; private set; }
    public long Results { get; private set; }
    public string? Error { get; private set; }

    /// <summary>
    /// The beacon's whole run: enroll, then the contact loop until cancelled.
    /// An optional <paramref name="enrollGate"/> bounds only the enrollment
    /// burst -- a fleet enrolls in waves without the gate ever holding a
    /// beacon's lifetime, which would stall the whole fleet at the gate's
    /// width.
    /// </summary>
    public async Task RunAsync(
        SemaphoreSlim? enrollGate = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            State = RangeBeaconState.Enrolling;
            if (enrollGate is null)
            {
                await EnrollAsync(cancellationToken);
            }
            else
            {
                await enrollGate.WaitAsync(cancellationToken);
                try
                {
                    await EnrollAsync(cancellationToken);
                }
                finally
                {
                    enrollGate.Release();
                }
            }

            State = RangeBeaconState.Contacting;
            await ContactLoopAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            State = RangeBeaconState.Stopped;
        }
        catch (Exception failure)
        {
            // A beacon that cannot continue says so and stops: the roster
            // will age it out the way it ages any silent implant out.
            State = RangeBeaconState.Failed;
            Error = failure.Message;
        }
    }

    private async Task ContactLoopAsync(CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var nextSleep = _sleepSeconds;
        // The results a cycle's tasking produced ride the NEXT cycle's
        // body -- the poll discipline the contract sets (MinimalImplant's
        // own shape): a contact carries the handshake plus whatever the
        // previous contact left owed.
        var pending = new List<Frame>();
        while (!cancellationToken.IsCancellationRequested)
        {
            if (_goDarkAfter is { } dark && DateTimeOffset.UtcNow - started >= dark)
            {
                // The beacon-lost leg: stop contacting until the roster
                // gives the implant up, then come back as the same
                // identity -- exactly what a real poll implant that lost
                // its network and found it again does.
                State = RangeBeaconState.Dark;
                await Task.Delay(_darkFor, cancellationToken);
                started = DateTimeOffset.UtcNow;
                State = RangeBeaconState.Contacting;
            }

            var (owed, retuned) = await ContactAsync(pending, cancellationToken);
            pending = owed;
            if (retuned is { } seconds)
                nextSleep = Math.Clamp(seconds, 1, 86400);
            await Task.Delay(
                TimeSpan.FromSeconds(nextSleep + Random.Shared.NextDouble() * _jitterSeconds),
                cancellationToken);
        }
    }

    private async Task EnrollAsync(CancellationToken cancellationToken)
    {
        // The enrollment keypair: ECDSA P-256, the public half enrolled as
        // SPKI base64 -- the reference client's exact shape.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var response = await _http.PostAsJsonAsync(
            new Uri(_base, "/implants/enroll"),
            new
            {
                deployTokenSecret = _tokenSecret,
                publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
                hostname = Hostname,
                os = Os,
                arch = Arch,
                sleepSeconds = _sleepSeconds,
                jitterSeconds = _jitterSeconds,
            },
            cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = await System.Text.Json.JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        var root = document.RootElement;
        lock (_gate)
        {
            _implantId = root.GetProperty("implantId").GetString()
                ?? throw new InvalidOperationException("the enroll response carried no implant id");
            _cas = root.GetProperty("caChain").EnumerateArray()
                .Select(b64 => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(b64.GetString()!)))
                .ToArray();
        }
    }

    /// <summary>One contact cycle: the handshake plus the owed results out,
    /// the response's tasking answered into the next cycle's owed set (and a
    /// beacon.sleep retune, if the tasking carried one).</summary>
    private async Task<(List<Frame> Owed, double? Retuned)> ContactAsync(
        List<Frame> owed,
        CancellationToken cancellationToken)
    {
        var outbound = new List<Frame>
        {
            new()
            {
                Payload = ByteString.CopyFrom(new HandshakeRequest
                {
                    Version = new ProtocolVersion { Major = 1, Minor = 0 },
                    ImplantId = ImplantId,
                    Capabilities = { RangeScript.Capabilities },
                    ReplayNonces = true,
                }.ToByteArray()),
            },
        };
        outbound.AddRange(owed);

        var response = await _http.PostAsync(
            new Uri(_base, "/implants/beacon"),
            new ByteArrayContent(EnvelopeFraming.Encode(outbound)),
            cancellationToken);
        response.EnsureSuccessStatusCode();
        var inbound = EnvelopeFraming.Parse(await response.Content.ReadAsByteArrayAsync(cancellationToken));
        Contacts++;

        if (inbound.Count == 0)
            return ([], null);
        var handshake = HandshakeResponse.Parser.ParseFrom(inbound[0].Payload);
        if (handshake.Status != HandshakeStatus.Ok)
            throw new InvalidOperationException($"the listener refused the handshake: {handshake.Status}");
        _nonceArm = handshake.ReplayNonces;

        var next = new List<Frame>();
        double? retuned = null;
        foreach (var frame in inbound.Skip(1))
        {
            if (frame.Kind == FrameKind.ChannelInput)
                continue; // No channel verb advertised: input never routes here.
            var request = TaskRequest.Parser.ParseFrom(frame.Payload);
            if (!VerifyTasking(request))
            {
                next.Add(Result(request, TaskOutcome.Failed, "rejected"));
                continue;
            }

            var (outcome, output, sleep) = RangeScript.Answer(Hostname, Os, Arch, request);
            if (sleep is { } seconds)
                retuned = seconds;
            next.Add(Result(request, outcome, output));
        }

        Results += next.Count;
        return (next, retuned);
    }

    private static Frame Result(TaskRequest request, TaskOutcome outcome, string output)
        => new()
        {
            Kind = FrameKind.TaskResult,
            Payload = ByteString.CopyFrom(new TaskResult
            {
                TaskId = request.TaskId,
                Outcome = outcome,
                Output = output,
            }.ToByteArray()),
        };

    /// <summary>
    /// The client's tasking verification, the contract's Tier 1 rule:
    /// RSASSA-PSS over SHA-256 on the canonical length-prefixed tuple (the
    /// implant id, task id, verb, arguments, and the nonce when present),
    /// verified against the enrollment CA chain, then the replay-nonce
    /// floor -- a nonce at or below the accepted floor is a replayed frame,
    /// and nonce-less tasking is refused once the arm was negotiated.
    /// </summary>
    private bool VerifyTasking(TaskRequest request)
    {
        if (request.Signature.Length == 0)
            return false;

        using var canonical = new MemoryStream();
        string[] fields = request.HasTaskNonce
            ? [ImplantId!, request.TaskId, request.Verb, request.Arguments, request.TaskNonce.ToString()]
            : [ImplantId!, request.TaskId, request.Verb, request.Arguments];
        foreach (var value in fields)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(value);
            canonical.Write(BitConverter.GetBytes((uint)bytes.Length), 0, 4);
            canonical.Write(bytes, 0, bytes.Length);
        }
        var signed = canonical.ToArray();

        foreach (var ca in _cas)
        {
            using var rsa = ca.GetRSAPublicKey();
            if (rsa is null || !rsa.VerifyData(
                    signed, request.Signature.ToByteArray(),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                continue;

            if (request.HasTaskNonce)
            {
                if (_nonces.IsReplay(request.TaskNonce))
                    return false;
                _nonces.Observed(request.TaskNonce);
                return true;
            }
            return !_nonceArm;
        }
        return false;
    }

    /// <summary>The accepted-nonce floor, monotonic across the beacon's run.</summary>
    private sealed class TaskNonceFloor
    {
        private ulong _highest;

        public bool IsReplay(ulong nonce) => nonce <= _highest;

        public void Observed(ulong nonce)
        {
            if (nonce > _highest)
                _highest = nonce;
        }
    }
}
