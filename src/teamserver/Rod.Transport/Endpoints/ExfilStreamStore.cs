using Rod.V1;

namespace Rod.Transport.Endpoints;

// The shared bounded reassembly for exfil uploads (architecture.md Sec 15.3,
// ADR-010 -- the upload arm). One store per teamserver process, owned by the
// BeaconIngest singleton and reached through every carriage's connection
// ingest: a run that spans contacts, connections, or carriages reassembles
// into the same stream, so an interrupted upload resumes from the bytes the
// server already holds instead of restarting.
//
// Placement mirrors the download arm's client-side rule (session.rs): every
// offset-bearing chunk places at its absolute position -- an
// already-covered duplicate is a no-op, offset 0 over a partial hold restarts
// the run, and a chunk past a gap stays unplaced until the sender re-serves
// from the seam the progress report names. Offset-less chunks (community
// implants, the pre-resume shape) keep the strict sequence discipline the
// per-connection reassembler always ran; a stream's first chunk decides its
// mode.
//
// The bounds are a memory-DoS guard, not an input-validation convenience, and
// moving them off the connection (where N connections could each hold the
// full set) to one shared store tightens the global ceiling while leaving the
// per-stream caps as they were: 64 MiB per stream (1 MiB for the DNS-origin
// arm, whose upload grammar is the slow wire's), 16 streams, and idle
// eviction so an abandoned run cannot pin one -- the DnsBeaconBridge's enroll
// and staged stores are the shape this follows. The cap push-out is LRU and
// never evicts the stream a chunk in hand belongs to, so spoofed debris
// occupying the map cannot starve a live run's chunks.

/// <summary>
/// Reassembles exfil chunk streams keyed by (task id, artifact name) across
/// connections and carriages. Thread-safe: every connection ingest and the
/// DNS bridge write through the one gate.
/// </summary>
internal sealed class ExfilStreamStore
{
    /// <summary>The per-stream byte cap for the frame carriages' runs.</summary>
    public const int FrameStreamBytes = 64 * 1024 * 1024;

    /// <summary>
    /// The per-stream byte cap for DNS-originated runs: the datagram upload
    /// grammar is the slowest wire the platform carries, so its runs are
    /// bounded far below the frame paths' ceiling.
    /// </summary>
    public const int DnsStreamBytes = 1024 * 1024;

    /// <summary>Concurrent open streams across every carriage.</summary>
    public const int MaxOpenStreams = 16;

    /// <summary>
    /// A stream that has not heard a chunk in this window is abandoned --
    /// dropped mid-run uploads and debris alike leave on idle, not only on
    /// completion or the caps.
    /// </summary>
    public static readonly TimeSpan IdleEviction = TimeSpan.FromMinutes(10);

    // First-wins ledger for completed runs: a re-sent terminal slice (a
    // response lost after the server placed the whole run) must not
    // materialize a second artifact, the same tolerance the delivery ledger
    // gives DNS reports. Entries leave on the idle window, oldest-first.
    private const int MaxCompletedMarks = 512;

    /// <summary>What Append did with a chunk.</summary>
    public enum AppendOutcome
    {
        /// <summary>The chunk placed (or duplicated a placed range); the run continues.</summary>
        Buffered,

        /// <summary>The terminal chunk closed a complete run; bytes available.</summary>
        Completed,

        /// <summary>The chunk could not place (a gap ahead of the held bytes, or a mode/cap violation); the stream keeps its state.</summary>
        Unplaced,

        /// <summary>The stream itself is gone (cap overflow, sequence violation, hash mismatch, or a completed-run duplicate).</summary>
        Dropped,
    }

    /// <summary>Append's outcome plus the stream's held-byte seam for progress reporting.</summary>
    public sealed record AppendResult(AppendOutcome Outcome, ulong HeldBytes, Reassembled? Reassembled);

    /// <summary>
    /// The reassembled artifact payload of a completed run: the name and
    /// content type the implant declared plus the concatenated bytes of the
    /// stream.
    /// </summary>
    public sealed record Reassembled(string Name, string ContentType, byte[] Data);

    private readonly object _gate = new();
    private readonly TimeProvider _clock;
    private readonly Dictionary<Key, Stream> _streams = new();
    private readonly Dictionary<Key, long> _completed = new();
    private readonly List<Key> _completedOrder = new();

    private readonly record struct Key(Guid TaskId, string Name);

    private enum Mode
    {
        /// <summary>Offset-less chunks, the pre-resume strict sequence discipline.</summary>
        Legacy,

        /// <summary>Offset-bearing chunks, the resumable placement rule.</summary>
        Resume,
    }

    private sealed class Stream(string name, string contentType, Mode mode)
    {
        public string Name { get; } = name;
        public string ContentType { get; } = contentType;
        public Mode Mode { get; } = mode;
        public List<byte> Data { get; } = new();
        public ulong? NextSequence { get; set; }
        public byte[]? DeclaredSha { get; set; }
        public DateTimeOffset Touched { get; set; }
    }

    public ExfilStreamStore(TimeProvider clock)
        => _clock = clock;

    /// <summary>
    /// Adds one chunk. The name/content-type/data validation the
    /// per-connection reassembler ran is unchanged; a completed run's
    /// duplicate answers Dropped (first-wins) so a re-sent terminal cannot
    /// double-materialize the artifact.
    /// </summary>
    public AppendResult Append(Guid taskId, ExfilChunk chunk, int maxStreamBytes)
    {
        lock (_gate)
        {
            var now = _clock.GetUtcNow();
            foreach (var stale in _streams
                         .Where(kv => now - kv.Value.Touched > IdleEviction)
                         .Select(kv => kv.Key)
                         .ToArray())
            {
                _streams.Remove(stale);
            }

            if (chunk.Name.Length == 0 || chunk.Name.Length > MaxNameBytes
                || chunk.ContentType.Length > MaxContentTypeBytes
                || chunk.Data.Length == 0)
            {
                return new AppendResult(AppendOutcome.Dropped, 0, null);
            }

            var key = new Key(taskId, chunk.Name);
            if (_completed.ContainsKey(key))
                return new AppendResult(AppendOutcome.Dropped, (ulong)_completed[key], null);

            if (!_streams.TryGetValue(key, out var stream))
            {
                while (_streams.Count >= MaxOpenStreams)
                {
                    var lru = _streams.Aggregate((a, b) => a.Value.Touched <= b.Value.Touched ? a : b).Key;
                    if (lru == key)
                        break; // never the stream in hand
                    _streams.Remove(lru);
                }
                stream = new Stream(chunk.Name, chunk.ContentType, chunk.HasOffset ? Mode.Resume : Mode.Legacy)
                {
                    Touched = now,
                };
                _streams[key] = stream;
            }
            stream.Touched = now;

            var result = stream.Mode == Mode.Resume && chunk.HasOffset
                ? AppendResumable(key, stream, chunk, maxStreamBytes)
                : stream.Mode == Mode.Legacy && !chunk.HasOffset
                    ? AppendLegacy(key, stream, chunk, maxStreamBytes)
                    : new AppendResult(AppendOutcome.Unplaced, (ulong)stream.Data.Count, null);
            return result;
        }
    }

    // The resumable placement rule (the mirror of the download arm's client
    // side): exact-seam appends, already-covered duplicates are no-ops,
    // offset 0 over a partial hold restarts, anything else is a gap the
    // sender re-serves from the reported seam. The terminal chunk completes
    // only when it placed and the declared hash (when the run carried one)
    // matches the reassembled bytes -- a mismatch drops the run whole rather
    // than materializing corrupt evidence.
    private AppendResult AppendResumable(Key key, Stream stream, ExfilChunk chunk, int maxStreamBytes)
    {
        var data = chunk.Data;
        var offset = chunk.Offset;
        if (chunk.HasPayloadSha256 && chunk.PayloadSha256.Length == 32 && stream.DeclaredSha is null)
            stream.DeclaredSha = chunk.PayloadSha256.ToByteArray();

        var placed = false;
        if (offset == (ulong)stream.Data.Count)
        {
            placed = TryExtend(key, stream, data, maxStreamBytes);
        }
        else if (offset + (ulong)data.Length <= (ulong)stream.Data.Count)
        {
            placed = true; // an already-covered duplicate
        }
        else if (offset == 0)
        {
            stream.Data.Clear();
            placed = TryExtend(key, stream, data, maxStreamBytes);
        }
        else
        {
            // A gap ahead of the held bytes: the run keeps its state and the
            // progress report names the seam the sender re-serves from.
            return new AppendResult(AppendOutcome.Unplaced, (ulong)stream.Data.Count, null);
        }

        if (!placed)
            return new AppendResult(AppendOutcome.Dropped, 0, null);

        if (!chunk.Terminal)
            return new AppendResult(AppendOutcome.Buffered, (ulong)stream.Data.Count, null);

        var reassembled = stream.Data.ToArray();
        if (stream.DeclaredSha is { Length: 32 } declared
            && !System.Security.Cryptography.SHA256.HashData(reassembled).AsSpan().SequenceEqual(declared))
        {
            _streams.Remove(key);
            return new AppendResult(AppendOutcome.Dropped, 0, null);
        }

        _streams.Remove(key);
        MarkCompleted(key, reassembled.Length);
        return new AppendResult(
            AppendOutcome.Completed,
            (ulong)reassembled.Length,
            new Reassembled(stream.Name, stream.ContentType, reassembled));
    }

    // The legacy discipline, exactly as the per-connection reassembler ran
    // it: the first chunk starts at 0 or 1 (both origins shipped), every
    // later chunk must be exactly the next index, and a gap, a repeat, or a
    // cap overflow drops the stream whole.
    private AppendResult AppendLegacy(Key key, Stream stream, ExfilChunk chunk, int maxStreamBytes)
    {
        if (stream.NextSequence is { } next)
        {
            if (chunk.Sequence != next)
            {
                _streams.Remove(key);
                return new AppendResult(AppendOutcome.Dropped, 0, null);
            }
        }
        else if (chunk.Sequence != 0 && chunk.Sequence != 1)
        {
            _streams.Remove(key);
            return new AppendResult(AppendOutcome.Dropped, 0, null);
        }

        if (!TryExtend(key, stream, chunk.Data, maxStreamBytes))
            return new AppendResult(AppendOutcome.Dropped, 0, null);

        stream.NextSequence = chunk.Sequence + 1;
        if (!chunk.Terminal)
            return new AppendResult(AppendOutcome.Buffered, (ulong)stream.Data.Count, null);

        var reassembled = stream.Data.ToArray();
        _streams.Remove(key);
        MarkCompleted(key, reassembled.Length);
        return new AppendResult(
            AppendOutcome.Completed,
            (ulong)reassembled.Length,
            new Reassembled(stream.Name, stream.ContentType, reassembled));
    }

    private bool TryExtend(Key key, Stream stream, Google.Protobuf.ByteString data, int maxStreamBytes)
    {
        if (stream.Data.Count + data.Length > maxStreamBytes)
        {
            _streams.Remove(key);
            return false;
        }
        stream.Data.AddRange(data);
        return true;
    }

    /// <summary>
    /// The contiguous-from-zero byte count a stream holds -- the seam a
    /// progress report or the DNS grammar's probe names. A completed run
    /// answers its full length for the idle window, so the sender that never
    /// saw the completion response still learns the run landed.
    /// </summary>
    public ulong Held(Guid taskId, string name)
    {
        lock (_gate)
        {
            var key = new Key(taskId, name);
            if (_streams.TryGetValue(key, out var stream))
                return (ulong)stream.Data.Count;
            return _completed.TryGetValue(key, out var held) ? (ulong)held : 0;
        }
    }

    private void MarkCompleted(Key key, long length)
    {
        while (_completed.Count >= MaxCompletedMarks && _completedOrder.Count > 0)
        {
            var oldest = _completedOrder[0];
            _completedOrder.RemoveAt(0);
            _completed.Remove(oldest);
        }
        if (!_completed.ContainsKey(key))
            _completedOrder.Add(key);
        _completed[key] = length;
    }

    private const int MaxNameBytes = 256;
    private const int MaxContentTypeBytes = 128;
}
