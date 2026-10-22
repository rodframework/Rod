using Google.Protobuf;
using Rod.Transport.Endpoints;
using Rod.V1;

namespace Rod.Integration.Tests;

/// <summary>
/// The shared exfil reassembly (architecture.md Sec 15.3, ADR-010 -- the
/// upload arm) as a unit: offset placement is idempotent with the same rule
/// the download arm's client runs, the bounds do not weaken (per-stream cap,
/// stream count, idle eviction), the declared hash gates materialization,
/// and legacy offset-less chunks keep the strict sequence discipline
/// community implants shipped against.
/// </summary>
public class ExfilStreamStoreTests
{
    private static ExfilChunk Chunk(
        Guid task, string name, byte[] data, ulong offset, bool terminal, byte[]? declared = null)
    {
        var chunk = new ExfilChunk
        {
            TaskId = task.ToString(),
            Name = name,
            ContentType = "application/octet-stream",
            Sequence = 0,
            Terminal = terminal,
            Offset = offset,
            Data = ByteString.CopyFrom(data),
        };
        if (declared is not null)
            chunk.PayloadSha256 = ByteString.CopyFrom(declared);
        return chunk;
    }

    private static byte[] Content(long length)
    {
        var bytes = new byte[length];
        Random.Shared.NextBytes(bytes);
        return bytes;
    }

    private sealed class FakeClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;
        public void Advance(TimeSpan span) => _now += span;
        public override DateTimeOffset GetUtcNow() => _now;
    }

    [Fact]
    public void OffsetChunks_PlaceIdempotently_AcrossAppendCalls()
    {
        var clock = new FakeClock();
        var store = new ExfilStreamStore(clock);
        var task = Guid.NewGuid();
        var payload = Content(1024);
        var declared = System.Security.Cryptography.SHA256.HashData(payload);

        // An interrupted run placed the first half.
        var first = store.Append(task, Chunk(task, "loot.bin", payload[..512], 0, false, declared), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Buffered, first.Outcome);
        Assert.Equal(512UL, first.HeldBytes);

        // A duplicate of the placed range is a no-op; the seam does not move.
        var duplicate = store.Append(task, Chunk(task, "loot.bin", payload[..512], 0, false, declared), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Buffered, duplicate.Outcome);
        Assert.Equal(512UL, duplicate.HeldBytes);

        // The remainder completes the run with the declared hash matching.
        var done = store.Append(task, Chunk(task, "loot.bin", payload[512..], 512, true, declared), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Completed, done.Outcome);
        Assert.NotNull(done.Reassembled);
        Assert.Equal(payload, done.Reassembled!.Data);
        Assert.Equal((ulong)payload.Length, done.HeldBytes);

        // The completed run answers its full length for the idle window, so
        // a sender that never saw the completion still learns it landed.
        Assert.Equal((ulong)payload.Length, store.Held(task, "loot.bin"));

        // A re-sent terminal after completion cannot double-materialize.
        var resent = store.Append(task, Chunk(task, "loot.bin", payload, 0, true, declared), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Dropped, resent.Outcome);
    }

    [Fact]
    public void AChunkPastAGap_StaysUnplaced_TheSeamNamesTheHold()
    {
        var store = new ExfilStreamStore(new FakeClock());
        var task = Guid.NewGuid();
        var payload = Content(1024);

        // Nothing placed yet, a chunk from the middle of the run is a gap.
        var gap = store.Append(task, Chunk(task, "loot.bin", payload[512..], 512, false), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Unplaced, gap.Outcome);
        Assert.Equal(0UL, gap.HeldBytes);

        // A terminal that cannot place does not complete the run.
        var gapTerminal = store.Append(task, Chunk(task, "loot.bin", payload[512..], 512, true), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Unplaced, gapTerminal.Outcome);

        // Serving from the reported seam (0) places and completes.
        var whole = store.Append(task, Chunk(task, "loot.bin", payload, 0, true), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Completed, whole.Outcome);
    }

    [Fact]
    public void OffsetZeroOverAPartialHold_RestartsTheRun()
    {
        var store = new ExfilStreamStore(new FakeClock());
        var task = Guid.NewGuid();
        var payload = Content(1024);
        var declared = System.Security.Cryptography.SHA256.HashData(payload);

        // Stale bytes from an aborted attempt, then the fresh run restarts.
        store.Append(task, Chunk(task, "loot.bin", "an aborted partial"u8.ToArray(), 0, false), ExfilStreamStore.FrameStreamBytes);
        var restarted = store.Append(task, Chunk(task, "loot.bin", payload, 0, true, declared), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Completed, restarted.Outcome);
        Assert.Equal(payload, restarted.Reassembled!.Data);
    }

    [Fact]
    public void DeclaredHashMismatch_DropsTheRunWhole()
    {
        var store = new ExfilStreamStore(new FakeClock());
        var task = Guid.NewGuid();
        var payload = Content(512);
        var wrong = System.Security.Cryptography.SHA256.HashData("not the payload"u8);

        var done = store.Append(task, Chunk(task, "loot.bin", payload, 0, true, wrong), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Dropped, done.Outcome);
        Assert.Equal(0UL, store.Held(task, "loot.bin"));
    }

    [Fact]
    public void LegacyOffsetLessChunks_KeepTheSequenceDiscipline()
    {
        var store = new ExfilStreamStore(new FakeClock());
        var task = Guid.NewGuid();
        var a = Content(16);
        var b = Content(16);

        static ExfilChunk Legacy(Guid task, string name, byte[] data, ulong sequence, bool terminal)
            => new()
            {
                TaskId = task.ToString(),
                Name = name,
                ContentType = "application/octet-stream",
                Sequence = sequence,
                Terminal = terminal,
                Data = ByteString.CopyFrom(data),
            };

        // Both shipped origins start a stream.
        Assert.Equal(
            ExfilStreamStore.AppendOutcome.Buffered,
            store.Append(task, Legacy(task, "legacy.bin", a, 1, false), ExfilStreamStore.FrameStreamBytes).Outcome);
        var done = store.Append(task, Legacy(task, "legacy.bin", b, 2, true), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Completed, done.Outcome);
        Assert.Equal(a.Concat(b).ToArray(), done.Reassembled!.Data);

        // A sequence gap drops the stream whole, exactly as the
        // per-connection reassembler did.
        var other = Guid.NewGuid();
        var first = Content(16);
        store.Append(task = other, Legacy(other, "gap.bin", first, 0, false), ExfilStreamStore.FrameStreamBytes);
        var gapped = store.Append(other, Legacy(other, "gap.bin", first, 5, true), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Dropped, gapped.Outcome);
        Assert.Equal(0UL, store.Held(other, "gap.bin"));
    }

    [Fact]
    public void TheStreamCap_EvictsTheRunThatExceedsIt()
    {
        var store = new ExfilStreamStore(new FakeClock());
        var task = Guid.NewGuid();
        var over = new byte[ExfilStreamStore.DnsStreamBytes + 1];

        var first = store.Append(task, Chunk(task, "big.bin", over, 0, false), ExfilStreamStore.DnsStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Dropped, first.Outcome);
        Assert.Equal(0UL, store.Held(task, "big.bin"));
    }

    [Fact]
    public void TheStreamCount_PushesOutTheIdlestStream_NeverTheOneInHand()
    {
        var store = new ExfilStreamStore(new FakeClock());
        var task = Guid.NewGuid();
        var payload = Content(8);

        for (var i = 0; i < ExfilStreamStore.MaxOpenStreams; i++)
            store.Append(
                Guid.NewGuid(), Chunk(Guid.NewGuid(), $"stream-{i}", payload, 0, false),
                ExfilStreamStore.FrameStreamBytes);

        // The map is full: the chunk in hand still places, the least recently
        // touched stream leaves instead.
        var admitted = store.Append(task, Chunk(task, "in-hand.bin", payload, 0, false), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(ExfilStreamStore.AppendOutcome.Buffered, admitted.Outcome);
        Assert.Equal((ulong)payload.Length, store.Held(task, "in-hand.bin"));
        Assert.Equal(0UL, store.Held(Guid.NewGuid(), "stream-0"));
    }

    [Fact]
    public void IdleStreams_LeaveOnTheEvictionWindow()
    {
        var clock = new FakeClock();
        var store = new ExfilStreamStore(clock);
        var task = Guid.NewGuid();
        var payload = Content(8);

        store.Append(task, Chunk(task, "stale.bin", payload, 0, false), ExfilStreamStore.FrameStreamBytes);
        clock.Advance(ExfilStreamStore.IdleEviction + TimeSpan.FromSeconds(1));

        var fresh = Guid.NewGuid();
        store.Append(fresh, Chunk(fresh, "fresh.bin", payload, 0, false), ExfilStreamStore.FrameStreamBytes);
        Assert.Equal(0UL, store.Held(task, "stale.bin"));
        Assert.Equal((ulong)payload.Length, store.Held(fresh, "fresh.bin"));
    }
}
