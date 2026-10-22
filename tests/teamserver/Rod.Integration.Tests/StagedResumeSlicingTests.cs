using System.Security.Cryptography;
using Google.Protobuf;
using Rod.Audit;
using Rod.Transport.Endpoints;
using Rod.V1;

namespace Rod.Integration.Tests;

/// <summary>
/// The byte-offset resume slicing (architecture.md Sec 15.3, ADR-010) over
/// <see cref="BeaconTasking.StagedChunkRunAsync"/>: a proven offset is served
/// from its seam, an unprovable one restarts the whole run, and every chunk
/// carries its absolute byte position. The tasking CA and audit store are not
/// on this path -- the slicing reads the artifact store alone.
/// </summary>
public class StagedResumeSlicingTests
{
    private static async Task<BeaconTasking> TaskingWithAsync(byte[] payload, Guid taskId)
    {
        var artifacts = new InMemoryArtifactStore();
        await artifacts.SaveAsync(new Artifact(
            ArtifactId: Guid.NewGuid(),
            EngagementId: Guid.NewGuid(),
            TaskId: taskId,
            OperatorId: Guid.NewGuid(),
            Name: StagedArtifacts.NameFor(taskId),
            ContentType: "application/octet-stream",
            Content: payload,
            Size: payload.Length,
            StoredAt: DateTimeOffset.UtcNow));
        return new BeaconTasking(null!, null!, artifacts);
    }

    private static List<StagedChunk> Decode(IReadOnlyList<Frame> run)
        => run.Select(f => StagedChunk.Parser.ParseFrom(f.Payload)).ToList();

    private static byte[] Content(long length)
    {
        var bytes = new byte[length];
        Random.Shared.NextBytes(bytes);
        return bytes;
    }

    private static byte[] Sha256Prefix(byte[] payload, long length)
        => SHA256.HashData(payload.AsSpan(0, (int)length));

    [Fact]
    public async Task FreshDemand_ServesTheWholeRun_WithAbsoluteOffsets()
    {
        var taskId = Guid.NewGuid();
        var payload = Content(BeaconTasking.StagedChunkSize * 2 + 1024);
        var tasking = await TaskingWithAsync(payload, taskId);

        var run = Decode(await tasking.StagedChunkRunAsync(taskId, CancellationToken.None));

        Assert.Equal(3, run.Count);
        Assert.All(run, chunk => Assert.Equal(new Rod.CoreState.TaskId(taskId).ToString(), chunk.TaskId));
        Assert.Equal(0UL, run[0].Offset);
        Assert.Equal((ulong)BeaconTasking.StagedChunkSize, run[1].Offset);
        Assert.Equal((ulong)BeaconTasking.StagedChunkSize * 2, run[2].Offset);
        Assert.True(run[^1].Terminal);
        var reassembled = run.SelectMany(c => c.Data).ToArray();
        Assert.Equal(payload, reassembled);
    }

    [Fact]
    public async Task ProvenResume_ServesOnlyTheRemainder_FromTheSeam()
    {
        var taskId = Guid.NewGuid();
        var payload = Content(BeaconTasking.StagedChunkSize * 3);
        var tasking = await TaskingWithAsync(payload, taskId);

        // An interrupted run left the implant holding the first chunk.
        var held = (ulong)BeaconTasking.StagedChunkSize;
        var run = Decode(await tasking.StagedChunkRunAsync(
            taskId, held, Sha256Prefix(payload, (long)held), CancellationToken.None));

        Assert.Equal(2, run.Count);
        Assert.Equal(0UL, run[0].Sequence);
        Assert.Equal(held, run[0].Offset);
        Assert.True(run[^1].Terminal);
        var reassembled = payload[..(int)held].Concat(run.SelectMany(c => c.Data)).ToArray();
        Assert.Equal(payload, reassembled);
    }

    [Fact]
    public async Task UnalignedResume_IsHonored_ThePlacementNeverDependsOnChunkGrid()
    {
        // The DNS carriage serves answer-sized slices, so a resumed offset is
        // whatever the implant happened to hold -- not a 512 KiB multiple.
        var taskId = Guid.NewGuid();
        var payload = Content(300_000);
        var tasking = await TaskingWithAsync(payload, taskId);

        var held = 123_456UL;
        var run = Decode(await tasking.StagedChunkRunAsync(
            taskId, held, Sha256Prefix(payload, (int)held), CancellationToken.None));

        Assert.Equal(held, run[0].Offset);
        var reassembled = payload[..(int)held].Concat(run.SelectMany(c => c.Data)).ToArray();
        Assert.Equal(payload, reassembled);
    }

    [Fact]
    public async Task WrongPrefixProof_RestartsTheRunWhole()
    {
        var taskId = Guid.NewGuid();
        var payload = Content(BeaconTasking.StagedChunkSize + 10);
        var tasking = await TaskingWithAsync(payload, taskId);

        // A proof over different bytes: the seam cannot be trusted, so the
        // answer is the fresh shape and the run's first chunk names offset 0.
        var run = Decode(await tasking.StagedChunkRunAsync(
            taskId, 512UL, SHA256.HashData("not the held prefix"u8), CancellationToken.None));

        Assert.Equal(0UL, run[0].Offset);
        Assert.Equal(payload, run.SelectMany(c => c.Data).ToArray());
    }

    [Fact]
    public async Task OffsetPastTheEnd_RestartsTheRunWhole()
    {
        var taskId = Guid.NewGuid();
        var payload = Content(4096);
        var tasking = await TaskingWithAsync(payload, taskId);

        var run = Decode(await tasking.StagedChunkRunAsync(
            taskId, (ulong)(payload.Length + 1), Sha256Prefix(payload, payload.Length), CancellationToken.None));

        Assert.Equal(0UL, run[0].Offset);
        Assert.Single(run);
        Assert.True(run[0].Terminal);
    }

    [Fact]
    public async Task ResumeAtTheWholePayload_AnswersWithTheEmptyTerminal()
    {
        // The implant holds every byte but the terminal chunk died with the
        // stream: the answer resolves it instead of re-serving the payload.
        var taskId = Guid.NewGuid();
        var payload = Content(4096);
        var tasking = await TaskingWithAsync(payload, taskId);

        var run = Decode(await tasking.StagedChunkRunAsync(
            taskId, (ulong)payload.Length, Sha256Prefix(payload, payload.Length), CancellationToken.None));

        var chunk = Assert.Single(run);
        Assert.True(chunk.Terminal);
        Assert.Equal((ulong)payload.Length, chunk.Offset);
        Assert.Empty(chunk.Data);
    }

    [Fact]
    public async Task MissingStagedBytes_AnswerWithTheEmptyTerminal()
    {
        var tasking = new BeaconTasking(null!, null!, new InMemoryArtifactStore());
        var run = Decode(await tasking.StagedChunkRunAsync(Guid.NewGuid(), CancellationToken.None));
        var chunk = Assert.Single(run);
        Assert.True(chunk.Terminal);
        Assert.Empty(chunk.Data);
    }
}
