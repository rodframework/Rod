using System.IO;

namespace Rod.Audit.Tests;

/// <summary>
/// The durable payload store's acceptance checks: a payload round-trips
/// through disk, the metadata index is metadata only (the bytes live in the
/// blob, never in the jsonl line -- a line must not grow with the artifact),
/// the library listing and deletion are engagement-scoped, and a fresh store
/// instance recovers the index from disk so payloads outlive a restart.
/// </summary>
public class FilePayloadStoreTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.UnixEpoch;

    private static PayloadRecord Payload(
        Guid engagement, int seed, string? target = null, string? endpoint = null, Guid? tokenId = null)
        => new(
            PayloadId: Guid.NewGuid(),
            EngagementId: engagement,
            Class: "Implant",
            UnitId: "DotNet",
            ContentType: "application/octet-stream",
            Fingerprint: new string('a', 64),
            Content: Enumerable.Range(0, 64).Select(i => (byte)(seed + i)).ToArray(),
            Size: 64,
            BuiltAt: T0.AddSeconds(seed),
            Target: target,
            Endpoint: endpoint,
            TokenId: tokenId);

    private sealed class TempDir : IDisposable
    {
        public string Path { get; }

        public TempDir()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "rod-payload-test-" + Guid.NewGuid().ToString("N"));
        }

        public void Dispose()
        {
            if (Directory.Exists(Path))
                Directory.Delete(Path, recursive: true);
        }
    }

    [Fact]
    public async Task SavedMetadataLine_CarriesNoBytes()
    {
        using var dir = new TempDir();
        var store = new FilePayloadStore(new AuditPersistenceOptions { DataDirectory = dir.Path });
        var engagement = Guid.NewGuid();
        var payload = Payload(engagement, seed: 1, target: "linux/amd64", endpoint: "https://c2.example.test", tokenId: Guid.NewGuid());

        await store.SaveAsync(payload);

        // The jsonl line is metadata: small, its content field empty -- the
        // bytes live in the blob beside it.
        var line = await File.ReadAllTextAsync(System.IO.Path.Combine(dir.Path, "payloads.jsonl"));
        Assert.True(line.Length < 1024, $"metadata line grew with the artifact: {line.Length} bytes");
        Assert.Contains("\"content\":\"\"", line);
        Assert.True(File.Exists(System.IO.Path.Combine(dir.Path, "payload-blobs", payload.PayloadId.ToString("N"))));

        // The store's own read path returns the whole record: the library
        // fields from the metadata line, the bytes from the blob.
        var found = await store.FindAsync(payload.PayloadId, engagement);
        Assert.NotNull(found);
        Assert.Equal(payload.Content, found!.Content);
        Assert.Equal("linux/amd64", found.Target);
        Assert.Equal("https://c2.example.test", found.Endpoint);
        Assert.Equal(payload.TokenId, found.TokenId);
    }

    [Fact]
    public async Task ListAndRemove_AreEngagementScoped_AndSurviveReload()
    {
        using var dir = new TempDir();
        var engagement = Guid.NewGuid();
        var other = Guid.NewGuid();

        var store = new FilePayloadStore(new AuditPersistenceOptions { DataDirectory = dir.Path });
        var kept = Payload(engagement, seed: 1);
        var dropped = Payload(engagement, seed: 2);
        var foreign = Payload(other, seed: 3);
        await store.SaveAsync(kept);
        await store.SaveAsync(dropped);
        await store.SaveAsync(foreign);

        // The listing is this engagement's payloads, newest first, metadata only.
        var listed = await store.ListAsync(engagement);
        Assert.Equal(2, listed.Count);
        Assert.Equal(dropped.PayloadId, listed[0].PayloadId);
        Assert.All(listed, p => Assert.Empty(p.Content));

        // Removal answers false across the engagement boundary and true within
        // it; the removed payload no longer reads, the other engagement's does.
        Assert.False(await store.RemoveAsync(foreign.PayloadId, engagement));
        Assert.True(await store.RemoveAsync(dropped.PayloadId, engagement));
        Assert.Null(await store.FindAsync(dropped.PayloadId, engagement));
        Assert.NotNull(await store.FindAsync(foreign.PayloadId, other));

        // A fresh instance recovers the index from disk: the surviving payload
        // still reads with its bytes after the "restart".
        var reloaded = new FilePayloadStore(new AuditPersistenceOptions { DataDirectory = dir.Path });
        var survived = await reloaded.FindAsync(kept.PayloadId, engagement);
        Assert.NotNull(survived);
        Assert.Equal(kept.Content, survived!.Content);
        Assert.Single(await reloaded.ListAsync(engagement));
    }

    [Fact]
    public async Task Remove_RewritesHistoryWithoutTheDroppedLine()
    {
        using var dir = new TempDir();
        var store = new FilePayloadStore(new AuditPersistenceOptions { DataDirectory = dir.Path });
        var engagement = Guid.NewGuid();
        var dropped = Payload(engagement, seed: 1);
        var kept = Payload(engagement, seed: 2);
        await store.SaveAsync(dropped);
        await store.SaveAsync(kept);

        Assert.True(await store.RemoveAsync(dropped.PayloadId, engagement));

        // The rewritten file holds the survivor alone: a fresh instance
        // recovers exactly one payload, and it is the right one.
        var reloaded = new FilePayloadStore(new AuditPersistenceOptions { DataDirectory = dir.Path });
        var listed = await reloaded.ListAsync(engagement);
        var single = Assert.Single(listed);
        Assert.Equal(kept.PayloadId, single.PayloadId);
    }
}
