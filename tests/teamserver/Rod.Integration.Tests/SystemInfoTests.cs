using System.Net;
using System.Net.Http.Json;

namespace Rod.Integration.Tests;

/// <summary>
/// The system page's read (architecture.md Sec 6): the host facts and the
/// build units' self-reported environment. The assertions stay structural
/// -- the probe's verdicts depend on the machine this runs on, so the test
/// pins the shape (sections present, every offered target reported with
/// its std and linker facts) rather than any particular finding.
/// </summary>
public class SystemInfoTests
{
    [Fact]
    public async Task TheSystemRead_ReportsTheHostAndTheBuildEnvironment()
    {
        // The full endpoint set (MapRodEndpoints) already carries the
        // system route; the host only needs the operator session.
        var (client, host, _) = AuthenticatedHost.Create();
        using var hostScope = host;
        using var clientScope = client;
        await AuthenticatedHost.LoginAsync(client);

        var info = await client.GetFromJsonAsync<SystemInfoDto>("/system");
        Assert.NotNull(info);
        Assert.False(string.IsNullOrWhiteSpace(info!.Server.Host));
        Assert.False(string.IsNullOrWhiteSpace(info.Server.OperatingSystem));
        Assert.Contains(".NET", info.Server.Runtime);
        Assert.True(info.Server.StartedAt <= DateTimeOffset.UtcNow);

        // The in-tree Rust unit reports: a verdict from the fixed
        // vocabulary, at least the source/cargo findings, and one row per
        // buildable triple with both halves of its readiness named.
        // The persistence section names an adapter for every store; this
        // host composes no database, so the Postgres target reads null and
        // the in-memory/file adapters stand in.
        Assert.Equal(5, info.Persistence.Stores.Count);
        Assert.All(info.Persistence.Stores, st =>
        {
            Assert.False(string.IsNullOrWhiteSpace(st.Concern));
            Assert.False(string.IsNullOrWhiteSpace(st.Adapter));
        });
        Assert.Null(info.Persistence.PostgresTarget);

        var rust = Assert.Single(info.BuildUnits, u => u.Language == "Rust");
        Assert.Contains(rust.Status, new[] { "ready", "partial", "unavailable" });
        Assert.Contains(rust.Findings, f => f.Area == "source tree");
        Assert.Contains(rust.Findings, f => f.Area == "cargo");
        Assert.Equal(8, rust.Targets.Count);
        Assert.All(rust.Targets, t =>
        {
            Assert.False(string.IsNullOrWhiteSpace(t.Triple));
            Assert.False(string.IsNullOrWhiteSpace(t.Linker));
        });
        Assert.Contains(rust.Targets, t => t.Triple == "x86_64-unknown-linux-musl");
        Assert.Contains(rust.Targets, t => t.Triple == "x86_64-pc-windows-gnu");
        Assert.Contains(rust.Targets, t => t.Triple == "aarch64-linux-android");
    }

    [Fact]
    public async Task TheBuildCacheSetting_AppliesLive_AndTheSystemPageReadsIt()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using var hostScope = host;
        using var clientScope = client;
        await AuthenticatedHost.LoginAsync(client);

        // A relative path is refused with the fix: it would resolve inside
        // each build's disposable staging dir.
        var refused = await client.PutAsJsonAsync(
            "/settings/build", new { RustTargetDir = "relative/cache" });
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

        // An absolute directory applies live: the settings read reflects
        // it, and so does the system page's build-cache finding -- the
        // warn posture turns into the ok posture naming the directory.
        var cacheDir = Path.Combine(Path.GetTempPath(), "rod-cache-" + Guid.NewGuid().ToString("N"));
        var applied = await client.PutAsJsonAsync(
            "/settings/build", new { RustTargetDir = cacheDir });
        applied.EnsureSuccessStatusCode();
        var settings = await client.GetFromJsonAsync<BuildSettingsDto>("/settings/build");
        Assert.Equal(cacheDir, settings!.RustTargetDir);

        var info = await client.GetFromJsonAsync<SystemInfoDto>("/system");
        // The registry carries more than one unit now; the cache finding is
        // the Rust unit's own.
        var rust = Assert.Single(info!.BuildUnits, u => u.Language == "Rust");
        var finding = Assert.Single(rust.Findings, f => f.Area == "build cache");
        Assert.Equal("ok", finding.Level);
        Assert.Contains(cacheDir, finding.Detail);

        // The empty string returns to the hermetic shape.
        var hermetic = await client.PutAsJsonAsync(
            "/settings/build", new { RustTargetDir = "" });
        hermetic.EnsureSuccessStatusCode();
        settings = await client.GetFromJsonAsync<BuildSettingsDto>("/settings/build");
        Assert.Null(settings!.RustTargetDir);
    }

    private sealed class BuildSettingsDto
    {
        public string? RustTargetDir { get; set; }
    }

    private sealed class SystemInfoDto
    {
        public ServerSectionDto Server { get; set; } = null!;
        public PersistenceSectionDto Persistence { get; set; } = null!;
        public List<BuildUnitDto> BuildUnits { get; set; } = [];
    }

    private sealed class PersistenceSectionDto
    {
        public string DataDirectory { get; set; } = "";
        public string? PostgresTarget { get; set; }
        public List<StoreAdapterDto> Stores { get; set; } = [];
    }

    private sealed class StoreAdapterDto
    {
        public string Concern { get; set; } = "";
        public string Adapter { get; set; } = "";
    }

    private sealed class ServerSectionDto
    {
        public string Host { get; set; } = "";
        public string OperatingSystem { get; set; } = "";
        public string Runtime { get; set; } = "";
        public DateTimeOffset StartedAt { get; set; }
        public DateTimeOffset Now { get; set; }
    }

    private sealed class BuildUnitDto
    {
        public string Language { get; set; } = "";
        public string Status { get; set; } = "";
        public List<FindingDto> Findings { get; set; } = [];
        public List<TargetDto> Targets { get; set; } = [];
    }

    private sealed class FindingDto
    {
        public string Level { get; set; } = "";
        public string Area { get; set; } = "";
        public string Detail { get; set; } = "";
    }

    private sealed class TargetDto
    {
        public string Triple { get; set; } = "";
        public string Target { get; set; } = "";
        public bool StdInstalled { get; set; }
        public bool LinkerFound { get; set; }
        public string Linker { get; set; } = "";
    }
}
