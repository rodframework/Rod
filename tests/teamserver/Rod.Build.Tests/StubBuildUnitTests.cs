using System.Security.Cryptography;
using System.Text;
using Rod.Build.Tests;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.Build.Tests;

/// <summary>
/// Unit tests for the stub build unit: the build contract's
/// benign producer. Proves the stub is deterministic, non-empty, correctly
/// fingerprinted, and that the per-implant key never appears in the artifact --
/// only its fingerprint does. Keeps build-layer coverage in the Build.Tests
/// project alongside the CPM guard.
/// </summary>
public class StubBuildUnitTests
{
    private static BuildParams Params(ImplantClass @class = ImplantClass.Implant) => new(
        EngagementId.New(),
        OperatorId.New(),
        @class,
        new TargetProfile("linux", "amd64"),
        new TransportProfile("http://c2.example.test", "/beacon"),
        new BeaconProfile(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10), DateTimeOffset.UtcNow.AddDays(30)));

    [Theory]
    [InlineData(ImplantClass.Implant, "shell.exec,shell.interact,file.push,file.pull,fs.list,proc.kill,beacon.sleep,tunnel.forward,tunnel.socks,recon.portscan,recon.hostenum,recon.service,recon.ps,lateral.move,lateral.token,lateral.exec_remote,persist.install,persist.remove,persist.list,collect.cred,collect.keylog,collect.screenshot,collect.minidump,inject.shellcode,exfil.push,exfil.stage,module.load,module.unload,module.list")]
    [InlineData(ImplantClass.WebShell, "shell.exec")]
    [InlineData(ImplantClass.Ephemeral, "shell.exec")]
    [InlineData(ImplantClass.Pivot, "tunnel.forward,tunnel.socks")]
    public async Task Build_BakesTheClassReducedVerbSet_IntoTheManifest(ImplantClass @class, string expectedVerbs)
    {
        // The class's reduced verb set is baked into the artifact
        // (architecture.md Sec 5.2), so a captured payload is self-describing.
        var unit = new StubBuildUnit();

        var artifact = await unit.BuildAsync(Params(@class));

        var manifest = Encoding.UTF8.GetString(artifact.Content);
        Assert.Contains($"verbs={expectedVerbs}", manifest);
    }

    [Fact]
    public async Task Build_BakesTheConfiguredBeaconProfile_IntoTheManifest()
    {
        // The configured beacon profile (architecture.md Sec 5.1, Sec 7) -- sleep,
        // jitter, kill date -- is what makes per-implant OPSEC possible, so it must
        // land in the artifact manifest, not be silently dropped. Use values that
        // differ from the build-contract defaults (30s/10s) so a regression to the
        // default is caught, and a pinned kill date so it survives the round trip.
        var sleep = TimeSpan.FromSeconds(45);
        var jitter = TimeSpan.FromSeconds(15);
        var killDate = new DateTimeOffset(2027, 1, 31, 12, 0, 0, TimeSpan.Zero);
        var @params = new BuildParams(
            EngagementId.New(),
            OperatorId.New(),
            ImplantClass.Implant,
            new TargetProfile("linux", "amd64"),
            new TransportProfile("http://c2.example.test", "/beacon"),
            new BeaconProfile(sleep, jitter, killDate));

        var unit = new StubBuildUnit();
        var artifact = await unit.BuildAsync(@params);

        var manifest = Encoding.UTF8.GetString(artifact.Content);
        Assert.Contains("sleep=45s", manifest);
        Assert.Contains("jitter=15s", manifest);
        Assert.Contains($"kill_date={killDate:O}", manifest);
    }

    [Fact]
    public async Task Build_BakesTheConfiguredTransportProfile_IntoTheManifest()
    {
        // The malleable transport profile (architecture.md Sec 7) is surfaced
        // in the stub manifest the same way the baked JSON surfaces it, so the stub
        // artifact is self-describing about its wire shape. Values differ from the
        // defaults so a regression to a default is caught.
        var transport = new TransportProfile("http://c2.example.test", "/beacon")
        {
            EnrollPath = "/api/v1/health",
            UserAgent = "Mozilla/5.0 (RodTest)",
            Headers = new Dictionary<string, string>
            {
                ["X-Forwarded-For"] = "10.0.0.1",
                ["Accept"] = "application/json",
            },
            RequestTimeout = TimeSpan.FromSeconds(12),
            Envelope = TransportEnvelope.Base64,
        };
        var @params = new BuildParams(
            EngagementId.New(),
            OperatorId.New(),
            ImplantClass.Implant,
            new TargetProfile("linux", "amd64"),
            transport,
            new BeaconProfile(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10), DateTimeOffset.UtcNow.AddDays(30)));

        var unit = new StubBuildUnit();
        var artifact = await unit.BuildAsync(@params);

        var manifest = Encoding.UTF8.GetString(artifact.Content);
        Assert.Contains("enroll_path=/api/v1/health", manifest);
        Assert.Contains("user_agent=Mozilla/5.0 (RodTest)", manifest);
        Assert.Contains("request_timeout=12s", manifest);
        Assert.Contains("envelope=base64", manifest);
        // Headers render as sorted Name=Value pairs joined by ';'.
        Assert.Contains("headers=Accept=application/json;X-Forwarded-For=10.0.0.1", manifest);
    }

    [Fact]
    public async Task Build_BakesTheDefaultTransportProfile_IntoTheManifest()
    {
        // A minimal transport profile fills the malleable knobs with the documented
        // defaults, so the stub manifest records the unchanged wire shape.
        var unit = new StubBuildUnit();
        var artifact = await unit.BuildAsync(Params());

        var manifest = Encoding.UTF8.GetString(artifact.Content);
        Assert.Contains($"enroll_path={TransportProfile.Defaults.EnrollPath}", manifest);
        Assert.Contains("user_agent=", manifest);
        Assert.Contains("headers=-", manifest);
        Assert.Contains("request_timeout=30s", manifest);
        Assert.Contains("envelope=aesgcm", manifest);
    }

    [Fact]
    public async Task Build_ReturnsNonEmptyArtifact_WithItsUnitId()
    {
        var unit = new StubBuildUnit();

        var artifact = await unit.BuildAsync(Params());

        Assert.Equal("stub-go", artifact.UnitId);
        Assert.NotEmpty(artifact.Content);
        Assert.Equal(artifact.Content.Length, artifact.Size);
        Assert.False(string.IsNullOrWhiteSpace(artifact.ContentType));
    }

    [Fact]
    public async Task Build_Fingerprint_MatchesSha256OfContent()
    {
        var unit = new StubBuildUnit();

        var artifact = await unit.BuildAsync(Params());

        var expected = Convert.ToHexString(SHA256.HashData(artifact.Content)).ToLowerInvariant();
        Assert.Equal(expected, artifact.Fingerprint);
        Assert.Equal(64, artifact.Fingerprint.Length);
    }

    [Fact]
    public void Registry_ResolvesUnit_ByItsId()
    {
        var registry = new InMemoryBuildUnitRegistry();
        registry.Register(new StubBuildUnit());

        var resolved = registry.Find("stub-go");

        Assert.NotNull(resolved);
        Assert.IsType<StubBuildUnit>(resolved);
    }

    [Fact]
    public void Registry_ReturnsNull_ForUnregisteredId()
    {
        var registry = new InMemoryBuildUnitRegistry();

        Assert.Null(registry.Find("no-such-unit"));
    }
}
