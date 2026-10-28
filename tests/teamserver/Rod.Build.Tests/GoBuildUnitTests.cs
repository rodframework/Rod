using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.Build.Tests;

/// <summary>
/// The Go unit's contract surface: the target map's supported set, the
/// format and loader refusals, and the missing-tree failure split -- the
/// same refusal discipline the Rust unit's tests hold (a wrong request
/// throws the contract exception, a broken environment the build-failure
/// one). The real-build leg self-skips on a host without a Go toolchain:
/// the environment report names the fix.
/// </summary>
public class GoBuildUnitTests
{
    private static BuildParams Params(ImplantClass @class = ImplantClass.Implant) => new(
        EngagementId.New(),
        OperatorId.New(),
        @class,
        new TargetProfile("linux", "amd64"),
        new TransportProfile("http://c2.example.test", "/beacon"),
        new BeaconProfile(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10), DateTimeOffset.UtcNow.AddDays(30)));

    [Theory]
    [InlineData("linux", "amd64", "linux", "amd64")]
    [InlineData("linux", "arm64", "linux", "arm64")]
    [InlineData("linux", "aarch64", "linux", "arm64")]
    [InlineData("linux", "x86", "linux", "386")]
    [InlineData("windows", "amd64", "windows", "amd64")]
    [InlineData("win", "x64", "windows", "amd64")]
    [InlineData("windows", "arm64", "windows", "arm64")]
    [InlineData("osx", "amd64", "darwin", "amd64")]
    [InlineData("macos", "arm64", "darwin", "arm64")]
    [InlineData("darwin", "aarch64", "darwin", "arm64")]
    public void TheTargetMapCoversTheGoToolchainSet(string os, string arch, string goos, string goarch)
    {
        var (mappedOs, mappedArch) = GoBuildUnit.MapTarget(new TargetProfile(os, arch));
        Assert.Equal((goos, goarch), (mappedOs, mappedArch));
    }

    [Theory]
    [InlineData("osx", "386", "amd64/arm64 only")]
    [InlineData("android", "arm64", "the Rust unit's leg")]
    [InlineData("linux", "riscv64", "supported")]
    [InlineData("plan9", "amd64", "supported")]
    public void OutOfSetTargetsAreContractRefusalsNamingTheSet(string os, string arch, string expect)
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => GoBuildUnit.MapTarget(new TargetProfile(os, arch)));
        Assert.Contains(expect, ex.Message);
    }

    [Theory]
    [InlineData(ArtifactFormat.Dll)]
    [InlineData(ArtifactFormat.SharedObject)]
    [InlineData(ArtifactFormat.Shellcode)]
    [InlineData(ArtifactFormat.Apk)]
    public async Task LibraryAndPackageFormatsAreContractSlotsThisUnitDoesNotProduce(ArtifactFormat format)
    {
        var unit = new GoBuildUnit();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => unit.BuildAsync(Params() with { Format = format }));
        Assert.Contains("build 'exe'", ex.Message);
    }

    [Fact]
    public async Task TheLoaderTierIsAContractRefusal()
    {
        var unit = new GoBuildUnit();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => unit.BuildAsync(Params() with { Kind = PayloadKind.Loader }));
        Assert.Contains("Rust unit's no_std crate", ex.Message);
    }

    [Fact]
    public async Task MissingSourceTree_ThrowsBuildUnitFailure_NotAContractRefusal()
    {
        var unit = new GoBuildUnit(
            goSourceDir: Path.Combine(Path.GetTempPath(), "rod-absent-" + Guid.NewGuid().ToString("N")));

        var ex = await Assert.ThrowsAsync<BuildUnitFailureException>(
            () => unit.BuildAsync(Params()));

        Assert.Contains("source tree not found", ex.Message);
    }

    [Fact]
    public async Task ARealBuildCompilesTheBakedArtifact()
    {
        var unit = new GoBuildUnit();
        if (unit.ReportEnvironment().Status is not "ready")
            return; // no Go toolchain on this host; the environment report names the fix

        var artifact = await unit.BuildAsync(Params());

        Assert.True(artifact.Size > 0);
        Assert.Equal(BuildUnitIds.Go, artifact.UnitId);
        Assert.Equal("application/octet-stream", artifact.ContentType);
    }
}
