using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.Build.Tests;

/// <summary>
/// The Rust unit's refusal split: a wrong request throws the contract
/// exception (the HTTP-400 path), a broken environment throws the
/// build-failure exception (the HTTP-500 path). The two read identically at
/// the HTTP surface if they ever share a type again -- which is how a
/// missing musl target on a CI runner once read as three hundred bad
/// requests instead of one broken toolchain.
/// </summary>
public class RustBuildUnitTests
{
    private static BuildParams Params(ImplantClass @class = ImplantClass.Implant) => new(
        EngagementId.New(),
        OperatorId.New(),
        @class,
        new TargetProfile("linux", "amd64"),
        new TransportProfile("http://c2.example.test", "/beacon"),
        new BeaconProfile(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10), DateTimeOffset.UtcNow.AddDays(30)));

    // The Windows cargo triples begin with the arch (x86_64-pc-windows-gnu),
    // so the exe-suffix pick must key on the OS segment, not a StartsWith
    // -- the bug this pins had every Windows build report success and then
    // fail its own artifact check.
    [Theory]
    [InlineData("amd64")]
    [InlineData("x86")]
    public async Task AWindowsTarget_ProducesTheExeArtifactName(string arch)
    {
        var unit = new RustBuildUnit();
        var triple = RustBuildUnit.MapTriple(new TargetProfile("windows", arch));
        if (unit.ReportEnvironment().Status is "unavailable" or null || !unit.CrossTargetReady(triple))
            return; // the cross is not installed here; the environment report names the fix

        var @params = Params() with { Target = new TargetProfile("windows", arch) };

        var artifact = await unit.BuildAsync(@params);

        // The artifact came back: the unit found the .exe cargo produced
        // (a wrong name read as "produced no rod-implant") on both the
        // x86_64 and i686 crosses.
        Assert.True(artifact.Size > 0);
    }

    // The matrix cells the native families serve: Apple and ARM Windows
    // link against the SDK their own host carries, so they resolve there
    // and the refusal names that host everywhere else. Windows amd64 is
    // the dual-host cell: MSVC native on Windows, the GNU cross
    // everywhere else (the linux deployment shape).
    [Theory]
    [InlineData("macos", "amd64", "x86_64-apple-darwin")]
    [InlineData("darwin", "arm64", "aarch64-apple-darwin")]
    public void AppleTargetsMapOnAMacHostAndNameItElsewhere(string os, string arch, string triple)
    {
        if (OperatingSystem.IsMacOS())
            Assert.Equal(triple, RustBuildUnit.MapTriple(new TargetProfile(os, arch)));
        else
        {
            var ex = Assert.Throws<InvalidOperationException>(
                () => RustBuildUnit.MapTriple(new TargetProfile(os, arch)));
            Assert.Contains("build it on a macOS host", ex.Message);
        }
    }

    [Fact]
    public void ArmWindowsMapsOnAWindowsHostAndNamesItElsewhere()
    {
        if (OperatingSystem.IsWindows())
            Assert.Equal(
                "aarch64-pc-windows-msvc", RustBuildUnit.MapTriple(new TargetProfile("windows", "arm64")));
        else
        {
            var ex = Assert.Throws<InvalidOperationException>(
                () => RustBuildUnit.MapTriple(new TargetProfile("windows", "arm64")));
            Assert.Contains("build it on a Windows host", ex.Message);
        }
    }

    [Fact]
    public void WindowsAmd64TakesTheMsvcAbiOnWindowsAndTheGnuCrossElsewhere()
    {
        Assert.Equal(
            OperatingSystem.IsWindows() ? "x86_64-pc-windows-msvc" : "x86_64-pc-windows-gnu",
            RustBuildUnit.MapTriple(new TargetProfile("windows", "amd64")));
    }

    // The aarch64 loader link: the host driver rejects the cortex fixup
    // flag rustc passes for that target, so the unit routes the pure-Rust
    // link through rust-lld from the toolchain itself. This drives the
    // real cross build and proves the artifact comes back; running the
    // aarch64 binary is qemu territory, not the unit's.
    [Fact]
    public async Task AnArm64LoaderBuild_LinksThroughRustLld()
    {
        var unit = new RustBuildUnit();
        if (unit.ReportEnvironment().Status is "unavailable" or null
            || !unit.CrossTargetReady(RustBuildUnit.MapTriple(new TargetProfile("linux", "arm64"))))
            return; // the cross is not installed here; the environment report names the fix

        var @params = Params() with
        {
            Kind = PayloadKind.Loader,
            DeliversPayloadId = Guid.NewGuid(),
            TokenSecret = "loader-probe",
            EnvelopeKeyId = Guid.NewGuid(),
            EnvelopeKey = new byte[32],
            Target = new TargetProfile("linux", "arm64"),
            Transport = new TransportProfile("http://127.0.0.1:8080", "/beacon"),
        };

        var artifact = await unit.BuildAsync(@params);

        Assert.True(artifact.Size > 0);
    }

    [Fact]
    public async Task MissingSourceTree_ThrowsBuildUnitFailure_NotAContractRefusal()
    {
        var unit = new RustBuildUnit(
            rustSourceDir: Path.Combine(Path.GetTempPath(), "rod-absent-" + Guid.NewGuid().ToString("N")));

        var ex = await Assert.ThrowsAsync<BuildUnitFailureException>(
            () => unit.BuildAsync(Params()));

        Assert.Contains("source tree not found", ex.Message);
    }

    // The loader tier's contract refusals: the dial must be cleartext http
    // (the tier carries no TLS; any host shape bakes), and the
    // seal pair and stage reference must ride the params -- the endpoint
    // mints them, and a request that reaches the unit without them is a
    // contract violation, not a toolchain fault.
    [Fact]
    public async Task ALoaderDialThatIsNotHttp_IsAContractRefusal_AndANameBakes()
    {
        var unit = new RustBuildUnit();
        var @params = Params() with
        {
            Kind = PayloadKind.Loader,
            DeliversPayloadId = Guid.NewGuid(),
            TokenSecret = "loader-probe",
            EnvelopeKeyId = Guid.NewGuid(),
            EnvelopeKey = new byte[32],
            Transport = new TransportProfile("https://front.example.test", "/beacon"),
        };

        var https = await Assert.ThrowsAsync<InvalidOperationException>(() => unit.BuildAsync(@params));
        Assert.Contains("cleartext http front", https.Message);

        // A named front bakes the resolver shape, not a refusal; the literal
        // v4/v6 authorities dial directly.
        if (unit.ReportEnvironment().Status is "unavailable" or null)
            return; // no toolchain on this runner; the environment report names the fix
        @params = @params with { Transport = new TransportProfile("http://front.example.test", "/beacon") };
        var artifact = await unit.BuildAsync(@params);
        Assert.True(artifact.Size > 0);
    }

    [Fact]
    public async Task ALoaderWithoutItsSealKey_IsAContractRefusal()
    {
        var unit = new RustBuildUnit();
        var @params = Params() with
        {
            Kind = PayloadKind.Loader,
            DeliversPayloadId = Guid.NewGuid(),
            TokenSecret = "loader-probe",
            Transport = new TransportProfile("http://10.0.0.9:8080", "/beacon"),
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => unit.BuildAsync(@params));
        Assert.Contains("delivery seal key", ex.Message);
    }

    // The loader crate carries syscall stubs for x86_64 and aarch64 only;
    // on the narrower linux triples that used to fail deep inside cargo
    // with an unresolved `mod sys`, the unit now names the pair it builds.
    [Theory]
    [InlineData("arm")]
    [InlineData("x86")]
    public async Task ALoaderOnAnArchWithoutStubs_IsAContractRefusal(string arch)
    {
        var unit = new RustBuildUnit();
        var @params = Params() with
        {
            Kind = PayloadKind.Loader,
            DeliversPayloadId = Guid.NewGuid(),
            TokenSecret = "loader-probe",
            EnvelopeKeyId = Guid.NewGuid(),
            EnvelopeKey = new byte[32],
            Target = new TargetProfile("linux", arch),
            Transport = new TransportProfile("http://10.0.0.9:8080", "/beacon"),
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => unit.BuildAsync(@params));
        Assert.Contains("syscall stubs for amd64 and arm64 only", ex.Message);
    }

    // The real compile: builds the loader crate for the host's musl target
    // and checks the two facts the delivery depends on -- the baked fetch
    // credential rides the binary verbatim (the dial presents it), and the
    // artifact stays in the tier's size class (a blown-up binary means the
    // no-libc link went wrong). Skipped without the toolchain, the same
    // environment gate the system page reports.
    [Fact]
    public async Task ALoaderBuild_BakesTheCredential_AndStaysSmall()
    {
        var unit = new RustBuildUnit();
        if (unit.ReportEnvironment().Status is "unavailable" or null)
            return; // no toolchain on this runner; the environment report names the fix

        var secret = "stage-credential-probe";
        var @params = Params() with
        {
            Kind = PayloadKind.Loader,
            DeliversPayloadId = Guid.NewGuid(),
            TokenSecret = secret,
            EnvelopeKeyId = Guid.NewGuid(),
            EnvelopeKey = new byte[32],
            Transport = new TransportProfile("http://127.0.0.1:8080", "/beacon"),
        };

        var artifact = await unit.BuildAsync(@params);

        Assert.Equal(PayloadKind.Loader, artifact.Params.Kind);
        // The token is baked as a plain string constant; its bytes are the
        // cheapest proof the bake reached the binary.
        Assert.True(
            artifact.Content.AsSpan().IndexOf(System.Text.Encoding.UTF8.GetBytes(secret)) >= 0,
            "the baked credential rides the loader binary");
        Assert.True(artifact.Size < 512 * 1024, $"loader weighed {artifact.Size} bytes");
    }

    // The android target set maps onto the carrier triples -- arm64 for
    // devices, amd64 for the emulator the lab runs the leg on -- with the
    // arch aliases the other sets take.
    [Theory]
    [InlineData("arm64", "aarch64-linux-android")]
    [InlineData("aarch64", "aarch64-linux-android")]
    [InlineData("amd64", "x86_64-linux-android")]
    [InlineData("x64", "x86_64-linux-android")]
    public void TheAndroidTargets_MapOntoTheCarrierTriples(string arch, string triple)
        => Assert.Equal(triple, RustBuildUnit.MapTriple(new TargetProfile("android", arch)));

    // The format axis over android: the carrier's two shapes alone, and
    // the carrier shapes belong to android alone -- refused as the
    // request's fault before any toolchain runs.
    [Fact]
    public async Task AnAndroidTarget_RefusesTheExecutableSpellings()
    {
        var unit = new RustBuildUnit();
        var @params = Params() with { Target = new TargetProfile("android", "arm64") };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => unit.BuildAsync(@params));

        Assert.Contains("build format 'so' or 'apk'", ex.Message);
    }

    [Fact]
    public async Task AnApkFormat_OffAndroid_IsAContractRefusal()
    {
        var unit = new RustBuildUnit();
        var @params = Params() with { Format = ArtifactFormat.Apk };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => unit.BuildAsync(@params));

        Assert.Contains("android carrier package", ex.Message);
    }

    // The android carrier legs: the real NDK cross builds the carrier
    // cdylib (the 'so' artifact), and the packaging chain wraps it as the
    // installable APK. Both legs skip without their host pieces -- the
    // same environment gate the system page reports -- and the emulator
    // e2e in the integration suite is what runs the APK these produce.
    [Fact]
    public async Task AnAndroidCarrierBuild_ProducesTheLibrary_ThenThePackage()
    {
        var unit = new RustBuildUnit();
        var triple = RustBuildUnit.MapTriple(new TargetProfile("android", "amd64"));
        if (unit.ReportEnvironment().Status is "unavailable" or null || !unit.CrossTargetReady(triple))
            return; // the NDK or its std is not installed here; the environment report names the fix

        var @params = Params() with
        {
            Target = new TargetProfile("android", "amd64"),
            Format = ArtifactFormat.SharedObject,
        };
        var so = await unit.BuildAsync(@params);

        // The carrier library is an ELF shared object for the android arch.
        Assert.True(so.Size > 0);
        Assert.Equal(0x7f, so.Content[0]);
        Assert.Equal((byte)'E', so.Content[1]);
        Assert.Equal((byte)'L', so.Content[2]);
        Assert.Equal((byte)'F', so.Content[3]);
        Assert.Equal("application/octet-stream", so.ContentType);

        if (RustBuildUnit.LocateBuildTools() is null
            || RustBuildUnit.LocatePlatformJar() is null
            || RustBuildUnit.LocateJava() is null)
            return; // the packaging chain is not installed; the library leg above is the artifact proof
        var apk = await unit.BuildAsync(@params with { Format = ArtifactFormat.Apk });

        // The package wraps the library: a zip (the local-file-header
        // magic) carrying more bytes than the .so alone, with the store's
        // download spelling on the content type.
        Assert.True(apk.Size > so.Size);
        Assert.Equal((byte)'P', apk.Content[0]);
        Assert.Equal((byte)'K', apk.Content[1]);
        Assert.Equal("application/vnd.android.package-archive", apk.ContentType);
    }
}
