using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.Build.Tests;

/// <summary>
/// The external build contract's spawn half (ADR-021): a package carrying a
/// <c>[unit]</c> table and a command, driven through the file contract -- the
/// request in, the result out, the pipeline fingerprinting whatever bytes the
/// unit claims. A shell script stands in for a real toolchain: the contract
/// is the seam under test, not any language.
/// </summary>
public class ExternalBuildUnitTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rod-external-unit-" + Guid.NewGuid().ToString("N"));

    private string Package(string name, string script)
    {
        var directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "rod-module.toml"), $"""
            [module]
            name = "{name}"
            version = "0.1.0"
            entry = "build-unit"
            license = "Apache-2.0"

            [compatibility]
            teamserver = "1.0.0"

            [opsec]
            lands-on-disk = true

            [unit]
            id = "community-{name}"
            command = "./build.sh"
            """);
        var build = Path.Combine(directory, "build.sh");
        File.WriteAllText(build, script);
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            File.SetUnixFileMode(build, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return directory;
    }

    private static BuildParams Params() => new(
        EngagementId.New(),
        OperatorId.New(),
        ImplantClass.Implant,
        new TargetProfile("linux", "amd64"),
        new TransportProfile("http://c2.example.test", "/beacon"),
        new BeaconProfile(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10), DateTimeOffset.UtcNow.AddDays(30)));

    [Fact]
    public async Task AShellUnit_BuildsThroughTheFileContract()
    {
        var directory = Package("shim", """
            #!/bin/sh
            # A stand-in toolchain: read the request, answer the result, and
            # leave the artifact beside the package for the pipeline to read.
            artifact="$(dirname "$ROD_BUILD_REQUEST")/artifact.bin"
            printf 'community-shim artifact\n' > "$artifact"
            printf '{"artifactPath":"%s","contentType":"text/x-shim","buildLog":["staged","compiled"]}\n' "$artifact" > "$ROD_BUILD_RESULT"
            """);

        var unit = ExternalBuildUnit.Load(directory);

        Assert.Equal("community-shim", unit.UnitId);
        var artifact = await unit.BuildAsync(Params());

        Assert.True(artifact.Size > 0);
        Assert.Equal("community-shim artifact\n".Length, artifact.Size);
        Assert.Equal("text/x-shim", artifact.ContentType);
        Assert.Equal("community-shim", artifact.UnitId);
    }

    [Fact]
    public async Task ANonzeroExit_FailsLoudlyWithTheOutput()
    {
        var directory = Package("broken", """
            #!/bin/sh
            echo "toolchain exploded" >&2
            exit 3
            """);
        var unit = ExternalBuildUnit.Load(directory);

        var failure = await Assert.ThrowsAsync<BuildUnitFailureException>(
            () => unit.BuildAsync(Params()));
        Assert.Contains("exit 3", failure.Message);
        Assert.Contains("toolchain exploded", failure.Message);
    }

    [Fact]
    public void APackageWithoutItsUnitTable_IsRefusedAtLoad()
    {
        var directory = Path.Combine(_root, "unitless");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "rod-module.toml"), """
            [module]
            name = "unitless"
            version = "0.1.0"
            entry = "server"
            license = "Apache-2.0"

            [compatibility]
            teamserver = "1.0.0"

            [opsec]
            lands-on-disk = false
            """);

        var refusal = Assert.Throws<InvalidOperationException>(() => ExternalBuildUnit.Load(directory));
        Assert.Contains(ExternalBuildUnit.ExternalUnitsSectionKey, refusal.Message);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }
}
