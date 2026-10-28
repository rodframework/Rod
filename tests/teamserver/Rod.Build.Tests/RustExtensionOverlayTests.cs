using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.Build.Tests;

/// <summary>
/// The extension overlay end to end (ADR-022): a fixture extension crate --
/// real Rust depending on the implant crate itself, the implant-native tier's
/// whole point -- compiled into a real artifact through the Rust unit's
/// overlay machinery. The generated registry, the staged dependency, and the
/// baked verb advertisement all prove out in one cargo build.
/// </summary>
public class RustExtensionOverlayTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rod-ext-overlay-" + Guid.NewGuid().ToString("N"));

    private static BuildParams Params() => new(
        EngagementId.New(),
        OperatorId.New(),
        ImplantClass.Implant,
        new TargetProfile("linux", "amd64"),
        new TransportProfile("http://c2.example.test", "/beacon"),
        new BeaconProfile(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10), DateTimeOffset.UtcNow.AddDays(30)));

    private string FixtureExtension()
    {
        // The extension contract for the rod-rust overlay: the package's
        // src/ tree compiles as a module inside the implant crate itself
        // (the implant's types behind crate:: paths -- the tier's whole
        // reach), exposing rod_extension(verb, arguments) -> HandlerOutput.
        var directory = Path.Combine(_root, "fixture-ext");
        Directory.CreateDirectory(Path.Combine(directory, "src"));
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "rod-module.toml"), """
            [module]
            name = "fixture-ext"
            version = "0.1.0"
            entry = "extension"
            license = "Apache-2.0"

            [compatibility]
            teamserver = "1.0.0"

            [opsec]
            lands-on-disk = false

            [[compatibility.targets]]
            implant-class = "implant"
            platform = "linux"
            arch = "amd64"
            build-unit = "rod-rust"

            [[verbs]]
            name = "collect.fixture"
            version = "0.1.0"
            category = "collect"
            output-kind = "text"
            """);
        File.WriteAllText(Path.Combine(directory, "src", "lib.rs"), """
            //! A fixture extension compiled into the implant (ADR-022): the
            //! sources land inside the implant crate, so its own types sit
            //! behind crate:: paths -- answered through the generated
            //! registry's one-call contract.
            use crate::handlers::{HandlerOutput, Outcome};

            pub fn rod_extension(verb: &str, arguments: &str) -> HandlerOutput {
                if verb == "collect.fixture" {
                    HandlerOutput {
                        outcome: Outcome::Succeeded,
                        output: format!("fixture:{arguments}"),
                        artifact: None,
                    }
                } else {
                    HandlerOutput {
                        outcome: Outcome::Failed,
                        output: format!("{verb}: no such extension verb"),
                        artifact: None,
                    }
                }
            }
            """);
        return directory;
    }

    [Fact]
    public async Task AnExtension_CompilesIntoTheArtifact()
    {
        var unit = new RustBuildUnit();
        if (unit.ReportEnvironment().Status is "unavailable" or null
            || !unit.CrossTargetReady(RustBuildUnit.MapTriple(new TargetProfile("linux", "amd64"))))
            return; // the toolchain is not installed here; the environment report names the fix

        var extension = FixtureExtension();
        var @params = Params() with
        {
            Extensions = [new ExtensionOverlay(
                "fixture-ext",
                extension,
                ["collect.fixture"])],
        };

        var artifact = await unit.BuildAsync(@params);

        // The build itself is the assertion: the overlay wired the crate, the
        // generated registry compiled, and the artifact came back carrying
        // bytes -- an extension that broke any link in that chain fails the
        // cargo step loudly.
        Assert.True(artifact.Size > 0);
        Assert.Equal(BuildUnitIds.Rust, artifact.UnitId);
    }

    [Fact]
    public async Task TheLoaderTier_RefusesExtensionSelection()
    {
        var unit = new RustBuildUnit();
        var @params = Params() with
        {
            Kind = PayloadKind.Loader,
            DeliversPayloadId = Guid.NewGuid(),
            Extensions = [new ExtensionOverlay("any", "/nowhere", ["any.thing"])],
        };

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(() => unit.BuildAsync(@params));
        Assert.Contains("loader", refusal.Message);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }
}
