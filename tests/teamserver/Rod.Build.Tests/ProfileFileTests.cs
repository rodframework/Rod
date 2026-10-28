using System.Text;
using System.Text.Json;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.Build.Tests;

/// <summary>
/// The profile file contract (architecture.md Sec 5.1, Sec 15.2): the bake
/// is one standalone file, <c>rod.profile.json</c>, that every build unit
/// stages verbatim and every implant tree embeds at compile time. The
/// acceptance here is the contract's whole point -- one profile file drives
/// both in-tree build units' bakes with no unit-specific parsing, so an
/// out-of-tree unit consumes the same documented shape the in-tree pair
/// proves (extending/implants.md, "The baked profile file").
/// </summary>
public class ProfileFileTests
{
    // A presentation marker no plausible binary noise produces: the file's
    // own JSON key-value fragments, asserted inside the built artifacts.
    private const string MarkerUa = "rod-file-contract-probe/1.0";

    [Fact]
    public void TheFileIsTheCanonicalJson_UnderTheContractName()
    {
        var @params = Params();
        var dir = Path.Combine(Path.GetTempPath(), "rod-profile-file-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            ProfileBake.WriteFile(@params, dir);

            var file = Path.Combine(dir, ProfileBake.FileName);
            Assert.Equal("rod.profile.json", Path.GetFileName(file));
            // Byte-for-byte the canonical render: the staged file and the
            // render are the same document, so every unit's tree embeds
            // identical bytes for identical params.
            var written = File.ReadAllText(file);
            Assert.Equal(ProfileBake.Render(@params), written);
            using var parsed = JsonDocument.Parse(written);
            Assert.Equal(MarkerUa, parsed.RootElement.GetProperty("userAgent").GetString());
            Assert.Equal(
                "contract",
                parsed.RootElement.GetProperty("headers").GetProperty("X-Rod-File").GetString());
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void TheRenderIsDeterministic_AcrossRenders()
    {
        // The same params bake the same bytes twice: the sorted headers
        // object and the fixed key order make the file's content a pure
        // function of the build params.
        Assert.Equal(ProfileBake.Render(Params()), ProfileBake.Render(Params()));
    }

    // The acceptance clause itself: one profile file drives both in-tree
    // units' bakes. The units self-skip on a host without their toolchain
    // (the environment report names the fix), and where both run, the same
    // staged document must appear inside both artifacts -- the embeds are
    // the trees' own (include_str! and go:embed), so the file's bytes ride
    // the binaries verbatim, not re-encoded per unit.
    [Fact]
    public async Task OneProfileFile_DrivesBothInTreeUnits_Bakes()
    {
        var rust = new RustBuildUnit();
        var go = new GoBuildUnit();
        // The same gates the units' own tests hold: the Rust report is
        // "partial" on any host without every cross linker, so readiness is
        // the requested triple's own (std installed, linker found), and the
        // Go report is ready-or-unavailable whole.
        var rustReady = rust.ReportEnvironment().Status is not ("unavailable" or null)
            && rust.CrossTargetReady(RustBuildUnit.MapTriple(new TargetProfile("linux", "amd64")));
        var goReady = go.ReportEnvironment().Status == "ready";
        if (!rustReady || !goReady)
            return; // a toolchain is missing on this host; the environment report names the fix

        var document = Encoding.UTF8.GetBytes(ProfileBake.Render(Params()));
        var ua = Encoding.UTF8.GetBytes($"\"userAgent\":\"{MarkerUa}\"");

        foreach (var artifact in new[] { await rust.BuildAsync(Params()), await go.BuildAsync(Params()) })
        {
            Assert.True(
                artifact.Content.AsSpan().IndexOf(document) >= 0,
                $"the {artifact.UnitId} artifact embeds the profile file verbatim");
            Assert.True(
                artifact.Content.AsSpan().IndexOf(ua) >= 0,
                $"the {artifact.UnitId} artifact carries the baked presentation marker");
        }
    }

    private static BuildParams Params() => new(
        EngagementId.New(),
        OperatorId.New(),
        ImplantClass.Implant,
        new TargetProfile("linux", "amd64"),
        new TransportProfile("http://c2.example.test", "/beacon")
        {
            UserAgent = MarkerUa,
            Headers = new Dictionary<string, string> { ["X-Rod-File"] = "contract" },
        },
        // A fixed kill date keeps the params -- and so the file's bytes --
        // identical across every Params() call, which is what the
        // determinism and both-unit clauses assert.
        new BeaconProfile(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10),
            new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero)));
}
