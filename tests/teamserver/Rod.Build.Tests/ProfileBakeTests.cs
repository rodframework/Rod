using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.Build.Tests;

/// <summary>
/// The baked profile's shape keys (architecture.md Sec 5.1, Sec 9): the
/// trust posture the dials validate under, and the presentation keys the
/// profile file carries for any consuming build unit. The file contract
/// itself -- one file driving every unit's bake -- lives in
/// <see cref="ProfileFileTests"/>.
/// </summary>
public class ProfileBakeTests
{
    [Theory]
    [InlineData(TlsTrust.Pinned, "pinned")]
    [InlineData(TlsTrust.Public, "public")]
    public void TheBakeCarriesTheTlsTrustPosture(TlsTrust trust, string wire)
    {
        var json = Bake(trust, ua: null);

        Assert.Contains($"\"tlsTrust\":\"{wire}\"", json);
    }

    [Fact]
    public void TheBakeCarriesThePresentationKeysAsPlainJson()
    {
        var json = Bake(TlsTrust.Pinned, ua: "RodProbe/1.0");

        // The presentation set any build unit consumes: the malleable
        // path, the agent, the sorted headers object, the timeout, and
        // the two envelope shapes -- plain JSON keys, no encoding layer
        // for an out-of-tree consumer to undo.
        Assert.Contains("\"enrollPath\":\"/implants/enroll\"", json);
        Assert.Contains("\"userAgent\":\"RodProbe/1.0\"", json);
        Assert.Contains("\"headers\":{\"X-Cover\":\"v\",\"X-First\":\"1\"}", json);
        Assert.Contains("\"requestTimeout\":\"45s\"", json);
        Assert.Contains("\"envelope\":\"aesgcm\"", json);
        Assert.Contains("\"contactEnvelope\":\"aesgcm\"", json);
    }

    // The headers ride as a JSON object sorted by key, so the bake's byte
    // output is stable regardless of the profile dictionary's order.
    [Fact]
    public void TheHeadersObjectIsSortedForStableBytes()
    {
        var json = Bake(TlsTrust.Pinned, ua: null);

        var at = json.IndexOf("\"headers\":", StringComparison.Ordinal);
        var sorted = json.Substring(at, json.IndexOf('}', at) - at + 1);
        Assert.Equal("\"headers\":{\"X-Cover\":\"v\",\"X-First\":\"1\"}", sorted);
    }

    private static string Bake(TlsTrust trust, string? ua)
        => ProfileBake.Render(new BuildParams(
            new EngagementId(Guid.NewGuid()),
            new OperatorId(Guid.NewGuid()),
            ImplantClass.Implant,
            new TargetProfile("linux", "amd64"),
            new TransportProfile("https://front.example", "/beacon")
            {
                TlsTrust = trust,
                UserAgent = ua ?? "",
                Headers = new Dictionary<string, string>
                {
                    // Deliberately out of sorted order in construction.
                    ["X-First"] = "1",
                    ["X-Cover"] = "v",
                },
                RequestTimeout = TimeSpan.FromSeconds(45),
            },
            new BeaconProfile(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10), KillDate: null),
            // The minted pair a contact-protection bake rides (the default
            // posture), so contactEnvelope reads its sealed spelling.
            EnvelopeKeyId: Guid.NewGuid(),
            EnvelopeKey: new byte[32]));
}
