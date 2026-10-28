using System.Text;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.Build.Tests;

/// <summary>
/// The post-build transform chain (architecture.md Sec 6, the transform
/// seam): the ordered application of out-of-tree transforms over the build
/// unit's output. These checks pin the seam's own contract -- transforms
/// compose in listed order, each one's output feeding the next; the empty
/// chain passes bytes through untouched; the artifact's fingerprint covers
/// the transformed bytes; and the applied names and metadata notes ride the
/// artifact for the audit trail. The loader checks mirror the tradecraft
/// module loader's: config-named types load, malformed or foreign entries
/// fail loudly.
/// </summary>
public class PayloadTransformTests
{
    // A transform that prepends its marker -- the composition order is
    // observable in the bytes.
    private sealed class PrefixTransform(string name, string marker, string? metadata = null) : IPayloadTransform
    {
        public string Name { get; } = name;

        public Task<PayloadTransformOutput> ApplyAsync(
            PayloadTransformInput input, CancellationToken cancellationToken = default)
            => Task.FromResult(new PayloadTransformOutput(
                Encoding.UTF8.GetBytes(marker).Concat(input.Artifact).ToArray(),
                metadata));
    }

    private static BuildRequest Request() => new(
        EngagementId.New(),
        OperatorId.New(),
        "stub-go",
        ImplantClass.Implant,
        new TargetProfile("linux", "amd64"),
        new TransportProfile("http://c2.example.test/implants/enroll", "/beacon"),
        Sleep: TimeSpan.FromSeconds(30),
        Jitter: TimeSpan.FromSeconds(10),
        KillDate: null);

    private static PayloadBuildService ServiceWith(params IPayloadTransform[] transforms)
    {
        var registry = new InMemoryBuildUnitRegistry();
        registry.Register(new StubBuildUnit());
        return new PayloadBuildService(registry, TimeProvider.System, new PayloadTransformChain(transforms));
    }

    [Fact]
    public async Task Chain_ComposesInOrder_AndRecordsNamesAndMetadata()
    {
        var service = ServiceWith(
            new PrefixTransform("outer-wrap", "OUT:"),
            new PrefixTransform("inner-wrap", "IN:", metadata: "the inner note"));

        var artifact = await service.BuildAsync(Request());

        var text = Encoding.UTF8.GetString(artifact.Content);
        // Listed order is application order: outer-wrap runs first over the
        // raw bytes, inner-wrap runs second over that output -- so each
        // prepending transform lands outside the ones before it.
        Assert.StartsWith("IN:OUT:", text);
        Assert.Equal(2, artifact.Transforms.Count);
        Assert.Equal("outer-wrap", artifact.Transforms[0].Name);
        Assert.Null(artifact.Transforms[0].Metadata);
        Assert.Equal("inner-wrap", artifact.Transforms[1].Name);
        Assert.Equal("the inner note", artifact.Transforms[1].Metadata);

        // The fingerprint covers the transformed bytes, not the unit's raw
        // output -- the stored trail answers for the bytes that ship.
        var expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(artifact.Content))
            .ToLowerInvariant();
        Assert.Equal(expected, artifact.Fingerprint);
        Assert.Equal(artifact.Content.Length, artifact.Size);
    }

    [Fact]
    public async Task EmptyChain_PassesBytesThroughUntouched()
    {
        var service = ServiceWith();

        var artifact = await service.BuildAsync(Request());

        // No marker, no transforms: the bytes are the unit's raw output and
        // the artifact says so -- the empty chain is the seam (Sec 6).
        var text = Encoding.UTF8.GetString(artifact.Content);
        Assert.DoesNotContain("OUT:", text);
        Assert.DoesNotContain("IN:", text);
        Assert.Empty(artifact.Transforms);

        var expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(artifact.Content))
            .ToLowerInvariant();
        Assert.Equal(expected, artifact.Fingerprint);
    }

    [Fact]
    public void Loader_LoadsAConfigNamedType_FromItsOwnAssembly()
    {
        var loaded = PayloadTransformLoader.Load(new[]
        {
            "Rod.Build.Tests.PayloadTransformTests+LoadableTransform, Rod.Build.Tests",
        });

        Assert.Single(loaded);
        Assert.Equal("loadable", loaded[0].Name);
    }

    [Fact]
    public void Loader_FailsLoudlyOnBadEntries()
    {
        Assert.Throws<InvalidOperationException>(
            () => PayloadTransformLoader.Load(new string?[] { "" }));
        Assert.Throws<InvalidOperationException>(
            () => PayloadTransformLoader.Load(new[] { "NoCommaHere" }));
        Assert.Throws<InvalidOperationException>(
            () => PayloadTransformLoader.Load(new[] { "Rod.Build.Tests.PayloadTransformTests, Rod.Build.Tests" }));
        Assert.Throws<InvalidOperationException>(
            () => PayloadTransformLoader.Load(new[] { "Rod.Build.Tests.NoSuchType, Rod.Build.Tests" }));
    }

    // The parameterless, contract-only stand-in the loader contactsstantiate.
    public sealed class LoadableTransform : IPayloadTransform
    {
        public string Name => "loadable";

        public Task<PayloadTransformOutput> ApplyAsync(
            PayloadTransformInput input, CancellationToken cancellationToken = default)
            => Task.FromResult(new PayloadTransformOutput(input.Artifact));
    }
}
