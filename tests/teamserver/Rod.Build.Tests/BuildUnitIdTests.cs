using Rod.BuildPipeline.PayloadBuild;

namespace Rod.Build.Tests;

/// <summary>
/// The build-unit id freeze pin (ADR-019, executed at v1.0.0): the ids ride
/// payload build requests, manifests' targeting rows, the canonical form,
/// and the external build contract's files, so a rename breaks every
/// published extension and unit package. The vocabulary stays open (a
/// community unit claims any kebab id); the pin holds the in-tree members
/// under their exact spelling.
/// </summary>
public class BuildUnitIdTests
{
    [Fact]
    public void TheInTreeUnitIds_AreTheConstantsVerbatim()
    {
        Assert.Equal("rod-rust", BuildUnitIds.Rust);
        Assert.Equal("rod-go", BuildUnitIds.Go);
    }
}
