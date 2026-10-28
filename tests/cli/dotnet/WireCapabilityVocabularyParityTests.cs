using Rod.Packaging;

namespace Rod.Cli.Tests;

/// <summary>
/// The wire-capability vocabulary is a file contract: Rod.Packaging parses
/// <c>compatibility.requires</c> from manifests, the teamserver's runtime
/// requirement gate (ADR-017's runtime half, in Rod.CoreState) matches the
/// names against a session's advertisement. The runtime vocabulary cannot
/// live in the contract library without CoreState depending on it, so this
/// test -- and only this test project -- bridges the two sets and fails
/// when either side grows without the other.
/// </summary>
public class WireCapabilityVocabularyParityTests
{
    [Fact]
    public void TheVocabularies_AreTheSameClosedSet()
    {
        Assert.Equal(
            Rod.CoreState.Implants.WireCapabilities.Requirable,
            WireCapabilities.Requirable);
    }
}
