using Rod.CoreState;
using Rod.CoreState.Implants;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// The payload-build result schema -- the build unit half of the build contract
/// (architecture.md Sec 6). A compiled (stub, for now) artifact returned to the
/// teamserver, fingerprinted and ready to be recorded. The fingerprint is a
/// SHA-256 hex digest over <see cref="Content"/>; <see cref="Size"/> is its byte
/// length. <see cref="Params"/> is the build request that produced this artifact,
/// carried back so the recorder has the full who/when/config alongside the
/// fingerprint (architecture.md Sec 11). <see cref="UnitId"/> records which
/// build unit compiled it -- the contract input is unit-neutral, so the unit
/// stamps its id on the result.
///
/// <see cref="Transforms"/> names every post-build transform that produced
/// <see cref="Content"/> (architecture.md Sec 6, the transform seam), in
/// application order -- empty when the chain was empty and the bytes are the
/// unit's raw output. The fingerprint covers the transformed bytes, so this
/// list is what answers "which transforms produced the stored bytes".
/// </summary>
public sealed record BuildArtifact(
    Guid ArtifactId,
    EngagementId EngagementId,
    ImplantClass Class,
    string UnitId,
    byte[] Content,
    string ContentType,
    string Fingerprint,
    long Size,
    DateTimeOffset BuiltAt,
    BuildParams Params)
{
    /// <summary>The applied transform names in application order; empty when none.</summary>
    public IReadOnlyList<PayloadTransformApplied> Transforms { get; init; } = Array.Empty<PayloadTransformApplied>();

    /// <summary>
    /// Builds a result from compiled <paramref name="content"/>, computing the
    /// fingerprint and size. Build units call this rather than hand-filling the
    /// fields, so the fingerprint always agrees with the bytes.
    /// </summary>
    public static BuildArtifact Of(
        string unitId,
        Guid artifactId,
        BuildParams @params,
        byte[] content,
        string contentType,
        DateTimeOffset builtAt)
    {
        var fingerprint = ArtifactFingerprint.Of(content);
        return new BuildArtifact(
            artifactId,
            @params.EngagementId,
            @params.Class,
            unitId,
            content,
            contentType,
            fingerprint,
            content.LongLength,
            builtAt,
            @params);
    }
}
