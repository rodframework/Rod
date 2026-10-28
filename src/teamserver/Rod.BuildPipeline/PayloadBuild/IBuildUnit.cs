namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// A build unit (architecture.md Sec 6, ADR-021): the owner of one implant
/// toolchain. The in-tree units compile the Rust and Go references; an
/// external unit is a package whose manifest declares its
/// <c>[unit]</c> table -- the pipeline routes a request to it by
/// <see cref="UnitId"/> and spawns its command with the request file, so a
/// community implant in any language registers without the teamserver
/// compiling a line of its code. The teamserver drives every unit through
/// this uniform contract and is coupled to it by nothing else.
/// </summary>
public interface IBuildUnit
{
    /// <summary>The unit id this unit answers to -- an open kebab-case
    /// vocabulary; the in-tree members are <see cref="BuildUnitIds.Rust"/>
    /// and <see cref="BuildUnitIds.Go"/>.</summary>
    string UnitId { get; }

    /// <summary>
    /// Compiles <paramref name="params"/> into a fingerprinted artifact. Build
    /// params are produced at request time so each artifact is unique
    /// (architecture.md Sec 6); the unit bakes them in and returns the bytes.
    /// </summary>
    Task<BuildArtifact> BuildAsync(BuildParams @params, CancellationToken cancellationToken = default);
}
