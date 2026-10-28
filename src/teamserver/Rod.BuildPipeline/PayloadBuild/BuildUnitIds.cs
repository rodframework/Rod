namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// The unit ids the in-tree build units claim (architecture.md Sec 6,
/// ADR-021). The build pipeline routes a request to its unit by this open
/// string -- not an enum -- so a community implant in any language registers
/// a build unit (an external unit's manifest declares the id, the pipeline
/// spawns the command) without the teamserver compiling a line of its code.
/// The vocabulary is open; these constants are the in-tree members an
/// operator can always expect.
/// </summary>
public static class BuildUnitIds
{
    /// <summary>The Rust reference implant's unit (Sec 12.2): native size,
    /// static musl, the platform breadth a managed runtime cannot
    /// cover.</summary>
    public const string Rust = "rod-rust";

    /// <summary>The Go community-slot reference (Sec 12.2): the Tier 0 wire
    /// client, its unit in-tree as the worked example of the open
    /// slot.</summary>
    public const string Go = "rod-go";
}
