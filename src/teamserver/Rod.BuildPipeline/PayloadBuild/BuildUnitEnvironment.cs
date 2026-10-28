namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// A build unit's self-reported environment (architecture.md Sec 6): what
/// the unit needs from its host -- toolchains, cross linkers, source trees,
/// caches -- and whether each was found. This is the diagnostics surface the
/// operator UI's system page reads, so an operator can see a missing
/// cross-compiler before a build spends minutes failing inside it. The seam
/// is a capability, not an obligation: an out-of-tree unit that cannot
/// probe itself simply does not implement it, and the system page reports
/// only what it can verify.
/// </summary>
public interface IBuildUnitEnvironment
{
    /// <summary>
    /// Probes the host now. Cheap enough for a page load, pointed enough to
    /// name the fix: process launches are version queries, directory walks
    /// are existence checks.
    /// </summary>
    BuildUnitEnvironmentReport ReportEnvironment();
}

/// <summary>
/// One unit's findings: a verdict (ready / partial / unavailable), the
/// per-area findings that compose it, and the per-target readiness for every
/// target the unit can map. The verdict only falls to unavailable on a
/// missing prerequisite -- findings at warn (a cold cache, say) leave a
/// usable unit.
/// </summary>
public sealed record BuildUnitEnvironmentReport(
    string UnitId,
    string Status,
    IReadOnlyList<BuildEnvironmentFinding> Findings,
    IReadOnlyList<BuildTargetReadiness> Targets);

/// <summary>
/// One environmental fact. <see cref="Level"/> is "ok", "warn", or
/// "missing"; <see cref="Area"/> names the concern (the tool, the source
/// tree, the cache) and <see cref="Detail"/> states what was found and,
/// when not "ok", the fix.
/// </summary>
public sealed record BuildEnvironmentFinding(string Level, string Area, string Detail);

/// <summary>
/// Whether one buildable target is actually buildable on this host: the
/// Rust std for its triple installed, and the C linker its platform pieces
/// need present on PATH.
/// </summary>
public sealed record BuildTargetReadiness(
    string Triple,
    string Target,
    bool StdInstalled,
    bool LinkerFound,
    string Linker);
