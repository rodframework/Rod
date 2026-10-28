namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// Resolves a build unit by its unit id (architecture.md Sec 6, ADR-021).
/// The teamserver is coupled to build units only by the build contract, and
/// a request names its unit by the open id, so the registry hands back the
/// unit that owns that toolchain -- in-tree or external alike. The registry
/// is process-local state; build units register into it at startup and, for
/// external units, as their packages are listed.
/// </summary>
public interface IBuildUnitRegistry
{
    /// <summary>Registers <paramref name="unit"/> under its id.</summary>
    void Register(IBuildUnit unit);

    /// <summary>
    /// The build unit for <paramref name="unitId"/>, or null when no unit is
    /// registered for it. Ids compare case-insensitively; kebab-case is the
    /// grammar.
    /// </summary>
    IBuildUnit? Find(string unitId);

    /// <summary>
    /// Every registered unit. The build path resolves by id; the
    /// diagnostics path (the system page's environment report) walks them
    /// all.
    /// </summary>
    IReadOnlyList<IBuildUnit> All { get; }
}
