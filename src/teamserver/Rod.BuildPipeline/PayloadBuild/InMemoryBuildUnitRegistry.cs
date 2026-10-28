using System.Collections.Concurrent;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// In-memory <see cref="IBuildUnitRegistry"/> by default. Build
/// units live in a process-local dictionary keyed by unit id (the open
/// kebab-case vocabulary ADR-021 opens); last registration wins. No lock is
/// needed: registration happens at startup (and, for external units, under
/// the module lifecycle's own serialization) before any build request, and
/// the dictionary is read-mostly thereafter (the same shape as the other
/// read-mostly in-memory adapters).
/// </summary>
public sealed class InMemoryBuildUnitRegistry : IBuildUnitRegistry
{
    private readonly ConcurrentDictionary<string, IBuildUnit> _units =
        new(StringComparer.OrdinalIgnoreCase);

    public void Register(IBuildUnit unit) => _units[unit.UnitId] = unit;

    public IBuildUnit? Find(string unitId)
        => _units.TryGetValue(unitId, out var unit) ? unit : null;

    public IReadOnlyList<IBuildUnit> All => _units.Values.ToArray();
}
