using Rod.Capabilities.Browser;
using Rod.Capabilities.Core;
using Rod.Capabilities.Evasion;
using Rod.Capabilities.Module;
using Rod.Capabilities.Registry;
using Rod.Capabilities.Tunnel;
using Rod.CoreState.Implants;

namespace Rod.Capabilities.Coverage;

/// <summary>
/// A technique's implementation status on this teamserver
/// (architecture.md Sec 15.3, ADR-007).
/// </summary>
public enum CoverageStatus
{
    /// <summary>
    /// An in-tree reference implementation carries the verb: the compiled
    /// implant core (architecture.md Sec 13) or the served browser hook
    /// script's read-and-steer set.
    /// </summary>
    Core,

    /// <summary>
    /// A loaded capability module carries the verb -- the status every
    /// community contribution earns on install.
    /// </summary>
    Module,

    /// <summary>
    /// Declared but unimplemented: the placeholder is the only registration,
    /// so the verb reads as an open work item on the matrix.
    /// </summary>
    Gap,
}

/// <summary>One technique row of the coverage matrix.</summary>
/// <param name="TechniqueId">The ATT&CK id, e.g. <c>T1082</c>.</param>
/// <param name="Name">The technique's display name.</param>
/// <param name="Tactics">The enterprise tactics (short names) it falls under.</param>
/// <param name="Carriers">
/// Every registered verb that maps to the technique, with its status and the
/// module and implant classes carrying it.
/// </param>
/// <param name="Platforms">
/// The union of the carriers' class platform surfaces; empty for techniques
/// carried only by ungated verbs, whose reach is decided per deployment.
/// </param>
public sealed record CoverageRow(
    string TechniqueId,
    string Name,
    IReadOnlyList<string> Tactics,
    IReadOnlyList<CoverageCarrier> Carriers,
    IReadOnlyList<string> Platforms);

/// <summary>
/// One verb carrying a matrix technique: the tasking identifier, its
/// implementation status, the module behind it (its published name when it
/// carries one), and the implant classes whose reduced set gates it
/// (<c>ungated</c> for the contract-only verbs no class carries).
/// </summary>
public sealed record CoverageCarrier(
    string Verb,
    CoverageStatus Status,
    string? Module,
    IReadOnlyList<string> ImplantClasses);

/// <summary>The whole matrix, with the tactic and platform facets the data carries.</summary>
public sealed record CoverageMatrix(
    string AttackVersion,
    IReadOnlyList<string> Tactics,
    IReadOnlyList<string> Platforms,
    IReadOnlyList<CoverageRow> Rows);

/// <summary>
/// Builds the coverage matrix (architecture.md Sec 15.3, ADR-007): technique
/// x platform x implementation status, each technique naming the verb, module,
/// and implant classes that carry it -- the "what can be done" face of the
/// mapping data, with the gap rows doubling as the work queue.
/// </summary>
/// <remarks>
/// The builder joins three authorities and invents none of its own: the
/// technique mapping (through <see cref="IVerbTechniqueResolver"/>, the same
/// answer the report's Navigator layer reads), the reference metadata
/// (<see cref="AttackTechniqueCatalog"/>: names and tactics), and the class
/// set (<see cref="ImplantClassCapabilities"/> with
/// <see cref="ImplantClassPlatforms"/>: carriers and the platform axis). A
/// technique only appears when a verb the process can actually task maps to
/// it -- the matrix reports the running deployment, never an aspiration.
/// </remarks>
public static class CoverageMatrixBuilder
{
    /// <summary>
    /// The verbs with an in-tree reference implementation behind their
    /// placeholder: the reference implant's compiled core (architecture.md
    /// Sec 13 -- the carriages including the plugin seam's own family,
    /// command execution, transfer both ways, listing, termination, cadence
    /// retuning, the tunnel pair, and the Windows-gated injection verb) plus
    /// the browser hook script's read-and-steer six.
    /// </summary>
    public static readonly IReadOnlySet<string> InTreeVerbs = new HashSet<string>(
        StringComparer.OrdinalIgnoreCase)
    {
        CoreCapabilities.ShellExec, CoreCapabilities.ShellInteract,
        CoreCapabilities.FilePush, CoreCapabilities.FilePull,
        CoreCapabilities.FsList, CoreCapabilities.ProcKill,
        CoreCapabilities.BeaconSleep,
        TunnelCapabilities.Forward, TunnelCapabilities.Socks,
        EvasionCapabilities.InjectShellcode,
        ModuleCapabilities.ModuleLoad, ModuleCapabilities.ModuleUnload,
        ModuleCapabilities.ModuleList,
        BrowserCapabilities.Fingerprint, BrowserCapabilities.Cookies,
        BrowserCapabilities.Dom, BrowserCapabilities.Screenshot,
        BrowserCapabilities.Redirect, BrowserCapabilities.Prompt,
    };

    /// <summary>
    /// Builds the matrix for the running registry. Optional
    /// <paramref name="tactic"/> and <paramref name="platform"/> filters keep
    /// the rows whose technique falls under the tactic and whose carriers
    /// reach the platform (case-insensitive; an unknown value filters to
    /// nothing, the honest answer).
    /// </summary>
    public static async Task<CoverageMatrix> BuildAsync(
        ICapabilityRegistry registry,
        IVerbTechniqueResolver techniques,
        string? tactic = null,
        string? platform = null,
        CancellationToken cancellationToken = default)
    {
        var byTechnique = new SortedDictionary<string, List<CoverageCarrier>>(StringComparer.Ordinal);
        foreach (var descriptor in await registry.ListAsync(cancellationToken))
        {
            var ids = techniques.Techniques(descriptor.Verb);
            if (ids is null)
                continue;

            var carrier = await CarrierAsync(registry, descriptor.Verb, cancellationToken);
            foreach (var id in ids)
            {
                if (!byTechnique.TryGetValue(id, out var carriers))
                    byTechnique[id] = carriers = new List<CoverageCarrier>();
                carriers.Add(carrier);
            }
        }

        var all = new List<CoverageRow>();
        foreach (var (id, carriers) in byTechnique)
        {
            // A module declaration may name a technique the kernel's catalog
            // carries no metadata for -- the catalog is display data for what
            // the kernel's own verbs map to, never a taxonomy of what may
            // exist (the advancement rule: coverage extends without a kernel
            // edit). The row renders with the id alone; suppressing it would
            // make the module's declared coverage invisible.
            var technique = AttackTechniqueCatalog.Find(id);

            all.Add(new CoverageRow(
                technique?.Id ?? id,
                technique?.Name ?? "",
                technique?.Tactics ?? [],
                carriers.OrderBy(c => c.Verb, StringComparer.Ordinal).ToArray(),
                carriers.SelectMany(PlatformsOf).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.Ordinal).ToArray()));
        }

        // The facets describe the whole matrix, not the filtered slice, so a
        // filter never hides the axis values it did not select.
        var rows = all
            .Where(r => tactic is not { Length: > 0 }
                || r.Tactics.Contains(tactic, StringComparer.OrdinalIgnoreCase))
            .Where(r => platform is not { Length: > 0 }
                || r.Carriers.Any(c => ReachesPlatform(c, platform)))
            .ToArray();

        return new CoverageMatrix(
            AttackTechniqueCatalog.AttackVersion,
            all.SelectMany(r => r.Tactics).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(t => t, StringComparer.Ordinal).ToArray(),
            all.SelectMany(r => r.Platforms).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.Ordinal).ToArray(),
            rows);
    }

    private static async Task<CoverageCarrier> CarrierAsync(
        ICapabilityRegistry registry, string verb, CancellationToken cancellationToken)
    {
        var module = await registry.FindAsync(verb, cancellationToken);
        if (module is not { } real || real is PlaceholderCapabilityModule)
        {
            // A registered verb always resolves, but the shape stays honest if
            // one ever does not: no module behind it, the in-tree set decides.
            return new CoverageCarrier(
                verb,
                InTreeVerbs.Contains(verb) ? CoverageStatus.Core : CoverageStatus.Gap,
                Module: null,
                ImplantClasses: ClassesOf(verb));
        }

        return new CoverageCarrier(
            verb,
            CoverageStatus.Module,
            Module: real.Name ?? real.GetType().Name,
            ImplantClasses: ClassesOf(verb));
    }

    private static IReadOnlyList<string> ClassesOf(string verb)
    {
        if (ImplantClassCapabilities.Ungated.Contains(verb, StringComparer.OrdinalIgnoreCase))
            return ["ungated"];

        var classes = new List<string>();
        foreach (ImplantClass @class in Enum.GetValues(typeof(ImplantClass)))
        {
            if (ImplantClassCapabilities.Allows(@class, verb))
                classes.Add(@class.ToString().ToLowerInvariant());
        }

        return classes;
    }

    private static IEnumerable<string> PlatformsOf(CoverageCarrier carrier)
        => carrier.ImplantClasses.Contains("ungated", StringComparer.OrdinalIgnoreCase)
            ? []
            : carrier.ImplantClasses
                .Select(name => Enum.TryParse<ImplantClass>(name, ignoreCase: true, out var @class)
                    ? ImplantClassPlatforms.For(@class)
                    : [])
                .SelectMany(p => p);

    private static bool ReachesPlatform(CoverageCarrier carrier, string platform)
        => PlatformsOf(carrier).Contains(platform, StringComparer.OrdinalIgnoreCase);
}
