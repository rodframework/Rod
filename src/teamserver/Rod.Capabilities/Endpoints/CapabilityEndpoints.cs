using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Capabilities.Registry;

namespace Rod.Capabilities.Endpoints;

/// <summary>
/// The operator-facing capability-catalog endpoint: lists every
/// registered capability verb so the operator UI can surface the full capability
/// set as tasking from the registry rather than a hardcoded verb table. The
/// catalog carries each verb's category and OPSEC attributes (architecture.md
/// Sec 7/10.1) so the UI can group verbs by operational purpose and flag risky
/// actions. Sensitive categories (evasion, exploit) are listed too -- this layer
/// holds only the contract and dispatch path, never concrete tradecraft
/// (architecture.md Sec 13, AGENTS.md Sec 7).
/// </summary>
/// <remarks>
/// Mapped by the composition root alongside <c>MapOperatorEndpoints</c>, the same
/// way the operator layer maps its SSE stream: transport cannot reference
/// <c>Rod.Capabilities</c> (architecture test <c>LayerDependencyTests</c>), so the
/// catalog endpoint is exposed from the layer that owns the registry. The catalog
/// is global (not engagement-scoped): capability verbs are the language-neutral
/// contract implants build against, independent of any one engagement.
/// </remarks>
public static class CapabilityEndpoints
{
    public static IEndpointRouteBuilder MapCapabilityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Operator-facing: the capability catalog requires an authenticated
        // operator session.
        var group = endpoints.MapGroup("/capabilities").RequireAuthorization();
        group.MapGet("/", ListAsync).WithName("ListCapabilities");
        group.MapGet("/coverage", GetCoverageAsync).WithName("GetCapabilityCoverage");
        return endpoints;
    }

    private static async Task<IResult> ListAsync(
        ICapabilityRegistry registry,
        Rod.CoreState.Implants.IVerbTechniqueResolver techniques,
        CancellationToken cancellationToken)
    {
        // Registration order is stable (the registry preserves it), so the catalog
        // reads in a predictable category order for the UI's grouping. The module
        // view carries each verb's module-level metadata beside the descriptor:
        // the published name and the requirement rows (ADR-017) the operator
        // UI's loadable-set filter matches against a session's advertisement.
        var modules = await registry.ListModulesAsync(cancellationToken);
        var body = modules.Select(m => CapabilityDescriptorResponse.Of(m, techniques)).ToArray();
        return Results.Ok(body);
    }

    private static async Task<IResult> GetCoverageAsync(
        ICapabilityRegistry registry,
        Rod.CoreState.Implants.IVerbTechniqueResolver techniques,
        string? tactic,
        string? platform,
        CancellationToken cancellationToken)
    {
        // The coverage matrix (ADR-007) is registry metadata like the catalog:
        // process-global, not engagement-scoped, so it lives beside the catalog
        // under the layer that owns the registry. The tactic and platform
        // filters are the matrix view's axes.
        var matrix = await Coverage.CoverageMatrixBuilder.BuildAsync(registry, techniques, tactic, platform, cancellationToken);
        return Results.Ok(CoverageResponse.Of(matrix));
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    /// <summary>
    /// One parameter of a verb's schema: the field the operator UI renders
    /// generically (architecture.md Sec 15.2, the trilogy's first contract).
    /// </summary>
    public sealed record VerbParameterResponse(
        string Name,
        string Label,
        string Kind,
        bool Required,
        string? Help,
        string? Placeholder,
        IReadOnlyList<string>? Choices,
        bool Trailing,
        bool Inline)
    {
        public static VerbParameterResponse Of(Capabilities.VerbParameter p)
            => new(
                p.Name,
                p.Label,
                p.Kind.ToString(),
                p.Required,
                p.Help,
                p.Placeholder,
                p.Choices,
                p.Trailing,
                p.Inline);
    }

    /// <summary>
    /// A verb's declared output: the taxonomy kind that routes its results to
    /// the generic panels (architecture.md Sec 15.2, the trilogy's second
    /// contract), plus the one-sentence description of what the results hold.
    /// Null when the verb declared none -- plain text, the honest fallback.
    /// </summary>
    public sealed record VerbOutputResponse(string Kind, string? Help)
    {
        public static VerbOutputResponse? Of(Capabilities.VerbOutput? o)
            => o is null ? null : new(o.Kind.ToString(), o.Help);
    }

    /// <summary>
    /// One capability a registered module provides. The verb is the tasking
    /// identifier (<c>namespace.action</c>); <see cref="Category"/> groups it for
    /// the UI; <see cref="Attributes"/> is the per-verb OPSEC surface
    /// (architecture.md Sec 7) the UI surfaces as risk badges;
    /// <see cref="Parameters"/> is the task-form schema and
    /// <see cref="Output"/> the output-taxonomy declaration (architecture.md
    /// Sec 15.2) -- everything the UI needs to task a verb it has never met.
    /// <see cref="Techniques"/> is the verb's resolved ATT&CK mapping
    /// (ADR-007): the module's declaration when it carries one, else the
    /// kernel data file's entry -- the same answer the coverage matrix and
    /// the report's Navigator layer read. <see cref="Module"/> and
    /// <see cref="Requires"/> are the module-level metadata (ADR-017): the
    /// published name a <c>module.load</c> names and the wire capabilities
    /// the hosting implant must advertise, both null for a placeholder.
    /// </summary>
    public sealed record CapabilityDescriptorResponse(
        string Verb,
        string Category,
        string Version,
        IReadOnlyDictionary<string, string> Attributes,
        IReadOnlyList<VerbParameterResponse>? Parameters,
        VerbOutputResponse? Output,
        IReadOnlyList<string> Techniques,
        string? Module = null,
        IReadOnlyList<string>? Requires = null)
    {
        public static CapabilityDescriptorResponse Of(
            Modules.ICapabilityModule module,
            Rod.CoreState.Implants.IVerbTechniqueResolver techniques)
        {
            var d = module.Descriptor;
            return new(
                d.Verb,
                d.Category.ToString(),
                d.Version,
                d.Attributes,
                d.Parameters?.Select(VerbParameterResponse.Of).ToArray(),
                VerbOutputResponse.Of(d.Output),
                techniques.Techniques(d.Verb) ?? Array.Empty<string>(),
                module.Name,
                module.Requires);
        }
    }

    // --- The coverage matrix (ADR-007): one projection, DTOs kept lean. ---

    public sealed record CoverageResponse(
        string AttackVersion,
        IReadOnlyList<string> Tactics,
        IReadOnlyList<string> Platforms,
        IReadOnlyList<CoverageRowResponse> Techniques)
    {
        public static CoverageResponse Of(Coverage.CoverageMatrix matrix)
            => new(
                matrix.AttackVersion,
                matrix.Tactics,
                matrix.Platforms,
                matrix.Rows.Select(CoverageRowResponse.Of).ToArray());
    }

    public sealed record CoverageRowResponse(
        string TechniqueId,
        string Name,
        IReadOnlyList<string> Tactics,
        IReadOnlyList<CoverageCarrierResponse> Carriers,
        IReadOnlyList<string> Platforms)
    {
        public static CoverageRowResponse Of(Coverage.CoverageRow row)
            => new(row.TechniqueId, row.Name, row.Tactics, row.Carriers.Select(CoverageCarrierResponse.Of).ToArray(), row.Platforms);
    }

    public sealed record CoverageCarrierResponse(
        string Verb,
        string Status,
        string? Module,
        IReadOnlyList<string> ImplantClasses)
    {
        public static CoverageCarrierResponse Of(Coverage.CoverageCarrier carrier)
            => new(carrier.Verb, carrier.Status.ToString().ToLowerInvariant(), carrier.Module, carrier.ImplantClasses);
    }

}
