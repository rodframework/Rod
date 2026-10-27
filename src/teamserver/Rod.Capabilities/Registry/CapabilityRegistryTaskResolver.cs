using Rod.CoreState.Implants;

namespace Rod.Capabilities.Registry;

/// <summary>
/// The capability-registry-backed <see cref="ITaskCapabilityResolver"/>
/// (architecture.md Sec 5.2/10.2/10.3). The composition root swaps this in for
/// core state's strict class-table default so the live task path resolves verbs
/// through the capability registry in addition to the per-class reduced set.
/// </summary>
/// <remarks>
/// <para>
/// The class table stays the primary authority: a verb in the implant's class
/// set is always dispatchable. A verb the class set does not admit falls
/// through to the registry only when no other class gates it -- the path that
/// opens dispatch for the contract-and-dispatch-only categories
/// (architecture.md Sec 10.2). Evasion and exploit are not class-gated
/// (Sec 5.2/10.1); they are dispatchable here when a module is registered for
/// the verb, which the built-in load guarantees for every framework verb and
/// a config-listed override keeps. A verb another class's set carries stays
/// gated to that class: the registry widens the gate for ungated verbs, it
/// never re-gates a class-gated one.
/// </para>
/// <para>
/// A registered module -- the built-in placeholder or an operator-supplied
/// module -- is what satisfies the gate. The placeholder represents
/// "the framework knows this verb"; concrete behavior runs on the implant
/// (architecture.md Sec 10.3) and arrives as an opt-in module for the sensitive
/// categories (Sec 13, AGENTS.md Sec 7). This layer holds the contract and the
/// dispatch path, never the tradecraft.
/// </para>
/// <para>
/// Lives in the capabilities layer (Layer 6, may depend on core state) so core
/// state stays inward-only: it defines the port, this layer implements it.
/// </para>
/// </remarks>
public sealed class CapabilityRegistryTaskResolver : ITaskCapabilityResolver
{
    private readonly ICapabilityRegistry _registry;

    public CapabilityRegistryTaskResolver(ICapabilityRegistry registry)
    {
        _registry = registry;
    }

    /// <summary>
    /// True when <paramref name="verb"/> is in <paramref name="class"/>'s reduced
    /// verb set, or -- for a verb no class set gates -- a capability module is
    /// registered for it. The class table is checked first (short-circuit, no
    /// allocation); only ungated verbs consult the registry.
    /// </summary>
    public bool IsDispatchable(ImplantClass @class, string verb)
        => ImplantClassCapabilities.Allows(@class, verb)
            || (!ImplantClassCapabilities.GatedToAnyClass(verb)
                && _registry.FindAsync(verb).GetAwaiter().GetResult() is not null);

    /// <summary>
    /// The named module's requirement rows (ADR-017's runtime half): the
    /// registry's by-name lookup, answered null for an unknown name or a
    /// module that declares none -- both mean no rows to check, exactly what
    /// the class-table default answers.
    /// </summary>
    public IReadOnlyList<string>? ModuleRequires(string moduleName)
        => _registry.FindByNameAsync(moduleName).GetAwaiter().GetResult()?.Requires;
}
