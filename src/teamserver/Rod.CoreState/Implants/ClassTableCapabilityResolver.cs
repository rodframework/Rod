namespace Rod.CoreState.Implants;

/// <summary>
/// The default <see cref="ITaskCapabilityResolver"/>: the per-class reduced verb
/// set alone (architecture.md Sec 5.2). This is the inner-ring authority both the
/// build pipeline and the capabilities layer read; it is the gate task issuance
/// consulted before the capabilities layer was wired onto the live path, so the
/// core-state unit tests and any host that does not opt into the capabilities layer
/// keep exactly the behavior they had.
/// </summary>
/// <remarks>
/// Stateless; safe as a singleton. The composition root replaces this with the
/// tradecraft-backed adapter (<c>Rod.Capabilities.CapabilityRegistryTaskResolver</c>)
/// when the capability registry is wired in, the same way the live-event bus
/// replaces the no-op default -- but this stays the fallback that admits only the
/// class-gated verbs.
/// </remarks>
public sealed class ClassTableCapabilityResolver : ITaskCapabilityResolver
{
    /// <summary>
    /// True when <paramref name="verb"/> is in <paramref name="class"/>'s reduced
    /// verb set (<see cref="ImplantClassCapabilities.Allows"/>). No registry
    /// fallback: an evasion or exploit verb (contract and dispatch only, Sec 10.2)
    /// is not admitted here -- that path opens when the capabilities layer is wired.
    /// </summary>
    public bool IsDispatchable(ImplantClass @class, string verb)
        => ImplantClassCapabilities.Allows(@class, verb);

    /// <summary>
    /// Always null: the class table holds no module registry, so no requirement
    /// rows exist to check and the runtime gate stands down (the store's
    /// install-time advisory is the only screen).
    /// </summary>
    public IReadOnlyList<string>? ModuleRequires(string moduleName) => null;
}
