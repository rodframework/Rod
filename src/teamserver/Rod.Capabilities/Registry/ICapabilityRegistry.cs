using Rod.Capabilities.Modules;

namespace Rod.Capabilities.Registry;

/// <summary>
/// The capability-module registry port (architecture.md Sec 4.1 layer 6, Sec 10).
/// Modules register themselves by their descriptor's verb; the dispatcher looks a
/// verb up to route an invocation. The default is an in-memory
/// implementation; the port keeps callers agnostic to that.
/// </summary>
/// <remarks>
/// Verb lookup is case-insensitive: capability verbs are <c>namespace.action</c>
/// identifiers, not display strings, and an implant or operator typing
/// <c>Shell.Exec</c> should not be told the verb is unknown. A later registration
/// for an already-registered verb replaces the prior one, so a module loaded later
/// (a config-listed override) is the single authority for its verb.
/// </remarks>
public interface ICapabilityRegistry
{
    /// <summary>
    /// Registers <paramref name="module"/> under its
    /// <see cref="ICapabilityModule.Descriptor"/> verb, replacing any module
    /// already registered for that verb. Idempotent for the same module.
    /// </summary>
    Task RegisterAsync(ICapabilityModule module, CancellationToken cancellationToken = default);

    /// <summary>
    /// The module registered for <paramref name="verb"/>, or null when no module
    /// handles it. Case-insensitive on <paramref name="verb"/>.
    /// </summary>
    Task<ICapabilityModule?> FindAsync(string verb, CancellationToken cancellationToken = default);

    /// <summary>
    /// The module registered under the published <paramref name="name"/> (the
    /// manifest name a <c>module.load</c> task names), or null when no named
    /// module matches. Case-insensitive on <paramref name="name"/>; last
    /// registration wins, mirroring <see cref="FindAsync"/>'s authority rule.
    /// The runtime requirement gate's lookup (architecture.md Sec 15.2,
    /// ADR-017).
    /// </summary>
    Task<ICapabilityModule?> FindByNameAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>
    /// Every registered capability descriptor, in registration order. The
    /// composition root uses this to confirm the core verbs loaded; a future
    /// read surface (operator discovery) consumes the same view.
    /// </summary>
    Task<IReadOnlyList<CapabilityDescriptor>> ListAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Every registered module, in registration order -- the descriptor plus
    /// the module-level metadata (published name, requirement rows) the
    /// catalog and the operator UI's loadable-set filter read. Same
    /// registration-order view <see cref="ListAsync"/> carries, with the
    /// module object beside its descriptor.
    /// </summary>
    Task<IReadOnlyList<ICapabilityModule>> ListModulesAsync(CancellationToken cancellationToken = default);
}
