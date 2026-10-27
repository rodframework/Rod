namespace Rod.CoreState.Implants;

/// <summary>
/// Decides whether a task verb may be dispatched for a given implant class
/// (architecture.md Sec 5.2, Sec 10.3). The inner-ring authority the task
/// issuance gate consults: a verb outside what <paramref name="class"/> may run
/// is refused before the task is queued.
/// </summary>
/// <remarks>
/// <para>
/// The default, in-process behavior is the per-class reduced verb set
/// (<see cref="ClassTableCapabilityResolver"/> reading
/// <see cref="ImplantClassCapabilities"/>, Sec 5.2): the inner ring both the
/// build pipeline and the capabilities layer read. This port lets a later layer
/// widen that decision without core state depending on it: the capabilities layer
/// supplies an adapter that additionally admits a verb a registered capability
/// module handles (architecture.md Sec 10.2 -- the evasion and exploit
/// categories are contract and dispatch only, not class-gated), and the
/// composition root swaps that adapter in. Core state stays inward-only: the
/// port is defined here, the tradecraft-backed implementation lives in
/// <c>Rod.Capabilities</c>.
/// </para>
/// <para>
/// The class table is the primary authority. An implementation that consults the
/// capability registry must keep it so: a verb the class set admits is always
/// dispatchable, and only a verb it does not admit falls through to the
/// registry path. That keeps the per-class reduced sets (Sec 5.2) the source of
/// truth for the class-gated categories while opening a dispatch path for the
/// no-class-gate ones.
/// </para>
/// </remarks>
public interface ITaskCapabilityResolver
{
    /// <summary>
    /// Whether a task carrying <paramref name="verb"/> may be queued for an
    /// implant of <paramref name="class"/>. The class table is the primary
    /// authority; a registered-module path, when present, admits the verbs the
    /// class set does not (architecture.md Sec 10.2).
    /// </summary>
    bool IsDispatchable(ImplantClass @class, string verb);

    /// <summary>
    /// The requirement rows the module named <paramref name="moduleName"/>
    /// declares against the wire-capability vocabulary (architecture.md
    /// Sec 15.2, ADR-017), or null when no such module is registered or it
    /// declares none. The runtime half of the compatibility collapse: a
    /// <c>module.load</c> issuance checks these rows against the session's
    /// handshake advertisement and refuses naming what it lacks. The
    /// class-table default answers null -- without a module registry there
    /// are no rows to check, and the store's install-time advisory stands.
    /// </summary>
    IReadOnlyList<string>? ModuleRequires(string moduleName);
}
