
namespace Rod.Capabilities.Modules;

/// <summary>
/// One pluggable post-exploitation capability module (architecture.md Sec 4.1
/// layer 6, Sec 10/13). A module declares the single capability it provides via
/// <see cref="Descriptor"/>; the registry indexes modules by that verb so the
/// task-issuance gate and the capability catalog can read them.
/// </summary>
/// <remarks>
/// This is a registration contract, not an execution contract: the teamserver
/// only gates and forwards on the live task path and never invokes a capability
/// module server-side -- verb execution and dispatch live on the implant
/// (architecture.md Sec 5.3, Sec 10.2/10.3), where the target's filesystem,
/// network, and credentials actually exist. A module therefore carries exactly
/// the declaration the server needs: the descriptor it registers under.
///
/// Concrete tradecraft -- recon, lateral movement, persistence, collection,
/// exfiltration, and any evasion/exploit behavior -- arrives as opt-in modules
/// implementing this interface: in-tree reference modules under <c>modules/</c>
/// or external ones, both through the same config-listed loading path
/// (AGENTS.md Sec 7, architecture.md Sec 13, Sec 15). The built-in core-verb
/// placeholders exist only to keep every framework verb registered so the
/// catalog lists the full set and a module replacing one is a registration,
/// not a schema change.
/// </remarks>
public interface ICapabilityModule
{
    /// <summary>
    /// The capability this module provides. Registered with the
    /// <see cref="Registry.ICapabilityRegistry"/> so the task-issuance gate can
    /// admit the verb and a later module can replace the placeholder for it
    /// (last registration wins).
    /// </summary>
    CapabilityDescriptor Descriptor { get; }

    /// <summary>
    /// The module's published name as the coverage surfaces display it
    /// (architecture.md Sec 15.3, ADR-007) -- the manifest name of a packaged
    /// module, e.g. <c>hostenum</c>. Optional: a module that does not carry
    /// one is shown under its type name. Display metadata only, never an
    /// identity the loader or the trust chain consults.
    /// </summary>
    string? Name => null;

    /// <summary>
    /// The wire capabilities the hosting implant must support for this
    /// module's execution half to run (architecture.md Sec 15.2, ADR-017):
    /// names from the closed vocabulary (<c>plugin-loader</c>,
    /// <c>exfil-chunks</c>, <c>staged-uploads</c>). The runtime mirror of the
    /// manifest's <c>compatibility.requires</c> row -- the manifest is the
    /// packaging truth the store and the CLI read; this property is what the
    /// live task path sees. Optional: a module that declares none requires
    /// nothing of its host. Registration refuses an unknown name, so a typo
    /// never silently mismatches the runtime gate.
    /// </summary>
    IReadOnlyList<string>? Requires => null;
}
