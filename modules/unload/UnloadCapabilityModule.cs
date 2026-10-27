using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.Unload;

/// <summary>
/// The server-side half of the unload module (the defense-evasion
/// family's second entry, architecture.md Sec 15.1): the descriptor
/// registration for <c>evasion.unload</c>, whose execution half is the
/// implant-side plugin at <c>src/implant/rust/modules/unload</c>. The
/// kernel ships this verb as a placeholder -- contract and OPSEC flag
/// with no behavior; this registration replaces the placeholder with
/// the described form, the same last-registration-wins path an
/// operator's external module rides, and every dispatched restore
/// rides the task audit dispatched actions already enter.
/// </summary>
/// <remarks>
/// The verb is sensitive twice over: its category is Evasion and its
/// attribute is <c>modifies-defenses</c>, so the registry-backed
/// policy holds it out of unattended firing and behind the operator
/// approval the sensitive queue carries (architecture.md Sec 10.4).
/// The parameter form keeps the bare task a read: an empty action
/// compares ntdll's mapped <c>.text</c> against the disk copy and
/// reports the differing bytes -- the restore is the write the
/// operator names, never a default.
/// </remarks>
public sealed class UnloadCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>evasion.unload</c> as <c>unload</c> (architecture.md Sec 15.3,
    /// ADR-007) -- the same name the registry and the lock file carry.
    /// </summary>
    public string? Name => "unload";

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>evasion.unload</c> against the plugin SDK,
    /// and this descriptor registers the same verb with the
    /// server-side registry -- the string, never a shared type, is the
    /// contract between them (architecture.md Sec 10). The attributes
    /// carry the verb's OPSEC flag (Sec 7): the restore rewrites the
    /// target process's defensive posture, the flag the sensitive-verb
    /// policy keys on -- the same flag the kernel's placeholder
    /// carried, now behind an implementation.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "evasion.unload",
        CapabilityCategory.Evasion,
        "1.0",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["modifies-defenses"] = "true",
        },
        parameters:
        [
            new VerbParameter(
                "action",
                "Action",
                VerbParameterKind.Enum,
                Required: false,
                Help: "Empty compares ntdll's in-memory .text against the disk copy -- a bare task is a read.",
                Choices: ["list", "restore"]),
        ],
        output: new VerbOutput(
            VerbOutputKind.Text,
            "One row: how many .text bytes differ from the disk copy, or how many the restore rewrote."),
        techniques: ["T1562.001"]);
}
