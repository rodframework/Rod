using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.Avoid;

/// <summary>
/// The server-side half of the avoid module (the defense-evasion
/// family's first entry, architecture.md Sec 15.1): the descriptor
/// registration for <c>evasion.avoid</c>, whose execution half is the
/// implant-side plugin at <c>src/implant/rust/modules/avoid</c>. The
/// kernel ships this verb as a placeholder -- contract and OPSEC flag
/// with no behavior; this registration replaces the placeholder with
/// the described form, the same last-registration-wins path an
/// operator's external module rides, and every dispatched patch rides
/// the task audit dispatched actions already enter.
/// </summary>
/// <remarks>
/// The verb is sensitive twice over: its category is Evasion and its
/// attribute is <c>modifies-defenses</c>, so the registry-backed
/// policy holds it out of unattended firing and behind the operator
/// approval the sensitive queue carries (architecture.md Sec 10.4) --
/// the first in-tree module whose registration rides that gate. The
/// parameter form is deliberately explicit: a sensitive act names its
/// target rather than guessing a default, so the target is required.
/// </remarks>
public sealed class AvoidCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>evasion.avoid</c> as <c>avoid</c> (architecture.md Sec 15.3,
    /// ADR-007) -- the same name the registry and the lock file carry.
    /// </summary>
    public string? Name => "avoid";

    /// <summary>
    /// The requirement rows (ADR-017), the runtime mirror of the manifest's
    /// compatibility.requires: the pair's execution half is a plugin the
    /// target loads through the module family, so the hosting implant must
    /// advertise the loader.
    /// </summary>
    public IReadOnlyList<string>? Requires => ["plugin-loader"];

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>evasion.avoid</c> against the plugin SDK, and
    /// this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The attributes carry the
    /// verb's OPSEC flag (Sec 7): the patch alters the target process's
    /// defensive posture, the flag the sensitive-verb policy keys on --
    /// the same flag the kernel's placeholder carried, now behind an
    /// implementation.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "evasion.avoid",
        CapabilityCategory.Evasion,
        "1.0",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["modifies-defenses"] = "true",
        },
        parameters:
        [
            new VerbParameter(
                "target",
                "Target",
                VerbParameterKind.Enum,
                Required: true,
                Help: "What the task patches in this process: amsi, etw, or all.",
                Choices: ["amsi", "etw", "all"]),
        ],
        output: new VerbOutput(
            VerbOutputKind.Text,
            "One row per patched entry point (the function and what its callers now see), or already-patched rows under a second run."),
        techniques: ["T1562.001"]);
}
