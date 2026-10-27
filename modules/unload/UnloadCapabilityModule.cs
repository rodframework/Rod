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
/// compares ntdll's mapped <c>.text</c> against the fresh copy and
/// reports the differing bytes -- the restore is the write the
/// operator names, never a default. The v1.1 slots scope the same act:
/// the library the task names and the exports it narrows to, with the
/// fresh copy served from the KnownDlls section object first and the
/// disk file the fallback the row names.
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
    /// The requirement rows (ADR-017), the runtime mirror of the manifest's
    /// compatibility.requires: the pair's execution half is a plugin the
    /// target loads through the module family, so the hosting implant must
    /// advertise the loader.
    /// </summary>
    public IReadOnlyList<string>? Requires => ["plugin-loader"];

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>evasion.unload</c> against the plugin SDK,
    /// and this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The attributes carry the
    /// verb's OPSEC flag (Sec 7): the restore rewrites the
    /// target process's defensive posture, the flag the sensitive-verb
    /// policy keys on -- the same flag the kernel's placeholder
    /// carried, now behind an implementation.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "evasion.unload",
        CapabilityCategory.Evasion,
        "1.1",
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
                Help: "Empty compares the named library's in-memory .text against the fresh copy -- a bare task is a read.",
                Choices: ["list", "restore"]),
            new VerbParameter(
                "dll",
                "Library",
                VerbParameterKind.Text,
                Required: false,
                Help: "The library the verb addresses -- a name, never a path; ntdll.dll the default.",
                Placeholder: "kernel32.dll"),
            new VerbParameter(
                "functions",
                "Exports",
                VerbParameterKind.Text,
                Required: false,
                Help: "The comma-joined exports to narrow to; empty addresses the whole .text.",
                Placeholder: "NtAllocateVirtualMemory,NtProtectVirtualMemory",
                Trailing: true),
        ],
        output: new VerbOutput(
            VerbOutputKind.Text,
            "One row for the whole .text, or one row per named export: how many bytes differ from the fresh copy or how many the restore rewrote, the row naming the source that served (KnownDlls section object or disk copy)."),
        techniques: ["T1562.001"]);
}
