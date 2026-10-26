using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.Hijack;

/// <summary>
/// The server-side half of the hijack module (the persistence family's
/// last entry, architecture.md Sec 15.1): the descriptor registration
/// for <c>persist.hijack</c>, whose execution half is the implant-side
/// plugin at <c>src/implant/rust/modules/hijack</c>. The verb carries
/// one discrete persistence technique -- a DLL planted beside a host
/// binary, read by the loader before System32 (T1574.001) -- with the
/// pairing the family's acceptance criterion turns on: the action that
/// installs a seat is the grammar that removes it, and both ride the
/// task audit every dispatched action already enters.
/// </summary>
/// <remarks>
/// Indistinguishable from an external module, like every in-tree one: a
/// separate assembly the teamserver never compile-references, deployed
/// beside the binary and listed under <c>Capabilities:Modules</c>, so it
/// reaches the registry through the same loader path an out-of-tree
/// module takes. A persist namespace verb is class-admissible already
/// (extending/modules.md), so this registration is what makes the verb
/// <i>described</i>: the parameter form the task dialog renders, the
/// OPSEC attributes the picker badges, and the technique the coverage
/// matrix, catalog, and report Navigator layer read.
/// </remarks>
public sealed class HijackCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>persist.hijack</c> as <c>hijack</c> (architecture.md Sec 15.3,
    /// ADR-007) -- the same name the registry and the lock file carry.
    /// </summary>
    public string? Name => "hijack";

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>persist.hijack</c> against the plugin SDK,
    /// and this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The attributes carry the
    /// verb's OPSEC flags (Sec 7): the seat is a file on disk and it
    /// loads every time the host binary runs -- the install's own
    /// facts, which the read-only list action never exceeds.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "persist.hijack",
        CapabilityCategory.Persist,
        "1.0",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["writes-to-disk"] = "true",
            ["persists"] = "true",
        },
        parameters:
        [
            new VerbParameter(
                "action",
                "Action",
                VerbParameterKind.Enum,
                Required: false,
                Help: "Empty lists the binary's slots -- the read names the binary it inspects.",
                Choices: ["install", "remove", "list"]),
            new VerbParameter(
                "binary",
                "Host binary",
                VerbParameterKind.String,
                Required: false,
                Help: "The host binary as a full path; its directory is the seat the loader reads first.",
                Placeholder: @"C:\app\app.exe"),
            new VerbParameter(
                "dll",
                "DLL name",
                VerbParameterKind.String,
                Required: false,
                Help: "The imported DLL name the seat claims; for list, a filter narrowing the report to it.",
                Placeholder: "VERSION.DLL"),
            new VerbParameter(
                "source",
                "Source file",
                VerbParameterKind.Text,
                Required: false,
                Help: "The already-pushed file to plant; install only.",
                Trailing: true),
        ],
        output: new VerbOutput(
            VerbOutputKind.Text,
            "One row per open slot on list (the DLL and where it stands in the loader's order), or the seat the install planted or the remove deleted."),
        techniques: ["T1574.001"]);
}
