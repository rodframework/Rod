using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.Runkeys;

/// <summary>
/// The server-side half of the run-keys module (the persistence
/// family's first entry, architecture.md Sec 15.1): the descriptor
/// registration for <c>persist.runkeys</c>, whose execution half is the
/// implant-side plugin at <c>src/implant/rust/modules/runkeys</c>. The
/// verb carries one discrete persistence technique -- the registry Run
/// key seat under HKCU or HKLM (T1547.001) -- with the pairing the
/// family's acceptance criterion turns on: the action that installs a
/// seat is the grammar that removes it, and both ride the task audit
/// every dispatched action already enters.
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
public sealed class RunKeysCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>persist.runkeys</c> as <c>runkeys</c> (architecture.md Sec
    /// 15.3, ADR-007) -- the same name the registry and the lock file
    /// carry.
    /// </summary>
    public string? Name => "runkeys";

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>persist.runkeys</c> against the plugin SDK,
    /// and this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The attributes carry the
    /// verb's OPSEC flags (Sec 7): the seat is a value in the on-disk
    /// hive and it persists across logons -- the install's own facts,
    /// which the read-only list action never exceeds.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "persist.runkeys",
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
                Help: "Empty lists the seats -- a bare task is a read.",
                Choices: ["install", "remove", "list"]),
            new VerbParameter(
                "hive",
                "Hive",
                VerbParameterKind.Enum,
                Required: false,
                Help: "HKCU holds the per-user seat; HKLM the machine-wide one elevation buys.",
                Choices: ["hkcu", "hklm"]),
            new VerbParameter(
                "name",
                "Value name",
                VerbParameterKind.String,
                Required: false,
                Help: "The seat's own name; for list, a filter narrowing the report to it.",
                Placeholder: "UpdateCheck"),
            new VerbParameter(
                "command",
                "Command",
                VerbParameterKind.Text,
                Required: false,
                Help: "The command line the seat runs at every logon; install only.",
                Trailing: true),
        ],
        output: new VerbOutput(
            VerbOutputKind.Text,
            "One row per seat on list (seat path, name, command), or the seat the install wrote or the remove deleted."),
        techniques: ["T1547.001"]);
}
