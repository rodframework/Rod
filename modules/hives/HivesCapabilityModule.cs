using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.Hives;

/// <summary>
/// The server-side half of the hives module (the credential
/// collection family's first entry, architecture.md Sec 15.1): the
/// descriptor registration for <c>collect.hives</c>, whose execution
/// half is the implant-side plugin at
/// <c>src/implant/rust/modules/hives</c>. The verb carries one
/// discrete collection technique -- the SAM, SYSTEM, and SECURITY
/// account hives saved under the backup privilege (T1003.002,
/// T1003.005) -- with the readiness read as the bare task's default
/// and every save riding the task audit dispatched actions already
/// enter.
/// </summary>
/// <remarks>
/// Indistinguishable from an external module, like every in-tree one: a
/// separate assembly the teamserver never compile-references, deployed
/// beside the binary and listed under <c>Capabilities:Modules</c>, so it
/// reaches the registry through the same loader path an out-of-tree
/// module takes. A collect namespace verb is class-admissible already
/// (extending/modules.md), so this registration is what makes the verb
/// <i>described</i>: the parameter form the task dialog renders, the
/// OPSEC attributes the picker badges and the sensitive-verb policy
/// reads, and the techniques the coverage matrix, catalog, and report
/// Navigator layer read.
/// </remarks>
public sealed class HivesCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>collect.hives</c> as <c>hives</c> (architecture.md Sec 15.3,
    /// ADR-007) -- the same name the registry and the lock file carry.
    /// </summary>
    public string? Name => "hives";

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>collect.hives</c> against the plugin SDK, and
    /// this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The attributes carry the
    /// verb's OPSEC flags (Sec 7) in the credential set's own shape:
    /// the dumps read account material and land on disk, the same pair
    /// <c>collect.minidump</c> carries minus the memory read -- facts
    /// the read-only list action never exceeds.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "collect.hives",
        CapabilityCategory.Collect,
        "1.0",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["reads-credential"] = "true",
            ["writes-to-disk"] = "true",
        },
        parameters:
        [
            new VerbParameter(
                "action",
                "Action",
                VerbParameterKind.Enum,
                Required: false,
                Help: "Empty reports the readiness facts -- a bare task is a read. The save needs an elevated implant.",
                Choices: ["save", "list"]),
            new VerbParameter(
                "directory",
                "Directory",
                VerbParameterKind.Text,
                Required: false,
                Help: "The directory the three dumps land in; save only.",
                Placeholder: @"C:\loot",
                Trailing: true),
        ],
        output: new VerbOutput(
            VerbOutputKind.Text,
            "The readiness rows on list (the backup privilege, each source hive), or one row per dump on save."),
        techniques: ["T1003.002", "T1003.005"]);
}
