using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.Dpapi;

/// <summary>
/// The server-side half of the dpapi module (the credential
/// collection family's second entry, architecture.md Sec 15.1): the
/// descriptor registration for <c>collect.dpapi</c>, whose execution
/// half is the implant-side plugin at
/// <c>src/implant/rust/modules/dpapi</c>. The verb carries one discrete
/// collection primitive -- the DPAPI unseal under the target user's own
/// masterkeys (T1555's decryption half) -- with the masterkey readiness
/// read as the bare task's default and every unseal riding the task
/// audit dispatched actions already enter.
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
/// reads, and the technique the coverage matrix, catalog, and report
/// Navigator layer read.
/// </remarks>
public sealed class DpapiCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>collect.dpapi</c> as <c>dpapi</c> (architecture.md Sec 15.3,
    /// ADR-007) -- the same name the registry and the lock file carry.
    /// </summary>
    public string? Name => "dpapi";

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>collect.dpapi</c> against the plugin SDK, and
    /// this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The attributes carry the
    /// verb's OPSEC flags (Sec 7): the unseal reads credential material
    /// and drops nothing on the target -- the read-only list action
    /// never exceeds the unseal's own flags.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "collect.dpapi",
        CapabilityCategory.Collect,
        "1.0",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["reads-credential"] = "true",
            ["writes-to-disk"] = "false",
        },
        parameters:
        [
            new VerbParameter(
                "action",
                "Action",
                VerbParameterKind.Enum,
                Required: false,
                Help: "Empty reports the masterkey readiness facts -- a bare task is a read.",
                Choices: ["unseal", "list"]),
            new VerbParameter(
                "blob",
                "DPAPI blob",
                VerbParameterKind.Text,
                Required: false,
                Help: "The base64 DPAPI blob to unseal under the target user's masterkeys; unseal only.",
                Trailing: true),
        ],
        output: new VerbOutput(
            VerbOutputKind.Text,
            "The masterkey SID rows on list, or the unsealed plaintext as text or base64 by what it is."),
        techniques: ["T1555"]);
}
