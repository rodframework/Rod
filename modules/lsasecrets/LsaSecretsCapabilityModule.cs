using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.LsaSecrets;

/// <summary>
/// The server-side half of the lsasecrets module (the credential
/// collection family's fourth entry, architecture.md Sec 15.1): the
/// descriptor registration for <c>collect.lsasecrets</c>, whose
/// execution half is the implant-side plugin at
/// <c>src/implant/rust/modules/lsasecrets</c>. The verb carries one
/// discrete collection technique -- the LSA policy's secret store read
/// in place, its inventory enumerated out of the registry's SECURITY
/// subtree and its values returned by the LSA's own policy API
/// (T1003.004) -- with the survey read as the bare task's default and
/// every value read riding the task audit dispatched actions already
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
public sealed class LsaSecretsCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>collect.lsasecrets</c> as <c>lsasecrets</c> (architecture.md
    /// Sec 15.3, ADR-007) -- the same name the registry and the lock
    /// file carry.
    /// </summary>
    public string? Name => "lsasecrets";

    /// <summary>
    /// The requirement rows (ADR-017), the runtime mirror of the manifest's
    /// compatibility.requires: the pair's execution half is a plugin the
    /// target loads through the module family, so the hosting implant must
    /// advertise the loader.
    /// </summary>
    public IReadOnlyList<string>? Requires => ["plugin-loader"];

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>collect.lsasecrets</c> against the plugin SDK,
    /// and this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The attributes carry the
    /// verb's OPSEC flags (Sec 7) in the credential set's own shape:
    /// the values read credential material and ride the task's result
    /// frames with nothing landing on disk -- the same single flag
    /// <c>collect.browser</c> carries, facts the survey read never
    /// exceeds.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "collect.lsasecrets",
        CapabilityCategory.Collect,
        "1.0",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["reads-credential"] = "true",
        },
        parameters:
        [
            new VerbParameter(
                "action",
                "Action",
                VerbParameterKind.Enum,
                Required: false,
                Help: "Empty reports the survey -- a bare task is a read. The value read needs a SYSTEM implant.",
                Choices: ["list", "read"]),
            new VerbParameter(
                "name",
                "Secret name",
                VerbParameterKind.Text,
                Required: false,
                Help: "The one secret read narrows to; absent reads the whole store. Read only.",
                Placeholder: "$MACHINE.ACC",
                Trailing: true),
        ],
        output: new VerbOutput(
            VerbOutputKind.Text,
            "The seat row and the store's names on list, or one row per secret on read -- the value as text where the bytes decode cleanly, as hex where they do not."),
        techniques: ["T1003.004"]);
}
