using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.CredMan;

/// <summary>
/// The server-side half of the credman module (the credential
/// collection family's fifth entry, architecture.md Sec 15.1): the
/// descriptor registration for <c>collect.credman</c>, whose execution
/// half is the implant-side plugin at
/// <c>src/implant/rust/modules/credman</c>. The verb carries one
/// discrete collection technique -- the Windows credential manager's
/// store read in place, enumerated through the credential API in the
/// calling logon session (T1555.004) -- with the survey read as the
/// bare task's default and every value read riding the task audit
/// dispatched actions already enter.
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
/// reads, the credential output kind that routes the rows into the
/// credentials board, and the techniques the coverage matrix, catalog,
/// and report Navigator layer read.
/// </remarks>
public sealed class CredManCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>collect.credman</c> as <c>credman</c> (architecture.md
    /// Sec 15.3, ADR-007) -- the same name the registry and the lock
    /// file carry.
    /// </summary>
    public string? Name => "credman";

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>collect.credman</c> against the plugin SDK,
    /// and this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The attributes carry the
    /// verb's OPSEC flags (Sec 7) in the credential set's own shape:
    /// the values read credential material and ride the task's result
    /// frames with nothing landing on disk -- the same single flag
    /// <c>collect.browser</c> and <c>collect.lsasecrets</c> carry, facts
    /// the survey read never exceeds.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "collect.credman",
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
                Help: "Empty reports the survey -- a bare task is a read. The read reaches the calling session's own store; no privilege asked.",
                Choices: ["list", "read"]),
            new VerbParameter(
                "target",
                "Target name",
                VerbParameterKind.Text,
                Required: false,
                Help: "The one entry read narrows to, matched against the entry's target name; absent reads the whole store. Read only.",
                Placeholder: "TERMSRV/web01.corp.example",
                Trailing: true),
        ],
        output: new VerbOutput(
            VerbOutputKind.Credential,
            "One credential row per line: the entry's kind, principal, source, and note (target, type, persistence, last write); the read adds the secret where the store handed its blob back -- the credentials board parses every row and masks the secret until revealed."),
        techniques: ["T1555.004"]);
}
