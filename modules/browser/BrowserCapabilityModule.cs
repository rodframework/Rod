using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.Browser;

/// <summary>
/// The server-side half of the browser module (the credential
/// collection family's third entry, architecture.md Sec 15.1): the
/// descriptor registration for <c>collect.browser</c>, whose execution
/// half is the implant-side plugin at
/// <c>src/implant/rust/modules/browser</c>. The verb carries one
/// discrete collection technique -- the Chromium login stores (Chrome
/// and Edge, T1555.003) -- with the login listing as the bare task's
/// default and every unseal riding the task audit dispatched actions
/// already enter.
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
public sealed class BrowserCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>collect.browser</c> as <c>browser</c> (architecture.md Sec
    /// 15.3, ADR-007) -- the same name the registry and the lock file
    /// carry.
    /// </summary>
    public string? Name => "browser";

    /// <summary>
    /// The requirement rows (ADR-017), the runtime mirror of the manifest's
    /// compatibility.requires: the pair's execution half is a plugin the
    /// target loads through the module family, so the hosting implant must
    /// advertise the loader.
    /// </summary>
    public IReadOnlyList<string>? Requires => ["plugin-loader"];

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>collect.browser</c> against the plugin SDK,
    /// and this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The attributes carry the
    /// verb's OPSEC flags (Sec 7): the sweep reads credential material
    /// and drops nothing on the target -- the listing action never
    /// exceeds the export's own flags.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "collect.browser",
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
                Help: "Empty lists the logins -- a bare task is a read.",
                Choices: ["list", "export"]),
            new VerbParameter(
                "browser",
                "Browser",
                VerbParameterKind.Enum,
                Required: false,
                Help: "Which Chromium store to sweep; empty probes both Chrome and Edge.",
                Choices: ["chrome", "edge", "all"]),
        ],
        output: new VerbOutput(
            VerbOutputKind.Credential,
            "One JSON credential row per login (kind, principal, host, source); export adds the secret, and a note names any row that refused decryption."),
        techniques: ["T1555.003"]);
}
