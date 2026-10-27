using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.Services;

/// <summary>
/// The server-side half of the services module (the persistence
/// family's second entry, architecture.md Sec 15.1): the descriptor
/// registration for <c>persist.services</c>, whose execution half is
/// the implant-side plugin at <c>src/implant/rust/modules/services</c>.
/// The verb carries one discrete persistence technique -- a service
/// record in the SCM database with its binary path (T1543.003) -- with
/// the pairing the family's acceptance criterion turns on: the action
/// that installs a seat is the grammar that removes it, and both ride
/// the task audit every dispatched action already enters.
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
public sealed class ServicesCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>persist.services</c> as <c>services</c> (architecture.md Sec
    /// 15.3, ADR-007) -- the same name the registry and the lock file
    /// carry.
    /// </summary>
    public string? Name => "services";

    /// <summary>
    /// The requirement rows (ADR-017), the runtime mirror of the manifest's
    /// compatibility.requires: the pair's execution half is a plugin the
    /// target loads through the module family, so the hosting implant must
    /// advertise the loader.
    /// </summary>
    public IReadOnlyList<string>? Requires => ["plugin-loader"];

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>persist.services</c> against the plugin SDK,
    /// and this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The attributes carry the
    /// verb's OPSEC flags (Sec 7): the seat is a record in the on-disk
    /// SCM database and it runs at every boot -- the install's own
    /// facts, which the read-only list action never exceeds.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "persist.services",
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
                Help: "Empty lists the seats -- a bare task is a read. Every write needs an elevated implant.",
                Choices: ["install", "remove", "list"]),
            new VerbParameter(
                "name",
                "Service name",
                VerbParameterKind.String,
                Required: false,
                Help: "The seat's own name in the service database; for list, a filter narrowing the report to it.",
                Placeholder: "UpdateCheck"),
            new VerbParameter(
                "command",
                "Command",
                VerbParameterKind.Text,
                Required: false,
                Help: "The command line the SCM runs as the service's binary path; install only.",
                Trailing: true),
        ],
        output: new VerbOutput(
            VerbOutputKind.Text,
            "One row per seat on list (service name, binary path, start kind), or the seat the install created or the remove marked for deletion."),
        techniques: ["T1543.003"]);
}
