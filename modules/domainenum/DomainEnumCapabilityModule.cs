using Rod.Capabilities;
using Rod.Capabilities.Modules;

namespace Rod.Modules.Domainenum;

/// <summary>
/// The server-side half of the domain-discovery module (the module
/// line's first tradecraft entry, architecture.md Sec 15.1): the
/// descriptor registration for <c>recon.domainenum</c>, whose execution
/// half is the implant-side plugin at
/// <c>src/implant/rust/modules/domainenum</c>. The verb carries both
/// halves of domain recon: the credential-free sweep (local domain
/// posture, DC location, the anonymous LDAP root DSE -- T1018, T1482)
/// and the authenticated directory read (domain users, groups, ACLs,
/// SPN objects, trusts -- T1087.002, T1069.002), the credential riding
/// the task's argument grammar as the platform's placeholder resolution
/// carries it.
/// </summary>
/// <remarks>
/// Indistinguishable from an external module, like every in-tree one: a
/// separate assembly the teamserver never compile-references, deployed
/// beside the binary and listed under <c>Capabilities:Modules</c>, so it
/// reaches the registry through the same loader path an out-of-tree
/// module takes. A recon namespace verb is class-admissible already
/// (extending/modules.md), so this registration is what makes the verb
/// *described*: the output taxonomy the topology panel keys on and the
/// techniques the coverage matrix, catalog, and report Navigator layer
/// read.
/// </remarks>
public sealed class DomainEnumCapabilityModule : ICapabilityModule
{
    /// <summary>
    /// The manifest name, so the coverage matrix names the module behind
    /// <c>recon.domainenum</c> as <c>domainenum</c> (architecture.md
    /// Sec 15.3, ADR-007) -- the same name the registry and the lock file
    /// carry.
    /// </summary>
    public string? Name => "domainenum";

    /// <summary>
    /// The verb string both halves declare independently: the implant
    /// plugin registers <c>recon.domainenum</c> against the plugin SDK,
    /// and this descriptor registers the same verb with the server-side
    /// registry -- the string, never a shared type, is the contract
    /// between them (architecture.md Sec 10). The output declaration is
    /// the module's half of the contract trilogy (Sec 15.2): the plugin
    /// prints the recon JSON-lines grammar, and its DC rows carry port
    /// and service, so the topology panel plots them. The attributes
    /// carry the per-command OPSEC flags (Sec 7): the sweep touches the
    /// network by design, writes nothing to the target's disk, and the
    /// authenticated scopes consume a credential the task carries.
    /// </summary>
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "recon.domainenum",
        CapabilityCategory.Recon,
        "1.1",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["touches-network"] = "true",
            ["writes-to-disk"] = "false",
            ["uses-credential"] = "true",
        },
        parameters:
        [
            new VerbParameter(
                "scope",
                "Scope",
                VerbParameterKind.Enum,
                Required: false,
                Help: "Empty runs the whole sweep the credential affords.",
                Choices: ["all", "info", "trusts", "spns", "users", "groups", "acls"]),
            new VerbParameter(
                "user",
                "Bind principal",
                VerbParameterKind.String,
                Required: false,
                Help: "UPN (jdoe@corp.example.com) or DOMAIN\\jdoe; the authenticated scopes need it."),
            new VerbParameter(
                "pass",
                "Bind secret",
                VerbParameterKind.String,
                Required: false,
                Help: "A $cred-<id> placeholder resolves to the stored secret at dispatch.",
                Trailing: true),
        ],
        output: new VerbOutput(
            VerbOutputKind.Enumeration,
            "One JSON finding per line: the posture row, then DC rows (host, port, service), the root-DSE row, and -- with a credential -- the directory rows (users, groups, ACLs, SPN objects, trusts)."),
        techniques: ["T1018", "T1482", "T1087.002", "T1069.002"]);
}
