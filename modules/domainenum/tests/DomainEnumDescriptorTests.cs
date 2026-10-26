using Rod.Capabilities;
using Rod.Modules.Domainenum;

namespace Rod.Modules.Domainenum.Tests;

/// <summary>
/// The descriptor contract the domain-discovery module registers: the
/// declaration the operator UI's task form, the topology panel, the
/// coverage matrix, and the report's Navigator layer all read. The
/// registry refuses a malformed descriptor at startup; these tests pin
/// the module's own declaration against drift -- a widened technique
/// list or a reshaped parameter set is a deliberate change someone
/// notices, not an accident that ships.
/// </summary>
public class DomainEnumDescriptorTests
{
    private static CapabilityDescriptor Descriptor => new DomainEnumCapabilityModule().Descriptor;

    [Fact]
    public void TheModuleDeclaresItsVerbInTheReconNamespace()
    {
        Assert.Equal("recon.domainenum", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Recon, Descriptor.Category);
        Assert.Equal("1.1", Descriptor.Version);
        Assert.Equal("domainenum", new DomainEnumCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are the
        // scopes the implant-side plugin's parser answers (all, info,
        // trusts, spns, plus the authenticated users/groups/acls), and
        // the credential pair is the grammar's positional tail: values
        // space-joined with the pass as the trailing remainder, where a
        // $cred-<id> placeholder resolves at dispatch -- the two halves
        // drift together or fail here.
        Assert.Empty(Descriptor.ValidateParameters());
        Assert.Equal(3, Descriptor.Parameters!.Count);

        var scope = Descriptor.Parameters[0];
        Assert.Equal("scope", scope.Name);
        Assert.Equal(VerbParameterKind.Enum, scope.Kind);
        Assert.False(scope.Required);
        Assert.Equal(new[] { "all", "info", "trusts", "spns", "users", "groups", "acls" }, scope.Choices);

        var user = Descriptor.Parameters[1];
        Assert.Equal("user", user.Name);
        Assert.Equal(VerbParameterKind.String, user.Kind);
        Assert.False(user.Required);

        var pass = Descriptor.Parameters[2];
        Assert.Equal("pass", pass.Name);
        Assert.Equal(VerbParameterKind.String, pass.Kind);
        Assert.True(pass.Trailing);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesBothHalves()
    {
        // T1018 (Remote System Discovery) and T1482 (Domain Trust
        // Discovery) are the credential-free sweep; T1087.002 (Domain
        // Account Discovery) and T1069.002 (Domain Groups Discovery)
        // are the authenticated directory read. The coverage matrix
        // follows the declaration, not any kernel file.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1018", "T1482", "T1087.002", "T1069.002" }, Descriptor.Techniques);
    }

    [Fact]
    public void TheOutputKindEarnsTheTopologyPanel()
    {
        // The plugin prints the recon JSON-lines grammar; the
        // Enumeration kind is what routes its rows into the topology
        // view -- the DC rows carry host, port, and service, and the
        // directory rows key on the DC that served them.
        Assert.NotNull(Descriptor.Output);
        Assert.Equal(VerbOutputKind.Enumeration, Descriptor.Output!.Kind);
    }

    [Fact]
    public void TheOpsecAttributesCarryTheHonestFlags()
    {
        // The sweep sends DNS and LDAP packets by design, writes
        // nothing to the target's disk, and the authenticated scopes
        // consume a credential the task carries -- the flags the
        // operator UI renders as risk badges (architecture.md Sec 7).
        Assert.Equal("true", Descriptor.Attributes["touches-network"]);
        Assert.Equal("false", Descriptor.Attributes["writes-to-disk"]);
        Assert.Equal("true", Descriptor.Attributes["uses-credential"]);
    }
}
