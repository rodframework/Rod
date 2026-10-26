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
    public void TheDeclaresItsVerbInTheReconNamespace()
    {
        Assert.Equal("recon.domainenum", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Recon, Descriptor.Category);
        Assert.Equal("domainenum", new DomainEnumCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are the
        // scopes the implant-side plugin's parser answers (all, info,
        // trusts, spns) -- the two halves drift together or fail here.
        Assert.Empty(Descriptor.ValidateParameters());
        var scope = Assert.Single(Descriptor.Parameters!);
        Assert.Equal("scope", scope.Name);
        Assert.Equal(VerbParameterKind.Enum, scope.Kind);
        Assert.False(scope.Required);
        Assert.Equal(new[] { "all", "info", "trusts", "spns" }, scope.Choices);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesTheCredentialFreeHalf()
    {
        // T1018 (Remote System Discovery) and T1482 (Domain Trust
        // Discovery) are exactly what the anonymous sweep covers; the
        // authenticated half (users, groups, ACLs) widens this list when
        // it ships, and the coverage matrix follows the declaration.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1018", "T1482" }, Descriptor.Techniques);
    }

    [Fact]
    public void TheOutputKindEarnsTheTopologyPanel()
    {
        // The plugin prints the recon JSON-lines grammar; the
        // Enumeration kind is what routes its rows into the topology
        // view -- the DC rows carry host, port, and service.
        Assert.NotNull(Descriptor.Output);
        Assert.Equal(VerbOutputKind.Enumeration, Descriptor.Output!.Kind);
    }

    [Fact]
    public void TheOpsecAttributesCarryTheHonestFlags()
    {
        // The sweep sends DNS and LDAP packets by design and writes
        // nothing to the target's disk -- the flags the operator UI
        // renders as risk badges (architecture.md Sec 7).
        Assert.Equal("true", Descriptor.Attributes["touches-network"]);
        Assert.Equal("false", Descriptor.Attributes["writes-to-disk"]);
    }
}
