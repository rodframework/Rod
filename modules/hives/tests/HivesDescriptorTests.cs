using Rod.Capabilities;
using Rod.Modules.Hives;

namespace Rod.Modules.Hives.Tests;

/// <summary>
/// The descriptor contract the hives module registers: the declaration
/// the operator UI's task form, the risk badges, the coverage matrix,
/// the report's Navigator layer, and the registry-backed sensitive-verb
/// policy all read. The registry refuses a malformed descriptor at
/// startup; these tests pin the module's own declaration against drift
/// -- a widened technique list or a reshaped parameter set is a
/// deliberate change someone notices, not an accident that ships.
/// </summary>
public class HivesDescriptorTests
{
    private static CapabilityDescriptor Descriptor => new HivesCapabilityModule().Descriptor;

    [Fact]
    public void TheModuleDeclaresItsVerbInTheCollectNamespace()
    {
        Assert.Equal("collect.hives", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Collect, Descriptor.Category);
        Assert.Equal("1.0", Descriptor.Version);
        Assert.Equal("hives", new HivesCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are the
        // actions the implant-side plugin's parser answers (its
        // unknown-token refusals quote the same set), and the directory
        // is the grammar's positional tail -- the two halves drift
        // together or fail here.
        Assert.Empty(Descriptor.ValidateParameters());
        Assert.Equal(2, Descriptor.Parameters!.Count);

        var action = Descriptor.Parameters[0];
        Assert.Equal("action", action.Name);
        Assert.Equal(VerbParameterKind.Enum, action.Kind);
        Assert.False(action.Required);
        Assert.Equal(new[] { "save", "list" }, action.Choices);

        var directory = Descriptor.Parameters[1];
        Assert.Equal("directory", directory.Name);
        Assert.Equal(VerbParameterKind.Text, directory.Kind);
        Assert.False(directory.Required);
        Assert.True(directory.Trailing);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesTheSeat()
    {
        // T1003.002 (OS Credential Dumping: Security Account Manager)
        // is the SAM dump and T1003.005 (Cached Domain Credentials) the
        // SECURITY hive's cached credentials; the kernel catalog
        // carries their T1003 parent under collect.cred and the matrix
        // renders both sub-techniques by id beside it. The coverage
        // matrix follows the declaration, not any kernel file.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1003.002", "T1003.005" }, Descriptor.Techniques);
    }

    [Fact]
    public void TheOpsecAttributesCarryTheCredentialHonestFlags()
    {
        // The dumps read account material and land on disk -- the same
        // pair collect.minidump carries minus the memory read, the
        // flags the operator UI renders as risk badges (architecture.md
        // Sec 7) and the sensitive-verb policy reads. The credential
        // read itself stays automatable, the collect set's own stance.
        Assert.Equal("true", Descriptor.Attributes["reads-credential"]);
        Assert.Equal("true", Descriptor.Attributes["writes-to-disk"]);
    }
}
