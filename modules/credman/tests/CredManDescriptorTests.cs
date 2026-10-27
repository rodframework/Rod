using Rod.Capabilities;
using Rod.Modules.CredMan;

namespace Rod.Modules.CredMan.Tests;

/// <summary>
/// The descriptor contract the credman module registers: the
/// declaration the operator UI's task form, the risk badges, the
/// coverage matrix, the report's Navigator layer, the credentials
/// board's row routing, and the registry-backed sensitive-verb policy
/// all read. The registry refuses a malformed descriptor at startup;
/// these tests pin the module's own declaration against drift -- a
/// widened technique list or a reshaped parameter set is a deliberate
/// change someone notices, not an accident that ships.
/// </summary>
public class CredManDescriptorTests
{
    private static CapabilityDescriptor Descriptor => new CredManCapabilityModule().Descriptor;

    [Fact]
    public void TheModuleDeclaresItsVerbInTheCollectNamespace()
    {
        Assert.Equal("collect.credman", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Collect, Descriptor.Category);
        Assert.Equal("1.0", Descriptor.Version);
        Assert.Equal("credman", new CredManCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are the
        // actions the implant-side plugin's parser answers (its
        // unknown-token refusals quote the same set), and the target
        // name is the grammar's positional tail -- the two halves drift
        // together or fail here.
        Assert.Empty(Descriptor.ValidateParameters());
        Assert.Equal(2, Descriptor.Parameters!.Count);

        var action = Descriptor.Parameters[0];
        Assert.Equal("action", action.Name);
        Assert.Equal(VerbParameterKind.Enum, action.Kind);
        Assert.False(action.Required);
        Assert.Equal(new[] { "list", "read" }, action.Choices);

        var target = Descriptor.Parameters[1];
        Assert.Equal("target", target.Name);
        Assert.Equal(VerbParameterKind.Text, target.Kind);
        Assert.False(target.Required);
        Assert.True(target.Trailing);
    }

    [Fact]
    public void TheOutputDeclaresTheCredentialKindTheBoardParses()
    {
        // The family's first verb on the taxonomy's credential kind:
        // the rows route into the credentials board, which masks the
        // secret field until an operator reveals it (architecture.md
        // Sec 15.2) -- the panel the declaration earns, not one the
        // module renders.
        Assert.Equal(VerbOutputKind.Credential, Descriptor.Output!.Kind);
        Assert.NotNull(Descriptor.Output.Help);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesTheStore()
    {
        // T1555.004 (Credentials from Password Stores: Windows
        // Credential Manager) is the in-place store read itself; the
        // kernel catalog carries its T1555 parent under collect.cred
        // and the matrix renders this sub-technique by id beside it.
        // The coverage matrix follows the declaration, not any kernel
        // file.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1555.004" }, Descriptor.Techniques);
    }

    [Fact]
    public void TheOpsecAttributesCarryTheCredentialHonestFlags()
    {
        // The values read credential material and ride the task's
        // result frames with nothing landing on disk -- the same single
        // flag collect.browser and collect.lsasecrets carry, the ones
        // the operator UI renders as risk badges (architecture.md
        // Sec 7) and the sensitive-verb policy reads. The credential
        // read itself stays automatable, the collect set's own stance.
        Assert.Equal("true", Descriptor.Attributes["reads-credential"]);
        Assert.False(Descriptor.Attributes.ContainsKey("writes-to-disk"));
    }
}
