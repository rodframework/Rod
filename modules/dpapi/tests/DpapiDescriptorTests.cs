using Rod.Capabilities;
using Rod.Modules.Dpapi;

namespace Rod.Modules.Dpapi.Tests;

/// <summary>
/// The descriptor contract the dpapi module registers: the declaration
/// the operator UI's task form, the risk badges, the coverage matrix,
/// the report's Navigator layer, and the registry-backed sensitive-verb
/// policy all read. The registry refuses a malformed descriptor at
/// startup; these tests pin the module's own declaration against drift
/// -- a widened technique list or a reshaped parameter set is a
/// deliberate change someone notices, not an accident that ships.
/// </summary>
public class DpapiDescriptorTests
{
    private static CapabilityDescriptor Descriptor => new DpapiCapabilityModule().Descriptor;

    [Fact]
    public void TheModuleDeclaresItsVerbInTheCollectNamespace()
    {
        Assert.Equal("collect.dpapi", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Collect, Descriptor.Category);
        Assert.Equal("1.0", Descriptor.Version);
        Assert.Equal("dpapi", new DpapiCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are the
        // actions the implant-side plugin's parser answers (its
        // unknown-token refusals quote the same set), and the blob is
        // the grammar's positional tail -- the two halves drift
        // together or fail here.
        Assert.Empty(Descriptor.ValidateParameters());
        Assert.Equal(2, Descriptor.Parameters!.Count);

        var action = Descriptor.Parameters[0];
        Assert.Equal("action", action.Name);
        Assert.Equal(VerbParameterKind.Enum, action.Kind);
        Assert.False(action.Required);
        Assert.Equal(new[] { "unseal", "list" }, action.Choices);

        var blob = Descriptor.Parameters[1];
        Assert.Equal("blob", blob.Name);
        Assert.Equal(VerbParameterKind.Text, blob.Kind);
        Assert.False(blob.Required);
        Assert.True(blob.Trailing);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesThePrimitive()
    {
        // T1555 (Credentials from Password Stores) is the family the
        // unsealing primitive serves -- its sub-techniques arrive as
        // their own modules that compose against this one's decryption
        // half; the kernel catalog carries the parent under collect.cred
        // and the matrix renders this row beside it. The coverage matrix
        // follows the declaration, not any kernel file.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1555" }, Descriptor.Techniques);
    }

    [Fact]
    public void TheOpsecAttributesCarryTheCredentialHonestFlags()
    {
        // The unseal reads credential material and drops nothing on the
        // target -- the flags the operator UI renders as risk badges
        // (architecture.md Sec 7) and the sensitive-verb policy reads.
        // The credential read itself stays automatable, the collect
        // set's own stance.
        Assert.Equal("true", Descriptor.Attributes["reads-credential"]);
        Assert.Equal("false", Descriptor.Attributes["writes-to-disk"]);
    }
}
