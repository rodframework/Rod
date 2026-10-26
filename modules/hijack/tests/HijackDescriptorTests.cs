using Rod.Capabilities;
using Rod.Modules.Hijack;

namespace Rod.Modules.Hijack.Tests;

/// <summary>
/// The descriptor contract the hijack module registers: the declaration
/// the operator UI's task form, the risk badges, the coverage matrix,
/// and the report's Navigator layer all read. The registry refuses a
/// malformed descriptor at startup; these tests pin the module's own
/// declaration against drift -- a widened technique list or a reshaped
/// parameter set is a deliberate change someone notices, not an
/// accident that ships.
/// </summary>
public class HijackDescriptorTests
{
    private static CapabilityDescriptor Descriptor => new HijackCapabilityModule().Descriptor;

    [Fact]
    public void TheModuleDeclaresItsVerbInThePersistNamespace()
    {
        Assert.Equal("persist.hijack", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Persist, Descriptor.Category);
        Assert.Equal("1.0", Descriptor.Version);
        Assert.Equal("hijack", new HijackCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are the
        // actions the implant-side plugin's parser answers (its
        // unknown-token refusals quote the same set), and the source
        // is the grammar's positional tail -- the two halves drift
        // together or fail here.
        Assert.Empty(Descriptor.ValidateParameters());
        Assert.Equal(4, Descriptor.Parameters!.Count);

        var action = Descriptor.Parameters[0];
        Assert.Equal("action", action.Name);
        Assert.Equal(VerbParameterKind.Enum, action.Kind);
        Assert.False(action.Required);
        Assert.Equal(new[] { "install", "remove", "list" }, action.Choices);

        var binary = Descriptor.Parameters[1];
        Assert.Equal("binary", binary.Name);
        Assert.Equal(VerbParameterKind.String, binary.Kind);
        Assert.False(binary.Required);

        var dll = Descriptor.Parameters[2];
        Assert.Equal("dll", dll.Name);
        Assert.Equal(VerbParameterKind.String, dll.Kind);
        Assert.False(dll.Required);

        var source = Descriptor.Parameters[3];
        Assert.Equal("source", source.Name);
        Assert.Equal(VerbParameterKind.Text, source.Kind);
        Assert.True(source.Trailing);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesTheSeat()
    {
        // T1574.001 (Hijack Execution Flow: DLL Search Order
        // Hijacking) is the seat itself; the kernel catalog carries no
        // T1574 parent, so the matrix renders this row by id alone --
        // the degradation path designed for module-carried techniques.
        // The coverage matrix follows the declaration, not any kernel
        // file.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1574.001" }, Descriptor.Techniques);
    }

    [Fact]
    public void TheOpsecAttributesCarryTheHonestFlags()
    {
        // The seat is a file on disk and it loads every time the host
        // binary runs -- the flags the operator UI renders as risk
        // badges (architecture.md Sec 7). The read-only list action
        // never exceeds what the install's own flags declare.
        Assert.Equal("true", Descriptor.Attributes["writes-to-disk"]);
        Assert.Equal("true", Descriptor.Attributes["persists"]);
    }
}
