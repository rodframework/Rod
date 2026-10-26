using Rod.Capabilities;
using Rod.Modules.Services;

namespace Rod.Modules.Services.Tests;

/// <summary>
/// The descriptor contract the services module registers: the
/// declaration the operator UI's task form, the risk badges, the
/// coverage matrix, and the report's Navigator layer all read. The
/// registry refuses a malformed descriptor at startup; these tests pin
/// the module's own declaration against drift -- a widened technique
/// list or a reshaped parameter set is a deliberate change someone
/// notices, not an accident that ships.
/// </summary>
public class ServicesDescriptorTests
{
    private static CapabilityDescriptor Descriptor => new ServicesCapabilityModule().Descriptor;

    [Fact]
    public void TheModuleDeclaresItsVerbInThePersistNamespace()
    {
        Assert.Equal("persist.services", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Persist, Descriptor.Category);
        Assert.Equal("1.0", Descriptor.Version);
        Assert.Equal("services", new ServicesCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are the
        // actions the implant-side plugin's parser answers (its
        // unknown-token refusals quote the same set), and the command
        // is the grammar's positional tail -- the two halves drift
        // together or fail here.
        Assert.Empty(Descriptor.ValidateParameters());
        Assert.Equal(3, Descriptor.Parameters!.Count);

        var action = Descriptor.Parameters[0];
        Assert.Equal("action", action.Name);
        Assert.Equal(VerbParameterKind.Enum, action.Kind);
        Assert.False(action.Required);
        Assert.Equal(new[] { "install", "remove", "list" }, action.Choices);

        var name = Descriptor.Parameters[1];
        Assert.Equal("name", name.Name);
        Assert.Equal(VerbParameterKind.String, name.Kind);
        Assert.False(name.Required);

        var command = Descriptor.Parameters[2];
        Assert.Equal("command", command.Name);
        Assert.Equal(VerbParameterKind.Text, command.Kind);
        Assert.True(command.Trailing);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesTheSeat()
    {
        // T1543.003 (Create or Modify System Process: Windows Service)
        // is the seat itself; the kernel catalog carries its parent
        // under persist.install and the matrix renders the
        // sub-technique by id alone. The coverage matrix follows the
        // declaration, not any kernel file.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1543.003" }, Descriptor.Techniques);
    }

    [Fact]
    public void TheOpsecAttributesCarryTheHonestFlags()
    {
        // The seat is a record in the on-disk SCM database and it runs
        // at every boot -- the flags the operator UI renders as risk
        // badges (architecture.md Sec 7). The read-only list action
        // never exceeds what the install's own flags declare.
        Assert.Equal("true", Descriptor.Attributes["writes-to-disk"]);
        Assert.Equal("true", Descriptor.Attributes["persists"]);
    }
}
