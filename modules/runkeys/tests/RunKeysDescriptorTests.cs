using Rod.Capabilities;
using Rod.Modules.Runkeys;

namespace Rod.Modules.Runkeys.Tests;

/// <summary>
/// The descriptor contract the run-keys module registers: the
/// declaration the operator UI's task form, the risk badges, the
/// coverage matrix, and the report's Navigator layer all read. The
/// registry refuses a malformed descriptor at startup; these tests pin
/// the module's own declaration against drift -- a widened technique
/// list or a reshaped parameter set is a deliberate change someone
/// notices, not an accident that ships.
/// </summary>
public class RunKeysDescriptorTests
{
    private static CapabilityDescriptor Descriptor => new RunKeysCapabilityModule().Descriptor;

    [Fact]
    public void TheModuleDeclaresItsVerbInThePersistNamespace()
    {
        Assert.Equal("persist.runkeys", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Persist, Descriptor.Category);
        Assert.Equal("1.0", Descriptor.Version);
        Assert.Equal("runkeys", new RunKeysCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are the
        // actions and hives the implant-side plugin's parser answers
        // (its unknown-token refusals quote the same sets), and the
        // command is the grammar's positional tail -- the two halves
        // drift together or fail here.
        Assert.Empty(Descriptor.ValidateParameters());
        Assert.Equal(4, Descriptor.Parameters!.Count);

        var action = Descriptor.Parameters[0];
        Assert.Equal("action", action.Name);
        Assert.Equal(VerbParameterKind.Enum, action.Kind);
        Assert.False(action.Required);
        Assert.Equal(new[] { "install", "remove", "list" }, action.Choices);

        var hive = Descriptor.Parameters[1];
        Assert.Equal("hive", hive.Name);
        Assert.Equal(VerbParameterKind.Enum, hive.Kind);
        Assert.False(hive.Required);
        Assert.Equal(new[] { "hkcu", "hklm" }, hive.Choices);

        var name = Descriptor.Parameters[2];
        Assert.Equal("name", name.Name);
        Assert.Equal(VerbParameterKind.String, name.Kind);
        Assert.False(name.Required);

        var command = Descriptor.Parameters[3];
        Assert.Equal("command", command.Name);
        Assert.Equal(VerbParameterKind.Text, command.Kind);
        Assert.True(command.Trailing);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesTheSeat()
    {
        // T1547.001 (Registry Run Keys / Startup Folder) is the seat
        // itself; the kernel catalog carries its parent and the matrix
        // renders the sub-technique by id alone. The coverage matrix
        // follows the declaration, not any kernel file.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1547.001" }, Descriptor.Techniques);
    }

    [Fact]
    public void TheOpsecAttributesCarryTheHonestFlags()
    {
        // The seat is a value in the on-disk hive and it persists across
        // logons -- the flags the operator UI renders as risk badges
        // (architecture.md Sec 7). The read-only list action never
        // exceeds what the install's own flags declare.
        Assert.Equal("true", Descriptor.Attributes["writes-to-disk"]);
        Assert.Equal("true", Descriptor.Attributes["persists"]);
    }
}
