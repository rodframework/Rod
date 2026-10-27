using Rod.Capabilities;
using Rod.Capabilities.Registry;
using Rod.Modules.Unload;
namespace Rod.Modules.Unload.Tests;

/// <summary>
/// The descriptor contract the unload module registers: the declaration
/// the operator UI's task form, the risk badges, the coverage matrix,
/// the report's Navigator layer, and the registry-backed sensitive-verb
/// policy all read. The registry refuses a malformed descriptor at
/// startup; these tests pin the module's own declaration against drift
/// -- a widened technique list or a reshaped parameter set is a
/// deliberate change someone notices, not an accident that ships.
/// </summary>
public class UnloadDescriptorTests
{
    private static CapabilityDescriptor Descriptor => new UnloadCapabilityModule().Descriptor;

    [Fact]
    public void TheModuleDeclaresItsVerbInTheEvasionNamespace()
    {
        Assert.Equal("evasion.unload", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Evasion, Descriptor.Category);
        Assert.Equal("1.1", Descriptor.Version);
        Assert.Equal("unload", new UnloadCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are the
        // action words the implant-side plugin's grammar answers (its
        // unknown-word refusal quotes the same set), and the two
        // widening slots sit in the grammar's own order -- the library
        // the task names, then the comma-joined export list as the
        // positional tail. The two halves drift together or fail here.
        Assert.Empty(Descriptor.ValidateParameters());
        Assert.Equal(3, Descriptor.Parameters!.Count);

        var action = Descriptor.Parameters[0];
        Assert.Equal("action", action.Name);
        Assert.Equal(VerbParameterKind.Enum, action.Kind);
        Assert.False(action.Required);
        Assert.Equal(new[] { "list", "restore" }, action.Choices);

        var dll = Descriptor.Parameters[1];
        Assert.Equal("dll", dll.Name);
        Assert.Equal(VerbParameterKind.Text, dll.Kind);
        Assert.False(dll.Required);
        Assert.False(dll.Trailing);

        var functions = Descriptor.Parameters[2];
        Assert.Equal("functions", functions.Name);
        Assert.Equal(VerbParameterKind.Text, functions.Kind);
        Assert.False(functions.Required);
        Assert.True(functions.Trailing);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesTheRestore()
    {
        // T1562.001 (Impair Defenses: Disable or Modify Tools) is the
        // restore itself, whole-text or per-function alike; the kernel
        // catalog maps this very verb to the id, so the sweep renders
        // this row beside the kernel's own carrier for the same verb.
        // The coverage matrix follows the declaration, not any kernel
        // file.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1562.001" }, Descriptor.Techniques);
    }

    [Fact]
    public async Task TheOpsecAttributesCarryTheSensitiveFlagThePolicyReads()
    {
        // The restore rewrites the target process's defensive posture --
        // the flag the sensitive-verb policy keys on (architecture.md
        // Sec 7, Sec 10.4). The category is Evasion on top of the
        // attribute, so the registration is sensitive twice over and
        // unattended firing refuses: the same registry path the
        // teamserver loads through answers.
        Assert.Equal("true", Descriptor.Attributes["modifies-defenses"]);

        var registry = new InMemoryCapabilityRegistry();
        await registry.RegisterAsync(new UnloadCapabilityModule());
        var policy = new CapabilityRegistrySensitiveVerbPolicy(registry);

        Assert.True(policy.IsSensitive("evasion.unload"));
    }
}
