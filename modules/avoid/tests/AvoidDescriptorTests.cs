using Rod.Capabilities;
using Rod.Capabilities.Registry;
using Rod.Modules.Avoid;
namespace Rod.Modules.Avoid.Tests;

/// <summary>
/// The descriptor contract the avoid module registers: the declaration
/// the operator UI's task form, the risk badges, the coverage matrix,
/// the report's Navigator layer, and the registry-backed sensitive-verb
/// policy all read. The registry refuses a malformed descriptor at
/// startup; these tests pin the module's own declaration against drift
/// -- a widened technique list or a reshaped parameter set is a
/// deliberate change someone notices, not an accident that ships.
/// </summary>
public class AvoidDescriptorTests
{
    private static CapabilityDescriptor Descriptor => new AvoidCapabilityModule().Descriptor;

    [Fact]
    public void TheModuleDeclaresItsVerbInTheEvasionNamespace()
    {
        Assert.Equal("evasion.avoid", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Evasion, Descriptor.Category);
        Assert.Equal("1.0", Descriptor.Version);
        Assert.Equal("avoid", new AvoidCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are the
        // target words the implant-side plugin's table answers (its
        // unknown-word refusal quotes the same set), and the target is
        // required -- a sensitive act names its target rather than
        // guessing a default. The two halves drift together or fail
        // here.
        Assert.Empty(Descriptor.ValidateParameters());
        var target = Assert.Single(Descriptor.Parameters!);

        Assert.Equal("target", target.Name);
        Assert.Equal(VerbParameterKind.Enum, target.Kind);
        Assert.True(target.Required);
        Assert.Equal(new[] { "amsi", "etw", "all" }, target.Choices);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesThePatch()
    {
        // T1562.001 (Impair Defenses: Disable or Modify Tools) is the
        // patch itself; the kernel catalog already carries the id under
        // evasion.unload, so this row renders beside a kernel carrier.
        // The coverage matrix follows the declaration, not any kernel
        // file.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1562.001" }, Descriptor.Techniques);
    }

    [Fact]
    public async Task TheOpsecAttributesCarryTheSensitiveFlagThePolicyReads()
    {
        // The patch alters the target process's defensive posture --
        // the flag the sensitive-verb policy keys on (architecture.md
        // Sec 7, Sec 10.4). The category is Evasion on top of the
        // attribute, so the registration is sensitive twice over and
        // unattended firing refuses: the same registry path the
        // teamserver loads through answers.
        Assert.Equal("true", Descriptor.Attributes["modifies-defenses"]);

        var registry = new InMemoryCapabilityRegistry();
        await registry.RegisterAsync(new AvoidCapabilityModule());
        var policy = new CapabilityRegistrySensitiveVerbPolicy(registry);

        Assert.True(policy.IsSensitive("evasion.avoid"));
    }
}
