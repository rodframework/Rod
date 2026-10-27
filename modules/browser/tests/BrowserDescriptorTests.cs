using Rod.Capabilities;
using Rod.Modules.Browser;

namespace Rod.Modules.Browser.Tests;

/// <summary>
/// The descriptor contract the browser module registers: the
/// declaration the operator UI's task form, the risk badges, the
/// coverage matrix, the report's Navigator layer, and the
/// registry-backed sensitive-verb policy all read. The registry
/// refuses a malformed descriptor at startup; these tests pin the
/// module's own declaration against drift -- a widened technique
/// list or a reshaped parameter set is a deliberate change someone
/// notices, not an accident that ships.
/// </summary>
public class BrowserDescriptorTests
{
    private static CapabilityDescriptor Descriptor => new BrowserCapabilityModule().Descriptor;

    [Fact]
    public void TheModuleDeclaresItsVerbInTheCollectNamespace()
    {
        Assert.Equal("collect.browser", Descriptor.Verb);
        Assert.Equal(CapabilityCategory.Collect, Descriptor.Category);
        Assert.Equal("1.0", Descriptor.Version);
        Assert.Equal("browser", new BrowserCapabilityModule().Name);
    }

    [Fact]
    public void TheParameterSchemaValidatesAndMatchesThePluginGrammar()
    {
        // The loader's own schema gate passes clean; the choices are
        // the actions and browsers the implant-side plugin's parser
        // answers (its unknown-token refusals quote the same sets) --
        // the two halves drift together or fail here.
        Assert.Empty(Descriptor.ValidateParameters());
        Assert.Equal(2, Descriptor.Parameters!.Count);

        var action = Descriptor.Parameters[0];
        Assert.Equal("action", action.Name);
        Assert.Equal(VerbParameterKind.Enum, action.Kind);
        Assert.False(action.Required);
        Assert.Equal(new[] { "list", "export" }, action.Choices);

        var browser = Descriptor.Parameters[1];
        Assert.Equal("browser", browser.Name);
        Assert.Equal(VerbParameterKind.Enum, browser.Kind);
        Assert.False(browser.Required);
        Assert.Equal(new[] { "chrome", "edge", "all" }, browser.Choices);
    }

    [Fact]
    public void TheTechniqueDeclarationValidatesAndNamesTheStoreSweep()
    {
        // T1555.003 (Credentials from Password Stores: Credentials
        // from Web Browsers) is the store sweep itself; the kernel
        // catalog carries the technique with its name and the parent
        // (T1555) under collect.cred, and the matrix renders this row
        // beside the family's other carriers. The coverage matrix
        // follows the declaration, not any kernel file.
        Assert.Empty(Descriptor.ValidateTechniques());
        Assert.Equal(new[] { "T1555.003" }, Descriptor.Techniques);
    }

    [Fact]
    public void TheOutputKindEarnsTheCredentialsBoard()
    {
        // The rows the plugin prints speak the credential grammar
        // (kind, principal, the sweep's own fields, the secret on
        // export), so the verb declares the kind the credentials
        // board parses -- the panel an in-tree collect verb earns by
        // its output's own shape.
        Assert.Equal(VerbOutputKind.Credential, Descriptor.Output!.Kind);
    }

    [Fact]
    public void TheOpsecAttributesCarryTheCredentialHonestFlags()
    {
        // The sweep reads credential material and drops nothing on
        // the target -- the flags the operator UI renders as risk
        // badges (architecture.md Sec 7) and the sensitive-verb
        // policy reads. The credential read itself stays automatable,
        // the collect set's own stance; the listing action never
        // exceeds the export's own flags.
        Assert.Equal("true", Descriptor.Attributes["reads-credential"]);
        Assert.Equal("false", Descriptor.Attributes["writes-to-disk"]);
    }
}
