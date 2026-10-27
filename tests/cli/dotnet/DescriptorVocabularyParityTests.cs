using Rod.Cli.Manifest;

namespace Rod.Cli.Tests;

/// <summary>
/// The descriptor vocabularies are file contracts the two sides of the
/// module ecosystem state independently: the CLI validates manifest verb
/// rows (category, parameter kind, output kind) at publish, the
/// teamserver's descriptor loader parses the same names into its own
/// enumerations (Rod.Capabilities' <c>CapabilityCategory</c>,
/// <c>VerbParameterKind</c>, <c>VerbOutputKind</c>) at startup. The CLI
/// references nothing in-house by design, so this test project -- and only
/// this test project -- bridges the two copies and fails when either side
/// grows without the other. The manifest spellings are lowercase kebab;
/// the enums are PascalCase, and the loader's name resolution ignores case
/// and separators, so the comparison normalizes the same way.
/// </summary>
public class DescriptorVocabularyParityTests
{
    [Fact]
    public void TheCategories_AreTheSameClosedSet()
    {
        Assert.Equal(
            Enum.GetNames<Rod.Capabilities.CapabilityCategory>().Select(Kebab).OrderBy(n => n, StringComparer.Ordinal),
            ManifestVocabularies.Categories.OrderBy(n => n, StringComparer.Ordinal));
    }

    [Fact]
    public void TheParameterKinds_AreTheSameClosedSet()
    {
        Assert.Equal(
            Enum.GetNames<Rod.Capabilities.VerbParameterKind>().Select(Kebab).OrderBy(n => n, StringComparer.Ordinal),
            ManifestVocabularies.ParameterKinds.OrderBy(n => n, StringComparer.Ordinal));
    }

    [Fact]
    public void TheOutputKinds_AreTheSameClosedSet()
    {
        Assert.Equal(
            Enum.GetNames<Rod.Capabilities.VerbOutputKind>().Select(Kebab).OrderBy(n => n, StringComparer.Ordinal),
            ManifestVocabularies.OutputKinds.OrderBy(n => n, StringComparer.Ordinal));
    }

    // The loader's own normalization (DescriptorModuleLoader.TryParseName):
    // PascalCase collapses to lowercase kebab, ProcessList -> process-list.
    private static string Kebab(string name)
        => string.Concat(name.Select((c, i) =>
            i > 0 && char.IsUpper(c) ? "-" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
}
