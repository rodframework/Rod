namespace Rod.Modules.BrowserHook.Tests;

/// <summary>
/// The template's half of the render contract (architecture.md Sec 5.2,
/// Sec 8): the teamserver's mint substitutes one bake object for one
/// placeholder and serves the result, so the template must carry the
/// placeholder exactly once and nothing else the renderer depends on may
/// drift. These pins travel with the module because they pin module
/// content; the kernel's suites pin the seam (mint, serve, audit), never
/// the script.
/// </summary>
public class HookTemplateTests
{
    private static readonly Lazy<string> Template = new(() =>
    {
        // The module root is the nearest ancestor carrying the manifest;
        // the test bin lives under tests/ inside it.
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent!)
        {
            var candidate = Path.Combine(directory.FullName, "rod-module.toml");
            if (File.Exists(candidate))
                return File.ReadAllText(Path.Combine(directory.FullName, "assets", "hook.js"));
        }
        throw new InvalidOperationException("Could not locate the module root from the test assembly.");
    });

    private static string TemplateText => Template.Value;

    [Fact]
    public void TheBakePlaceholder_AppearsExactlyOnce()
    {
        var count = Count(TemplateText, "__ROD_BAKE_JSON__");
        Assert.Equal(1, count);
    }

    [Fact]
    public void TheBakeLine_IsTheSubstitutionSiteTheServedScriptCarries()
    {
        // The rendered artifact's bake line is what a bootstrapping client
        // (the browser, or a conformance test) parses; the template must
        // keep the line's shape so the substitution stays one JSON literal.
        Assert.Contains("var ROD_HOOK_BAKE = __ROD_BAKE_JSON__;", TemplateText);
    }

    [Fact]
    public void TheCodecSection_CarriesItsSliceMarkers()
    {
        // The cross-language smoke below slices the dependency-free codec
        // region between these markers; losing either marker breaks the
        // slice, so the template pins them.
        Assert.Contains("// ---- byte helpers", TemplateText);
        Assert.Contains("// ---- seal", TemplateText);
    }

    private static int Count(string text, string needle)
    {
        var count = 0;
        for (var at = text.IndexOf(needle, StringComparison.Ordinal);
             at >= 0;
             at = text.IndexOf(needle, at + needle.Length, StringComparison.Ordinal))
            count++;
        return count;
    }
}
