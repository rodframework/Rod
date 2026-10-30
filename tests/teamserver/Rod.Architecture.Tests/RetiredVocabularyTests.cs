namespace Rod.Architecture.Tests;

/// <summary>
/// The retired-vocabulary guard (the word discipline behind
/// architecture.md Sec 6 and the wire-wide rename the trail records): the
/// stager vocabulary -- stage0/stage-0, stage1/stage-1, stage2/stage-2,
/// stager, StagerToken -- described a delivery model the platform no
/// longer has. The surface speaks payload, deploy token, implant, and
/// loader; letting the old words creep back in would grow two names for
/// one concept and re-entangle the contract the rename settled.
///
/// Three sanctioned homes are exempt, each by what the line itself shows:
/// the EF migration snapshots (schema history is immutable), the refusal
/// paths (the wire must keep recognizing the retired spellings it
/// refuses, and the tests that pin those refusals), and lines that
/// narrate the retirement itself (they say "retired"). Everything else --
/// comments, identifiers, operator copy, UI text, the Rust tree included
/// -- must carry the current vocabulary, and this test fails naming the
/// file and line when one slips in.
/// </summary>
public class RetiredVocabularyTests
{
    private static readonly string RepoRoot = FindRepoRoot(new DirectoryInfo(AppContext.BaseDirectory));

    private static string[] SourceSuffixes { get; } = [".cs", ".rs", ".ts", ".tsx", ".toml", ".proto"];

    [Fact]
    public void TheSourceTree_CarriesNoRetiredStagerVocabulary()
    {
        var violations = new List<string>();
        var scanned = 0;
        foreach (var tree in new[] { Path.Combine("src"), Path.Combine("tests") })
        {
            var root = Path.Combine(RepoRoot, tree);
            if (!Directory.Exists(root))
                continue;
            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(RepoRoot, file).Replace('\\', '/');
                if (!SourceSuffixes.Any(suffix => relative.EndsWith(suffix, StringComparison.Ordinal)))
                    continue;
                // Build output, cargo targets, and the npm tree are generated.
                if (relative.Contains("/bin/") || relative.Contains("/obj/")
                    || relative.Contains("/target/") || relative.Contains("/node_modules/")
                    // Schema history is immutable once shipped.
                    || relative.Contains("/Migrations/")
                    // This guard's own pattern table names the retired words
                    // by construction.
                    || relative.EndsWith("RetiredVocabularyTests.cs", StringComparison.Ordinal))
                    continue;
                scanned++;
                var line = 0;
                foreach (var text in File.ReadLines(file))
                {
                    line++;
                    if (!MatchesRetiredWord(text))
                        continue;
                    // The refusal paths keep recognizing the retired spellings,
                    // and the narration of the retirement says "retired".
                    if (text.Contains("stage2PayloadId", StringComparison.Ordinal)
                        || text.Contains("Stage2PayloadId", StringComparison.Ordinal)
                        || text.Contains("\"stager\"", StringComparison.Ordinal)
                        || text.Contains("\"Stager\"", StringComparison.Ordinal)
                        || text.Contains("retired", StringComparison.OrdinalIgnoreCase)
                        || text.Contains("retire ", StringComparison.OrdinalIgnoreCase))
                        continue;
                    violations.Add($"{relative}:{line}: {text.Trim()}");
                }
            }
        }

        Assert.True(
            violations.Count == 0,
            $"Retired stager vocabulary found in {violations.Count} line(s) -- the surface speaks payload, deploy token, implant, and loader (architecture.md Sec 6):\n"
                + string.Join("\n", violations.Take(20)));
    }

    // The word shapes that carry the retired vocabulary. "staged" is not
    // one of them: the staged transfer of file.push and exfil.stage is a
    // live, unrelated mechanism.
    private static bool MatchesRetiredWord(string text) =>
        text.Contains("stage-0", StringComparison.OrdinalIgnoreCase)
        || text.Contains("stage-1", StringComparison.OrdinalIgnoreCase)
        || text.Contains("stage-2", StringComparison.OrdinalIgnoreCase)
        || text.Contains("stage0", StringComparison.OrdinalIgnoreCase)
        || text.Contains("stage1", StringComparison.OrdinalIgnoreCase)
        || text.Contains("stage2", StringComparison.OrdinalIgnoreCase)
        || text.Contains("stager", StringComparison.OrdinalIgnoreCase);

    private static string FindRepoRoot(DirectoryInfo start)
    {
        var dir = start;
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src"))
                && Directory.Exists(Path.Combine(dir.FullName, "tests")))
                return dir.FullName;
            dir = dir.Parent!;
        }
        throw new InvalidOperationException("Repository root not found above the test binary.");
    }
}
