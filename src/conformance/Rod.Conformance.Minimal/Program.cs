using Rod.Conformance;

namespace Rod.Conformance.Minimal;

/// <summary>
/// rod-minimal-implant -- the harness's worked example as a process: the
/// minimal Tier 0 implant driven entirely by the documented candidate
/// environment (ROD_ENROLL_URL, ROD_DEPLOY_TOKEN, and optionally
/// ROD_KILL_DATE, the same shape any candidate the standalone runner drives
/// reads). It runs its contact loop until terminated, and exits on its own
/// when its baked kill date is past -- the refusal the kill-date clause
/// observes. ROD_DEFECTS (comma-separated, names from
/// <see cref="ImplantDefects.Names"/>) breaks exactly one clause
/// deliberately, the negative lane of the harness's own acceptance.
/// </summary>
public static class Program
{
    public static async Task<int> Main()
    {
        var enrollUrl = Environment.GetEnvironmentVariable("ROD_ENROLL_URL");
        var token = Environment.GetEnvironmentVariable("ROD_DEPLOY_TOKEN");
        if (string.IsNullOrEmpty(enrollUrl) || string.IsNullOrEmpty(token))
        {
            Console.Error.WriteLine(
                "rod-minimal-implant: ROD_ENROLL_URL and ROD_DEPLOY_TOKEN are required.");
            return 1;
        }
        DateTimeOffset? killDate = DateTimeOffset.TryParse(
            Environment.GetEnvironmentVariable("ROD_KILL_DATE"), out var kill) ? kill : null;
        var defectNames = (Environment.GetEnvironmentVariable("ROD_DEFECTS") ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (!ImplantDefects.TryParse(defectNames, out var defects, out var unknown))
        {
            Console.Error.WriteLine(
                $"rod-minimal-implant: unknown defect '{unknown}' (valid: {string.Join(", ", ImplantDefects.Names)}).");
            return 1;
        }

        // The runner stops the process between phases; until then the loop
        // is the whole program.
        await new MinimalImplantLoop(defects).RunAsync(
            new ConformanceTarget(enrollUrl, token, killDate), CancellationToken.None);
        return 0;
    }
}
