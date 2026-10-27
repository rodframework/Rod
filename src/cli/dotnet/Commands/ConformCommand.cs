using System.Diagnostics;

namespace Rod.Cli;

/// <summary>
/// <c>rod conform &lt;candidate&gt;</c> -- the standalone conformance
/// runner's front (architecture.md Sec 15.2, ADR-018): spawns the
/// <c>rod-conform</c> executable against a candidate implant and lets it
/// drive the whole Tier 0 clause battery, streaming its report and
/// propagating its exit code. The CLI keeps its zero-in-house-reference
/// line: the harness is a sibling process reached by file contract --
/// resolved beside the rod binary, on PATH, or named by <c>--runner</c> --
/// never a project reference, exactly like the registry and lock-file
/// contracts the mod suite rides.
/// </summary>
internal static class ConformCommand
{
    private const string RunnerName = "rod-conform";

    public static Task<int> RunAsync(string[] args, TextWriter output, TextWriter error)
        => Run(args, output, error);

    private static async Task<int> Run(string[] args, TextWriter output, TextWriter error)
    {
        var parsed = ParsedArgs.Parse(args,
            valueOptions: new HashSet<string> { "runner" },
            flags: new HashSet<string> { "selftest", "help" },
            command: "conform",
            repeatableOptions: new HashSet<string> { "env" });

        if (parsed.Has("help"))
        {
            PrintUsage(output);
            return RodCli.ExitOk;
        }

        if (parsed.Positional.Count > 1)
            throw new CliError("rod conform takes exactly one candidate path.");
        var candidate = parsed.Positional.SingleOrDefault();
        var selftest = parsed.Has("selftest");
        if (selftest == (candidate is not null))
            throw new CliError(
                "name a candidate path, or pass --selftest to run the harness's own minimal implant -- exactly one.");
        if (candidate is not null && !File.Exists(candidate))
            throw new CliError($"the candidate '{candidate}' does not exist.");
        foreach (var pair in parsed.Values("env"))
            if (pair.IndexOf('=') <= 0)
                throw new CliError($"--env expects KEY=VALUE, got '{pair}'.");

        var runner = ResolveRunner(parsed)
            ?? throw new CliError(
                $"the conformance runner ({RunnerName}) was not found beside rod or on PATH; " +
                "pass --runner <path> to name it.");

        // The runner's report streams through the CLI's own writers, so a
        // caller capturing rod's output captures the report with it.
        var info = new ProcessStartInfo
        {
            FileName = runner,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (candidate is not null)
            info.ArgumentList.Add(candidate);
        if (selftest)
            info.ArgumentList.Add("--selftest");
        foreach (var pair in parsed.Values("env"))
        {
            info.ArgumentList.Add("--env");
            info.ArgumentList.Add(pair);
        }
        using var process = Process.Start(info)
            ?? throw new CliError($"failed to start the conformance runner '{runner}'.");
        var piping = Task.WhenAll(
            PipeAsync(process.StandardOutput, output),
            PipeAsync(process.StandardError, error));
        await process.WaitForExitAsync(CancellationToken.None);
        await piping;
        // The runner's exit codes are the CLI's own vocabulary: 0 pass,
        // 1 usage, 2 a clause failed.
        return process.ExitCode;
    }

    // Character-level piping: the report's lines pass through untouched,
    // and a runner that writes partial lines still streams as it writes.
    private static async Task PipeAsync(StreamReader reader, TextWriter writer)
    {
        var buffer = new char[4096];
        int read;
        while ((read = await reader.ReadAsync(buffer)) > 0)
            await writer.WriteAsync(buffer, 0, read);
        await writer.FlushAsync();
    }

    // The file contract's resolution order: an explicit path, the binary
    // shipped beside rod (the release layout), then PATH.
    private static string? ResolveRunner(ParsedArgs parsed)
    {
        if (parsed.Value("runner") is { } explicitPath)
        {
            if (!File.Exists(explicitPath))
                throw new CliError($"the conformance runner '{explicitPath}' does not exist (--runner).");
            return explicitPath;
        }

        var beside = new[] { RunnerName, RunnerName + ".exe" }
            .Select(name => Path.Combine(AppContext.BaseDirectory, name))
            .FirstOrDefault(File.Exists);
        if (beside is not null)
            return beside;

        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        return path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .SelectMany(directory => new[]
            {
                Path.Combine(directory, RunnerName),
                Path.Combine(directory, RunnerName + ".exe"),
            })
            .FirstOrDefault(File.Exists);
    }

    private static void PrintUsage(TextWriter output)
    {
        output.WriteLine("""
            rod conform -- run the Tier 0 conformance clauses against a candidate

            usage: rod conform <candidate> [options]
                   rod conform --selftest [options]

            Spawns the rod-conform runner (resolved beside rod, on PATH, or
            named by --runner), which boots a live teamserver in-process and
            drives the candidate through the whole clause battery, printing
            the per-clause pass/fail report -- the same clause set and format
            the in-tree conformance rig produces. The candidate is launched
            once per phase with ROD_ENROLL_URL, ROD_DEPLOY_TOKEN, and
            (kill-date phase only) ROD_KILL_DATE in its environment.

            options:
              --env KEY=VALUE   extra environment for the candidate (repeatable)
              --runner <path>   the rod-conform executable to spawn
              --selftest        run the harness's own minimal implant instead
                                of a candidate binary

            exit codes (the runner's, propagated): 0 every clause passed,
            1 usage error, 2 a clause failed.
            """);
    }
}
