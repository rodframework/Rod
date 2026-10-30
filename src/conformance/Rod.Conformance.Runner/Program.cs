using Rod.Conformance;

namespace Rod.Conformance.Runner;

/// <summary>
/// rod-conform -- the conformance harness as a standalone executable
/// (ADR-018): it boots the live teamserver in-process and drives a
/// candidate through the whole clause battery, printing the per-clause
/// report -- the same clause names, order, and format the in-tree rig
/// produces, because it runs the same rig. The candidate is an arbitrary
/// process launched against the documented environment (ROD_ENROLL_URL,
/// ROD_DEPLOY_TOKEN, ROD_KILL_DATE); `--selftest` runs the harness's own
/// minimal implant in-process instead, the toolchain check that needs no
/// candidate at all. Exit codes carry meaning to scripts: 0 every clause
/// passed, 1 usage or start failure, 2 a clause failed -- the one an
/// engagement pipeline must treat as red.
/// </summary>
public static class Program
{
    public const int ExitOk = 0;
    public const int ExitUsage = 1;
    public const int ExitConformanceFailure = 2;

    public static async Task<int> Main(string[] args)
    {
        try
        {
            return await RunAsync(args);
        }
        catch (RunnerError failure)
        {
            Console.Error.WriteLine($"rod-conform: {failure.Message}");
            return ExitUsage;
        }
        catch (System.ComponentModel.Win32Exception failure)
        {
            // Process.Start reaching the OS and being refused: not an
            // executable, or the loader rejects it. Name the file.
            Console.Error.WriteLine($"rod-conform: failed to start the candidate: {failure.Message}");
            return ExitUsage;
        }
    }

    private static async Task<int> RunAsync(string[] args)
    {
        string? candidate = null;
        var selftest = false;
        string? pluginPath = null;
        var environment = new Dictionary<string, string>(StringComparer.Ordinal);
        var defectNames = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            var token = args[i];
            switch (token)
            {
                case "--help" or "-h":
                    PrintUsage();
                    return ExitOk;
                case "--selftest":
                    selftest = true;
                    break;
                case "--plugin":
                    pluginPath = i + 1 < args.Length ? args[++i] : null;
                    if (string.IsNullOrEmpty(pluginPath))
                        throw new RunnerError("--plugin needs a value (the exec-v1 fixture module's path).");
                    if (!File.Exists(pluginPath))
                        throw new RunnerError($"the plugin '{pluginPath}' does not exist.");
                    break;
                case "--env":
                case "--defect":
                    var value = i + 1 < args.Length ? args[++i] : null;
                    if (string.IsNullOrEmpty(value))
                        throw new RunnerError($"{token} needs a value.");
                    if (token == "--env")
                    {
                        var separator = value.IndexOf('=');
                        if (separator <= 0)
                            throw new RunnerError($"--env expects KEY=VALUE, got '{value}'.");
                        environment[value[..separator]] = value[(separator + 1)..];
                    }
                    else
                    {
                        defectNames.Add(value);
                    }
                    break;
                default:
                    if (token.StartsWith("--", StringComparison.Ordinal))
                        throw new RunnerError($"unknown option '{token}'.");
                    if (candidate is not null)
                        throw new RunnerError("exactly one candidate path is expected.");
                    candidate = token;
                    break;
            }
        }

        if (selftest == (candidate is not null))
            throw new RunnerError(
                "name a candidate path, or pass --selftest to run the harness's own minimal implant -- exactly one.");
        if (!selftest && !File.Exists(candidate))
            throw new RunnerError($"the candidate '{candidate}' does not exist.");
        // The plugin clauses are opt-in: --plugin names the exec-v1 fixture
        // module (modules/conform's release binary) whose staging the two
        // Tier 2 clauses read.

        if (!ImplantDefects.TryParse(defectNames, out var defects, out var unknown))
            throw new RunnerError(
                $"unknown defect '{unknown}' (valid: {string.Join(", ", ImplantDefects.Names)}).");

        await using var rig = await ConformanceRig.StartAsync();
        IImplantCandidate instance = selftest
            ? new MinimalImplant(defects)
            : new ProcessCandidate(candidate!, environment);
        using (instance)
        {
            var report = await rig.RunAsync(
                instance,
                pluginPath is null ? null : await File.ReadAllBytesAsync(pluginPath));
            // The report is the whole stdout: byte-identical to what the
            // in-tree rig renders, so the two are diffable as-is.
            Console.Out.WriteLine(report);
            return report.Failed.Count == 0 ? ExitOk : ExitConformanceFailure;
        }
    }

    public static void PrintUsage()
    {
        Console.Out.WriteLine("""
            rod-conform -- the Rod Tier 0 conformance runner

            usage: rod-conform <candidate> [options]
                   rod-conform --selftest [options]

            Drives a candidate implant process against a live in-process
            teamserver and prints the pass/fail report per contract clause --
            the same clause set and format the in-tree conformance rig
            produces. The candidate is launched once per phase with
            ROD_ENROLL_URL, ROD_DEPLOY_TOKEN, and (kill-date phase only)
            ROD_KILL_DATE in its environment; it enrolls through that front
            and runs its contact loop until terminated, and must contact
            within the harness's 30-second observation deadlines.

            options:
              --env KEY=VALUE   extra environment for the candidate (repeatable);
                                the ROD_* target variables above are set by the
                                runner and win over these
              --selftest        run the harness's own minimal implant in-process
              --defect NAME     with --selftest: break the minimal implant
                                (repeatable; one of skip-signature-verification,
                                speak-handshake-second, scramble-chunk-sequences)
              --help            print this usage

            exit codes: 0 every clause passed, 1 usage or start failure,
            2 a clause failed.
            """);
    }
}

/// <summary>A usage failure rendered once at the top with exit code 1.</summary>
internal sealed class RunnerError(string message) : Exception(message);
