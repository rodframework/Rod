namespace Rod.Cli.Tests;

/// <summary>
/// The conform command's contract is the process seam itself: the CLI
/// resolves the rod-conform runner, forwards the candidate, the --env
/// extras, and --selftest, and propagates the runner's exit codes --
/// everything an engagement pipeline scripts against. A shell-script
/// runner stands in for the real executable (the harness's own
/// end-to-end acceptance lives with the conformance suite), so these
/// tests pin the seam without bridging the CLI to anything in-house.
/// </summary>
public class ConformCommandTests
{
    [Fact]
    public void ForwardsTheCandidateAndEnv_ToTheRunner()
    {
        using var root = new TempRoot();
        var (runner, forwarded, _) = FakeRunner(root, "PASS  everything");
        var candidate = WriteCandidate(root);

        var run = CliRun.Run("conform", candidate, "--runner", runner,
            "--env", "ROD_SLEEP=1", "--env", "ROD_JITTER=0");

        Assert.Equal(0, run.Code);
        Assert.Equal(
            [candidate, "--env", "ROD_SLEEP=1", "--env", "ROD_JITTER=0"],
            File.ReadAllLines(forwarded));
    }

    [Fact]
    public void ForwardsSelftest_InsteadOfACandidate()
    {
        using var root = new TempRoot();
        var (runner, forwarded, _) = FakeRunner(root, "PASS  everything");

        var run = CliRun.Run("conform", "--selftest", "--runner", runner);

        Assert.Equal(0, run.Code);
        Assert.Equal(["--selftest"], File.ReadAllLines(forwarded));
    }

    [Fact]
    public void PropagatesTheRunnerExitCode_AndStreamsItsReport()
    {
        using var root = new TempRoot();
        var reportLine = "FAIL  signature.verification: executed the unsigned tasking";
        var (runner, _, _) = FakeRunner(root, reportLine, exitCode: 2);
        var candidate = WriteCandidate(root);

        var run = CliRun.Run("conform", candidate, "--runner", runner);

        Assert.Equal(2, run.Code);
        Assert.Contains(reportLine, run.Output);
    }

    [Fact]
    public void AMissingRunner_IsAUsageErrorNamingTheContract()
    {
        using var root = new TempRoot();
        var candidate = WriteCandidate(root);

        var run = CliRun.Run("conform", candidate, "--runner", root["nowhere"]);

        Assert.Equal(RodCli.ExitUsage, run.Code);
        Assert.Contains("--runner", run.Error);
    }

    [Fact]
    public void UsageErrors_AreCaughtBeforeSpawning()
    {
        using var root = new TempRoot();
        var (runner, _, _) = FakeRunner(root, "unused");
        var candidate = WriteCandidate(root);

        var missing = CliRun.Run("conform", root["no-such-binary"], "--runner", runner);
        Assert.Equal(RodCli.ExitUsage, missing.Code);
        Assert.Contains("does not exist", missing.Error);

        var both = CliRun.Run("conform", candidate, "--selftest", "--runner", runner);
        Assert.Equal(RodCli.ExitUsage, both.Code);
        Assert.Contains("exactly one", both.Error);

        var malformed = CliRun.Run("conform", candidate, "--runner", runner, "--env", "MISSING-EQUALS");
        Assert.Equal(RodCli.ExitUsage, malformed.Code);
        Assert.Contains("KEY=VALUE", malformed.Error);
    }

    [Fact]
    public void Help_PrintsTheUsage()
    {
        var run = CliRun.Run("conform", "--help");

        Assert.Equal(0, run.Code);
        Assert.Contains("rod-conform", run.Output);
        Assert.Contains("ROD_ENROLL_URL", run.Output);
    }

    /// <summary>
    /// A stand-in runner: it records the arguments it was handed, echoes a
    /// report on stdout, and exits with the code the test chose.
    /// </summary>
    private static (string Runner, string ForwardedArgs, string Report) FakeRunner(
        TempRoot root, string reportLine, int exitCode = 0)
    {
        var runner = root["rod-conform-fake.sh"];
        var forwarded = root["forwarded-args"];
        File.WriteAllText(runner, $"""
            #!/bin/sh
            printf '%s\n' "$@" > '{forwarded}'
            echo '{reportLine}'
            exit {exitCode}
            """);
        using (var chmod = System.Diagnostics.Process.Start(
                   new System.Diagnostics.ProcessStartInfo("chmod", $"+x {runner}"))!)
        {
            chmod.WaitForExit(15_000);
            Assert.True(chmod.ExitCode == 0, $"chmod +x {runner} failed");
        }
        return (runner, forwarded, reportLine);
    }

    private static string WriteCandidate(TempRoot root)
    {
        var candidate = root["candidate-implant"];
        File.WriteAllText(candidate, "an opaque candidate binary\n");
        return candidate;
    }
}
