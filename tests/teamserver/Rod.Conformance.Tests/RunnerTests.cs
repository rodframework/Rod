using System.Diagnostics;
using Rod.Conformance;

namespace Rod.Conformance.Tests;

/// <summary>
/// Acceptance for the standalone conformance runner (architecture.md
/// Sec 15.2, ADR-018): a candidate authored outside the harness -- an
/// opaque process speaking only the documented candidate environment --
/// runs the whole clause suite and gets the same pass/fail report the
/// in-tree rig produces. The worked example implant (rod-minimal-implant)
/// is that candidate here, launched through a wrapper exactly as a
/// community binary would be; the reference implant rides the same path
/// where the Rust toolchain is present. The comparison is literal: the
/// runner's stdout is the in-tree report, byte for byte.
/// </summary>
public class RunnerTests
{
    [Fact]
    public async Task Selftest_PassesEveryClauseInProcess()
    {
        var run = await SpawnRunner("--selftest");

        Assert.True(run.Code == 0, run.StandardError);
        var lines = run.StandardOutput.Split(
            Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        Assert.All(lines, line => Assert.StartsWith("PASS  ", line, StringComparison.Ordinal));
        Assert.Equal(
            EnumerateClauses(),
            lines.Select(line => line["PASS  ".Length..].Split(':')[0]));
    }

    [Fact]
    public async Task TheRunner_ProducesTheInTreeRigReport_ForAProcessCandidate()
    {
        await using var rig = await ConformanceRig.StartAsync();
        using var inTree = new MinimalImplant(new ImplantDefects());
        var expected = (await rig.RunAsync(inTree)).ToString();

        var run = await SpawnRunner(CandidateScript());

        Assert.True(run.Code == 0,
            $"exit {run.Code}:{Environment.NewLine}{run.StandardOutput}{run.StandardError}");
        Assert.Equal(expected, run.StandardOutput.TrimEnd());
    }

    [Fact]
    public async Task TheRunner_FailsANamedClause_ForADefectCandidate()
    {
        await using var rig = await ConformanceRig.StartAsync();
        using var inTree = new MinimalImplant(
            new ImplantDefects(SkipSignatureVerification: true));
        var expected = (await rig.RunAsync(inTree)).ToString();

        var run = await SpawnRunner(CandidateScript(),
            "--env", "ROD_DEFECTS=skip-signature-verification");

        Assert.Equal(2, run.Code);
        Assert.Equal(expected, run.StandardOutput.TrimEnd());
        Assert.Contains("FAIL  signature.verification", run.StandardOutput);
    }

    [Fact]
    public async Task TheRunner_PassesTheReferenceImplant_WithTheDocumentedKnobs()
    {
        if (!ConformanceHarnessTests.CargoAvailable())
            return; // The reference implant needs the Rust toolchain.

        var reference = ReferenceImplantCandidate.Build();
        var arguments = new List<string> { reference.Binary };
        foreach (var (key, value) in ReferenceImplantCandidate.DevEnvironment)
        {
            arguments.Add("--env");
            arguments.Add($"{key}={value}");
        }

        var run = await SpawnRunner([.. arguments]);

        Assert.True(run.Code == 0,
            $"exit {run.Code}:{Environment.NewLine}{run.StandardOutput}{run.StandardError}");
    }

    [Fact]
    public async Task UsageErrors_ExitOneWithAMessage()
    {
        var bare = await SpawnRunner();
        Assert.Equal(1, bare.Code);
        Assert.Contains("exactly one", bare.StandardError);

        var malformed = await SpawnRunner("--env", "MISSING-SEPARATOR");
        Assert.Equal(1, malformed.Code);
        Assert.Contains("KEY=VALUE", malformed.StandardError);
    }

    // The runner assembly flows into the test output beside the test
    // assembly; `dotnet rod-conform.dll` is the author's
    // `./rod-conform` modulo the apphost.
    private static async Task<(int Code, string StandardOutput, string StandardError)> SpawnRunner(
        params string[] arguments)
    {
        var runner = Path.Combine(AppContext.BaseDirectory, "rod-conform.dll");
        Assert.True(File.Exists(runner), "rod-conform.dll did not flow into the test output.");
        var info = new ProcessStartInfo("dotnet", [runner, .. arguments])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(info)!;
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync(CancellationToken.None);
        return (process.ExitCode, stdout, stderr);
    }

    /// <summary>
    /// The example implant as an opaque candidate executable: a shell
    /// wrapper exec'ing the assembly, the shape any launcher-scripted
    /// community binary takes. The environment the runner sets (and the
    /// ROD_DEFECTS extra, when passed) flows through exec unchanged.
    /// </summary>
    private static string CandidateScript()
    {
        var implant = Path.Combine(AppContext.BaseDirectory, "rod-minimal-implant.dll");
        Assert.True(File.Exists(implant), "rod-minimal-implant.dll did not flow into the test output.");
        var script = Path.Combine(Path.GetTempPath(),
            "rod-conform-candidate-" + Guid.NewGuid().ToString("N") + ".sh");
        File.WriteAllText(script, $"#!/bin/sh\nexec dotnet '{implant}' \"$@\"\n");
        MakeExecutable(script);
        return script;
    }

    private static void MakeExecutable(string path)
    {
        using var chmod = Process.Start(new ProcessStartInfo("chmod", $"+x {path}"))!;
        chmod.WaitForExit(15_000);
        Assert.True(chmod.ExitCode == 0, $"chmod +x {path} failed");
    }

    private static IEnumerable<string> EnumerateClauses()
    {
        yield return ConformanceRig.EnrollClause;
        yield return ConformanceRig.HandshakeClause;
        yield return ConformanceRig.RoundTripClause;
        yield return ConformanceRig.ChunkClause;
        yield return ConformanceRig.SignatureClause;
        yield return ConformanceRig.KillDateClause;
    }
}
