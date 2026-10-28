using System.Diagnostics;
using Rod.Conformance;

namespace Rod.Conformance.Tests;

/// <summary>
/// Acceptance for the linkable core (architecture.md Sec 15.2, ADR-018):
/// the crate's lib target as a C-ABI embedding surface, proved by the only
/// shape that can prove it -- a shell that is not Rust. The worked C shell
/// under <c>src/implant/rust/shell/</c> compiles against the static library
/// and runs the whole conformance clause battery as an ordinary candidate
/// process; if it passes, any language that can link a static library gets
/// the same result writing nothing but its own <c>main</c> and pump loop.
/// The build needs cargo (the static library) and a C compiler (the
/// shell); each is probed for and the tests skip, not fail, where absent,
/// the same rule the reference-implant candidate applies.
/// </summary>
public class LinkableCoreTests
{
    [Fact]
    public async Task TheCShellLinkedCore_PassesEveryClause()
    {
        if (!OperatingSystem.IsLinux())
            return; // The static-library link line is Linux-shaped here.
        if (!ConformanceHarnessTests.CargoAvailable() || !CcAvailable())
            return; // The worked shell needs the Rust and C toolchains.

        using var candidate = new ProcessCandidate(
            GetOrBuildShell(), ReferenceImplantCandidate.DevEnvironment);
        await using var rig = await ConformanceRig.StartAsync();

        var report = await rig.RunAsync(candidate);

        Assert.True(report.Failed.Count == 0,
            $"the C shell over the linked core failed clauses:{Environment.NewLine}{report}");
    }

    [Fact]
    public void TheCShellLinkedCore_ExitsAtTheInitGate_WithoutAProfile()
    {
        if (!OperatingSystem.IsLinux())
            return;
        if (!ConformanceHarnessTests.CargoAvailable() || !CcAvailable())
            return;

        using var process = Process.Start(new ProcessStartInfo(GetOrBuildShell())
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        }) ?? throw new InvalidOperationException("Failed to start the shell.");
        // The gate is immediate: no ROD_* environment, so the core answers
        // its init gate (exit 2) without a dial, the same answer the
        // standalone Rust binary gives.
        if (!process.WaitForExit(15_000))
        {
            process.Kill(entireProcessTree: true);
            Assert.Fail("the shell did not exit at the init gate");
        }
        Assert.Equal(2, process.ExitCode);
    }

    // The C compiler probe, the CargoAvailable pattern: absent means skip,
    // not fail -- `cc` is the worked shell's only toolchain assumption.
    internal static bool CcAvailable()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("cc", "--version")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (process is null)
                return false;
            process.WaitForExit(15000);
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    // Builds the shell once per test run: the static library out of the
    // source tree, then the C shell linked against it. Both artifacts land
    // in cargo's target directory, where repeat runs reuse them.
    private static string GetOrBuildShell() => _shell.Value;

    private static readonly Lazy<string> _shell = new(BuildShell);

    private static string BuildShell()
    {
        var tree = ReferenceImplantCandidate.LocateRustTree()
            ?? throw new InvalidOperationException(
                "The Rust implant tree (src/implant/rust) was not found from the test assembly.");

        // Always cargo build: incremental cost is seconds, and staleness of
        // the .a under any input (sources, manifest, rod.proto through
        // build.rs) is cargo's own concern, not a timestamp walk's.
        Run("cargo", tree, 300_000, "build", "--release");
        var library = Path.Combine(tree, "target", "release", "librod_implant.a");
        if (!File.Exists(library))
            throw new InvalidOperationException($"cargo reported success but {library} is missing.");

        var shell = Path.Combine(tree, "target", "rod-shell");
        var source = Path.Combine(tree, "shell", "main.c");
        Run("cc", tree, 60_000,
            "-O2", "-Wall", "-Wextra", "-o", shell, source, library,
            "-lpthread", "-lm", "-ldl");
        return shell;
    }

    private static void Run(string tool, string workingDirectory, int timeoutMs, params string[] arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = tool,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {tool} (is it on PATH?).");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit(timeoutMs);
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"{tool} {string.Join(' ', arguments)} failed (exit {process.ExitCode}):" +
                $"{Environment.NewLine}{stdout}{Environment.NewLine}{stderr}");
    }
}
