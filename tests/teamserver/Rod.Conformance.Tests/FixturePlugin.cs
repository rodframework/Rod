using System.Diagnostics;

namespace Rod.Conformance.Tests;

/// <summary>
/// The exec-v1 fixture module every plugin-clause lane stages: the conform
/// crate beside the reference implant's modules, built in release and
/// cached in the shared target dir. Both lanes -- the Rust reference and
/// the Go reference -- stage the same bytes, so the clauses prove the
/// contract, not a host's fixture.
/// </summary>
internal static class FixturePlugin
{
    public static string Build()
    {
        var tree = ReferenceImplantCandidate.LocateRustTree()
            ?? throw new InvalidOperationException("the Rust tree walked up to nothing");
        var crate = Path.GetFullPath(Path.Combine(tree, "modules", "conform"));
        var binary = Path.Combine(crate, "target", "release", "rod-module-conform");
        if (File.Exists(binary))
            return binary;

        var start = new ProcessStartInfo
        {
            FileName = "cargo",
            WorkingDirectory = crate,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("build");
        start.ArgumentList.Add("--release");
        using var build = Process.Start(start)
            ?? throw new InvalidOperationException("Failed to start cargo (is it on PATH?).");
        var stdout = build.StandardOutput.ReadToEnd();
        var stderr = build.StandardError.ReadToEnd();
        build.WaitForExit();
        if (build.ExitCode != 0)
            throw new InvalidOperationException($"cargo build failed for the fixture plugin:\n{stdout}\n{stderr}");
        return binary;
    }
}
