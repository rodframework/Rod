using System.Diagnostics;
using Rod.Conformance;

namespace Rod.Conformance.Tests;

/// <summary>
/// The reference Rust implant as a harness candidate: compiled once from the
/// source tree, then launched per phase as a real subprocess pointed at the
/// rig's endpoints through its dev shape (ROD_* environment) -- exactly the
/// documented candidate contract the standalone runner drives, with the
/// tuning knobs a poll candidate needs to fit the harness's observation
/// deadlines. This is the adapter that lets the harness's clause battery run
/// against the implant an operator actually deploys.
/// </summary>
public sealed class ReferenceImplantCandidate : IImplantCandidate
{
    /// <summary>
    /// The dev-shape tuning every harness run of the reference implant
    /// carries: a brisk poll cadence, the poll contact mode, the plaintext
    /// lab envelope, and the verb set the battery tasks. Shared surface with
    /// the standalone runner's tests, which pass the same knobs through
    /// <c>--env</c> to prove the runner against the reference binary.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> DevEnvironment =
        new Dictionary<string, string>
        {
            ["ROD_SLEEP"] = "1",
            ["ROD_JITTER"] = "0",
            ["ROD_MODE"] = "poll",
            ["ROD_ENVELOPE"] = "none",
            ["ROD_VERBS"] = "shell.exec,file.pull,fs.list,beacon.sleep,proc.kill,module.load,module.unload,module.list",
        };

    /// <summary>The compiled reference implant binary, cargo's release output.</summary>
    public string Binary { get; }

    private readonly ProcessCandidate _candidate;

    private ReferenceImplantCandidate(string binary)
    {
        Binary = binary;
        _candidate = new ProcessCandidate(binary, DevEnvironment);
    }

    /// <summary>
    /// Builds the reference implant from its source tree -- the pinned
    /// release the platform's lock names, or whatever checkout the
    /// resolution finds first. Throws when the build fails so the failure
    /// is attributable.
    /// </summary>
    public static ReferenceImplantCandidate Build()
    {
        var tree = LocateRustTree()
            ?? throw new InvalidOperationException(
                "The Rust implant tree did not resolve: no ROD_IMPLANT_RUST_DIR checkout, no co-located "
                + "tree, and no fetchable pinned release from rod-implants.lock.json.");
        var psi = new ProcessStartInfo
        {
            FileName = "cargo",
            WorkingDirectory = tree,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("build");
        psi.ArgumentList.Add("--release");
        using var build = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start cargo (is it on PATH?).");
        var stdout = build.StandardOutput.ReadToEnd();
        var stderr = build.StandardError.ReadToEnd();
        build.WaitForExit(300_000);
        if (build.ExitCode != 0)
            throw new InvalidOperationException(
                $"cargo build failed (exit {build.ExitCode}):{Environment.NewLine}{stdout}{Environment.NewLine}{stderr}");
        var binary = Path.Combine(tree, "target", "release", "rod-implant");
        if (!File.Exists(binary))
            throw new InvalidOperationException($"cargo reported success but {binary} is missing.");
        return new ReferenceImplantCandidate(binary);
    }

    public Task StartAsync(ConformanceTarget target) => _candidate.StartAsync(target);

    public Task StopAsync() => _candidate.StopAsync();

    public bool HasExited => _candidate.HasExited;

    public void Dispose() => _candidate.Dispose();

    // The build pipeline's pinned-source resolution: an environment
    // checkout, a co-located tree, then the pinned release the lock names.
    // Shared with the linkable-core tests, which build the static library
    // out of the same tree.
    internal static string? LocateRustTree()
        => Rod.BuildPipeline.PayloadBuild.PinnedImplantSource.LocateRustTree();
}
