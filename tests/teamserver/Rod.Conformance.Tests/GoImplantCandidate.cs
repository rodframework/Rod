using System.Diagnostics;
using Rod.Conformance;

namespace Rod.Conformance.Tests;

/// <summary>
/// A fact that runs only when a Go toolchain is on PATH: the Go implant's
/// legs build it as a process. The integration suite carries its own copy;
/// this project does not reference it, and the probe is three lines.
/// </summary>
public sealed class GoFactAttribute : FactAttribute
{
    public GoFactAttribute()
    {
        try
        {
            var probe = Process.Start(new ProcessStartInfo
            {
                FileName = "go",
                ArgumentList = { "version" },
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            probe?.WaitForExit(5000);
            if (probe is null || probe.ExitCode != 0)
                Skip = "go is not usable on PATH";
        }
        catch
        {
            Skip = "go is not on PATH";
        }
    }
}

/// <summary>
/// The Go reference implant as a harness candidate: compiled once from the
/// source tree with the same hermetic environment the build unit drives
/// (vendored modules, network off, local toolchain), then launched per
/// phase through its dev shape like any community candidate. The plugin
/// clauses running against it are the contract's cross-host-language
/// proof: the same fixture bytes, a different host, the same clauses.
/// </summary>
public sealed class GoImplantCandidate : IImplantCandidate
{
    /// <summary>
    /// The dev-shape tuning the Go candidate carries: a brisk poll cadence,
    /// the plaintext lab envelope, the verb set the battery tasks (module
    /// family included, so the widened advertisement carries it), and the
    /// contact envelope explicitly off -- the Go dev shape defaults it to
    /// aesgcm and refuses to run without a key.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> DevEnvironment =
        new Dictionary<string, string>
        {
            ["ROD_SLEEP"] = "1",
            ["ROD_JITTER"] = "0",
            ["ROD_ENVELOPE"] = "none",
            ["ROD_CONTACT_ENVELOPE"] = "none",
            ["ROD_VERBOSE"] = "1",
            ["ROD_VERBS"] = "shell.exec,file.pull,module.load,module.unload,module.list",
        };

    private readonly ProcessCandidate _candidate;

    private GoImplantCandidate(string binary)
    {
        Binary = binary;
        _candidate = new ProcessCandidate(binary, DevEnvironment);
    }

    /// <summary>The compiled Go implant binary.</summary>
    public string Binary { get; }

    /// <summary>
    /// Builds the Go implant from the source tree with the build unit's
    /// hermetic environment. Throws when the build fails so the failure is
    /// attributable.
    /// </summary>
    public static GoImplantCandidate Build()
    {
        var tree = LocateGoTree()
            ?? throw new InvalidOperationException(
                "The Go implant tree (src/implant/go) was not found from the test assembly.");
        var binary = Path.Combine(Path.GetTempPath(), "rod-conform-" + Guid.NewGuid().ToString("N"), "rod-go-implant");
        Directory.CreateDirectory(Path.GetDirectoryName(binary)!);

        var psi = new ProcessStartInfo
        {
            FileName = "go",
            WorkingDirectory = tree,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("build");
        psi.ArgumentList.Add("-o");
        psi.ArgumentList.Add(binary);
        psi.ArgumentList.Add(".");
        psi.Environment["CGO_ENABLED"] = "0";
        psi.Environment["GOFLAGS"] = "-mod=vendor";
        psi.Environment["GOPROXY"] = "off";
        psi.Environment["GOTOOLCHAIN"] = "local";
        using var build = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start go (is it on PATH?).");
        var stdout = build.StandardOutput.ReadToEnd();
        var stderr = build.StandardError.ReadToEnd();
        build.WaitForExit(300_000);
        if (build.ExitCode != 0)
            throw new InvalidOperationException(
                $"go build failed (exit {build.ExitCode}):{Environment.NewLine}{stdout}{Environment.NewLine}{stderr}");
        if (!File.Exists(binary))
            throw new InvalidOperationException($"go reported success but {binary} is missing.");
        return new GoImplantCandidate(binary);
    }

    public Task StartAsync(ConformanceTarget target) => _candidate.StartAsync(target);

    public Task StopAsync() => _candidate.StopAsync();

    public bool HasExited => _candidate.HasExited;

    public void Dispose()
    {
        _candidate.Dispose();
        try { Directory.Delete(Path.GetDirectoryName(Binary)!, recursive: true); } catch { }
    }

    // Walks up from the test assembly to the repo root, the same resolution
    // the reference candidate applies to the Rust tree.
    private static string? LocateGoTree()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "implant", "go")) &&
                Directory.Exists(Path.Combine(dir.FullName, "src", "teamserver")))
                return Path.Combine(dir.FullName, "src", "implant", "go");
            dir = dir.Parent!;
        }
        return null;
    }
}
