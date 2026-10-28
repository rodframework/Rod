using System.Diagnostics;
using Rod.CoreState.Implants;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// The Go build unit (architecture.md Sec 6, Sec 12.2): drives the Go
/// toolchain against the Go community implant tree through the same build
/// contract the Rust unit serves. The unit copies the tree into a
/// per-build staging dir (the vendored dependency set rides along, so the
/// build never touches the network), stages the per-artifact profile file
/// -- the same language-neutral rod.profile.json every unit writes,
/// embedded by the module's own go:embed -- and compiles a
/// static binary for the requested GOOS/GOARCH with cgo off. The size
/// posture rides <c>-trimpath -ldflags "-s -w"</c> unconditionally: the
/// executable formats are compatibility names over the one artifact the
/// Go toolchain always produces ahead-of-time.
/// </summary>
/// <remarks>
/// Build failures throw <see cref="BuildUnitFailureException"/> (a
/// server-side fault: the toolchain, the source tree, or the host is
/// wrong) while contract refusals -- the loader tier, unsupported
/// formats, unmapped targets -- throw <see cref="InvalidOperationException"/>
/// (the request is wrong). The compile cache stays at the Go default
/// (the user cache), which staging copies share by construction: only the
/// main module recompiles per build.
/// </remarks>
public sealed class GoBuildUnit : IBuildUnit, IBuildUnitEnvironment
{
    // The ceiling every spawned toolchain process runs under, shared with
    // the Rust unit's knob (ROD_BUILD_TIMEOUT_MINUTES): a hung build must
    // not pin the build queue forever. Zero disables.
    private static readonly TimeSpan ProcessTimeout = ResolveProcessTimeout();

    private static TimeSpan ResolveProcessTimeout()
    {
        var raw = Environment.GetEnvironmentVariable("ROD_BUILD_TIMEOUT_MINUTES");
        if (!int.TryParse(raw, out var minutes))
            return TimeSpan.FromMinutes(20);
        return minutes <= 0 ? Timeout.InfiniteTimeSpan : TimeSpan.FromMinutes(minutes);
    }

    private readonly string _goSourceDir;
    private readonly string _goBinary;

    public string UnitId => BuildUnitIds.Go;

    public GoBuildUnit(string? goSourceDir = null, string? goBinary = null)
    {
        _goSourceDir = string.IsNullOrWhiteSpace(goSourceDir)
            ? ResolveDefaultGoSourceDir()
            : goSourceDir;
        _goBinary = goBinary ?? "go";
    }

    /// <summary>
    /// Probes the host: the go tool by version query, the source tree by
    /// existence, and the vendored dependency set by existence -- a tree
    /// without vendor/ builds network-bound, which the unit's hermetic
    /// posture refuses to surprise anyone with.
    /// </summary>
    public BuildUnitEnvironmentReport ReportEnvironment()
    {
        var findings = new List<BuildEnvironmentFinding>
        {
            new("ok", "source tree", $"Go implant module at '{_goSourceDir}'"),
        };
        if (!Directory.Exists(_goSourceDir))
            findings[0] = new("missing", "source tree",
                $"Go implant source tree not found at '{_goSourceDir}' -- set Build:GoSourceDirectory to the module's location");

        var vendor = Directory.Exists(Path.Combine(_goSourceDir, "vendor"));
        findings.Add(vendor
            ? new("ok", "vendored deps", "the module carries vendor/, so builds run hermetically with -mod=vendor")
            : new("missing", "vendored deps",
                "the Go tree carries no vendor/ directory -- run 'go mod vendor' in it, or every build needs the network"));

        var go = ProbeVersion(_goBinary, "version");
        findings.Add(go.Found
            ? new("ok", "go", go.FirstLine)
            : new("missing", "go",
                $"'{_goBinary}' was not found on PATH -- every Go build fails until a Go toolchain is installed"));

        var status = !Directory.Exists(_goSourceDir) || !vendor || !go.Found ? "unavailable" : "ready";
        return new BuildUnitEnvironmentReport(UnitId, status, findings, Array.Empty<BuildTargetReadiness>());
    }

    public async Task<BuildArtifact> BuildAsync(BuildParams @params, CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(_goSourceDir))
            throw new BuildUnitFailureException($"Go implant source tree not found at '{_goSourceDir}'.");

        // The loader tier is the Rust unit's no_std crate; a Go build is
        // the implant only.
        if (@params.Kind == PayloadKind.Loader)
            throw new InvalidOperationException(
                "The loader tier is the Rust unit's no_std crate; a Go build produces the implant only.");

        // The format axis over the target: Go always emits one native
        // executable ahead-of-time, so the exe spellings are synonyms and
        // every shared-library or shellcode spelling is a contract slot
        // this unit does not produce.
        if (@params.Format is ArtifactFormat.Dll
            or ArtifactFormat.SharedObject
            or ArtifactFormat.Shellcode
            or ArtifactFormat.Apk)
            throw new InvalidOperationException(
                $"The '{ArtifactFormats.Name(@params.Format)}' format is a contract slot the Go unit does not produce; build 'exe'.");

        var (goos, goarch) = MapTarget(@params.Target);

        var workDir = Path.Combine(Path.GetTempPath(), "rod-go-build-" + Guid.NewGuid().ToString("N"));
        var stagingDir = Path.Combine(workDir, "src", "implant", "go");
        try
        {
            CopyTree(_goSourceDir, stagingDir);

            // The bake: the profile file staged into the module root, the
            // one language-neutral write every unit performs -- the module's
            // baked.go embeds it verbatim via go:embed.
            ProfileBake.WriteFile(@params, stagingDir);

            var binaryName = goos == "windows" ? "rod-implant.exe" : "rod-implant";
            var binaryPath = Path.Combine(workDir, "out", binaryName);
            Directory.CreateDirectory(Path.GetDirectoryName(binaryPath)!);

            var go = new ProcessStartInfo
            {
                FileName = _goBinary,
                WorkingDirectory = stagingDir,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };
            go.ArgumentList.Add("build");
            go.ArgumentList.Add("-trimpath");
            go.ArgumentList.Add("-ldflags");
            go.ArgumentList.Add("-s -w");
            go.ArgumentList.Add("-o");
            go.ArgumentList.Add(binaryPath);
            go.ArgumentList.Add(".");
            // Hermetic and static: vendor/ answers every dependency, cgo is
            // off, and no toolchain download may ever ride a payload build.
            go.Environment["GOOS"] = goos;
            go.Environment["GOARCH"] = goarch;
            go.Environment["CGO_ENABLED"] = "0";
            go.Environment["GOFLAGS"] = "-mod=vendor";
            go.Environment["GOPROXY"] = "off";
            go.Environment["GOTOOLCHAIN"] = "local";

            var result = await RunAsync(go, cancellationToken);
            if (result.ExitCode != 0)
            {
                var diag = result.Stdout;
                if (result.Stderr.Length > 0)
                    diag = (diag.Length > 0 ? diag + "\n" : "") + result.Stderr;
                throw new BuildUnitFailureException($"go build failed (exit {result.ExitCode}):\n{diag}");
            }
            if (!File.Exists(binaryPath))
                throw new BuildUnitFailureException(
                    $"go reported success but produced no {binaryName} for {goos}/{goarch}.");

            var content = await File.ReadAllBytesAsync(binaryPath, cancellationToken);
            return BuildArtifact.Of(
                UnitId,
                artifactId: Guid.NewGuid(),
                @params,
                content,
                contentType: "application/octet-stream",
                builtAt: DateTimeOffset.UtcNow);
        }
        finally
        {
            try { Directory.Delete(workDir, recursive: true); }
            catch { /* best-effort; temp dir is disposable */ }
        }
    }

    // Maps the contract's os/arch pairs onto Go's GOOS/GOARCH. The Go
    // toolchain crosses everything it maps natively (no sysroot, no cross
    // linker -- cgo is off), so the set is the toolchain's own breadth
    // minus the legs this unit does not carry: android belongs to the
    // Rust carrier. Apple joined when the e2e matrix named it: darwin
    // crosses from any host like every other GOOS.
    public static (string Goos, string Goarch) MapTarget(TargetProfile target)
    {
        var os = target.OperatingSystem.Trim().ToLowerInvariant();
        var arch = target.Architecture.Trim().ToLowerInvariant();
        var goarch = arch switch
        {
            "amd64" or "x64" or "x86_64" => "amd64",
            "arm64" or "aarch64" => "arm64",
            "arm" or "armv7" => "arm",
            "x86" or "386" => "386",
            _ => "",
        };
        return (os, goarch) switch
        {
            ("linux", "amd64" or "arm64" or "arm" or "386") => ("linux", goarch),
            ("windows" or "win", "amd64" or "arm64" or "386") => ("windows", goarch),
            ("osx" or "darwin" or "macos", "amd64" or "arm64") => ("darwin", goarch),
            ("osx" or "darwin" or "macos", _) => throw new InvalidOperationException(
                "The Go build unit carries Apple at amd64/arm64 only."),
            ("android", _) => throw new InvalidOperationException(
                "The android carrier is the Rust unit's leg; build android through it."),
            _ => throw new InvalidOperationException(
                $"Unsupported target '{target.OperatingSystem}/{target.Architecture}' for the Go build unit "
                + "(supported: linux amd64/arm64/arm/x86, windows amd64/arm64/x86, macos amd64/arm64)."),
        };
    }

    /// <summary>
    /// Removes work directories earlier builds left behind -- the crash or
    /// host-loss shapes the per-build cleanup cannot cover. Same shape and
    /// threshold discipline as the Rust unit's sweep.
    /// </summary>
    public static void SweepAbandonedWorkDirectories()
    {
        var threshold = DateTimeOffset.UtcNow - TimeSpan.FromHours(1);
        try
        {
            var root = new DirectoryInfo(Path.GetTempPath());
            foreach (var dir in root.EnumerateDirectories("rod-go-build-*"))
            {
                try
                {
                    if (dir.LastWriteTimeUtc < threshold)
                        dir.Delete(recursive: true);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    // Recursively copies the module: go.mod, go.sum, the sources, and the
    // vendor tree (the hermetic dependency set -- without it the build
    // needs the network). Nothing is skipped; Go has no build-output
    // directory inside the tree.
    private static void CopyTree(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var entry in Directory.EnumerateFileSystemEntries(source))
        {
            var to = Path.Combine(destination, Path.GetFileName(entry));
            if (Directory.Exists(entry))
                CopyTree(entry, to);
            else
                File.Copy(entry, to, overwrite: true);
        }
    }

    private static (bool Found, string FirstLine) ProbeVersion(string binary, params string[] arguments)
    {
        try
        {
            var start = new ProcessStartInfo
            {
                FileName = binary,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            foreach (var argument in arguments)
                start.ArgumentList.Add(argument);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            using var process = Process.Start(start);
            if (process is null)
                return (false, "");
            var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
            try
            {
                process.WaitForExitAsync(timeout.Token).GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return (false, "");
            }
            if (process.ExitCode != 0)
                return (false, "");
            return (true, (output.IsCompletedSuccessfully ? output.Result : "").Split('\n', 2)[0].Trim());
        }
        catch
        {
            return (false, "");
        }
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunAsync(
        ProcessStartInfo start, CancellationToken cancellationToken)
    {
        using var process = new Process { StartInfo = start };
        if (!process.Start())
            throw new BuildUnitFailureException($"Failed to start go ('{start.FileName}').");
        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (ProcessTimeout != Timeout.InfiniteTimeSpan)
            bounded.CancelAfter(ProcessTimeout);
        try
        {
            await process.WaitForExitAsync(bounded.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new BuildUnitFailureException(
                $"'{start.FileName}' did not finish within {ProcessTimeout.TotalMinutes:0} minutes; "
                + "the process tree was killed. Set ROD_BUILD_TIMEOUT_MINUTES on a slow build host.");
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw;
        }
        return (process.ExitCode, await stdout, await stderr);
    }

    private static string ResolveDefaultGoSourceDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "implant", "go"))
                && Directory.Exists(Path.Combine(dir.FullName, "src", "teamserver")))
                return Path.Combine(dir.FullName, "src", "implant", "go");
            dir = dir.Parent!;
        }
        return Path.Combine("..", "..", "..", "..", "..", "src", "implant", "go");
    }
}
