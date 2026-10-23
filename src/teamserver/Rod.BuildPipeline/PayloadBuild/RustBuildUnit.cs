using System.Diagnostics;
using Rod.CoreState.Implants;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// The Rust build unit: drives cargo against the Rust reference implant tree
/// through the same build contract the .NET unit serves (architecture.md
/// Sec 6, Sec 12.2). The unit copies the tree into a per-build staging dir,
/// overwrites the checked-in baked-profile stub with the per-artifact profile
/// (the same base64url JSON the .NET unit bakes, the language-neutral wire
/// contract), and compiles a release binary for the requested target
/// triple. Rust is always native code: the executable formats are synonyms
/// here (the size posture lives in the crate's release profile -- opt-level,
/// LTO, strip); android targets deploy through the carrier library ('so')
/// or its packaged APK ('apk'), and the remaining shared-library and
/// shellcode spellings stay contract slots. Loader-tier requests compile
/// the no_std crate beside the implant instead, baked with fetch constants
/// rather than a contact profile.
/// </summary>
/// <remarks>
/// The transport and handler trims the .NET unit applies have Rust
/// equivalents ahead: transport selection and verb trimming will ride cargo
/// features (compile only the contact clients and handlers the bake dials),
/// and the Windows-sensitive verbs already self-gate on <c>cfg(windows)</c>
/// so a Linux build compiles none of them.
///
/// Build failures throw <see cref="BuildUnitFailureException"/> (a
/// server-side fault: the toolchain, the source tree, or the host is wrong)
/// while contract refusals -- retired classes and formats, unsupported
/// target triples -- throw <see cref="InvalidOperationException"/> (the
/// request is wrong). Set <c>ROD_RUST_TARGET_DIR</c> to point builds at a
/// shared, persistent cargo target dir and reuse dependency compilation
/// across builds.
/// </remarks>
public sealed class RustBuildUnit : IBuildUnit, IBuildUnitEnvironment
{
    // The live knob holder (the settings page's build section); null keeps
    // the environment-variable boot shape for direct constructions.
    private readonly IBuildRuntimeSettings? _settings;

    // Every target the contract can map (MapTriple), with the C linker its
    // platform pieces need on the build host: the musl triples get the
    // cross names the build itself sets as CC_*/AR_* (ring's primitives),
    // the Windows GNU pair the mingw-w64 drivers cargo invokes by default,
    // and the android pair the NDK clang wrapper named per triple -- which
    // never sits on PATH, so its readiness resolves through the NDK
    // (LocateNdk) instead of the PATH scan. A target without its row here
    // still builds; the table exists so the environment report can name
    // what is missing per target.
    private static readonly (string Triple, string Os, string Arch, string Linker)[] CrossTargets =
    [
        ("x86_64-unknown-linux-musl", "linux", "amd64", "musl-gcc"),
        ("aarch64-unknown-linux-musl", "linux", "arm64", "aarch64-linux-musl-gcc"),
        ("armv7-unknown-linux-musleabihf", "linux", "arm", "armv7-linux-musleabihf-gcc"),
        ("i686-unknown-linux-musl", "linux", "x86", "musl-gcc"),
        ("x86_64-pc-windows-gnu", "windows", "amd64", "x86_64-w64-mingw32-gcc"),
        ("i686-pc-windows-gnu", "windows", "x86", "i686-w64-mingw32-gcc"),
        ("aarch64-linux-android", "android", "arm64", "aarch64-linux-android24-clang"),
        ("x86_64-linux-android", "android", "amd64", "x86_64-linux-android24-clang"),
    ];

    // The bionic floor the carrier leg bakes: API 24 (Android 7.0) covers
    // the device floor an engagement names, and the NDK clang wrappers
    // carry it in their names. The carrier manifest's minSdkVersion agrees.
    private const int AndroidApiLevel = 24;

    // The ceiling every spawned toolchain process runs under. A hung cargo
    // (a network fetch stalled mid-restore is the plausible shape) must not
    // pin the build queue forever: past the ceiling the tree is killed and
    // the build fails like any other toolchain fault. An environment
    // variable overrides the default for slow build hosts; zero disables.
    private static readonly TimeSpan ProcessTimeout = ResolveProcessTimeout();

    private static TimeSpan ResolveProcessTimeout()
    {
        var raw = Environment.GetEnvironmentVariable("ROD_BUILD_TIMEOUT_MINUTES");
        if (!int.TryParse(raw, out var minutes))
            return TimeSpan.FromMinutes(20);
        return minutes <= 0 ? Timeout.InfiniteTimeSpan : TimeSpan.FromMinutes(minutes);
    }

    private readonly string _rustSourceDir;
    private readonly string _cargoBinary;
    private readonly string? _sharedTargetDir;

    public Language Language => Language.Rust;

    public RustBuildUnit(
        string? rustSourceDir = null,
        string? cargoBinary = null,
        IBuildRuntimeSettings? settings = null)
    {
        _rustSourceDir = string.IsNullOrWhiteSpace(rustSourceDir)
            ? ResolveDefaultRustSourceDir()
            : rustSourceDir;
        _cargoBinary = cargoBinary ?? "cargo";
        _settings = settings;
        // The environment variable is the boot default a service unit sets;
        // a live setting (persisted operator change) outranks it per build.
        _sharedTargetDir = NonEmptyOrNull(Environment.GetEnvironmentVariable("ROD_RUST_TARGET_DIR"));
    }

    // The cache the next build uses: the live setting when one is held,
    // else the environment boot default; null stays hermetic.
    private string? SharedTargetDir => _settings?.RustTargetDir ?? _sharedTargetDir;

    private static string? NonEmptyOrNull(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value;

    /// <summary>
    /// Probes the host: cargo and rustc by running their version queries,
    /// the source and proto trees by existence, the installed std set by
    /// walking rustc's sysroot, and each cross linker by a PATH scan. The
    /// findings name the fix for everything not "ok" -- a build that fails
    /// inside a missing toolchain wastes minutes saying less.
    /// </summary>
    public BuildUnitEnvironmentReport ReportEnvironment()
    {
        var findings = new List<BuildEnvironmentFinding>
        {
            new("ok", "source tree", $"Rust implant crate at '{_rustSourceDir}'"),
        };
        var sourceMissing = !Directory.Exists(_rustSourceDir);
        if (sourceMissing)
            findings[0] = new("missing", "source tree",
                $"Rust implant source tree not found at '{_rustSourceDir}' -- set Build:RustSourceDirectory to the crate's location");

        var proto = LocateProtoDir();
        findings.Add(proto is null
            ? new("missing", "proto tree",
                "The teamserver proto tree (src/teamserver/Rod.Protocol/protos) was not found beside the crate "
                + "-- the wire contract's source is part of the build, not the binary")
            : new("ok", "proto tree", $"rod.proto located at '{proto}'"));

        var cargo = Probe.Run(_cargoBinary, "--version");
        findings.Add(cargo.Found
            ? new("ok", "cargo", cargo.FirstLine)
            : new("missing", "cargo",
                $"'{_cargoBinary}' was not found on PATH -- every build fails until the Rust toolchain is installed"));

        // The installed std set reads off rustc's sysroot (one directory per
        // target, host included), which works for rustup-managed and distro
        // toolchains alike; rustup's own list is a rustup-only view.
        var sysroot = Probe.Run("rustc", "--print", "sysroot");
        var stdRoot = sysroot.Found
            ? Path.Combine(sysroot.FirstLine.Trim(), "lib", "rustlib")
            : null;
        var installed = stdRoot is not null && Directory.Exists(stdRoot)
            ? Directory.EnumerateDirectories(stdRoot)
                .Select(Path.GetFileName)
                .Where(name => name is not null && !name.Equals("rustlib-src", StringComparison.Ordinal))
                .ToHashSet(StringComparer.Ordinal)!
            : [];
        findings.Add(sysroot.Found
            ? new("ok", "rustc", $"std for {installed.Count} target(s) under '{stdRoot}'")
            : new("warn", "rustc",
                "rustc was not found on PATH -- target readiness below is unverified (cargo may still be a distro install that names it differently)"));

        var targets = new List<BuildTargetReadiness>();
        var anyTargetMissing = false;
        foreach (var (triple, os, arch, linker) in CrossTargets)
        {
            var std = installed.Contains(triple);
            // The android linker lives inside the NDK, never on PATH -- the
            // row's linker name is the wrapper file name, resolved through
            // the NDK location chain.
            var hasLinker = triple.EndsWith("-android", StringComparison.Ordinal)
                ? ResolveNdkClang(triple) is not null
                : FindOnPath(linker);
            if (!std || !hasLinker)
                anyTargetMissing = true;
            targets.Add(new BuildTargetReadiness(triple, $"{os}/{arch}", std, hasLinker, linker));
        }

        // The android chain's host pieces beyond rustup: the NDK names the
        // cross itself, and the apk format rides the SDK's build-tools plus
        // a JDK (apksigner and keytool are jars; the carrier carries no
        // Java of its own).
        var ndk = LocateNdk();
        findings.Add(ndk is { } ndkRoot
            ? new("ok", "android ndk", $"NDK {Path.GetFileName(ndkRoot)} at '{ndkRoot}'")
            : new("missing", "android ndk",
                "no NDK found -- set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) to an unpacked NDK, or install one under "
                + "$ANDROID_HOME/ndk; every android build (formats 'so' and 'apk') fails without it"));
        var apkChain = LocateBuildTools() is not null && LocatePlatformJar() is not null && LocateJava() is not null;
        findings.Add(apkChain
            ? new("ok", "apk packaging", "aapt2/apksigner resolved through ANDROID_HOME build-tools with a JDK on the chain")
            : new("warn", "apk packaging",
                "the 'apk' format needs the SDK's build-tools and a platform jar (ANDROID_HOME) plus a JDK for "
                + "apksigner/keytool (JAVA_HOME or PATH) -- absent those, android builds still deliver the bare 'so'"));

        findings.Add(SharedTargetDir is null
            ? new("warn", "build cache",
                "no shared cargo target dir -- builds are hermetic, so every cold cross-compile pays the full dependency build; "
                + "set the build cache on the Settings page (or the ROD_RUST_TARGET_DIR variable at boot) to share a warm cache "
                + "(concurrent builds queue on cargo's lock)")
            : new("ok", "build cache",
                $"shared cargo target dir '{SharedTargetDir}' (adjustable on the Settings page)"));

        var unavailable = sourceMissing || proto is null || !cargo.Found;
        var status = unavailable ? "unavailable" : anyTargetMissing ? "partial" : "ready";
        return new BuildUnitEnvironmentReport(Language.ToString(), status, findings, targets);
    }

    // The proto tree's location, without the build's copying: the same
    // walk-up ResolveEndpointAsync-style search CopyProtoTree performs,
    // factored so both the build and the environment report agree on where
    // it should be.
    private static string? LocateProtoDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var protoDir = Path.Combine(dir.FullName, "src", "teamserver", "Rod.Protocol", "protos");
            if (Directory.Exists(protoDir))
                return protoDir;
            dir = dir.Parent!;
        }
        return null;
    }

    // A PATH scan for an executable by name: presence-level only (an
    // unset execute bit still reads present), the bar a diagnostics page
    // needs -- the build itself remains the final judge.
    private static bool FindOnPath(string name)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(path))
            return false;
        foreach (var dir in path.Split(Path.PathSeparator))
        {
            if (dir.Length == 0)
                continue;
            try
            {
                if (File.Exists(Path.Combine(dir, name)))
                    return true;
            }
            catch
            {
                // An unreadable PATH entry is not a verdict.
            }
        }
        return false;
    }

    // A bounded one-shot process run for version/sysroot queries: found
    // means it started and exited zero, and the first line carries the
    // answer the report shows.
    private static class Probe
    {
        public static (bool Found, string FirstLine) Run(string binary, params string[] arguments)
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
                var first = (output.IsCompletedSuccessfully ? output.Result : "")
                    .Split('\n', 2)[0].Trim();
                return (true, first);
            }
            catch
            {
                // A probe never throws: not-found is an answer, not a fault.
                return (false, "");
            }
        }
    }

    public async Task<BuildArtifact> BuildAsync(BuildParams @params, CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(_rustSourceDir))
            throw new BuildUnitFailureException($"Rust implant source tree not found at '{_rustSourceDir}'.");

        var triple = MapTriple(@params.Target);

        // The format axis over the target: an android target deploys
        // through the carrier library or its package, and every other
        // target refuses them -- one shape per deployment story.
        if (triple.EndsWith("-android", StringComparison.Ordinal))
        {
            if (@params.Format is not (ArtifactFormat.SharedObject or ArtifactFormat.Apk))
                throw new InvalidOperationException(
                    "An android target deploys through the carrier library or its package; build format 'so' or 'apk'.");
        }
        else if (@params.Format is ArtifactFormat.Dll
            or ArtifactFormat.SharedObject
            or ArtifactFormat.Shellcode
            or ArtifactFormat.Apk)
        {
            throw new InvalidOperationException(
                @params.Format == ArtifactFormat.Apk
                    ? "The 'apk' format is the android carrier package; build an android target for it."
                    : $"The '{ArtifactFormats.Name(@params.Format)}' format is a contract slot the in-tree Rust unit does not produce on this target; build 'exe' or 'aot'.");
        }

        var workDir = Path.Combine(Path.GetTempPath(), "rod-rust-build-" + Guid.NewGuid().ToString("N"));
        // The staging copy mirrors the crate's real repo layout: build.rs
        // references the teamserver proto at ../../teamserver/... relative to
        // the crate dir, so the copy sits at <work>/src/implant/rust with the
        // proto at <work>/src/teamserver/Rod.Protocol/protos -- the same
        // relative dance the .NET unit performs for its csproj's proto
        // reference.
        var stagingDir = Path.Combine(workDir, "src", "implant", "rust");
        // Hermetic by default: a per-build target dir under the disposable
        // work dir. ROD_RUST_TARGET_DIR opts a deployment into a shared,
        // persistent dir instead: every registry dependency's compiled
        // artifacts are reused across builds (only the implant crate itself
        // recompiles, since its staging path is per-build), which turns a
        // cold full cross-compile into a one-time cost. Concurrent builds
        // through a shared dir queue on cargo's own target-dir lock -- they
        // wait, not fail.
        var targetDir = SharedTargetDir ?? Path.Combine(workDir, "target");
        try
        {
            CopyTree(_rustSourceDir, stagingDir);
            CopyProtoTree(_rustSourceDir, workDir);

            // The loader tier branches before the implant bake: its artifact
            // is the no_std crate beside the implant, baked with fetch
            // constants rather than a contact profile.
            if (@params.Kind == PayloadKind.Loader)
                return await BuildLoaderAsync(@params, triple, stagingDir, targetDir, cancellationToken);

            // The bake: the same base64url profile JSON every unit emits --
            // one language-neutral contract, decoded identically by every
            // implant.
            var baked = ProfileBake.Render(@params);

            // Overwrite the checked-in baked.rs stub with the per-build
            // profile, the same mechanism the .NET trees' BakedProfile uses.
            var bakedPath = Path.Combine(stagingDir, "src", "baked.rs");
            await File.WriteAllTextAsync(
                bakedPath,
                "// <auto-generated> Generated by Rod.RustBuildUnit at build time.\n"
                    + "// The per-artifact profile, baked in at generation (architecture.md Sec 5.1),\n"
                    + "// base64url JSON with the same keys every build unit emits.\n"
                    + "pub const PROFILE: &str = \"" + baked + "\";\n",
                cancellationToken);

            // The android branch: the carrier crate beside the implant (the
            // loader's sibling) is the cdylib the package's
            // android.app.NativeActivity loads, and the bake above already
            // sits in the implant crate's src/baked.rs, read through the
            // carrier's path dependency.
            if (triple.EndsWith("-android", StringComparison.Ordinal))
                return await BuildCarrierAsync(@params, triple, stagingDir, targetDir, cancellationToken);

            // A per-build target dir keeps builds hermetic (the shared cargo
            // home and registry cache stay warm across builds). The
            // wireguard front's build enables the crate's optional transport
            // behind its cargo feature -- the compile-time half of the
            // transport-enable set (Sec 15.3, ADR-004 as amended), the
            // listener the bake dials being the other.
            var arguments = new List<string> { "build", "--release", "--target", triple };
            if (@params.WireGuardPrivateKey is not null)
            {
                arguments.Add("--features");
                arguments.Add("wireguard");
            }
            var cargo = new ProcessStartInfo
            {
                FileName = _cargoBinary,
                WorkingDirectory = stagingDir,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };
            foreach (var argument in arguments)
                cargo.ArgumentList.Add(argument);
            cargo.Environment["CARGO_TARGET_DIR"] = targetDir;
            cargo.Environment["CARGO_NET_GIT_FETCH_WITH_CLI"] = "true";
            // The static (musl) triples: rust ships their std, and the C
            // bits -- ring's primitives -- need a musl cross compiler the
            // build host names per target. A host without the cross fails
            // inside cargo with the toolchain's own error, loudly. The
            // cc-cased stem keeps the triple's own case (the cc crate
            // reads CC_x86_64_unknown_linux_musl), and the archiver stays
            // unset on purpose: the common musl cross shapes ship a gcc
            // wrapper without a prefixed ar, and the cc crate's own
            // fallback (plain ar) archives the freestanding objects fine.
            if (triple.EndsWith("-musl", StringComparison.Ordinal))
            {
                var ccStem = triple.Replace('-', '_');
                var prefix = triple.Split('-')[0] switch
                {
                    "x86_64" => "musl-gcc",
                    "aarch64" => "aarch64-linux-musl-gcc",
                    "armv7" => "armv7-linux-musleabihf-gcc",
                    _ => "musl-gcc",
                };
                cargo.Environment[$"CC_{ccStem}"] = prefix;
            }
            var result = await RunAsync(cargo, cancellationToken);
            if (result.ExitCode != 0)
            {
                var diag = result.Stdout;
                if (result.Stderr.Length > 0)
                    diag = (diag.Length > 0 ? diag + "\n" : "") + result.Stderr;
                throw new BuildUnitFailureException(
                    $"cargo build failed (exit {result.ExitCode}):\n{diag}");
            }

            // The Windows triples (x86_64-pc-windows-gnu, i686-pc-windows-gnu)
            // begin with the arch, not the OS -- a StartsWith("windows") check
            // names the wrong file and a successful build reads as a missing
            // artifact.
            var binaryName = triple.Contains("-windows-", StringComparison.Ordinal)
                ? "rod-implant.exe"
                : "rod-implant";
            var binaryPath = Path.Combine(targetDir, triple, "release", binaryName);
            if (!File.Exists(binaryPath))
                throw new BuildUnitFailureException(
                    $"cargo reported success but produced no {binaryName} for {triple}.");

            var content = await File.ReadAllBytesAsync(binaryPath, cancellationToken);
            return BuildArtifact.Of(
                Language,
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

    // The loader tier's build: bakes the fetch constants into the no_std
    // crate beside the implant and compiles rod-loader for the target. The
    // artifact id is minted here, before cargo runs, because the fetch path
    // the loader bakes names it -- the recorded payload id and the baked
    // route must be the same guid by construction. The seal key pair rides
    // the params exactly as the envelope pair does on an implant build (the
    // endpoint minted it unconditionally for this kind); a request that
    // reaches this depth without one is a contract violation, refused
    // rather than baked as a loader that can never open its delivery.
    private async Task<BuildArtifact> BuildLoaderAsync(
        BuildParams @params,
        string triple,
        string stagingDir,
        string targetDir,
        CancellationToken cancellationToken)
    {
        // The loader crate's syscall stubs (its sys module) exist for x86_64
        // and aarch64 only, so any other linux triple would fail deep inside
        // cargo with a confusing "mod sys not found" -- refuse it here, the
        // same way MapTriple refuses an arm windows target.
        if (triple is not ("x86_64-unknown-linux-musl" or "aarch64-unknown-linux-musl"))
            throw new InvalidOperationException(
                "The loader is a Linux memfd shape with syscall stubs for amd64 and arm64 only; "
                + "build it against a linux/amd64 or linux/arm64 target.");
        if (@params.TokenSecret is not { } token)
            throw new InvalidOperationException(
                "A loader build bakes a deploy token; the transport layer must mint one.");
        if (@params.EnvelopeKeyId is not { } keyId || @params.EnvelopeKey is not { } key)
            throw new InvalidOperationException(
                "A loader build's delivery seal key must ride the build params (minted beside the token).");
        if (@params.DeliversPayloadId is null)
            throw new InvalidOperationException(
                "A loader build names the stored payload it delivers.");
        var (kind, hostV4, hostV6, hostName, port) = ParseLoaderDial(@params.Transport.Endpoint);

        // The bake: plain consts, the loader crate's whole contract. The
        // dial is a discriminated shape -- literal v4, literal v6, or a
        // name the loader resolves -- and the fetch path names this
        // artifact's own id: the loader payload route serves the delivered
        // payload sealed under the key above.
        var artifactId = Guid.NewGuid();
        var baked =
            "// <auto-generated> Generated by Rod.RustBuildUnit at build time.\n"
            + "// The loader's fetch constants: the dial, the credential, and the\n"
            + "// delivery seal (architecture.md Sec 6, the loader tier).\n"
            + $"pub const HOST_KIND: u8 = {kind};\n"
            + "pub const HOST_V4: [u8; 4] = [" + string.Join(", ", hostV4.Select(b => b.ToString())) + "];\n"
            + "pub const HOST_V6: [u8; 16] = [" + string.Join(", ", hostV6.Select(b => b.ToString())) + "];\n"
            + $"pub const HOST_NAME: &str = \"{hostName}\";\n"
            + "pub const RESOLVER: &str = \"\";\n"
            + $"pub const PORT: u16 = {port};\n"
            + $"pub const PATH: &str = \"/implants/loaders/{artifactId:N}/payload\";\n"
            + $"pub const TOKEN: &str = \"{token}\";\n"
            + "pub const KEY_ID: [u8; 16] = ["
            + string.Join(", ", keyId.ToByteArray().Select(b => b.ToString())) + "];\n"
            + "pub const KEY: [u8; 32] = [" + string.Join(", ", key.Select(b => b.ToString())) + "];\n";
        var loaderDir = Path.Combine(stagingDir, "loader");
        if (!Directory.Exists(loaderDir))
            throw new BuildUnitFailureException(
                $"The loader crate was not found beside the implant at '{loaderDir}'.");
        await File.WriteAllTextAsync(
            Path.Combine(loaderDir, "src", "baked.rs"),
            baked,
            cancellationToken);

        var arguments = new List<string> { "build", "--release", "--target", triple };
        var cargo = new ProcessStartInfo
        {
            FileName = _cargoBinary,
            WorkingDirectory = loaderDir,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        foreach (var argument in arguments)
            cargo.ArgumentList.Add(argument);
        cargo.Environment["CARGO_TARGET_DIR"] = targetDir;
        cargo.Environment["CARGO_NET_GIT_FETCH_WITH_CLI"] = "true";
        // The aarch64 musl link: rustc passes --fix-cortex-a53-843419 to the
        // driver, which the build host's default bfd linker rejects -- the
        // loader is pure Rust with no C bits, so rust-lld from the toolchain
        // itself links it without any cross gcc. The x86_64 musl link needs
        // nothing: the host driver carries every flag that target asks for.
        if (triple == "aarch64-unknown-linux-musl")
        {
            var lld = FindRustLld();
            if (lld is not null)
                cargo.Environment["RUSTFLAGS"] =
                    $"-C linker={lld} -C linker-flavor=ld.lld -C link-self-contained=no -C relocation-model=static";
            else
                throw new BuildUnitFailureException(
                    "The aarch64 loader link needs rust-lld (under the toolchain's lib/rustlib bin); "
                    + "none was found beside rustc.");
        }
        var result = await RunAsync(cargo, cancellationToken);
        if (result.ExitCode != 0)
        {
            var diag = result.Stdout;
            if (result.Stderr.Length > 0)
                diag = (diag.Length > 0 ? diag + "\n" : "") + result.Stderr;
            throw new BuildUnitFailureException(
                $"cargo build failed for the loader (exit {result.ExitCode}):\n{diag}");
        }

        var binaryPath = Path.Combine(targetDir, triple, "release", "rod-loader");
        if (!File.Exists(binaryPath))
            throw new BuildUnitFailureException(
                $"cargo reported success but produced no rod-loader for {triple}.");

        var content = await File.ReadAllBytesAsync(binaryPath, cancellationToken);
        return BuildArtifact.Of(
            Language,
            artifactId,
            @params,
            content,
            contentType: "application/octet-stream",
            builtAt: DateTimeOffset.UtcNow);
    }

    // The android carrier's build: the cdylib crate beside the implant
    // (the same shape the loader tier uses -- an external crate the unit
    // compiles per request), cross-compiled through the NDK's clang
    // wrapper, which serves as the C compiler (ring's primitives), the
    // archiver, and the final library link in one toolchain. The artifact
    // is the bare library for 'so', or the packaged APK for 'apk' -- the
    // package's face is the carrier crate's own checked-in
    // AndroidManifest.xml.
    private async Task<BuildArtifact> BuildCarrierAsync(
        BuildParams @params,
        string triple,
        string stagingDir,
        string targetDir,
        CancellationToken cancellationToken)
    {
        var carrierDir = Path.Combine(stagingDir, "carrier");
        if (!Directory.Exists(carrierDir))
            throw new BuildUnitFailureException(
                $"The carrier crate was not found beside the implant at '{carrierDir}'.");
        var clang = ResolveNdkClang(triple)
            ?? throw new BuildUnitFailureException(
                "The android cross needs the NDK -- set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) to an unpacked NDK, "
                + "or install one under $ANDROID_HOME/ndk; the environment report names the gap.");

        var cargo = new ProcessStartInfo
        {
            FileName = _cargoBinary,
            WorkingDirectory = carrierDir,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        foreach (var argument in new[] { "build", "--release", "--target", triple })
            cargo.ArgumentList.Add(argument);
        // The wireguard bake reaches the carrier through the forwarded
        // feature: the implant core the cdylib links compiles its tunnel
        // carriage only under it.
        if (@params.WireGuardPrivateKey is not null)
        {
            cargo.ArgumentList.Add("--features");
            cargo.ArgumentList.Add("wireguard");
        }
        cargo.Environment["CARGO_TARGET_DIR"] = targetDir;
        cargo.Environment["CARGO_NET_GIT_FETCH_WITH_CLI"] = "true";
        // The NDK toolchain: one clang wrapper serves ring's C, the
        // archive step, and the cdylib link -- the same CC_*/AR_* dance
        // the musl crosses do, plus cargo's own linker override for the
        // final library. The cc-cased stems keep the triple's own case
        // (CC_x86_64_linux_android); only cargo's LINKER key uppercases.
        var ccStem = triple.Replace('-', '_');
        var envStem = ccStem.ToUpperInvariant();
        cargo.Environment[$"CC_{ccStem}"] = clang;
        cargo.Environment[$"AR_{ccStem}"] = NdkSibling(clang, "llvm-ar");
        cargo.Environment[$"CARGO_TARGET_{envStem}_LINKER"] = clang;
        var result = await RunAsync(cargo, cancellationToken);
        if (result.ExitCode != 0)
        {
            var diag = result.Stdout;
            if (result.Stderr.Length > 0)
                diag = (diag.Length > 0 ? diag + "\n" : "") + result.Stderr;
            throw new BuildUnitFailureException(
                $"cargo build failed for the carrier (exit {result.ExitCode}):\n{diag}");
        }

        var soPath = Path.Combine(targetDir, triple, "release", "librod_carrier.so");
        if (!File.Exists(soPath))
            throw new BuildUnitFailureException(
                $"cargo reported success but produced no librod_carrier.so for {triple}.");

        if (@params.Format == ArtifactFormat.SharedObject)
        {
            var so = await File.ReadAllBytesAsync(soPath, cancellationToken);
            return BuildArtifact.Of(
                Language,
                Guid.NewGuid(),
                @params,
                so,
                contentType: "application/octet-stream",
                builtAt: DateTimeOffset.UtcNow);
        }
        return await PackageApkAsync(@params, triple, soPath, carrierDir, cancellationToken);
    }

    // Assembles the installable package from the carrier: aapt2 links the
    // crate's manifest against the SDK's platform jar (the package carries
    // no dex -- hasCode=false, the framework's own NativeActivity is the
    // whole app), the cdylib rides in at lib/<abi>/ stored uncompressed
    // (extractNativeLibs=false: the loader maps it straight out of the
    // package), zipalign fixes the boundaries including the .so's page
    // alignment, and apksigner signs. The signing key is the ecosystem's
    // debug keystore convention (~/.android/debug.keystore, generated on
    // first use): the lab shape an engagement replaces with its own key
    // for a deliverable that must survive reinstalls (the runbook owns
    // that step).
    private async Task<BuildArtifact> PackageApkAsync(
        BuildParams @params,
        string triple,
        string soPath,
        string carrierDir,
        CancellationToken cancellationToken)
    {
        var buildTools = LocateBuildTools()
            ?? throw new BuildUnitFailureException(
                "The 'apk' format needs the SDK's build-tools (aapt2/zipalign/apksigner) -- set ANDROID_HOME to the SDK root.");
        var platformJar = LocatePlatformJar()
            ?? throw new BuildUnitFailureException(
                "The 'apk' format needs an installed platform (ANDROID_HOME/platforms/android-*/android.jar) for the manifest link.");
        var java = LocateJava()
            ?? throw new BuildUnitFailureException(
                "The 'apk' format needs a JDK for apksigner and keytool -- set JAVA_HOME or put java on PATH.");
        var javaHome = JavaHome(java)
            ?? throw new BuildUnitFailureException(
                "The 'apk' format needs JAVA_HOME (or a resolvable java) for the jar-launching packaging scripts.");

        var work = Path.Combine(Path.GetTempPath(), "rod-apk-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        try
        {
            var baseApk = Path.Combine(work, "base.apk");
            var aligned = Path.Combine(work, "aligned.apk");
            var signed = Path.Combine(work, "signed.apk");

            var link = Step(Path.Combine(buildTools, "aapt2"), work);
            link.ArgumentList.Add("link");
            link.ArgumentList.Add("--manifest");
            link.ArgumentList.Add(Path.Combine(carrierDir, "AndroidManifest.xml"));
            link.ArgumentList.Add("-I");
            link.ArgumentList.Add(platformJar);
            link.ArgumentList.Add("-o");
            link.ArgumentList.Add(baseApk);
            await RunStepAsync(link, "aapt2 link", cancellationToken);

            // The library rides at lib/<abi>/librod_carrier.so -- the path
            // the package manager maps into the app's linker namespace,
            // named by android ABI, not by triple. Stored, not deflated:
            // an uncompressed page-aligned .so is what extractNativeLibs=
            // false loads directly.
            var abi = triple.StartsWith("aarch64-", StringComparison.Ordinal) ? "arm64-v8a" : "x86_64";
            using (var archive = System.IO.Compression.ZipFile.Open(baseApk, System.IO.Compression.ZipArchiveMode.Update))
            {
                var entry = archive.CreateEntry($"lib/{abi}/librod_carrier.so", System.IO.Compression.CompressionLevel.NoCompression);
                await using (var target = entry.Open())
                await using (var source = File.OpenRead(soPath))
                    await source.CopyToAsync(target, cancellationToken);
            }

            var align = Step(Path.Combine(buildTools, "zipalign"), work);
            align.ArgumentList.Add("-f");
            align.ArgumentList.Add("-p");
            align.ArgumentList.Add("4");
            align.ArgumentList.Add(baseApk);
            align.ArgumentList.Add(aligned);
            await RunStepAsync(align, "zipalign", cancellationToken);

            var keystore = await EnsureDebugKeystoreAsync(javaHome, cancellationToken);
            var sign = Step(Path.Combine(buildTools, "apksigner"), work);
            sign.Environment["JAVA_HOME"] = javaHome;
            // The apksigner launcher execs bare `java`, PATH-resolved: the
            // JDK the chain resolved rides in front so the script cannot
            // pick a different one (or none).
            sign.Environment["PATH"] =
                Path.Combine(javaHome, "bin") + Path.PathSeparator
                + (Environment.GetEnvironmentVariable("PATH") ?? "");
            sign.ArgumentList.Add("sign");
            sign.ArgumentList.Add("--ks");
            sign.ArgumentList.Add(keystore);
            sign.ArgumentList.Add("--ks-pass");
            sign.ArgumentList.Add("pass:android");
            sign.ArgumentList.Add("--ks-key-alias");
            sign.ArgumentList.Add("androiddebugkey");
            sign.ArgumentList.Add("--key-pass");
            sign.ArgumentList.Add("pass:android");
            sign.ArgumentList.Add("--out");
            sign.ArgumentList.Add(signed);
            sign.ArgumentList.Add(aligned);
            await RunStepAsync(sign, "apksigner sign", cancellationToken);

            var apk = await File.ReadAllBytesAsync(signed, cancellationToken);
            return BuildArtifact.Of(
                Language,
                Guid.NewGuid(),
                @params,
                apk,
                contentType: "application/vnd.android.package-archive",
                builtAt: DateTimeOffset.UtcNow);
        }
        finally
        {
            try { Directory.Delete(work, recursive: true); }
            catch { /* best-effort; temp dir is disposable */ }
        }
    }

    // The debug keystore convention: generated once under ~/.android and
    // reused, so lab builds install over each other. keytool comes from
    // the same JDK the packaging chain rides.
    private static async Task<string> EnsureDebugKeystoreAsync(string javaHome, CancellationToken cancellationToken)
    {
        var profileRoot = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(profileRoot))
            throw new BuildUnitFailureException("No user profile directory for the debug keystore.");
        var keystore = Path.Combine(profileRoot, ".android", "debug.keystore");
        var keystoreDir = Path.GetDirectoryName(keystore)!;
        if (File.Exists(keystore))
            return keystore;
        Directory.CreateDirectory(keystoreDir);

        var keytool = Path.Combine(javaHome, "bin", "keytool");
        var generate = Step(File.Exists(keytool) ? keytool : "keytool", keystoreDir);
        foreach (var argument in new[]
        {
            "-genkeypair",
            "-keystore", keystore,
            "-storepass", "android",
            "-keypass", "android",
            "-alias", "androiddebugkey",
            "-dname", "CN=Android Debug,O=Android,C=US",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
        })
            generate.ArgumentList.Add(argument);
        var result = await RunAsync(generate, cancellationToken);
        if (result.ExitCode != 0)
            throw new BuildUnitFailureException(
                $"keytool could not generate the debug keystore (exit {result.ExitCode}):\n{result.Stderr}");
        return keystore;
    }

    private static ProcessStartInfo Step(string binary, string workingDirectory)
        => new()
        {
            FileName = binary,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };

    private static async Task RunStepAsync(ProcessStartInfo start, string name, CancellationToken cancellationToken)
    {
        var result = await RunAsync(start, cancellationToken);
        if (result.ExitCode != 0)
        {
            var diag = result.Stdout;
            if (result.Stderr.Length > 0)
                diag = (diag.Length > 0 ? diag + "\n" : "") + result.Stderr;
            throw new BuildUnitFailureException($"{name} failed (exit {result.ExitCode}):\n{diag}");
        }
    }

    // --- The android host chain: the NDK cross and the SDK packaging ---

    // The NDK root: an explicit variable names an unpacked NDK directly
    // (ANDROID_NDK_HOME, then ANDROID_NDK_ROOT); otherwise the SDK's own
    // ndk/<version> slot with the highest version. Null when the host
    // carries neither -- the first refusal every android build names.
    public static string? LocateNdk()
    {
        foreach (var variable in new[] { "ANDROID_NDK_HOME", "ANDROID_NDK_ROOT" })
        {
            var named = NonEmptyOrNull(Environment.GetEnvironmentVariable(variable));
            if (named is not null && File.Exists(Path.Combine(named, "source.properties")))
                return named;
        }
        var sdk = LocateAndroidSdk();
        if (sdk is null)
            return null;
        var ndkRoot = Path.Combine(sdk, "ndk");
        if (!Directory.Exists(ndkRoot))
            return null;
        return Directory.EnumerateDirectories(ndkRoot)
            .Where(d => File.Exists(Path.Combine(d, "source.properties")))
            .Select(d => (Dir: d, Version: Version.TryParse(Path.GetFileName(d), out var v) ? v : null))
            .Where(t => t.Version is not null)
            .OrderByDescending(t => t.Version)
            .Select(t => t.Dir)
            .FirstOrDefault();
    }

    // The SDK root (ANDROID_HOME, then ANDROID_SDK_ROOT): the packaging
    // chain's shared home.
    public static string? LocateAndroidSdk()
    {
        foreach (var variable in new[] { "ANDROID_HOME", "ANDROID_SDK_ROOT" })
        {
            var named = NonEmptyOrNull(Environment.GetEnvironmentVariable(variable));
            if (named is not null && Directory.Exists(named))
                return named;
        }
        return null;
    }

    // The NDK's llvm toolchain bin for this build host: prebuilt/ carries
    // one directory per supported host; a Linux host takes the linux one
    // whatever its arch suffix.
    private static string? NdkToolchainBin(string ndkRoot)
    {
        var prebuilt = Path.Combine(ndkRoot, "toolchains", "llvm", "prebuilt");
        if (!Directory.Exists(prebuilt))
            return null;
        var host = Directory.EnumerateDirectories(prebuilt)
            .FirstOrDefault(d => Path.GetFileName(d).StartsWith("linux", StringComparison.Ordinal));
        return host is null ? null : Path.Combine(host, "bin");
    }

    // The per-target clang wrapper with the bionic floor baked into its
    // name -- the one tool the android cross needs. Current NDKs ship the
    // bare name; older ones the .sh spelling; either answers.
    public static string? ResolveNdkClang(string triple)
    {
        var ndk = LocateNdk();
        if (ndk is null)
            return null;
        var bin = NdkToolchainBin(ndk);
        if (bin is null)
            return null;
        var name = $"{triple}{AndroidApiLevel}-clang";
        foreach (var candidate in new[] { name, name + ".sh" })
        {
            var path = Path.Combine(bin, candidate);
            if (File.Exists(path))
                return path;
        }
        return null;
    }

    // A tool beside the resolved clang (llvm-ar, say): the same bin dir.
    private static string NdkSibling(string tool, string name)
        => Path.Combine(Path.GetDirectoryName(tool)!, name);

    // The newest build-tools dir carrying the packaging trio.
    public static string? LocateBuildTools()
    {
        var root = SdkDir("build-tools");
        if (root is null)
            return null;
        return Directory.EnumerateDirectories(root)
            .Where(d => File.Exists(Path.Combine(d, "aapt2"))
                && File.Exists(Path.Combine(d, "zipalign"))
                && File.Exists(Path.Combine(d, "apksigner")))
            .OrderByDescending(d => Version.TryParse(Path.GetFileName(d), out var v) ? v : new Version(0, 0))
            .FirstOrDefault();
    }

    // The newest installed platform's android.jar -- the compilation
    // target of the manifest link.
    public static string? LocatePlatformJar()
    {
        var root = SdkDir("platforms");
        if (root is null)
            return null;
        return Directory.EnumerateDirectories(root)
            .Where(d => File.Exists(Path.Combine(d, "android.jar")))
            .OrderByDescending(d => Version.TryParse(
                Path.GetFileName(d).Replace("android-", "", StringComparison.Ordinal), out var v) ? v : new Version(0, 0))
            .Select(d => Path.Combine(d, "android.jar"))
            .FirstOrDefault();
    }

    // A usable java binary: JAVA_HOME's own first, else PATH -- apksigner
    // and keytool ride it.
    public static string? LocateJava()
    {
        var home = NonEmptyOrNull(Environment.GetEnvironmentVariable("JAVA_HOME"));
        if (home is not null && File.Exists(Path.Combine(home, "bin", "java")))
            return Path.Combine(home, "bin", "java");
        return FindOnPath("java") ? "java" : null;
    }

    // JAVA_HOME for the jar-launching packaging scripts: the variable when
    // set, else derived from a resolved java binary.
    private static string? JavaHome(string java)
    {
        var declared = NonEmptyOrNull(Environment.GetEnvironmentVariable("JAVA_HOME"));
        if (declared is not null)
            return declared;
        try
        {
            var derived = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(java)));
            return derived is not null && File.Exists(Path.Combine(derived, "bin", "java"))
                ? derived
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? SdkDir(string name)
    {
        var sdk = LocateAndroidSdk();
        if (sdk is null)
            return null;
        var root = Path.Combine(sdk, name);
        return Directory.Exists(root) ? root : null;
    }

    // Whether a cross target is actually buildable on this host: the
    // target's std under rustc's sysroot and its C linker on PATH. Tests
    // that drive real cross builds gate on this rather than the whole-
    // report status -- a host can carry cargo and the source tree (the
    // report's "unavailable" line) and still lack one target's std, which
    // is a skip, not a failure (the environment report names the gap).
    public bool CrossTargetReady(string triple)
    {
        var sysroot = Probe.Run("rustc", "--print", "sysroot");
        if (!sysroot.Found)
            return false;
        var stdRoot = Path.Combine(sysroot.FirstLine.Trim(), "lib", "rustlib");
        if (!Directory.Exists(stdRoot)
            || !Directory.Exists(Path.Combine(stdRoot, triple)))
            return false;
        // The android linker resolves through the NDK rather than PATH --
        // the same split the environment report's readiness rows follow.
        if (triple.EndsWith("-android", StringComparison.Ordinal))
            return ResolveNdkClang(triple) is not null;
        var linker = CrossTargets.FirstOrDefault(t => t.Triple == triple).Linker;
        return linker is not null && FindOnPath(linker);
    }

    // rust-lld beside the host toolchain, the aarch64 loader's linker. The
    // file ships with every rustup-managed toolchain; a distro toolchain
    // may carry it elsewhere or not at all, in which case the caller
    // refuses with the fix named.
    private static string? FindRustLld()
    {
        var sysroot = Probe.Run("rustc", "--print", "sysroot");
        if (!sysroot.Found)
            return null;
        var candidate = Path.Combine(
            sysroot.FirstLine.Trim(), "lib", "rustlib", "x86_64-unknown-linux-gnu", "bin", "rust-lld");
        return File.Exists(candidate) ? candidate : null;
    }

    // The loader's baked dial: the authority of a cleartext http URL, split
    // into the discriminated shape the loader bakes -- a literal IPv4, a
    // literal IPv6 (brackets optional, the port outside them), or a name
    // the loader resolves. The parser guarantees the scheme; this read is
    // the unit's own refusal of anything that slipped through (a front
    // repointed between parse and build, say) rather than a bake of a dial
    // the loader cannot parse.
    private static (int Kind, byte[] HostV4, byte[] HostV6, string HostName, int Port) ParseLoaderDial(
        string endpoint)
    {
        var trimmed = endpoint.Trim();
        if (!trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"The loader dials a cleartext http front; '{endpoint}' is not one.");
        var authority = trimmed[7..].Split('/')[0];
        // An IPv6 literal carries its colons in brackets when a port rides
        // along; without a port the whole authority may be the bare
        // literal.
        string host;
        var port = 80;
        if (authority.StartsWith('['))
        {
            var close = authority.IndexOf(']');
            if (close < 0)
                throw new InvalidOperationException(
                    $"The loader dial's bracketed IPv6 is malformed: '{endpoint}'.");
            host = authority[1..close];
            if (authority.Length > close + 1
                && (!int.TryParse(authority[(close + 2)..], out port) || port is < 1 or > 65535))
                throw new InvalidOperationException(
                    $"The loader dial's port must be numeric; '{endpoint}' is not one.");
        }
        else
        {
            var colon = authority.LastIndexOf(':');
            host = colon >= 0 ? authority[..colon] : authority;
            if (colon >= 0 && (!int.TryParse(authority[(colon + 1)..], out port) || port is < 1 or > 65535))
                throw new InvalidOperationException(
                    $"The loader dial's port must be numeric; '{endpoint}' is not one.");
        }
        if (System.Net.IPAddress.TryParse(host, out var parsed))
        {
            if (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                return (0, parsed.GetAddressBytes(), new byte[16], "", port);
            if (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                return (1, new byte[4], parsed.GetAddressBytes(), "", port);
        }
        return (2, new byte[4], new byte[16], host, port);
    }

    // Maps the contract's os/arch pairs onto Rust target triples. Linux is
    // musl everywhere -- the static, runtime-free deployment shape that is
    // the reach implant's whole point (routers, appliances, IoT); measured
    // x86_64: 2.25 MB fully static. Android maps onto the carrier legs:
    // arm64 for devices, amd64 for the emulator the lab proves them on
    // (architecture.md Sec 12.2), the NDK's bionic floor baked into the
    // triple's clang wrapper name. Apple targets need the Apple SDK a
    // Linux build host does not carry, and ARM Windows has no GNU target,
    // so both refuse with the supported set named rather than failing
    // inside cargo with a less fixable error.
    public static string MapTriple(TargetProfile target)
    {
        var os = target.OperatingSystem.Trim().ToLowerInvariant();
        var arch = target.Architecture.Trim().ToLowerInvariant();
        return (os, arch) switch
        {
            ("linux", "amd64" or "x64" or "x86_64") => "x86_64-unknown-linux-musl",
            ("linux", "arm64" or "aarch64") => "aarch64-unknown-linux-musl",
            ("linux", "arm" or "armv7") => "armv7-unknown-linux-musleabihf",
            ("linux", "x86" or "386") => "i686-unknown-linux-musl",
            ("windows" or "win", "amd64" or "x64" or "x86_64") => "x86_64-pc-windows-gnu",
            ("windows" or "win", "x86" or "386") => "i686-pc-windows-gnu",
            ("android", "arm64" or "aarch64") => "aarch64-linux-android",
            ("android", "amd64" or "x64" or "x86_64") => "x86_64-linux-android",
            ("osx" or "darwin" or "macos", _) => throw new InvalidOperationException(
                "The Rust build unit does not cross Apple targets (the link needs the Apple SDK); build on a macOS host."),
            ("windows" or "win", "arm64" or "aarch64") => throw new InvalidOperationException(
                "The Rust build unit has no GNU target for ARM Windows."),
            _ => throw new InvalidOperationException(
                $"Unsupported target '{target.OperatingSystem}/{target.Architecture}' for the Rust build unit " +
                "(supported: linux amd64/arm64/arm/x86, windows amd64/x86, android arm64/amd64)."),
        };
    }

    // Recursively copies the crate, skipping target/ (cargo's build output)
    // so a stale build never leaks in. Cargo.lock rides along: the lock pins
    // the dependency set, keeping per-build compiles reproducible.
    private static void CopyTree(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var entry in Directory.EnumerateFileSystemEntries(source))
        {
            var name = Path.GetFileName(entry);
            if (name is "target")
                continue;
            var to = Path.Combine(destination, name);
            if (Directory.Exists(entry))
                CopyTree(entry, to);
            else
                File.Copy(entry, to, overwrite: true);
        }
    }

    // Copies the teamserver proto tree into the work dir under the same
    // relative path build.rs references it by (../../teamserver/... from the
    // crate dir). The proto is the wire contract's single source of truth;
    // rod.proto has no imports, so the directory holds all it needs.
    private static void CopyProtoTree(string rustSourceDir, string workDir)
    {
        var protoDir = LocateProtoDir();
        if (protoDir is null)
            throw new BuildUnitFailureException(
                "The Rust build needs the teamserver proto tree (src/teamserver/Rod.Protocol/protos) beside the crate; the repo walk-up found none.");
        var to = Path.Combine(workDir, "src", "teamserver", "Rod.Protocol", "protos");
        Directory.CreateDirectory(to);
        foreach (var file in Directory.EnumerateFiles(protoDir))
            File.Copy(file, Path.Combine(to, Path.GetFileName(file)), overwrite: true);
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunAsync(
        ProcessStartInfo start, CancellationToken cancellationToken)
    {
        using var process = new Process { StartInfo = start };
        if (!process.Start())
            throw new BuildUnitFailureException($"Failed to start cargo ('{start.FileName}').");
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
            // The build's own ceiling, not a caller shutdown: the process
            // tree is killed and the build reports a toolchain fault the
            // queue can move past.
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

    /// <summary>
    /// Removes work directories earlier builds left behind -- the crash,
    /// OOM-kill, or host-loss shapes the per-build cleanup in each
    /// <c>finally</c> cannot cover. Only directories idle past the sweep
    /// threshold go: a build in flight keeps writing under its tree, and an
    /// hour of silence is not a live cargo. Best-effort by design; a locked
    /// file is next boot's sweep, not a startup failure.
    /// </summary>
    public static void SweepAbandonedWorkDirectories()
    {
        var threshold = DateTimeOffset.UtcNow - TimeSpan.FromHours(1);
        foreach (var prefix in (string[])["rod-rust-build-", "rod-apk-"])
        {
            try
            {
                var root = new DirectoryInfo(Path.GetTempPath());
                foreach (var dir in root.EnumerateDirectories(prefix + "*"))
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
    }

    private static string ResolveDefaultRustSourceDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "implant", "rust"))
                && Directory.Exists(Path.Combine(dir.FullName, "src", "teamserver")))
                return Path.Combine(dir.FullName, "src", "implant", "rust");
            dir = dir.Parent;
        }
        return Path.Combine("..", "..", "..", "..", "..", "src", "implant", "rust");
    }
}
