using Rod.Packaging;

namespace Rod.Cli.Tests;

/// <summary>
/// The in-tree reference modules eat the ecosystem's own dogfood: every
/// manifest under <c>modules/</c> is well-formed against the same loader
/// the template repository path uses, and every tree module publishes
/// and installs through the identical chain (Sec 15.1's rule, carried to
/// the manifest layer). The team carries no rod-module.key for the
/// reference modules -- an in-tree module is published by whoever cuts
/// its release, so the tests sign with a generated key, exactly what a
/// release operator does.
/// </summary>
public class InTreeModuleTests
{
    /// <summary>
    /// The server-entry modules under modules/: manifest name plus the
    /// verb its manifest's first row registers (each of these modules
    /// registers exactly one). hostenum is not here: it graduated to the
    /// plugin tier (ADR-020), so its publish chain needs the cargo-built
    /// artifact and lives in the integration suite; its manifest shape is
    /// pinned by <see cref="InTreePluginModuleTests"/> below.
    /// </summary>
    public static TheoryData<string, string> ServerModules => new()
    {
        { "domainenum", "recon.domainenum" },
        { "runkeys", "persist.runkeys" },
        { "services", "persist.services" },
        { "wmi", "persist.wmi" },
        { "hijack", "persist.hijack" },
        { "hives", "collect.hives" },
        { "dpapi", "collect.dpapi" },
        { "avoid", "evasion.avoid" },
        { "browser", "collect.browser" },
        { "unload", "evasion.unload" },
        { "lsasecrets", "collect.lsasecrets" },
        { "credman", "collect.credman" },
    };

    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src"))
                && Directory.Exists(Path.Combine(directory.FullName, "modules")))
                return directory.FullName;
            directory = directory.Parent!;
        }
        throw new InvalidOperationException("could not locate the repo root from the test assembly.");
    }

    [Theory]
    [MemberData(nameof(ServerModules))]
    public void TheInTreeManifest_IsWellFormed(string name, string verbName)
    {
        var (manifest, errors) = ManifestToml.LoadFile(
            Path.Combine(RepoRoot(), "modules", name, ManifestToml.FileName));
        Assert.Empty(errors);
        Assert.Equal(name, manifest.Name);
        Assert.Equal(ModuleEntryKind.Server, manifest.Entry);
        Assert.Equal("Apache-2.0", manifest.License);
        Assert.NotEmpty(manifest.Techniques);
        Assert.NotEmpty(manifest.Targets);
        Assert.NotEmpty(manifest.Package!.Include);

        // The version matrix rides the tree module like any external
        // one: the verb it registers carries its row, and the module's
        // technique roll-up matches the verb rows it declares.
        var verb = Assert.Single(manifest.Verbs);
        Assert.Equal(verbName, verb.Name);
        Assert.Equal(manifest.Version, verb.Version);
        Assert.NotEmpty(verb.Techniques!);

        // The row is the module's whole server-side half (ADR-018): a
        // descriptor row -- the category anchors it, and the schema it
        // declares is one the teamserver's registry gate accepts. This is
        // the drift protection the per-module descriptor tests used to
        // carry, restated at the manifest the declaration now lives in.
        Assert.True(verb.IsDescriptor);
        Assert.NotNull(verb.Category);

        // ADR-017's sweep: every tree pair's execution half is a plugin the
        // hosting implant loads through the module family, so every tree
        // manifest declares the loader requirement -- a future module that
        // forgets the row fails here rather than installing unfiltered.
        Assert.Equal(new[] { "plugin-loader/exec-v1", "plugin-loader/native-v1" }, manifest.Requires);
    }

    [Theory]
    [MemberData(nameof(ServerModules))]
    public void TheInTreeModule_PublishesAndInstallsThroughTheStandardChain(string name, string _)
    {
        using var root = new TempRoot();
        var module = Path.Combine(RepoRoot(), "modules", name);
        var keyDirectory = root["keys"];
        var registry = root["registry"];
        var install = root["install"];

        Directory.CreateDirectory(keyDirectory);
        Rod.Packaging.KeyFiles.Generate(keyDirectory);

        // The tree's module directory carries build output (bin/, obj/);
        // the packaging rules must keep it out of the package, and the
        // dist output lands in the temp root, never in the tree.
        var publish = CliRun.Run("mod", "publish", "--path", module, "--registry", registry,
            "--key", Path.Combine(keyDirectory, Rod.Packaging.KeyFiles.SecretFileName),
            "--out", root["dist"]);
        Assert.True(publish.Code == 0, publish.Error);

        var (manifest, _) = ManifestToml.LoadFile(Path.Combine(module, ManifestToml.FileName));
        var version = manifest.Version.ToString();
        var installed = CliRun.Run("mod", "install", name, "--registry", registry,
            "--dir", install, "--teamserver", "1.0.0");
        Assert.True(installed.Code == 0, installed.Error);

        var landed = Path.Combine(install, "modules", name, version);
        // The module is its manifest (ADR-018): the descriptor rows are the
        // whole package, so the landed tree carries the manifest and no
        // payload at all.
        var landedFiles = Directory.GetFiles(landed);
        Assert.Equal(ManifestToml.FileName, Assert.Single(landedFiles.Select(Path.GetFileName)));
        Assert.False(Directory.Exists(Path.Combine(landed, "bin")));

        var verify = CliRun.Run("mod", "verify", "--dir", install);
        Assert.True(verify.Code == 0, verify.Error);
        Assert.Contains($"PASS {name}@{version}", verify.Output);
    }
}

/// <summary>
/// The tree's plugin-tier module: hostenum is the first in-tree v4
/// plugin package (ADR-020), so its manifest is pinned here in the
/// plugin's own shape -- the artifact row the package ships, the
/// requirement rows exactly its ABI union, and the target the artifact
/// set covers. The publish chain itself needs the cargo-built artifact
/// and rides the integration suite's marketplace end-to-end leg.
/// </summary>
public class InTreePluginModuleTests
{
    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src"))
                && Directory.Exists(Path.Combine(directory.FullName, "modules")))
                return directory.FullName;
            directory = directory.Parent!;
        }
        throw new InvalidOperationException("could not locate the repo root from the test assembly.");
    }

    [Fact]
    public void TheInTreePluginManifest_IsWellFormed()
    {
        var (manifest, errors) = ManifestToml.LoadFile(
            Path.Combine(RepoRoot(), "modules", "hostenum", ManifestToml.FileName));
        Assert.Empty(errors);
        Assert.Equal("hostenum", manifest.Name);
        Assert.Equal(ModuleEntryKind.Plugin, manifest.Entry);

        // One artifact per shipped target, and the requirement rows are
        // exactly its ABI union -- the store's static filter, a function
        // of what the package carries.
        var artifact = Assert.Single(manifest.PluginArtifacts);
        Assert.Equal("linux", artifact.Platform);
        Assert.Equal("amd64", artifact.Arch);
        Assert.Equal("exec-v1", artifact.Abi);
        Assert.Equal("plugin/hostenum-linux-amd64", artifact.Path);
        Assert.Equal(["plugin-loader/exec-v1"], manifest.Requires);

        // The targeting rows claim only what the artifact set covers.
        var target = Assert.Single(manifest.Targets);
        Assert.Equal("linux", target.Platform);
        Assert.Equal("amd64", target.Arch);

        // The server half is still the descriptor row, unchanged from the
        // descriptor-only package: same verb, same declaration.
        var verb = Assert.Single(manifest.Verbs);
        Assert.Equal("recon.hostenum", verb.Name);
        Assert.True(verb.IsDescriptor);
        Assert.Equal("recon", verb.Category);
        Assert.Equal(["T1082"], verb.Techniques);

        // The packaging rules admit the manifest and the artifact
        // directory only; the tree's build script stays out.
        Assert.Equal(["rod-module.toml", "plugin/**"], manifest.Package!.Include);
    }
}

/// <summary>
/// The static git index needs a git client to fetch -- the same dependency
/// Homebrew has. This exercises the URL branch against a local bare
/// repository with the ROD_HOME cache pointed at the temp root, so the
/// test never touches the operator's profile.
/// </summary>
public class GitRegistryTests
{
    [Fact]
    public void AGitRegistry_ClonesSearchesAndCachesUnderRodHome()
    {
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        var registry = root["registry"];
        var bare = root["registry.git"];

        CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        var toml = File.ReadAllText(Path.Combine(module, "rod-module.toml"))
            .Replace("license = \"UNLICENSED\"", "license = \"MIT\"")
            .Replace("version = \"0.1.0\"", "version = \"1.0.0\"");
        File.WriteAllText(Path.Combine(module, "rod-module.toml"), toml);
        Directory.CreateDirectory(Path.Combine(module, "src"));
        File.WriteAllText(Path.Combine(module, "src", "payload.cs"), "payload");
        var publish = CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        Assert.True(publish.Code == 0, publish.Error);

        // Registry-as-repository: commit the index, then a bare clone is a
        // remote registry any operator can point --registry at.
        Run("git", $"-C {registry} init -q", root.Path);
        Run("git", $"-C {registry} add .", root.Path);
        Run("git", $"-C {registry} -c user.name=rod -c user.email=rod@test commit -qm index", root.Path);
        Run("git", $"clone --bare -q {registry} {bare}", root.Path);

        var priorHome = Environment.GetEnvironmentVariable("ROD_HOME");
        Environment.SetEnvironmentVariable("ROD_HOME", root["rod-home"]);
        try
        {
            var search = CliRun.Run("mod", "search", "demo", "--registry", "file://" + bare);
            Assert.True(search.Code == 0, search.Error);
            Assert.Contains("demo-sweep", search.Output);

            Assert.True(Directory.Exists(root["rod-home", "registry-cache"]),
                "the clone must land under ROD_HOME, never the profile default");
        }
        finally
        {
            Environment.SetEnvironmentVariable("ROD_HOME", priorHome);
        }
    }

    private static void Run(string file, string arguments, string workingDirectory)
    {
        var info = new System.Diagnostics.ProcessStartInfo(file, arguments)
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = System.Diagnostics.Process.Start(info)!;
        process.WaitForExit();
        Assert.True(process.ExitCode == 0,
            $"{file} {arguments} failed: {process.StandardError.ReadToEnd()}");
    }
}

/// <summary>
/// The binary itself: the same entry the in-process tests drive, spawned
/// as a real process so argument handling, exit codes, and output are
/// exercised the way an operator's shell sees them.
/// </summary>
public class ProcessSpawnTests
{
    [Fact]
    public void TheRodBinary_ReportsItsVersionAndUsage()
    {
        var rodDll = FindRodDll();
        var version = Spawn(rodDll, "--version");
        Assert.Equal(0, version.code);
        Assert.StartsWith("rod ", version.stdout);

        var usage = Spawn(rodDll, "mod", "help");
        Assert.Equal(0, usage.code);
        Assert.Contains("init", usage.stdout);

        var unknown = Spawn(rodDll, "mod", "nonsense");
        Assert.Equal(RodCli.ExitUsage, unknown.code);
        Assert.Contains("unknown mod verb", unknown.stderr);
    }

    private static string FindRodDll()
    {
        // The test project references the CLI project, so its output
        // directory carries rod.dll with its deps and runtimeconfig.
        var candidate = Path.Combine(AppContext.BaseDirectory, "rod.dll");
        if (File.Exists(candidate))
            return candidate;
        throw new InvalidOperationException("rod.dll did not flow into the test output; check the project reference.");
    }

    private static (int code, string stdout, string stderr) Spawn(string dll, params string[] args)
    {
        var info = new System.Diagnostics.ProcessStartInfo("dotnet", [dll, .. args])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = System.Diagnostics.Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdout, stderr);
    }
}

/// <summary>
/// The assets scaffold: <c>rod mod init --entry assets</c> produces a
/// manifest that already validates (one asset row bound to the scaffold's
/// file), so the content-module contribution threshold is the same one
/// directory, one manifest, one key every other entry kind rides.
/// </summary>
public class AssetScaffoldTests
{
    [Fact]
    public void InitWithEntryAssets_ScaffoldsAValidAssetModule()
    {
        using var root = new TempRoot();
        var module = root["demo-lures"];

        var init = CliRun.Run("mod", "init", "demo-lures", "--entry", "assets", "--path", module);
        Assert.True(init.Code == 0, init.Error);

        var (manifest, errors) = ManifestToml.LoadFile(Path.Combine(module, ManifestToml.FileName));
        Assert.Empty(errors);
        Assert.Equal(ModuleEntryKind.Assets, manifest.Entry);
        var asset = Assert.Single(manifest.Assets);
        Assert.Equal("demo-lures", asset.Name);
        Assert.True(File.Exists(Path.Combine(module, asset.Path)),
            "the scaffold must bind its asset row to a file that exists");
    }
}
