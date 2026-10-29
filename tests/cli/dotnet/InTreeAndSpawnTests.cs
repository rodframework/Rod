using Rod.Packaging;

namespace Rod.Cli.Tests;

/// <summary>
/// The in-tree reference modules eat the ecosystem's own dogfood: every
/// manifest under <c>modules/</c> is well-formed against the same loader
/// the template repository path uses. The whole in-tree set now rides the
/// v4 plugin tier (ADR-020), so the shape pins and the publish-chain
/// acceptance live where the plugin shape lives: the pins in
/// <see cref="InTreePluginModuleTests"/> below, the publish chains in
/// the integration suite's marketplace round trips (they need the
/// cargo-built artifact first). The team carries no rod-module.key for
/// the reference modules -- an in-tree module is published by whoever
/// cuts its release, so those tests sign with a generated key, exactly
/// what a release operator does.
/// </summary>
public class InTreeModuleTests
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

    /// <summary>
    /// Every manifest under modules/ that is not an asset module loads
    /// against the shared parser: the discovery the config-listed path
    /// and the coverage lane both ride, pinned here so a malformed
    /// manifest fails a test before it fails an operator's install. The
    /// plugin-entry set the sweep finds must match the pinned theory
    /// table exactly -- a new module rides the shape pin or the suite
    /// names the drift.
    /// </summary>
    [Fact]
    public void EveryInTreeManifest_ParsesClean()
    {
        var pluginEntries = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var directory in Directory.GetDirectories(
                     Path.Combine(RepoRoot(), "modules")).OrderBy(d => d, StringComparer.Ordinal))
        {
            var file = Path.Combine(directory, ManifestToml.FileName);
            if (!File.Exists(file))
                continue;
            var (manifest, errors) = ManifestToml.LoadFile(file);
            Assert.True(errors.Count == 0, $"{directory}: {string.Join("; ", errors)}");
            // The asset trees predate the name-directory agreement (their
            // packages carry a kebab name in a non-kebab directory); every
            // other entry kind must agree with the directory it sits in.
            if (manifest.Entry != ModuleEntryKind.Assets)
                Assert.Equal(Path.GetFileName(directory), manifest.Name);
            if (manifest.Entry == ModuleEntryKind.Plugin)
                pluginEntries.Add(manifest.Name);
        }
        var pinned = new SortedSet<string>(
            InTreePluginModuleTests.Modules.Select(row => (string)row[0]),
            StringComparer.Ordinal);
        Assert.Equal(pinned, pluginEntries);
    }
}

/// <summary>
/// The tree's plugin-tier modules: every in-tree pair rides the v4 plugin
/// package shape (ADR-020) -- hostenum first, then the twelve that
/// followed -- so each manifest is pinned here in the plugin's own
/// shape: the artifact row the package ships, the requirement rows
/// exactly its ABI union, and the target the artifact set covers. The
/// publish chains need the cargo-built artifacts and ride the
/// integration suite's marketplace round trips.
/// </summary>
public class InTreePluginModuleTests
{
    /// <summary>
    /// The plugin packages under modules/: manifest name, the verb its
    /// manifest registers (each carries exactly one), and that verb
    /// row's own version -- the row iterates under its own module-scoped
    /// version, independently of the package version, so the pair is
    /// pinned apart.
    /// </summary>
    public static TheoryData<string, string, string> Modules => new()
    {
        { "hostenum", "recon.hostenum", "1.1.0" },
        { "domainenum", "recon.domainenum", "1.1.0" },
        { "runkeys", "persist.runkeys", "1.0.0" },
        { "services", "persist.services", "1.0.0" },
        { "wmi", "persist.wmi", "1.0.0" },
        { "hijack", "persist.hijack", "1.0.0" },
        { "hives", "collect.hives", "1.0.0" },
        { "dpapi", "collect.dpapi", "1.0.0" },
        { "avoid", "evasion.avoid", "1.0.0" },
        { "browser", "collect.browser", "1.0.0" },
        { "unload", "evasion.unload", "1.1.0" },
        { "lsasecrets", "collect.lsasecrets", "1.0.0" },
        { "credman", "collect.credman", "1.0.0" },
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
    [MemberData(nameof(Modules))]
    public void TheInTreePluginManifest_IsWellFormed(string name, string verbName, string verbVersion)
    {
        var (manifest, errors) = ManifestToml.LoadFile(
            Path.Combine(RepoRoot(), "modules", name, ManifestToml.FileName));
        Assert.Empty(errors);
        Assert.Equal(name, manifest.Name);
        Assert.Equal(ModuleEntryKind.Plugin, manifest.Entry);
        Assert.Equal("Apache-2.0", manifest.License);

        // One artifact per shipped target, and the requirement rows are
        // exactly its ABI union -- the store's static filter, a function
        // of what the package carries.
        var artifact = Assert.Single(manifest.PluginArtifacts);
        Assert.Equal("linux", artifact.Platform);
        Assert.Equal("amd64", artifact.Arch);
        Assert.Equal("exec-v1", artifact.Abi);
        Assert.Equal($"plugin/{name}-linux-amd64", artifact.Path);
        Assert.Equal(["plugin-loader/exec-v1"], manifest.Requires);

        // The targeting rows claim only what the artifact set covers.
        var target = Assert.Single(manifest.Targets);
        Assert.Equal("linux", target.Platform);
        Assert.Equal("amd64", target.Arch);

        // The server half is still the descriptor row, unchanged from the
        // descriptor-only package the tier change packed the artifact
        // beside: same verb, same declaration, its own version.
        var verb = Assert.Single(manifest.Verbs);
        Assert.Equal(verbName, verb.Name);
        Assert.True(verb.IsDescriptor);
        Assert.Equal(verbVersion, verb.Version.ToString());
        Assert.NotEmpty(verb.Techniques!);
        Assert.Equal(verb.Techniques, manifest.Techniques);

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
