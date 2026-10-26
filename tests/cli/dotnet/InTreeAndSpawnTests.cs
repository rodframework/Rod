using Rod.Cli.Manifest;

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
    /// registers exactly one).
    /// </summary>
    public static TheoryData<string, string> ServerModules => new()
    {
        { "hostenum", "recon.hostenum" },
        { "domainenum", "recon.domainenum" },
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
        Rod.Cli.Signing.KeyFiles.Generate(keyDirectory);

        // The tree's module directory carries build output (bin/, obj/);
        // the packaging rules must keep it out of the package, and the
        // dist output lands in the temp root, never in the tree.
        var publish = CliRun.Run("mod", "publish", "--path", module, "--registry", registry,
            "--key", Path.Combine(keyDirectory, Rod.Cli.Signing.KeyFiles.SecretFileName),
            "--out", root["dist"]);
        Assert.True(publish.Code == 0, publish.Error);

        var (manifest, _) = ManifestToml.LoadFile(Path.Combine(module, ManifestToml.FileName));
        var version = manifest.Version.ToString();
        var installed = CliRun.Run("mod", "install", name, "--registry", registry,
            "--dir", install, "--teamserver", "1.0.0");
        Assert.True(installed.Code == 0, installed.Error);

        var landed = Path.Combine(install, "modules", name, version);
        Assert.NotEmpty(Directory.GetFiles(landed, "*.cs"));
        Assert.False(Directory.Exists(Path.Combine(landed, "bin")));

        var verify = CliRun.Run("mod", "verify", "--dir", install);
        Assert.True(verify.Code == 0, verify.Error);
        Assert.Contains($"PASS {name}@{version}", verify.Output);
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
