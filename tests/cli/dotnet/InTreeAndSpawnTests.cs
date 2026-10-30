using Rod.Packaging;

namespace Rod.Cli.Tests;

/// <summary>
/// The CLI's spawn and scaffold faces. The reference modules left the
/// platform tree for their own repositories (ADR-024), so the manifest
/// dogfooding pins moved with them: the ecosystem's round trips (the
/// integration suite's marketplace tests against the real registry, the
/// module lane's validation of the reference set) hold the manifest-shape
/// acceptance, and what stays here is what lives in this repository --
/// the git-registry mechanics, the spawned binary's contract, and the
/// scaffolds an author starts from.
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
            $"{file} {arguments} failed ({process.StandardError.ReadToEnd()})");
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
