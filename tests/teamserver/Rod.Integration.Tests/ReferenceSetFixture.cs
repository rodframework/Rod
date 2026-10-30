using System.Diagnostics;
using Rod.Cli;
using Rod.Packaging;

namespace Rod.Integration.Tests;

/// <summary>
/// The official reference set, installed once per test run: the sixteen
/// modules live in their rod-&lt;kind&gt;-&lt;name&gt; repositories (ADR-024), and
/// this fixture brings them back as consumable trees by walking the
/// production install chain -- the rod CLI installing every entry of the
/// organization's rod-registry into one shared store, digest-verified and
/// key-pinned exactly the way an operator's workstation does. Tests that
/// need a module's tree (a descriptor to config-list, an asset to serve,
/// an artifact to byte-compare) read the store; tests that exercise the
/// console's own install leg point a teamserver at
/// <see cref="MarketplaceRegistry"/> instead.
/// </summary>
/// <remarks>
/// The CLI reads the tap through a shallow clone under the fixture's own
/// temp root (ROD_HOME is pointed there for the fixture's lifetime), and
/// package downloads always follow the URLs the entries carry -- the
/// organization's release assets -- so the fixture needs the network the
/// way any install does. ROD_TEST_REGISTRY overrides the tap (a local
/// checkout directory or any git URL) for forked or doctored runs.
/// </remarks>
public sealed class ReferenceSetFixture : IDisposable
{
    public const string DefaultGitUrl = "https://github.com/rodframework/rod-registry.git";
    public const string DefaultHttpsBase = "https://rodframework.github.io/rod-registry";

    // One name per repository, alphabetical; browser-hook is the manifest
    // name the browserhook tree always carried.
    public static readonly IReadOnlyList<string> Names =
    [
        "avoid", "browser", "browser-hook", "credman", "domainenum", "dpapi",
        "hijack", "hives", "hostenum", "lsasecrets", "lure-templates",
        "procwatch", "runkeys", "services", "unload", "wmi",
    ];

    private readonly string _root;
    private readonly string? _priorRodHome;

    public ReferenceSetFixture()
    {
        _root = Path.Combine(Path.GetTempPath(), "rod-reference-set-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);

        // The CLI's registry cache (ROD_HOME) stays out of the operator's
        // profile: the fixture owns one for the run.
        _priorRodHome = Environment.GetEnvironmentVariable("ROD_HOME");
        Environment.SetEnvironmentVariable("ROD_HOME", Path.Combine(_root, "rod-home"));

        var overrideRegistry = Environment.GetEnvironmentVariable("ROD_TEST_REGISTRY");
        if (string.IsNullOrWhiteSpace(overrideRegistry))
        {
            // The tap clone rides the same intermittence any long-lived
            // network does; retry with backoff so a blip fails no test.
            var clone = Path.Combine(_root, "registry");
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    Run("git", $"clone --depth 1 {DefaultGitUrl} {clone}");
                    break;
                }
                catch (InvalidOperationException) when (attempt < 6)
                {
                    Thread.Sleep(TimeSpan.FromSeconds(10 * attempt));
                }
            }
            Registry = clone;
            MarketplaceRegistry = DefaultHttpsBase;
        }
        else
        {
            Registry = overrideRegistry;
            // A local checkout serves the teamserver's local-dir browsing
            // mode directly; a git URL does not, so the https default
            // stands unless the override is a directory.
            MarketplaceRegistry = Directory.Exists(overrideRegistry) ? overrideRegistry : DefaultHttpsBase;
        }

        Store = Path.Combine(_root, "store");
        foreach (var name in Names)
            InstallWithRetry(name);
    }

    /// <summary>The registry the CLI installs through (a local checkout
    /// of the tap).</summary>
    public string Registry { get; }

    /// <summary>The registry reference a teamserver's Modules:Registry
    /// reads -- the https mirror by default, or the override when it is a
    /// directory.</summary>
    public string MarketplaceRegistry { get; }

    /// <summary>The installed-module store the fixture owns.</summary>
    public string Store { get; }

    /// <summary>The tap's entry file for one module, for index-shape
    /// assertions against the real registry.</summary>
    public string EntryPath(string name)
        => Path.Combine(Registry, "modules", name + ".json");

    /// <summary>The store's installed tree for one module.</summary>
    public string ModuleDirectory(string name)
        => Directory.GetDirectories(Path.Combine(Store, "modules", name))
            .OrderByDescending(path => path, StringComparer.Ordinal)
            .Single();

    /// <summary>The installed trees whose entry kind is not assets -- the
    /// set a Capabilities:DescriptorModules list names.</summary>
    public IReadOnlyList<string> DescriptorDirectories()
    {
        var directories = new List<string>();
        foreach (var name in Names)
        {
            var directory = ModuleDirectory(name);
            var (manifest, _) = ManifestToml.LoadFile(
                Path.Combine(directory, ManifestToml.FileName));
            if (manifest!.Entry != ModuleEntryKind.Assets)
                directories.Add(directory);
        }
        return directories;
    }

    private void InstallWithRetry(string name)
    {
        Exception? last = null;
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var output = new StringWriter();
            var error = new StringWriter();
            var code = RodCli.RunAsync(
                ["mod", "install", name, "--registry", Registry, "--dir", Store],
                output, error).GetAwaiter().GetResult();
            if (code == RodCli.ExitOk)
                return;
            last = new InvalidOperationException($"rod mod install {name} failed:\n{error}");
            Thread.Sleep(TimeSpan.FromSeconds(5 * attempt));
        }
        throw last!;
    }

    private void Run(string file, string arguments)
    {
        var info = new ProcessStartInfo(file, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(info)!;
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"{file} failed ({process.ExitCode}): {stderr.Trim()}");
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("ROD_HOME", _priorRodHome);
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (UnauthorizedAccessException)
        {
            // A test host may still be letting go of store files; the temp
            // directory is the OS's to sweep.
        }
        catch (IOException)
        {
        }
    }
}

[CollectionDefinition("reference-set")]
public sealed class ReferenceSetCollection : ICollectionFixture<ReferenceSetFixture>;
