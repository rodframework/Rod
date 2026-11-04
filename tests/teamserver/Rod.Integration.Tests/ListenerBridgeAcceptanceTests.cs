using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Rod.Audit;
using Rod.Capabilities;
using Rod.Capabilities.Lifecycle;
using Rod.Capabilities.Registry;
using Rod.Conformance;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Listeners;
using Rod.CoreState.Operators;
using Rod.CoreState.Sessions;
using Rod.CoreState.Tasks;
using Rod.Packaging;
using Rod.Transport;
using Rod.Transport.Listeners;
using Microsoft.AspNetCore.Hosting;
using Task = System.Threading.Tasks.Task;
using TaskStatus = Rod.CoreState.Tasks.TaskStatus;

namespace Rod.Integration.Tests;

/// <summary>
/// The listener bridge's acceptance leg (ADR-025, todo.md's first queue
/// item): a candidate listener process in a non-C# language -- the
/// stdlib-Python fixture package -- carries the conformance rig's minimal
/// implant end to end, entirely over the bridge, and a killed process
/// marks its listener unhealthy without touching the teamserver. Every
/// leg rides the real chain: the package is built and signed, installed
/// through the lifecycle service, and bound through the listener manager;
/// the implant is the rig's own loop; the observations are the core
/// services the operator API drives.
/// </summary>
public sealed class ListenerBridgeAcceptanceTests : IAsyncLifetime
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(30);

    private readonly string _root = Path.Combine(
        Path.GetTempPath(), "rod-listener-bridge-" + Guid.NewGuid().ToString("N"));
    private readonly int _operatorPort = GetFreeTcpPort();
    private readonly int _frontPort = GetFreeTcpPort();
    private readonly Ed25519.KeyPair _publisherKeys = Ed25519.GenerateKeyPair();

    private IHost _host = null!;
    private OperatorId _operator;
    private IImplantRepository _implants = null!;
    private ISessionRegistry _sessions = null!;
    private EngagementService _engagements = null!;
    private TaskService _tasks = null!;
    private ITaskRepository _taskRecords = null!;
    private IAuditStore _audit = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_root);

        // The fixture package rides the real install chain: pack and sign
        // the candidate tree exactly as a publisher's shell would, register
        // it in a local registry, and let the lifecycle service verify,
        // adopt, and pin it into the host's module store.
        var fixture = Path.Combine(AppContext.BaseDirectory, "fixtures", "rod-listener-candidate");
        var zip = Path.Combine(_root, "dist", "rod-listener-candidate.zip");
        Directory.CreateDirectory(Path.GetDirectoryName(zip)!);
        var selection = ModulePackage.SelectFiles(fixture, null);
        var (_, sha256) = await ModulePackage.WriteZipAsync(selection, zip);
        var (manifest, _) = ManifestToml.LoadFile(Path.Combine(fixture, ManifestToml.FileName));
        var canonical = CanonicalForm.Build(manifest!, CanonicalForm.DigestPayload(fixture));
        var signature = Convert.ToBase64String(
            Ed25519.Sign(_publisherKeys.SecretKey, System.Text.Encoding.UTF8.GetBytes(canonical)));

        var registryRoot = Path.Combine(_root, "registry");
        Directory.CreateDirectory(Path.Combine(registryRoot, "modules"));
        var entry = new RegistryEntry(
            manifest!.Name, "listener", manifest.Description ?? "", manifest.License, null,
            new RegistryEntry.OpsecInfo(manifest.Opsec.LandsOnDisk, manifest.Opsec.Notes), [], []);
        entry = entry with
        {
            Versions =
            [
                new RegistryVersion(
                    manifest.Version.ToString(), DateTimeOffset.UtcNow.ToString("O"), zip, sha256,
                    signature, Convert.ToBase64String(_publisherKeys.PublicKey),
                    Ed25519.Fingerprint(_publisherKeys.PublicKey),
                    new RegistryVersion.CompatibilityInfo("1.0.0", [])),
            ],
        };
        await File.WriteAllTextAsync(
            Path.Combine(registryRoot, "modules", manifest.Name + ".json"), RegistryJson.SaveEntry(entry));

        var storeRoot = Path.Combine(_root, "store");
        var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Modules:Store"] = storeRoot,
            })
            .Build();
        _host = TransportHost.CreateHostBuilder(
                configureServices: services =>
                    RodCapabilitiesHost.AddRodCapabilities(services, configuration),
                configuration: configuration)
            .ConfigureWebHost(web => web
                .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(_operatorPort)))
            .ConfigureLogging(logging => logging.ClearProviders())
            .Build();

        {
            var operators = _host.Services.GetRequiredService<IOperatorRepository>();
            await operators.SaveAsync(Operator.Register(
                OperatorId.New(), "bridge-acceptance", DateTimeOffset.UtcNow, DeploymentRole.Member));
            _operator = operators.FindByHandleAsync("bridge-acceptance").GetAwaiter().GetResult()!.Id;
        }
        await _host.StartAsync();

        var lifecycle = _host.Services.GetRequiredService<ModuleLifecycleService>();
        await lifecycle.InstallFromRegistryAsync(
            new ModuleRegistryClient(registryRoot), manifest.Name, operatorId: _operator.Value);

        _implants = _host.Services.GetRequiredService<IImplantRepository>();
        _sessions = _host.Services.GetRequiredService<ISessionRegistry>();
        _engagements = _host.Services.GetRequiredService<EngagementService>();
        _tasks = _host.Services.GetRequiredService<TaskService>();
        _taskRecords = _host.Services.GetRequiredService<ITaskRepository>();
        _audit = _host.Services.GetRequiredService<IAuditStore>();
    }

    public async Task DisposeAsync()
    {
        await _host.StopAsync();
        _host.Dispose();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // A still-draining child process holds the store a moment; the
            // temp root is the OS's to sweep.
        }
    }

    private static int GetFreeTcpPort()
    {
        using var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        return ((IPEndPoint)probe.LocalEndpoint).Port;
    }

    private static async Task<bool> UntilAsync(
        TimeSpan deadline, Func<Task<bool>> observe, TimeSpan? cadence = null)
    {
        var end = DateTimeOffset.UtcNow + deadline;
        while (DateTimeOffset.UtcNow < end)
        {
            if (await observe())
                return true;
            await Task.Delay(cadence ?? TimeSpan.FromMilliseconds(200));
        }
        return false;
    }

    [Fact]
    public async Task ACandidateListenerProcess_CarriesTheMinimalImplantOverTheBridge()
    {
        AssertPythonAvailable();

        // The engagement, its token, and the package-backed listener: the
        // supervisor binds the bridge socket and spawns the candidate
        // process against it.
        var created = await _engagements.CreateEngagementAsync(
            new CreateEngagementCommand(_operator, "bridge-" + Guid.NewGuid().ToString("N")[..8]));
        var minted = await _engagements.MintDeployTokenAsync(
            new MintDeployTokenCommand(created.EngagementId, _operator));

        var pidfile = Path.Combine(_root, "candidate.pid");
        var manager = _host.Services.GetRequiredService<ListenerManager>();
        var listener = await manager.CreateAsync(new ListenerConfig(
            "candidate-front",
            "rod-listener-candidate",
            $"127.0.0.1:{_frontPort}",
            $"http://127.0.0.1:{_frontPort}",
            created.EngagementId,
            PackageName: "rod-listener-candidate",
            Params: new Dictionary<string, string>
            {
                ["bind"] = $"127.0.0.1:{_frontPort}",
                ["pidfile"] = pidfile,
            }));

        Assert.Equal("id-only", listener.SealTier);
        Assert.Equal(ListenerState.Running, listener.State);

        // The candidate's medium front comes up on its own bind.
        Assert.True(await UntilAsync(Deadline, () => Task.FromResult(TcpPortOpen(_frontPort))),
            "the candidate process never bound its HTTP front");

        // The rig's own minimal implant, pointed at the candidate's front:
        // enroll, contact, and a task round trip, each entirely over the
        // bridge -- the kernel's Kestrel never sees the implant.
        using var stop = new CancellationTokenSource();
        var implant = Task.Run(() => new MinimalImplantLoop(new ImplantDefects()).RunAsync(
            new ConformanceTarget(
                $"http://127.0.0.1:{_frontPort}/implants/enroll",
                minted.Secret),
            stop.Token));

        Assert.True(await UntilAsync(Deadline, async () =>
                (await _implants.ListByEngagementAsync(created.EngagementId)).Count > 0),
            "no enrollment appeared: the candidate never carried the enroll leg over the bridge");
        Assert.True(await UntilAsync(Deadline, async () =>
                (await _sessions.ListActiveAsync(created.EngagementId)).Count > 0),
            "no session opened: the candidate never carried the contact leg over the bridge");

        var enrolled = (await _implants.ListByEngagementAsync(created.EngagementId))[0].Id;
        var marker = "rod-bridge-" + Guid.NewGuid().ToString("N")[..8];
        var issued = await _tasks.IssueAsync(new IssueTaskCommand(
            created.EngagementId, enrolled, _operator, "shell.exec", $"echo {marker}"));
        Assert.True(await UntilAsync(Deadline, async () =>
            {
                var task = await _taskRecords.FindAsync(issued.TaskId);
                return task is { Status: TaskStatus.Completed }
                    && task.Outcome == TaskOutcome.Succeeded
                    && task.Output?.Contains(marker) == true;
            }),
            "the shell.exec task never completed through the bridge");

        // The kill leg: the killed process marks its listener unhealthy
        // without touching the teamserver -- the operator port keeps
        // answering while the badge flips, and the audit trail carries the
        // exit fact. The supervisor then respawns and the state returns.
        var candidatePid = int.Parse(await File.ReadAllTextAsync(pidfile));
        Process.GetProcessById(candidatePid).Kill(entireProcessTree: true);

        Assert.True(await UntilAsync(Deadline, async () =>
                await Task.FromResult(listener.State == ListenerState.Unhealthy)),
            "killing the process never marked the listener unhealthy");
        using (var http = new HttpClient())
        {
            using var alive = await http.GetAsync($"http://127.0.0.1:{_operatorPort}/engagements");
            // Any answer -- authorized or not -- is the kernel serving; a
            // crashed teamserver answers nothing at all.
            Assert.True(alive.StatusCode != 0);
        }
        Assert.True(await UntilAsync(Deadline, async () =>
                (await _audit.ListAsync(created.EngagementId.Value))
                .Any(e => e.Kind == AuditEventKind.ListenerProcessExited && e.Verb == "listener.process-exited")),
            "the exit fact never landed in the engagement's audit trail");

        Assert.True(await UntilAsync(Deadline, async () =>
                await Task.FromResult(listener.State == ListenerState.Running && TcpPortOpen(_frontPort))),
            "the supervisor never respawned the candidate process");

        // The loop's stop is its cancellation; a canceled poll cycle ends
        // it, which surfaces here as the expected cancellation.
        stop.Cancel();
        try
        {
            await implant;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static bool TcpPortOpen(int port)
    {
        try
        {
            using var client = new TcpClient();
            client.Connect(IPAddress.Loopback, port);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    // The candidate is a Python process; the leg fails loudly (not as a
    // skip) on a host without python3, naming the missing piece.
    private static void AssertPythonAvailable()
    {
        try
        {
            using var check = Process.Start(new ProcessStartInfo
            {
                FileName = "python3",
                ArgumentList = { "--version" },
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            check?.WaitForExit(5000);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            Assert.Fail("python3 is not on PATH; the bridge acceptance candidate needs it.");
        }
    }
}
