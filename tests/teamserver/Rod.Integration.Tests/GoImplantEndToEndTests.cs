using System.Diagnostics;
using System.Net.Http.Json;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.CoreState;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.BuildPipeline.PayloadBuild;

namespace Rod.Integration.Tests;

/// <summary>
/// A fact that runs only when a Go toolchain is on PATH: the Go implant's
/// legs build it as a process.
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
/// Acceptance for the Go community implant (architecture.md Sec 12.2, the
/// first community-slot reference): the AC is the full arc -- enroll, task,
/// and exfil end to end -- over the envelope POST cycle, first in the dev
/// shape (plaintext lab posture) with an exfil run past the per-contact
/// budget (the ADR-010 offset-resume arm spanning contacts), then through
/// the build pipeline (the Go build unit's baked artifact, sealed contacts
/// under the per-artifact key). Cross-language interoperability is the
/// product; this is its proof for the second wire-speaking tree.
/// </summary>
public class GoImplantEndToEndTests
{
    [GoFact]
    public async Task GoImplant_EnrollsRunsTasking_AndExfilsPastTheContactBudget()
    {
        var goDir = FindGoTree()
            ?? throw new InvalidOperationException("the Go implant tree was not found from the test assembly");
        // The dev-shape binary: a plain go build of the checked-in tree.
        var binary = Path.Combine(
            Path.GetTempPath(), "rod-go-e2e-" + Guid.NewGuid().ToString("N") + TestCell.ExeSuffix);
        var build = Process.Start(new ProcessStartInfo
        {
            FileName = "go",
            WorkingDirectory = goDir,
            ArgumentList = { "build", "-o", binary, "." },
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        var buildOutput = (await build!.StandardOutput.ReadToEndAsync())
            + await build.StandardError.ReadToEndAsync();
        build.WaitForExit(300_000);
        Assert.True(build.ExitCode == 0, $"go build failed:\n{buildOutput}");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(binary,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        await using var env = await TestEnv.StartAsync();
        await env.CreateEngagementAsync();

        // The deployment credential: a manual mint (the rotation shape),
        // spent by the dev-shape enroll below.
        var mint = await env.Http.PostAsync(
            $"/engagements/{env.EngagementId}/deploy-tokens", content: null);
        mint.EnsureSuccessStatusCode();
        var token = await mint.Content.ReadFromJsonAsync<MintedToken>();
        Assert.False(string.IsNullOrEmpty(token?.Secret));

        // The spanning exfil run: 9 MiB against the 8 MiB per-contact
        // budget, so the run must chain contacts through the seam reports.
        var loot = Path.Combine(Path.GetTempPath(), "rod-go-exfil-" + Guid.NewGuid().ToString("N") + ".bin");
        var content = new byte[9 * 1024 * 1024 + 123];
        Random.Shared.NextBytes(content);
        await File.WriteAllBytesAsync(loot, content);

        var (process, stderr) = Start(binary, new Dictionary<string, string>
        {
            ["ROD_ENROLL_URL"] = $"http://127.0.0.1:{env.HttpPort}/implants/enroll",
            ["ROD_DEPLOY_TOKEN"] = token!.Secret!,
            ["ROD_VERBOSE"] = "1",
            ["ROD_SLEEP"] = "1",
            ["ROD_JITTER"] = "0",
            ["ROD_ENVELOPE"] = "none",
            ["ROD_CONTACT_ENVELOPE"] = "none",
            ["ROD_VERBS"] = "shell.exec,file.pull",
        });
        try
        {
            // Enroll crossed and the session went live on the roster.
            var implantId = await WaitForOnlineAsync(env, TimeSpan.FromSeconds(60), stderr);

            // The task leg: a dispatched shell.exec rides down, the Go
            // handler runs it, the result rides back up.
            var marker = "rod-go-smoke-" + Guid.NewGuid().ToString("N")[..8];
            var echo = await IssueAsync(env, implantId, "shell.exec", $"echo {marker}");
            var done = await WaitForTaskAsync(env, echo.TaskId, TimeSpan.FromSeconds(60), stderr);
            Assert.Equal("Succeeded", done.Outcome);
            Assert.Contains(marker, done.Output);

            // The exfil leg: file.pull streams the 9 MiB run past one
            // contact's budget -- the offset-bearing chunks and the seam
            // reports chain the contacts until the artifact lands whole.
            var pull = await IssueAsync(env, implantId, "file.pull", loot);
            var artifacts = env.Host.Services.GetRequiredService<IArtifactStore>();
            Artifact? landed = null;
            var deadline = DateTimeOffset.UtcNow.AddSeconds(120);
            while (DateTimeOffset.UtcNow < deadline && landed is null)
            {
                landed = (await artifacts.ForTaskAsync(Guid.Parse(pull.TaskId)))
                    .FirstOrDefault(a => a.Name == Path.GetFileName(loot));
                if (landed is null)
                    await Task.Delay(500);
            }
            Assert.NotNull(landed);
            Assert.Equal(content.Length, landed!.Size);
            Assert.Equal(content, landed.Content);
        }
        finally
        {
            Kill(process);
            try { File.Delete(loot); } catch { }
            try { File.Delete(binary); } catch { }
        }
    }

    [GoFact]
    public async Task GoImplant_BuildsThroughThePipeline_AndRunsFromTheBake()
    {
        await using var env = await TestEnv.StartAsync();
        await env.CreateEngagementAsync();

        // The front the bake dials: a plain http listener whose public
        // endpoint is the dial itself.
        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "go-e2e-http",
                Transport: "http",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"http://127.0.0.1:{port}"));
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        var front = (await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>())!.Id;

        // The pipeline build: the Go unit bakes the profile -- sealed
        // contacts on, the default posture -- and mints the credential.
        var built = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Unit: "rod-go",
                Class: "Implant",
                TargetOs: TestCell.Os,
                TargetArch: TestCell.Arch,
                ListenerId: front,
                UriPath: null,
                SleepSeconds: 1.0,
                JitterSeconds: 0.0,
                KillDate: null));
        Assert.True(built.IsSuccessStatusCode, await built.Content.ReadAsStringAsync());
        var artifact = await built.Content.ReadFromJsonAsync<BuildBody>();
        Assert.NotNull(artifact);
        Assert.Equal(BuildUnitIds.Go, artifact!.UnitId);

        var outDir = Path.Combine(Path.GetTempPath(), "rod-e2e-go-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outDir);
        var binaryPath = Path.Combine(outDir, "rod-implant" + TestCell.ExeSuffix);
        Process? process = null;
        var stderr = new StringBuilder();
        try
        {
            using (var download = await env.Http.GetAsync(
                $"/engagements/{artifact.EngagementId}/payloads/{artifact.ArtifactId}"))
            {
                download.EnsureSuccessStatusCode();
                await File.WriteAllBytesAsync(binaryPath, await download.Content.ReadAsByteArrayAsync());
            }
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(binaryPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            // The fielded shape: no arguments, no environment -- the bake
            // is the configuration, the sealed contact path the carriage.
            (process, stderr) = Start(binaryPath, new Dictionary<string, string> { ["ROD_VERBOSE"] = "1" });
            var implantId = await WaitForOnlineAsync(env, TimeSpan.FromSeconds(90), stderr);

            // The task leg over the sealed cycle.
            var marker = "rod-go-baked-" + Guid.NewGuid().ToString("N")[..8];
            var echo = await IssueAsync(env, implantId, "shell.exec", $"echo {marker}");
            var done = await WaitForTaskAsync(env, echo.TaskId, TimeSpan.FromSeconds(60), stderr);
            Assert.Equal("Succeeded", done.Outcome);
            Assert.Contains(marker, done.Output);

            // The exfil leg over the sealed cycle: the chunked path with
            // offset chunks and seam reports under the contact seal.
            var loot = Path.Combine(outDir, "loot.bin");
            var content = new byte[2 * 1024 * 1024 + 77];
            Random.Shared.NextBytes(content);
            await File.WriteAllBytesAsync(loot, content);
            var pull = await IssueAsync(env, implantId, "file.pull", loot);
            var artifacts = env.Host.Services.GetRequiredService<IArtifactStore>();
            var deadline = DateTimeOffset.UtcNow.AddSeconds(90);
            while (DateTimeOffset.UtcNow < deadline)
            {
                var stored = (await artifacts.ForTaskAsync(Guid.Parse(pull.TaskId)))
                    .FirstOrDefault(a => a.Name == "loot.bin");
                if (stored is not null)
                {
                    Assert.Equal(content, stored.Content);
                    return;
                }
                await Task.Delay(500);
            }
            Assert.Fail($"the sealed exfil run did not land. Implant stderr:\n{stderr}");
        }
        finally
        {
            Kill(process);
            process?.Dispose();
            try { Directory.Delete(outDir, recursive: true); } catch { }
        }
    }

    // --- The shared harness, mirroring the Rust e2e's shape ---

    private static (Process Process, StringBuilder Stderr) Start(
        string binary, IReadOnlyDictionary<string, string> environment)
    {
        var stderr = new StringBuilder();
        var start = new ProcessStartInfo
        {
            FileName = binary,
            UseShellExecute = false,
            RedirectStandardError = true,
        };
        foreach (var (key, value) in environment)
            start.Environment[key] = value;
        var process = Process.Start(start) ?? throw new InvalidOperationException("the implant failed to start");
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
        process.BeginErrorReadLine();
        return (process, stderr);
    }

    private static void Kill(Process? process)
    {
        if (process is { HasExited: false })
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            process.WaitForExit(5000);
        }
    }

    private static async Task<TaskBody> IssueAsync(
        TestEnv env, string implantId, string verb, string arguments)
    {
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks",
            new TaskEndpoints.IssueTaskRequest(implantId, verb, arguments));
        issued.EnsureSuccessStatusCode();
        var task = await issued.Content.ReadFromJsonAsync<TaskBody>();
        Assert.NotNull(task);
        return task!;
    }

    private static async Task<TaskBody> WaitForTaskAsync(
        TestEnv env, string taskId, TimeSpan deadline, StringBuilder stderr)
    {
        var end = DateTimeOffset.UtcNow + deadline;
        while (DateTimeOffset.UtcNow < end)
        {
            var read = await env.Http.GetFromJsonAsync<TaskBody>(
                $"/engagements/{env.EngagementId}/tasks/{taskId}");
            if (read?.Status == "Completed")
                return read;
            await Task.Delay(500);
        }
        throw new TimeoutException($"the dispatched task did not complete. Implant stderr:\n{stderr}");
    }

    private static async Task<string> WaitForOnlineAsync(
        TestEnv env, TimeSpan deadline, StringBuilder stderr)
    {
        var end = DateTimeOffset.UtcNow + deadline;
        while (DateTimeOffset.UtcNow < end)
        {
            try
            {
                var implants = await env.Http.GetFromJsonAsync<ImplantEndpoints.ImplantResponse[]>(
                    $"/engagements/{env.EngagementId}/implants");
                var online = implants?.FirstOrDefault(i => i.Class == "Implant" && i.IsOnline);
                if (online is not null)
                    return online.ImplantId;
            }
            catch (HttpRequestException)
            {
                // The listing read races the enrollment; retry.
            }
            await Task.Delay(500);
        }
        throw new TimeoutException("the Go implant did not appear online. Stderr:\n" + stderr);
    }

    private static string? FindGoTree()
        // The build pipeline's pinned-source resolution, the Go twin of the
        // Rust suite's locator.
        => Rod.BuildPipeline.PayloadBuild.PinnedImplantSource.LocateGoTree();

    private sealed record MintedToken(string? Secret);

    private sealed class TaskBody
    {
        public string TaskId { get; set; } = "";
        public string Status { get; set; } = "";
        public string? Outcome { get; set; }
        public string? Output { get; set; }
    }

    private sealed class BuildBody
    {
        public string ArtifactId { get; set; } = "";
        public string EngagementId { get; set; } = "";
        public string UnitId { get; set; } = "";
    }

    /// <summary>
    /// A real Kestrel teamserver with the implant-facing endpoints and the
    /// operator API on one port, mirroring the Rust e2e harness.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;
        public int HttpPort { get; private set; }

        public static async Task<TestEnv> StartAsync()
        {
            var env = new TestEnv();
            env.HttpPort = TestSupport.GetFreeTcpPort();

            var config = AuthenticatedHost.BuildConfig();
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
                    .UseRodListeners(new List<Rod.Transport.Listeners.ListenerConfig>())
                    .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(env.HttpPort)))
                .Build();
            await env.Host.StartAsync();

            env.Http = new HttpClient(new CookieHandler(new HttpClientHandler()))
            {
                BaseAddress = new Uri($"http://127.0.0.1:{env.HttpPort}"),
            };
            await AuthenticatedHost.LoginAsync(env.Http);
            return env;
        }

        public async Task CreateEngagementAsync()
        {
            var createResponse = await Http.PostAsJsonAsync("/engagements",
                new EngagementEndpoints.CreateEngagementRequest(Name: "Operation Go Slice"));
            createResponse.EnsureSuccessStatusCode();
            var created = await createResponse.Content.ReadFromJsonAsync<EngagementEndpoints.EngagementResponse>();
            EngagementId = created!.EngagementId;
        }

        public string? EngagementId { get; private set; }

        public async ValueTask DisposeAsync()
        {
            Http?.Dispose();
            if (Host is not null)
                await Host.StopAsync();
            Host?.Dispose();
        }
    }
}
