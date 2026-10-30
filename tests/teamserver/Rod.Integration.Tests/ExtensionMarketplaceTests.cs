using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Rod.Audit;
using Rod.BuildPipeline.PayloadBuild;
using Rod.Capabilities;
using Rod.Capabilities.Endpoints;
using Rod.Packaging;
using Rod.Transport;
using Rod.Transport.Endpoints;

namespace Rod.Integration.Tests;

/// <summary>
/// The first real extension module, end to end over the real ecosystem
/// (ADRs 022/023): procwatch walks the extension tier's whole chain --
/// the scaffold an external author starts from (<c>rod mod init --entry
/// extension</c>), the organization's published entry in the registry, the
/// operator console's marketplace install with the hot registration into
/// the build catalog, a payload build that ticks the extension in (the
/// build page's compiled-in selection), and the fielded artifact running
/// its verb with no environment at all -- the bake is the configuration.
/// Nothing is mocked at any seam: the signature, the catalog gate, the
/// overlay merge, and the tasking are the production ones, and the
/// package is the one an operator downloads.
/// </summary>
[Collection("reference-set")]
public class ExtensionMarketplaceTests(ReferenceSetFixture fixture)
{
    [RustFact]
    public async Task Procwatch_WalksTheChain_InitInstallBuildAndRun()
    {
        var root = Path.Combine(Path.GetTempPath(), "rod-ext-procwatch-" + Guid.NewGuid().ToString("N"));

        // The scaffold leg: the same entry an external author starts
        // from, validated the same way the assets scaffold is.
        var scaffold = Path.Combine(root, "scaffold");
        var initOut = new StringWriter();
        var initErr = new StringWriter();
        var init = await Rod.Cli.RodCli.RunAsync(
            ["mod", "init", "procwatch", "--entry", "extension", "--path", scaffold],
            initOut, initErr);
        Assert.True(init == Rod.Cli.RodCli.ExitOk, $"rod mod init failed:\n{initErr}");
        var (scaffoldManifest, scaffoldErrors) = ManifestToml.LoadFile(
            Path.Combine(scaffold, ManifestToml.FileName));
        Assert.Empty(scaffoldErrors);
        Assert.Equal(ModuleEntryKind.Extension, scaffoldManifest!.Entry);
        Assert.True(File.Exists(Path.Combine(scaffold, "src", "lib.rs")),
            "the scaffold must carry the src/ tree the overlay merges");

        // The registry leg: the organization's real entry, read off the
        // tap the fixture cloned -- the extension kind, the verb row, no
        // plugin artifacts (an extension's sources compile in).
        var entry = RegistryJson.LoadEntry(fixture.EntryPath("procwatch"))!;
        Assert.Equal("extension", entry.Entry);
        Assert.Contains(entry.Versions,
            version => version.Verbs!.Any(verb => verb.Name == "recon.procwatch"));
        Assert.All(entry.Versions, version => Assert.Empty(version.PluginArtifacts ?? []));

        // The consumer half: a real teamserver with the module store and
        // the default registry composed, the marketplace endpoints
        // mapped, and the build-side hook wired the way the composition
        // root wires it -- the capabilities layer cannot reference the
        // pipeline, so the delegate lands here exactly where Program.cs
        // lands it.
        await using var env = await TestEnv.StartAsync(
            extendConfig: settings =>
            {
                settings["Modules:Store"] = Path.Combine(root, "store");
                settings["Modules:Registry"] = fixture.MarketplaceRegistry;
            },
            configureServicesWithConfig: (services, config) =>
            {
                services.AddRodCapabilities(config);
                services.AddSingleton<Rod.Capabilities.Lifecycle.ModuleLifecycleService>(sp =>
                    new Rod.Capabilities.Lifecycle.ModuleLifecycleService(
                        sp.GetRequiredService<Rod.Capabilities.Lifecycle.ModuleStore>(),
                        sp.GetRequiredService<Rod.Capabilities.Registry.ICapabilityRegistry>(),
                        sp.GetRequiredService<Rod.Audit.IAuditStore>(),
                        sp.GetRequiredService<TimeProvider>(),
                        sp.GetService<Rod.Capabilities.Registry.ModuleAssetStore>(),
                        registerBuildSide: (name, directory) =>
                        {
                            sp.GetRequiredService<Rod.BuildPipeline.PayloadBuild.ExtensionCatalog>()
                                .Add(directory);
                            return Task.CompletedTask;
                        },
                        unregisterBuildSide: name =>
                        {
                            sp.GetRequiredService<Rod.BuildPipeline.PayloadBuild.ExtensionCatalog>()
                                .Remove(name);
                            return Task.CompletedTask;
                        }));
            },
            mapEndpoints: MapMarketplace);
        await env.CreateEngagementAsync();

        var install = await env.Http.PostAsJsonAsync("/modules/install", new { name = "procwatch" });
        Assert.True(install.IsSuccessStatusCode, await install.Content.ReadAsStringAsync());
        var installed = await env.Http.GetFromJsonAsync<JsonElement[]>("/modules");
        var held = Assert.Single(installed!, m => m.GetProperty("name").GetString() == "procwatch");
        Assert.Equal("extension", held.GetProperty("entry").GetString());

        // The build-page tick: a payload build naming the extension
        // through the same field the console's checkbox fills -- the
        // catalog's targeting gate resolves it against the rod-rust unit.
        var front = await WebFrontAsync(env);
        var built = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Unit: BuildUnitIds.Rust,
                Class: "Implant",
                TargetOs: "linux",
                TargetArch: "amd64",
                ListenerId: front,
                UriPath: null,
                SleepSeconds: 1.0,
                JitterSeconds: 0.0,
                KillDate: null,
                Extensions: ["procwatch"]));
        Assert.True(built.IsSuccessStatusCode, await built.Content.ReadAsStringAsync());
        var artifact = await built.Content.ReadFromJsonAsync<ArtifactBody>();
        Assert.NotNull(artifact);

        var outDir = Path.Combine(root, "run");
        Directory.CreateDirectory(outDir);
        var binaryPath = Path.Combine(outDir, "rod-implant");
        Process? process = null;
        Process? marker = null;
        var stderr = new StringBuilder();
        try
        {
            using (var download = await env.Http.GetAsync(
                $"/engagements/{artifact!.EngagementId}/payloads/{artifact.ArtifactId}"))
            {
                download.EnsureSuccessStatusCode();
                await File.WriteAllBytesAsync(binaryPath, await download.Content.ReadAsByteArrayAsync());
            }
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(binaryPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            // The run leg: the fielded artifact, no arguments and no
            // environment -- the bake carries the extension's verb in its
            // advertised set, which is what lets the task dispatch at all.
            process = Process.Start(new ProcessStartInfo
            {
                FileName = binaryPath,
                UseShellExecute = false,
                RedirectStandardError = true,
                Environment = { ["ROD_VERBOSE"] = "1" },
            });
            Assert.NotNull(process);
            process!.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
            process.BeginErrorReadLine();

            var implantId = await ModuleLoadTestSupport.WaitForOnlineAsync(env, TimeSpan.FromSeconds(90), stderr);

            // The first ask starts the watch: the table as it sits is the
            // baseline, and the answer says so.
            var start = await IssueAsync(env, implantId, "recon.procwatch", "");
            var started = await ModuleLoadTestSupport.WaitForTaskAsync(
                env, start.TaskId, t => t.Status == "Completed", stderr, "the watch-start task");
            Assert.Equal("Succeeded", started.Outcome);
            Assert.Contains("the watch started", started.Output);

            // The grammar guard: the read is bare, and a named argument
            // refuses without touching the watch.
            var bad = await IssueAsync(env, implantId, "recon.procwatch", "bogus");
            var refused = await ModuleLoadTestSupport.WaitForTaskAsync(
                env, bad.TaskId, t => t.Status == "Completed", stderr, "the grammar-refusal task");
            Assert.Equal("Failed", refused.Outcome);
            Assert.Contains("takes no arguments", refused.Output);

            // A process that starts between asks is the watch's whole
            // point: a uniquely named copy of sleep runs under its own
            // name for two sampler sweeps (a shell -c would exec its
            // single command and lose the name; the name stays within
            // the kernel comm field's fifteen characters).
            var markerName = "rod-pw-" + Guid.NewGuid().ToString("N")[..8];
            var markerPath = Path.Combine(outDir, markerName);
            File.Copy("/usr/bin/sleep", markerPath);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(markerPath, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            marker = Process.Start(new ProcessStartInfo
            {
                FileName = markerPath,
                Arguments = "25",
                UseShellExecute = false,
            });
            Assert.NotNull(marker);

            // Two cadence periods, then the flush: the marker's row, in
            // the grammar the recon output contract names.
            await Task.Delay(TimeSpan.FromSeconds(5));
            var flush = await IssueAsync(env, implantId, "recon.procwatch", "");
            var swept = await ModuleLoadTestSupport.WaitForTaskAsync(
                env, flush.TaskId, t => t.Status == "Completed", stderr, "the flush task");
            Assert.Equal("Succeeded", swept.Outcome);
            Assert.Contains(markerName, swept.Output);
            Assert.Contains("\"pid\":", swept.Output);
            Assert.Contains("\"ppid\":", swept.Output);

            // The cursor moved: the next ask does not repeat the row.
            var again = await IssueAsync(env, implantId, "recon.procwatch", "");
            var repeated = await ModuleLoadTestSupport.WaitForTaskAsync(
                env, again.TaskId, t => t.Status == "Completed", stderr, "the repeat ask");
            Assert.Equal("Succeeded", repeated.Outcome);
            Assert.DoesNotContain(markerName, repeated.Output);

            // The task's audit arc is any task's.
            var audit = env.Host.Services.GetRequiredService<IAuditStore>();
            var trail = await audit.ForTaskAsync(Guid.Parse(flush.TaskId));
            Assert.Contains(trail, e => e.Kind == AuditEventKind.TaskCompleted);
            Assert.Contains(trail, e => e.ImplantId == Guid.Parse(implantId));
        }
        finally
        {
            foreach (var running in new[] { marker, process })
            {
                if (running is { HasExited: false })
                {
                    try { running.Kill(entireProcessTree: true); } catch { }
                    running.WaitForExit(5000);
                }
            }
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    private static void MapMarketplace(IEndpointRouteBuilder endpoints)
        => endpoints.MapRodModuleEndpoints();

    private static async Task<string> WebFrontAsync(TestEnv env)
    {
        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "procwatch-e2e",
                Transport: "http",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"http://127.0.0.1:{port}"));
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        return (await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>())!.Id;
    }

    private static async Task<TaskBody> IssueAsync(
        TestEnv env, string implantId, string verb, string arguments, byte[]? content = null)
    {
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks",
            new TaskEndpoints.IssueTaskRequest(implantId, verb, arguments, content));
        Assert.True(issued.IsSuccessStatusCode, await issued.Content.ReadAsStringAsync());
        var task = await issued.Content.ReadFromJsonAsync<TaskBody>();
        Assert.NotNull(task);
        return task!;
    }

    private sealed record ArtifactBody(string ArtifactId, string EngagementId);
}
