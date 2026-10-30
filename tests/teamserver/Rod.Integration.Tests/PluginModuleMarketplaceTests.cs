using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Rod.Audit;
using Rod.Capabilities;
using Rod.Capabilities.Endpoints;
using Rod.Packaging;
using Rod.Transport;
using Rod.Transport.Endpoints;

namespace Rod.Integration.Tests;

/// <summary>
/// The twelve module pairs that followed hostenum onto the plugin tier,
/// end to end over the real ecosystem (ADRs 020/023): each installs off
/// the operator console against the shipped default registry -- the
/// organization's published packages, browsed over the https mirror --
/// and the implant loads the artifact the endpoint served. One registry,
/// one teamserver, one implant: the twelve ride the identical production
/// chain a marketplace deploy runs, nothing mocked at any seam -- the
/// signatures, the digests, the lock, and the tasking are the production
/// ones.
/// </summary>
[Collection("reference-set")]
public class PluginModuleMarketplaceTests(ReferenceSetFixture fixture)
{
    // The twelve packages and the dispatch each one's verb gets on this
    // Linux host. Eleven techniques are Windows-only: their artifacts
    // load and their verbs answer with the named off-Windows refusal --
    // that dispatch is the round trip this lane proves (the load, the
    // registration, the dispatch reaching the plugin's code, the
    // unload); the techniques themselves run on their targets.
    // domainenum is the cross-platform pair: its sweep runs here and the
    // posture row always answers.
    private static readonly (string Name, string Verb, string Arguments, bool Refuses)[] Modules =
    [
        ("avoid", "evasion.avoid", "amsi", true),
        ("browser", "collect.browser", "", true),
        ("credman", "collect.credman", "", true),
        ("domainenum", "recon.domainenum", "", false),
        ("dpapi", "collect.dpapi", "", true),
        ("hijack", "persist.hijack", """list C:\app\app.exe""", true),
        ("hives", "collect.hives", "", true),
        ("lsasecrets", "collect.lsasecrets", "", true),
        ("runkeys", "persist.runkeys", "", true),
        ("services", "persist.services", "", true),
        ("unload", "evasion.unload", "", true),
        ("wmi", "persist.wmi", "", true),
    ];

    [RustFact]
    public async Task TheTwelve_InstallAndLoad_ThroughTheMarketplace()
    {
        var root = Path.Combine(Path.GetTempPath(), "rod-marketplace-twelve-" + Guid.NewGuid().ToString("N"));
        var rustDir = ModuleLoadTestSupport.FindRustTree()
            ?? throw new InvalidOperationException("the Rust implant tree was not found from the test assembly");

        // The implant binary is still a platform-tree build; the plugin
        // artifacts travel the ecosystem -- read each package's artifact
        // out of the fixture's installed store, the bytes the console
        // must stage.
        await ModuleLoadTestSupport.RunCargoAsync(rustDir, "build --release");
        var implantBinary = Path.Combine(rustDir, "target", "release", "rod-implant");
        Assert.True(File.Exists(implantBinary), $"cargo reported success but {implantBinary} is missing");

        var artifacts = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (name, _, _, _) in Modules)
        {
            artifacts[name] = await File.ReadAllBytesAsync(Path.Combine(
                fixture.ModuleDirectory(name), "plugin", $"{name}-linux-amd64"));
        }

        // The registry index carries every entry with its artifact row and
        // the organization key -- read off the tap the fixture cloned.
        foreach (var (name, _, _, _) in Modules)
        {
            var entry = RegistryJson.LoadEntry(fixture.EntryPath(name))!;
            Assert.Equal("plugin", entry.Entry);
            var version = Assert.Single(entry.Versions);
            var artifactRow = Assert.Single(version.PluginArtifacts!);
            Assert.Equal("linux", artifactRow.Platform);
            Assert.Equal("amd64", artifactRow.Arch);
            Assert.Equal("exec-v1", artifactRow.Abi);
            Assert.StartsWith("https://github.com/rodframework/", version.Url, StringComparison.Ordinal);
            Assert.Equal("7eb0ea8cc3b2158fe0da3492935cce23", version.Fingerprint);
        }

        // The consumer half: a real teamserver with the module store and
        // the default registry composed, the marketplace endpoints mapped.
        await using var env = await TestEnv.StartAsync(
            extendConfig: settings =>
            {
                settings["Modules:Store"] = Path.Combine(root, "store");
                settings["Modules:Registry"] = fixture.MarketplaceRegistry;
            },
            configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config),
            mapEndpoints: MapMarketplace);
        await env.CreateEngagementAsync();

        foreach (var (name, _, _, _) in Modules)
        {
            var install = await env.Http.PostAsJsonAsync("/modules/install", new { name });
            Assert.True(install.IsSuccessStatusCode,
                $"install {name} failed: {await install.Content.ReadAsStringAsync()}");
        }
        var installed = await env.Http.GetFromJsonAsync<JsonElement[]>("/modules");
        Assert.NotNull(installed);
        foreach (var (name, _, _, _) in Modules)
        {
            var held = Assert.Single(installed!, m => m.GetProperty("name").GetString() == name);
            Assert.Equal("plugin", held.GetProperty("entry").GetString());
        }

        // The artifacts the console stages: the platform-matched rows,
        // byte for byte the packages the registry served.
        foreach (var (name, _, _, _) in Modules)
        {
            var staged = await env.Http.GetAsync(
                $"/modules/{name}/artifact?platform=linux&arch=amd64");
            Assert.Equal(HttpStatusCode.OK, staged.StatusCode);
            Assert.Equal(artifacts[name], await staged.Content.ReadAsByteArrayAsync());
        }

        // The delivery: every marketplace artifact rides a module.load
        // task exactly the way hostenum's does, the verb the artifact
        // registers answers, and the unload retracts it -- twelve loads,
        // twelve dispatches, twelve unloads against one implant.
        var mint = await env.Http.PostAsync(
            $"/engagements/{env.EngagementId}/deploy-tokens", content: null);
        mint.EnsureSuccessStatusCode();
        var token = await mint.Content.ReadFromJsonAsync<MintedToken>();
        Assert.False(string.IsNullOrEmpty(token?.Secret));

        var stderr = new StringBuilder();
        var start = new ProcessStartInfo
        {
            FileName = implantBinary,
            UseShellExecute = false,
            RedirectStandardError = true,
        };
        start.Environment["ROD_ENROLL_URL"] = $"http://127.0.0.1:{env.HttpPort}/implants/enroll";
        start.Environment["ROD_DEPLOY_TOKEN"] = token!.Secret;
        start.Environment["ROD_VERBOSE"] = "1";
        start.Environment["ROD_SLEEP"] = "1";
        start.Environment["ROD_JITTER"] = "0";
        start.Environment["ROD_ENVELOPE"] = "none";
        start.Environment["ROD_VERBS"] = "shell.exec,module.load,module.unload,module.list";
        using var process = Process.Start(start);
        Assert.NotNull(process);

        try
        {
            process!.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
            process.BeginErrorReadLine();
            var implantId = await ModuleLoadTestSupport.WaitForOnlineAsync(env, TimeSpan.FromSeconds(60), stderr);

            string? auditedTaskId = null;
            foreach (var (name, verb, arguments, refuses) in Modules)
            {
                var load = await IssueAsync(env, implantId, "module.load", name, artifacts[name]);
                var loaded = await ModuleLoadTestSupport.WaitForTaskAsync(
                    env, load.TaskId, t => t.Status == "Completed", stderr, $"the {name} module.load task");
                Assert.True(loaded.Outcome == "Succeeded",
                    $"{name} module.load: {loaded.Outcome} {loaded.Output}. Implant stderr:\n{stderr}");
                Assert.Contains(verb, loaded.Output);

                var dispatch = await IssueAsync(env, implantId, verb, arguments);
                var answered = await ModuleLoadTestSupport.WaitForTaskAsync(
                    env, dispatch.TaskId, t => t.Status == "Completed", stderr, $"the {verb} task");
                if (refuses)
                {
                    // The off-Windows refusal, named: the dispatch reached
                    // the plugin's code and the technique said where it
                    // runs instead.
                    Assert.True(answered.Outcome == "Failed",
                        $"{verb}: expected the named off-Windows refusal, got {answered.Outcome} {answered.Output}");
                    Assert.Contains("Windows technique", answered.Output);
                    Assert.Contains("linux", answered.Output);
                }
                else
                {
                    // The sweep runs on this host: the posture row always
                    // answers first, its own host fact always present --
                    // a workgroup machine simply carries no domain fact.
                    Assert.Equal("Succeeded", answered.Outcome);
                    Assert.Contains("\"host\":", answered.Output);
                }
                auditedTaskId = dispatch.TaskId;

                var unload = await IssueAsync(env, implantId, "module.unload", name);
                var unloaded = await ModuleLoadTestSupport.WaitForTaskAsync(
                    env, unload.TaskId, t => t.Status == "Completed", stderr, $"the {name} module.unload task");
                Assert.Contains(verb, unloaded.Output);
            }

            // The audit arc is any task's: issued, completed, attributed
            // through the implant -- pinned once for the sweep.
            var audit = env.Host.Services.GetRequiredService<IAuditStore>();
            var trail = await audit.ForTaskAsync(Guid.Parse(auditedTaskId!));
            Assert.Contains(trail, e => e.Kind == AuditEventKind.TaskCompleted);
            Assert.Contains(trail, e => e.ImplantId == Guid.Parse(implantId));
        }
        finally
        {
            if (!process!.HasExited)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                process.WaitForExit(5000);
            }
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    private static void MapMarketplace(IEndpointRouteBuilder endpoints)
        => endpoints.MapRodModuleEndpoints();

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

    private sealed record MintedToken(string Secret);
}
