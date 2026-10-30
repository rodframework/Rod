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
/// The first plugin package, end to end over the real ecosystem (ADRs
/// 020-023): hostenum, published from its rod-plugin-hostenum repository
/// into the organization's registry, is browsed and installed off the
/// operator console against the shipped default registry -- the https
/// mirror the configuration names -- and the implant loads the artifact
/// the endpoint served. Nothing is mocked at any seam: the signature, the
/// digest, the lock, and the tasking are the production ones, and the
/// package is the one an operator downloads. The reference set fixture
/// beside this suite installs the same entry once per run for tree-level
/// reads; this test exercises the console's own install leg.
/// </summary>
[Collection("reference-set")]
public class HostenumMarketplaceTests(ReferenceSetFixture fixture)
{
    [RustFact]
    public async Task Hostenum_InstallsAndLoads_ThroughTheMarketplace()
    {
        var root = Path.Combine(Path.GetTempPath(), "rod-marketplace-" + Guid.NewGuid().ToString("N"));
        var rustDir = ModuleLoadTestSupport.FindRustTree()
            ?? throw new InvalidOperationException("the Rust implant tree was not found from the test assembly");

        // The implant binary is still a platform-tree build; the plugin
        // artifact now travels the ecosystem -- the fixture installed the
        // real package, and the console must stage exactly those bytes.
        await ModuleLoadTestSupport.RunCargoAsync(rustDir, "build --release");
        var implantBinary = Path.Combine(rustDir, "target", "release", "rod-implant");
        Assert.True(File.Exists(implantBinary), $"cargo reported success but {implantBinary} is missing");
        var artifactBytes = await File.ReadAllBytesAsync(Path.Combine(
            fixture.ModuleDirectory("hostenum"), "plugin", "hostenum-linux-amd64"));

        // The registry index carries the entry with the artifact row, the
        // organization key, and the release-asset URL the console will
        // download -- read off the tap the fixture cloned.
        var entry = RegistryJson.LoadEntry(fixture.EntryPath("hostenum"))!;
        Assert.Equal("plugin", entry.Entry);
        var version = Assert.Single(entry.Versions);
        var artifactRow = Assert.Single(version.PluginArtifacts!);
        Assert.Equal("linux", artifactRow.Platform);
        Assert.Equal("amd64", artifactRow.Arch);
        Assert.Equal("exec-v1", artifactRow.Abi);
        Assert.StartsWith("https://github.com/rodframework/", version.Url, StringComparison.Ordinal);
        Assert.Equal("7eb0ea8cc3b2158fe0da3492935cce23", version.Fingerprint);

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

        var install = await env.Http.PostAsJsonAsync("/modules/install", new { name = "hostenum" });
        Assert.True(install.IsSuccessStatusCode, await install.Content.ReadAsStringAsync());
        var installed = await env.Http.GetFromJsonAsync<JsonElement[]>("/modules");
        var held = Assert.Single(installed!, m => m.GetProperty("name").GetString() == "hostenum");
        Assert.Equal("plugin", held.GetProperty("entry").GetString());

        // The artifact the console stages: the platform-matched row, byte
        // for byte the package the registry served.
        var staged = await env.Http.GetAsync(
            "/modules/hostenum/artifact?platform=linux&arch=amd64");
        Assert.Equal(HttpStatusCode.OK, staged.StatusCode);
        Assert.Equal(artifactBytes, await staged.Content.ReadAsByteArrayAsync());

        // The delivery: the marketplace's artifact rides a module.load task
        // exactly the way a direct-build module does, and the verb the
        // artifact registers answers like a compiled one.
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
        process!.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
        process.BeginErrorReadLine();

        try
        {
            var implantId = await ModuleLoadTestSupport.WaitForOnlineAsync(env, TimeSpan.FromSeconds(60), stderr);

            var load = await IssueAsync(env, implantId, "module.load", "hostenum", artifactBytes);
            var loaded = await ModuleLoadTestSupport.WaitForTaskAsync(
                env, load.TaskId, t => t.Status == "Completed", stderr, "the module.load task");
            Assert.Equal("Succeeded", loaded.Outcome);
            Assert.Contains("recon.hostenum", loaded.Output);

            var sweep = await IssueAsync(env, implantId, "recon.hostenum", "");
            var swept = await ModuleLoadTestSupport.WaitForTaskAsync(
                env, sweep.TaskId, t => t.Status == "Completed", stderr, "the recon.hostenum task");
            Assert.Equal("Succeeded", swept.Outcome);
            Assert.Contains("\"host\":", swept.Output);
            Assert.Contains("\"user\":", swept.Output);

            // The task's audit arc is any task's: issued, completed,
            // attributed through the implant.
            var audit = env.Host.Services.GetRequiredService<IAuditStore>();
            var trail = await audit.ForTaskAsync(Guid.Parse(sweep.TaskId));
            Assert.Contains(trail, e => e.Kind == AuditEventKind.TaskCompleted);
            Assert.Contains(trail, e => e.ImplantId == Guid.Parse(implantId));

            var unload = await IssueAsync(env, implantId, "module.unload", "hostenum");
            var unloaded = await ModuleLoadTestSupport.WaitForTaskAsync(
                env, unload.TaskId, t => t.Status == "Completed", stderr, "the module.unload task");
            Assert.Contains("recon.hostenum", unloaded.Output);
        }
        finally
        {
            if (!process.HasExited)
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
