using System.Diagnostics;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Rod.BuildPipeline.PayloadBuild;
using Rod.Transport;
using Rod.Transport.Endpoints;

namespace Rod.Integration.Tests;

/// <summary>
/// The adb bridge the android lab leg drives: adb from the SDK when
/// present, else PATH; every call resolves the device the same way adb
/// itself does (one device, or ROD_ANDROID_SERIAL to pick).
/// </summary>
internal static class AndroidLab
{
    public static string? Run(params string[] arguments)
    {
        try
        {
            var sdk = RustBuildUnit.LocateAndroidSdk();
            var adb = sdk is not null && File.Exists(Path.Combine(sdk, "platform-tools", "adb"))
                ? Path.Combine(sdk, "platform-tools", "adb")
                : "adb";
            var start = new ProcessStartInfo
            {
                FileName = adb,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            foreach (var argument in arguments)
                start.ArgumentList.Add(argument);
            using var process = Process.Start(start);
            if (process is null)
                return null;
            var output = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(10_000))
                return null;
            return process.ExitCode == 0 ? output.Result.Trim() : null;
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// A fact that runs only when the android lab leg is present: the NDK
/// cross for the emulator's triple (rustup std plus the NDK toolchain)
/// and an adb-visible device in the "device" state -- a booted emulator
/// or a phone attached for debugging. The runbook
/// (operations/android.md) names both setups.
/// </summary>
public sealed class AndroidEmulatorFactAttribute : FactAttribute
{
    public AndroidEmulatorFactAttribute()
    {
        if (RustBuildUnit.ResolveNdkClang("x86_64-linux-android") is null)
        {
            Skip = "no NDK cross for x86_64-linux-android -- see docs/operations/android.md";
            return;
        }
        if (AndroidLab.Run("get-state") is not "device")
            Skip = "no adb device in the device state (boot an emulator or attach a phone)";
    }
}

/// <summary>
/// The android carrier's acceptance leg (architecture.md Sec 12.2): the
/// same e2e the desktop legs run, with the emulator standing in for the
/// device -- a pipeline-built apk installs on it, the carrier's
/// NativeActivity starts the core in-process, it enrolls through the
/// front the guest dials (the host's loopback via the emulator's 10.0.2.2
/// alias), and a dispatched shell.exec completes with its output. The
/// aarch64 cross for real devices is proven by the build-unit tests; what
/// this leg proves is the carrier itself.
/// </summary>
public class RodImplantAndroidEndToEndTests
{

    private sealed record ArtifactBody
    {
        public string ArtifactId { get; set; } = "";
        public string EngagementId { get; set; } = "";
    }

    private sealed record ImplantBody
    {
        public string ImplantId { get; set; } = "";
        public string Class { get; set; } = "";
        public bool IsOnline { get; set; }
    }

    private sealed record TaskBody
    {
        public string TaskId { get; set; } = "";
        public string Status { get; set; } = "";
        public string? Outcome { get; set; }
        public string? Output { get; set; }
    }

    [AndroidEmulatorFact]
    public async Task TheAndroidCarrier_InstallsEnrolsAndRunsTasking()
    {
        await using var env = await TestEnv.StartAsync();
        await env.CreateEngagementAsync();

        // The front the guest dials: the host's loopback through the
        // emulator's 10.0.2.2 alias -- the listener binds loopback on the
        // host, and the baked public endpoint names the guest-side dial.
        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "e2e-android",
                Transport: "http",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"http://10.0.2.2:{port}"));
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        var front = (await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>())!.Id;

        // The pipeline build: the emulator's amd64 triple, packaged as the
        // installable apk -- the exact operator path, no shortcuts.
        var built = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Unit: "rod-rust",
                Class: "Implant",
                TargetOs: "android",
                TargetArch: "amd64",
                ListenerId: front,
                UriPath: null,
                SleepSeconds: 1.0,
                JitterSeconds: 0.0,
                KillDate: null,
                Mode: "poll",
                Format: "apk"));
        Assert.True(built.IsSuccessStatusCode, await built.Content.ReadAsStringAsync());
        var artifact = await built.Content.ReadFromJsonAsync<ArtifactBody>();
        Assert.NotNull(artifact);

        var apkPath = Path.Combine(Path.GetTempPath(), "rod-e2e-android-" + Guid.NewGuid().ToString("N") + ".apk");
        try
        {
            using (var download = await env.Http.GetAsync(
                $"/engagements/{artifact!.EngagementId}/payloads/{artifact.ArtifactId}"))
            {
                download.EnsureSuccessStatusCode();
                await File.WriteAllBytesAsync(apkPath, await download.Content.ReadAsByteArrayAsync());
            }

            var installed = AndroidLab.Run("install", "-r", apkPath);
            Assert.True(installed?.Contains("Success") == true, $"adb install failed: {installed}");

            try
            {
                // The carrier launch: the manifest's own launcher activity
                // (the framework's NativeActivity, which dlopens the cdylib
                // and calls the entry the glue installs).
                Assert.NotNull(AndroidLab.Run("shell", "am", "start", "-n", "rod.carrier/android.app.NativeActivity"));

                var implantId = await WaitForOnlineAsync(env, TimeSpan.FromSeconds(120));
                Assert.False(string.IsNullOrEmpty(implantId));

                // The same acceptance the desktop legs run: a dispatched
                // task rides the wire down, the core's handler runs it in
                // the app process, and the result rides back up.
                var marker = "rod-android-" + Guid.NewGuid().ToString("N")[..8];
                var issued = await env.Http.PostAsJsonAsync(
                    $"/engagements/{env.EngagementId}/tasks",
                    new TaskEndpoints.IssueTaskRequest(implantId!, "shell.exec", $"echo {marker}"));
                issued.EnsureSuccessStatusCode();
                var task = await issued.Content.ReadFromJsonAsync<TaskBody>();
                Assert.NotNull(task);

                var deadline = DateTimeOffset.UtcNow.AddSeconds(90);
                while (DateTimeOffset.UtcNow < deadline)
                {
                    var read = await env.Http.GetFromJsonAsync<TaskBody>(
                        $"/engagements/{env.EngagementId}/tasks/{task!.TaskId}");
                    if (read?.Status == "Completed")
                    {
                        Assert.Equal("Succeeded", read.Outcome);
                        Assert.Contains(marker, read.Output);
                        return;
                    }
                    await Task.Delay(500);
                }
                Assert.Fail(
                    $"the dispatched task did not complete. Recent logcat:\n{AndroidLab.Run("logcat", "-d", "-t", "200")}");
            }
            finally
            {
                // Stop the loop before the uninstall takes the process with
                // it: force-stop is the clean kill the runbook names.
                AndroidLab.Run("shell", "am", "force-stop", "rod.carrier");
                AndroidLab.Run("uninstall", "rod.carrier");
            }
        }
        finally
        {
            try { File.Delete(apkPath); } catch { }
        }
    }

    private static async Task<string?> WaitForOnlineAsync(TestEnv env, TimeSpan deadline)
    {
        var end = DateTimeOffset.UtcNow + deadline;
        while (DateTimeOffset.UtcNow < end)
        {
            try
            {
                var implants = await env.Http.GetFromJsonAsync<ImplantBody[]>(
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
        throw new TimeoutException(
            "the android carrier did not appear online. Recent logcat:\n" + AndroidLab.Run("logcat", "-d", "-t", "200"));
    }

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
                // The android cross is a cold cargo build the first time
                // (the whole dependency set for a new triple); the desktop
                // legs' warm minutes become tens of them here.
                Timeout = TimeSpan.FromMinutes(20),
            };
            await AuthenticatedHost.LoginAsync(env.Http);
            return env;
        }

        public async Task CreateEngagementAsync()
        {
            var createResponse = await Http.PostAsJsonAsync("/engagements",
                new EngagementEndpoints.CreateEngagementRequest(Name: "Operation Android Slice"));
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
