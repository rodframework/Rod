using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.Transport;
using Rod.Transport.Endpoints;

namespace Rod.Integration.Tests;

/// <summary>
/// A fact that runs only when a Rust toolchain (cargo) is on PATH: the
/// pipeline-build tests and the reference implant's legs need it.
/// </summary>
public sealed class RustFactAttribute : FactAttribute
{
    public RustFactAttribute()
    {
        try
        {
            var probe = Process.Start(new ProcessStartInfo
            {
                FileName = "cargo",
                ArgumentList = { "--version" },
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            probe?.WaitForExit(5000);
            if (probe is null || probe.ExitCode != 0)
                Skip = "cargo is not usable on PATH";
        }
        catch
        {
            Skip = "cargo is not on PATH";
        }
    }
}

/// <summary>
/// Acceptance for the Rust reference implant (architecture.md Sec 12.2): the
/// reach implant must ride the same wire the .NET reference rides. The test
/// stands up a real teamserver, mints a deployment credential, builds the
/// Rust implant with cargo, and runs it in its dev shape (ROD_* environment)
/// against the anonymous enroll listener -- then the acceptance is the full
/// round trip: it enrolls, goes online, and a dispatched shell.exec completes
/// with its output. Cross-implant interoperability is the product; this is
/// its proof for the second language.
/// </summary>
public class RustImplantEndToEndTests
{
    [RustFact]
    public async Task RustImplant_Enrols_GoesOnline_AndRunsTasking()
    {
        var rustDir = FindRustTree()
            ?? throw new InvalidOperationException("the Rust implant tree was not found from the test assembly");
        // The dev-shape binary: cargo release build of the checked-in tree.
        var build = Process.Start(new ProcessStartInfo
        {
            FileName = "cargo",
            WorkingDirectory = rustDir,
            ArgumentList = { "build", "--release" },
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        var buildOutput = (await build!.StandardOutput.ReadToEndAsync())
            + await build.StandardError.ReadToEndAsync();
        build.WaitForExit(300_000);
        Assert.True(build.ExitCode == 0, $"cargo build failed:\n{buildOutput}");
        var binary = Path.Combine(rustDir, "target", "release", "rod-implant");
        Assert.True(File.Exists(binary), $"cargo reported success but {binary} is missing");

        await using var env = await TestEnv.StartAsync();
        await env.CreateEngagementAsync();

        // The deployment credential: a manual mint (the rotation shape), spent
        // by the dev-shape enroll below.
        var mint = await env.Http.PostAsync(
            $"/engagements/{env.EngagementId}/deploy-tokens", content: null);
        mint.EnsureSuccessStatusCode();
        var token = await mint.Content.ReadFromJsonAsync<MintedToken>();
        Assert.False(string.IsNullOrEmpty(token?.Secret));

        var stderr = new StringBuilder();
        var start = new ProcessStartInfo
        {
            FileName = binary,
            UseShellExecute = false,
            RedirectStandardError = true,
        };
        start.Environment["ROD_ENROLL_URL"] = $"http://127.0.0.1:{env.HttpPort}/implants/enroll";
        start.Environment["ROD_DEPLOY_TOKEN"] = token!.Secret;
        // The fielded artifact is terminal-silent by default; the suite runs
        // verbose so a failed leg's stderr says why.
        start.Environment["ROD_VERBOSE"] = "1";
        start.Environment["ROD_SLEEP"] = "1";
        start.Environment["ROD_JITTER"] = "0";
        start.Environment["ROD_ENVELOPE"] = "none";
        start.Environment["ROD_VERBS"] = "shell.exec,fs.list,file.pull,beacon.sleep";
        using var process = Process.Start(start);
        Assert.NotNull(process);
        process!.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
        process.BeginErrorReadLine();

        try
        {
            // The first acceptance: the Rust implant enrolled and went live on
            // the roster, speaking the shared wire.
            var implantId = await WaitForOnlineAsync(env, TimeSpan.FromSeconds(60), stderr);
            Assert.False(string.IsNullOrEmpty(implantId));

            // The second acceptance: a dispatched task rides the wire down, the
            // Rust handler runs it, and the result rides back up.
            var marker = "rod-rust-smoke-" + Guid.NewGuid().ToString("N")[..8];
            var issued = await env.Http.PostAsJsonAsync(
                $"/engagements/{env.EngagementId}/tasks",
                new TaskEndpoints.IssueTaskRequest(implantId, "shell.exec", $"echo {marker}"));
            issued.EnsureSuccessStatusCode();
            var task = await issued.Content.ReadFromJsonAsync<TaskBody>();
            Assert.NotNull(task);

            var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
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
            Assert.Fail($"the dispatched task did not complete. Implant stderr:\n{stderr}");
        }
        finally
        {
            if (!process.HasExited)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                process.WaitForExit(5000);
            }
        }
    }

    [RustFact]
    public async Task RustImplant_BuildsThroughThePipeline_AndRunsFromTheBake()
        => await BuildRunAndRoundtripAsync("poll", "rod-rust-baked-");

    [RustFact]
    public async Task RustImplant_StreamsOverTheWebSocketBeacon_FromTheBake()
        => await BuildRunAndRoundtripAsync("stream", "rod-rust-stream-");

    [Fact]
    public async Task RustImplant_ExfilsARunPastTheContactBudget_OverThePollCycle()
    {
        // The upload arm's implant-side acceptance (ADR-010): a run larger
        // than one contact's exfil budget (8 MiB) spans POSTs -- the session
        // slices from the confirmed seam, the seam reports chain the
        // contacts, and the artifact lands whole with the declared hash.
        var rustDir = FindRustTree()
            ?? throw new InvalidOperationException("the Rust implant tree was not found from the test assembly");
        var build = Process.Start(new ProcessStartInfo
        {
            FileName = "cargo",
            WorkingDirectory = rustDir,
            ArgumentList = { "build", "--release" },
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        var buildOutput = (await build!.StandardOutput.ReadToEndAsync())
            + await build.StandardError.ReadToEndAsync();
        build.WaitForExit(300_000);
        Assert.True(build.ExitCode == 0, $"cargo build failed:\n{buildOutput}");
        var binary = Path.Combine(rustDir, "target", "release", "rod-implant");

        await using var env = await TestEnv.StartAsync();
        await env.CreateEngagementAsync();
        var mint = await env.Http.PostAsync(
            $"/engagements/{env.EngagementId}/deploy-tokens", content: null);
        mint.EnsureSuccessStatusCode();
        var token = await mint.Content.ReadFromJsonAsync<MintedToken>();

        var loot = Path.Combine(Path.GetTempPath(), "rod-rust-exfil-" + Guid.NewGuid().ToString("N") + ".bin");
        var content = new byte[9 * 1024 * 1024 + 123];
        Random.Shared.NextBytes(content);
        await File.WriteAllBytesAsync(loot, content);

        var stderr = new StringBuilder();
        var start = new ProcessStartInfo
        {
            FileName = binary,
            UseShellExecute = false,
            RedirectStandardError = true,
        };
        start.Environment["ROD_ENROLL_URL"] = $"http://127.0.0.1:{env.HttpPort}/implants/enroll";
        start.Environment["ROD_DEPLOY_TOKEN"] = token!.Secret;
        start.Environment["ROD_VERBOSE"] = "1";
        start.Environment["ROD_SLEEP"] = "1";
        start.Environment["ROD_JITTER"] = "0";
        start.Environment["ROD_ENVELOPE"] = "none";
        start.Environment["ROD_VERBS"] = "shell.exec,fs.list,file.pull,beacon.sleep";
        using var process = Process.Start(start);
        Assert.NotNull(process);
        process!.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
        process.BeginErrorReadLine();

        try
        {
            var implantId = await WaitForOnlineAsync(env, TimeSpan.FromSeconds(60), stderr);
            Assert.False(string.IsNullOrEmpty(implantId));

            var issued = await env.Http.PostAsJsonAsync(
                $"/engagements/{env.EngagementId}/tasks",
                new TaskEndpoints.IssueTaskRequest(implantId, "file.pull", loot));
            issued.EnsureSuccessStatusCode();
            var task = await issued.Content.ReadFromJsonAsync<TaskBody>();
            Assert.NotNull(task);

            // The run spans at least two contacts (9 MiB against the 8 MiB
            // budget); poll the artifact store until the terminal chunk
            // landed and verify the bytes whole.
            var artifacts = env.Host.Services.GetRequiredService<IArtifactStore>();
            var deadline = DateTimeOffset.UtcNow.AddSeconds(90);
            while (DateTimeOffset.UtcNow < deadline)
            {
                var stored = (await artifacts.ForTaskAsync(Guid.Parse(task!.TaskId)))
                    .FirstOrDefault(a => a.Name == Path.GetFileName(loot));
                if (stored is not null)
                {
                    Assert.Equal(content.Length, stored.Size);
                    Assert.Equal(content, stored.Content);
                    return;
                }
                await Task.Delay(500);
            }
            Assert.Fail($"the exfil run did not land. Implant stderr:\n{stderr}");
        }
        finally
        {
            if (!process.HasExited)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                process.WaitForExit(5000);
            }
            try { File.Delete(loot); } catch { }
        }
    }

    /// The full operable loop through the operator API at the given contact
    /// mode: a language "rust" build bakes the profile (sealed contacts on,
    /// the default posture) and mints the credential; the artifact downloads
    /// and runs in its fielded shape -- no arguments, no environment, the
    /// bake is the configuration. The sealed contact path (AES-256-GCM
    /// bodies under the per-artifact key, counter over the frames) rides
    /// whichever carriage the mode names: the POST cycle on poll, the
    /// WebSocket stream on stream.
    private static async Task BuildRunAndRoundtripAsync(string mode, string markerPrefix)
    {
        await using var env = await TestEnv.StartAsync();
        await env.CreateEngagementAsync();

        var front = await HttpFrontAsync(env);
        var built = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Language: "rust",
                Class: "Implant",
                TargetOs: "linux",
                TargetArch: "amd64",
                ListenerId: front,
                UriPath: null,
                SleepSeconds: 1.0,
                JitterSeconds: 0.0,
                KillDate: null,
                Mode: mode));
        Assert.True(built.IsSuccessStatusCode, await built.Content.ReadAsStringAsync());
        var artifact = await built.Content.ReadFromJsonAsync<ArtifactBody>();
        Assert.NotNull(artifact);

        var outDir = Path.Combine(Path.GetTempPath(), "rod-e2e-rust-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outDir);
        var binaryPath = Path.Combine(outDir, "rod-implant");
        Process? process = null;
        try
        {
            using (var download = await env.Http.GetAsync(
                $"/engagements/{artifact!.EngagementId}/payloads/{artifact.ArtifactId}"))
            {
                download.EnsureSuccessStatusCode();
                await File.WriteAllBytesAsync(binaryPath, await download.Content.ReadAsByteArrayAsync());
            }
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(binaryPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            var stderr = new StringBuilder();
            process = Process.Start(new ProcessStartInfo
            {
                FileName = binaryPath,
                UseShellExecute = false,
                RedirectStandardError = true,
                // The fielded artifact is terminal-silent by default; the
                // suite runs verbose so a failed leg's stderr says why.
                Environment = { ["ROD_VERBOSE"] = "1" },
            });
            Assert.NotNull(process);
            process!.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
            process.BeginErrorReadLine();

            var implantId = await WaitForOnlineAsync(env, TimeSpan.FromSeconds(90), stderr);
            Assert.False(string.IsNullOrEmpty(implantId));

            var marker = markerPrefix + Guid.NewGuid().ToString("N")[..8];
            var issued = await env.Http.PostAsJsonAsync(
                $"/engagements/{env.EngagementId}/tasks",
                new TaskEndpoints.IssueTaskRequest(implantId, "shell.exec", $"echo {marker}"));
            issued.EnsureSuccessStatusCode();
            var task = await issued.Content.ReadFromJsonAsync<TaskBody>();

            var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
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
            Assert.Fail($"the dispatched task did not complete. Implant stderr:\n{stderr}");
        }
        finally
        {
            if (process is { HasExited: false })
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                process.WaitForExit(5000);
            }
            process?.Dispose();
            try { Directory.Delete(outDir, recursive: true); } catch { }
        }
    }

    [RustFact]
    public async Task RustImplant_RunsAnInteractiveShell_OverTheWebSocketBeacon()
        => await InteractRoundtripAsync("stream");

    [RustFact]
    public async Task RustImplant_RunsAnInteractiveShell_OverThePollCycle()
        => await InteractRoundtripAsync("poll");

    [RustFact]
    public async Task RustImplant_BridgesAThroughTheForwardTunnel()
    {
        using var third = EchoHost.Start();
        await using var implant = await BuildRunAndAwaitOnlineAsync("stream");
        var env = implant.Env;

        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks",
            new TaskEndpoints.IssueTaskRequest(implant.ImplantId, "tunnel.forward", $"127.0.0.1 {third.Port}"));
        issued.EnsureSuccessStatusCode();
        var task = await issued.Content.ReadFromJsonAsync<TaskBody>();
        await WaitForTaskAsync(env, task!.TaskId,
            body => body.Status is "Dispatched" or "Completed",
            implant.Stderr, "the tunnel task's dispatch");

        // The relay bind: the tunnel's operator-side socket, so unmodified
        // tooling rides the channel without per-byte input posts.
        var bound = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks/{task.TaskId}/relay", new { });
        bound.EnsureSuccessStatusCode();
        var relay = await bound.Content.ReadFromJsonAsync<RelayBody>();

        using var tool = new TcpClient();
        await tool.ConnectAsync(IPAddress.Loopback, relay!.Port);
        var stream = tool.GetStream();
        await stream.WriteAsync(Encoding.UTF8.GetBytes("ping-through-the-tunnel"));
        var buffer = new byte[256];
        var read = await ReadWithDeadlineAsync(stream, buffer);
        Assert.Equal("ping-through-the-tunnel", Encoding.UTF8.GetString(buffer, 0, read));

        // eof half-closes the tunnel's implant side; the third host's close
        // completes the task with the relay summary.
        var closed = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks/{task.TaskId}/input", new { Eof = true });
        closed.EnsureSuccessStatusCode();
        var done = await WaitForTaskAsync(env, task.TaskId,
            body => body.Status == "Completed", implant.Stderr, "the forward tunnel's completion");
        Assert.Equal("Succeeded", done.Outcome);
        Assert.Contains("bytes up", done.Output);
        Assert.Contains("bytes down", done.Output);
    }

    [RustFact]
    public async Task RustImplant_ServesSocksAcrossManyConnections()
    {
        using var thirdOne = EchoHost.Start();
        using var thirdTwo = EchoHost.Start();
        await using var implant = await BuildRunAndAwaitOnlineAsync("stream");
        var env = implant.Env;

        // The proxy opens like any other task: no arguments, because every
        // destination arrives per connection.
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks",
            new TaskEndpoints.IssueTaskRequest(implant.ImplantId, "tunnel.socks", ""));
        issued.EnsureSuccessStatusCode();
        var task = await issued.Content.ReadFromJsonAsync<TaskBody>();
        await WaitForTaskAsync(env, task!.TaskId,
            body => body.Status is "Dispatched" or "Completed",
            implant.Stderr, "the socks task's dispatch");

        var bound = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks/{task.TaskId}/relay", new { });
        bound.EnsureSuccessStatusCode();
        var relay = await bound.Content.ReadFromJsonAsync<RelayBody>();

        // Two SOCKS clients to two different third hosts through the one
        // channel: the multiplexer must keep the connections apart.
        var one = await SocksConnectAsync(relay!.Port, "127.0.0.1", thirdOne.Port);
        var two = await SocksConnectAsync(relay.Port, "127.0.0.1", thirdTwo.Port);
        await one.WriteAsync(Encoding.UTF8.GetBytes("first"));
        await two.WriteAsync(Encoding.UTF8.GetBytes("second"));
        var buffer = new byte[256];
        Assert.Equal("first", Encoding.UTF8.GetString(buffer, 0, await ReadWithDeadlineAsync(one, buffer)));
        Assert.Equal("second", Encoding.UTF8.GetString(buffer, 0, await ReadWithDeadlineAsync(two, buffer)));
        one.Dispose();
        two.Dispose();

        // eof closes the proxy with the task; the summary is the proxy's
        // record of what it dialed and moved.
        var closed = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks/{task.TaskId}/input", new { Eof = true });
        closed.EnsureSuccessStatusCode();
        var done = await WaitForTaskAsync(env, task.TaskId,
            body => body.Status == "Completed", implant.Stderr, "the socks proxy's completion");
        Assert.Equal("Succeeded", done.Outcome);
        Assert.Contains("2 connections (0 refused)", done.Output);
    }

    [RustFact]
    public async Task RustImplant_EnrollsAndContactsOverRawTcp_PollShape()
    {
        // The socket family end to end: a runtime-created tcp listener owns
        // the socket, the bake dials it typed, and the whole lifecycle --
        // enrollment over the opening stream exchange, poll contacts one
        // connection each, tasking and results -- never touches HTTP.
        await using var implant = await BuildRunAndAwaitOnlineAsync(
            "poll", bindFront: env => TcpFrontAsync(env));
    }

    [RustFact]
    public async Task RustImplant_HoldsTheLiveSessionOverRawTcp_AndRunsTheInteractiveChannel()
    {
        await using var implant = await BuildRunAndAwaitOnlineAsync(
            "stream", bindFront: env => TcpFrontAsync(env));
        var env = implant.Env;

        // The held live session: the handshake's live advertisement switches
        // the connection, tasking pushes the moment it queues, and the
        // interactive channel runs over the same socket.
        var marker = "rod-tcp-live-" + Guid.NewGuid().ToString("N")[..8];
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks",
            new TaskEndpoints.IssueTaskRequest(implant.ImplantId, "shell.interact", $"echo {marker}"));
        issued.EnsureSuccessStatusCode();
        var task = await issued.Content.ReadFromJsonAsync<TaskBody>();

        await WaitForTaskAsync(env, task!.TaskId,
            body => body.Output?.Contains(marker) == true,
            implant.Stderr, "the live shell's first output");

        var closed = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks/{task.TaskId}/input", new { Eof = true });
        closed.EnsureSuccessStatusCode();
        var done = await WaitForTaskAsync(env, task.TaskId,
            body => body.Status == "Completed", implant.Stderr, "the live shell's completion");
        Assert.Equal("Succeeded", done.Outcome);
        Assert.Contains("shell exited", done.Output);
    }

    [RustFact]
    public async Task RustImplant_EnrollsAndContactsOverClassicDns()
    {
        // The datagram family end to end: a runtime-created dns listener owns
        // the UDP socket, the bake dials it typed, and the whole lifecycle --
        // the chunked enroll exchange, presence polls, a short-argument task,
        // the chunked result with its delivery confirmation -- rides TXT
        // queries under the zone.
        var zone = "e2e-dns.test";
        await using var implant = await BuildRunAndAwaitOnlineAsync(
            "poll", bindFront: env => DnsFrontAsync(env, zone));
        var env = implant.Env;

        var marker = "rod-dns-" + Guid.NewGuid().ToString("N")[..8];
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks",
            new TaskEndpoints.IssueTaskRequest(implant.ImplantId, "shell.exec", $"echo {marker}"));
        issued.EnsureSuccessStatusCode();
        var task = await issued.Content.ReadFromJsonAsync<TaskBody>();

        var done = await WaitForTaskAsync(env, task!.TaskId,
            body => body.Status == "Completed", implant.Stderr, "the DNS task's completion");
        Assert.Equal("Succeeded", done.Outcome);
        Assert.Contains(marker, done.Output);
    }

    [RustFact]
    public async Task RustImplant_EnrollsAndContactsOverWireGuard()
    {
        // The optional transport end to end (architecture.md Sec 8, Sec 15.3
        // ADR-004 as amended): a runtime-created wireguard listener owns the
        // UDP socket, the build mints the artifact's X25519 pair (the private
        // half baked with the listener's public half, the public half
        // registered as the router's peer), and the whole lifecycle -- the
        // in-band enrollment datagram, the sealed poll contacts, tasking and
        // results -- rides WireGuard-encrypted UDP, never touching TCP.
        await using var implant = await BuildRunAndAwaitOnlineAsync(
            "poll", bindFront: env => WireGuardFrontAsync(env), wireGuard: true);
        var env = implant.Env;

        var marker = "rod-wireguard-" + Guid.NewGuid().ToString("N")[..8];
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks",
            new TaskEndpoints.IssueTaskRequest(implant.ImplantId, "shell.exec", $"echo {marker}"));
        issued.EnsureSuccessStatusCode();
        var task = await issued.Content.ReadFromJsonAsync<TaskBody>();

        var done = await WaitForTaskAsync(env, task!.TaskId,
            body => body.Status == "Completed", implant.Stderr, "the wireguard task's completion");
        Assert.Equal("Succeeded", done.Outcome);
        Assert.Contains(marker, done.Output);
    }

    /// The egress walk's acceptance (architecture.md Sec 8): a burned front
    /// must not silence the implant. The artifact enrolls and contacts
    /// through the primary front, the primary's listener is then deleted
    /// (its port goes dark), and the next contact walks to the baked
    /// fallback front -- the same identity, tasking keeps flowing.
    [RustFact]
    public async Task RustImplant_WalksToTheFallbackFront_WhenThePrimaryBurns()
    {
        await using var env = await TestEnv.StartAsync();
        await env.CreateEngagementAsync();

        var primaryPort = TestSupport.GetFreeTcpPort();
        var fallbackPort = TestSupport.GetFreeTcpPort();
        var primary = await HttpFrontOnPortAsync(env, "walk-primary", primaryPort);
        await HttpFrontOnPortAsync(env, "walk-fallback", fallbackPort);

        var built = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Language: "rust",
                Class: "Implant",
                TargetOs: "linux",
                TargetArch: "amd64",
                ListenerId: primary,
                UriPath: null,
                SleepSeconds: 1.0,
                JitterSeconds: 0.0,
                KillDate: null,
                Mode: "poll",
                FallbackEndpoints: new List<string> { $"http://127.0.0.1:{fallbackPort}" }));
        Assert.True(built.IsSuccessStatusCode, await built.Content.ReadAsStringAsync());
        var artifact = await built.Content.ReadFromJsonAsync<ArtifactBody>();
        Assert.NotNull(artifact);

        var outDir = Path.Combine(Path.GetTempPath(), "rod-e2e-rust-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outDir);
        var binaryPath = Path.Combine(outDir, "rod-implant");
        Process? process = null;
        try
        {
            using (var download = await env.Http.GetAsync(
                $"/engagements/{artifact!.EngagementId}/payloads/{artifact.ArtifactId}"))
            {
                download.EnsureSuccessStatusCode();
                await File.WriteAllBytesAsync(binaryPath, await download.Content.ReadAsByteArrayAsync());
            }
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(binaryPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            var stderr = new StringBuilder();
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

            var implantId = await WaitForOnlineAsync(env, TimeSpan.FromSeconds(90), stderr);
            Assert.False(string.IsNullOrEmpty(implantId));

            // The primary carries the first round trip.
            var firstMarker = "rod-walk-primary-" + Guid.NewGuid().ToString("N")[..8];
            var first = await env.Http.PostAsJsonAsync(
                $"/engagements/{env.EngagementId}/tasks",
                new TaskEndpoints.IssueTaskRequest(implantId, "shell.exec", $"echo {firstMarker}"));
            first.EnsureSuccessStatusCode();
            var firstTask = await first.Content.ReadFromJsonAsync<TaskBody>();
            var firstDone = await WaitForTaskAsync(env, firstTask!.TaskId,
                body => body.Status == "Completed", stderr, "the primary-front round trip");
            Assert.Contains(firstMarker, firstDone.Output);

            // The burn: the primary listener is deleted and its port goes
            // dark; the implant's next contacts must refuse there. The
            // force flag overrides the dark-implants guard -- going dark is
            // exactly what this leg proves the walk survives.
            var burned = await env.Http.DeleteAsync(
                $"/engagements/{env.EngagementId}/listeners/{primary}?force=true");
            burned.EnsureSuccessStatusCode();

            // The walk: the failed contacts advance to the fallback front's
            // dial and the same identity completes the second task through
            // it -- the fallback serves contact, not enrollment alone.
            var fallbackMarker = "rod-walk-fallback-" + Guid.NewGuid().ToString("N")[..8];
            var second = await env.Http.PostAsJsonAsync(
                $"/engagements/{env.EngagementId}/tasks",
                new TaskEndpoints.IssueTaskRequest(implantId, "shell.exec", $"echo {fallbackMarker}"));
            second.EnsureSuccessStatusCode();
            var secondTask = await second.Content.ReadFromJsonAsync<TaskBody>();
            var secondDone = await WaitForTaskAsync(env, secondTask!.TaskId,
                body => body.Status == "Completed", stderr, "the fallback-front round trip");
            Assert.Equal("Succeeded", secondDone.Outcome);
            Assert.Contains(fallbackMarker, secondDone.Output);
        }
        finally
        {
            if (process is { HasExited: false })
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                process.WaitForExit(5000);
            }
            process?.Dispose();
            try { Directory.Delete(outDir, recursive: true); } catch { }
        }
    }

    /// Creates the engagement's runtime http listener on the given loopback
    /// port -- the leg needs the number it dials, both to burn the primary
    /// and to type the fallback's dial.
    private static async Task<string> HttpFrontOnPortAsync(TestEnv env, string name, int port)
    {
        var created = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/listeners",
            new Rod.Transport.Endpoints.ListenerEndpoints.CreateListenerRequest(
                Name: name,
                Transport: "http",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"http://127.0.0.1:{port}"));
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        return (await created.Content.ReadFromJsonAsync<Rod.Transport.Endpoints.ListenerEndpoints.ListenerResponse>())!.Id;
    }

    /// Creates the engagement's runtime dns listener on a free loopback port
    /// and returns its id for the build to name -- the parser resolves the
    /// typed dns dial (the bind as the resolver, the record's zone) from the
    /// listener itself.
    private static async Task<string> DnsFrontAsync(TestEnv env, string zone)
    {
        var port = TestSupport.GetFreeUdpPort();
        var created = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/listeners",
            new Rod.Transport.Endpoints.ListenerEndpoints.CreateListenerRequest(
                Name: "e2e-dns",
                Transport: "dns",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: zone));
        created.EnsureSuccessStatusCode();
        return (await created.Content.ReadFromJsonAsync<Rod.Transport.Endpoints.ListenerEndpoints.ListenerResponse>())!.Id;
    }

    /// Creates the engagement's runtime tcp listener on a free loopback port
    /// and returns its id for the build to name -- the operator path an
    /// engagement's own socket takes (bind-then-register, the public
    /// endpoint the bare host:port implants dial).
    private static async Task<string> TcpFrontAsync(TestEnv env)
    {
        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/listeners",
            new Rod.Transport.Endpoints.ListenerEndpoints.CreateListenerRequest(
                Name: "e2e-tcp",
                Transport: "tcp",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"127.0.0.1:{port}"));
        created.EnsureSuccessStatusCode();
        return (await created.Content.ReadFromJsonAsync<Rod.Transport.Endpoints.ListenerEndpoints.ListenerResponse>())!.Id;
    }

    /// The wireguard listener's fixed name -- the deployment-shape coupling
    /// between a listener and its provisioned server key (the name is the
    /// key's slot under WireGuard:ListenerKeys).
    private const string WireGuardFrontName = "e2e-wireguard";

    /// Creates the engagement's runtime wireguard listener on a free loopback
    /// UDP port -- against the server key the test env provisioned under the
    /// listener's fixed name, the deployment shape.
    private static async Task<string> WireGuardFrontAsync(TestEnv env)
    {
        var port = TestSupport.GetFreeUdpPort();
        var created = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/listeners",
            new Rod.Transport.Endpoints.ListenerEndpoints.CreateListenerRequest(
                Name: WireGuardFrontName,
                Transport: "wireguard",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"127.0.0.1:{port}"));
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        return (await created.Content.ReadFromJsonAsync<Rod.Transport.Endpoints.ListenerEndpoints.ListenerResponse>())!.Id;
    }

    /// Creates the engagement's runtime http listener on a free loopback
    /// port and returns its id for the build to name: every web front is a
    /// listener record, and the baked dial resolves from the record.
    private static async Task<string> HttpFrontAsync(TestEnv env)
        => await WebFrontAsync(env, "http");

    /// The TLS twin: the front whose leaf must carry a SAN naming the dialed
    /// host, or the implant's rustls client (full webpki validation, the
    /// baked CA as the only root) aborts the handshake on name matching --
    /// the field failure this leg exists to guard against.
    private static async Task<string> HttpsFrontAsync(TestEnv env)
        => await WebFrontAsync(env, "https");

    private static async Task<string> WebFrontAsync(TestEnv env, string transport)
    {
        var port = TestSupport.GetFreeTcpPort();
        var created = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/listeners",
            new Rod.Transport.Endpoints.ListenerEndpoints.CreateListenerRequest(
                Name: $"e2e-{transport}",
                Transport: transport,
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"{transport}://127.0.0.1:{port}"));
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        return (await created.Content.ReadFromJsonAsync<Rod.Transport.Endpoints.ListenerEndpoints.ListenerResponse>())!.Id;
    }

    /// The TLS front end to end: enrollment and contacts over the https
    /// listener whose leaf the engagement CA issues on demand.
    [RustFact]
    public async Task RustImplant_EnrollsOverTheHttpsFront()
        => await BuildRunAndAwaitOnlineAsync(
            "poll", bindFront: env => HttpsFrontAsync(env));

    /// The interactive shell through a baked artifact at the named contact
    /// mode: the task opens the channel with its initial command, the
    /// transcript goes live before any completion, typed input crosses as
    /// channel input, and eof closes the shell through an ordinary result.
    /// Poll mode exercises the degraded discipline end to end -- the
    /// channels.poll advertisement, server-side parking, and per-cycle
    /// drain -- while stream mode rides the live sink and the tick flush.
    private static async Task InteractRoundtripAsync(string mode)
    {
        await using var implant = await BuildRunAndAwaitOnlineAsync(mode);
        var env = implant.Env;
        var marker = "rod-interact-open-" + Guid.NewGuid().ToString("N")[..8];
        var typed = "rod-interact-typed-" + Guid.NewGuid().ToString("N")[..8];

        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks",
            new TaskEndpoints.IssueTaskRequest(implant.ImplantId, "shell.interact", $"echo {marker}"));
        issued.EnsureSuccessStatusCode();
        var task = await issued.Content.ReadFromJsonAsync<TaskBody>();

        await WaitForTaskAsync(env, task!.TaskId,
            body => body.Output?.Contains(marker) == true,
            implant.Stderr, "the shell's first output");

        var sent = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks/{task.TaskId}/input",
            new { Data = Encoding.UTF8.GetBytes($"echo {typed}\n") });
        sent.EnsureSuccessStatusCode();
        await WaitForTaskAsync(env, task.TaskId,
            body => body.Output?.Contains(typed) == true,
            implant.Stderr, "the typed command's output");

        var closed = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/tasks/{task.TaskId}/input", new { Eof = true });
        closed.EnsureSuccessStatusCode();
        var done = await WaitForTaskAsync(env, task.TaskId,
            body => body.Status == "Completed", implant.Stderr, "the shell's completion");
        Assert.Equal("Succeeded", done.Outcome);
        Assert.Contains("shell exited", done.Output);
    }

    /// A built-and-running baked artifact plus its live teamserver: the
    /// shared harness of the channel legs.
    private sealed class RunningRust : IAsyncDisposable
    {
        public required TestEnv Env { get; init; }
        public required string ImplantId { get; init; }
        public required Process Process { get; init; }
        public required StringBuilder Stderr { get; init; }
        public required string OutDir { get; init; }

        public async ValueTask DisposeAsync()
        {
            if (!Process.HasExited)
            {
                try { Process.Kill(entireProcessTree: true); } catch { }
                Process.WaitForExit(5000);
            }
            Process.Dispose();
            await Env.DisposeAsync();
            try { Directory.Delete(OutDir, recursive: true); } catch { }
        }
    }

    /// Builds the artifact through the operator API at the given contact
    /// mode, runs it in its fielded shape, and waits for the roster to show
    /// it online -- the channel legs' shared prefix. The build names its
    /// front as a listener record (the only web/socket shape the contract
    /// accepts since the typed dial narrowed to the DNS family); the parser
    /// resolves each family's dial from the record. The wireguard flag
    /// provisions the optional transport's deployment facts on the env (the
    /// enable switch and the test listener's server key).
    private static async Task<RunningRust> BuildRunAndAwaitOnlineAsync(
        string mode, Func<TestEnv, Task<string>>? bindFront = null, bool wireGuard = false)
    {
        var env = await TestEnv.StartAsync(wireGuard);
        try
        {
            await env.CreateEngagementAsync();
            var front = bindFront is null ? await HttpFrontAsync(env) : await bindFront(env);
            var built = await env.Http.PostAsJsonAsync(
                $"/engagements/{env.EngagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Language: "rust",
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    ListenerId: front,
                    UriPath: null,
                    SleepSeconds: 1.0,
                    JitterSeconds: 0.0,
                    KillDate: null,
                    Mode: mode));
            Assert.True(built.IsSuccessStatusCode, await built.Content.ReadAsStringAsync());
            var artifact = await built.Content.ReadFromJsonAsync<ArtifactBody>();
            Assert.NotNull(artifact);

            var outDir = Path.Combine(Path.GetTempPath(), "rod-e2e-rust-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(outDir);
            var binaryPath = Path.Combine(outDir, "rod-implant");
            using (var download = await env.Http.GetAsync(
                $"/engagements/{artifact!.EngagementId}/payloads/{artifact.ArtifactId}"))
            {
                download.EnsureSuccessStatusCode();
                await File.WriteAllBytesAsync(binaryPath, await download.Content.ReadAsByteArrayAsync());
            }
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(binaryPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            var stderr = new StringBuilder();
            var process = Process.Start(new ProcessStartInfo
            {
                FileName = binaryPath,
                UseShellExecute = false,
                RedirectStandardError = true,
                // The fielded artifact is terminal-silent by default; the
                // suite runs verbose so a failed leg's stderr says why.
                Environment = { ["ROD_VERBOSE"] = "1" },
            });
            Assert.NotNull(process);
            process!.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
            process.BeginErrorReadLine();

            var implantId = await WaitForOnlineAsync(env, TimeSpan.FromSeconds(90), stderr);
            return new RunningRust
            {
                Env = env,
                ImplantId = implantId,
                Process = process,
                Stderr = stderr,
                OutDir = outDir,
            };
        }
        catch
        {
            await env.DisposeAsync();
            throw;
        }
    }

    private static async Task<TaskBody> WaitForTaskAsync(
        TestEnv env, string taskId, Func<TaskBody, bool> done, StringBuilder stderr, string awaiting)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(90);
        TaskBody? last = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            var read = await env.Http.GetFromJsonAsync<TaskBody>(
                $"/engagements/{env.EngagementId}/tasks/{taskId}");
            if (read is not null)
                last = read;
            if (read is not null && done(read))
                return read;
            await Task.Delay(500);
        }
        Assert.Fail(
            $"timed out waiting for {awaiting}. Task status: {last?.Status} {last?.Outcome} {last?.Output}. Implant stderr:\n{stderr}");
        throw new InvalidOperationException("unreachable");
    }

    private sealed record RelayBody
    {
        public string TaskId { get; set; } = "";
        public string Host { get; set; } = "";
        public int Port { get; set; }
    }

    /// The third host of the tunnel legs: a loopback listener that echoes
    /// every byte back until its peer closes.
    private sealed class EchoHost : IDisposable
    {
        private readonly TcpListener _listener;

        private EchoHost(TcpListener listener, int port)
        {
            _listener = listener;
            Port = port;
        }

        public int Port { get; }

        public static EchoHost Start()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var host = new EchoHost(listener, ((IPEndPoint)listener.LocalEndpoint).Port);
            _ = host.ServeAsync();
            return host;
        }

        private async Task ServeAsync()
        {
            while (true)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync();
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    return;
                }
                _ = ServeOneAsync(client);
            }
        }

        private static async Task ServeOneAsync(TcpClient client)
        {
            using (client)
            {
                var buffer = new byte[16 * 1024];
                var stream = client.GetStream();
                while (true)
                {
                    int read;
                    try
                    {
                        read = await stream.ReadAsync(buffer);
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                    {
                        return;
                    }
                    if (read <= 0)
                        return;
                    await stream.WriteAsync(buffer.AsMemory(0, read));
                }
            }
        }

        public void Dispose() => _listener.Stop();
    }

    /// The minimal SOCKS5 client a browser implements: no-auth greeting,
    /// CONNECT with a domain-shaped address, then a byte stream.
    private static async Task<NetworkStream> SocksConnectAsync(int proxyPort, string host, int port)
    {
        var tool = new TcpClient();
        await tool.ConnectAsync(IPAddress.Loopback, proxyPort);
        var stream = tool.GetStream();

        await stream.WriteAsync(new byte[] { 5, 1, 0 });
        var method = new byte[2];
        await ReadExactlyAsync(stream, method);
        Assert.Equal(5, method[0]);
        Assert.Equal(0, method[1]);

        var name = Encoding.ASCII.GetBytes(host);
        var request = new List<byte> { 5, 1, 0, 3, (byte)name.Length };
        request.AddRange(name);
        request.Add((byte)(port >> 8));
        request.Add((byte)port);
        await stream.WriteAsync(request.ToArray());

        var reply = new byte[10];
        await ReadExactlyAsync(stream, reply);
        Assert.Equal(0, reply[1]); // the dial's result, through the implant
        return stream;
    }

    private static async Task<int> ReadWithDeadlineAsync(NetworkStream stream, byte[] buffer)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            return await stream.ReadAsync(buffer, deadline.Token);
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException("the tunnel did not answer within 30s");
        }
    }

    private static async Task ReadExactlyAsync(NetworkStream stream, byte[] buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var read = await stream.ReadAsync(buffer.AsMemory(offset), deadline.Token);
            if (read <= 0)
                throw new IOException("the peer closed early");
            offset += read;
        }
    }

    private sealed record ArtifactBody
    {
        public string ArtifactId { get; set; } = "";
        public string EngagementId { get; set; } = "";
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
        throw new TimeoutException("the Rust implant did not appear online. Stderr:\n" + stderr);
    }

    private static string? FindRustTree()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "src", "implant", "rust");
            if (Directory.Exists(candidate) && Directory.Exists(Path.Combine(dir.FullName, "src", "teamserver")))
                return candidate;
            dir = dir.Parent;
        }
        return null;
    }

    private sealed record MintedToken(string Secret);

    private sealed record TaskBody
    {
        public string TaskId { get; set; } = "";
        public string Status { get; set; } = "";
        public string? Outcome { get; set; }
        public string? Output { get; set; }
    }

    /// <summary>
    /// A real Kestrel teamserver with the plain-HTTP operator/enroll API and
    /// the implant endpoint, logged in; the end-to-end harness shape.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;
        public int HttpPort { get; private set; }

        public static async Task<TestEnv> StartAsync(bool wireGuard = false)
        {
            var env = new TestEnv();
            env.HttpPort = TestSupport.GetFreeTcpPort();

            var config = AuthenticatedHost.BuildConfig(settings =>
            {
                if (!wireGuard)
                    return;
                // The optional transport's deployment facts: the enable
                // switch and the fixed-name listener's provisioned server
                // key -- the shape WireGuardFrontAsync's create reads.
                settings["WireGuard:Enabled"] = "true";
                settings[$"WireGuard:ListenerKeys:{WireGuardFrontName}"] =
                    Convert.ToBase64String(WireGuardTestClient.SeededKey(41));
            });
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
                    // No startup listeners of its own, but the empty call
                    // still activates the Kestrel half of runtime listener
                    // management -- the web fronts the legs name bind as
                    // dynamic endpoints, which never open without it.
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
                new EngagementEndpoints.CreateEngagementRequest(Name: "Operation Rust Slice"));
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
