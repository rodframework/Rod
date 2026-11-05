using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Rod.Audit;
using Rod.Capabilities.Lifecycle;
using Rod.CoreState;
using Rod.CoreState.Implants;
using Rod.Capabilities.Registry;
using Rod.Conformance;
using Rod.Packaging;
using Rod.Transport.Endpoints;

namespace Rod.Integration.Tests;

/// <summary>
/// The official listener packages' acceptance (todo.md's top queue item,
/// ADR-025): both reference implants' e2e legs pass against the official
/// packages over the bridge -- the same legs the in-tree families serve
/// today. Each leg rides the real chain: the package resolved through the
/// pinned-source contract, built by its own build script, packed and
/// signed, installed through the module lifecycle into the host's store,
/// and bound as a package-backed listener; the implant is the reference
/// Rust or Go tree's own build; the observations are the operator API the
/// suites drive.
/// </summary>
public class OfficialListenerPackageEndToEndTests
{
    // The legs need the real packages and the real implant toolchains; the
    // suites' own fact attributes answer toolchain availability, and the
    // packages resolve loudly when absent.
    private static readonly Lazy<string> HttpsPackage = new(() =>
    {
        var root = Rod.BuildPipeline.PayloadBuild.PinnedListenerSource.LocateHttpsPackage()
            ?? throw new InvalidOperationException(
                "the rod-listener-https package did not resolve -- point ROD_LISTENER_HTTPS_DIR at its checkout");
        BuildPackage(root, TestCell.Os == "macos" ? "darwin" : TestCell.Os, TestCell.Arch);
        return root;
    });

    private static readonly Lazy<string> DohPackage = new(() =>
    {
        var root = Rod.BuildPipeline.PayloadBuild.PinnedListenerSource.LocateDohPackage()
            ?? throw new InvalidOperationException(
                "the rod-listener-doh package did not resolve -- point ROD_LISTENER_DOH_DIR at its checkout");
        BuildPackage(root, "", "");
        return root;
    });

    // One package build per test-class run: the https package names its
    // own (os, arch) cell -- macos spells itself darwin where the
    // cross-compile ecosystem is concerned -- and the doh package builds
    // its one framework-dependent tree.
    private static void BuildPackage(string root, string os, string arch)
    {
        Console.WriteLine($"building the package at {root}");
        var script = Path.Combine(root, "build.sh");
        var start = new ProcessStartInfo
        {
            FileName = "/bin/sh",
            WorkingDirectory = root,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(script);
        if (os.Length > 0)
        {
            start.ArgumentList.Add(os);
            start.ArgumentList.Add(arch);
        }
        using var build = Process.Start(start)
            ?? throw new InvalidOperationException($"build.sh did not start for {root}");
        var output = build.StandardOutput.ReadToEndAsync();
        var errors = build.StandardError.ReadToEndAsync();
        if (!build.WaitForExit(300_000))
        {
            try { build.Kill(entireProcessTree: true); } catch { }
            Assert.Fail($"build.sh did not finish within 300 s:\n{output.Result}\n{errors.Result}");
        }
        Assert.True(build.ExitCode == 0, $"build.sh failed:\n{output.Result}\n{errors.Result}");
    }

    // One host's install chain: pack and sign the package exactly as a
    // publisher's shell would, register it in a local registry, and let the
    // lifecycle service verify, adopt, and pin it into the host's module
    // store -- the same chain the candidate acceptance leg rides.
    private static async Task InstallAsync(System.IServiceProvider services, string packageRoot, string root)
    {
        var publisherKeys = Ed25519.GenerateKeyPair();
        var zip = Path.Combine(root, "dist", Path.GetFileName(packageRoot.TrimEnd('/')) + ".zip");
        Directory.CreateDirectory(Path.GetDirectoryName(zip)!);
        var (manifest, _) = ManifestToml.LoadFile(Path.Combine(packageRoot, ManifestToml.FileName));
        // The signature covers exactly what the package carries: the same
        // selection the zip holds, so the install side's re-derivation from
        // the extracted files matches byte for byte.
        var selection = ModulePackage.SelectFiles(packageRoot, manifest!.Package);
        var (_, sha256) = await ModulePackage.WriteZipAsync(selection, zip);
        var digests = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var relative in selection.Files.Where(f => f != ManifestToml.FileName))
            digests[relative] = Convert.ToHexStringLower(
                System.Security.Cryptography.SHA256.HashData(
                    File.ReadAllBytes(Path.Combine(packageRoot, relative))));
        var canonical = CanonicalForm.Build(manifest!, digests);
        var signature = Convert.ToBase64String(
            Ed25519.Sign(publisherKeys.SecretKey, System.Text.Encoding.UTF8.GetBytes(canonical)));

        var registryRoot = Path.Combine(root, "registry");
        Directory.CreateDirectory(Path.Combine(registryRoot, "modules"));
        var entry = new RegistryEntry(
            manifest!.Name, "listener", manifest.Description ?? "", manifest.License, null,
            new RegistryEntry.OpsecInfo(manifest.Opsec.LandsOnDisk, manifest.Opsec.Notes), [], [])
            with
        {
            Versions =
                [
                    new RegistryVersion(
                        manifest.Version.ToString(), DateTimeOffset.UtcNow.ToString("O"), zip, sha256,
                        signature, Convert.ToBase64String(publisherKeys.PublicKey),
                        Ed25519.Fingerprint(publisherKeys.PublicKey),
                        new RegistryVersion.CompatibilityInfo("1.0.0", [])),
                ],
        };
        await File.WriteAllTextAsync(
            Path.Combine(registryRoot, "modules", manifest.Name + ".json"), RegistryJson.SaveEntry(entry));

        var lifecycle = services.GetRequiredService<ModuleLifecycleService>();
        await lifecycle.InstallFromRegistryAsync(
            new ModuleRegistryClient(registryRoot), manifest.Name, operatorId: Guid.NewGuid());
    }

    private static async Task<RustImplantEndToEndTests.TestEnv> StartRustEnvAsync(string packageRoot)
    {
        var root = Path.Combine(Path.GetTempPath(), "rod-official-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var env = await RustImplantEndToEndTests.TestEnv.StartAsync(modulesStore: Path.Combine(root, "store"));
        await env.CreateEngagementAsync();
        await InstallAsync(env.Host.Services, packageRoot, root);
        return env;
    }

    private static async Task<GoImplantEndToEndTests.TestEnv> StartGoEnvAsync(string packageRoot)
    {
        var root = Path.Combine(Path.GetTempPath(), "rod-official-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var env = await GoImplantEndToEndTests.TestEnv.StartAsync(modulesStore: Path.Combine(root, "store"));
        await env.CreateEngagementAsync();
        await InstallAsync(env.Host.Services, packageRoot, root);
        return env;
    }

    private sealed record PackageFront(string Id, int Port);

    // The package-backed front the legs dial, bound through the operator
    // API the way an operator binds it: one https-package listener on a
    // free loopback port, http or https by the leg's posture. The bind
    // parameter is the medium's own; the kernel opens no socket of its own.
    private static Task<PackageFront> HttpsFrontAsync(
        RustImplantEndToEndTests.TestEnv env, string scheme)
        => HttpsFrontAsync(env.Http, env.EngagementId!, scheme);

    private static Task<PackageFront> HttpsFrontAsync(
        GoImplantEndToEndTests.TestEnv env, string scheme)
        => HttpsFrontAsync(env.Http, env.EngagementId!, scheme);

    private static async Task<PackageFront> HttpsFrontAsync(
        System.Net.Http.HttpClient http, string engagementId, string scheme)
    {
        var port = TestSupport.GetFreeTcpPort();
        var created = await http.PostAsJsonAsync(
            $"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "official-https",
                Transport: "rod-listener-https",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"{scheme}://127.0.0.1:{port}",
                Trust: null,
                Package: "rod-listener-https",
                PackageVersion: null,
                Params: new Dictionary<string, string> { ["bind"] = $"127.0.0.1:{port}" }));
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.Equal("running", listener!.State);
        await WaitUntilPortAcceptsAsync(port);
        return new PackageFront(listener.Id, port);
    }

    // The medium front's bind is the package process's own; the spawn's
    // acknowledgment (the state badge) precedes the process's first listen
    // by its boot time, so the legs wait for the socket the way the
    // acceptance leg waits for the candidate's.
    private static async Task WaitUntilPortAcceptsAsync(int port)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(20);
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                using var probe = new System.Net.Sockets.TcpClient();
                await probe.ConnectAsync(System.Net.IPAddress.Loopback, port);
                return;
            }
            catch (System.Net.Sockets.SocketException)
            {
            }
            await Task.Delay(200);
        }
        Assert.Fail($"the package process never bound port {port}");
    }

    // The doh package's front, the DNS family's own dial shape: the public
    // endpoint is the zone its queries answer under, and the faces the
    // medium parameters bind.
    private static Task<PackageFront> DohFrontAsync(
        RustImplantEndToEndTests.TestEnv env, string zone, string? udpBind, string? httpBind)
        => DohFrontAsync(env.Http, env.EngagementId!, zone, udpBind, httpBind);

    private static async Task<PackageFront> DohFrontAsync(
        System.Net.Http.HttpClient http, string engagementId, string zone, string? udpBind, string? httpBind)
    {
        var parameters = new Dictionary<string, string>();
        var port = 0;
        if (udpBind is not null)
        {
            port = TestSupport.GetFreeUdpPort();
            parameters["udp-bind"] = $"127.0.0.1:{port}";
        }
        if (httpBind is not null)
        {
            port = TestSupport.GetFreeTcpPort();
            parameters["http-bind"] = $"127.0.0.1:{port}";
        }
        var created = await http.PostAsJsonAsync(
            $"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "official-doh",
                Transport: "rod-listener-doh",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: zone,
                Trust: null,
                Package: "rod-listener-doh",
                PackageVersion: null,
                Params: parameters));
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.Equal("running", listener!.State);
        if (httpBind is not null)
            await WaitUntilPortAcceptsAsync(port);
        return new PackageFront(listener.Id, port);
    }

    // --- The https package: the reference implants' web legs over the bridge.

    [RustFact]
    public async Task HttpPackage_CarriesTheRustBake_EnrollAndTasking()
    {
        _ = HttpsPackage.Value;
        await using var env = await StartRustEnvAsync(HttpsPackage.Value);
        await RustImplantEndToEndTests.BuildRunAndRoundtripAsync(
            "poll", "rod-https-package-", bindFront: async e => (await HttpsFrontAsync(e, "http")).Id, host: env);
    }

    [RustFact]
    public async Task HttpPackage_CarriesTheRustBake_OverTheWebSocketStream()
    {
        _ = HttpsPackage.Value;
        await using var env = await StartRustEnvAsync(HttpsPackage.Value);
        // The live session's arm: the package upgrades the WebSocket
        // in-process and carries the messages as the bridge's session
        // units -- the kernel pushes tasking unprompted down the same
        // stream.
        await RustImplantEndToEndTests.BuildRunAndRoundtripAsync(
            "stream", "rod-https-package-stream-", bindFront: async e => (await HttpsFrontAsync(e, "http")).Id, host: env);
    }

    [RustFact]
    public async Task HttpPackage_CarriesTheInteractiveShell_OverTheWebSocketBeacon()
    {
        _ = HttpsPackage.Value;
        await using var env = await StartRustEnvAsync(HttpsPackage.Value);
        await RustImplantEndToEndTests.InteractRoundtripAsync(
            "stream", bindFront: async e => (await HttpsFrontAsync(e, "http")).Id, host: env);
    }

    [RustFact]
    public async Task HttpPackage_FrontsTlsWithTheEngagementLeaf()
    {
        _ = HttpsPackage.Value;
        await using var env = await StartRustEnvAsync(HttpsPackage.Value);
        // The TLS twin: the front's leaf must carry a SAN naming the dialed
        // host, or the implant's rustls client (full webpki validation, the
        // baked CA as the only root) aborts the handshake -- the field
        // failure this leg exists to guard against, now proven against the
        // leaf the supervisor handed the package's process.
        await RustImplantEndToEndTests.BuildRunAndRoundtripAsync(
            "poll", "rod-https-package-tls-", bindFront: async e => (await HttpsFrontAsync(e, "https")).Id, host: env);
    }

    [GoFact]
    public async Task HttpPackage_CarriesTheGoImplant_EnrollTaskingAndExfil()
    {
        _ = HttpsPackage.Value;
        var goDir = GoImplantEndToEndTests.FindGoTree()
            ?? throw new InvalidOperationException("the Go implant tree was not found from the test assembly");
        var binary = Path.Combine(
            Path.GetTempPath(), "rod-go-official-" + Guid.NewGuid().ToString("N") + TestCell.ExeSuffix);
        var start = new ProcessStartInfo
        {
            FileName = "go",
            WorkingDirectory = goDir,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("build");
        start.ArgumentList.Add("-o");
        start.ArgumentList.Add(binary);
        start.ArgumentList.Add(".");
        using var build = Process.Start(start)!;
        var buildOutput = (await build.StandardOutput.ReadToEndAsync())
            + await build.StandardError.ReadToEndAsync();
        build.WaitForExit(300_000);
        Assert.True(build.ExitCode == 0, $"go build failed:\n{buildOutput}");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(binary,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        await using var env = await StartGoEnvAsync(HttpsPackage.Value);
        var front = await HttpsFrontAsync(env, "http");

        var mint = await env.Http.PostAsync(
            $"/engagements/{env.EngagementId}/deploy-tokens", content: null);
        mint.EnsureSuccessStatusCode();
        var token = await mint.Content.ReadFromJsonAsync<GoImplantEndToEndTests.MintedToken>();
        Assert.False(string.IsNullOrEmpty(token?.Secret));

        var loot = Path.Combine(Path.GetTempPath(), "rod-go-official-" + Guid.NewGuid().ToString("N") + ".bin");
        var content = new byte[9 * 1024 * 1024 + 123];
        Random.Shared.NextBytes(content);
        await File.WriteAllBytesAsync(loot, content);

        var (process, stderr) = GoImplantEndToEndTests.Start(binary, new Dictionary<string, string>
        {
            // The enroll dial points at the package's own front, not the
            // operator tier: the kernel's Kestrel never sees the implant.
            ["ROD_ENROLL_URL"] = $"http://127.0.0.1:{front.Port}/implants/enroll",
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
            var implantId = await GoImplantEndToEndTests.WaitForOnlineAsync(
                env, TimeSpan.FromSeconds(60), stderr);

            var marker = "rod-go-official-" + Guid.NewGuid().ToString("N")[..8];
            var echo = await GoImplantEndToEndTests.IssueAsync(env, implantId, "shell.exec", $"echo {marker}");
            var done = await GoImplantEndToEndTests.WaitForTaskAsync(
                env, echo.TaskId, TimeSpan.FromSeconds(60), stderr);
            Assert.Equal("Succeeded", done.Outcome);
            Assert.Contains(marker, done.Output);

            var pull = await GoImplantEndToEndTests.IssueAsync(env, implantId, "file.pull", loot);
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
            GoImplantEndToEndTests.Kill(process);
            try { File.Delete(loot); } catch { }
            try { File.Delete(binary); } catch { }
        }
    }

    [GoFact]
    public async Task HttpPackage_CarriesTheGoBake()
    {
        _ = HttpsPackage.Value;
        await using var env = await StartGoEnvAsync(HttpsPackage.Value);
        var front = await HttpsFrontAsync(env, "http");

        // The pipeline build: the Go unit bakes the profile -- sealed
        // contacts on, the default posture -- against the package-backed
        // front's record, and the artifact runs in its fielded shape.
        var built = await env.Http.PostAsJsonAsync(
            $"/engagements/{env.EngagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Unit: "rod-go",
                Class: "Implant",
                TargetOs: TestCell.Os,
                TargetArch: TestCell.Arch,
                ListenerId: front.Id,
                UriPath: null,
                SleepSeconds: 1.0,
                JitterSeconds: 0.0,
                KillDate: null));
        Assert.True(built.IsSuccessStatusCode, await built.Content.ReadAsStringAsync());
        var artifact = await built.Content.ReadFromJsonAsync<GoImplantEndToEndTests.BuildBody>();
        Assert.NotNull(artifact);

        var outDir = Path.Combine(Path.GetTempPath(), "rod-go-official-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outDir);
        var binaryPath = Path.Combine(outDir, "rod-implant" + TestCell.ExeSuffix);
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

            var (process, stderr) = GoImplantEndToEndTests.Start(
                binaryPath, new Dictionary<string, string> { ["ROD_VERBOSE"] = "1" });
            try
            {
                var implantId = await GoImplantEndToEndTests.WaitForOnlineAsync(
                    env, TimeSpan.FromSeconds(90), stderr);

                var marker = "rod-go-official-baked-" + Guid.NewGuid().ToString("N")[..8];
                var echo = await GoImplantEndToEndTests.IssueAsync(env, implantId, "shell.exec", $"echo {marker}");
                var done = await GoImplantEndToEndTests.WaitForTaskAsync(
                    env, echo.TaskId, TimeSpan.FromSeconds(60), stderr);
                Assert.Equal("Succeeded", done.Outcome);
                Assert.Contains(marker, done.Output);
            }
            finally
            {
                GoImplantEndToEndTests.Kill(process);
            }
        }
        finally
        {
            try { Directory.Delete(outDir, recursive: true); } catch { }
        }
    }

    // --- The doh package: the DNS grammar's legs over the bridge.

    [RustFact]
    public async Task DohPackage_CarriesTheClassicDnsLeg()
    {
        _ = DohPackage.Value;
        await using var env = await StartRustEnvAsync(DohPackage.Value);
        // The datagram family end to end over the official package: the
        // chunked enroll exchange, presence polls, a short-argument task,
        // and the chunked result with its delivery confirmation, all riding
        // TXT queries under the zone -- the package's UDP face carrying
        // each datagram to the kernel's dns-query arm.
        await RustImplantEndToEndTests.BuildRunAndRoundtripAsync(
            "poll", "rod-doh-package-", bindFront: async e => (await DohFrontAsync(e, "official-doh.test", udpBind: "on", httpBind: null)).Id,
            host: env);
    }

    [RustFact]
    public async Task DohPackage_AnswersTheRfc8484Face()
    {
        _ = DohPackage.Value;
        await using var env = await StartRustEnvAsync(DohPackage.Value);
        var front = await DohFrontAsync(env, "official-doh-http.test", udpBind: null, httpBind: "on");

        // A wire query against the RFC 8484 face: TLS (the package's leaf,
        // handed over by the kernel -- the chain itself is the TLS front
        // leg's proof, so this client accepts the presented leaf), the
        // urlsafe-base64 GET form, and the NXDOMAIN a resolver expects for
        // an implant the zone never enrolled.
        var pollName = Rod.Transport.Listeners.Dns.DnsContactNames.PollName(
            ImplantId.New(), "official-doh-http.test");
        using var trusting = new HttpClient(new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
        });
        var encoded = Convert.ToBase64String(DnsQuery(pollName)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var get = await trusting.GetAsync($"https://127.0.0.1:{front.Port}/dns-query?dns={encoded}");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal("application/dns-message", get.Content.Headers.ContentType?.MediaType);
        var response = await get.Content.ReadAsByteArrayAsync();
        // The query's id echoed and a well-formed answer came back: an
        // unenrolled implant's poll answers NOERROR-empty (the grammar's
        // own shape), not an HTTP problem -- the arm answers DNS.
        Assert.Equal(0x12, response[0]);
        Assert.Equal(0x34, response[1]);
        Assert.True((response[3] & 0x0F) is 0 or 3, $"rcode {response[3] & 0x0F} is not a DNS verdict");
    }

    // Builds one TXT query wire message for a name, the hand-rolled shape
    // the DNS codec's own round-trip test pins.
    private static byte[] DnsQuery(string name)
    {
        var buffer = new List<byte>(128);
        buffer.Add(0x12); buffer.Add(0x34); // id
        buffer.Add(0); buffer.Add(1); // flags: query, recursion desired
        buffer.Add(0); buffer.Add(1); // qdcount
        buffer.Add(0); buffer.Add(0);
        buffer.Add(0); buffer.Add(0);
        buffer.Add(0); buffer.Add(1); // arcount: the OPT record

        foreach (var label in name.Split('.'))
        {
            buffer.Add((byte)label.Length);
            buffer.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        buffer.Add(0);
        buffer.Add(0); buffer.Add((byte)Rod.Transport.Listeners.Dns.DnsCodec.TxtType);
        buffer.Add(0); buffer.Add(1);

        // OPT: root name, type 41, class = payload size, no data.
        buffer.Add(0);
        buffer.Add(0); buffer.Add(41);
        buffer.Add(4); buffer.Add(208); // 1232
        buffer.Add(0); buffer.Add(0); buffer.Add(0); buffer.Add(0);
        buffer.Add(0); buffer.Add(0);
        return buffer.ToArray();
    }
}
