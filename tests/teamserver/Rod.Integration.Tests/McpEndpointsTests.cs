using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Tasks;
using Rod.Transport.Endpoints;
// The domain entity shares its name with System.Threading.Tasks.Task and this
// file imports its namespace; the BCL type is what the handlers return, so it
// gets the short name and the entity stays fully qualified.
using Task = System.Threading.Tasks.Task;

namespace Rod.Integration.Tests;

/// <summary>
/// The MCP-over-the-operator-surface acceptance (architecture.md Sec 4, the
/// operator layer's agent surface): an external MCP client -- speaking plain
/// Streamable HTTP JSON-RPC, authenticated with an operator API token --
/// initializes the session, lists the toolset, and reads engagement state
/// through it. The toolset is read-only by construction, so the acceptance
/// also asserts no write tool is exposed. Unauthenticated calls are refused
/// with the same 401 every operator-facing endpoint answers.
/// </summary>
public class McpEndpointsTests
{
    private static async Task<(HttpClient Client, IHost Host, OperatorId Operator, Guid Engagement, Implant Implant, Rod.CoreState.Tasks.Task Task)> SeedAsync()
    {
        // Only the MCP tests map the endpoint (the SDK's mapping pins the
        // host's configuration root; a churning test process maps it exactly
        // where it exercises it).
        var (client, host, operatorId) = AuthenticatedHost.Create(
            mapEndpoints: endpoints => Rod.Operators.Mcp.RodMcpHost.MapRodMcp(endpoints));
        await AuthenticatedHost.LoginAsync(client);

        var response = await client.PostAsJsonAsync("/engagements",
            new EngagementEndpoints.CreateEngagementRequest(Name: "Operation Agent Watch"));
        response.EnsureSuccessStatusCode();
        var created = await response.Content.ReadFromJsonAsync<EngagementEndpoints.EngagementResponse>();
        var engagement = Guid.Parse(created!.EngagementId);

        var implant = await EngagementSetup.EnrollImplantAsync(host, new EngagementId(engagement));

        var tasks = host.Services.GetRequiredService<ITaskRepository>();
        var clock = host.Services.GetRequiredService<TimeProvider>();
        var now = clock.GetUtcNow();
        var task = Rod.CoreState.Tasks.Task.Create(
            TaskId.New(), new EngagementId(engagement), implant.Id, operatorId,
            "shell.exec", "whoami", now);
        task.MarkDispatched(now.AddSeconds(1));
        task.Complete("operator\n", TaskOutcome.Succeeded, now.AddSeconds(2));
        await tasks.SaveAsync(task);

        // A second client speaking raw JSON-RPC with the bearer credential --
        // the shape an external MCP client presents.
        var bearer = await MintTokenAsync(client, operatorId);
        var server = host.Services.GetRequiredService<IServer>() as TestServer
            ?? throw new InvalidOperationException("TestServer was not registered.");
        var mcp = new HttpClient(server.CreateHandler()) { BaseAddress = new Uri("http://localhost") };
        mcp.DefaultRequestHeaders.Authorization = new("Bearer", bearer);
        // The Streamable HTTP transport negotiates its response media type:
        // the client must accept both JSON and SSE frames.
        mcp.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        mcp.DefaultRequestHeaders.Accept.ParseAdd("text/event-stream");

        return (mcp, host, operatorId, engagement, implant, task);
    }

    private static async Task<string> MintTokenAsync(HttpClient client, OperatorId operatorId, string? scope = null)
    {
        var response = await client.PostAsJsonAsync($"/operators/{operatorId.Value}/tokens", new { scope });
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("token").GetString()!;
    }

    [Fact]
    public async Task Mcp_ServesReadOnlyTools_OverOperatorTokenAuth()
    {
        var (mcp, host, operatorId, engagement, implant, task) = await SeedAsync();
        using (host)
        using (mcp)
        {
            // The protocol handshake: initialize, then the initialized
            // notification, then the working calls.
            var init = ResultOf(await RpcAsync(mcp, new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new
                {
                    protocolVersion = "2025-06-18",
                    capabilities = new { },
                    clientInfo = new { name = "rod-test-client", version = "1.0" },
                },
            }));
            Assert.Equal("Rod teamserver", init.GetProperty("serverInfo").GetProperty("name").GetString());

            await NotifyAsync(mcp, new { jsonrpc = "2.0", method = "notifications/initialized" });

            // The read-only acceptance: every tool is a read, none writes.
            var tools = ResultOf(await RpcAsync(mcp, new { jsonrpc = "2.0", id = 2, method = "tools/list" }));
            var names = tools.GetProperty("tools").EnumerateArray()
                .Select(t => t.GetProperty("name").GetString()!)
                .ToHashSet();
            Assert.True(names.IsSupersetOf(new[]
            {
                "list_engagements", "list_implants", "list_sessions", "list_tasks", "get_task", "list_audit",
            }), $"The toolset is missing reads: {string.Join(", ", names)}");
            Assert.All(names, name => Assert.True(name.StartsWith("list_") || name == "get_task",
                $"The tool '{name}' is not a read."));

            // An engagement's implants, listed through the tool.
            var implants = await CallToolAsync(mcp, 3, "list_implants", new { engagementId = engagement.ToString() });
            Assert.Contains(implant.Id.ToString(), implants);

            // A completed task's output, read through the tool. The tool's
            // payload is JSON text; the captured output is a field in it, so
            // the newline survives as a value, not as an escaped literal.
            var detail = await CallToolAsync(mcp, 4, "get_task", new
            {
                engagementId = engagement.ToString(),
                taskId = task.Id.ToString(),
            });
            using var detailJson = JsonDocument.Parse(detail);
            var row = detailJson.RootElement;
            Assert.Equal(task.Id.ToString(), row.GetProperty("taskId").GetString());
            Assert.Equal("shell.exec", row.GetProperty("verb").GetString());
            Assert.Equal("Completed", row.GetProperty("status").GetString());
            Assert.Equal("operator\n", row.GetProperty("output").GetString());

            // Engagement scoping holds: another engagement's id answers
            // not-found with the reason on the wire -- an isError result,
            // not a masked invocation error.
            var foreign = await RpcAsync(mcp, new
            {
                jsonrpc = "2.0",
                id = 5,
                method = "tools/call",
                @params = new { name = "list_implants", arguments = new { engagementId = Guid.NewGuid().ToString() } },
            });
            Assert.Contains("No such engagement", RefusalTextOf(foreign));
        }
    }

    [Fact]
    public async Task Mcp_RefusesUnauthenticatedCalls()
    {
        var (client, host, _, _, _, _) = await SeedAsync();
        using (host)
        using (client)
        {
            client.DefaultRequestHeaders.Authorization = null;
            var response = await client.PostAsJsonAsync("/mcp", new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new
                {
                    protocolVersion = "2025-06-18",
                    capabilities = new { },
                    clientInfo = new { name = "anon", version = "1.0" },
                },
            });
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    /// <summary>
    /// The write-gate acceptance (docs/operations/mcp.md, the Evolution note):
    /// the task-issuing tools do not exist until the deployment opens
    /// <c>Mcp:AllowWriteTools</c> -- a closed gate means tools/list names no
    /// way to act, not a way that refuses -- and an open gate issues through
    /// the same TaskService path the console's task dialog drives, with the
    /// identical audit fact.
    /// </summary>
    private static async Task<(HttpClient Mcp, IHost Host, OperatorId Operator, Guid Engagement, Implant Implant)> SeedGatedAsync(
        string scope = "operate")
    {
        var (client, host, operatorId) = AuthenticatedHost.Create(
            extendConfig: dict => dict["Mcp:AllowWriteTools"] = "true",
            mapEndpoints: endpoints => Rod.Operators.Mcp.RodMcpHost.MapRodMcp(endpoints));
        await AuthenticatedHost.LoginAsync(client);

        var response = await client.PostAsJsonAsync("/engagements",
            new EngagementEndpoints.CreateEngagementRequest(Name: "Operation Agent Act"));
        response.EnsureSuccessStatusCode();
        var created = await response.Content.ReadFromJsonAsync<EngagementEndpoints.EngagementResponse>();
        var engagement = Guid.Parse(created!.EngagementId);
        var implant = await EngagementSetup.EnrollImplantAsync(host, new EngagementId(engagement));

        // The write tools take the operate floor -- the same rank the route
        // gate gives an engagement-scoped write -- so the acceptance mints
        // there and the refusal tests mint below it.
        var bearer = await MintTokenAsync(client, operatorId, scope);
        var server = host.Services.GetRequiredService<IServer>() as TestServer
            ?? throw new InvalidOperationException("TestServer was not registered.");
        var mcp = new HttpClient(server.CreateHandler()) { BaseAddress = new Uri("http://localhost") };
        mcp.DefaultRequestHeaders.Authorization = new("Bearer", bearer);
        mcp.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        mcp.DefaultRequestHeaders.Accept.ParseAdd("text/event-stream");
        return (mcp, host, operatorId, engagement, implant);
    }

    [Fact]
    public async Task Mcp_WriteTools_StayHiddenUntilTheGateOpens()
    {
        var (mcp, host, _, _, _, _) = await SeedAsync();
        using (host)
        using (mcp)
        {
            await RpcAsync(mcp, new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new
                {
                    protocolVersion = "2025-06-18",
                    capabilities = new { },
                    clientInfo = new { name = "rod-test-client", version = "1.0" },
                },
            });
            await NotifyAsync(mcp, new { jsonrpc = "2.0", method = "notifications/initialized" });

            var tools = ResultOf(await RpcAsync(mcp, new { jsonrpc = "2.0", id = 2, method = "tools/list" }));
            var names = tools.GetProperty("tools").EnumerateArray()
                .Select(t => t.GetProperty("name").GetString()!)
                .ToHashSet();
            Assert.DoesNotContain("issue_task", names);
            Assert.DoesNotContain("replay_snippet", names);
        }
    }

    [Fact]
    public async Task Mcp_WriteTools_IssueAndReplayThroughTheRealGates()
    {
        var (mcp, host, operatorId, engagement, implant) = await SeedGatedAsync();
        using (host)
        using (mcp)
        {
            await RpcAsync(mcp, new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new
                {
                    protocolVersion = "2025-06-18",
                    capabilities = new { },
                    clientInfo = new { name = "rod-test-client", version = "1.0" },
                },
            });
            await NotifyAsync(mcp, new { jsonrpc = "2.0", method = "notifications/initialized" });

            var tools = ResultOf(await RpcAsync(mcp, new { jsonrpc = "2.0", id = 2, method = "tools/list" }));
            var names = tools.GetProperty("tools").EnumerateArray()
                .Select(t => t.GetProperty("name").GetString()!)
                .ToHashSet();
            Assert.Contains("issue_task", names);
            Assert.Contains("replay_snippet", names);

            // One task through the tool: the real issuance path, so the task
            // queues for the implant and the trail carries the identical
            // issued fact the operator API's endpoint appends.
            var taskId = await CallToolAsync(mcp, 3, "issue_task", new
            {
                engagementId = engagement.ToString(),
                implantId = implant.Id.ToString(),
                verb = "shell.exec",
                arguments = "id",
            });
            Assert.False(string.IsNullOrEmpty(taskId));

            var tasks = host.Services.GetRequiredService<ITaskRepository>();
            Assert.True(Rod.CoreState.TaskId.TryParse(taskId, out var parsed));
            var queued = await tasks.FindAsync(parsed);
            Assert.NotNull(queued);
            Assert.Equal("shell.exec", queued!.Verb);
            Assert.Equal(Rod.CoreState.Tasks.TaskStatus.Queued, queued.Status);

            // Replay: the snippet's steps issue in order to the named implant.
            var snippets = host.Services.GetRequiredService<Rod.CoreState.Snippets.ITaskSnippetStore>();
            var snippet = Rod.CoreState.Snippets.TaskSnippet.Create(
                Rod.CoreState.TaskSnippetId.New(),
                new EngagementId(engagement),
                "recon-sweep",
                new[]
                {
                    new Rod.CoreState.Snippets.TaskSnippetStep("shell.exec", "hostname"),
                    new Rod.CoreState.Snippets.TaskSnippetStep("shell.exec", "uname -a"),
                },
                DateTimeOffset.UtcNow,
                operatorId);
            await snippets.SaveAsync(snippet);

            var replayed = await CallToolAsync(mcp, 4, "replay_snippet", new
            {
                engagementId = engagement.ToString(),
                snippetId = snippet.Id.ToString(),
                implantId = implant.Id.ToString(),
            });
            using var replayJson = JsonDocument.Parse(replayed);
            Assert.Equal(2, replayJson.RootElement.GetProperty("tasks").GetArrayLength());

            // The audit carries the agent-issued facts, attributed to the
            // token's operator like every issuance.
            var audit = host.Services.GetRequiredService<Rod.Audit.IAuditStore>();
            var trail = await audit.ListAsync(engagement);
            Assert.Equal(3, trail.Count(e => e.Kind == Rod.Audit.AuditEventKind.TaskIssued));

            // The engagement bar holds: a reader's token (a stranger here)
            // reads no such engagement on a write tool, reason on the wire.
            var foreign = await RpcAsync(mcp, new
            {
                jsonrpc = "2.0",
                id = 5,
                method = "tools/call",
                @params = new
                {
                    name = "issue_task",
                    arguments = new
                    {
                        engagementId = Guid.NewGuid().ToString(),
                        implantId = implant.Id.ToString(),
                        verb = "shell.exec",
                    },
                },
            });
            Assert.Contains("No such engagement", RefusalTextOf(foreign));
        }
    }

    [Fact]
    public async Task Mcp_WriteTools_RefuseATokenBelowTheOperateFloor()
    {
        var (mcp, host, _, engagement, implant) = await SeedGatedAsync(scope: "read");
        using (host)
        using (mcp)
        {
            await HandshakeAsync(mcp);

            // The gate is the deployment's, so the tool is named; the floor
            // is the credential's, so the call refuses -- a read-scoped
            // token observes the engagement but cannot act on it, whatever
            // the deployment opened for other credentials.
            var tools = ResultOf(await RpcAsync(mcp, new { jsonrpc = "2.0", id = 2, method = "tools/list" }));
            Assert.Contains("issue_task", tools.GetProperty("tools").EnumerateArray()
                .Select(t => t.GetProperty("name").GetString()));

            var refusal = RefusalTextOf(await RpcAsync(mcp, new
            {
                jsonrpc = "2.0",
                id = 3,
                method = "tools/call",
                @params = new
                {
                    name = "issue_task",
                    arguments = new
                    {
                        engagementId = engagement.ToString(),
                        implantId = implant.Id.ToString(),
                        verb = "shell.exec",
                    },
                },
            }));
            Assert.Contains("scope does not cover this action", refusal);

            // Reads ride the read floor every mintable scope carries.
            var implants = await CallToolAsync(mcp, 4, "list_implants", new { engagementId = engagement.ToString() });
            Assert.Contains(implant.Id.ToString(), implants);
        }
    }

    /// <summary>
    /// The unattended red line (architecture.md Sec 10.4) holds on the write
    /// face: the channel verbs and every verb the sensitivity policy names
    /// refuse -- the same answer the automation engine reads off the same
    /// port -- and a snippet carrying one refuses whole, before any step
    /// issues, so the trail carries nothing from a refused replay.
    /// </summary>
    [Fact]
    public async Task Mcp_WriteTools_RefuseTheUnattendedRedLine()
    {
        var (mcp, host, operatorId, engagement, implant) = await SeedGatedAsync();
        using (host)
        using (mcp)
        {
            await HandshakeAsync(mcp);

            var sensitive = RefusalTextOf(await RpcAsync(mcp, new
            {
                jsonrpc = "2.0",
                id = 2,
                method = "tools/call",
                @params = new
                {
                    name = "issue_task",
                    arguments = new
                    {
                        engagementId = engagement.ToString(),
                        implantId = implant.Id.ToString(),
                        verb = "collect.minidump",
                    },
                },
            }));
            Assert.Contains("sensitive", sensitive);

            var channel = RefusalTextOf(await RpcAsync(mcp, new
            {
                jsonrpc = "2.0",
                id = 3,
                method = "tools/call",
                @params = new
                {
                    name = "issue_task",
                    arguments = new
                    {
                        engagementId = engagement.ToString(),
                        implantId = implant.Id.ToString(),
                        verb = "shell.interact",
                    },
                },
            }));
            Assert.Contains("live channel", channel);

            var snippets = host.Services.GetRequiredService<Rod.CoreState.Snippets.ITaskSnippetStore>();
            var snippet = Rod.CoreState.Snippets.TaskSnippet.Create(
                Rod.CoreState.TaskSnippetId.New(),
                new EngagementId(engagement),
                "sweep-with-a-blocked-step",
                new[]
                {
                    new Rod.CoreState.Snippets.TaskSnippetStep("shell.exec", "hostname"),
                    new Rod.CoreState.Snippets.TaskSnippetStep("collect.keylog", "60"),
                },
                DateTimeOffset.UtcNow,
                operatorId);
            await snippets.SaveAsync(snippet);

            var replay = RefusalTextOf(await RpcAsync(mcp, new
            {
                jsonrpc = "2.0",
                id = 4,
                method = "tools/call",
                @params = new
                {
                    name = "replay_snippet",
                    arguments = new
                    {
                        engagementId = engagement.ToString(),
                        snippetId = snippet.Id.ToString(),
                        implantId = implant.Id.ToString(),
                    },
                },
            }));
            Assert.Contains("sensitive", replay);

            var audit = host.Services.GetRequiredService<Rod.Audit.IAuditStore>();
            var trail = await audit.ListAsync(engagement);
            Assert.DoesNotContain(trail, e => e.Kind == Rod.Audit.AuditEventKind.TaskIssued);
        }
    }

    // One JSON-RPC post, decoding either wire form the Streamable HTTP
    // transport answers with (bare JSON or an SSE frame carrying one message).
    private static async Task<JsonElement> RpcAsync(HttpClient client, object payload)
    {
        using var response = await client.PostAsJsonAsync("/mcp", payload);
        Assert.True(response.IsSuccessStatusCode,
            $"The RPC call failed with HTTP {(int)response.StatusCode}.");
        var media = response.Content.Headers.ContentType?.MediaType;
        if (string.Equals(media, "text/event-stream", StringComparison.OrdinalIgnoreCase))
        {
            var text = await response.Content.ReadAsStringAsync();
            var data = string.Join("\n",
                text.Split('\n').Where(l => l.StartsWith("data: ", StringComparison.Ordinal)).Select(l => l["data: ".Length..]));
            using var body = JsonDocument.Parse(data);
            return body.RootElement.Clone();
        }
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    // The protocol handshake every stateless session repeats: initialize,
    // then the initialized notification, before the working calls.
    private static async Task HandshakeAsync(HttpClient client)
    {
        await RpcAsync(client, new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "initialize",
            @params = new
            {
                protocolVersion = "2025-06-18",
                capabilities = new { },
                clientInfo = new { name = "rod-test-client", version = "1.0" },
            },
        });
        await NotifyAsync(client, new { jsonrpc = "2.0", method = "notifications/initialized" });
    }

    // Unwraps the JSON-RPC result member; the error member is the caller's to
    // inspect when a call is expected to fail.
    private static JsonElement ResultOf(JsonElement message)
        => message.GetProperty("result");

    // The refusal text off either wire shape a failed tool call answers
    // with: a JSON-RPC error member, or a result carrying isError with the
    // tool's text.
    private static string RefusalTextOf(JsonElement message)
    {
        if (message.TryGetProperty("error", out var error))
            return error.GetProperty("message").GetString()!;
        var result = message.GetProperty("result");
        Assert.True(result.TryGetProperty("isError", out var isError) && isError.GetBoolean(),
            $"The call was expected to fail: {message.GetRawText()}");
        return result.GetProperty("content")[0].GetProperty("text").GetString()!;
    }

    private static async Task NotifyAsync(HttpClient client, object payload)
    {
        using var response = await client.PostAsJsonAsync("/mcp", payload);
        Assert.True(response.IsSuccessStatusCode);
    }

    private static async Task<string> CallToolAsync(HttpClient client, int id, string name, object arguments)
    {
        var message = await RpcAsync(client, new
        {
            jsonrpc = "2.0",
            id,
            method = "tools/call",
            @params = new { name, arguments },
        });
        Assert.True(message.TryGetProperty("result", out var result),
            $"The tool call errored: {message.GetRawText()}");
        Assert.False(result.TryGetProperty("isError", out var isError) && isError.GetBoolean(),
            $"The tool call failed: {message.GetRawText()}");
        return result.GetProperty("content")[0].GetProperty("text").GetString()!;
    }
}
