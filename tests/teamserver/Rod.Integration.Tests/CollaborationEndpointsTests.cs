using System.Net;
using System.Net.Http.Json;
using Google.Protobuf;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.Transport;
using Rod.V1;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance for the collaboration surfaces (architecture.md Sec 15.3,
/// ADR-005): comments and chat ride the engagement timeline as ordinary,
/// explicitly mutable events and never enter the hash chain; task
/// references resolve at publish -- a credential placeholder substitutes
/// on the dispatch wire only, so the plaintext never lands in a store;
/// and global search answers across the corpora through the operator API.
/// The chain-purity assertions are the item's acceptance criterion: the
/// audit chain carries no mutable content.
/// </summary>
public class CollaborationEndpointsTests
{
    private const string ChatMarker = "chat-marker-4f2a";
    private const string CommentMarker = "comment-marker-9c1d";
    private const string SecretMarker = "secret-marker-77e0";

    [Fact]
    public async Task CommentLifecycle_RidesTheTimeline_NeverTheChain()
    {
        await using var env = await TestEnv.StartAsync();
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);
        await AuthenticatedHost.LoginAsync(env.Http);

        // Comment on the implant, with a task reference that must resolve.
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "whoami" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var body = $"first take {CommentMarker} see @{TaskToken(issuedBody!.TaskId)}";
        var created = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/comments",
            new { SubjectKind = "implant", SubjectId = implant.Id.ToString(), Body = body });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var comment = await created.Content.ReadFromJsonAsync<CommentBody>();
        Assert.NotNull(comment);
        Assert.True(comment!.Editable);
        Assert.Equal(AuthenticatedHost.Handle, comment.AuthorHandle);

        // The panel read returns it, scoped by subject, naming the author by
        // handle -- resolved on the read, the member role's only path to it.
        var listed = await env.Http.GetFromJsonAsync<CommentListBody>(
            $"/engagements/{implant.EngagementId}/comments?subjectKind=implant&subjectId={implant.Id}");
        Assert.NotNull(listed);
        var row = Assert.Single(listed!.Items);
        Assert.Equal(body, row.Body);
        Assert.Equal(AuthenticatedHost.Handle, row.AuthorHandle);

        // The author edits within the window; the row changes in place.
        var edited = await env.Http.PatchAsJsonAsync(
            $"/engagements/{implant.EngagementId}/comments/{comment.Id}",
            new { Body = $"corrected {CommentMarker}" });
        Assert.Equal(HttpStatusCode.OK, edited.StatusCode);
        listed = await env.Http.GetFromJsonAsync<CommentListBody>(
            $"/engagements/{implant.EngagementId}/comments?subjectKind=implant&subjectId={implant.Id}");
        Assert.Equal($"corrected {CommentMarker}", Assert.Single(listed!.Items).Body);
        Assert.NotNull(Assert.Single(listed.Items).EditedAt);

        // The merged timeline carries the comment as an ordinary, mutable
        // event beside the chain's own rows -- the timeline ride.
        var timeline = await env.Http.GetFromJsonAsync<AuditListBody>(
            $"/engagements/{implant.EngagementId}/audit/");
        Assert.NotNull(timeline);
        var entry = timeline!.Items.SingleOrDefault(e => e.Kind == "Comment");
        Assert.NotNull(entry);
        Assert.True(entry!.Mutable);
        Assert.Equal($"corrected {CommentMarker}", entry.Payload);
        Assert.Equal($"implant:{implant.Id.Value}", entry.Outcome);
        Assert.Equal(implant.Id.Value, entry.ImplantId);
        // The chain's own rows read as immutable through the same shape.
        Assert.Contains(timeline.Items, e => e.Kind == "TaskIssued" && !e.Mutable);

        // The acceptance line: the audit trail holds no mutable content.
        // No event of any kind carries the comment's text, and the chain
        // still verifies -- the comment lives only in its own store.
        var trail = await audit.ListAsync(implant.EngagementId.Value);
        Assert.DoesNotContain(trail, e => Contains(e, CommentMarker));
        Assert.Null(AuditChain.VerifyTrail(trail));

        // Delete within the window: the row leaves the panel and the
        // timeline, with no trace to scrub -- there was never one.
        var deleted = await env.Http.DeleteAsync(
            $"/engagements/{implant.EngagementId}/comments/{comment.Id}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        timeline = await env.Http.GetFromJsonAsync<AuditListBody>(
            $"/engagements/{implant.EngagementId}/audit/");
        Assert.DoesNotContain(timeline!.Items, e => e.Kind == "Comment");
    }

    [Fact]
    public async Task Comment_UnknownSubjectAndDanglingReference_AreRefused()
    {
        await using var env = await TestEnv.StartAsync();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);
        await AuthenticatedHost.LoginAsync(env.Http);

        var unknownSubject = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/comments",
            new { SubjectKind = "task", SubjectId = Guid.NewGuid().ToString(), Body = "n/a" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, unknownSubject.StatusCode);

        var dangling = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/comments",
            new
            {
                SubjectKind = "engagement",
                SubjectId = implant.EngagementId.ToString(),
                Body = $"see @{TaskToken(Guid.NewGuid().ToString())}",
            });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, dangling.StatusCode);
        var message = await dangling.Content.ReadFromJsonAsync<ProblemBody>();
        Assert.Contains("@task-", message!.Error);
    }

    [Fact]
    public async Task Chat_DefaultChannel_Messages_RideTheTimeline_NeverTheChain()
    {
        await using var env = await TestEnv.StartAsync();
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);
        await AuthenticatedHost.LoginAsync(env.Http);

        // The first read materializes the default channel -- no cold start.
        var channels = await env.Http.GetFromJsonAsync<ChannelListBody>(
            $"/engagements/{implant.EngagementId}/chat/channels");
        Assert.NotNull(channels);
        var general = Assert.Single(channels!.Items);
        Assert.Equal("general", general.Name);

        var sent = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/chat/channels/{general.Id}/messages",
            new { Body = $"watch handoff at 06:00 {ChatMarker}" });
        Assert.Equal(HttpStatusCode.Created, sent.StatusCode);

        // The transcript names the sender by handle, resolved on the read.
        var messages = await env.Http.GetFromJsonAsync<MessageListBody>(
            $"/engagements/{implant.EngagementId}/chat/channels/{general.Id}/messages");
        Assert.NotNull(messages);
        Assert.Single(messages!.Items);
        Assert.Equal($"watch handoff at 06:00 {ChatMarker}", messages.Items[0].Body);
        Assert.Equal(AuthenticatedHost.Handle, messages.Items[0].AuthorHandle);

        var timeline = await env.Http.GetFromJsonAsync<AuditListBody>(
            $"/engagements/{implant.EngagementId}/audit/");
        var entry = timeline!.Items.SingleOrDefault(e => e.Kind == "ChatMessage");
        Assert.NotNull(entry);
        Assert.True(entry!.Mutable);
        Assert.Equal($"watch handoff at 06:00 {ChatMarker}", entry.Payload);

        // The chain holds no chat: no event carries the message text and no
        // chat-shaped event kind exists (the AC's mutable-content line).
        var trail = await audit.ListAsync(implant.EngagementId.Value);
        Assert.DoesNotContain(trail, e => Contains(e, ChatMarker));
        Assert.Null(AuditChain.VerifyTrail(trail));
    }

    [Fact]
    public async Task CredentialHarvest_LandsWithStableIds_AndLists()
    {
        await using var env = await TestEnv.StartAsync();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        using var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);
        await AuthenticatedHost.LoginAsync(env.Http);

        // A credential-kind verb completes with harvest rows; the rows land
        // in the credential store with stable ids the panel reads.
        var harvestOutput = $"{{\"kind\":\"password\",\"principal\":\"svc-web\",\"secret\":\"{SecretMarker}\",\"host\":\"web01\"}}\n"
            + "{\"kind\":\"hash\",\"principal\":\"svc-db\"}";
        var credentialId = await RunTaskCollectingCredentialsAsync(env, implant, beacon, harvestOutput);

        var credentials = await env.Http.GetFromJsonAsync<CredentialListBody>(
            $"/engagements/{implant.EngagementId}/credentials");
        Assert.NotNull(credentials);
        Assert.Equal(2, credentials!.Items.Length);
        var password = credentials.Items.Single(c => c.Principal == "svc-web");
        Assert.Equal(SecretMarker, password.Secret);
        Assert.Equal(credentialId.ToString(), password.Id, ignoreCase: true);
        Assert.Equal("collect.cred", password.Verb);

        // The stable id addresses a task reference: a comment carrying the
        // placeholder validates, and the placeholder stays a placeholder in
        // the stored body -- the secret never lands there.
        var commented = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/comments",
            new
            {
                SubjectKind = "engagement",
                SubjectId = implant.EngagementId.ToString(),
                Body = $"reused $cred-{credentialId} on web01",
            });
        Assert.Equal(HttpStatusCode.Created, commented.StatusCode);
        var commentBody = await commented.Content.ReadFromJsonAsync<CommentBody>();
        Assert.DoesNotContain(SecretMarker, commentBody!.Body);
        Assert.Contains($"$cred-{credentialId}", commentBody.Body);
    }

    [Fact]
    public async Task CredentialPlaceholder_SubstitutesOnTheWire_Only()
    {
        await using var env = await TestEnv.StartAsync();
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        using var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);
        await AuthenticatedHost.LoginAsync(env.Http);

        // Harvest first, so the placeholder has something to address.
        var harvestOutput = $"{{\"kind\":\"password\",\"principal\":\"svc-web\",\"secret\":\"{SecretMarker}\"}}";
        var credentialId = await RunTaskCollectingCredentialsAsync(env, implant, beacon, harvestOutput);

        // The operator tasks with the placeholder in the input. Issuance
        // validates it; the dispatch wire carries the resolved secret.
        var placeholder = $"runas /user:svc-web $cred-{credentialId}";
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = placeholder });
        issued.EnsureSuccessStatusCode();

        var request = TaskRequest.Parser.ParseFrom(await beacon.ReceiveSingleFrameAsync());
        Assert.Contains(SecretMarker, request.Arguments);
        Assert.DoesNotContain("$cred-", request.Arguments);

        // Every stored form keeps the placeholder: the task row and the
        // issued/dispatched chain events. The secret the implant executed
        // exists on the wire alone.
        var fetched = await env.Http.GetFromJsonAsync<TaskBody>(
            $"/engagements/{implant.EngagementId}/tasks/{request.TaskId}");
        Assert.Contains("$cred-", fetched!.Arguments);
        Assert.DoesNotContain(SecretMarker, fetched.Arguments);

        var trail = await audit.ListAsync(implant.EngagementId.Value);
        var issuedEvent = trail.Single(e => e.Kind == AuditEventKind.TaskIssued && e.TaskId == Guid.Parse(request.TaskId));
        Assert.Contains("$cred-", issuedEvent.Payload);
        Assert.DoesNotContain(SecretMarker, issuedEvent.Payload);
        var dispatched = trail.Single(e => e.Kind == AuditEventKind.TaskDispatched && e.TaskId == Guid.Parse(request.TaskId));
        Assert.Contains("$cred-", dispatched.Payload);
        Assert.DoesNotContain(SecretMarker, dispatched.Payload);

        // Outside the harvest's own captured output (the evidence of what
        // the implant returned, immutable by design), no chain event
        // carries the secret.
        var carrying = trail.Where(e => Contains(e, SecretMarker)).ToArray();
        Assert.All(carrying, e => Assert.Equal(AuditEventKind.TaskCompleted, e.Kind));
        Assert.Null(AuditChain.VerifyTrail(trail));
    }

    [Fact]
    public async Task Issuance_WithDanglingPlaceholder_IsRefused()
    {
        await using var env = await TestEnv.StartAsync();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);
        await AuthenticatedHost.LoginAsync(env.Http);

        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = $"$cred-{Guid.NewGuid()}" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, issued.StatusCode);
        var message = await issued.Content.ReadFromJsonAsync<ProblemBody>();
        Assert.Contains("$cred-", message!.Error);
    }

    [Fact]
    public async Task GlobalSearch_AnswersAcrossCorpora_EngagementScoped()
    {
        await using var env = await TestEnv.StartAsync();
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        using var beacon = await WsBeaconClient.ConnectAsync(env.HttpPort, implant.Id.ToString());
        Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);
        await AuthenticatedHost.LoginAsync(env.Http);

        // One seeded needle per corpus.
        await RunTaskCollectingCredentialsAsync(env, implant, beacon,
            "{\"kind\":\"password\",\"principal\":\"needle-principal-svc\",\"secret\":\"irrelevant\"}",
            principal: "needle-principal-svc");
        await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/comments",
            new
            {
                SubjectKind = "engagement",
                SubjectId = implant.EngagementId.ToString(),
                Body = "needle-comment on the pivot",
            });
        var channels = await env.Http.GetFromJsonAsync<ChannelListBody>(
            $"/engagements/{implant.EngagementId}/chat/channels");
        await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/chat/channels/{channels!.Items[0].Id}/messages",
            new { Body = "needle-chat on the watch" });
        var tasked = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "shell.exec", Arguments = "grep needle-output /var/log/app.log" });
        tasked.EnsureSuccessStatusCode();
        var taskBody = await tasked.Content.ReadFromJsonAsync<TaskIssuedBody>();
        var result = new TaskResult
        {
            TaskId = taskBody!.TaskId,
            Outcome = TaskOutcome.Succeeded,
            Output = "one line with needle-output inside",
        };
        await beacon.SendFramesAsync(new[] { ResultFrame(result) });
        await TestSupport.WaitUntilAsync(async () => (await audit.ForTaskAsync(Guid.Parse(taskBody.TaskId))).Count == 3);

        var hits = await env.Http.GetFromJsonAsync<SearchBody>(
            $"/engagements/{implant.EngagementId}/search?q=needle");
        Assert.NotNull(hits);
        // The grep task and the harvest's own output both carry the needle,
        // so the assertion is the corpora covered, not an exact count.
        Assert.Equal(
            new[] { "chat_message", "comment", "credential", "task_output" },
            hits!.Items.Select(h => h.Corpus).Distinct().OrderBy(c => c).ToArray());
        Assert.Contains(hits.Items, h => h.Corpus == "credential" && h.Title == "needle-principal-svc");

        // The corpus filter narrows; a foreign engagement's needle stays
        // invisible (isolation by construction).
        var narrowed = await env.Http.GetFromJsonAsync<SearchBody>(
            $"/engagements/{implant.EngagementId}/search?q=needle&corpora=credential,chat_message");
        Assert.Equal(2, narrowed!.Items.Length);

        var other = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);
        var empty = await env.Http.GetFromJsonAsync<SearchBody>(
            $"/engagements/{other.EngagementId}/search?q=needle");
        Assert.Empty(empty!.Items);

        // The credential's secret is not searchable text.
        var bySecret = await env.Http.GetFromJsonAsync<SearchBody>(
            $"/engagements/{implant.EngagementId}/search?q=irrelevant");
        Assert.DoesNotContain(bySecret!.Items, h => h.Corpus == "credential");
    }

    [Fact]
    public async Task CommentsAndChat_NameWhoeverWroteThem_ByHandle()
    {
        await using var env = await TestEnv.StartAsync();
        var implant = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);
        await AuthenticatedHost.LoginAsync(env.Http);

        // A member beside the engagement's lead: the reads must name whoever
        // actually wrote the row, not the session that opened the engagement
        // -- and the member's own session resolves the same way, without the
        // roster walk the member role cannot make.
        await AuthenticatedHost.RegisterOperatorAsync(env.Host, "runner", "runner-p@ss!");
        var added = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/members", new { handle = "runner", role = "writer" });
        added.EnsureSuccessStatusCode();

        var member = new HttpClient(new CookieHandler(new HttpClientHandler()))
        {
            BaseAddress = new Uri($"http://127.0.0.1:{env.HttpPort}"),
        };
        using (member)
        {
            await AuthenticatedHost.LoginAsync(member, "runner", "runner-p@ss!");

            var memberComment = await member.PostAsJsonAsync(
                $"/engagements/{implant.EngagementId}/comments",
                new { SubjectKind = "implant", SubjectId = implant.Id.ToString(), Body = "member's take" });
            Assert.Equal(HttpStatusCode.Created, memberComment.StatusCode);
            var memberCommentBody = await memberComment.Content.ReadFromJsonAsync<CommentBody>();
            Assert.Equal("runner", memberCommentBody!.AuthorHandle);

            var channels = await member.GetFromJsonAsync<ChannelListBody>(
                $"/engagements/{implant.EngagementId}/chat/channels");
            var sent = await member.PostAsJsonAsync(
                $"/engagements/{implant.EngagementId}/chat/channels/{channels!.Items[0].Id}/messages",
                new { Body = "member on the watch" });
            Assert.Equal(HttpStatusCode.Created, sent.StatusCode);
            var sentBody = await sent.Content.ReadFromJsonAsync<MessageListBody.MessageRow>();
            Assert.Equal("runner", sentBody!.AuthorHandle);

            // The member's own reads name the same actor.
            var memberListed = await member.GetFromJsonAsync<CommentListBody>(
                $"/engagements/{implant.EngagementId}/comments?subjectKind=implant&subjectId={implant.Id}");
            Assert.Equal("runner", Assert.Single(memberListed!.Items).AuthorHandle);
            var memberMessages = await member.GetFromJsonAsync<MessageListBody>(
                $"/engagements/{implant.EngagementId}/chat/channels/{channels.Items[0].Id}/messages");
            Assert.Equal("runner", Assert.Single(memberMessages!.Items).AuthorHandle);
        }

        // The lead's reads name the member, not the lead.
        var listed = await env.Http.GetFromJsonAsync<CommentListBody>(
            $"/engagements/{implant.EngagementId}/comments?subjectKind=implant&subjectId={implant.Id}");
        Assert.Equal("runner", Assert.Single(listed!.Items).AuthorHandle);
        var leadChannels = await env.Http.GetFromJsonAsync<ChannelListBody>(
            $"/engagements/{implant.EngagementId}/chat/channels");
        var messages = await env.Http.GetFromJsonAsync<MessageListBody>(
            $"/engagements/{implant.EngagementId}/chat/channels/{leadChannels!.Items[0].Id}/messages");
        Assert.Equal("runner", Assert.Single(messages!.Items).AuthorHandle);
    }

    // Runs one collect.cred task over the beacon to completion and returns
    // the harvested credential row's stable id, picked by principal.
    private static async Task<Guid> RunTaskCollectingCredentialsAsync(
        TestEnv env,
        Implant implant,
        WsBeaconClient beacon,
        string output,
        string principal = "svc-web")
    {
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{implant.EngagementId}/tasks",
            new { ImplantId = implant.Id.ToString(), Verb = "collect.cred", Arguments = "stores" });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();

        var request = TaskRequest.Parser.ParseFrom(await beacon.ReceiveSingleFrameAsync());
        var result = new TaskResult
        {
            TaskId = request.TaskId,
            Outcome = TaskOutcome.Succeeded,
            Output = output,
        };
        await beacon.SendFramesAsync(new[] { ResultFrame(result) });
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();
        await TestSupport.WaitUntilAsync(async () => (await audit.ForTaskAsync(Guid.Parse(request.TaskId))).Count == 3);

        var credentials = await env.Http.GetFromJsonAsync<CredentialListBody>(
            $"/engagements/{implant.EngagementId}/credentials");
        return Guid.Parse(credentials!.Items.Single(c => c.Principal == principal).Id);
    }

    private static string TaskToken(string taskId) => $"@task-{taskId}";

    private static bool Contains(AuditEvent e, string marker)
        => (e.Payload?.Contains(marker, StringComparison.Ordinal) ?? false)
            || (e.Output?.Contains(marker, StringComparison.Ordinal) ?? false)
            || e.Outcome.Contains(marker, StringComparison.Ordinal);

    private static Frame ResultFrame(TaskResult result)
        => new() { Payload = ByteString.CopyFrom(result.ToByteArray()) };

    // Minimal DTOs for the JSON round-trip; the endpoints own the wire shape.

    private sealed class TaskIssuedBody
    {
        public string TaskId { get; set; } = "";
    }

    private sealed class TaskBody
    {
        public string? Arguments { get; set; }
    }

    private sealed class CommentBody
    {
        public string Id { get; set; } = "";
        public string AuthorHandle { get; set; } = "";
        public string Body { get; set; } = "";
        public DateTimeOffset? EditedAt { get; set; }
        public bool Editable { get; set; }
    }

    private sealed class CommentListBody
    {
        public CommentRow[] Items { get; set; } = [];

        public sealed class CommentRow
        {
            public string Id { get; set; } = "";
            public string AuthorHandle { get; set; } = "";
            public string Body { get; set; } = "";
            public DateTimeOffset? EditedAt { get; set; }
        }
    }

    private sealed class ChannelListBody
    {
        public ChannelRow[] Items { get; set; } = [];

        public sealed class ChannelRow
        {
            public string Id { get; set; } = "";
            public string Name { get; set; } = "";
        }
    }

    private sealed class MessageListBody
    {
        public MessageRow[] Items { get; set; } = [];

        public sealed class MessageRow
        {
            public string AuthorHandle { get; set; } = "";
            public string Body { get; set; } = "";
        }
    }

    private sealed class CredentialListBody
    {
        public CredentialRow[] Items { get; set; } = [];

        public sealed class CredentialRow
        {
            public string Id { get; set; } = "";
            public string Principal { get; set; } = "";
            public string? Secret { get; set; }
            public string Verb { get; set; } = "";
        }
    }

    private sealed class SearchBody
    {
        public SearchRow[] Items { get; set; } = [];

        public sealed class SearchRow
        {
            public string Corpus { get; set; } = "";
            public string Title { get; set; } = "";
        }
    }

    private sealed class AuditListBody
    {
        public TimelineRow[] Items { get; set; } = [];

        public sealed class TimelineRow
        {
            public Guid EventId { get; set; }
            public string Kind { get; set; } = "";
            public string Payload { get; set; } = "";
            public string Outcome { get; set; } = "";
            public Guid ImplantId { get; set; }
            public bool Mutable { get; set; }
        }
    }

    private sealed class ProblemBody
    {
        public string Error { get; set; } = "";
    }

    // The non-Postgres host: the operator layer composed beside transport,
    // with an optional config extension (the edit-window tests shrink it).
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;
        public OperatorId OperatorId { get; private set; }
        public int HttpPort { get; private set; }

        public static async Task<TestEnv> StartAsync(
            Action<Dictionary<string, string?>>? extendConfig = null)
        {
            var env = new TestEnv();
            env.HttpPort = TestSupport.GetFreeTcpPort();

            var config = AuthenticatedHost.BuildConfig(extend: dict =>
            {
                extendConfig?.Invoke(dict);
            });
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder
                    .ConfigureKestrel(kestrel => kestrel.ListenLocalhost(env.HttpPort)))
                .Build();
            await env.Host.StartAsync();
            env.OperatorId = AuthenticatedHost.GetOperatorId(env.Host);

            env.Http = new HttpClient(new CookieHandler(new HttpClientHandler()))
            {
                BaseAddress = new Uri($"http://127.0.0.1:{env.HttpPort}"),
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
