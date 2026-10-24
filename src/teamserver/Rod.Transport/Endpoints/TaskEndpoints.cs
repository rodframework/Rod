using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Collaboration;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Tasks;
using Rod.Transport.Channels;
// The domain entity shares its name with System.Threading.Tasks.Task. Pin it
// here so the endpoint's Task references resolve to the entity; the BCL type is
// not used by name in this file (handlers return IResult).
using Task = Rod.CoreState.Tasks.Task;

namespace Rod.Transport.Endpoints;

/// <summary>
/// The operator-facing tasking endpoints: issue a task against an
/// implant in an engagement, read a task back with its captured result and audit
/// trail, retract a queued task before the implant wakes, and list every task
/// in an engagement -- the operator UI
/// shows the engagement's whole task history, not one implant's. Lets an
/// operator task an implant and see output plus an audit event -- the
/// acceptance point -- and survey all tasking across the engagement. Scoped by
/// engagement so tasking never crosses engagement boundaries (architecture.md
/// Sec 3).
/// </summary>
public static class TaskEndpoints
{
    public static IEndpointRouteBuilder MapTaskEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Tasking reads need the viewing scope; issuing, retracting, typing,
        // and bridging are acting (architecture.md Sec 4.5) and require the
        // task scope on top of the group's read.
        var group = endpoints
            .MapGroup("/engagements/{engagementId}/tasks")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));

        group.MapPost("/", IssueAsync)
            .AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName("IssueTask");
        // The collection route is listed before {taskId} so the literal "/" does
        // not get captured as a task id; ASP.NET Core route matching prefers the
        // more specific template, and the {taskId} segment requires a non-empty
        // value, so "GET /tasks" (no segment) resolves here and "GET /tasks/{id}"
        // resolves to GetAsync. Ordered this way for readability.
        group.MapGet("/", ListAsync).WithName("ListEngagementTasks");
        group.MapGet("/{taskId}", GetAsync).WithName("GetTask");
        // The queued tasking's way back (architecture.md Sec 10.3): retract a
        // task before the implant wakes.
        group.MapPost("/{taskId}:cancel", CancelAsync)
            .AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName("CancelTask");
        // The streaming task shape's other half (architecture.md Sec 10.3):
        // operator input into a live channel task.
        group.MapPost("/{taskId}/input", SendInputAsync)
            .AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName("SendTaskInput");
        // The operator-side relay bind (architecture.md Sec 10.1 tunnel,
        // Sec 10.3): bridge a local TCP listener onto a live tunnel channel,
        // so unmodified tooling rides the tunnel without per-byte input posts.
        group.MapPost("/{taskId}/relay", BindRelayAsync)
            .AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName("BindTaskRelay");
        // Unbinding is teardown -- the safety valve any task-scoped operator
        // may pull, claim or no claim (the bind required one).
        group.MapDelete("/{taskId}/relay", UnbindRelayAsync)
            .AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName("UnbindTaskRelay");

        return endpoints;
    }

    // Task arguments ride the wire as one string per task and sit in the queue
    // until dispatch; bound them so a single task cannot pin megabytes and every
    // downstream TaskRequest frame stays inside the frame budget the carriages
    // enforce.
    private const int MaxArgumentBytes = 512 * 1024;

    // The staged-content ceiling: the typed arm's payload rides the artifact
    // store, not the arguments string, so it is bounded by the same ceiling an
    // evidence attach honors -- one JSON request must stay sane, and anything
    // larger belongs in an object store before it belongs in a task.
    private const int MaxStagedBytes = 64 * 1024 * 1024;

    private static async Task<Results<Created<TaskIssuedResponse>, BadRequest<Problem>, UnauthorizedHttpResult, NotFound<Problem>, JsonHttpResult<Problem>>> IssueAsync(
        string engagementId,
        IssueTaskRequest body,
        ClaimsPrincipal user,
        TaskService service,
        Rod.CoreState.Operators.Interaction.OperatorInteractionService interaction,
        IArtifactStore artifacts,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        // The issuing operator is the authenticated operator, resolved off the
        // session principal rather than named in the body (operator auth).
        var issuedBy = user.TryGetOperatorId();
        if (issuedBy is null)
            return TypedResults.Unauthorized();
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return TypedResults.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(body.ImplantId, out var implantValue))
            return TypedResults.BadRequest(new Problem("Implant id is not a valid identifier."));
        if (string.IsNullOrWhiteSpace(body.Verb))
            return TypedResults.BadRequest(new Problem("Task verb is required."));
        if (body.Arguments is { Length: > MaxArgumentBytes })
            return TypedResults.BadRequest(new Problem($"Task arguments exceed {MaxArgumentBytes} bytes."));

        // The typed arm (architecture.md Sec 10): a task whose bulk payload
        // outgrows the arguments string carries it as Content instead. The
        // payload's sha256 is appended to the arguments so it lands inside the
        // signed tasking tuple -- the staged bytes are then exactly as
        // tamper-evident as an inline ones -- and the task is issued with the
        // staged marker. The bytes themselves are staged below, after the task
        // exists to bind them to.
        if (body.Content is { Length: 0 })
            return TypedResults.BadRequest(new Problem("Staged content must not be empty."));
        if (body.Content is { Length: > MaxStagedBytes })
            return TypedResults.Json(
                new Problem($"Staged content exceeds {MaxStagedBytes} bytes."),
                statusCode: StatusCodes.Status413PayloadTooLarge);
        var stagedHash = body.Content is null
            ? null
            : "sha256:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(body.Content)).ToLowerInvariant();
        var arguments = body.Content is null
            ? body.Arguments ?? string.Empty
            : (body.Arguments ?? string.Empty).TrimEnd() + " " + stagedHash;

        TaskIssued issued;
        try
        {
            issued = await service.IssueAsync(
                new IssueTaskCommand(
                    new EngagementId(engagementValue),
                    new ImplantId(implantValue),
                    issuedBy.Value,
                    body.Verb,
                    arguments,
                    body.Content?.Length ?? null),
                onIssued: (taskIssued, ct) => AppendIssuedAuditAsync(taskIssued, audit, ct),
                cancellationToken: cancellationToken);
        }
        catch (TaskRejectedException ex)
        {
            // An unsupported verb, a retired implant, an ROE refusal, and a
            // closed engagement are all well-formed requests the server refuses
            // to act on -> 422; an unknown or foreign implant is a routing
            // failure -> 404.
            if (ex.Reason == TaskRejectionReason.RoeViolation)
            {
                // The refusal is part of the engagement's story, so it lands in
                // the trail (architecture.md Sec 9, Sec 11): attributed to the
                // issuing operator, the payload the refused verb and arguments,
                // the outcome the violated rule. No task exists to carry ids.
                await audit.AppendAsync(
                    AuditEvent.Fact(
                        eventId: Guid.NewGuid(),
                        engagementId: engagementValue,
                        operatorId: issuedBy.Value.Value,
                        implantId: implantValue,
                        taskId: Guid.Empty,
                        verb: body.Verb,
                        kind: AuditEventKind.TaskRoeRefused,
                        payload: body.Arguments ?? string.Empty,
                        output: null,
                        outcome: ex.Message,
                        at: clock.GetUtcNow()),
                    cancellationToken);
                return TypedResults.Json(
                    new Problem(ex.Message),
                    statusCode: StatusCodes.Status422UnprocessableEntity);
            }

            return ex.Reason switch
            {
                TaskRejectionReason.UnsupportedVerbForClass
                or TaskRejectionReason.NoChannelCarrier
                or TaskRejectionReason.ImplantRetired
                or TaskRejectionReason.EngagementClosed
                or TaskRejectionReason.UnknownTaskReference
                    => TypedResults.Json(new Problem(ex.Message), statusCode: StatusCodes.Status422UnprocessableEntity),
                _ => TypedResults.NotFound(new Problem(ex.Message)),
            };
        }

        var response = new TaskIssuedResponse(
            issued.TaskId.ToString(),
            issued.EngagementId.ToString(),
            issued.ImplantId.ToString(),
            issued.IssuedBy.ToString(),
            issued.Verb,
            issued.Arguments,
            issued.CreatedAt);

        // Issuing is driving activity (architecture.md Sec 4.5): the implant
        // the tasking targets gains its issuer as driver. Publishes only on a
        // hand-off, so routine tasking stays silent on the bus.
        await interaction.NoteActivityAsync(
            issued.EngagementId, issued.ImplantId, issued.IssuedBy, cancellationToken);

        // The task's issuance audit write ran inside IssueAsync (the onIssued
        // hook, above the dispatch wake release): the push dispatch the wake
        // releases audits TaskDispatched on the stream thread, and the arc
        // must read TaskIssued -> TaskDispatched -> TaskCompleted in the
        // trail, not the other way (architecture.md Sec 11).

        // A staged payload is bound to its task as an artifact -- the same
        // first-class object an evidence attach produces (architecture.md Sec
        // 11) -- so the bytes the implant will demand are stored, scoped, and
        // audited exactly once. The beacon stream streams them downstream on
        // the implant's StagedPull; the trail shows both the task's arc and
        // the artifact that fed it.
        if (body.Content is not null)
        {
            var artifactId = Guid.NewGuid();
            await artifacts.SaveAsync(
                new Artifact(
                    ArtifactId: artifactId,
                    EngagementId: issued.EngagementId.Value,
                    TaskId: issued.TaskId.Value,
                    OperatorId: issued.IssuedBy.Value,
                    Name: StagedArtifacts.NameFor(issued.TaskId.Value),
                    ContentType: "application/octet-stream",
                    Content: body.Content,
                    Size: body.Content.Length,
                    StoredAt: clock.GetUtcNow()),
                cancellationToken);
            await audit.AppendAsync(
                AuditEvent.Fact(
                    eventId: Guid.NewGuid(),
                    engagementId: issued.EngagementId.Value,
                    operatorId: issued.IssuedBy.Value,
                    implantId: issued.ImplantId.Value,
                    taskId: issued.TaskId.Value,
                    verb: "stage-artifact",
                    kind: AuditEventKind.ArtifactAttached,
                    payload: $"{stagedHash};{body.Content.Length} bytes",
                    output: null,
                    outcome: artifactId.ToString("N"),
                    at: clock.GetUtcNow()),
                cancellationToken);
        }

        return TypedResults.Created($"/engagements/{response.EngagementId}/tasks/{response.TaskId}", response);
    }

    // The task's issuance record (architecture.md Sec 11): attributed to the
    // issuing operator, the payload the verb and arguments, the outcome the
    // new task id. This is the operator's intent; the TaskDispatched event
    // records the server handing it to the implant and TaskCompleted the
    // result. Runs as IssueAsync's onIssued hook so it lands in the trail
    // before the dispatch the wake release pushes.
    private static async System.Threading.Tasks.Task AppendIssuedAuditAsync(
        TaskIssued issued,
        IAuditStore audit,
        CancellationToken cancellationToken)
        => await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: issued.EngagementId.Value,
                operatorId: issued.IssuedBy.Value,
                implantId: issued.ImplantId.Value,
                taskId: issued.TaskId.Value,
                verb: issued.Verb,
                kind: AuditEventKind.TaskIssued,
                payload: issued.Arguments,
                output: null,
                outcome: issued.TaskId.ToString(),
                at: issued.CreatedAt),
            cancellationToken);

    private static async Task<Results<Ok<TaskListResponse>, BadRequest<Problem>>> ListAsync(
        string engagementId,
        int? limit,
        string? cursor,
        ITaskRepository tasks,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return TypedResults.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!ListPaging.TryBind(limit, cursor, c => TaskPageCursor.TryDecode(c, out _),
                out var boundLimit, out var boundCursor, out var pagingError))
        {
            return TypedResults.BadRequest(new Problem(pagingError));
        }

        // One page of the engagement's task history across every implant, newest
        // window first across pages, oldest first within a page. Scoped by
        // engagement by construction (architecture.md Sec 3); the operator UI
        // surveys all tasking across the engagement from this view, walking
        // pages instead of loading the unbounded full history. Reuses
        // ImplantTaskResponse (same field set the per-implant listing returns)
        // so the two task-list shapes read identically to a client.
        var page = await tasks.ListByEngagementPageAsync(
            new EngagementId(engagementValue),
            boundLimit,
            boundCursor,
            cancellationToken);

        // Resolve the page's issuing operators to handles once per request,
        // the tolerance the audit read applies (the bare id when the account
        // no longer resolves): the member role cannot walk the operator
        // roster to do it client-side, so the read names the actor itself.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in page.Items.Select(t => t.IssuedBy.Value).Where(id => id != Guid.Empty).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        var body = new TaskListResponse(
            page.Items
                .Select(t => ToResponse(t, handles.GetValueOrDefault(t.IssuedBy.Value, t.IssuedBy.Value.ToString())))
                .ToArray(),
            page.NextCursor);

        return TypedResults.Ok(body);
    }

    private static ImplantEndpoints.ImplantTaskResponse ToResponse(Task t, string issuedByHandle)
        => new(
            t.Id.ToString(),
            t.ImplantId.ToString(),
            t.IssuedBy.ToString(),
            issuedByHandle,
            t.Verb,
            t.Arguments,
            t.Status.ToString(),
            t.Output,
            t.Outcome?.ToString(),
            t.CreatedAt,
            t.CompletedAt);

    private static async Task<Results<Ok<TaskResponse>, BadRequest<Problem>, NotFound<Problem>>> GetAsync(
        string engagementId,
        string taskId,
        TaskService service,
        ITaskRepository tasks,
        IOperatorRepository operators,
        IAuditStore audit,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return TypedResults.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(taskId, out var taskValue))
            return TypedResults.BadRequest(new Problem("Task id is not a valid identifier."));

        var task = await tasks.FindAsync(new TaskId(taskValue), cancellationToken);
        if (task is null || task.EngagementId != new EngagementId(engagementValue))
            return TypedResults.NotFound(new Problem("Task does not exist in this engagement."));

        var events = await audit.ForTaskAsync(task.Id.Value, cancellationToken);

        // The issuer's handle, resolved with the same tolerance the listing
        // applies.
        var issuer = await operators.FindAsync(task.IssuedBy, cancellationToken);

        return TypedResults.Ok(TaskResponse.Of(task, events, issuer?.Handle ?? task.IssuedBy.ToString()));
    }

    // Retract a queued task before the implant wakes (architecture.md Sec
    // 10.3): the operator's own tasking, taken back. Only a queued task can be
    // cancelled -- once the beacon stream has claimed it, the implant owns the
    // execution and the server cannot call it back. The cancelling operator is
    // the authenticated operator; the retraction is recorded in the engagement
    // trail as a TaskCancelled event attributed to them.
    private static async Task<IResult> CancelAsync(
        string engagementId,
        string taskId,
        ClaimsPrincipal user,
        TaskService service,
        ITaskRepository tasks,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var cancelledBy = user.TryGetOperatorId();
        if (cancelledBy is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(taskId, out var taskValue))
            return Results.BadRequest(new Problem("Task id is not a valid identifier."));

        // Resolve the task against the engagement first: an unknown or foreign
        // task is a routing failure -> 404, the same shape GetAsync returns.
        var existing = await tasks.FindAsync(new TaskId(taskValue), cancellationToken);
        if (existing is null || existing.EngagementId != new EngagementId(engagementValue))
            return Results.NotFound(new Problem("Task does not exist in this engagement."));

        Rod.CoreState.Application.TaskCancelled cancelled;
        try
        {
            cancelled = await service.CancelAsync(
                new EngagementId(engagementValue),
                new TaskId(taskValue),
                cancelledBy.Value,
                cancellationToken);
        }
        catch (InvalidOperationException)
        {
            // The task left the queue between the read above and the atomic
            // retraction -- a dispatch claimed it, it completed, or another
            // operator cancelled it first. The client's state problem, not a
            // routing failure.
            return Results.Conflict(
                new Problem("The task is no longer queued: it was dispatched, completed, or already cancelled."));
        }

        // The retraction is the operator's action on the engagement
        // (architecture.md Sec 11): attributed to the cancelling operator, bound
        // to the retracted task, the payload the verb's arguments and the
        // outcome the recorded cancellation timestamp. A cancelled task's audit
        // arc ends here -- no TaskDispatched follows it.
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagementValue,
                operatorId: cancelledBy.Value.Value,
                implantId: cancelled.ImplantId.Value,
                taskId: taskValue,
                verb: cancelled.Verb,
                kind: AuditEventKind.TaskCancelled,
                payload: cancelled.Arguments,
                output: null,
                outcome: cancelled.CancelledAt.ToString("O"),
                at: clock.GetUtcNow()),
            cancellationToken);

        return Results.Ok(new TaskCancelledResponse(
            cancelled.TaskId.ToString(),
            cancelled.EngagementId.ToString(),
            cancelled.CancelledBy.ToString(),
            cancelled.CancelledAt));
    }

    // The per-post input ceiling: input is keystrokes and pastes, not file
    // transfer -- anything larger belongs in a staged task (the typed arm), and
    // a single post must stay small enough to frame and audit sanely.
    private const int MaxChannelInputBytes = 64 * 1024;

    // Operator input into a live channel task (architecture.md Sec 10.3, the
    // streaming task shape): the body carries the bytes (base64, the same
    // shape staged content rides) and optionally eof -- the operator closing
    // the channel's stdin, which the implant turns into the shell's exit. The
    // task must be a dispatched channel task on an implant with a live beacon
    // stream; input for anything else is a well-formed refusal, and every
    // accepted post is audited as the operator action it is.
    private static async Task<IResult> SendInputAsync(
        string engagementId,
        string taskId,
        TaskInputRequest body,
        ClaimsPrincipal user,
        ITaskRepository tasks,
        IImplantRepository implants,
        LiveChannelHub channels,
        Rod.Transport.Channels.DegradedChannelHub degraded,
        Rod.CoreState.Collaboration.TaskReferenceService references,
        Rod.CoreState.Operators.Interaction.OperatorInteractionService interaction,
        Rod.CoreState.Operators.IOperatorRepository operators,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(taskId, out var taskValue))
            return Results.BadRequest(new Problem("Task id is not a valid identifier."));

        var data = body.Data ?? Array.Empty<byte>();
        if (data.Length == 0 && !body.Eof)
            return Results.BadRequest(new Problem("Channel input requires data or eof."));
        if (data.Length > MaxChannelInputBytes)
            return Results.Json(
                new Problem($"Channel input exceeds {MaxChannelInputBytes} bytes."),
                statusCode: StatusCodes.Status413PayloadTooLarge);

        var task = await tasks.FindAsync(new TaskId(taskValue), cancellationToken);
        if (task is null || task.EngagementId != new EngagementId(engagementValue))
            return Results.NotFound(new Problem("Task does not exist in this engagement."));

        // A one-shot task takes no live input; a channel task that is not
        // Dispatched has no channel to carry it. Both are the client's state
        // problem to see clearly, not routing failures.
        if (!ChannelVerbs.IsChannelVerb(task.Verb))
            return Results.Json(
                new Problem($"'{task.Verb}' is not a channel task; it takes no live input."),
                statusCode: StatusCodes.Status422UnprocessableEntity);
        if (task.Status != Rod.CoreState.Tasks.TaskStatus.Dispatched)
            return Results.Conflict(
                new Problem("The task's channel is not live: it is queued or already completed."));

        // The typing half is exclusively owned (architecture.md Sec 4.5): the
        // first input takes an unclaimed channel, and a channel another
        // operator holds refuses the input outright -- two operators cannot
        // type into one shell.
        var claim = await interaction.TryAcquireAsync(
            task.EngagementId,
            Rod.CoreState.Operators.Interaction.InteractionSurface.ChannelTask,
            taskValue,
            operatorId.Value,
            cancellationToken);
        if (!claim.Acquired)
        {
            var holder = claim.HeldBy!;
            var handle = (await operators.FindAsync(holder.OperatorId, cancellationToken))?.Handle
                ?? holder.OperatorId.ToString();
            return Results.Conflict(new Problem(
                $"This channel is held by {handle} since {holder.AcquiredAt:O}; "
                + "input is refused until they release it or disconnect."));
        }

        // Task references in typed input hold to the same rule the issuance
        // path enforces (architecture.md Sec 15.3, ADR-005): well-formed
        // <c>@task-</c>/<c>$cred-</c> tokens must resolve in the engagement,
        // and a credential token resolves on the wire only -- the bytes the
        // hub carries hold the secret, the audit record below decodes the
        // placeholder the operator typed, so the plaintext never lands.
        var wire = data;
        var typed = Encoding.UTF8.GetString(data);
        if (TaskReferences.Extract(typed).Count > 0)
        {
            var unresolved = await references.UnresolvedAsync(
                task.EngagementId, typed, cancellationToken);
            if (unresolved.Count > 0)
            {
                return Results.Json(
                    new Problem("Channel input references "
                        + string.Join(", ", unresolved.Select(t => t.Render()))
                        + " -- no such task or credential in this engagement."),
                    statusCode: StatusCodes.Status422UnprocessableEntity);
            }

            var substituted = await references.SubstituteCredentialsAsync(
                task.EngagementId, typed, cancellationToken);
            if (!ReferenceEquals(substituted, typed))
                wire = Encoding.UTF8.GetBytes(substituted);
        }

        // A poll-mode implant (the degraded advertisement) takes its input
        // through the parking queue even while one of its cycle's streams
        // happens to be open: those streams are transient -- the idle window
        // ends them mid-typing, and a live-sink write racing the close drops
        // the keystroke -- while the queue is the carrier its cycles pump,
        // drained onto whichever connection comes next.
        if (await degraded.AdvertisedAsync(task.ImplantId, cancellationToken))
        {
            if (!await degraded.TryEnqueueAsync(
                    task.ImplantId, new TaskId(taskValue), wire, body.Eof, cancellationToken))
            {
                return Results.Conflict(
                    new Problem("The implant's poll cycle is not accepting channel input."));
            }
        }
        // The hub reaches the implant's live beacon stream. No sink (or a full
        // one) means the channel cannot take this input right now -- unless
        // the implant opted into the degraded discipline, whose parking queue
        // is the poll carrier's sink and whose contact cycle is its pump. A
        // pivot child's channel has no sink of its own (Sec 5.2): its input
        // rides the fronting parent's stream, so a child that holds no sink
        // routes through its parent.
        else if (!channels.TryEnqueue(task.ImplantId, taskValue, wire, body.Eof))
        {
            var target = await implants.FindAsync(task.ImplantId, cancellationToken);
            if (target is { Class: ImplantClass.Pivot, ParentImplantId: { } fronting }
                && channels.TryEnqueue(fronting, taskValue, wire, body.Eof))
            {
                // Rode the fronting parent's live stream.
            }
            else if (target is not { Class: ImplantClass.Pivot }
                && await degraded.TryEnqueueAsync(
                    task.ImplantId, new TaskId(taskValue), wire, body.Eof, cancellationToken))
            {
                // Parked for the implant's next poll contact: the input
                // lands when the cycle delivers it, not instantly -- the
                // degraded discipline the implant opted into.
            }
            else
            {
                return Results.Conflict(
                    new Problem("The implant's beacon stream is not accepting channel input."));
            }
        }

        // The input is the operator's action on the engagement (architecture.md
        // Sec 11): attributed to the sender, bound to the channel's task, the
        // payload the decoded input and the outcome whether it closed stdin.
        // What the channel streamed back rides the task's TaskCompleted event.
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagementValue,
                operatorId: operatorId.Value.Value,
                implantId: task.ImplantId.Value,
                taskId: taskValue,
                verb: task.Verb,
                kind: AuditEventKind.ChannelInput,
                payload: data.Length > 0 ? Encoding.UTF8.GetString(data) : "<eof>",
                output: null,
                outcome: body.Eof ? "eof" : "sent",
                at: clock.GetUtcNow()),
            cancellationToken);

        // Driving activity (architecture.md Sec 4.5): typing into an implant
        // marks its driver. Publishes only on a hand-off, so this is silent
        // for the operator already driving.
        await interaction.NoteActivityAsync(
            task.EngagementId, task.ImplantId, operatorId.Value, cancellationToken);

        return Results.Ok(new TaskInputResponse(taskValue.ToString(), body.Eof));
    }

    // The operator-side relay bind (architecture.md Sec 10.1 tunnel, Sec 10.3):
    // start a teamserver-bound listener bridged onto a dispatched tunnel
    // channel, so an operator's unmodified tool rides the tunnel by connecting
    // a socket instead of driving the channel by input posts. The verb picks
    // the shape -- tunnel.forward gets the raw one-connection relay,
    // tunnel.socks the SOCKS proxy that multiplexes every connection onto the
    // one task. Tunnel-only: a shell channel's grammar is a terminal, and a
    // TCP bridge onto it would hand the tool a stream the shell cannot speak.
    // Loopback by default; an operator reaching the relay from elsewhere names
    // the address explicitly and owns that exposure.
    private static async Task<IResult> BindRelayAsync(
        string engagementId,
        string taskId,
        RelayBindRequest? body,
        ClaimsPrincipal user,
        ITaskRepository tasks,
        TaskRelayHub relays,
        SocksProxyHub socks,
        Rod.CoreState.Operators.Interaction.OperatorInteractionService interaction,
        Rod.CoreState.Operators.IOperatorRepository operators,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(taskId, out var taskValue))
            return Results.BadRequest(new Problem("Task id is not a valid identifier."));

        if (!TryParseRelayAddress(body?.BindAddress, out var address, out var addressError))
            return Results.BadRequest(new Problem(addressError));
        var port = body?.Port ?? 0;
        if (port is < 0 or > 65535)
            return Results.BadRequest(new Problem("Relay port must be 0 (ephemeral) through 65535."));

        var task = await tasks.FindAsync(new TaskId(taskValue), cancellationToken);
        if (task is null || task.EngagementId != new EngagementId(engagementValue))
            return Results.NotFound(new Problem("Task does not exist in this engagement."));

        var forward = string.Equals(task.Verb, ChannelVerbs.TunnelForward, StringComparison.OrdinalIgnoreCase);
        var proxy = string.Equals(task.Verb, ChannelVerbs.TunnelSocks, StringComparison.OrdinalIgnoreCase);
        if (!forward && !proxy)
            return Results.Json(
                new Problem($"'{task.Verb}' is not a tunnel task; a relay bridges tunnel.forward, a SOCKS proxy bridges tunnel.socks."),
                statusCode: StatusCodes.Status422UnprocessableEntity);
        if (task.Status != Rod.CoreState.Tasks.TaskStatus.Dispatched)
            return Results.Conflict(
                new Problem("The task's channel is not live: it is queued or already completed."));
        if (relays.IsBound(taskValue) || socks.IsBound(taskValue))
            return Results.Conflict(new Problem("A relay is already bound for this task."));

        // A relay is the tunnel's other typing half (architecture.md Sec 4.5):
        // the machine producer rides the same exclusive claim the input posts
        // do -- binding takes an unclaimed channel and refuses onto a held
        // one, so an operator's tool and a peer's keystrokes never mix.
        var claim = await interaction.TryAcquireAsync(
            task.EngagementId,
            Rod.CoreState.Operators.Interaction.InteractionSurface.ChannelTask,
            taskValue,
            operatorId.Value,
            cancellationToken);
        if (!claim.Acquired)
        {
            var holder = claim.HeldBy!;
            var handle = (await operators.FindAsync(holder.OperatorId, cancellationToken))?.Handle
                ?? holder.OperatorId.ToString();
            return Results.Conflict(new Problem(
                $"This tunnel is held by {handle} since {holder.AcquiredAt:O}; "
                + "a relay cannot bind until they release it or disconnect."));
        }

        var bind = new TaskRelayHub.RelayBind(
            new EngagementId(engagementValue),
            task.ImplantId,
            new TaskId(taskValue),
            operatorId.Value,
            task.Verb,
            address,
            port);
        var bound = forward
            ? await relays.OpenAsync(bind, cancellationToken)
            : await socks.OpenAsync(bind, cancellationToken);
        if (bound is null)
            return Results.Conflict(new Problem("A relay is already bound for this task."));

        // The bind is the operator's action on the engagement (architecture.md
        // Sec 11): attributed to the binder, bound to the tunnel's task, the
        // payload the listen endpoint the tool connects to. How the relay ended
        // rides the RelayClosed event the hub writes on close.
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagementValue,
                operatorId: operatorId.Value.Value,
                implantId: task.ImplantId.Value,
                taskId: taskValue,
                verb: task.Verb,
                kind: AuditEventKind.RelayBound,
                payload: $"{address}:{bound.Value.Port}",
                output: null,
                outcome: "bound",
                at: clock.GetUtcNow()),
            cancellationToken);

        return Results.Created(
            $"/engagements/{engagementId}/tasks/{taskValue}/relay",
            new RelayBindResponse(new TaskId(taskValue).ToString(), bound.Value.Host, bound.Value.Port));
    }

    // Ends a relay bind early. The tunnel itself stays up -- the relay is one
    // bridge onto the channel, not the channel; the operator can bind again or
    // keep driving the tunnel by input posts.
    private static async Task<IResult> UnbindRelayAsync(
        string engagementId,
        string taskId,
        ClaimsPrincipal user,
        ITaskRepository tasks,
        TaskRelayHub relays,
        SocksProxyHub socks,
        CancellationToken cancellationToken)
    {
        if (user.TryGetOperatorId() is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(taskId, out var taskValue))
            return Results.BadRequest(new Problem("Task id is not a valid identifier."));

        var task = await tasks.FindAsync(new TaskId(taskValue), cancellationToken);
        if (task is null || task.EngagementId != new EngagementId(engagementValue))
            return Results.NotFound(new Problem("Task does not exist in this engagement."));
        if (!relays.IsBound(taskValue) && !socks.IsBound(taskValue))
            return Results.NotFound(new Problem("No relay is bound for this task."));

        relays.CloseTask(taskValue, "the operator unbound the relay");
        socks.CloseTask(taskValue, "the operator unbound the relay");
        return Results.NoContent();
    }

    // The relay listen address grammar: "loopback" (the default), "any", or an
    // IP literal. Names are refused -- a typo'd hostname must not silently
    // bind loopback, and DNS at bind time is a dependency a relay does not
    // need.
    private static bool TryParseRelayAddress(string? text, out System.Net.IPAddress address, out string error)
    {
        const string loopback = "loopback";
        const string any = "any";
        if (string.IsNullOrWhiteSpace(text) || string.Equals(text.Trim(), loopback, StringComparison.OrdinalIgnoreCase))
        {
            address = System.Net.IPAddress.Loopback;
            error = string.Empty;
            return true;
        }
        if (string.Equals(text.Trim(), any, StringComparison.OrdinalIgnoreCase))
        {
            address = System.Net.IPAddress.Any;
            error = string.Empty;
            return true;
        }
        if (System.Net.IPAddress.TryParse(text.Trim(), out var parsed))
        {
            address = parsed;
            error = string.Empty;
            return true;
        }
        error = "Relay bind address must be 'loopback' (default), 'any', or an IP literal.";
        address = System.Net.IPAddress.Loopback;
        return false;
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    // The issuing operator is the authenticated operator; the request carries
    // the target implant and the verb to run. Content is the typed arm's
    // optional payload (architecture.md Sec 10): present when the verb's bulk
    // input outgrows the arguments string -- the server stages it as a
    // task-bound artifact, binds its sha256 into the signed arguments, and the
    // implant pulls it as downstream chunks. It rides as base64 in JSON, the
    // same shape an artifact attach uses.
    public sealed record IssueTaskRequest(
        string ImplantId,
        string Verb,
        string? Arguments,
        byte[]? Content = null);

    // Operator input for a live channel task (architecture.md Sec 10.3): the
    // bytes (base64 in JSON, the same shape staged content rides; the channel
    // itself is byte-transparent, so text encodes UTF-8 client-side) and eof --
    // the operator closing the channel's stdin.
    public sealed record TaskInputRequest(
        byte[]? Data = null,
        bool Eof = false);

    // A relay bind request (architecture.md Sec 10.1 tunnel, Sec 10.3): the
    // listen address ("loopback" by default, "any", or an IP literal) and the
    // port (0 for an ephemeral one).
    public sealed record RelayBindRequest(
        string? BindAddress = null,
        int? Port = null);

    // The bound relay: the task it bridges and the endpoint the operator's
    // tool connects to.
    public sealed record RelayBindResponse(
        string TaskId,
        string Host,
        int Port);

    // Acknowledgement for accepted input: the task it was routed to and
    // whether the post carried eof.
    public sealed record TaskInputResponse(string TaskId, bool Eof);

    public sealed record TaskIssuedResponse(
        string TaskId,
        string EngagementId,
        string ImplantId,
        string IssuedBy,
        string Verb,
        string Arguments,
        DateTimeOffset CreatedAt);

    /// <summary>
    /// One page of the engagement's task history: the page's items (oldest first
    /// within the page) plus the cursor that walks one page older, null when the
    /// beginning of the history is reached.
    /// </summary>
    public sealed record TaskListResponse(
        ImplantEndpoints.ImplantTaskResponse[] Items,
        string? NextCursor);

    public sealed record TaskResponse(
        string TaskId,
        string EngagementId,
        string ImplantId,
        string IssuedBy,
        // The issuing operator's handle, resolved at read time -- the member
        // role cannot walk the operator roster to map the id client-side, so
        // the read names the actor itself. The bare id stands in when the
        // account no longer resolves.
        string IssuedByHandle,
        string Verb,
        string Arguments,
        string Status,
        string? Output,
        string? Outcome,
        DateTimeOffset CreatedAt,
        DateTimeOffset? DispatchedAt,
        DateTimeOffset? CompletedAt,
        DateTimeOffset? CancelledAt,
        AuditEventResponse[] Audit)
    {
        public static TaskResponse Of(Task task, IReadOnlyList<AuditEvent> events, string issuedByHandle)
            => new(
                task.Id.ToString(),
                task.EngagementId.ToString(),
                task.ImplantId.ToString(),
                task.IssuedBy.ToString(),
                issuedByHandle,
                task.Verb,
                task.Arguments,
                task.Status.ToString(),
                task.Output,
                task.Outcome?.ToString(),
                task.CreatedAt,
                task.DispatchedAt,
                task.CompletedAt,
                task.CancelledAt,
                events.Select(AuditEventResponse.Of).ToArray());
    }

    // A successful retraction: the task, the operator who took it back, and
    // when. The task's read-back (GetAsync) carries the Cancelled status.
    public sealed record TaskCancelledResponse(
        string TaskId,
        string EngagementId,
        string CancelledBy,
        DateTimeOffset CancelledAt);

    public sealed record AuditEventResponse(
        Guid EventId,
        string Kind,
        string Verb,
        string Payload,
        string? Output,
        string Outcome,
        DateTimeOffset At)
    {
        public static AuditEventResponse Of(AuditEvent e)
            => new(
                e.EventId,
                e.Kind.ToString(),
                e.Verb,
                e.Payload,
                e.Output,
                e.Outcome,
                e.At);
    }

}
