using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Sessions;
using Rod.CoreState.Tasks;

namespace Rod.Transport.Endpoints;

/// <summary>
/// The operator-facing implant endpoints (, the operator UI):
/// which implants have enrolled into an engagement, with a live online indicator
/// and their retirement state, plus the tasks directed at a given implant and
/// the retire action. Joins the implant registry with the session registry so
/// the operator UI can show sessions at a glance, and reads the task registry
/// for an implant's task history. Scoped by engagement so implant identity never
/// leaks across engagements (architecture.md Sec 3).
///
/// An implant is online exactly when it has an active session; the
/// listing projects that onto the enrolled implants. Retiring an implant
/// takes it out of operation: it is marked retired, its active
/// session is closed, and the retire is recorded in the engagement audit trail.
/// Operators can also write free-text, attributed notes on an implant -- the
/// "whose beacon is this" memory -- recorded as audit events and read back
/// from the same trail, so they survive a restart like every engagement fact.
/// Labels are the marker vocabulary beside the notes (architecture.md Sec
/// 11.2): set and cleared as appended events, reduced last-wins at read time
/// off the same trail.
/// </summary>
public static class ImplantEndpoints
{
    public static IEndpointRouteBuilder MapImplantEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Operator-facing: implant views and retire require an authenticated
        // operator session.
        var group = endpoints
            .MapGroup("/engagements/{engagementId}/implants")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));
        group.MapGet("/", ListImplantsAsync).WithName(nameof(ListImplantsAsync));
        group.MapGet("/{implantId}", GetImplantAsync).WithName(nameof(GetImplantAsync));
        group.MapGet("/{implantId}/tasks", ListImplantTasksAsync)
            .WithName(nameof(ListImplantTasksAsync));
        group.MapGet("/{implantId}/notes", ListNotesAsync).WithName(nameof(ListNotesAsync));
        group.MapPost("/{implantId}/notes", AddNoteAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(AddNoteAsync));
        group.MapGet("/{implantId}/labels", ListLabelsAsync).WithName(nameof(ListLabelsAsync));
        group.MapPost("/{implantId}/labels", SetLabelAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(SetLabelAsync));
        group.MapDelete("/{implantId}/labels/{label}", ClearLabelAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(ClearLabelAsync));
        group.MapPost("/{implantId}:retire", RetireAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(RetireAsync));
        return endpoints;
    }

    private static async Task<Results<Ok<ImplantResponse[]>, BadRequest<Problem>>> ListImplantsAsync(
        string engagementId,
        IImplantRepository implants,
        ISessionRegistry sessions,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return TypedResults.BadRequest(new Problem("Engagement id is not a valid identifier."));

        var engagementKey = new EngagementId(engagementValue);
        var enrolled = await implants.ListByEngagementAsync(engagementKey, cancellationToken);
        var online = await sessions.ListActiveAsync(engagementKey, cancellationToken);
        var onlineById = online.Select(s => s.ImplantId).ToHashSet();
        var sessionById = online.ToDictionary(s => s.ImplantId);

        // Resolve the deploying operators to handles once per request, the
        // tolerance the audit read applies (the bare id when the account no
        // longer resolves): the member role cannot walk the operator roster
        // to do it client-side, so the read names the actor itself.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in enrolled.Select(i => i.DeployedBy.Value).Where(id => id != Guid.Empty).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        var body = enrolled
            .Select(i => ProjectImplant(
                i,
                onlineById.Contains(i.Id),
                sessionById.GetValueOrDefault(i.Id),
                handles.GetValueOrDefault(i.DeployedBy.Value)))
            .ToArray();

        return TypedResults.Ok(body);
    }

    // The chain walk's defense against a corrupt parent loop: no path the
    // writes can legally build reaches this, and a stale cycle must not
    // pin the read.
    private const int MaxProvenanceDepth = 64;

    // One implant's detail (architecture.md Sec 15.4): the row the listing
    // projects, plus the provenance chain around it -- the ancestors whose
    // derivations reach this implant (root first), the children it derived,
    // and the delivery campaign whose lure it followed, the recipient's
    // arc included. A chain that breaks (a parent the engagement no longer
    // resolves) renders to the break, the topology projection's posture.
    private static async Task<IResult> GetImplantAsync(
        string engagementId,
        string implantId,
        IImplantRepository implants,
        ISessionRegistry sessions,
        IOperatorRepository operators,
        CoreState.Campaigns.ICampaignStore campaigns,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(implantId, out var implantValue))
            return Results.BadRequest(new Problem("Implant id is not a valid identifier."));

        var engagementKey = new EngagementId(engagementValue);
        var implant = await implants.FindAsync(new ImplantId(implantValue), cancellationToken);
        if (implant is null || implant.EngagementId != engagementKey)
            return Results.NotFound(new Problem("Implant does not exist in this engagement."));

        var online = (await sessions.ListActiveAsync(engagementKey, cancellationToken))
            .ToDictionary(s => s.ImplantId);
        var deployedBy = await operators.FindAsync(implant.DeployedBy, cancellationToken);
        var response = ProjectImplant(
            implant,
            online.ContainsKey(implant.Id),
            online.GetValueOrDefault(implant.Id),
            deployedBy?.Handle ?? implant.DeployedBy.ToString());

        // The ancestors: walk parent links outward until the chain roots,
        // breaks, or hits the depth guard -- a parent outside this
        // engagement (not a legal write, but a defensive read) ends the
        // walk the same way a missing one does.
        var ancestors = new List<ProvenanceAncestor>();
        var visited = new HashSet<ImplantId> { implant.Id };
        var walker = implant.ParentImplantId;
        while (walker is { } parentId && visited.Add(parentId) && ancestors.Count < MaxProvenanceDepth)
        {
            var parent = await implants.FindAsync(parentId, cancellationToken);
            if (parent is null || parent.EngagementId != engagementKey)
                break;

            ancestors.Add(new ProvenanceAncestor(
                parent.Id.ToString(),
                parent.Hostname,
                parent.Os,
                parent.Class.ToString(),
                parent.CreatedAt,
                parent.RetiredAt));
            walker = parent.ParentImplantId;
        }
        ancestors.Reverse(); // root first: how the fleet's reach grew into this implant

        // The children: the lateral-movement tree this implant rooted.
        var children = (await implants.ListByEngagementAsync(engagementKey, cancellationToken))
            .Where(i => i.ParentImplantId == implant.Id)
            .OrderBy(i => i.CreatedAt)
            .Select(i => new ProvenanceChild(i.Id.ToString(), i.Hostname, i.Class.ToString(), i.CreatedAt))
            .ToList();

        // The campaign leg: the lure this implant followed, the recipient
        // row it redeemed, and the target-selection record riding it.
        CoreState.Campaigns.Campaign? campaignRow = null;
        if (implant.CampaignId is { } campaignId)
            campaignRow = await campaigns.FindAsync(campaignId, engagementKey, cancellationToken);
        var recipient = campaignRow is null || implant.CampaignRecipientId is not { } recipientId
            ? null
            : campaignRow.FindRecipient(recipientId);
        var campaign = campaignRow is null || recipient is null
            ? null
            : new ImplantCampaignProvenance(
                campaignRow.Id.ToString(),
                campaignRow.Name,
                campaignRow.State.ToString().ToLowerInvariant(),
                recipient.Id.ToString(),
                recipient.Email,
                recipient.Name,
                recipient.SentAt,
                recipient.OpenedAt,
                recipient.ClickedAt,
                recipient.ExecutedAt,
                recipient.PayloadId?.ToString(),
                recipient.ReconAssetId?.ToString());

        return Results.Ok(new ImplantDetailResponse(
            response,
            new ImplantProvenanceResponse(ancestors, children, campaign)));
    }

    // The listing/detail row projection, one shape for both reads.
    private static ImplantResponse ProjectImplant(
        Implant i, bool isOnline, Rod.CoreState.Sessions.Session? session,
        string? deployedByHandle) => new(
        i.Id.ToString(),
        i.EngagementId.ToString(),
        i.Class.ToString(),
        i.KillDate,
        i.CreatedAt,
        IsOnline: isOnline,
        i.RetiredAt,
        ParentImplantId: i.ParentImplantId?.ToString(),
        Hostname: i.Hostname,
        Os: i.Os,
        Arch: i.Arch,
        Username: i.Username,
        SleepSeconds: i.SleepSeconds,
        JitterSeconds: i.JitterSeconds,
        DeployedBy: i.DeployedBy.ToString(),
        DeployedByHandle: deployedByHandle,
        EnrolledViaListenerId: i.EnrolledViaListenerId?.ToString("N"),
        LastSeenAt: i.LastSeenAt,
        LastCarrier: session?.LastCarrier,
        Carriers: i.Carriers,
        CampaignId: i.CampaignId?.ToString(),
        CampaignRecipientId: i.CampaignRecipientId?.ToString());

    private static async Task<IResult> ListImplantTasksAsync(
        string engagementId,
        string implantId,
        int? limit,
        string? cursor,
        IImplantRepository implants,
        ITaskRepository tasks,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(implantId, out var implantValue))
            return Results.BadRequest(new Problem("Implant id is not a valid identifier."));
        if (!ListPaging.TryBind(limit, cursor, c => TaskPageCursor.TryDecode(c, out _),
                out var boundLimit, out var boundCursor, out var pagingError))
        {
            return Results.BadRequest(new Problem(pagingError));
        }

        // Confirm the implant belongs to this engagement before listing its
        // tasks; a foreign implant id yields no rows here (architecture.md Sec 3).
        var implant = await implants.FindAsync(new ImplantId(implantValue), cancellationToken);
        if (implant is null || implant.EngagementId != new EngagementId(engagementValue))
            return Results.NotFound(new Problem("Implant does not exist in this engagement."));

        // One page of the implant's task history, same cursor semantics and
        // envelope as the engagement-wide listing.
        var page = await tasks.ListByImplantPageAsync(
            new ImplantId(implantValue), boundLimit, boundCursor, cancellationToken);

        // Resolve the page's issuing operators to handles once per request,
        // the tolerance the audit read applies (the bare id when the account
        // no longer resolves) -- the same resolution the engagement-wide
        // listing performs, so the two task-list shapes agree.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in page.Items.Select(t => t.IssuedBy.Value).Where(id => id != Guid.Empty).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        var body = new TaskEndpoints.TaskListResponse(
            page.Items
                .Select(t => new ImplantTaskResponse(
                    t.Id.ToString(),
                    t.ImplantId.ToString(),
                    t.IssuedBy.ToString(),
                    handles.GetValueOrDefault(t.IssuedBy.Value, t.IssuedBy.Value.ToString()),
                    t.Verb,
                    t.Arguments,
                    t.Status.ToString(),
                    t.Output,
                    t.Outcome?.ToString(),
                    t.CreatedAt,
                    t.CompletedAt))
                .ToArray(),
            page.NextCursor);

        return Results.Ok(body);
    }

    // A note is a sentence or three -- "web server, HVXC-web-03, JBS's box" --
    // not a paste target; anything larger belongs in an artifact attached to a
    // task. Bounded so one post cannot pin the trail's JSON lines.
    private const int MaxNoteChars = 8 * 1024;    // Operator notes on implants: the free-text, attributed "whose beacon is
    // this" memory. Notes are recorded as ImplantNoteAdded audit events and
    // read back from the same trail (architecture.md Sec 11), so they ride the
    // hash chain -- attributed, immutable, and durable exactly like every other
    // engagement fact -- with no separate note store to keep consistent.
    private static async Task<IResult> ListNotesAsync(
        string engagementId,
        string implantId,
        IImplantRepository implants,
        IAuditStore audit,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(implantId, out var implantValue))
            return Results.BadRequest(new Problem("Implant id is not a valid identifier."));

        // Confirm the implant belongs to this engagement before reading its
        // notes; a foreign implant id yields no rows here (architecture.md Sec 3).
        var implant = await implants.FindAsync(new ImplantId(implantValue), cancellationToken);
        if (implant is null || implant.EngagementId != new EngagementId(engagementValue))
            return Results.NotFound(new Problem("Implant does not exist in this engagement."));

        var events = await audit.ForImplantAsync(implantValue, cancellationToken);
        var notes = events
            .Where(e => e.Kind == AuditEventKind.ImplantNoteAdded)
            .ToArray();

        // Resolve the notes' authors to handles once per request, the
        // tolerance the audit read applies (the bare id when the account no
        // longer resolves): the member role cannot walk the operator roster
        // to do it client-side, so the read names the actor itself.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in notes.Select(e => e.OperatorId).Where(id => id != Guid.Empty).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        return Results.Ok(notes
            .Select(e => new ImplantNoteResponse(
                e.EventId.ToString(),
                new ImplantId(e.ImplantId).ToString(),
                new OperatorId(e.OperatorId).ToString(),
                handles.GetValueOrDefault(e.OperatorId, e.OperatorId.ToString()),
                e.Payload,
                e.At))
            .ToArray());
    }

    private static async Task<IResult> AddNoteAsync(
        string engagementId,
        string implantId,
        AddNoteRequest body,
        ClaimsPrincipal user,
        IImplantRepository implants,
        IAuditStore audit,
        IOperatorRepository operators,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        // The writing operator is the authenticated operator, resolved off the
        // session principal rather than named in the body (operator auth).
        var author = user.TryGetOperatorId();
        if (author is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(implantId, out var implantValue))
            return Results.BadRequest(new Problem("Implant id is not a valid identifier."));
        if (string.IsNullOrWhiteSpace(body.Text))
            return Results.BadRequest(new Problem("Note text is required."));
        if (body.Text.Length > MaxNoteChars)
            return Results.Json(
                new Problem($"Note text exceeds {MaxNoteChars} characters."),
                statusCode: StatusCodes.Status413PayloadTooLarge);

        var implant = await implants.FindAsync(new ImplantId(implantValue), cancellationToken);
        if (implant is null || implant.EngagementId != new EngagementId(engagementValue))
            return Results.NotFound(new Problem("Implant does not exist in this engagement."));

        // The note is the operator's action on the engagement (architecture.md
        // Sec 11): attributed to the writer, bound to the implant it describes,
        // the payload the note text itself. Reading it back is a query over the
        // same trail, so the note's only storage is the chain.
        var at = clock.GetUtcNow();
        var noteId = Guid.NewGuid();
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: noteId,
                engagementId: engagementValue,
                operatorId: author.Value.Value,
                implantId: implantValue,
                taskId: Guid.Empty,
                verb: "note",
                kind: AuditEventKind.ImplantNoteAdded,
                payload: body.Text,
                output: null,
                outcome: "added",
                at: at),
            cancellationToken);

        // The writer is the principal itself; resolve the handle with the
        // tolerance the listing applies.
        var writer = await operators.FindAsync(author.Value, cancellationToken);

        return Results.Created(
            $"/engagements/{engagementId}/implants/{implantId}/notes",
            new ImplantNoteResponse(
                noteId.ToString(),
                implantId,
                author.Value.ToString(),
                writer?.Handle ?? author.Value.ToString(),
                body.Text,
                at));
    }

    // A label is a marker, not a sentence: "jump", "owned", "watch-edr". The
    // bounds keep the vocabulary chip-sized on the fleet view and the trail's
    // JSON lines cheap, and cap how many distinct markers one implant carries
    // so the set stays a picture, not a diary.
    private const int MaxLabelChars = 64;
    private const int MaxLabelsPerImplant = 32;

    // Operator labels on implants: the set/clear marker vocabulary the intel
    // layer groups and filters by (architecture.md Sec 11.2). Like notes, a
    // label's only storage is the trail -- ImplantLabeled events reduced at
    // read time last-wins per label, so setting and clearing are appends and
    // the append-only chain never rewrites history to change a label.
    private static async Task<IResult> ListLabelsAsync(
        string engagementId,
        string implantId,
        IImplantRepository implants,
        IAuditStore audit,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(implantId, out var implantValue))
            return Results.BadRequest(new Problem("Implant id is not a valid identifier."));

        // Confirm the implant belongs to this engagement before reading its
        // labels; a foreign implant id yields no rows here (architecture.md
        // Sec 3).
        var implant = await implants.FindAsync(new ImplantId(implantValue), cancellationToken);
        if (implant is null || implant.EngagementId != new EngagementId(engagementValue))
            return Results.NotFound(new Problem("Implant does not exist in this engagement."));

        var reduced = ReduceLabels(await audit.ForImplantAsync(implantValue, cancellationToken));

        // Resolve the labels' setters to handles once per request, the
        // tolerance the audit read applies (the bare id when the account no
        // longer resolves): the member role cannot walk the operator roster
        // to do it client-side, so the read names the actor itself.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in reduced.Select(l => l.OperatorId).Where(id => id != Guid.Empty).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        return Results.Ok(reduced
            .Select(l => new ImplantLabelResponse(
                l.Label,
                new OperatorId(l.OperatorId).ToString(),
                handles.GetValueOrDefault(l.OperatorId, l.OperatorId.ToString()),
                l.At))
            .ToArray());
    }

    private static async Task<IResult> SetLabelAsync(
        string engagementId,
        string implantId,
        SetLabelRequest body,
        ClaimsPrincipal user,
        IImplantRepository implants,
        IAuditStore audit,
        IOperatorRepository operators,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        // The acting operator is the authenticated operator, resolved off the
        // session principal rather than named in the body (operator auth).
        var actor = user.TryGetOperatorId();
        if (actor is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(implantId, out var implantValue))
            return Results.BadRequest(new Problem("Implant id is not a valid identifier."));
        var label = body.Label?.Trim();
        if (string.IsNullOrWhiteSpace(label))
            return Results.BadRequest(new Problem("Label text is required."));
        if (label.Length > MaxLabelChars)
            return Results.BadRequest(new Problem($"Label text exceeds {MaxLabelChars} characters."));

        var implant = await implants.FindAsync(new ImplantId(implantValue), cancellationToken);
        if (implant is null || implant.EngagementId != new EngagementId(engagementValue))
            return Results.NotFound(new Problem("Implant does not exist in this engagement."));

        // The cap is evaluated against the reduced set, so re-setting a label
        // the implant already carries never trips it and a cleared label's
        // slot is free again.
        var current = ReduceLabels(await audit.ForImplantAsync(implantValue, cancellationToken));
        if (current.Count >= MaxLabelsPerImplant
            && !current.Any(l => string.Equals(l.Label, label, StringComparison.OrdinalIgnoreCase)))
        {
            return Results.Json(
                new Problem($"An implant carries at most {MaxLabelsPerImplant} labels."),
                statusCode: StatusCodes.Status422UnprocessableEntity);
        }

        // The label change is the operator's action on the engagement
        // (architecture.md Sec 11.2): attributed to the actor, bound to the
        // implant it marks, the payload the label text, the outcome the
        // action. The reduced set is a query over the same trail.
        var at = clock.GetUtcNow();
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagementValue,
                operatorId: actor.Value.Value,
                implantId: implantValue,
                taskId: Guid.Empty,
                verb: "label",
                kind: AuditEventKind.ImplantLabeled,
                payload: label,
                output: null,
                outcome: "set",
                at: at),
            cancellationToken);

        // The setter is the principal itself; resolve the handle with the
        // tolerance the listing applies.
        var setter = await operators.FindAsync(actor.Value, cancellationToken);

        return Results.Created(
            $"/engagements/{engagementId}/implants/{implantId}/labels",
            new ImplantLabelResponse(label, actor.Value.ToString(), setter?.Handle ?? actor.Value.ToString(), at));
    }

    private static async Task<IResult> ClearLabelAsync(
        string engagementId,
        string implantId,
        string label,
        ClaimsPrincipal user,
        IImplantRepository implants,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        // The acting operator is the authenticated operator, resolved off the
        // session principal rather than named in the body (operator auth).
        var actor = user.TryGetOperatorId();
        if (actor is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(implantId, out var implantValue))
            return Results.BadRequest(new Problem("Implant id is not a valid identifier."));

        var implant = await implants.FindAsync(new ImplantId(implantValue), cancellationToken);
        if (implant is null || implant.EngagementId != new EngagementId(engagementValue))
            return Results.NotFound(new Problem("Implant does not exist in this engagement."));

        // Idempotent like retirement: every clear is appended, so the trail
        // reflects each operator action even when the label was already gone;
        // the reduction decides what the live set holds.
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagementValue,
                operatorId: actor.Value.Value,
                implantId: implantValue,
                taskId: Guid.Empty,
                verb: "label",
                kind: AuditEventKind.ImplantLabeled,
                payload: label,
                output: null,
                outcome: "cleared",
                at: clock.GetUtcNow()),
            cancellationToken);

        return Results.NoContent();
    }

    // The live label set: walk the implant's label events oldest first and let
    // the newest action per label win (case-insensitive -- "web" and "Web"
    // are the same marker). Returns the reduced set in the order the labels
    // were (re)set, as raw facts -- the read edge shapes the response and
    // resolves the setter handles.
    private static List<(string Label, Guid OperatorId, DateTimeOffset At)> ReduceLabels(
        IReadOnlyList<AuditEvent> events)
    {
        var order = new List<string>();
        var byLabel = new Dictionary<string, (string Label, Guid OperatorId, DateTimeOffset At)>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var e in events)
        {
            if (e.Kind != AuditEventKind.ImplantLabeled)
                continue;

            if (string.Equals(e.Outcome, "cleared", StringComparison.OrdinalIgnoreCase))
            {
                if (byLabel.Remove(e.Payload))
                    order.Remove(e.Payload);
                continue;
            }

            if (!byLabel.ContainsKey(e.Payload))
                order.Add(e.Payload);
            byLabel[e.Payload] = (e.Payload, e.OperatorId, e.At);
        }

        return order.Select(label => byLabel[label]).ToList();
    }

    private static async Task<IResult> RetireAsync(
        string engagementId,
        string implantId,
        ClaimsPrincipal user,
        ImplantService service,
        IAuditStore audit,
        CancellationToken cancellationToken)
    {
        // The retiring operator is the authenticated operator, resolved off the
        // session principal rather than named in the body (operator auth).
        var retiredBy = user.TryGetOperatorId();
        if (retiredBy is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (!Guid.TryParse(implantId, out var implantValue))
            return Results.BadRequest(new Problem("Implant id is not a valid identifier."));

        Rod.CoreState.Application.ImplantRetired retired;
        try
        {
            retired = await service.RetireAsync(
                new RetireImplantCommand(
                    new EngagementId(engagementValue),
                    new ImplantId(implantValue),
                    retiredBy.Value),
                cancellationToken);
        }
        catch (ImplantNotFoundException ex)
        {
            // Unknown or foreign implant -- same shape the listing and task
            // endpoints return for a foreign implant (architecture.md Sec 3).
            return Results.NotFound(new Problem(ex.Message));
        }

        // The retire is recorded (architecture.md Sec 11): an ImplantRetired
        // audit event in the engagement trail, attributed to the retiring
        // operator. The outcome is the recorded retirement timestamp. No task is
        // involved -- retirement is an operator action on the implant. The store
        // stamps the chain hashes on append; the call site supplies only the
        // facts. Idempotent: a duplicate retire is still recorded, so the trail
        // reflects every operator action; JustRetired distinguishes the first.
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: retired.EngagementId.Value,
                operatorId: retired.RetiredBy.Value,
                implantId: retired.ImplantId.Value,
                taskId: Guid.Empty,
                verb: "retire",
                kind: AuditEventKind.ImplantRetired,
                payload: retired.JustRetired ? "retired" : "already retired",
                output: null,
                outcome: retired.RetiredAt.ToString("O"),
                at: retired.RetiredAt),
            cancellationToken);

        return Results.Ok(new RetireImplantResponse(
            retired.ImplantId.ToString(),
            retired.EngagementId.ToString(),
            retired.RetiredBy.ToString(),
            retired.RetiredAt,
            retired.JustRetired,
            retired.ClosedSession?.ToString()));
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    public sealed record ImplantResponse(
        string ImplantId,
        string EngagementId,
        string Class,
        // The artifact's time fuse as reported at enroll; null = open-ended.
        DateTimeOffset? KillDate,
        DateTimeOffset CreatedAt,
        bool IsOnline,
        DateTimeOffset? RetiredAt,
        string? ParentImplantId = null,
        string? Hostname = null,
        string? Os = null,
        string? Arch = null,
        string? Username = null,
        // The contact cadence the implant last advertised, in seconds; null
        // on either half means "not reported".
        double? SleepSeconds = null,
        double? JitterSeconds = null,
        // The operator the implant's events attribute to (the token issuer).
        string? DeployedBy = null,
        // The deploying operator's handle, resolved at read time -- the
        // member role cannot walk the operator roster to map the id
        // client-side, so the read names the actor itself. The bare id
        // stands in when the account no longer resolves.
        string? DeployedByHandle = null,
        // The listener whose socket carried the enrollment, when the transport
        // could attribute one -- what a listener deletion warns about.
        string? EnrolledViaListenerId = null,
        // The durable heartbeat: when the teamserver last heard from the
        // implant, kept after the session is gone. While a session is active
        // the presence roster's stamp is the fresher one.
        DateTimeOffset? LastSeenAt = null,
        // The carrier the live session's last contact rode (the degraded
        // vocabulary on Session.LastCarrier); null while offline or when no
        // contact recorded one.
        string? LastCarrier = null,
        // The baked carrier set the artifact's endpoints dial; null when the
        // enroll derived none.
        IReadOnlyList<string>? Carriers = null,
        // The delivery campaign whose lure this implant followed (Sec 11.5):
        // the campaign and the recipient row, null pair on every ordinary
        // enrollment.
        string? CampaignId = null,
        string? CampaignRecipientId = null);

    // --- The provenance chain (architecture.md Sec 15.4): the detail
    // read's second half, the related-entities sidebar before the UI
    // rework ships it. ---

    // One implant's detail: the row (the listing's own projection) plus
    // the chain around it.
    public sealed record ImplantDetailResponse(
        ImplantResponse Implant,
        ImplantProvenanceResponse Provenance);

    // The chain: ancestors root-first, the children this implant derived,
    // and the campaign leg (null on every ordinary, campaign-free
    // enrollment).
    public sealed record ImplantProvenanceResponse(
        IReadOnlyList<ProvenanceAncestor> Ancestors,
        IReadOnlyList<ProvenanceChild> Children,
        ImplantCampaignProvenance? Campaign);

    // One ancestor: a parent derivation on the path from the first
    // foothold to this implant.
    public sealed record ProvenanceAncestor(
        string ImplantId,
        string? Hostname,
        string? Os,
        string Class,
        DateTimeOffset CreatedAt,
        DateTimeOffset? RetiredAt);

    // One child: an implant this one derived -- the lateral-movement
    // tree this detail roots.
    public sealed record ProvenanceChild(
        string ImplantId,
        string? Hostname,
        string Class,
        DateTimeOffset CreatedAt);

    // The campaign leg: the lure this implant followed, the recipient row
    // whose baked credential it redeemed, and the recon asset the target
    // was selected from when it was (Sec 15.4's link, read back).
    public sealed record ImplantCampaignProvenance(
        string CampaignId,
        string CampaignName,
        string CampaignState,
        string RecipientId,
        string Email,
        string? Name,
        DateTimeOffset? SentAt,
        DateTimeOffset? OpenedAt,
        DateTimeOffset? ClickedAt,
        DateTimeOffset? ExecutedAt,
        string? PayloadId,
        string? ReconAssetId);

    public sealed record ImplantTaskResponse(
        string TaskId,
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
        DateTimeOffset? CompletedAt);

    // A note's request body: the free-form text. The author is the
    // authenticated operator, never a body field.
    public sealed record AddNoteRequest(string Text);

    // A label's request body: the marker text. The actor is the authenticated
    // operator, never a body field.
    public sealed record SetLabelRequest(string Label);

    // One note on an implant: the audit event's id (a note is its event -- the
    // two are one object), the implant it describes, the writing operator and
    // its handle (resolved at read time; the bare id stands in when the
    // account no longer resolves), the text, and when.
    public sealed record ImplantNoteResponse(
        string NoteId,
        string ImplantId,
        string Author,
        string AuthorHandle,
        string Text,
        DateTimeOffset At);

    // One label an implant currently carries: the marker text, the operator
    // whose set action last won the reduction and its handle (resolved at
    // read time; the bare id stands in when the account no longer resolves),
    // and when. No event id -- a label is the reduced state of many events,
    // not one object the way a note is.
    public sealed record ImplantLabelResponse(
        string Label,
        string SetBy,
        string SetByHandle,
        DateTimeOffset SetAt);

    public sealed record RetireImplantResponse(
        string ImplantId,
        string EngagementId,
        string RetiredBy,
        DateTimeOffset RetiredAt,
        bool JustRetired,
        string? ClosedSession);

}
