using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Tasks;
// The domain entity shares its name with System.Threading.Tasks.Task. Pin it
// here so the builder's fields refer to the engagement task, not the BCL type;
// the BCL type is reached by its full name where the handlers return it.
using Task = Rod.CoreState.Tasks.Task;

namespace Rod.Transport.Endpoints;

/// <summary>
/// The operator-facing timeline, report export, and shift handoff digest
/// endpoints: the built-in consumers of the event + task + artifact store
/// (architecture.md Sec 11).
/// A red-team operation ends in a deliverable -- a timeline, findings, and evidence
/// -- and Rod treats the audit trail as the <em>source for report generation</em>,
/// not a post-hoc scrape. These endpoints render the per-engagement trail, tasks,
/// implants, operators, and artifact index directly into that deliverable, both as
/// JSON (machine-consumed, e.g. by an operator UI) and as Markdown (the human
/// deliverable). The digest (Sec 11.1) is the same projection at watch scale: a
/// windowed, kind-whitelisted account for the operator resuming the watch.
///
/// Read-only by construction: like the audit read and the artifact
/// listing, these endpoints compose nothing onto the trail and mutate no state.
/// Every engagement fact they surface is already durable and attributed; the
/// report is a projection of it. Scoped by engagement (architecture.md Sec 3): the
/// engagement id in the path binds every lookup, and a foreign or unknown
/// engagement yields a 404 rather than another engagement's evidence.
///
/// Reproducibility: each response carries a <see cref="TimelineReport.ContentHash"/>
/// / <see cref="EngagementReport.ContentHash"/> -- a SHA-256 hex digest over a
/// canonical join of the engagement's facts, excluding only the wall-clock
/// <c>generatedAt</c>. Two exports of identical state are byte-for-byte equal in
/// hash; the digest joins the engagement summary, every operator, implant, task,
/// artifact, and each timeline event's stored <see cref="AuditEvent.Hash"/> (which
/// itself commits to its predecessor via <see cref="AuditChain"/>), so the report's
/// integrity anchor is the same tamper-evident trail head the audit read observes.
/// </summary>
public static class ReportEndpoints
{
    // The digest window contract (architecture.md Sec 11.1): `to` defaults to
    // now, `from` to twelve hours before it -- one long watch plus the handoff
    // gap -- and the span cap keeps a single ordered account bounded. Longer
    // horizons are the timeline's job, which pages.
    private static readonly TimeSpan DefaultDigestWindow = TimeSpan.FromHours(12);
    private static readonly TimeSpan MaxDigestWindow = TimeSpan.FromDays(31);

    public static IEndpointRouteBuilder MapReportEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Operator-facing: timeline/report deliverables and the handoff digest
        // require an authenticated operator session.
        var group = endpoints
            .MapGroup("/engagements/{engagementId}")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));
        group.MapGet("/timeline", GetTimelineAsync).WithName(nameof(GetTimelineAsync));
        group.MapGet("/report", GetReportAsync).WithName(nameof(GetReportAsync));
        group.MapGet("/report/attack-layer", GetAttackLayerAsync).WithName(nameof(GetAttackLayerAsync));
        group.MapGet("/handoff-digest", GetHandoffDigestAsync).WithName(nameof(GetHandoffDigestAsync));
        return endpoints;
    }

    private static async Task<IResult> GetTimelineAsync(
        string engagementId,
        string? format,
        IEngagementRepository engagements,
        IAuditStore audit,
        IArtifactStore artifacts,
        IOperatorRepository operators,
        IImplantRepository implants,
        ITaskRepository tasks,
        IEngagementMembershipStore memberships,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        var engagement = await engagements.FindAsync(new EngagementId(engagementValue), cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));

        var builder = await ReportBuilder.BuildAsync(
            engagement, audit, artifacts, operators, implants, tasks, memberships, cancellationToken);

        var timeline = builder.Timeline(engagement);
        return format is { } f && IsMarkdown(f)
            ? MarkdownTimeline(timeline)
            : Results.Ok(timeline);
    }

    private static async Task<IResult> GetReportAsync(
        string engagementId,
        string? format,
        IEngagementRepository engagements,
        IAuditStore audit,
        IArtifactStore artifacts,
        IOperatorRepository operators,
        IImplantRepository implants,
        ITaskRepository tasks,
        IEngagementMembershipStore memberships,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        var engagement = await engagements.FindAsync(new EngagementId(engagementValue), cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));

        var builder = await ReportBuilder.BuildAsync(
            engagement, audit, artifacts, operators, implants, tasks, memberships, cancellationToken);

        var report = builder.Report(engagement);
        return format is { } f && IsMarkdown(f)
            ? MarkdownReport(report)
            : Results.Ok(report);
    }

    private static async Task<IResult> GetAttackLayerAsync(
        string engagementId,
        IVerbTechniqueResolver techniques,
        IEngagementRepository engagements,
        IAuditStore audit,
        IArtifactStore artifacts,
        IOperatorRepository operators,
        IImplantRepository implants,
        ITaskRepository tasks,
        IEngagementMembershipStore memberships,
        CancellationToken cancellationToken)
    {
        // The "what was done" face of the ATT&CK mapping (ADR-007): an
        // engagement-scoped Navigator layer over the same projection the
        // report renders, resolved through the same technique resolver the
        // coverage matrix reads. Transport cannot reach the capabilities
        // layer, so the resolver arrives through the core-state port -- the
        // same dependency shape the other read-side projections use.
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        var engagement = await engagements.FindAsync(new EngagementId(engagementValue), cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));

        var builder = await ReportBuilder.BuildAsync(
            engagement, audit, artifacts, operators, implants, tasks, memberships, cancellationToken);

        var report = builder.Report(engagement);
        return Results.Ok(AttackNavigatorLayer.Build(report, techniques));
    }

    private static async Task<IResult> GetHandoffDigestAsync(
        string engagementId,
        string? from,
        string? to,
        string? format,
        IEngagementRepository engagements,
        IAuditStore audit,
        IArtifactStore artifacts,
        IOperatorRepository operators,
        IImplantRepository implants,
        ITaskRepository tasks,
        IEngagementMembershipStore memberships,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        var engagement = await engagements.FindAsync(new EngagementId(engagementValue), cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));

        var windowEnd = clock.GetUtcNow();
        if (to is { } toText)
        {
            if (!TryParseTimestamp(toText, out var parsed))
                return Results.BadRequest(new Problem("to must be an ISO 8601 timestamp."));
            windowEnd = parsed;
        }

        var windowStart = windowEnd - DefaultDigestWindow;
        if (from is { } fromText)
        {
            if (!TryParseTimestamp(fromText, out var parsed))
                return Results.BadRequest(new Problem("from must be an ISO 8601 timestamp."));
            windowStart = parsed;
        }

        if (windowStart >= windowEnd)
            return Results.BadRequest(new Problem("from must precede to."));
        if (windowEnd - windowStart > MaxDigestWindow)
            return Results.BadRequest(new Problem(
                $"The digest window must not exceed {MaxDigestWindow.Days} days; use the timeline for longer horizons."));

        var builder = await ReportBuilder.BuildAsync(
            engagement, audit, artifacts, operators, implants, tasks, memberships, cancellationToken);

        var digest = builder.HandoffDigest(engagement, windowStart, windowEnd);
        return format is { } f && IsMarkdown(f)
            ? Results.Text(HandoffDigestMarkdown.Render(digest), "text/markdown; charset=utf-8", Encoding.UTF8)
            : Results.Ok(digest);
    }

    private static bool TryParseTimestamp(string text, out DateTimeOffset value)
        => DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out value);

    private static bool IsMarkdown(string format)
        => format.Equals("markdown", StringComparison.OrdinalIgnoreCase)
            || format.Equals("md", StringComparison.OrdinalIgnoreCase);

    // Markdown deliverables: text/markdown over UTF-8. JSON stays inline (the
    // operator UI and any scripting consume it directly).
    private static IResult MarkdownTimeline(TimelineReport timeline)
        => Results.Text(TimelineMarkdown.Render(timeline), "text/markdown; charset=utf-8", Encoding.UTF8);

    private static IResult MarkdownReport(EngagementReport report)
        => Results.Text(ReportMarkdown.Render(report), "text/markdown; charset=utf-8", Encoding.UTF8);
}

/// <summary>
/// Builds the engagement report projection: enriches the per-engagement audit
/// trail, tasks, implants, operators, and artifacts into the report DTOs and
/// computes the reproducibility hash. State is read once and held here so a single
/// report call resolves each operator/implant/task at most once (the engagement's
/// entities are small and enumerable; the trail and the task history are the long
/// lists).
///
/// The builder never reaches outside the engagement: every store query is
/// engagement-scoped, so cross-engagement access never returns another engagement's
/// evidence (architecture.md Sec 3).
/// </summary>
internal static class ReportBuilder
{
    // The digest's kind whitelist (architecture.md Sec 11.1): the watch's
    // operational beats. Dispatch plumbing, payload fetches, and configuration
    // churn stay out -- the timeline remains the view for them.
    internal static readonly IReadOnlySet<AuditEventKind> DigestKinds = new HashSet<AuditEventKind>
    {
        AuditEventKind.SessionOpened,
        AuditEventKind.SessionClosed,
        AuditEventKind.ImplantEnrolled,
        AuditEventKind.ImplantRetired,
        AuditEventKind.TaskIssued,
        AuditEventKind.TaskCompleted,
        AuditEventKind.TaskCancelled,
        AuditEventKind.TaskRoeRefused,
        AuditEventKind.ImplantNoteAdded,
        AuditEventKind.ShellSessionOpened,
        AuditEventKind.ShellSessionEnded,
    };

    public static async Task<ReportBuilderContext> BuildAsync(
        Engagement engagement,
        IAuditStore audit,
        IArtifactStore artifacts,
        IOperatorRepository operators,
        IImplantRepository implants,
        ITaskRepository tasks,
        IEngagementMembershipStore memberships,
        CancellationToken cancellationToken)
    {
        var engagementId = engagement.Id;
        var engagementValue = engagementId.Value;

        // The engagement's full evidence surface, each list scoped to it. The
        // trail and tasks are oldest-first by contract; implants, operators, and
        // artifacts resolve per entity.
        var trail = await audit.ListAsync(engagementValue, cancellationToken);
        // Verify the hash chain before any export is built: the deliverable is
        // evidence, so a tampered trail must be flagged in the output rather
        // than silently rendered (architecture.md Sec 11).
        var chainBreak = AuditChain.VerifyTrail(trail);
        var engagementImplants = await implants.ListByEngagementAsync(engagementId, cancellationToken);
        var engagementTasks = await tasks.ListByEngagementAsync(engagementId, cancellationToken);
        var engagementArtifacts = await artifacts.ListAsync(engagementValue, cancellationToken);
        var engagementMembers = await memberships.ListAsync(engagementId, cancellationToken);

        // Operator resolution: the engagement owner and every operator named on
        // the trail/task/artifact. Unknown ids (an event predates the operator
        // record) fall back to the bare id -- the same tolerance the engagement
        // listing applies. The default Guid.Empty operator (implant-initiated
        // events that predate attribution) renders as "system".
        var operatorIds = new HashSet<Guid>();
        operatorIds.Add(engagement.OwnerId.Value);
        foreach (var m in engagementMembers)
            operatorIds.Add(m.OperatorId.Value);
        foreach (var e in trail)
            if (e.OperatorId != Guid.Empty)
                operatorIds.Add(e.OperatorId);
        foreach (var t in engagementTasks)
            operatorIds.Add(t.IssuedBy.Value);
        foreach (var a in engagementArtifacts)
            if (a.OperatorId is { } op)
                operatorIds.Add(op);

        var operatorNames = new Dictionary<Guid, string>();
        foreach (var id in operatorIds)
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            operatorNames[id] = op?.Handle ?? id.ToString();
        }

        // Implant resolution: class enriches the trail entries and the inventory.
        var implantById = new Dictionary<Guid, Implant>();
        foreach (var implant in engagementImplants)
            implantById[implant.Id.Value] = implant;

        var implantClasses = new Dictionary<Guid, string>();
        foreach (var e in trail)
            if (e.ImplantId != Guid.Empty)
                implantClasses.TryAdd(e.ImplantId, implantById.GetValueOrDefault(e.ImplantId)?.Class.ToString() ?? e.ImplantId.ToString());

        // Task resolution: verb/outcome enrich the trail entries bound to a task.
        var taskById = new Dictionary<Guid, Task>();
        foreach (var task in engagementTasks)
            taskById[task.Id.Value] = task;

        // Artifacts folded onto their task for the task-history view. A
        // task-less artifact (a pre-foothold finding) has no bucket: it stays
        // in the artifact index and the workbench event names it there.
        var artifactsByTask = new Dictionary<Guid, List<Artifact>>();
        foreach (var artifact in engagementArtifacts)
        {
            if (artifact.TaskId is not { } taskKey)
                continue;
            if (!artifactsByTask.TryGetValue(taskKey, out var bucket))
            {
                bucket = new List<Artifact>();
                artifactsByTask[taskKey] = bucket;
            }
            bucket.Add(artifact);
        }

        return new ReportBuilderContext(
            engagement, trail, engagementMembers, engagementImplants, engagementTasks, engagementArtifacts,
            operatorNames, implantClasses, implantById, taskById, artifactsByTask, chainBreak);
    }

    // The canonical join for the reproducibility hash. Fixed field order, fields
    // joined with a unit separator (\u001f, which cannot appear in any joined
    // value) and records with a record separator (\u001e). Excludes only the
    // wall-clock generatedAt; every durable fact is in. The timeline event hashes
    // already commit to their predecessor (AuditChain), so joining them folds the
    // whole tamper-evident trail into the digest.
    internal static string ComputeReportHash(EngagementReport report)
    {
        var sb = new StringBuilder();
        const string sep = "\u001f";
        const string rec = "\u001e";

        sb.Append(report.Engagement.EngagementId).Append(sep)
            .Append(report.Engagement.Name).Append(sep)
            .Append(report.Engagement.OwnerId).Append(sep)
            .Append(report.Engagement.OwnerHandle).Append(sep)
            .Append(report.Engagement.CreatedAt.ToUnixTimeMilliseconds()).Append(sep)
            .Append(report.Engagement.Range).Append(rec);

        foreach (var op in report.Operators)
            sb.Append(op.OperatorId).Append(sep)
                .Append(op.Handle).Append(sep)
                .Append(op.Role).Append(rec);

        foreach (var implant in report.Implants)
            sb.Append(implant.ImplantId).Append(sep)
                .Append(implant.Class).Append(sep)
                .Append(implant.ParentImplantId ?? string.Empty).Append(sep)
                .Append(implant.RetiredAt?.ToUnixTimeMilliseconds().ToString() ?? string.Empty).Append(rec);

        foreach (var task in report.Tasks)
            sb.Append(task.TaskId).Append(sep)
                .Append(task.Verb).Append(sep)
                .Append(task.Arguments).Append(sep)
                .Append(task.Status).Append(sep)
                .Append(task.Outcome ?? string.Empty).Append(sep)
                .Append(task.IssuedBy).Append(sep)
                .Append(task.CreatedAt.ToUnixTimeMilliseconds()).Append(rec);

        foreach (var artifact in report.Artifacts)
            sb.Append(artifact.ArtifactId).Append(sep)
                .Append(artifact.Name).Append(sep)
                .Append(artifact.ContentType).Append(sep)
                .Append(artifact.Size).Append(sep)
                .Append(artifact.TaskId).Append(rec);

        AppendTimeline(sb, report.Timeline);

        return Hash(sb.ToString());
    }

    // The timeline's own reproducibility digest: joins only the enriched entries.
    // The engagement facts the full report covers are not part of the timeline's
    // scope, so a timeline export is reproducible on its own terms.
    internal static string ComputeTimelineHash(IReadOnlyList<TimelineEntry> timeline)
    {
        var sb = new StringBuilder();
        AppendTimeline(sb, timeline);
        return Hash(sb.ToString());
    }

    // The digest's reproducibility join: the window bounds plus the selected
    // entries, so two digests of the same window are equal no matter when each
    // was requested (the wall-clock generatedAt is excluded, the timeline's
    // discipline).
    internal static string ComputeDigestHash(
        DateTimeOffset from, DateTimeOffset to, IReadOnlyList<TimelineEntry> entries)
    {
        var sb = new StringBuilder();
        const string sep = "\u001f";
        const string rec = "\u001e";
        sb.Append(from.ToUnixTimeMilliseconds()).Append(sep)
            .Append(to.ToUnixTimeMilliseconds()).Append(rec);
        AppendTimeline(sb, entries);
        return Hash(sb.ToString());
    }

    private static void AppendTimeline(StringBuilder sb, IReadOnlyList<TimelineEntry> timeline)
    {
        const string sep = "\u001f";
        const string rec = "\u001e";
        foreach (var entry in timeline)
            sb.Append(entry.EventId).Append(sep)
                .Append(entry.At.ToUnixTimeMilliseconds()).Append(sep)
                .Append(entry.Kind).Append(sep)
                .Append(entry.Verb).Append(sep)
                .Append(entry.Operator?.OperatorId ?? Guid.Empty).Append(sep)
                .Append(entry.Operator?.Handle ?? string.Empty).Append(sep)
                .Append(entry.Implant?.ImplantId ?? Guid.Empty).Append(sep)
                .Append(entry.Implant?.Class ?? string.Empty).Append(sep)
                .Append(entry.Task?.TaskId ?? Guid.Empty).Append(sep)
                .Append(entry.Task?.Verb ?? string.Empty).Append(sep)
                .Append(entry.Task?.Outcome ?? string.Empty).Append(sep)
                .Append(entry.Payload).Append(sep)
                .Append(entry.Output ?? string.Empty).Append(sep)
                .Append(entry.Outcome).Append(sep)
                .Append(entry.Hash).Append(rec);
    }

    private static string Hash(string canonical)
    {
        var bytes = Encoding.UTF8.GetBytes(canonical);
        return Convert.ToHexString(SHA256.HashData(bytes));
    }
}

/// <summary>
/// The resolved evidence surface for one engagement, held while a single timeline
/// or report call renders it. Carries the engagement, its trail, inventory, task
/// history, and artifact index, plus the per-id enrichment maps (operator handle,
/// implant class, task verb/outcome, per-task artifacts). Render-only: nothing
/// here mutates the stores.
/// </summary>
internal sealed record ReportBuilderContext(
    Engagement Engagement,
    IReadOnlyList<AuditEvent> Trail,
    IReadOnlyList<EngagementMembership> Memberships,
    IReadOnlyList<Implant> Implants,
    IReadOnlyList<Task> Tasks,
    IReadOnlyList<Artifact> Artifacts,
    IReadOnlyDictionary<Guid, string> OperatorNames,
    IReadOnlyDictionary<Guid, string> ImplantClasses,
    IReadOnlyDictionary<Guid, Implant> ImplantById,
    IReadOnlyDictionary<Guid, Task> TaskById,
    IReadOnlyDictionary<Guid, List<Artifact>> ArtifactsByTask,
    ChainBreak? ChainBreak)
{
    private string OperatorHandle(Guid id)
        => id == Guid.Empty ? "system" : OperatorNames.GetValueOrDefault(id, id.ToString());

    public TimelineReport Timeline(Engagement engagement)
    {
        var entries = Trail.Select(e => EntryOf(e)).ToArray();
        return new TimelineReport(
            EngagementId: engagement.Id.Value,
            EngagementName: engagement.Name,
            GeneratedAt: DateTimeOffset.UtcNow,
            ContentHash: ReportBuilder.ComputeTimelineHash(entries),
            ChainVerified: ChainBreak is null,
            ChainBreak: ChainBreak?.ToString(),
            Entries: entries);
    }

    // The report bundle. Built in display order: the crew (the owner and
    // every granted membership, role-tagged), implants and tasks oldest-first
    // (the store order), artifacts oldest-first, and the enriched timeline.
    // The content hash is stamped last, over the fully resolved facts.
    public EngagementReport Report(Engagement engagement)
    {
        // The owner first (access by creation), then the granted memberships
        // in roster order -- the crew view the member routes render.
        var operatorRoster = new List<ReportOperator>
        {
            new ReportOperator(
                OperatorId: engagement.OwnerId.Value,
                Handle: OperatorHandle(engagement.OwnerId.Value),
                Role: "owner"),
        };
        operatorRoster.AddRange(Memberships.Select(m => new ReportOperator(
            m.OperatorId.Value,
            OperatorHandle(m.OperatorId.Value),
            EngagementRoles.ToName(m.Role))));

        var implantInventory = Implants
            .Select(i => new ReportImplant(
                ImplantId: i.Id.Value,
                Class: i.Class.ToString(),
                ParentImplantId: i.ParentImplantId?.Value.ToString("N"),
                RetiredAt: i.RetiredAt))
            .ToArray();

        var taskHistory = Tasks
            .Select(t => new ReportTask(
                TaskId: t.Id.Value,
                Verb: t.Verb,
                Arguments: t.Arguments,
                Status: t.Status.ToString(),
                Outcome: t.Outcome?.ToString(),
                IssuedBy: t.IssuedBy.Value,
                IssuedByHandle: OperatorHandle(t.IssuedBy.Value),
                ImplantId: t.ImplantId.Value,
                CreatedAt: t.CreatedAt,
                DispatchedAt: t.DispatchedAt,
                CompletedAt: t.CompletedAt,
                Output: t.Output,
                Artifacts: (ArtifactsByTask.GetValueOrDefault(t.Id.Value) ?? new List<Artifact>())
                    .Select(a => a.ArtifactId.ToString("N"))
                    .ToArray()))
            .ToArray();

        // Artifact index: engagement-wide, metadata only (bytes excluded, the
        // same discipline as the artifact list endpoint -- content is fetched on
        // demand through the retrieve endpoint).
        var artifactIndex = Artifacts
            .Select(a => new ReportArtifactIndexEntry(
                ArtifactId: a.ArtifactId,
                TaskId: a.TaskId,
                Name: a.Name,
                ContentType: a.ContentType,
                Size: a.Size))
            .ToArray();

        var timeline = Trail.Select(EntryOf).ToArray();

        var report = new EngagementReport(
            Engagement: new ReportEngagement(
                EngagementId: engagement.Id.Value,
                Name: engagement.Name,
                OwnerId: engagement.OwnerId.Value,
                OwnerHandle: OperatorHandle(engagement.OwnerId.Value),
                CreatedAt: engagement.CreatedAt,
                Range: engagement.Range),
            GeneratedAt: DateTimeOffset.UtcNow,
            ContentHash: string.Empty,
            ChainVerified: ChainBreak is null,
            ChainBreak: ChainBreak?.ToString(),
            Operators: operatorRoster,
            Implants: implantInventory,
            Tasks: taskHistory,
            Artifacts: artifactIndex,
            Timeline: timeline);

        return report with { ContentHash = ReportBuilder.ComputeReportHash(report) };
    }

    // The shift handoff digest (architecture.md Sec 11.1): the same resolved
    // context as the timeline, projected onto a window. Filtering is by event
    // timestamp (inclusive bounds) and the digest kind whitelist; the selected
    // entries keep the trail's own order -- the chain's append order is the
    // engagement's event order, and the digest re-sorts nothing.
    public HandoffDigest HandoffDigest(Engagement engagement, DateTimeOffset from, DateTimeOffset to)
    {
        var selected = Trail
            .Where(e => from <= e.At && e.At <= to && ReportBuilder.DigestKinds.Contains(e.Kind))
            .ToArray();
        var entries = selected.Select(EntryOf).ToArray();

        int Count(AuditEventKind kind) => selected.Count(e => e.Kind == kind);

        return new HandoffDigest(
            EngagementId: engagement.Id.Value,
            EngagementName: engagement.Name,
            From: from,
            To: to,
            GeneratedAt: DateTimeOffset.UtcNow,
            ContentHash: ReportBuilder.ComputeDigestHash(from, to, entries),
            ChainVerified: ChainBreak is null,
            ChainBreak: ChainBreak?.ToString(),
            Summary: new HandoffDigestSummary(
                SessionsOpened: Count(AuditEventKind.SessionOpened),
                SessionsClosed: Count(AuditEventKind.SessionClosed),
                ImplantsEnrolled: Count(AuditEventKind.ImplantEnrolled),
                ImplantsRetired: Count(AuditEventKind.ImplantRetired),
                TasksIssued: Count(AuditEventKind.TaskIssued),
                TasksCompleted: Count(AuditEventKind.TaskCompleted),
                TasksCancelled: Count(AuditEventKind.TaskCancelled),
                RoeRefusals: Count(AuditEventKind.TaskRoeRefused),
                NotesAdded: Count(AuditEventKind.ImplantNoteAdded),
                ShellSessionsOpened: Count(AuditEventKind.ShellSessionOpened),
                ShellSessionsEnded: Count(AuditEventKind.ShellSessionEnded)),
            Entries: entries);
    }

    // Enriches one audit event into a timeline entry: resolves the operator
    // handle (system for the unattributed Guid.Empty), the implant class when the
    // event names one, and the task's verb/outcome when the event names one. The
    // bare id is the fallback throughout -- a reader always sees a stable handle
    // or the id, never a hole.
    private TimelineEntry EntryOf(AuditEvent e)
    {
        TimelineActor? actor = null;
        if (e.OperatorId != Guid.Empty)
            actor = new TimelineActor(e.OperatorId, OperatorHandle(e.OperatorId));

        TimelineSubject? implant = null;
        if (e.ImplantId != Guid.Empty)
            implant = new TimelineSubject(
                e.ImplantId,
                ImplantClasses.GetValueOrDefault(e.ImplantId, e.ImplantId.ToString()));

        TimelineTaskRef? task = null;
        if (e.TaskId != Guid.Empty)
        {
            var referenced = TaskById.GetValueOrDefault(e.TaskId);
            task = new TimelineTaskRef(
                e.TaskId,
                referenced?.Verb,
                referenced?.Outcome?.ToString());
        }

        return new TimelineEntry(
            EventId: e.EventId,
            At: e.At,
            Kind: e.Kind.ToString(),
            Verb: e.Verb,
            Operator: actor,
            Implant: implant,
            Task: task,
            Payload: e.Payload,
            Output: e.Output,
            Outcome: e.Outcome,
            Hash: e.Hash);
    }
}

// --- Markdown renderers. Plain StringBuilder, no new package: the transport ---
// --- layer's only Markdown obligation is this deliverable, and it is small. ---

internal static class TimelineMarkdown
{
    public static string Render(TimelineReport timeline)
    {
        var sb = new StringBuilder();
        sb.Append("# Engagement timeline: ").Append(timeline.EngagementName).Append('\n');
        sb.Append('\n');
        sb.Append("- Engagement: `").Append(timeline.EngagementId.ToString("N")).Append("`\n");
        sb.Append("- Generated: ").Append(timeline.GeneratedAt.ToString("O")).Append('\n');
        sb.Append("- Integrity: `").Append(timeline.ContentHash).Append("`\n");
        if (!timeline.ChainVerified)
            sb.Append("- **Audit chain verification failed:** ").Append(timeline.ChainBreak).Append("**\n");

        if (timeline.Entries.Count == 0)
        {
            sb.Append("_No events recorded._\n");
            return sb.ToString();
        }

        foreach (var e in timeline.Entries)
            AppendEntry(sb, e);

        return sb.ToString();
    }

    // One timeline entry as a Markdown line. Shared with the handoff digest
    // renderer so the two deliverables tell an event the same way.
    internal static void AppendEntry(StringBuilder sb, TimelineEntry e)
    {
        sb.Append("- `").Append(e.At.ToString("O")).Append("` **").Append(e.Kind).Append("** ");
        if (e.Operator is { } op)
            sb.Append("by `").Append(op.Handle).Append("` ");
        sb.Append("— `").Append(e.Verb).Append("`");
        if (e.Implant is { } implant)
            sb.Append(" on implant `").Append(implant.Class).Append("`");
        if (e.Task is { } task && task.Verb is { } verb)
            sb.Append(" (task `").Append(verb).Append("`)");
        sb.Append("  \n  outcome: `").Append(Escape(e.Outcome)).Append("` — hash `").Append(e.Hash).Append("`\n");
        if (!string.IsNullOrEmpty(e.Payload))
            sb.Append("  \n  payload: `").Append(Escape(e.Payload)).Append("`\n");
        if (!string.IsNullOrEmpty(e.Output))
            sb.Append("  \n  output: `").Append(Escape(e.Output)).Append("`\n");
    }

    internal static string Escape(string value)
        => value.Replace("`", "\\`").Replace('\n', ' ');
}

internal static class ReportMarkdown
{
    public static string Render(EngagementReport report)
    {
        var sb = new StringBuilder();
        sb.Append("# Engagement report: ").Append(report.Engagement.Name).Append('\n');
        sb.Append('\n');
        // The range banner (architecture.md Sec 15.3): a simulated
        // engagement's report says so in its first breath -- the evidence
        // discipline a range exists under.
        if (report.Engagement.Range)
            sb.Append("**This is a range engagement: the fleet is simulated (scripted beacons); ")
                .Append("nothing here ran on a real target.**\n\n");
        sb.Append("- Engagement: `").Append(report.Engagement.EngagementId.ToString("N")).Append("`\n");
        sb.Append("- Owner: `").Append(report.Engagement.OwnerHandle).Append("` (`")
            .Append(report.Engagement.OwnerId.ToString("N")).Append("`)\n");
        sb.Append("- Created: ").Append(report.Engagement.CreatedAt.ToString("O")).Append('\n');
        if (!report.ChainVerified)
            sb.Append("- **Audit chain verification failed:** ").Append(report.ChainBreak).Append("**\n");
        sb.Append("- Generated: ").Append(report.GeneratedAt.ToString("O")).Append('\n');
        sb.Append("- Integrity: `").Append(report.ContentHash).Append("`\n");
        sb.Append('\n');

        sb.Append("## Operators\n\n");
        if (report.Operators.Count == 0)
            sb.Append("_None._\n");
        else
            foreach (var op in report.Operators)
                sb.Append("- `").Append(op.Handle).Append("` (")
                    .Append(op.Role).Append(", `")
                    .Append(op.OperatorId.ToString("N")).Append("`)\n");
        sb.Append('\n');

        sb.Append("## Implants\n\n");
        if (report.Implants.Count == 0)
            sb.Append("_None._\n");
        else
            foreach (var i in report.Implants)
            {
                sb.Append("- `").Append(i.ImplantId.ToString("N")).Append("` — ").Append(i.Class);
                if (i.ParentImplantId is { } parent)
                    sb.Append(" (child of `").Append(parent).Append("`)");
                if (i.RetiredAt is { } retired)
                    sb.Append(" — retired ").Append(retired.ToString("O"));
                sb.Append('\n');
            }
        sb.Append('\n');

        sb.Append("## Tasks\n\n");
        if (report.Tasks.Count == 0)
            sb.Append("_None._\n");
        else
            foreach (var t in report.Tasks)
            {
                sb.Append("- `").Append(t.TaskId.ToString("N")).Append("` — `").Append(t.Verb).Append("` ")
                    .Append(t.Status);
                if (t.Outcome is { } outcome)
                    sb.Append(" (").Append(outcome).Append(')');
                sb.Append(" — by `").Append(t.IssuedByHandle).Append("` ")
                    .Append(t.CreatedAt.ToString("O"));
                if (t.Artifacts.Count > 0)
                    sb.Append("  \n  artifacts: ").Append(string.Join(", ", t.Artifacts));
                if (!string.IsNullOrEmpty(t.Output))
                    sb.Append("  \n  output: `").Append(TimelineMarkdown.Escape(t.Output)).Append("`");
                sb.Append('\n');
            }
        sb.Append('\n');

        sb.Append("## Artifacts\n\n");
        if (report.Artifacts.Count == 0)
            sb.Append("_None._\n");
        else
            foreach (var a in report.Artifacts)
            {
                sb.Append("- `").Append(a.Name).Append("` (").Append(a.ContentType)
                    .Append(", ").Append(a.Size).Append(" B) — ");
                // A pre-foothold finding has no task; the workbench lookup that
                // produced it is its own trail entry.
                if (a.TaskId is { } taskId)
                    sb.Append("task `").Append(taskId.ToString("N")).Append("` ");
                sb.Append("(`").Append(a.ArtifactId.ToString("N")).Append("`)\n");
            }
        sb.Append('\n');

        sb.Append("## Timeline\n\n");
        if (report.Timeline.Count == 0)
            sb.Append("_No events recorded._\n");
        else
            foreach (var e in report.Timeline)
            {
                sb.Append("- `").Append(e.At.ToString("O")).Append("` **").Append(e.Kind).Append("** ");
                if (e.Operator is { } op)
                    sb.Append("by `").Append(op.Handle).Append("` ");
                sb.Append("— `").Append(e.Verb).Append("`");
                if (e.Implant is { } implant)
                    sb.Append(" on implant `").Append(implant.Class).Append("`");
                sb.Append("  \n  outcome: `").Append(TimelineMarkdown.Escape(e.Outcome))
                    .Append("` — hash `").Append(e.Hash).Append("`\n");
            }

        return sb.ToString();
    }
}

internal static class HandoffDigestMarkdown
{
    public static string Render(HandoffDigest digest)
    {
        var sb = new StringBuilder();
        sb.Append("# Shift handoff digest: ").Append(digest.EngagementName).Append('\n');
        sb.Append('\n');
        sb.Append("- Engagement: `").Append(digest.EngagementId.ToString("N")).Append("`\n");
        sb.Append("- Window: ").Append(digest.From.ToString("O")).Append(" to ")
            .Append(digest.To.ToString("O")).Append('\n');
        sb.Append("- Generated: ").Append(digest.GeneratedAt.ToString("O")).Append('\n');
        sb.Append("- Integrity: `").Append(digest.ContentHash).Append("`\n");
        if (!digest.ChainVerified)
            sb.Append("- **Audit chain verification failed:** ").Append(digest.ChainBreak).Append("**\n");
        sb.Append('\n');

        sb.Append("## The watch in numbers\n\n");
        var s = digest.Summary;
        sb.Append("- Sessions: ").Append(s.SessionsOpened).Append(" opened, ")
            .Append(s.SessionsClosed).Append(" closed\n");
        sb.Append("- Implants: ").Append(s.ImplantsEnrolled).Append(" enrolled, ")
            .Append(s.ImplantsRetired).Append(" retired\n");
        sb.Append("- Tasking: ").Append(s.TasksIssued).Append(" issued -- ")
            .Append(s.TasksCompleted).Append(" completed, ")
            .Append(s.TasksCancelled).Append(" cancelled\n");
        sb.Append("- ROE refusals: ").Append(s.RoeRefusals).Append('\n');
        sb.Append("- Implant notes: ").Append(s.NotesAdded).Append('\n');
        sb.Append("- Shell sessions: ").Append(s.ShellSessionsOpened).Append(" opened, ")
            .Append(s.ShellSessionsEnded).Append(" ended\n");
        sb.Append('\n');

        sb.Append("## The watch in order\n\n");
        if (digest.Entries.Count == 0)
            sb.Append("_No watch events in the window._\n");
        else
            foreach (var e in digest.Entries)
                TimelineMarkdown.AppendEntry(sb, e);

        return sb.ToString();
    }
}

// --- DTOs. camelCase JSON is the framework default; records stay clean. ---

/// <summary>
/// One attributed, enriched event on the engagement timeline. The raw audit entry
/// (audit layer) carries only primitive ids; this view resolves the operator
/// handle, the implant class, and the task's verb/outcome so a reader gets a
/// human account of the action rather than bare GUIDs. The hash-chain fields are
/// reduced to the single stored <see cref="Hash"/> (the link's own hash, which
/// commits to its predecessor): the trail is tamper-evident by construction and a
/// report consumer reads the facts, not the chain internals.
/// </summary>
public sealed record TimelineEntry(
    Guid EventId,
    DateTimeOffset At,
    string Kind,
    string Verb,
    TimelineActor? Operator,
    TimelineSubject? Implant,
    TimelineTaskRef? Task,
    string Payload,
    string? Output,
    string Outcome,
    string Hash);

/// <summary>The operator who performed (or was attributed) an action, with the resolved handle.</summary>
public sealed record TimelineActor(Guid OperatorId, string Handle);

/// <summary>The implant an action touched, with its resolved class.</summary>
public sealed record TimelineSubject(Guid ImplantId, string Class);

/// <summary>The task an action references, enriched with the task's verb and outcome when known.</summary>
public sealed record TimelineTaskRef(Guid TaskId, string? Verb, string? Outcome);

/// <summary>
/// The chronological engagement timeline, enriched and integrity-stamped. The
///  deliverable as a pure projection of the audit trail: ordered oldest-first,
/// each entry attributed and hash-linked, with a reproducibility digest over the
/// whole.
/// </summary>
public sealed record TimelineReport(
    Guid EngagementId,
    string EngagementName,
    DateTimeOffset GeneratedAt,
    string ContentHash,
    bool ChainVerified,
    string? ChainBreak,
    IReadOnlyList<TimelineEntry> Entries);

/// <summary>Engagement summary carried at the head of the report bundle.</summary>
public sealed record ReportEngagement(
    Guid EngagementId,
    string Name,
    Guid OwnerId,
    string OwnerHandle,
    DateTimeOffset CreatedAt,
    // The range mark (architecture.md Sec 15.3): a simulated engagement's
    // report must never read as a real operation's. Rendered as the header
    // banner below and sealed into the report's content hash like every
    // other engagement fact.
    bool Range = false);

/// <summary>
/// One crew row of the report: an operator who holds standing on the
/// engagement (the owner by creation, members by grant), with the resolved
/// handle and the role the access ran under.
/// </summary>
public sealed record ReportOperator(
    Guid OperatorId,
    string Handle,
    string Role);

/// <summary>An enrolled implant, with its class, parentage, and retirement state.</summary>
public sealed record ReportImplant(
    Guid ImplantId,
    string Class,
    string? ParentImplantId,
    DateTimeOffset? RetiredAt);

/// <summary>A task in the engagement's history, with its full lifecycle, result, and evidence references.</summary>
public sealed record ReportTask(
    Guid TaskId,
    string Verb,
    string Arguments,
    string Status,
    string? Outcome,
    Guid IssuedBy,
    string IssuedByHandle,
    Guid ImplantId,
    DateTimeOffset CreatedAt,
    DateTimeOffset? DispatchedAt,
    DateTimeOffset? CompletedAt,
    string? Output,
    IReadOnlyList<string> Artifacts);

/// <summary>An artifact in the engagement's evidence index -- metadata only, bytes excluded. The task reference is null for pre-foothold findings (Sec 11.4).</summary>
public sealed record ReportArtifactIndexEntry(
    Guid ArtifactId,
    Guid? TaskId,
    string Name,
    string ContentType,
    long Size);

/// <summary>
/// The full engagement report bundle: summary, operator roster, implant
/// inventory, task history, artifact index, and the enriched timeline, with a
/// reproducibility digest over all of it. The  deliverable rendered from the
/// audit/task/artifact stores -- a single, attributed, hash-stamped account of the
/// engagement.
/// </summary>
public sealed record EngagementReport(
    ReportEngagement Engagement,
    DateTimeOffset GeneratedAt,
    string ContentHash,
    bool ChainVerified,
    string? ChainBreak,
    IReadOnlyList<ReportOperator> Operators,
    IReadOnlyList<ReportImplant> Implants,
    IReadOnlyList<ReportTask> Tasks,
    IReadOnlyList<ReportArtifactIndexEntry> Artifacts,
    IReadOnlyList<TimelineEntry> Timeline);

/// <summary>
/// The watch-in-numbers header of the digest: one count per whitelisted kind,
/// so the incoming operator sizes the watch before reading it.
/// </summary>
public sealed record HandoffDigestSummary(
    int SessionsOpened,
    int SessionsClosed,
    int ImplantsEnrolled,
    int ImplantsRetired,
    int TasksIssued,
    int TasksCompleted,
    int TasksCancelled,
    int RoeRefusals,
    int NotesAdded,
    int ShellSessionsOpened,
    int ShellSessionsEnded);

/// <summary>
/// The shift handoff digest (architecture.md Sec 11.1): a time-windowed,
/// kind-whitelisted, ordered account of the watch, projected from the same
/// resolved report context as the timeline. Entries keep the trail's order and
/// carry the timeline's enrichment and per-event hashes; the content hash joins
/// the window bounds with the selected entries, so two digests of the same
/// window are equal.
/// </summary>
public sealed record HandoffDigest(
    Guid EngagementId,
    string EngagementName,
    DateTimeOffset From,
    DateTimeOffset To,
    DateTimeOffset GeneratedAt,
    string ContentHash,
    bool ChainVerified,
    string? ChainBreak,
    HandoffDigestSummary Summary,
    IReadOnlyList<TimelineEntry> Entries);

// --- The ATT&CK Navigator layer export (architecture.md Sec 15.3, ADR-007).
//     One shape, two faces: this is the "what was done" half -- the techniques
//     the engagement's dispatched tasks actually exercised, resolved through
//     the same verb-to-technique mapping the coverage matrix renders. ---

/// <summary>
/// An ATT&CK Navigator layer (format 4.5) over an engagement's executed
/// techniques: loadable into the Navigator as proof of coverage, with each
/// technique scored by dispatched-task count and carrying per-verb metadata.
/// </summary>
public sealed record AttackLayer(
    string Name,
    AttackLayerVersions Versions,
    string Domain,
    string Description,
    IReadOnlyList<AttackLayerTechnique> Techniques,
    AttackLayerLayout Layout,
    AttackLayerGradient Gradient,
    IReadOnlyList<AttackLayerMetadata> Metadata,
    IReadOnlyList<object> LegendItems,
    IReadOnlyList<object> Links,
    bool HideDisabled,
    int Sorting,
    bool ShowTacticRowBackground,
    string TacticRowBackground,
    bool SelectTechniquesAcrossTactics,
    bool SelectSubtechniquesWithParent);

/// <summary>The ATT&CK and Navigator format versions the layer targets.</summary>
public sealed record AttackLayerVersions(string Attack, string Navigator);

/// <summary>One technique the engagement exercised, with its per-verb attribution.</summary>
public sealed record AttackLayerTechnique(
    string TechniqueID,
    int Score,
    string Comment,
    bool Enabled,
    IReadOnlyList<AttackLayerMetadata> Metadata);

/// <summary>A Navigator metadata cell: a name/value pair rendered in the technique or layer details.</summary>
public sealed record AttackLayerMetadata(string Name, string Value);

/// <summary>The Navigator layout block; the fixed readable default.</summary>
public sealed record AttackLayerLayout(
    string Layout,
    string AggregateFunction,
    bool ShowID,
    bool ShowName,
    bool ShowAggregateScores,
    bool CountUnscored);

/// <summary>
/// The score gradient: task counts map onto it, so heavier-used techniques
/// render darker. MaxValue is the layer's own maximum count (at least one).
/// </summary>
public sealed record AttackLayerGradient(IReadOnlyList<string> Colors, int MinValue, int MaxValue);

/// <summary>
/// Builds the Navigator layer from the engagement report projection: every
/// technique a dispatched task's verb maps to, scored by task count, each
/// carrying per-verb counts as metadata. A task that never reached its
/// implant (queued and cancelled) proved nothing, so only dispatched tasks
/// count; a verb with no mapping (proc.kill, the plumbing families) honestly
/// appears nowhere.
/// </summary>
internal static class AttackNavigatorLayer
{
    private const string NavigatorVersion = "4.9.1";

    public static AttackLayer Build(EngagementReport report, IVerbTechniqueResolver techniques)
    {
        // Verb -> dispatched-task count, in first-dispatch order for stable
        // metadata; a verb dispatched zero times is not on the layer.
        var dispatched = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var task in report.Tasks)
        {
            if (task.DispatchedAt is null)
                continue;
            dispatched[task.Verb] = dispatched.TryGetValue(task.Verb, out var count) ? count + 1 : 1;
        }

        var rows = new List<AttackLayerTechnique>();
        foreach (var (verb, count) in dispatched)
        {
            var ids = techniques.Techniques(verb);
            if (ids is null)
                continue;

            foreach (var id in ids)
            {
                var existing = rows.FirstOrDefault(r => string.Equals(r.TechniqueID, id, StringComparison.OrdinalIgnoreCase));
                if (existing is null)
                {
                    rows.Add(new AttackLayerTechnique(
                        id, count, $"{verb}: {count} task(s)", Enabled: true,
                        Metadata: [new AttackLayerMetadata(verb, count.ToString())]));
                }
                else
                {
                    var index = rows.IndexOf(existing);
                    rows[index] = existing with
                    {
                        Score = existing.Score + count,
                        Comment = $"{existing.Comment}; {verb}: {count} task(s)",
                        Metadata = [.. existing.Metadata, new AttackLayerMetadata(verb, count.ToString())],
                    };
                }
            }
        }

        var ordered = rows.OrderBy(r => r.TechniqueID, StringComparer.Ordinal).ToArray();
        return new AttackLayer(
            Name: $"Rod: {report.Engagement.Name}",
            Versions: new AttackLayerVersions(AttackTechniqueCatalog.AttackVersion, NavigatorVersion),
            Domain: "enterprise-attack",
            Description:
                "Techniques exercised by dispatched tasks in this engagement, "
                + "generated by the Rod teamserver from the engagement's audit-trail projection.",
            Techniques: ordered,
            Layout: new AttackLayerLayout("side", "average", ShowID: false, ShowName: true, ShowAggregateScores: false, CountUnscored: false),
            Gradient: new AttackLayerGradient(
                ["#ffffff", "#ff6666"], 0, Math.Max(1, ordered.Max(r => r.Score))),
            Metadata:
            [
                new AttackLayerMetadata("engagement", report.Engagement.Name),
                new AttackLayerMetadata("generatedAt", report.GeneratedAt.ToString("O")),
            ],
            LegendItems: [],
            Links: [],
            HideDisabled: false,
            Sorting: 0,
            ShowTacticRowBackground: false,
            TacticRowBackground: "#dddddd",
            SelectTechniquesAcrossTactics: true,
            SelectSubtechniquesWithParent: false);
    }
}

