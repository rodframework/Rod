using Rod.CoreState.Collaboration;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Operators.Interaction;
using Rod.CoreState.Tasks;

namespace Rod.CoreState.Live;

/// <summary>
/// One realtime operational change pushed to connected operator sessions
/// (architecture.md Sec 4.1, layer 4). Every event is engagement-scoped: the bus
/// never delivers an event for one engagement to a subscriber on another
/// (architecture.md Sec 3). The wire serializer (transport) maps each kind onto
/// an SSE <c>event:</c> name and turns <see cref="Payload"/> into its
/// <c>data:</c> block, so this type carries only domain meaning, not framing.
///
/// The bus is best-effort: a dropped subscriber does not lose durable history --
/// the audit trail (Sec 11) is the attributed record. This type is the transient
/// projection operators read while they are connected.
/// </summary>
public sealed record LiveEvent(
    EngagementId EngagementId,
    LiveEventKind Kind,
    OperatorId OperatorId,
    ImplantId? ImplantId,
    TaskId? TaskId,
    string Payload,
    DateTimeOffset At)
{
    /// <summary>
    /// Builds a presence event (operator joined/left). No implant or task is
    /// involved; <paramref name="payload"/> carries the operator handle for the
    /// peers' "who is online" view.
    /// </summary>
    public static LiveEvent Presence(
        EngagementId engagement,
        LiveEventKind kind,
        OperatorId operatorId,
        string payload,
        DateTimeOffset at)
        => new(engagement, kind, operatorId, ImplantId: null, TaskId: null, payload, at);

    /// <summary>
    /// Builds a task-issued event. <paramref name="payload"/> is the verb and
    /// arguments; the operator and implant ids carry the attribution and scope.
    /// </summary>
    public static LiveEvent TaskIssued(
        EngagementId engagement,
        OperatorId operatorId,
        ImplantId implantId,
        TaskId taskId,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.TaskIssued, operatorId, implantId, taskId, payload, at);

    /// <summary>
    /// Builds a task-completed event. <paramref name="payload"/> carries the
    /// captured output and outcome so peers see the result without re-reading.
    /// </summary>
    public static LiveEvent TaskCompleted(
        EngagementId engagement,
        OperatorId operatorId,
        ImplantId implantId,
        TaskId taskId,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.TaskCompleted, operatorId, implantId, taskId, payload, at);

    /// <summary>
    /// Builds a task-cancelled event (architecture.md Sec 10.3): a queued task
    /// retracted before dispatch, attributed to the cancelling operator.
    /// <paramref name="payload"/> carries the verb and arguments so peers see
    /// which tasking left the queue.
    /// </summary>
    public static LiveEvent TaskCancelled(
        EngagementId engagement,
        OperatorId operatorId,
        ImplantId implantId,
        TaskId taskId,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.TaskCancelled, operatorId, implantId, taskId, payload, at);

    /// <summary>
    /// Builds a channel-output event (architecture.md Sec 10.3): one streamed
    /// chunk of a live task channel, attributed to the operator whose task the
    /// channel runs. The payload is the chunk itself so a connected operator
    /// appends it to the live view; the task's accumulating transcript is the
    /// durable record.
    /// </summary>
    public static LiveEvent ChannelOutput(
        EngagementId engagement,
        OperatorId operatorId,
        ImplantId implantId,
        TaskId taskId,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.ChannelOutput, operatorId, implantId, taskId, payload, at);

    /// <summary>
    /// Builds an implant-retired event (architecture.md Sec 7). Carries
    /// the implant id and the retiring operator; no task is involved, so the
    /// task id is null. <paramref name="payload"/> is a short description peers
    /// can render directly.
    /// </summary>
    public static LiveEvent ImplantRetired(
        EngagementId engagement,
        OperatorId operatorId,
        ImplantId implantId,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.ImplantRetired, operatorId, implantId, TaskId: null, payload, at);

    /// <summary>
    /// Builds a session-closed event for the staleness sweep (architecture.md
    /// Sec 10.3): the server closed the session itself, so the operator id is
    /// <see cref="OperatorId.Empty"/> and no task is involved.
    /// <paramref name="payload"/> describes why the session was swept.
    /// </summary>
    public static LiveEvent SessionClosed(
        EngagementId engagement,
        ImplantId implantId,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.SessionClosed, OperatorId.Empty, implantId, TaskId: null, payload, at);

    /// <summary>
    /// Builds a session-opened event: an implant contacted and opened its live
    /// channel. As with the transport's <c>SessionOpened</c> audit record, it is
    /// published only for a genuinely new session -- the registry reuses the
    /// active session on a poll cadence, and a contact cadence must not flood
    /// the stream. Implant-initiated, so it is attributed to the implant's
    /// <paramref name="deployedBy"/> operator (the token issuer who authorized
    /// the deployment), the same attribution the audit record carries; the
    /// payload is the advertised protocol version.
    /// </summary>
    public static LiveEvent SessionOpened(
        EngagementId engagement,
        OperatorId deployedBy,
        ImplantId implantId,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.SessionOpened, deployedBy, implantId, TaskId: null, payload, at);

    /// <summary>
    /// Builds a shell-session event -- a caught reverse shell joining or
    /// leaving the live roster (architecture.md Sec 8). System-initiated
    /// either way (the accept, the socket's end), so it is attributed to
    /// the null operator; no implant or task is involved, and the payload
    /// carries the shell session id and what happened.
    /// </summary>
    public static LiveEvent ShellSession(
        EngagementId engagement,
        LiveEventKind kind,
        string payload,
        DateTimeOffset at)
        => new(engagement, kind, OperatorId.Empty, ImplantId: null, TaskId: null, payload, at);

    /// <summary>
    /// Builds a payload-built event: a build job finished into a stored
    /// artifact (architecture.md Sec 6), attributed to the operator that
    /// requested the build. The payload names the unit, target, and
    /// fingerprint for direct rendering -- the console's build strip and
    /// the timeline no longer need polling to learn a build landed.
    /// </summary>
    public static LiveEvent PayloadBuilt(
        EngagementId engagement,
        OperatorId operatorId,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.PayloadBuilt, operatorId, ImplantId: null, TaskId: null, payload, at);

    /// <summary>
    /// Builds a payload-fetched event: an artifact was fetched over an
    /// engagement front's delivery route (architecture.md Sec 6), spending one
    /// use of the launcher credential it presented. System-initiated (the
    /// fetch), so it is attributed to the null operator; no implant or task
    /// exists yet, and <paramref name="payload"/> describes the fetcher for
    /// direct rendering.
    /// </summary>
    public static LiveEvent PayloadFetched(
        EngagementId engagement,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.PayloadFetched, OperatorId.Empty, ImplantId: null, TaskId: null, payload, at);

    /// <summary>
    /// Builds a campaign-activity event (architecture.md Sec 11.5): a
    /// recipient's state moved -- sent, failed, opened, clicked, executed.
    /// Engine facts (the send) attribute to the campaign's creator; public
    /// edge facts (the open, the click) and the executed binding carry the
    /// null operator. No implant or task rides the event; the payload names
    /// the campaign, the recipient, and what moved, and connected consoles
    /// refetch the campaign's detail on it.
    /// </summary>
    public static LiveEvent CampaignActivity(
        EngagementId engagement,
        OperatorId operatorId,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.CampaignActivity, operatorId, ImplantId: null, TaskId: null, payload, at);

    /// <summary>
    /// Builds an interaction-claim event -- acquired or released
    /// (architecture.md Sec 4.5). Attributed to the holder the claim concerns;
    /// a channel claim carries the surface's task id so a console binds the
    /// lock to its pane, a shell claim carries none, and the payload names
    /// the surface (<c>channel/{id}</c> / <c>shell/{id}</c>).
    /// </summary>
    public static LiveEvent Claim(
        EngagementId engagement,
        LiveEventKind kind,
        OperatorId holder,
        InteractionSurface surface,
        Guid surfaceId,
        DateTimeOffset at)
        => new(
            engagement,
            kind,
            holder,
            ImplantId: null,
            TaskId: surface == InteractionSurface.ChannelTask ? new TaskId(surfaceId) : null,
            $"{surface.RouteKind()}/{InteractionClaim.WireId(surface, surfaceId)}",
            at);

    /// <summary>
    /// Builds an implant-activity event (architecture.md Sec 4.5, activity
    /// presence): a different operator's tasking action marked the implant as
    /// theirs -- a hand-off, one beat. Attributed to the new driver; the
    /// payload carries the driving stamp.
    /// </summary>
    public static LiveEvent ImplantActivity(
        EngagementId engagement,
        OperatorId driver,
        ImplantId implant,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.ImplantActivity, driver, implant, TaskId: null, payload, at);

    /// <summary>
    /// Builds a membership-changed event (architecture.md Sec 3): the owner
    /// added a member, changed a role, or removed one. Attributed to the
    /// acting owner; the payload names the member, action, and role for
    /// direct rendering.
    /// </summary>
    public static LiveEvent Membership(
        EngagementId engagement,
        OperatorId actingOwner,
        string payload,
        DateTimeOffset at)
        => new(engagement, LiveEventKind.MembershipChanged, actingOwner, ImplantId: null, TaskId: null, payload, at);

    /// <summary>
    /// Builds a comment event -- added, edited, or deleted (architecture.md
    /// Sec 15.3, ADR-005). Attributed to the author; the comment's task or
    /// implant subject rides the matching id so a console binds the refresh
    /// to its pane; the payload is <c>subject:body</c> (the subject rendered
    /// as <c>task/&lt;id&gt;</c> and its kin), body omitted on delete.
    /// Comments ride this bus and the timeline as ordinary, mutable events
    /// and never enter the audit chain.
    /// </summary>
    public static LiveEvent Comment(
        EngagementId engagement,
        LiveEventKind kind,
        OperatorId author,
        CommentSubjectKind subjectKind,
        Guid subjectId,
        string payload,
        DateTimeOffset at)
        => new(
            engagement,
            kind,
            author,
            subjectKind == CommentSubjectKind.Implant ? new ImplantId(subjectId) : null,
            subjectKind == CommentSubjectKind.Task ? new TaskId(subjectId) : null,
            payload,
            at);

    /// <summary>
    /// Builds a chat event -- a channel created or a message sent
    /// (architecture.md Sec 15.3, ADR-005). Attributed to the acting
    /// operator; no implant or task rides it; the payload is
    /// <c>channel:body</c> for a message and the channel name for a
    /// creation, so an open chat pane renders it directly. Chat rides this
    /// bus and the timeline as ordinary, mutable events and never enters
    /// the audit chain.
    /// </summary>
    public static LiveEvent Chat(
        EngagementId engagement,
        LiveEventKind kind,
        OperatorId actor,
        string payload,
        DateTimeOffset at)
        => new(engagement, kind, actor, ImplantId: null, TaskId: null, payload, at);
}
