namespace Rod.CoreState.Live;

/// <summary>
/// The kinds of operational change the operator layer pushes live to connected
/// operator sessions (architecture.md Sec 4.1, layer 4). These are the
/// realtime fan-out events -- the durable, attributed record of every action
/// still lives in the audit trail (Sec 11); the bus is best-effort and rebuilds
/// its projection from current state on reconnect.
/// </summary>
public enum LiveEventKind
{
    /// <summary>
    /// An operator session opened on the engagement. Carries the operator id and
    /// handle so peers can render "who is online" without an extra round-trip.
    /// </summary>
    OperatorJoined,

    /// <summary>An operator session closed on the engagement.</summary>
    OperatorLeft,

    /// <summary>
    /// A task was issued against an implant in the engagement. Lets every
    /// connected operator see tasking the moment it is queued, attributed to the
    /// issuing operator.
    /// </summary>
    TaskIssued,

    /// <summary>
    /// A task completed -- the implant returned a result. The captured outcome
    /// reaches every operator session in real time.
    /// </summary>
    TaskCompleted,

    /// <summary>
    /// A queued task was retracted before dispatch (architecture.md Sec 10.3).
    /// Lets every connected operator see the tasking leave the queue the moment
    /// it is cancelled, so a peer's queued view does not linger.
    /// </summary>
    TaskCancelled,

    /// <summary>
    /// A streaming task's channel produced output (architecture.md Sec 10.3,
    /// the streaming task shape). The chunk reaches every connected operator
    /// session as it streams, so a live channel reads like a terminal; the
    /// task's accumulating transcript remains the durable record.
    /// </summary>
    ChannelOutput,

    /// <summary>
    /// An implant was retired (architecture.md Sec 7). Lets connected
    /// operators see an implant leave the live fleet the moment it is taken out
    /// of operation, rather than waiting for it to drop off presence on its
    /// next (refused) handshake.
    /// </summary>
    ImplantRetired,

    /// <summary>
    /// A session was closed by the staleness sweep: its beacon stream stopped
    /// producing frames longer than the configured threshold (architecture.md
    /// Sec 10.3). System-initiated, so it carries the null operator
    /// (<c>OperatorId.Empty</c>); connected operators refresh the roster on it,
    /// seeing the implant drop offline without polling.
    /// </summary>
    SessionClosed,

    /// <summary>
    /// An implant opened a session -- it contacted and came online
    /// (architecture.md Sec 10.3). Fires only for a genuinely new session: the
    /// registry reuses the active session on a poll contact or a flapped
    /// stream, and a contact cadence must not flood the stream. Connected
    /// operators refresh the online roster on it, seeing the implant appear
    /// without waiting out a poll -- the roster's mirror of
    /// <see cref="SessionClosed"/>.
    /// </summary>
    SessionOpened,

    /// <summary>
    /// A shellcatch listener accepted a reverse-shell connection
    /// (architecture.md Sec 8). Connected operators refresh the shell roster
    /// on it -- the shell-facing mirror of <see cref="SessionOpened"/>. The
    /// payload carries the shell session id, remote address, and listener;
    /// output itself is not fanned out per chunk (the console reads the
    /// shell's output log directly), so the stream stays roster-paced.
    /// </summary>
    ShellSessionOpened,

    /// <summary>
    /// A caught shell left the live roster -- lost to the network or closed
    /// by an operator (architecture.md Sec 8). The shell-facing mirror of
    /// <see cref="SessionClosed"/>; the payload carries the shell session id
    /// and how it ended.
    /// </summary>
    ShellSessionEnded,

    /// <summary>
    /// An artifact was fetched over an engagement web front's delivery route
    /// (architecture.md Sec 6): a launcher credential was spent by an actual
    /// download. Connected operators refresh their kept-launcher rows on it,
    /// seeing the remaining budget move the moment a target pulls it -- without
    /// waiting for the enrollment that may follow (and may never come: a
    /// burned one-liner pulled by a scanner never enrolls). System-initiated
    /// (the fetch), so it carries the null operator; the payload names the
    /// fetcher's address and user agent.
    /// </summary>
    PayloadFetched,

    /// <summary>A build finished into a stored artifact (Sec 6): the
    /// operator-attributed completion the build strip and the timeline
    /// render live, without polling.</summary>
    PayloadBuilt,

    /// <summary>
    /// An operator took the claim on an interaction surface
    /// (architecture.md Sec 4.5) -- a live channel task's typing half or a
    /// caught shell's input. Carries the holder as its operator; the payload
    /// names the surface, and a channel claim also carries the task id so a
    /// console can bind the lock to its pane. Connected operators render the
    /// claim as "held by" state on the surface.
    /// </summary>
    ClaimAcquired,

    /// <summary>
    /// An interaction claim ended -- released by its holder, or dropped
    /// because the holder left the engagement's live stream or the claimed
    /// surface itself ended (architecture.md Sec 4.5). The mirror of
    /// <see cref="ClaimAcquired"/>: connected operators clear the "held by"
    /// lock and may take the surface themselves.
    /// </summary>
    ClaimReleased,

    /// <summary>
    /// The operator driving an implant changed (architecture.md Sec 4.5,
    /// activity presence): a different operator's tasking action marked the
    /// implant as theirs. Carries the new driver and the implant; a refresh
    /// by the current driver publishes nothing, so the beat fires only on a
    /// hand-off. Connected operators refresh the roster's driving badges.
    /// </summary>
    ImplantActivity,

    /// <summary>
    /// The engagement's membership changed (architecture.md Sec 3): the owner
    /// added a member, changed a role, or removed one. Carries the acting
    /// owner as its operator; the payload names the member, the action, and
    /// the role. Connected operators refresh their members view on it -- the
    /// roster-paced mirror of the audit trail's durable record.
    /// </summary>
    MembershipChanged,

    /// <summary>
    /// A delivery campaign's recipient state moved (architecture.md
    /// Sec 11.5) -- a message sent or failed, a lure opened or clicked, a
    /// recipient executed into an implant. System-initiated except the
    /// send, so the operator id carries the campaign's creator on engine
    /// facts and the null operator on edge facts; the payload names the
    /// campaign, the recipient, and what moved. Connected operators
    /// refresh their campaign view on it -- the roster-paced mirror of
    /// the audit trail's per-fact record.
    /// </summary>
    CampaignActivity,

    /// <summary>
    /// A collaboration comment was added (architecture.md Sec 15.3,
    /// ADR-005). Carries the author as its operator and the task or
    /// implant id when the comment attaches to one, so a console can bind
    /// the refresh to its pane. Comments are mutable process knowledge:
    /// they ride this bus and the timeline as ordinary events but never
    /// enter the audit chain.
    /// </summary>
    CommentAdded,

    /// <summary>
    /// A collaboration comment's body was edited within its window
    /// (architecture.md Sec 15.3, ADR-005). The mirror of
    /// <see cref="CommentAdded"/> for a row that changed in place.
    /// </summary>
    CommentEdited,

    /// <summary>
    /// A collaboration comment was deleted within its window
    /// (architecture.md Sec 15.3, ADR-005). Connected operators drop the
    /// row from their panels and timeline reads.
    /// </summary>
    CommentDeleted,

    /// <summary>
    /// A chat channel was created on the engagement (architecture.md
    /// Sec 15.3, ADR-005). Connected operators refresh their channel list.
    /// </summary>
    ChatChannelCreated,

    /// <summary>
    /// A chat message was sent on an engagement channel (architecture.md
    /// Sec 15.3, ADR-005). The payload names the channel and carries the
    /// body, so an open chat pane appends it without a refetch. Chat is
    /// mutable process knowledge beside comments: it rides this bus and
    /// the timeline, never the audit chain.
    /// </summary>
    ChatMessageSent,
}
