using Rod.CoreState.Deployment;
using Rod.CoreState.Recon;

namespace Rod.CoreState.Campaigns;

/// <summary>
/// Where a delivery campaign sits in its arc (architecture.md Sec 11.5).
/// A campaign is created <see cref="Draft"/> (nothing leaves), moves to
/// <see cref="Launched"/> when the operator arms it (the engine drives
/// per-recipient builds and sends), and lands <see cref="Completed"/> when
/// every recipient is terminal. <see cref="Revoked"/> is the burn answer:
/// no further sends and every lure in the campaign 404s.
/// </summary>
public enum CampaignState
{
    /// <summary>Created; nothing has been sent and no builds were driven.</summary>
    Draft,

    /// <summary>Armed; the engine owns the recipient arcs.</summary>
    Launched,

    /// <summary>Every recipient is terminal (sent or failed).</summary>
    Completed,

    /// <summary>Revoked: sends stopped, lures dead.</summary>
    Revoked,
}

/// <summary>
/// One recipient's delivery arc (architecture.md Sec 11.5). The evidence
/// timestamps (<c>OpenedAt</c>, <c>ClickedAt</c>, <c>ExecutedAt</c>) are
/// not states in this arc -- they are monotonic first-stamps that arrive
/// from the public edge and the enrollment, in any order, without moving
/// the delivery status.
/// </summary>
public enum CampaignRecipientStatus
{
    /// <summary>Awaiting the engine's first tick.</summary>
    Pending,

    /// <summary>The per-recipient build is queued or running; the credential
    /// is minted and the job id recorded.</summary>
    Building,

    /// <summary>The message was accepted by the relay; terminal success.</summary>
    Sent,

    /// <summary>Terminal failure, the reason on the row; delivery is
    /// single-attempt, so a retry is a new campaign.</summary>
    Failed,
}

/// <summary>
/// The TLS posture a campaign's relay connection keeps -- an explicit
/// operator decision per campaign (the runbook's egress decisions), never
/// a silent default. <see cref="StartTls"/> is the mainstream shape;
/// <see cref="None"/> exists for lab relays and sends the campaign's
/// credentials in the clear.
/// </summary>
public enum CampaignRelayTls
{
    /// <summary>No TLS at all; lab relays only.</summary>
    None,

    /// <summary>Upgrade in the clear after the greeting (the default).</summary>
    StartTls,

    /// <summary>TLS from the first byte (smtps, port 465's shape).</summary>
    ImplicitTls,
}

/// <summary>
/// One delivery campaign (architecture.md Sec 11.5): the sending profile,
/// the template, the build profile, the listener whose public endpoint
/// fronts the lure, and the recipient list -- the engagement-scoped row
/// that carries the causal chain from lure to implant. The campaign is
/// declarative state; the transport layer's send engine interprets it.
///
/// Mutations are the entity's own methods so the state invariants (a
/// Draft campaign can only be launched, a terminal campaign never moves,
/// a revoked campaign never un-revokes) live here rather than in whichever
/// caller happened to mutate last. The store's targeted operations call
/// these; the durable twin mirrors the same guards in its WHERE clauses.
/// </summary>
public sealed class Campaign
{
    public CampaignId Id { get; }
    public EngagementId EngagementId { get; }

    /// <summary>The operator-facing name ("q3-renewal-push").</summary>
    public string Name { get; }

    /// <summary>The operator who created the campaign; engine-side facts
    /// (the per-recipient token mints, the sends) attribute to the creator
    /// the way a build's mint attributes to the engagement owner.</summary>
    public OperatorId CreatedBy { get; }

    public DateTimeOffset CreatedAt { get; }
    public CampaignState State { get; private set; }

    // --- The sending profile. ---

    public string RelayHost { get; }
    public int RelayPort { get; }
    public CampaignRelayTls RelayTls { get; }

    /// <summary>
    /// The relay's username, when the relay authenticates. The password is
    /// held in the clear the way a launcher's download credential is
    /// (architecture.md Sec 11.5): the server must present it again, so it
    /// rides the row, is deletable with the campaign, never enters the
    /// audit trail, and is never returned on read-back.
    /// </summary>
    public string? RelayUsername { get; }

    /// <summary>See <see cref="RelayUsername"/>; the read-back contract is
    /// the transport layer's to enforce.</summary>
    public string? RelayPassword { get; }

    /// <summary>The envelope sender and From header, one address.</summary>
    public string FromAddress { get; }

    // --- The content. ---

    public string Subject { get; }
    public string Body { get; }
    public bool BodyIsHtml { get; }

    // --- The delivery shape. ---

    /// <summary>
    /// The build profile as the build request's JSON, exactly as the
    /// operator's create carried it. The campaign never re-states build
    /// semantics: the transport layer parses it with the build pipeline's
    /// own parser at launch, so a build knob added later needs no campaign
    /// change. A plain string because the DTO belongs to the transport
    /// layer -- the inner ring carries it as an opaque blob.
    /// </summary>
    public string BuildRequestJson { get; }

    /// <summary>
    /// The listener whose <c>publicEndpoint</c> composes the lure URLs and
    /// whose engagement scopes the serving socket. A bare Guid because the
    /// typed id belongs to the transport layer (the same shape
    /// <see cref="Implants.Implant.EnrolledViaListenerId"/> keeps).
    /// </summary>
    public Guid ListenerId { get; }

    public IReadOnlyList<CampaignRecipient> Recipients { get; }

    public DateTimeOffset? LaunchedAt { get; private set; }
    public DateTimeOffset? CompletedAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }

    public Campaign(
        CampaignId id,
        EngagementId engagementId,
        string name,
        OperatorId createdBy,
        DateTimeOffset createdAt,
        string relayHost,
        int relayPort,
        CampaignRelayTls relayTls,
        string? relayUsername,
        string? relayPassword,
        string fromAddress,
        string subject,
        string body,
        bool bodyIsHtml,
        string buildRequestJson,
        Guid listenerId,
        IReadOnlyList<CampaignRecipient> recipients,
        CampaignState state = CampaignState.Draft,
        DateTimeOffset? launchedAt = null,
        DateTimeOffset? completedAt = null,
        DateTimeOffset? revokedAt = null)
    {
        Id = id;
        EngagementId = engagementId;
        Name = name;
        CreatedBy = createdBy;
        CreatedAt = createdAt;
        RelayHost = relayHost;
        RelayPort = relayPort;
        RelayTls = relayTls;
        RelayUsername = relayUsername;
        RelayPassword = relayPassword;
        FromAddress = fromAddress;
        Subject = subject;
        Body = body;
        BodyIsHtml = bodyIsHtml;
        BuildRequestJson = buildRequestJson;
        ListenerId = listenerId;
        Recipients = recipients;
        State = state;
        LaunchedAt = launchedAt;
        CompletedAt = completedAt;
        RevokedAt = revokedAt;
    }

    /// <summary>
    /// Arms the campaign: only a Draft campaign may launch, and only once.
    /// Returns whether the state moved, so the caller (and its durable
    /// twin's WHERE clause) can answer 409 on a second attempt.
    /// </summary>
    public bool Launch(DateTimeOffset at)
    {
        if (State is not CampaignState.Draft)
            return false;

        State = CampaignState.Launched;
        LaunchedAt = at;
        return true;
    }

    /// <summary>
    /// Burns the campaign from any live state: sends stop and every lure
    /// 404s. A terminal campaign (Completed) may still revoke -- the lures
    /// stay live past the last send until someone kills them. Idempotent in
    /// effect: a second call returns false and changes nothing.
    /// </summary>
    public bool Revoke(DateTimeOffset at)
    {
        if (State is CampaignState.Revoked)
            return false;

        State = CampaignState.Revoked;
        RevokedAt = at;
        return true;
    }

    /// <summary>
    /// Moves a launched campaign to Completed when the last recipient went
    /// terminal. Derived, not operator-driven: the engine offers it after
    /// every recipient transition and the store applies it under the same
    /// atomicity, so completion never lands while a recipient is mid-arc.
    /// </summary>
    public bool TryComplete(DateTimeOffset at)
    {
        if (State is not CampaignState.Launched)
            return false;
        if (Recipients.Any(r => r.Status is CampaignRecipientStatus.Pending or CampaignRecipientStatus.Building))
            return false;

        State = CampaignState.Completed;
        CompletedAt = at;
        return true;
    }

    /// <summary>Finds a recipient row by its id, or null.</summary>
    public CampaignRecipient? FindRecipient(CampaignRecipientId recipient)
        => Recipients.FirstOrDefault(r => r.Id == recipient);
}

/// <summary>
/// One recipient of a campaign (architecture.md Sec 11.5): the target's
/// address, the unguessable lure id whose route serves their artifact, and
/// the delivery/evidence arc. The enrollment credential binding
/// (<see cref="EnrollTokenId"/>) is what attributes the implant that
/// follows the lure -- the whole surface's reason to exist.
///
/// The address arrives two ways (the unified entity model's target link,
/// Sec 15.4): typed by the operator, or by reference to a recon asset --
/// <see cref="ReconAssetId"/> names the row the address was selected from,
/// and the asset's value and display name resolved into
/// <see cref="Email"/>/<see cref="Name"/> at creation, so the delivery
/// arc never depends on the asset row staying alive.
/// </summary>
public sealed class CampaignRecipient
{
    public CampaignRecipientId Id { get; }
    public string Email { get; }

    /// <summary>The display name the merge field <c>{{name}}</c> renders;
    /// null when the campaign carries none (the field renders empty).</summary>
    public string? Name { get; }

    /// <summary>
    /// The recon asset this recipient was selected from (architecture.md
    /// Sec 15.4), when the target came from the engagement's asset list
    /// rather than the operator's keyboard. Null on a typed address. The
    /// reference is the record of selection; the resolved address rides
    /// <see cref="Email"/>.
    /// </summary>
    public ReconAssetId? ReconAssetId { get; }

    /// <summary>
    /// The unguessable id whose route is the lure -- the capability URL
    /// shape the hook serving edge keeps. Minted at creation so the URL is
    /// stable from the moment the campaign exists, before anything is sent.
    /// </summary>
    public Guid LureId { get; }

    public CampaignRecipientStatus Status { get; private set; }

    /// <summary>The terminal failure's readable reason; null unless
    /// <see cref="Status"/> is <see cref="CampaignRecipientStatus.Failed"/>.</summary>
    public string? Failure { get; private set; }

    /// <summary>
    /// The build job driving this recipient's artifact while Building. A
    /// job lost to a restart is re-requested with a fresh credential, so a
    /// stale id is a lookup miss and nothing worse.
    /// </summary>
    public Guid? JobId { get; private set; }

    /// <summary>
    /// The enrollment credential minted for and baked into this recipient's
    /// artifact. The binding that attributes the enrollment: when an
    /// implant redeems this token, it enrolled by following this
    /// recipient's lure. Null until the engine mints at build submission.
    /// </summary>
    public DeployTokenId? EnrollTokenId { get; private set; }

    /// <summary>
    /// The built artifact the lure serves. Null until the build completes;
    /// a lure fetched before then 404s -- the link exists, the artifact
    /// does not yet.
    /// </summary>
    public Guid? PayloadId { get; private set; }

    public DateTimeOffset? SentAt { get; private set; }
    public DateTimeOffset? OpenedAt { get; private set; }
    public DateTimeOffset? ClickedAt { get; private set; }

    /// <summary>
    /// Stamped when an implant redeemed <see cref="EnrollTokenId"/> -- the
    /// only proof of execution; a click proves a fetch, never a run.
    /// </summary>
    public DateTimeOffset? ExecutedAt { get; private set; }

    /// <summary>The implant that redeemed the credential, bound at the
    /// same moment <see cref="ExecutedAt"/> stamps.</summary>
    public Guid? EnrolledImplantId { get; private set; }

    public CampaignRecipient(
        CampaignRecipientId id,
        string email,
        string? name,
        Guid lureId,
        CampaignRecipientStatus status = CampaignRecipientStatus.Pending,
        string? failure = null,
        Guid? jobId = null,
        DeployTokenId? enrollTokenId = null,
        Guid? payloadId = null,
        DateTimeOffset? sentAt = null,
        DateTimeOffset? openedAt = null,
        DateTimeOffset? clickedAt = null,
        DateTimeOffset? executedAt = null,
        Guid? enrolledImplantId = null,
        ReconAssetId? reconAssetId = null)
    {
        Id = id;
        Email = email;
        Name = name;
        LureId = lureId;
        Status = status;
        Failure = failure;
        JobId = jobId;
        EnrollTokenId = enrollTokenId;
        PayloadId = payloadId;
        SentAt = sentAt;
        OpenedAt = openedAt;
        ClickedAt = clickedAt;
        ExecutedAt = executedAt;
        EnrolledImplantId = enrolledImplantId;
        ReconAssetId = reconAssetId;
    }

    /// <summary>
    /// Binds the minted credential and the submitted job, moving the
    /// recipient into Building. Valid from Pending (the first submission)
    /// or Building itself (a re-submission after a lost job, with a fresh
    /// credential overwriting the stale binding). Returns whether the
    /// binding landed.
    /// </summary>
    public bool MarkBuilding(DeployTokenId enrollToken, Guid jobId)
    {
        if (Status is not (CampaignRecipientStatus.Pending or CampaignRecipientStatus.Building))
            return false;

        Status = CampaignRecipientStatus.Building;
        EnrollTokenId = enrollToken;
        JobId = jobId;
        return true;
    }

    /// <summary>
    /// Records the relay's acceptance: the artifact id the lure serves, the
    /// send stamp, terminal success. Valid from Building only -- a message
    /// cannot be sent for a recipient whose build never ran.
    /// </summary>
    public bool MarkSent(Guid payloadId, DateTimeOffset at)
    {
        if (Status is not CampaignRecipientStatus.Building)
            return false;

        Status = CampaignRecipientStatus.Sent;
        PayloadId = payloadId;
        SentAt = at;
        return true;
    }

    /// <summary>
    /// Records a terminal failure from any non-terminal point of the arc
    /// (the build refused, the build failed, the send failed). Delivery is
    /// single-attempt, so this is the row's last move.
    /// </summary>
    public bool MarkFailed(string reason, DateTimeOffset at, Guid? payloadId = null)
    {
        if (Status is CampaignRecipientStatus.Sent or CampaignRecipientStatus.Failed)
            return false;

        Status = CampaignRecipientStatus.Failed;
        Failure = reason;
        PayloadId ??= payloadId;
        return true;
    }

    /// <summary>
    /// The first open evidence stamp; monotonic -- a later pixel fetch
    /// never moves it. Returns whether the stamp landed.
    /// </summary>
    public bool NoteOpened(DateTimeOffset at)
    {
        if (OpenedAt is not null)
            return false;

        OpenedAt = at;
        return true;
    }

    /// <summary>The first click evidence stamp; monotonic like
    /// <see cref="NoteOpened"/>.</summary>
    public bool NoteClicked(DateTimeOffset at)
    {
        if (ClickedAt is not null)
            return false;

        ClickedAt = at;
        return true;
    }

    /// <summary>
    /// The executed binding: the implant that redeemed this recipient's
    /// credential. Monotonic and one-shot like the other evidence stamps --
    /// the credential is single-use, so a second redemption never happens;
    /// the guard keeps a store race from double-stamping.
    /// </summary>
    public bool NoteExecuted(Guid implantId, DateTimeOffset at)
    {
        if (ExecutedAt is not null)
            return false;

        ExecutedAt = at;
        EnrolledImplantId = implantId;
        return true;
    }
}
