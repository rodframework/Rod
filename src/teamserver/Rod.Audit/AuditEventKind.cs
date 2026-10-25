namespace Rod.Audit;

/// <summary>
/// What kind of operational fact an <see cref="AuditEvent"/> records
/// (architecture.md Sec 11). Every per-engagement action that changes state or
/// binds an identity produces exactly one kind: the engagement's own creation, a
/// deploy token mint, an implant enrollment, a session opening, a task's
/// issuance/dispatch/completion, a payload build, an implant's retirement, an
/// evidence artifact attached to a task, and an artifact the implant itself
/// exfiltrated over the beacon stream. Together they form the engagement
/// timeline -- the attributed, append-only, hash-chained event stream the
/// acceptance point calls for.
/// </summary>
public enum AuditEventKind
{
    /// <summary>
    /// An operator created an engagement (architecture.md Sec 3).
    /// The first event in any engagement's trail. The event carries the
    /// engagement name in its payload and the new engagement id as its outcome;
    /// it is attributed to the creating owner. The chain's genesis link.
    /// </summary>
    EngagementCreated,

    /// <summary>
    /// An operator minted a deploy token for an engagement. The payload carries
    /// the token's bounded-use/expiry shape; the outcome is
    /// the new token id. The secret itself is never recorded -- only the fact
    /// that a token was minted, by whom, and against which engagement.
    /// </summary>
    DeployTokenMinted,

    /// <summary>
    /// A deploy token was redeemed and an implant enrolled into its engagement.
    /// The payload carries the implant's class (and the parent when it is a
    /// child derivation, architecture.md Sec 5.2); the
    /// outcome is the new implant id. Enrollment is implant-initiated, so the
    /// event is attributed to the operator who minted the redeemed token -- the
    /// one who authorized the deployment -- carried on the implant as
    /// <c>DeployedBy</c>.
    /// </summary>
    ImplantEnrolled,

    /// <summary>
    /// An implant opened a session on a successful handshake. The payload
    /// carries the negotiated protocol version; the outcome is the
    /// session id. As with enrollment the actor is the implant, but the event is
    /// attributed to the operator who deployed it (the token issuer), so the
    /// "an implant came online" fact is bound to an accountable operator.
    /// </summary>
    SessionOpened,

    /// <summary>
    /// An operator issued a task against an implant. The event carries the verb
    /// and arguments in its payload and the new task id
    /// as its outcome. Issuance is the operator's intent; <see cref="TaskDispatched"/>
    /// records the server handing the task to the implant, and
    /// <see cref="TaskCompleted"/> records the result. A task's full attributed
    /// arc is these three events.
    /// </summary>
    TaskIssued,

    /// <summary>
    /// A queued task was handed to an implant on its beacon stream. The payload carries the verb and arguments; the outcome is
    /// the dispatched task id. Dispatch is server-driven (the implant pulls the
    /// queue), so the event is attributed to the operator who issued the task --
    /// the one whose tasking the dispatch carries out.
    /// </summary>
    TaskDispatched,

    /// <summary>
    /// An implant returned a task result; the event carries the verb, the
    /// captured output, and the outcome. Emitted on every completed task.
    /// </summary>
    TaskCompleted,

    /// <summary>
    /// An operator retracted a queued task before the implant woke
    /// (architecture.md Sec 10.3). The event carries the retracted verb and
    /// arguments in its payload; the outcome is the recorded cancellation
    /// timestamp. Attributed to the cancelling operator and bound to the task
    /// it retracts. A cancelled task's arc ends here: no
    /// <see cref="TaskDispatched"/> follows, because the retraction is
    /// claim-proof against the dispatch queue.
    /// </summary>
    TaskCancelled,

    /// <summary>
    /// A payload was built; the event carries the build's class and config and,
    /// as its outcome, the artifact's SHA-256 fingerprint (architecture.md Sec 6
    /// -- every generated artifact is fingerprinted and recorded). Emitted on
    /// every successful build. No implant is enrolled yet at build time, so the
    /// event's implant/task ids are unused.
    /// </summary>
    PayloadBuilt,

    /// <summary>
    /// A stored payload was deleted from the library by an operator: the bytes
    /// and the listing entry are gone, and a fetch of it 404s from now
    /// on -- the kill switch for a hosted payload. The event carries the
    /// payload's class and target with the fingerprint it carried in life, so
    /// the trail still names what was removed even though the bytes are not
    /// retrievable anymore.
    /// </summary>
    PayloadDeleted,

    /// <summary>
    /// An implant was retired (architecture.md Sec 7). The event carries
    /// the implant id and the retiring operator; the outcome is the recorded
    /// retirement timestamp. A retired implant is refused at handshake and
    /// untaskable thereafter. The event has no task -- retirement is an
    /// operator action on the implant, not a task it ran.
    /// </summary>
    ImplantRetired,

    /// <summary>
    /// An operator wrote a free-text note on an implant -- the "whose beacon
    /// is this" memory. The note is recorded as this event (the payload is the
    /// note text, the outcome "added"), attributed to the writing operator and
    /// bound to the implant it describes; notes read back from the trail, so
    /// they survive a teamserver restart the same way every engagement fact
    /// does, with no separate note store to keep consistent. The event has no
    /// task -- a note annotates the implant, it does not task it.
    /// </summary>
    ImplantNoteAdded,

    /// <summary>
    /// An operator attached an evidence artifact to a task (architecture.md
    /// Sec 11). Artifacts -- files, screenshots, captured command
    /// output -- are first-class objects linked to the task that gathered them,
    /// not loose files; this event records the binding. The payload carries the
    /// artifact's name and content type, and the outcome is the new artifact id.
    /// The event is attributed to the attaching operator and carries the task it
    /// was bound to.
    /// </summary>
    ArtifactAttached,

    /// <summary>
    /// An implant streamed an artifact to the teamserver over the beacon stream
    /// (architecture.md Sec 10.1 exfil, Sec 11). Unlike <see cref="ArtifactAttached"/>,
    /// which records an operator binding a file it already holds, this records
    /// the implant itself exfiltrating bytes off the target as ExfilChunk
    /// frames; the server reassembles the chunks into an artifact scoped to the
    /// engagement and bound to the task that triggered the push. The payload
    /// carries the artifact's name and content type, and the outcome is the new
    /// artifact id. The event is attributed to the implant (via the task's
    /// <c>IssuedBy</c>) and carries the task the push was bound to.
    /// </summary>
    ExfilCaptured,

    /// <summary>
    /// An operator applied an engagement's rules-of-engagement profile
    /// (architecture.md Sec 9 -- ROE guardrails). The payload carries the
    /// profile's shape (permitted verbs and targets; empty lists are the
    /// unrestricted scope) and the outcome is the engagement id. Every later
    /// refusal the profile causes is a <see cref="TaskRoeRefused"/> event, so
    /// this record is what the trail shows the scope in force at any moment.
    /// </summary>
    RoeUpdated,

    /// <summary>
    /// The engagement's owner granted an operator membership
    /// (architecture.md Sec 3, the membership model). The payload names the
    /// granted role ("reader" / "writer") and the member's handle; the
    /// outcome is the member's operator id. Membership is engagement state,
    /// unlike operator account state, so the change lands in this
    /// engagement's own trail -- the who-was-let-in record the story keeps.
    /// </summary>
    EngagementMemberAdded,

    /// <summary>
    /// The engagement's owner changed a member's role (reader to writer or
    /// back, architecture.md Sec 3). The payload names the new role and the
    /// member's handle; the outcome is the member's operator id. The role
    /// change takes effect on the member's next request -- the access check
    /// reads the store fresh.
    /// </summary>
    EngagementMemberRoleChanged,

    /// <summary>
    /// The engagement's owner removed a member (architecture.md Sec 3). The
    /// payload names the removed member's handle and last role; the outcome
    /// is the member's operator id. From the next request on, the removed
    /// operator no longer sees the engagement at all.
    /// </summary>
    EngagementMemberRemoved,

    /// <summary>
    /// A task issuance was refused by the engagement's rules-of-engagement
    /// profile before it was queued (architecture.md Sec 9). The payload
    /// carries the verb and arguments that were refused, and the outcome names
    /// the violated rule -- which verb or target was outside the engagement's
    /// permitted scope. The event is attributed to the issuing operator; the
    /// task never exists, so it carries no task id.
    /// </summary>
    TaskRoeRefused,

    /// <summary>
    /// An operator sent input to a live task channel (architecture.md Sec
    /// 10.3, the streaming task shape). The payload carries the decoded input
    /// (or the eof marker when the operator closed the channel's stdin); the
    /// event is attributed to the sending operator and bound to the channel's
    /// task. What the channel streamed back rides the task's
    /// <see cref="TaskCompleted"/> event as its transcript.
    /// </summary>
    ChannelInput,

    /// <summary>
    /// An operator bound a relay port onto a live tunnel channel
    /// (architecture.md Sec 10.1 tunnel, Sec 10.3): a teamserver-side TCP
    /// listener whose accepted connection bridges into the channel, so
    /// unmodified operator tooling rides the tunnel without per-byte input
    /// posts. The payload carries the listen endpoint; the event is attributed
    /// to the binding operator and bound to the tunnel's task.
    /// <see cref="RelayClosed"/> records how the relay ended.
    /// </summary>
    RelayBound,

    /// <summary>
    /// A relay port bound onto a live tunnel channel ended
    /// (architecture.md Sec 10.1 tunnel, Sec 10.3): the task completed, the
    /// beacon stream died, the operator unbound it, or the bridged connection
    /// ended. The payload names the cause and the relayed byte tallies; the
    /// event is attributed to the operator who bound the relay. The relayed
    /// traffic itself rides the task's transcript -- the same no-per-chunk
    /// discipline the channel's own output follows.
    /// </summary>
    RelayClosed,

    /// <summary>
    /// An operator froze the engagement for close-out (architecture.md Sec 2
    /// step 10). From this event on, the engagement accepts no new tasking and
    /// no new deployments; the payload carries the freeze timestamp, and the
    /// outcome is the engagement id. The first event of the close-out arc that
    /// ends with <see cref="EvidenceExported"/> and
    /// <see cref="EngagementRetired"/>.
    /// </summary>
    EngagementFrozen,

    /// <summary>
    /// An operator exported the engagement's evidence package (architecture.md
    /// Sec 11): the hash-chained audit trail, the artifacts, and the report as
    /// one package that survives infrastructure teardown and re-verifies
    /// offline. The payload carries the package's file counts; the outcome is
    /// the exported trail's chain-head hash -- the digest that pins everything
    /// the package carries. Written after the package is built, so it is not
    /// part of the exported trail -- a later re-export carries it.
    /// </summary>
    EvidenceExported,

    /// <summary>
    /// An operator retired the engagement, completing its close-out
    /// (architecture.md Sec 2 step 10): terminal. The payload carries the
    /// retirement timestamp; the outcome is the engagement id. The trail --
    /// including this event -- remains the durable, append-only account of the
    /// engagement after its infrastructure is gone.
    /// </summary>
    EngagementRetired,

    /// <summary>
    /// An operator reversed a freeze: the engagement reopens and accepts
    /// tasking and deployments again. The recovery for a mistaken freeze,
    /// refused after retirement. The payload carries the unfreeze timestamp;
    /// the outcome is the engagement id. The freeze and this event both stay
    /// in the trail, so an exported package from the frozen window remains a
    /// verifiable snapshot of that window while the live trail tells the full
    /// story.
    /// </summary>
    EngagementUnfrozen,

    /// <summary>
    /// An operator revoked a deploy token: the credential stops working at the
    /// next redeem or verify, whatever uses and validity it had left. The
    /// emergency answer to a leaked credential -- above all one baked into a
    /// deployed artifact. The payload names why revocation exists (the baked
    /// shape or the manual mint); the outcome is the revoked token id.
    /// </summary>
    DeployTokenRevoked,

    /// <summary>
    /// An operator edited the engagement's working record: its name and
    /// free-text description. The payload carries the new name (and whether a
    /// description is set); the outcome is the engagement id. The description
    /// text itself is not recorded -- it is the crew's working notes, not a
    /// fact about the target environment, and the trail records that the
    /// record moved, not every draft of it.
    /// </summary>
    EngagementUpdated,

    /// <summary>
    /// A shellcatch listener accepted a reverse-shell connection
    /// (architecture.md Sec 8). The peer speaks no Rod protocol and carries
    /// no identity, so the event is scoped by the engagement-bound listener
    /// it landed on. System-initiated (the accept), so it is attributed to
    /// the null operator. The payload carries the remote address, the
    /// listener, and the fingerprint once guessed; the outcome is the new
    /// shell session id.
    /// </summary>
    ShellSessionOpened,

    /// <summary>
    /// A caught shell session ended on its own -- the peer vanished, the
    /// shell exited, or the socket died (Lost). System-initiated, so it is
    /// attributed to the null operator; an operator's deliberate close is
    /// its own operator-attributed <see cref="ShellSessionClosed"/> event.
    /// The payload carries the last-input/output stamps; the outcome is the
    /// shell session id.
    /// </summary>
    ShellSessionEnded,

    /// <summary>
    /// An operator closed a caught shell deliberately. Operator-attributed;
    /// the outcome is the shell session id. The socket's unblock and the
    /// session's Closed marking follow from the pump honoring the close.
    /// </summary>
    ShellSessionClosed,

    /// <summary>
    /// An operator wrote input to a caught shell (architecture.md Sec 8).
    /// Operator-attributed and precise per submission, unlike output (which
    /// flows unsolicited and is summarized on the session's end events):
    /// input is the operator's own action against the target and is recorded
    /// exactly. The payload carries the submitted text; the outcome is the
    /// shell session id.
    /// </summary>
    ShellSessionInput,

    /// <summary>
    /// An operator switched a caught shell's session encoding (architecture.md
    /// Sec 8): the codec both directions speak -- the console's answer to a
    /// target on a legacy code page (a GBK cmd.exe box). The payload carries
    /// the encoding's wire name; the outcome is the shell session id.
    /// </summary>
    ShellSessionEncodingChanged,

    /// <summary>
    /// An operator registered a web-shell endpoint into the engagement
    /// (architecture.md Sec 5.2's Web-shell class): a script already placed
    /// in a target's web root, bound to the engagement by the register
    /// action itself. The payload carries the URL and protocol adapter; the
    /// outcome is the WebShell-class implant id the endpoint is anchored
    /// to. The connection password is not recorded -- the script that
    /// carries it lives on the target, and the trail records the fact of
    /// the binding, not the credential.
    /// </summary>
    WebShellRegistered,

    /// <summary>
    /// An operator removed a web-shell endpoint: the connection profile is
    /// gone and the anchor implant row retired with its history readable
    /// (architecture.md Sec 7's shape). The payload carries the URL; the
    /// outcome is the implant id.
    /// </summary>
    WebShellRemoved,

    /// <summary>
    /// An operator probed a web-shell endpoint -- the one-request health
    /// check that stands in for a beacon's liveness answer. The payload
    /// carries the outcome (ok, latency, or the refusal reason); the
    /// outcome is the implant id. A probe executes a marker echo on the
    /// target, so it is recorded like any other operator action.
    /// </summary>
    WebShellProbed,

    /// <summary>
    /// An artifact was fetched over the launcher delivery route
    /// (<c>GET /implants/payloads/{id}</c>, architecture.md Sec 6): the
    /// deployment's first observable footprint on the wire. The fetcher
    /// speaks no Rod protocol and carries no identity yet, so the event is
    /// scoped by the credential's engagement and attributed to the null
    /// operator -- the enrollment that may follow is the identity-bearing
    /// half of the exchange. Recorded for every fetch a resolvable
    /// credential gate-keeps, served or refused: the payload carries what
    /// the wire showed (remote address, user agent, listener socket,
    /// payload id, credential id) and the outcome is
    /// <c>served</c> or <c>refused:{reason}</c>. A credential whose row is
    /// deleted no longer resolves, and its fetches leave no record -- an
    /// unknown secret belongs to no engagement.
    /// </summary>
    PayloadFetched,

    /// <summary>
    /// An automation rule fired (architecture.md Sec 10.4): the engine
    /// matched a rule's trigger and issued the rule's task through the
    /// ordinary tasking path. The event attributes to the synthetic
    /// automation operator; the payload names the rule and its trigger, and
    /// the outcome is the issued task's id or <c>refused:{reason}</c> when a
    /// gate refused the issuance. The task's own TaskIssued arc follows
    /// beside it, shaped exactly like an operator-issued one.
    /// </summary>
    AutomationRuleFired,

    /// <summary>
    /// An operator created an automation rule. The payload names the rule
    /// (id, name, trigger, action); the outcome is the rule id.
    /// </summary>
    AutomationRuleCreated,

    /// <summary>
    /// An automation rule was enabled or disabled -- by an operator (the
    /// payload's cause is <c>operator</c>) or by the engine's own guards (a
    /// firing cap reached, repeated issuance refusals; the cause names which,
    /// attributed to the automation operator). The payload names the rule and
    /// the cause; the outcome is the rule id.
    /// </summary>
    AutomationRuleUpdated,

    /// <summary>
    /// An operator deleted an automation rule. The payload names the rule;
    /// the outcome is the rule id.
    /// </summary>
    AutomationRuleDeleted,

    /// <summary>
    /// The notification forwarder pushed one live event to a registered
    /// webhook (architecture.md Sec 4.4), or an operator fired a
    /// subscription's <c>:test</c>. The payload names the subscription and
    /// the event (kind, ids) but never the URL -- the URL is the channel's
    /// bearer secret and does not enter the trail. The outcome is
    /// <c>delivered:{status}</c>, <c>failed:{reason}</c>, or
    /// <c>tested:{status}</c>. Best-effort like the bus it rides: the fact
    /// records the attempt, and the surrounding trail remains the record.
    /// </summary>
    WebhookDelivered,

    /// <summary>
    /// An operator registered a webhook subscription. The payload names the
    /// subscription (name, notifiable event kinds); the outcome is the
    /// subscription id.
    /// </summary>
    WebhookSubscriptionCreated,

    /// <summary>
    /// A webhook subscription was enabled or disabled -- by an operator or
    /// by the forwarder's failure guard (consecutive delivery failures
    /// parked it, the cause named in the payload). The outcome is the
    /// subscription id.
    /// </summary>
    WebhookSubscriptionUpdated,

    /// <summary>
    /// An operator deleted a webhook subscription. The payload names the
    /// subscription; the outcome is the subscription id.
    /// </summary>
    WebhookSubscriptionDeleted,

    /// <summary>
    /// The staleness sweep closed a session whose beacon stream went silent
    /// (architecture.md Sec 10.3, Sec 11.1). The payload carries the last-seen
    /// stamp and how long the stream had been silent; the outcome is the closed
    /// session id. The sweep is server-driven, so the event attributes to no
    /// operator. A session closed by supersession (a re-enroll opening its
    /// successor) writes no close event; the successor's
    /// <see cref="SessionOpened"/> is its trace.
    /// </summary>
    SessionClosed,

    /// <summary>
    /// An operator saved a task snippet -- a named sequence of issue
    /// commands the console replays through the ordinary tasking path. The
    /// payload names the snippet and its steps; the outcome is the snippet
    /// id. Running a snippet writes no record of its own: the tasks it
    /// issues are the trail, attributed to the running operator exactly
    /// like typed tasking.
    /// </summary>
    TaskSnippetSaved,

    /// <summary>
    /// An operator deleted a task snippet. The payload names the snippet;
    /// the outcome is the snippet id.
    /// </summary>
    TaskSnippetDeleted,

    /// <summary>
    /// An operator set or cleared a label on an implant -- the short marker
    /// vocabulary ("jump", "owned", "watch-edr") the fleet's picture groups
    /// and filters by (architecture.md Sec 11.2). The payload is the label
    /// text, the outcome <c>set</c> or <c>cleared</c>; the live label set is
    /// the last-wins reduction over these events, so an append-only trail
    /// can still change a label without rewriting history. Attributed to
    /// the acting operator and bound to the implant it marks; like a note,
    /// a label annotates the implant, it does not task it.
    /// </summary>
    ImplantLabeled,

    /// <summary>
    /// An operator wrote a free-text note about a host -- the device
    /// dimension of the picture, grouped by the hostname the implants
    /// themselves report at enroll (architecture.md Sec 11.2). A host is
    /// that grouping read-side; there is no host entity, so the note's
    /// payload carries a small JSON object naming the host alongside the
    /// text (the audit record's field set is frozen -- the chain's
    /// canonical form -- so a new subject rides the free string fields).
    /// The outcome is <c>added</c>; notes are immutable appends read back
    /// as a query over the trail, exactly like implant notes.
    /// </summary>
    HostNoteAdded,

    /// <summary>
    /// An operator set or cleared a label on a host (architecture.md Sec
    /// 11.2). The payload carries the same JSON shape as
    /// <see cref="HostNoteAdded"/> with the label in place of the text; the
    /// outcome is <c>set</c> or <c>cleared</c>, and the live label set is
    /// the last-wins reduction over these events -- the implant-label
    /// discipline on the host key.
    /// </summary>
    HostLabeled,

    /// <summary>
    /// An operator retrieved an evidence artifact's bytes (architecture.md
    /// Sec 11.2) -- the loot view's open, or any artifact download. Reading
    /// a projection of the evidence is not an act on the engagement (the
    /// digest's posture), but retrieving the bytes is: the artifact leaves
    /// the platform, and the chain-of-custody question "who pulled what"
    /// deserves the same trail record the payload fetch route writes for
    /// delivered bytes (<see cref="PayloadFetched"/>). The payload carries
    /// the artifact's name and content type; the outcome is the artifact
    /// id. Attributed to the downloading operator and bound to the task
    /// that gathered the evidence.
    /// </summary>
    ArtifactViewed,

    /// <summary>
    /// The LLM triage client made one request on an operator's behalf
    /// (architecture.md Sec 11, the attention-compression surface). Every
    /// request lands here, succeeded or failed: engagement content left the
    /// platform toward the configured endpoint, so the trail records the
    /// egress itself, not just the answer. The payload names what was sent
    /// (the task summarized, its verb, the input size) but never the
    /// endpoint or the key -- configuration names the endpoint and the
    /// runbook documents the egress decision, and neither belongs in the
    /// chain. The output is the generated summary on success; the outcome
    /// is <c>succeeded:{model}</c> or <c>failed:{reason}</c>. Attributed to
    /// the requesting operator and bound to the task whose output was sent.
    /// </summary>
    LlmSummaryGenerated,

    /// <summary>
    /// The recon workbench ran one passive lookup on an operator's behalf
    /// (architecture.md Sec 11.4): an RDAP registration query (whois
    /// behind it when the registry has no record), a
    /// certificate-transparency subdomain enumeration, or a name
    /// resolution through the configured resolver, against a named
    /// target, egressing the teamserver toward the configured service.
    /// Every attempt lands here, succeeded or failed -- the egress itself
    /// is the act the trail records. The payload names the lookup and the
    /// target but never the egress endpoint (configuration names the
    /// endpoint, the runbook the decision); the output carries a one-line
    /// summary of what came back; the outcome is the findings artifact id
    /// or <c>failed:{reason}</c>. Attributed to the requesting operator;
    /// no implant and no task exist pre-foothold, so the artifact carries
    /// the operator attribution alone.
    /// </summary>
    ReconLookupCompleted,

    /// <summary>
    /// The recon workbench ran a port scan on an operator's behalf
    /// (architecture.md Sec 11.4): a TCP connect scan of a named target
    /// from the configured scan origin, its open ports landing as JSON-lines
    /// findings. The payload names the target and the ports scanned; the
    /// outcome is the findings artifact id or <c>failed:{reason}</c>. A
    /// target outside the engagement's ROE scope never reaches this event
    /// -- <see cref="ReconScanRefused"/> records the refusal instead.
    /// </summary>
    ReconScanCompleted,

    /// <summary>
    /// The recon workbench's scan was refused by the engagement's ROE
    /// target scope before a connection was opened (architecture.md Sec 9,
    /// Sec 11.4) -- the task gate's <see cref="TaskRoeRefused"/> posture on
    /// the workbench's own kind, because no task exists to refuse. The
    /// payload names the target and the ports asked for; the outcome names
    /// the violated rule. Attributed to the requesting operator.
    /// </summary>
    ReconScanRefused,

    /// <summary>
    /// An operator minted a browser hook for the engagement (architecture.md
    /// Sec 5.2, Sec 8): rendered the in-tree script with a bake (credential,
    /// seal, cadence, verbs) and stored it as a served payload record. The
    /// payload carries the mint's shape -- which listener fronts it, the
    /// seal posture, the cadence, the enrollment budget the baked token
    /// carries -- and never the token secret or the key; the outcome is the
    /// hook's payload id, the id its serving route answers to.
    /// </summary>
    HookMinted,

    /// <summary>
    /// A browser fetched the hook (or its test page) off the public edge
    /// (architecture.md Sec 8) -- the hooked browser's first observable
    /// touch, before any identity exists: the fetcher speaks no Rod protocol
    /// and carries no identity, so the event is scoped by the hook record's
    /// engagement and attributed to the null operator, exactly like a
    /// payload fetch. The payload carries what the wire showed (remote
    /// address, user agent, listener socket, whether script or test page);
    /// the outcome is the hook's payload id. The enrollment that may follow
    /// is the identity-bearing half of the exchange.
    /// </summary>
    HookFetched,

    /// <summary>
    /// A delivery campaign was created, launched, or revoked
    /// (architecture.md Sec 11.5). The payload carries the campaign's
    /// shape -- the recipient count, the relay's host (the address alone,
    /// never the credential), the listener fronting the lure -- and the
    /// outcome is the campaign id. Attributed to the acting operator. The
    /// state flips share this kind with the verb naming which flip
    /// (campaign.created / campaign.launched / campaign.revoked).
    /// </summary>
    CampaignStateChanged,

    /// <summary>
    /// The send engine delivered one campaign message to its relay -- or
    /// failed to (architecture.md Sec 11.5). The payload names the
    /// campaign and the recipient; the outcome is <c>delivered</c> or
    /// <c>failed:{reason}</c>. Delivery is single-attempt by design, so
    /// this fact is the send's whole record. Attributed to the campaign's
    /// creator, the operator whose launch authorized the send.
    /// </summary>
    CampaignMessageSent,

    /// <summary>
    /// A recipient fetched their lure off the public edge (architecture.md
    /// Sec 11.5) -- the click, or the tracking pixel's open. The fetcher
    /// speaks no Rod protocol and carries no identity, so the event is
    /// scoped by the campaign's engagement and attributed to the null
    /// operator, exactly like a payload fetch or a hook fetch. The payload
    /// carries what the wire showed (remote address, user agent, listener
    /// socket, open or click); the outcome is the recipient's lure id. The
    /// enrollment that may follow is the identity-bearing half of the
    /// exchange, recorded on the ImplantEnrolled fact.
    /// </summary>
    CampaignLinkServed,

    /// <summary>
    /// An operator changed a listener's front list (architecture.md Sec 8):
    /// attached a front to an enrolled redirector node, detached one, or
    /// promoted one to primary. The payload names the node, the listen
    /// endpoint the node binds, and the public endpoint implants dial; the
    /// outcome is the front id, and the verb names the change
    /// (listener.front-attached / listener.front-detached /
    /// listener.front-primary). Attributed to the acting operator, scoped to
    /// the listener's engagement -- the front is where deployment capacity
    /// meets engagement scope. The node-side rule push that follows is
    /// derived state, not a separate fact.
    /// </summary>
    ListenerFrontChanged,

    /// <summary>
    /// An operator changed the listener itself (architecture.md Sec 8):
    /// created one, deleted one, or repointed its public endpoint -- the
    /// burn-handling move that severs a compromised redirector without
    /// touching the backend. The payload names the listener, its transport,
    /// and the endpoints involved (the repoint carries old to new); the
    /// outcome is the listener id, and the verb names the change
    /// (listener.created / listener.deleted / listener.repointed).
    /// Attributed to the acting operator, scoped to the listener's
    /// engagement -- a deleted listener's trail must outlive the listener.
    /// </summary>
    ListenerChanged,

    /// <summary>
    /// The platform expired a dispatched task whose response never came
    /// back (architecture.md Sec 10.3): the TXT answer or contact response
    /// carrying it was lost, and no poll carrier re-delivers a dispatched
    /// task, so past the expiry window the task completes as failed with
    /// this fact closing its arc. Attributed to the null operator (a
    /// platform action, no human in the loop), scoped to the task's
    /// engagement; the payload names the verb and the age at expiry. A
    /// late-arriving real result finds the task already terminal and is
    /// dropped by the first-wins rule, exactly like a duplicate.
    /// </summary>
    TaskExpired,

    /// <summary>
    /// An operator changed deployment-level state (architecture.md Sec 9):
    /// an operator account or its credentials -- creation, disable/enable,
    /// password set, credential revocation, API-token mint and revocation.
    /// These actions are the highest-privilege ones the platform takes
    /// ("who created the backdoor account" is a question a review must be
    /// able to answer), but they are global: they bind to no engagement, so
    /// they land in the deployment bucket -- the trail under the empty
    /// engagement id, the same "none" convention the event's own implant
    /// and task ids carry -- hash-chained and read like any engagement's
    /// through the admin-only deployment trail route. Attributed to the
    /// acting operator, the payload names the change, the outcome is the
    /// target account's id.
    /// </summary>
    OperatorAccountChanged,

    /// <summary>
    /// An operator recorded a recon asset (architecture.md Sec 15.4): the
    /// curatorial act of promoting an address to a tracked target of the
    /// unified entity model -- typed by hand or lifted from a workbench
    /// findings artifact. The payload names the kind and the value; the
    /// outcome is the asset id, and the artifact link rides the payload
    /// (<c>from=artifact:{id}</c>) when a finding stands behind the asset.
    /// Attributed to the recording operator; no implant and no task are
    /// involved.
    /// </summary>
    ReconAssetRecorded,

    /// <summary>
    /// An operator removed a recon asset (architecture.md Sec 15.4): the
    /// engagement's target list loses the row. A campaign that already
    /// selected the asset keeps its resolved address -- a recipient row
    /// never depends on the asset staying alive -- which is also why the
    /// delete is refused while a recipient still references the asset:
    /// the reference is the record of selection, and the foreign key
    /// guarding it is the one refusing. The payload names the kind and
    /// the value; the outcome is the asset id.
    /// </summary>
    ReconAssetDeleted,

    /// <summary>
    /// An operator spawned a range engagement's simulated fleet
    /// (architecture.md Sec 15.3): the beacons are the teamserver's own
    /// scripted clients, enrolling and tasking through the real ingress
    /// paths. The payload names the listener, size, cadence, and simulated
    /// host shape; the outcome is the shared enrollment token's id -- the
    /// mint every simulated enrollment's own ImplantEnrolled fact resolves
    /// back to, binding the whole fleet to this spawn's operator.
    /// </summary>
    RangeFleetSpawned,

    /// <summary>
    /// An operator stopped a range engagement's simulated fleet. The payload
    /// carries the fleet's final posture (beacons, contacts, results); the
    /// beacons' own trails stay as they ran -- stopping a fleet retires no
    /// evidence.
    /// </summary>
    RangeFleetStopped,
}
