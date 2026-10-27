using Rod.CoreState.Collaboration;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Live;
using Rod.CoreState.Operators;
using Rod.CoreState.Sessions;
using Rod.CoreState.Tasks;
using Rod.CoreState.Transports;
// The domain entity shares its name with System.Threading.Tasks.Task. Pin it
// here so the service's own Task type wins; the BCL type is reached by its full
// name where the methods below return it.
using Task = Rod.CoreState.Tasks.Task;

namespace Rod.CoreState.Application;

/// <summary>
/// The tasking use cases: an operator issues a task against an
/// implant; the beacon stream pulls the next queued task to dispatch; the
/// implant's result is captured back into the task. Orchestrates the core-state
/// task port; holds no state of its own, and -- by design -- knows nothing of
/// the audit trail. The transport layer composes the audit write on result
/// capture (architecture.md Sec 11); audit wiring arrives properly with the
/// storage &amp; audit layer.
///
/// As of the operator layer, issuing a task also publishes a
/// <see cref="LiveEventKind.TaskIssued"/> event on the live bus so every
/// connected operator session sees new tasking the moment it is queued. The bus
/// is optional at the constructor: the core-state unit tests construct this
/// service without one, and the absence simply skips the publish (the task
/// itself is the source of truth; the bus is the transient fan-out).
///
/// Issuance is gated through the capability resolver
/// (<see cref="ITaskCapabilityResolver"/>, architecture.md Sec 5.2/10.3): the
/// per-class reduced verb set is the primary authority, and a verb a registered
/// capability module handles is admitted too -- so the evasion and exploit
/// categories (contract and dispatch only, not class-gated, Sec 10.2) are no
/// longer refused before dispatch. A verb outside both is refused before the task
/// is queued, throwing <see cref="TaskRejectedException"/> for the transport to
/// map. The implant is resolved here so the gate reads the class the implant
/// actually enrolled with, and the engagement binding is checked against it
/// (architecture.md Sec 3). The engagement's rules-of-engagement scope is the
/// final issuance gate (architecture.md Sec 9): a task outside the profile the
/// engagement's operators set -- a non-permitted verb or target -- is refused
/// the same way, after the class gate so the refusal names the ROE rule.
///
/// As with <see cref="EnrollmentService"/> and <see cref="HandshakeService"/>,
/// refusals propagate as exceptions the transport maps to wire status.
/// </summary>
public sealed class TaskService
{
    private readonly ITaskRepository _tasks;
    private readonly IImplantRepository _implants;
    private readonly IEngagementRepository _engagements;
    private readonly TimeProvider _clock;
    private readonly ILiveEventBus? _bus;
    private readonly ITaskCapabilityResolver _capabilities;
    private readonly ITaskDispatchWake? _wake;
    private readonly TaskReferenceService? _references;
    private readonly CredentialHarvester? _harvester;
    private readonly ISessionRegistry? _sessions;

    public TaskService(
        ITaskRepository tasks,
        IImplantRepository implants,
        IEngagementRepository engagements,
        TimeProvider clock)
        : this(tasks, implants, engagements, clock, bus: null, capabilities: new ClassTableCapabilityResolver(), wake: null)
    {
    }

    /// <summary>
    /// Constructs the service with a live-event bus. The composition root wires
    /// the bus; the four-argument constructor above keeps the
    /// core-state unit tests bus-free.
    /// </summary>
    public TaskService(
        ITaskRepository tasks,
        IImplantRepository implants,
        IEngagementRepository engagements,
        TimeProvider clock,
        ILiveEventBus? bus)
        : this(tasks, implants, engagements, clock, bus, capabilities: new ClassTableCapabilityResolver(), wake: null)
    {
    }

    /// <summary>
    /// Constructs the service with a live-event bus and a capability resolver.
    /// The resolver is the verb-gate authority (architecture.md Sec 5.2/10.3):
    /// the composition root passes the tradecraft-backed resolver once the
    /// capability registry is wired onto the live path, so the evasion and
    /// exploit categories -- contract and dispatch only, not class-gated
    /// (architecture.md Sec 10.2) -- are no longer refused before dispatch. The
    /// simpler constructors above keep the class-table-only default so the
    /// core-state unit tests and any host that does not opt into the tradecraft
    /// layer keep exactly the behavior they had.
    /// </summary>
    /// <param name="wake">
    /// The per-implant dispatch wake (architecture.md Sec 10.3): released on
    /// every accepted enqueue so the beacon stream's writer pushes the task
    /// downstream instead of waiting for a poll. A real parameter, not an
    /// optional one: the container selects the longest constructor whose
    /// parameters all resolve, so the wake reaches the host only when the
    /// composition root registers it (and the capability-resolver default)
    /// alongside this service. The chaining constructors pass null, which
    /// simply skips the release.
    /// </param>
    public TaskService(
        ITaskRepository tasks,
        IImplantRepository implants,
        IEngagementRepository engagements,
        TimeProvider clock,
        ILiveEventBus? bus,
        ITaskCapabilityResolver capabilities,
        ITaskDispatchWake? wake)
        : this(tasks, implants, engagements, clock, bus, capabilities, wake, references: null, harvester: null)
    {
    }

    /// <summary>
    /// The fullest construction: the wake, the collaboration halves
    /// (architecture.md Sec 15.3, ADR-005) -- the reference validator that
    /// keeps <c>@task-</c>/<c>$cred-</c> tokens in task input from dangling
    /// (checked at issuance, before the queue, so the refusal names the
    /// token), and the harvester that lands a credential-kind task's rows
    /// when it completes -- plus the session registry ADR-017's runtime
    /// requirement gate reads. All optional the same way the wake is: the
    /// container selects this constructor only when the composition root
    /// registers them, and their absence skips the behavior exactly as a
    /// missing bus skips the publish.
    /// </summary>
    public TaskService(
        ITaskRepository tasks,
        IImplantRepository implants,
        IEngagementRepository engagements,
        TimeProvider clock,
        ILiveEventBus? bus,
        ITaskCapabilityResolver capabilities,
        ITaskDispatchWake? wake,
        TaskReferenceService? references,
        CredentialHarvester? harvester,
        ISessionRegistry? sessions = null)
    {
        _tasks = tasks;
        _implants = implants;
        _engagements = engagements;
        _clock = clock;
        _bus = bus;
        _capabilities = capabilities;
        _wake = wake;
        _references = references;
        _harvester = harvester;
        _sessions = sessions;
    }

    /// <summary>
    /// Issues a task: resolves and validates the implant against the engagement,
    /// gates the verb on the implant's class reduced verb set
    /// (architecture.md Sec 5.2), creates it in <see cref="TaskStatus.Queued"/>
    /// for the implant and persists it, then publishes a live event so connected
    /// operators see the new tasking in real time. Returns the created task.
    /// Throws <see cref="TaskRejectedException"/> (unknown implant, engagement
    /// mismatch, or an unsupported verb) for the transport to map to a wire
    /// status -- the class's reduced set is the authority for what the implant
    /// may run.
    /// <paramref name="onIssued" /> composes the issuance's durable record (the
    /// transport's audit write) before the dispatch wake releases: the push
    /// dispatch it releases audits <c>TaskDispatched</c> on the stream thread,
    /// and without this hook that append can beat the issuance's own
    /// <c>TaskIssued</c> to the trail, reading the attributed arc backwards
    /// (architecture.md Sec 11).
    /// </summary>
    public async System.Threading.Tasks.Task<TaskIssued> IssueAsync(
        IssueTaskCommand command,
        Func<TaskIssued, CancellationToken, System.Threading.Tasks.Task>? onIssued = null,
        CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow();

        // Resolve the implant and check its engagement binding (architecture.md
        // Sec 3) before anything is queued. The class the implant enrolled with
        // is what the verb gate below reads.
        var implant = await _implants.FindAsync(command.ImplantId, cancellationToken);
        if (implant is null)
        {
            throw new TaskRejectedException(
                TaskRejectionReason.UnknownImplant,
                $"Implant {command.ImplantId} is not enrolled.");
        }
        if (implant.EngagementId != command.EngagementId)
        {
            throw new TaskRejectedException(
                TaskRejectionReason.ImplantEngagementMismatch,
                $"Implant {implant.Id} belongs to engagement {implant.EngagementId}, " +
                $"not {command.EngagementId}.");
        }

        // A retired implant is out of operation and untaskable (architecture.md
        // Sec 7). Checked after the binding resolves and before the verb
        // gate, so a retirement is refused regardless of the verb.
        if (implant.IsRetired)
        {
            throw new TaskRejectedException(
                TaskRejectionReason.ImplantRetired,
                $"Implant {implant.Id} was retired at {implant.RetiredAt:O}.");
        }

        // The capability resolver is the authority for what this implant may run
        // (architecture.md Sec 5.2, Sec 10.3). Its default is the per-class
        // reduced verb set; the composition root swaps in the tradecraft-backed
        // resolver so a verb a registered capability module handles -- including
        // the no-class-gate evasion and exploit categories (architecture.md Sec
        // 10.2) -- is admitted too. A verb outside both never reaches the queue,
        // so a reduced-class implant cannot be tasked past its purpose.
        if (!_capabilities.IsDispatchable(implant.Class, command.Verb))
        {
            throw new TaskRejectedException(
                TaskRejectionReason.UnsupportedVerbForClass,
                $"Verb '{command.Verb}' is not in the {implant.Class} reduced verb set " +
                "and no capability module is registered for it.");
        }

        // The runtime half of the compatibility collapse (architecture.md
        // Sec 15.2, ADR-017): a module.load naming a registered module checks
        // the module's requirement rows against the live session's handshake
        // advertisement -- the truth the store's install-time rows only
        // approximate. Refused here with the missing capability named, before
        // the queue, because the load's only other outcome is failing on the
        // target after a round trip. The module name is the arguments' first
        // token (the staged-content hash the transport appends never leads);
        // a name no registered module carries has no rows to check, and an
        // implant with no active session has no advertisement to check
        // against -- its queued tasking keeps the store-advisory posture and
        // the gate re-arms on the next session.
        if (_sessions is not null
            && string.Equals(command.Verb, WireCapabilities.ModuleLoadVerb, StringComparison.OrdinalIgnoreCase))
        {
            var moduleName = command.Arguments.Split(' ', 2)[0].Trim();
            var requires = moduleName.Length > 0 ? _capabilities.ModuleRequires(moduleName) : null;
            if (requires is { Count: > 0 })
            {
                var session = await _sessions.GetActiveAsync(implant.Id, cancellationToken);
                if (session is not null)
                {
                    var missing = requires
                        .Where(name => !WireCapabilities.Covers(session.Capabilities, name))
                        .ToArray();
                    if (missing.Length > 0)
                    {
                        throw new TaskRejectedException(
                            TaskRejectionReason.ModuleRequirementNotMet,
                            $"Module '{moduleName}' requires {string.Join(", ", missing)}; " +
                            $"implant {implant.Id}'s session does not advertise the covering verb, " +
                            "so it cannot host the module's execution half.");
                    }
                }
            }
        }

        // The carrier gate (architecture.md Sec 8, Sec 10.3): a channel verb
        // needs an implant whose baked carriers can claim one -- natively (a
        // live stream) or by the degraded store-and-forward discipline the
        // bake opted into. Refusing here replaces the old shape where the
        // task queued forever, deferred by every poll carrier that claimed
        // around it. Null is the permissive shape (a legacy implant, a build
        // whose endpoint shapes the derivation did not recognize): the
        // dispatch-time claim evaluation alone decides, exactly as before the
        // stamp existed.
        if (ChannelVerbs.IsChannelVerb(command.Verb)
            && implant.Carriers is { Count: > 0 }
            && !HoldsChannelCapableCarrier(implant.Carriers))
        {
            throw new TaskRejectedException(
                TaskRejectionReason.NoChannelCarrier,
                $"Implant {implant.Id} contacts over {string.Join(", ", implant.Carriers)}; " +
                "no baked carrier can run a channel task. Build it against a web front in " +
                "stream mode, or bake the degraded-channels opt-in for its poll cadence.");
        }

        // The engagement's rules-of-engagement scope is the last gate before
        // the queue (architecture.md Sec 9 -- ROE guardrails). Unlike the class
        // gate it is operator-set per engagement, not baked per implant class:
        // it narrows what the engagement's operators may task regardless of
        // what the implant could run. Checked after the binding and capability
        // gates so the refusal names the ROE rule, the most specific cause. An
        // engagement the implant binding already validated always resolves
        // here; a null engagement leaves the scope unrestricted rather than
        // inventing a refusal the binding checks above did not.
        var engagement = await _engagements.FindAsync(command.EngagementId, cancellationToken);
        var roeViolation = engagement?.Roe.Evaluate(implant.Id.ToString(), command.Verb);
        if (roeViolation is not null)
        {
            throw new TaskRejectedException(
                TaskRejectionReason.RoeViolation,
                $"Task refused by the engagement's rules of engagement: {roeViolation}.");
        }

        // A closed engagement (frozen for close-out or retired) accepts no new
        // tasking (architecture.md Sec 2 step 10): the exported evidence
        // package must be the final account of what was tasked. Checked after
        // the ROE gate -- the same engagement object, resolved once -- but
        // before the task is queued.
        if (engagement?.IsClosed == true)
        {
            throw new TaskRejectedException(
                TaskRejectionReason.EngagementClosed,
                $"Engagement {engagement.Id} is closed for close-out" +
                (engagement.IsRetired ? " (retired)" : " (frozen)") +
                $"; it accepts no new tasking.");
        }

        // Task references in the input resolve now, not at dispatch
        // (architecture.md Sec 15.3, ADR-005): every well-formed
        // <c>@task-</c>/<c>$cred-</c> token must address an entity of this
        // engagement, or the tasking is refused before the queue with the
        // offender named. The token itself rides the task row and the trail
        // in placeholder form; only the dispatch wire ever sees the
        // credential's secret.
        if (_references is not null)
        {
            var unresolved = await _references.UnresolvedAsync(command.EngagementId, command.Arguments, cancellationToken);
            if (unresolved.Count > 0)
            {
                throw new TaskRejectedException(
                    TaskRejectionReason.UnknownTaskReference,
                    "Task input references "
                    + string.Join(", ", unresolved.Select(t => t.Render()))
                    + " -- no such task or credential in this engagement.");
            }
        }

        var task = Task.Create(
            TaskId.New(),
            command.EngagementId,
            command.ImplantId,
            command.IssuedBy,
            command.Verb,
            command.Arguments,
            now,
            command.StagedBytes);
        await _tasks.SaveAsync(task, cancellationToken);

        var issued = new TaskIssued(
            task.Id,
            task.EngagementId,
            task.ImplantId,
            task.IssuedBy,
            task.Verb,
            task.Arguments,
            task.CreatedAt);

        // The issuance's durable record composes before the wake: the push
        // dispatch it releases audits TaskDispatched on the stream thread, and
        // that append must not beat the TaskIssued it follows to the trail.
        if (onIssued is not null)
            await onIssued(issued, cancellationToken);

        // The queue accepted the task: wake the beacon writer so it is pushed
        // downstream the moment it is queued, not on the next poll
        // (architecture.md Sec 10.3). A permit with no open stream simply
        // accumulates for the next connect. A pivot child's task wakes its
        // fronting parent too (Sec 5.2): the child has no stream of its own
        // to park on the child's wake -- the parent's writer is the one that
        // claims and executes it.
        _wake?.Release(task.ImplantId);
        if (implant.Class == ImplantClass.Pivot && implant.ParentImplantId is { } fronting)
            _wake?.Release(fronting);

        if (_bus is not null)
        {
            await _bus.PublishAsync(
                LiveEvent.TaskIssued(
                    task.EngagementId,
                    task.IssuedBy,
                    task.ImplantId,
                    task.Id,
                    payload: $"{task.Verb} {task.Arguments}".TrimEnd(),
                    now),
                cancellationToken);
        }

        return issued;
    }

    /// <summary>
    /// Atomically claims the next queued task for <paramref name="implant"/>,
    /// or returns null when nothing is queued. What the beacon stream drains on
    /// each contact. The claim is atomic inside the repository adapter, so a
    /// reconnect overlap for one implant cannot dispatch the same task twice.
    /// A claimed task for an implant that negotiated the replay-nonce arm
    /// (architecture.md Sec 9) is stamped with the next per-implant nonce --
    /// every claim, including a requeue's re-claim, gets a fresh value, so the
    /// transport signs and delivers the five-element tuple.
    /// </summary>
    /// <param name="cancellationToken">
    /// Passed through to the repository claims and implant lookups.
    /// </param>
    /// <param name="includeFronted">
    /// Widens the claim to the Pivot children this implant fronts
    /// (architecture.md Sec 5.2): their tasking is claimed here and executed by
    /// this implant's stream, because a pivot child has no process of its own
    /// to claim with. Opt-in -- a poll transport (DNS, an envelope contact)
    /// cannot carry a fronted channel's input half, so it keeps the narrow
    /// claim and fronted tasks park for a stream to claim.
    /// </param>
    /// <param name="exclude">
    /// The calling carrier's skip set: tasks it just requeued for a capable
    /// transport. The claim passes over them so one oversized or
    /// channel-bound task cannot stand at the queue head and wedge a
    /// poll-only implant's tasking.
    /// </param>
    public async System.Threading.Tasks.Task<TaskDispatched?> DispatchNextAsync(
        ImplantId implant,
        CancellationToken cancellationToken = default,
        bool includeFronted = false,
        IReadOnlySet<TaskId>? exclude = null)
    {
        var at = _clock.GetUtcNow();
        Rod.CoreState.Tasks.Task? task;
        if (!includeFronted)
        {
            task = await _tasks.ClaimNextPendingAsync(implant, at, exclude, cancellationToken);
        }
        else
        {
            // The fronting set resolves per claim, so a pivot child enrolled
            // mid-stream is fronted from the next claim onward. An empty
            // fronted set falls back to the single-implant claim.
            var fronted = await _implants.ListFrontedPivotsAsync(implant, cancellationToken);
            if (fronted.Count == 0)
            {
                task = await _tasks.ClaimNextPendingAsync(implant, at, exclude, cancellationToken);
            }
            else
            {
                var targets = new List<ImplantId>(fronted.Count + 1) { implant };
                foreach (var pivot in fronted)
                    targets.Add(pivot.Id);
                task = await _tasks.ClaimNextPendingForAsync(targets, at, exclude, cancellationToken);
            }
        }

        if (task is null)
            return null;

        // The nonce arm follows the claimed task's own implant: fronted
        // tasking belongs to the pivot child, which never handshakes and so
        // never negotiated the arm -- it keeps the nonce-less tuple.
        ulong? nonce = null;
        var record = await _implants.FindAsync(task.ImplantId, cancellationToken);
        if (record is { ReplayNonces: true })
            nonce = await _tasks.NextNonceAsync(task.ImplantId, cancellationToken);

        return new TaskDispatched(
            task.Id,
            task.EngagementId,
            task.ImplantId,
            task.IssuedBy,
            task.Verb,
            task.Arguments,
            task.StagedBytes,
            task.DispatchedAt!.Value,
            Nonce: nonce);
    }

    /// <summary>
    /// Returns a claimed task to the queue (architecture.md Sec 10.3): the
    /// transport calls this when the downstream frame write failed, so the task
    /// is redelivered on a later contact instead of stranding Dispatched.
    /// Throws <see cref="InvalidOperationException"/> when the task is not in
    /// Dispatched -- same refusal shape as <see cref="RecordResultAsync"/>.
    /// </summary>
    public async System.Threading.Tasks.Task RequeueAsync(
        TaskId id,
        CancellationToken cancellationToken = default)
    {
        var task = await _tasks.FindAsync(id, cancellationToken)
            ?? throw new InvalidOperationException($"Task {id} is not known.");

        task.Requeue();
        await _tasks.SaveAsync(task, cancellationToken);

        // A requeue is an enqueue too: a live overlapping stream for the
        // implant picks the task back up immediately instead of waiting for
        // the reconnect (architecture.md Sec 10.3). A fronted task's requeue
        // wakes the fronting parent as well -- its writer is the claimer
        // (Sec 5.2).
        _wake?.Release(task.ImplantId);
        var target = await _implants.FindAsync(task.ImplantId, cancellationToken);
        if (target is { Class: ImplantClass.Pivot, ParentImplantId: { } fronting })
            _wake?.Release(fronting);
    }

    /// <summary>
    /// Retracts a queued task before the implant wakes (architecture.md Sec
    /// 10.3): the operator's own tasking, taken back before dispatch. The
    /// repository performs the transition atomically against a racing claim, so
    /// a task already handed to the implant stream is not cancellable -- the
    /// implant owns it now. Resolves the task's engagement binding first
    /// (architecture.md Sec 3) and throws <see cref="InvalidOperationException"/>
    /// for an unknown task or a task that is no longer queued; returns the
    /// cancelled view so the caller can compose the audit record. No wake is
    /// released: there is nothing left to push downstream.
    /// </summary>
    public async System.Threading.Tasks.Task<TaskCancelled> CancelAsync(
        EngagementId engagement,
        TaskId id,
        OperatorId cancelledBy,
        CancellationToken cancellationToken = default)
    {
        // Resolve the engagement binding before the retraction: a task outside
        // this engagement does not exist as far as the caller is concerned
        // (architecture.md Sec 3).
        var existing = await _tasks.FindAsync(id, cancellationToken)
            ?? throw new InvalidOperationException($"Task {id} is not known.");
        if (existing.EngagementId != engagement)
            throw new InvalidOperationException($"Task {id} does not exist in engagement {engagement}.");

        var task = await _tasks.CancelAsync(id, _clock.GetUtcNow(), cancellationToken)
            ?? throw new InvalidOperationException($"Task {id} is not known.");
        if (task.Status != Rod.CoreState.Tasks.TaskStatus.Cancelled)
            throw new InvalidOperationException(
                $"Task {id} cannot be cancelled from {task.Status}: only a queued task can be retracted.");

        var cancelled = new TaskCancelled(
            task.Id,
            task.EngagementId,
            task.ImplantId,
            task.IssuedBy,
            cancelledBy,
            task.Verb,
            task.Arguments,
            task.CancelledAt!.Value);

        // The retraction reaches connected operators the same moment the queue
        // drops it, so a peer's queued view does not linger. Like issuance this
        // is the transient fan-out; the audit event is the durable record.
        if (_bus is not null)
        {
            await _bus.PublishAsync(
                LiveEvent.TaskCancelled(
                    task.EngagementId,
                    cancelledBy,
                    task.ImplantId,
                    task.Id,
                    payload: $"{task.Verb} {task.Arguments}".TrimEnd(),
                    task.CancelledAt!.Value),
                cancellationToken);
        }

        return cancelled;
    }

    /// <summary>
    /// Appends one chunk of a streaming task's channel output to its
    /// transcript (architecture.md Sec 10.3, the streaming task shape). The
    /// chunk lands on the task's Output while it is Dispatched, so an operator
    /// reads a live channel the same way it reads a captured result. Throws
    /// <see cref="InvalidOperationException"/> when the task is unknown or no
    /// longer Dispatched: a straggler chunk after the final TaskResult (a
    /// retransmission, a race at channel close) carries nothing new, and the
    /// transport ignores it rather than tearing the session down. Returns the
    /// appended view so the caller can attribute the live fan-out.
    /// </summary>
    public async System.Threading.Tasks.Task<TaskAppended> AppendChannelOutputAsync(
        TaskId id,
        string chunk,
        CancellationToken cancellationToken = default)
    {
        var task = await _tasks.FindAsync(id, cancellationToken)
            ?? throw new InvalidOperationException($"Task {id} is not known.");

        task.AppendOutput(chunk);
        await _tasks.SaveAsync(task, cancellationToken);

        return new TaskAppended(
            task.Id,
            task.EngagementId,
            task.ImplantId,
            task.IssuedBy,
            task.Verb);
    }

    /// <summary>
    /// Captures the implant's result into the task and completes it. The
    /// transition is atomic in the repository, so a duplicate result -- the
    /// receive-ack arm makes retransmits a normal occurrence (architecture.md
    /// Sec 10.3) -- loses the race and the first result wins. Throws
    /// <see cref="InvalidOperationException"/> if the task is unknown or no
    /// longer Dispatched (a prior result already completed it). Returns the
    /// completed view so the caller (the transport) can build the audit event
    /// from it.
    /// </summary>
    public async System.Threading.Tasks.Task<TaskCompleted> RecordResultAsync(
        TaskId id,
        string output,
        TaskOutcome outcome,
        CancellationToken cancellationToken = default)
    {
        var task = await _tasks.CompleteAsync(id, output, outcome, _clock.GetUtcNow(), cancellationToken)
            ?? throw new InvalidOperationException(
                $"Task {id} is not known or is no longer dispatched; the first result stands.");

        var completed = new TaskCompleted(
            task.Id,
            task.EngagementId,
            task.ImplantId,
            task.IssuedBy,
            task.Verb,
            task.Arguments,
            task.Output!,
            task.Outcome!.Value,
            task.CompletedAt!.Value);

        // A credential-kind task's output lands in the credential store as
        // it completes (architecture.md Sec 15.3, ADR-005) -- the rows a
        // task-reference placeholder addresses. Beside the completion, not
        // inside the repository: the harvest is a product of the result,
        // never a state of the task.
        if (_harvester is not null)
            await _harvester.CaptureAsync(completed, cancellationToken);

        return completed;
    }

    /// <summary>
    /// Expires dispatched tasks whose response never came back (architecture.md
    /// Sec 10.3): a poll carrier hands a task out once, and when the answer it
    /// rode is lost nothing re-delivers it -- without this sweep the task hangs
    /// Dispatched forever (the operator's cancel only reaches Queued). A task
    /// past <paramref name="staleness"/> completes as failed, closing its arc;
    /// a channel task is never expired, because a live channel legitimately
    /// runs for hours and losing its eventual result would misreport it. The
    /// completion races a late-arriving real result under the first-wins rule:
    /// a result that lands first spares the task, and one that lands after the
    /// expiry is dropped exactly like a duplicate. Returns the tasks this call
    /// expired, for the caller to audit.
    /// </summary>
    public async System.Threading.Tasks.Task<IReadOnlyList<TaskCompleted>> ExpireLostTasksAsync(
        TimeSpan staleness,
        CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow();
        var cutoff = now - staleness;
        var candidates = await _tasks.ListDispatchedBeforeAsync(cutoff, cancellationToken);

        var expired = new List<TaskCompleted>();
        foreach (var candidate in candidates)
        {
            if (ChannelVerbs.IsChannelVerb(candidate.Verb))
                continue;

            var task = await _tasks.CompleteAsync(
                candidate.Id,
                $"expired: dispatched {now - candidate.DispatchedAt!.Value:h\\hh\\ m\\mm} ago with no response "
                + "(the carrying answer was lost; no poll carrier re-delivers a dispatched task)",
                TaskOutcome.Failed,
                now,
                cancellationToken);
            if (task is null)
                continue; // A real result won the race; it stands.

            expired.Add(new TaskCompleted(
                task.Id,
                task.EngagementId,
                task.ImplantId,
                task.IssuedBy,
                task.Verb,
                task.Arguments,
                task.Output!,
                task.Outcome!.Value,
                task.CompletedAt!.Value));
        }

        return expired;
    }

    // The carrier gate's half of the question: can any baked carrier run a
    // channel task? A native carrier holds a live stream; a degraded carrier
    // carries the store-and-forward discipline on its poll cycles (the
    // artifact always advertises it). Only a carrier with no channel support
    // at all (DNS's datagram poll) keeps the refusal.
    private static bool HoldsChannelCapableCarrier(IReadOnlyList<string> carriers)
    {
        foreach (var carrier in carriers)
        {
            if (TransportCapabilities.Find(carrier).Channels != ChannelSupport.None)
                return true;
        }
        return false;
    }
}

/// <summary>
/// Request to issue a task. <see cref="EngagementId"/> and <see cref="ImplantId"/>
/// scope it; <see cref="IssuedBy"/> attributes it; <see cref="Verb"/> is the
/// capability verb (e.g. <c>shell.exec</c>); <see cref="Arguments"/> is its input.
/// <see cref="StagedBytes"/> is the typed arm's advisory size
/// (architecture.md Sec 10): set (by the transport, which stages the bytes as a
/// task-bound artifact) when the payload is too large for the arguments string,
/// null for the ordinary inline shape.
/// </summary>
public sealed record IssueTaskCommand(
    EngagementId EngagementId,
    ImplantId ImplantId,
    OperatorId IssuedBy,
    string Verb,
    string Arguments,
    long? StagedBytes = null);

/// <summary>Result of issuing a task: its identity, scope, attribution, and verb.</summary>
public sealed record TaskIssued(
    TaskId TaskId,
    EngagementId EngagementId,
    ImplantId ImplantId,
    OperatorId IssuedBy,
    string Verb,
    string Arguments,
    DateTimeOffset CreatedAt);

/// <summary>
/// Result of retracting a queued task (architecture.md Sec 10.3):
/// <see cref="IssuedBy"/> is the operator whose tasking it was;
/// <see cref="CancelledBy"/> is the operator who retracted it -- the same
/// operator in the common case, but the retraction is its own attributed
/// action, so it carries its own actor and stamp for the audit record.
/// </summary>
public sealed record TaskCancelled(
    TaskId TaskId,
    EngagementId EngagementId,
    ImplantId ImplantId,
    OperatorId IssuedBy,
    OperatorId CancelledBy,
    string Verb,
    string Arguments,
    DateTimeOffset CancelledAt);

/// <summary>
/// Result of appending a streamed chunk to a task's transcript: the identity,
/// scope, and attribution the live fan-out needs (architecture.md Sec 10.3).
/// </summary>
public sealed record TaskAppended(
    TaskId TaskId,
    EngagementId EngagementId,
    ImplantId ImplantId,
    OperatorId IssuedBy,
    string Verb);

/// <summary>
/// Result of dispatching a task to the implant stream. <see cref="IssuedBy"/> is
/// the operator whose tasking the dispatch carries out -- dispatch is
/// server-driven (the implant pulls the queue), so the event the beacon composes
/// attributes through this rather than through a request body.
/// <see cref="StagedBytes"/> echoes the typed arm's marker so the stream writes
/// it onto the TaskRequest (architecture.md Sec 10).
/// </summary>
public sealed record TaskDispatched(
    TaskId TaskId,
    EngagementId EngagementId,
    ImplantId ImplantId,
    OperatorId IssuedBy,
    string Verb,
    string Arguments,
    long? StagedBytes,
    DateTimeOffset DispatchedAt,
    ulong? Nonce = null);

/// <summary>
/// Result of capturing a task's outcome: the full attributed, scoped record,
/// including the captured output. This is what the transport turns into an
/// audit event.
/// </summary>
public sealed record TaskCompleted(
    TaskId TaskId,
    EngagementId EngagementId,
    ImplantId ImplantId,
    OperatorId IssuedBy,
    string Verb,
    string Arguments,
    string Output,
    TaskOutcome Outcome,
    DateTimeOffset CompletedAt);
