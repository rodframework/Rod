using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
// The domain entity shares its name with System.Threading.Tasks.Task. Pin it
// here so the port's own Task type wins; the BCL type is reached by its full
// name where the methods return it.
using Task = Rod.CoreState.Tasks.Task;

namespace Rod.CoreState.Tasks;

/// <summary>
/// Persistence port for <see cref="Task"/> aggregates. The core-state layer
/// shapes this as a first-class task queue and history: per-implant
/// FIFO dequeue for dispatch, plus implant- and engagement-scoped history. Every
/// query is rooted in an implant or engagement (which themselves belong to one
/// engagement), so cross-engagement access stays impossible by construction
/// (architecture.md Sec 3).
///
/// The default is an in-memory implementation; the port keeps callers
/// agnostic to that.
/// </summary>
public interface ITaskRepository
{
    /// <summary>
    /// Stores <paramref name="task"/>, inserting or replacing by id. Re-saving a
    /// dispatched/completed task keeps it in history with its updated status.
    /// </summary>
    System.Threading.Tasks.Task SaveAsync(Task task, CancellationToken cancellationToken = default);

    /// <summary>The task, or null when unknown.</summary>
    System.Threading.Tasks.Task<Task?> FindAsync(TaskId id, CancellationToken cancellationToken = default);

    /// <summary>
    /// All tasks directed at an implant, oldest first -- the implant's task
    /// history across queued, dispatched, and completed states.
    /// </summary>
    System.Threading.Tasks.Task<IReadOnlyList<Task>> ListByImplantAsync(
        ImplantId implant,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// All tasks in an engagement, oldest first -- the engagement's task history.
    /// Scoped by engagement so cross-engagement access never reaches this with
    /// another engagement's id.
    /// </summary>
    System.Threading.Tasks.Task<IReadOnlyList<Task>> ListByEngagementAsync(
        EngagementId engagement,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// One page of the engagement's task history (architecture.md Sec 10.3): the
    /// newest <paramref name="limit"/> tasks, or the next older page when
    /// <paramref name="cursor"/> carries the previous page's
    /// <see cref="TaskPage.NextCursor"/>. A long engagement no longer grows the
    /// listing endpoint without bound -- the operator UI walks pages.
    /// </summary>
    System.Threading.Tasks.Task<TaskPage> ListByEngagementPageAsync(
        EngagementId engagement,
        int limit,
        string? cursor,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// One page of an implant's task history, newest window first, with the same
    /// cursor semantics as <see cref="ListByEngagementPageAsync"/>.
    /// </summary>
    System.Threading.Tasks.Task<TaskPage> ListByImplantPageAsync(
        ImplantId implant,
        int limit,
        string? cursor,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The next not-yet-dispatched task for an implant, oldest first (FIFO by
    /// enqueue time), or null when none is queued. A peek: the caller (task
    /// issuance gating, tests) reads without changing state.
    /// </summary>
    System.Threading.Tasks.Task<Task?> NextPendingAsync(ImplantId implant, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically claims the next queued task for an implant: marks it
    /// Dispatched at <paramref name="at"/> and persists the transition before
    /// returning it, or returns null when nothing is queued. Concurrent claims
    /// for the same implant never hand out the same task -- the beacon writer
    /// drains through this, so a reconnect overlap cannot double-dispatch
    /// (architecture.md Sec 10.3).
    ///
    /// <paramref name="exclude"/> names tasks the claim must pass over --
    /// the poll carriers' skip set, so a task the carrier just requeued for
    /// a capable transport does not block the tasks behind it (a strict
    /// head-of-line claim would wedge a poll-only implant's queue on one
    /// oversized or channel-bound task forever).
    /// </summary>
    System.Threading.Tasks.Task<Task?> ClaimNextPendingAsync(
        ImplantId implant,
        DateTimeOffset at,
        IReadOnlySet<TaskId>? exclude = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The fronting claim (architecture.md Sec 5.2, the Pivot class):
    /// atomically claims the oldest queued task across a set of implant
    /// targets -- a fronting parent and the Pivot children its stream
    /// executes for -- with the same claim-once guarantee
    /// <see cref="ClaimNextPendingAsync"/> gives one implant. FIFO across the
    /// whole set by enqueue order, so a task queued for the parent and one
    /// queued for a fronted child dispatch in the order they were issued.
    /// Null when no target holds a queued task. <paramref name="exclude"/>
    /// carries the same skip semantics the single-implant claim documents.
    /// </summary>
    System.Threading.Tasks.Task<Task?> ClaimNextPendingForAsync(
        IReadOnlyCollection<ImplantId> implants,
        DateTimeOffset at,
        IReadOnlySet<TaskId>? exclude = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically retracts a queued task (architecture.md Sec 10.3): marks it
    /// Cancelled at <paramref name="at"/> and persists the transition, with the
    /// same claim-once serialization <see cref="ClaimNextPendingAsync"/> gives a
    /// dispatch -- a cancel racing a claim resolves one way, never both. Returns
    /// the task as it stands after the attempt: Cancelled on success, the
    /// untouched task when it is no longer queued (a dispatch or a completion
    /// already won the race), null when the task is unknown. The caller refuses
    /// anything that did not come back Cancelled.
    /// </summary>
    System.Threading.Tasks.Task<Task?> CancelAsync(
        TaskId id,
        DateTimeOffset at,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically completes a dispatched task (architecture.md Sec 10.3):
    /// records the implant's result and marks it Completed at
    /// <paramref name="at"/>, with the same one-way serialization
    /// <see cref="ClaimNextPendingAsync"/> gives a dispatch -- so a duplicate
    /// result loses the race and the first one wins. Returns the completed
    /// task when this call performed the transition, null when the task is
    /// unknown or no longer Dispatched (a prior result already completed it).
    /// The receive-ack arm makes retransmitted results a normal occurrence
    /// rather than an error -- an implant resends a cached result after a
    /// stream death, and either the original or the resend may land first,
    /// never both.
    /// </summary>
    System.Threading.Tasks.Task<Task?> CompleteAsync(
        TaskId id,
        string output,
        TaskOutcome outcome,
        DateTimeOffset at,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically reserves and persists the next per-implant replay nonce
    /// (architecture.md Sec 9 -- tasking replay nonces): returns 1 the first
    /// time and monotonically increases after, so a negotiating implant never
    /// sees the same nonce twice and a captured frame replayed after a
    /// reconnect still falls at or below the floor it already accepted. The
    /// floor lives behind the repository so a durable store keeps it across a
    /// restart: the in-memory adapter's counter is per-process (which the
    /// signing posture tolerates -- the task queue itself is equally
    /// per-process there), while the durable adapter persists the count.
    /// </summary>
    System.Threading.Tasks.Task<ulong> NextNonceAsync(
        ImplantId implant,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// How many tasks the deployment holds per lifecycle status. The port's
    /// one deployment-wide read: pure counts, never task data, never a
    /// per-engagement breakdown -- the built-in diagnostics face's queue-depth
    /// number (architecture.md Sec 15.3, ADR-008), which is a deployment
    /// aggregate by design. Every other query here stays rooted in an implant
    /// or engagement; this one crosses them only in the count.
    /// </summary>
    System.Threading.Tasks.Task<IReadOnlyDictionary<TaskStatus, long>> CountByStatusAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Every task still Dispatched that was dispatched at or before
    /// <paramref name="cutoff"/> -- the expiry sweep's candidate set
    /// (architecture.md Sec 10.3). The caller decides which candidates are
    /// expirable (a channel task legitimately runs for hours); the read is a
    /// snapshot and the completion races a late result by the same
    /// first-wins rule <see cref="CompleteAsync"/> enforces.
    /// </summary>
    System.Threading.Tasks.Task<IReadOnlyList<Task>> ListDispatchedBeforeAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default);
}
