using System.Collections.Concurrent;
using System.Threading;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
// The domain entity shares its name with System.Threading.Tasks.Task. Pin it
// here so the repository's own Task type wins; the BCL type is reached by its
// full name where the methods below return it.
using Task = Rod.CoreState.Tasks.Task;

namespace Rod.CoreState.Tasks;

/// <summary>
/// In-memory <see cref="ITaskRepository"/> by default.
/// -- no Postgres yet. Tasks live in a process-local map keyed by task id;
/// per-implant dispatch drains the queued tasks in FIFO enqueue order, and the
/// same map backs the implant- and engagement-scoped history. Implant- and
/// engagement-scoped queries filter that map, so a caller scoped to one
/// engagement never sees another's tasks. State is lost on restart; the port
/// keeps callers agnostic to that.
/// </summary>
public sealed class InMemoryTaskRepository : ITaskRepository
{
    private readonly ConcurrentDictionary<TaskId, Task> _tasks = new();

    // A single global enqueue sequence so history ordering is deterministic
    // regardless of which implant or engagement a task belongs to. Restricting
    // this order to one implant is that implant's enqueue order, so per-implant
    // dispatch stays FIFO; an explicit per-implant counter would tie across
    // implants and leave history order nondeterministic.
    private long _nextSequence = 1;
    private readonly ConcurrentDictionary<TaskId, long> _order = new();

    public System.Threading.Tasks.Task SaveAsync(Task task, CancellationToken cancellationToken = default)
    {
        // Record the enqueue order only the first time a task is seen: re-saves
        // (dispatch, completion) must not move a task to the back of its queue.
        if (_tasks.TryAdd(task.Id, task))
        {
            _order[task.Id] = Interlocked.Increment(ref _nextSequence);
        }
        else
        {
            _tasks[task.Id] = task;
        }
        return System.Threading.Tasks.Task.CompletedTask;
    }

    public System.Threading.Tasks.Task<Task?> FindAsync(TaskId id, CancellationToken cancellationToken = default)
        => System.Threading.Tasks.Task.FromResult(_tasks.TryGetValue(id, out var task) ? task : null);

    public System.Threading.Tasks.Task<IReadOnlyList<Task>> ListByImplantAsync(
        ImplantId implant,
        CancellationToken cancellationToken = default)
    {
        var matches = _tasks.Values
            .Where(t => t.ImplantId == implant)
            .OrderBy(t => _order.GetValueOrDefault(t.Id))
            .ToArray();
        return System.Threading.Tasks.Task.FromResult<IReadOnlyList<Task>>(matches);
    }

    public System.Threading.Tasks.Task<IReadOnlyList<Task>> ListByEngagementAsync(
        EngagementId engagement,
        CancellationToken cancellationToken = default)
    {
        var matches = _tasks.Values
            .Where(t => t.EngagementId == engagement)
            .OrderBy(t => _order.GetValueOrDefault(t.Id))
            .ToArray();
        return System.Threading.Tasks.Task.FromResult<IReadOnlyList<Task>>(matches);
    }

    public System.Threading.Tasks.Task<TaskPage> ListByEngagementPageAsync(
        EngagementId engagement,
        int limit,
        string? cursor,
        CancellationToken cancellationToken = default)
    {
        var ordered = _tasks.Values
            .Where(t => t.EngagementId == engagement)
            .OrderBy(t => _order.GetValueOrDefault(t.Id))
            .ToArray();
        return System.Threading.Tasks.Task.FromResult(Page(ordered, limit, cursor));
    }

    public System.Threading.Tasks.Task<TaskPage> ListByImplantPageAsync(
        ImplantId implant,
        int limit,
        string? cursor,
        CancellationToken cancellationToken = default)
    {
        var ordered = _tasks.Values
            .Where(t => t.ImplantId == implant)
            .OrderBy(t => _order.GetValueOrDefault(t.Id))
            .ToArray();
        return System.Threading.Tasks.Task.FromResult(Page(ordered, limit, cursor));
    }

    // Pages an enqueue-ordered array from the newest end: a null cursor starts
    // at the newest task, a cursor skips everything at-or-newer than its encoded
    // sequence. The returned page reads oldest first and carries the next cursor
    // (the oldest included task's sequence) only when older tasks remain.
    private TaskPage Page(Task[] orderedAscending, int limit, string? cursor)
    {
        long? after = null;
        if (cursor is not null)
        {
            if (!TaskPageCursor.TryDecode(cursor, out var decoded))
                throw new ArgumentException("Cursor is not a valid task page cursor.", nameof(cursor));
            after = decoded;
        }

        var taken = new List<Task>(limit);
        var hasOlder = false;
        for (var i = orderedAscending.Length - 1; i >= 0; i--)
        {
            var seq = _order.GetValueOrDefault(orderedAscending[i].Id);
            if (after is { } a && seq >= a)
                continue; // Already on an earlier (newer) page.

            taken.Add(orderedAscending[i]);
            if (taken.Count == limit)
            {
                hasOlder = i > 0;
                break;
            }
        }

        taken.Reverse(); // Oldest first within the page, matching the full listing.
        var next = hasOlder
            ? TaskPageCursor.Encode(_order.GetValueOrDefault(taken[0].Id))
            : null;
        return new TaskPage(taken, next);
    }

    public System.Threading.Tasks.Task<Task?> NextPendingAsync(ImplantId implant, CancellationToken cancellationToken = default)
    {
        // Oldest still-queued task for the implant by global enqueue order; the
        // beacon drains these one at a time on each contact.
        var next = _tasks.Values
            .Where(t => t.ImplantId == implant && t.Status == TaskStatus.Queued)
            .OrderBy(t => _order.GetValueOrDefault(t.Id))
            .FirstOrDefault();
        return System.Threading.Tasks.Task.FromResult(next);
    }

    public System.Threading.Tasks.Task<Task?> ClaimNextPendingAsync(
        ImplantId implant,
        DateTimeOffset at,
        IReadOnlySet<TaskId>? exclude = null,
        CancellationToken cancellationToken = default)
    {
        // The peek-and-mark transition runs under one lock so two concurrent
        // claims for the same implant cannot observe the same Queued task; the
        // second claim sees the first's Dispatched state and moves on.
        lock (_claimLock)
        {
            var next = _tasks.Values
                .Where(t => t.ImplantId == implant && t.Status == TaskStatus.Queued
                    && (exclude is null || !exclude.Contains(t.Id)))
                .OrderBy(t => _order.GetValueOrDefault(t.Id))
                .FirstOrDefault();
            return System.Threading.Tasks.Task.FromResult(Claimed(next, at));
        }
    }

    public System.Threading.Tasks.Task<Task?> ClaimNextPendingForAsync(
        IReadOnlyCollection<ImplantId> implants,
        DateTimeOffset at,
        IReadOnlySet<TaskId>? exclude = null,
        CancellationToken cancellationToken = default)
    {
        // The fronting claim (architecture.md Sec 5.2): the same locked
        // peek-and-mark, widened across the fronting set -- the oldest queued
        // task any target holds, so parent and fronted children dispatch in
        // issue order under the same claim-once guarantee.
        lock (_claimLock)
        {
            var next = _tasks.Values
                .Where(t => t.Status == TaskStatus.Queued && implants.Contains(t.ImplantId)
                    && (exclude is null || !exclude.Contains(t.Id)))
                .OrderBy(t => _order.GetValueOrDefault(t.Id))
                .FirstOrDefault();
            return System.Threading.Tasks.Task.FromResult(Claimed(next, at));
        }
    }

    // Marks the claimed task Dispatched and re-persists it, or passes a null
    // claim through. Inside the claim lock.
    private Task? Claimed(Task? next, DateTimeOffset at)
    {
        if (next is null)
            return null;

        next.MarkDispatched(at);
        _tasks[next.Id] = next;
        return next;
    }

    public System.Threading.Tasks.Task<Task?> CancelAsync(
        TaskId id,
        DateTimeOffset at,
        CancellationToken cancellationToken = default)
    {
        // The retraction runs under the claim lock so a cancel racing a dispatch
        // claim resolves one way: whichever enters first transitions the task,
        // and the loser sees the new status and stands down (a cancelled task is
        // never selected by a claim; a dispatched task is not cancelled here).
        lock (_claimLock)
        {
            if (!_tasks.TryGetValue(id, out var task))
                return System.Threading.Tasks.Task.FromResult<Task?>(null);

            if (task.Status == TaskStatus.Queued)
            {
                task.Cancel(at);
                _tasks[id] = task;
            }

            return System.Threading.Tasks.Task.FromResult<Task?>(task);
        }
    }

    public System.Threading.Tasks.Task<Task?> CompleteAsync(
        TaskId id,
        string output,
        TaskOutcome outcome,
        DateTimeOffset at,
        CancellationToken cancellationToken = default)
    {
        // The completion runs under the claim lock for the same one-way
        // serialization the retraction gets: a duplicate result racing the
        // original sees the Completed status and loses, so the first result
        // wins (architecture.md Sec 10.3 -- the receive-ack arm's
        // retransmission tolerance).
        lock (_claimLock)
        {
            if (!_tasks.TryGetValue(id, out var task) || task.Status != TaskStatus.Dispatched)
                return System.Threading.Tasks.Task.FromResult<Task?>(null);

            task.Complete(output, outcome, at);
            _tasks[id] = task;
            return System.Threading.Tasks.Task.FromResult<Task?>(task);
        }
    }

    // The per-implant replay-nonce counters (architecture.md Sec 9 -- tasking
    // replay nonces). Monotonic for the implant's life in this process, across
    // sessions and transports. Per-process by design here: the in-memory
    // adapters lose the task queue on restart too, and the signing posture
    // tolerates it -- the durable adapter keeps the floor across a restart.
    private readonly ConcurrentDictionary<ImplantId, ulong> _nonces = new();

    public System.Threading.Tasks.Task<ulong> NextNonceAsync(
        ImplantId implant,
        CancellationToken cancellationToken = default)
        => System.Threading.Tasks.Task.FromResult(
            _nonces.AddOrUpdate(implant, 1, (_, last) => last + 1));

    public System.Threading.Tasks.Task<IReadOnlyDictionary<TaskStatus, long>> CountByStatusAsync(
        CancellationToken cancellationToken = default)
        => System.Threading.Tasks.Task.FromResult<IReadOnlyDictionary<TaskStatus, long>>(
            _tasks.Values
                .GroupBy(t => t.Status)
                .ToDictionary(g => g.Key, g => (long)g.Count()));

    public System.Threading.Tasks.Task<IReadOnlyList<Task>> ListDispatchedBeforeAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default)
        => System.Threading.Tasks.Task.FromResult<IReadOnlyList<Task>>(
            _tasks.Values
                .Where(t => t.Status == TaskStatus.Dispatched && t.DispatchedAt <= cutoff)
                .OrderBy(t => t.DispatchedAt)
                .ToArray());

    private readonly Lock _claimLock = new();
}
