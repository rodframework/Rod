using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Tasks;
// Pin Task to the BCL type (the TaskClaimConcurrencyTests convention): this
// file is async-heavy, so the domain entity is reached by its full name.
using Task = System.Threading.Tasks.Task;

namespace Rod.CoreState.Tests;

/// <summary>
/// The deployment-wide status counts (<see cref="ITaskRepository.CountByStatusAsync"/>):
/// the diagnostics face's queue-depth number is a pure aggregate across every
/// engagement (architecture.md Sec 15.3, ADR-008) -- tasks from two engagements
/// land in one dictionary, and no engagement id or task data rides along.
/// </summary>
public class TaskCountByStatusTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch;

    private static Rod.CoreState.Tasks.Task Issue(
        EngagementId engagement,
        ImplantId implant,
        DateTimeOffset at)
        => Rod.CoreState.Tasks.Task.Create(
            TaskId.New(), engagement, implant, OperatorId.New(), "shell.exec", arguments: string.Empty, at);

    [Fact]
    public async Task Counts_AggregateAcrossEngagements_AndCarryNoEntityData()
    {
        var tasks = new InMemoryTaskRepository();
        var left = EngagementId.New();
        var right = EngagementId.New();
        var leftImplant = ImplantId.New();
        var rightImplant = ImplantId.New();

        // Two queued: one per engagement -- the queue-depth number mixes them.
        var queuedLeft = Issue(left, leftImplant, Now);
        var queuedRight = Issue(right, rightImplant, Now);
        await tasks.SaveAsync(queuedLeft);
        await tasks.SaveAsync(queuedRight);

        // One dispatched, one completed, one cancelled. Each gets its own
        // implant so the FIFO claim (it takes the oldest queued task for the
        // implant, not a named one) is deterministic against the queued pair.
        var worker = ImplantId.New();
        var dispatched = Issue(left, worker, Now);
        await tasks.SaveAsync(dispatched);
        await tasks.ClaimNextPendingAsync(worker, Now);

        var finisher = ImplantId.New();
        var completed = Issue(left, finisher, Now);
        await tasks.SaveAsync(completed);
        await tasks.ClaimNextPendingAsync(finisher, Now);
        await tasks.CompleteAsync(completed.Id, "done", TaskOutcome.Succeeded, Now);

        var cancelled = Issue(left, worker, Now);
        await tasks.SaveAsync(cancelled);
        await tasks.CancelAsync(cancelled.Id, Now);

        var counts = await tasks.CountByStatusAsync();

        Assert.Equal(2, counts[Rod.CoreState.Tasks.TaskStatus.Queued]);
        Assert.Equal(1, counts[Rod.CoreState.Tasks.TaskStatus.Dispatched]);
        Assert.Equal(1, counts[Rod.CoreState.Tasks.TaskStatus.Completed]);
        Assert.Equal(1, counts[Rod.CoreState.Tasks.TaskStatus.Cancelled]);
    }

    [Fact]
    public async Task Counts_OnAnEmptyQueue_ReportNothingQueued()
    {
        var tasks = new InMemoryTaskRepository();

        var counts = await tasks.CountByStatusAsync();

        // Only statuses with at least one task appear; the reader zero-fills
        // the rest, so an empty queue is an empty dictionary.
        Assert.Empty(counts);
    }
}
