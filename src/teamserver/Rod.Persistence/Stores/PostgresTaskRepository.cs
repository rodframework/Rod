using Microsoft.EntityFrameworkCore;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Tasks;
using Rod.Persistence.Configurations;
// The domain entity shares its name with System.Threading.Tasks.Task. Pin it
// here so the adapter's Task type wins; the BCL type is reached by its full
// name where the methods return it, exactly as the port does.
using Task = Rod.CoreState.Tasks.Task;

namespace Rod.Persistence.Stores;

/// <summary>
/// PostgreSQL-backed <see cref="ITaskRepository"/> (ADR 0003). Each call
/// creates a short-lived <see cref="RodPersistenceDbContext"/> from the factory,
/// performs its work, and disposes the context; the context is never held across
/// calls so the singleton adapter stays safe for concurrent use.
/// </summary>
/// <remarks>
/// FIFO ordering (the in-memory adapter's global enqueue sequence) is reproduced
/// by the <c>enqueue_seq</c> column on <c>tasks</c>, a Postgres IDENTITY column
/// whose value is generated exactly once at INSERT and never touched on the
/// UPDATE path a dispatch/completion re-save takes. Two concurrent enqueues get
/// distinct, increasing values from the database without the adapter managing a
/// counter. <see cref="NextPendingAsync"/> and the listing methods order by that
/// column, so per-implant dispatch drains in enqueue order and the engagement /
/// implant histories read in the same order across restarts.
/// </remarks>
internal sealed class PostgresTaskRepository : ITaskRepository
{
    private readonly IDbContextFactory<RodPersistenceDbContext> _factory;

    public PostgresTaskRepository(IDbContextFactory<RodPersistenceDbContext> factory)
        => _factory = factory;

    public async System.Threading.Tasks.Task SaveAsync(Task task, CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);

        // Insert-or-replace by id: a queued task is inserted (the IDENTITY column
        // assigns its enqueue sequence), and a dispatch/completion re-save updates
        // the lifecycle columns in place without touching enqueue_seq.
        var existing = await db.Tasks.FindAsync(new object?[] { task.Id }, cancellationToken);
        if (existing is null)
            db.Tasks.Add(task);
        else
            db.Entry(existing).CurrentValues.SetValues(task);

        await db.SaveChangesAsync(cancellationToken);
    }

    public async System.Threading.Tasks.Task<Task?> FindAsync(TaskId id, CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        return await db.Tasks.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id, cancellationToken);
    }

    public async System.Threading.Tasks.Task<IReadOnlyList<Task>> ListByImplantAsync(
        ImplantId implant,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        return await db.Tasks
            .AsNoTracking()
            .Where(t => t.ImplantId == implant)
            .OrderBy(t => EF.Property<long>(t, TaskConfiguration.EnqueueSequenceShadow))
            .ToArrayAsync(cancellationToken);
    }

    public async System.Threading.Tasks.Task<IReadOnlyList<Task>> ListByEngagementAsync(
        EngagementId engagement,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        return await db.Tasks
            .AsNoTracking()
            .Where(t => t.EngagementId == engagement)
            .OrderBy(t => EF.Property<long>(t, TaskConfiguration.EnqueueSequenceShadow))
            .ToArrayAsync(cancellationToken);
    }

    public async System.Threading.Tasks.Task<TaskPage> ListByEngagementPageAsync(
        EngagementId engagement,
        int limit,
        string? cursor,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        return await PageAsync(
            db.Tasks.AsNoTracking().Where(t => t.EngagementId == engagement),
            limit, cursor, cancellationToken);
    }

    public async System.Threading.Tasks.Task<TaskPage> ListByImplantPageAsync(
        ImplantId implant,
        int limit,
        string? cursor,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        return await PageAsync(
            db.Tasks.AsNoTracking().Where(t => t.ImplantId == implant),
            limit, cursor, cancellationToken);
    }

    // Keyset pagination over the enqueue sequence: the newest window first (a
    // null cursor), each next cursor reading strictly older rows. The LIMIT
    // fetches one extra row so "is there a next page" needs no second query.
    private static async System.Threading.Tasks.Task<TaskPage> PageAsync(
        IQueryable<Task> scoped,
        int limit,
        string? cursor,
        CancellationToken cancellationToken)
    {
        if (cursor is not null)
        {
            if (!TaskPageCursor.TryDecode(cursor, out var after))
                throw new ArgumentException("Cursor is not a valid task page cursor.", nameof(cursor));
            scoped = scoped.Where(t => EF.Property<long>(t, TaskConfiguration.EnqueueSequenceShadow) < after);
        }

        // Project the enqueue sequence alongside the entity: the shadow value
        // must be read inside the query -- EF.Property refuses to read it off an
        // already-materialized instance.
        var newestFirst = await scoped
            .OrderByDescending(t => EF.Property<long>(t, TaskConfiguration.EnqueueSequenceShadow))
            .Take(limit + 1)
            .Select(t => new
            {
                t,
                Seq = EF.Property<long>(t, TaskConfiguration.EnqueueSequenceShadow),
            })
            .ToArrayAsync(cancellationToken);

        var hasMore = newestFirst.Length > limit;
        var items = newestFirst.Take(limit).Select(x => x.t).ToArray();
        Array.Reverse(items); // Oldest first within the page, matching the full listing.
        var next = hasMore
            ? TaskPageCursor.Encode(newestFirst[limit - 1].Seq)
            : null;
        return new TaskPage(items, next);
    }

    public async System.Threading.Tasks.Task<Task?> NextPendingAsync(
        ImplantId implant,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        // The oldest still-queued task for the implant by enqueue sequence; the
        // beacon drains these one at a time on each contact.
        return await db.Tasks
            .AsNoTracking()
            .Where(t => t.ImplantId == implant && t.Status == Rod.CoreState.Tasks.TaskStatus.Queued)
            .OrderBy(t => EF.Property<long>(t, TaskConfiguration.EnqueueSequenceShadow))
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async System.Threading.Tasks.Task<Task?> ClaimNextPendingAsync(
        ImplantId implant,
        DateTimeOffset at,
        IReadOnlySet<TaskId>? exclude = null,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // FOR UPDATE SKIP LOCKED makes the claim atomic across concurrent
        // beacons: the subquery locks the oldest Queued row (or skips it when
        // another transaction already holds it), so two claims for one implant
        // can never select the same task. The outer query turns the lock into a
        // plain id; the entity is then loaded and transitioned inside the same
        // transaction so the Dispatched mark commits with the lock released
        // only after SaveChanges. The scalar column must alias AS "Value":
        // SqlQuery composes the raw SQL as a subquery selecting s."Value".
        // The skip set passes over rows the calling carrier just requeued;
        // an empty set compares true against <> ALL, so the plain claim
        // reads clean.
        var skip = exclude is null || exclude.Count == 0
            ? Array.Empty<Guid>()
            : exclude.Select(id => id.Value).ToArray();
        var claimedId = await db.Database.SqlQuery<Guid>($"""
            SELECT task_id AS "Value"
            FROM tasks
            WHERE task_id = (
                SELECT task_id
                FROM tasks
                WHERE implant_id = {implant.Value} AND status = {(int)Rod.CoreState.Tasks.TaskStatus.Queued}
                    AND task_id <> ALL({skip})
                ORDER BY enqueue_seq
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            """).FirstOrDefaultAsync(cancellationToken);

        if (claimedId == Guid.Empty)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        var task = await db.Tasks.FirstAsync(t => t.Id == new TaskId(claimedId), cancellationToken);
        task.MarkDispatched(at);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return task;
    }

    public async System.Threading.Tasks.Task<Task?> ClaimNextPendingForAsync(
        IReadOnlyCollection<ImplantId> implants,
        DateTimeOffset at,
        IReadOnlySet<TaskId>? exclude = null,
        CancellationToken cancellationToken = default)
    {
        if (implants.Count == 0)
            return null;

        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // The fronting claim (architecture.md Sec 5.2): the same locked
        // peek-and-mark as ClaimNextPendingAsync, widened across the fronting
        // set with an ANY over the target ids -- the oldest queued row any
        // target holds, so parent and fronted children dispatch in issue
        // order under the same claim-once guarantee. The skip set carries
        // the same semantics the single-implant claim documents.
        var targets = implants.Select(i => i.Value).ToArray();
        var skip = exclude is null || exclude.Count == 0
            ? Array.Empty<Guid>()
            : exclude.Select(id => id.Value).ToArray();
        var frontedId = await db.Database.SqlQuery<Guid>($"""
            SELECT task_id AS "Value"
            FROM tasks
            WHERE task_id = (
                SELECT task_id
                FROM tasks
                WHERE implant_id = ANY({targets}) AND status = {(int)Rod.CoreState.Tasks.TaskStatus.Queued}
                    AND task_id <> ALL({skip})
                ORDER BY enqueue_seq
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            """).FirstOrDefaultAsync(cancellationToken);

        if (frontedId == Guid.Empty)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        var fronted = await db.Tasks.FirstAsync(t => t.Id == new TaskId(frontedId), cancellationToken);
        fronted.MarkDispatched(at);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return fronted;
    }

    public async System.Threading.Tasks.Task<Task?> CancelAsync(
        TaskId id,
        DateTimeOffset at,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // The retraction takes the row lock the claim takes, but by task id and
        // without SKIP LOCKED: a cancel racing a dispatch claim serializes here
        // -- whichever commits first transitions the task, and the loser reads
        // the new status and stands down. A plain FOR UPDATE (wait, not skip) is
        // the correct posture: the cancel wants this exact row, not any other.
        var cancelledId = await db.Database.SqlQuery<Guid>($"""
            SELECT task_id AS "Value"
            FROM tasks
            WHERE task_id = {id.Value}
            FOR UPDATE
            """).FirstOrDefaultAsync(cancellationToken);

        if (cancelledId == Guid.Empty)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        var task = await db.Tasks.FirstAsync(t => t.Id == id, cancellationToken);
        if (task.Status == Rod.CoreState.Tasks.TaskStatus.Queued)
        {
            task.Cancel(at);
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return task;
        }

        // Not queued -- the task already left the queue (dispatched, completed,
        // or already cancelled). Hand it back untouched so the caller can refuse
        // with the state it is in.
        await transaction.RollbackAsync(cancellationToken);
        return task;
    }

    public async System.Threading.Tasks.Task<Task?> CompleteAsync(
        TaskId id,
        string output,
        TaskOutcome outcome,
        DateTimeOffset at,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // The completion takes the same row lock the retraction takes, for the
        // same reason: a duplicate result racing the original serializes here,
        // and the loser reads the Completed status and stands down -- the first
        // result wins (architecture.md Sec 10.3). The entity's own Complete
        // refuses anything but Dispatched, so the transition itself carries the
        // one-way guarantee the lock serializes.
        var completedId = await db.Database.SqlQuery<Guid>($"""
            SELECT task_id AS "Value"
            FROM tasks
            WHERE task_id = {id.Value}
            FOR UPDATE
            """).FirstOrDefaultAsync(cancellationToken);

        if (completedId == Guid.Empty)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        var task = await db.Tasks.FirstAsync(t => t.Id == id, cancellationToken);
        if (task.Status != Rod.CoreState.Tasks.TaskStatus.Dispatched)
        {
            // A prior result already completed it (or it never left the queue).
            // Null, not the untouched task: the caller treats a lost race as a
            // duplicate to drop, and has no use for the state it lost to.
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        task.Complete(output, outcome, at);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return task;
    }

    public async System.Threading.Tasks.Task<ulong> NextNonceAsync(
        ImplantId implant,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);

        // The floor is durable and the reservation atomic: the upsert inserts
        // the first row (floor 1) or increments the existing one, and RETURNING
        // hands back the reserved value in the same statement -- concurrent
        // beacons for one implant never reserve the same nonce, and a restarted
        // teamserver reads the persisted floor instead of restarting the count
        // (architecture.md Sec 9). Raw ADO on the context's connection because
        // the reservation is an INSERT whose RETURNING value must come back
        // from the same statement -- nothing in EF's composable SqlQuery shape
        // can wrap that.
        var connection = db.Database.GetDbConnection();
        await db.Database.OpenConnectionAsync(cancellationToken);
        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO implant_task_nonces (implant_id, nonce_floor)
                VALUES (@implant, 1)
                ON CONFLICT (implant_id) DO UPDATE SET nonce_floor = implant_task_nonces.nonce_floor + 1
                RETURNING nonce_floor
                """;
            var parameter = command.CreateParameter();
            parameter.ParameterName = "@implant";
            parameter.Value = implant.Value;
            command.Parameters.Add(parameter);

            var reserved = await command.ExecuteScalarAsync(cancellationToken);
            return (ulong)(long)reserved!;
        }
        finally
        {
            db.Database.CloseConnection();
        }
    }

    public async System.Threading.Tasks.Task<IReadOnlyDictionary<Rod.CoreState.Tasks.TaskStatus, long>> CountByStatusAsync(
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);

        // The deployment aggregate the diagnostics face reads (ADR-008): one
        // grouped count over the whole table, no row data, no engagement
        // dimension. A single aggregate query per diagnostics read.
        var counts = await db.Tasks
            .AsNoTracking()
            .GroupBy(t => t.Status)
            .Select(g => new { Status = g.Key, Count = g.LongCount() })
            .ToArrayAsync(cancellationToken);
        return counts.ToDictionary(c => c.Status, c => c.Count);
    }

    public async System.Threading.Tasks.Task<IReadOnlyList<Task>> ListDispatchedBeforeAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);

        // The expiry sweep's candidate set: dispatched rows old enough to
        // consider. The status filter rides the enqueue-sequence index's
        // implant columns only partially -- the sweep runs rarely, so a
        // filtered scan of the dispatched minority is the right shape.
        return await db.Tasks
            .AsNoTracking()
            .Where(t => t.Status == Rod.CoreState.Tasks.TaskStatus.Dispatched
                && t.DispatchedAt <= cutoff)
            .OrderBy(t => t.DispatchedAt)
            .ToArrayAsync(cancellationToken);
    }
}

