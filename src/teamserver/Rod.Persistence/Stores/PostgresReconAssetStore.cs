using Microsoft.EntityFrameworkCore;
using Rod.CoreState;
using Rod.CoreState.Recon;
using Rod.Persistence.Configurations;

namespace Rod.Persistence.Stores;

/// <summary>
/// Postgres-backed <see cref="IReconAssetStore"/>: one row per asset in
/// <c>recon_assets</c>, the durable twin of the in-memory default. The
/// (engagement, kind, value) unique constraint is the duplicate backstop
/// -- the endpoint's pre-check names the existing row, the constraint
/// catches the race. A delete that still has campaign recipients
/// referencing the asset surfaces as the foreign key's own refusal
/// (rethrown for the endpoint to answer 409).
/// </summary>
public sealed class PostgresReconAssetStore : IReconAssetStore
{
    private readonly IDbContextFactory<RodPersistenceDbContext> _factory;

    public PostgresReconAssetStore(IDbContextFactory<RodPersistenceDbContext> factory)
    {
        _factory = factory;
    }

    public async Task<bool> AddAsync(ReconAsset asset, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        context.ReconAssets.Add(StoredReconAsset.From(asset));
        try
        {
            await context.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            // The (engagement, kind, value) unique index refused the row:
            // the identity a concurrent recording raced past the caller's
            // pre-check. Reported, not rethrown -- the endpoint answers it.
            return false;
        }
    }

    private static bool IsUniqueViolation(DbUpdateException ex)
        => ex.InnerException is Npgsql.PostgresException { SqlState: Npgsql.PostgresErrorCodes.UniqueViolation };

    public async Task<ReconAsset?> FindAsync(
        ReconAssetId id,
        EngagementId engagement,
        CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = await context.ReconAssets
            .SingleOrDefaultAsync(
                a => a.Id == id && a.EngagementId == engagement,
                cancellationToken);
        return stored?.ToDomain();
    }

    public async Task<ReconAsset?> FindAsync(
        EngagementId engagement,
        ReconAssetKind kind,
        string value,
        CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = await context.ReconAssets
            .SingleOrDefaultAsync(
                a => a.EngagementId == engagement
                    && a.Kind == (int)kind
                    && a.Value == value,
                cancellationToken);
        return stored?.ToDomain();
    }

    public async Task<IReadOnlyList<ReconAsset>> ListByEngagementAsync(
        EngagementId engagement,
        CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = await context.ReconAssets
            .Where(a => a.EngagementId == engagement)
            .OrderBy(a => a.CreatedAt)
            .ToArrayAsync(cancellationToken);
        return stored.Select(a => a.ToDomain()).ToArray();
    }

    public async Task<bool> RemoveAsync(
        ReconAssetId id,
        EngagementId engagement,
        CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = new StoredReconAsset { Id = id, EngagementId = engagement };
        context.ReconAssets.Remove(stored);
        // A delete the composite foreign key refuses (a campaign recipient
        // still references the asset) surfaces as its own exception; the
        // endpoint's pre-check answers the common case long before here.
        return await context.SaveChangesAsync(cancellationToken) > 0;
    }
}
