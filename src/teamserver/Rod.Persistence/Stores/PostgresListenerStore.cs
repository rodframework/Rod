using Microsoft.EntityFrameworkCore;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Listeners;
using Rod.Persistence.Configurations;

namespace Rod.Persistence.Stores;

/// <summary>
/// PostgreSQL-backed <see cref="IListenerStore"/> (ADR 0003): engagement-scoped
/// listener definitions survive a teamserver restart, so the rebinding pass
/// finds what the operator built. Plain rows, no concurrency hazard -- the
/// listener manager serializes creates and deletes per process, and a second
/// teamserver against the same database is not a supported shape.
/// </summary>
internal sealed class PostgresListenerStore : IListenerStore
{
    private readonly IDbContextFactory<RodPersistenceDbContext> _factory;

    public PostgresListenerStore(IDbContextFactory<RodPersistenceDbContext> factory)
        => _factory = factory;

    public async Task SaveAsync(ListenerDefinition definition, CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = await db.ListenerDefinitions.FindAsync(new object[] { definition.Id }, cancellationToken);
        if (stored is null)
        {
            db.ListenerDefinitions.Add(FromDefinition(definition));
        }
        else
        {
            stored.Name = definition.Name;
            stored.Transport = definition.Transport;
            stored.BindAddress = definition.BindAddress;
            stored.PublicEndpoint = definition.PublicEndpoint;
            stored.RepointedAt = definition.RepointedAt;
            stored.TrustPosture = definition.TrustPosture;
            stored.FrontsJson = ListenerFrontsJson.Of(definition.Fronts);
            stored.PackageName = definition.PackageName;
            stored.PackageVersion = definition.PackageVersion;
            stored.SealTier = definition.SealTier;
            stored.ParamsJson = definition.ParamsJson;
        }
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<ListenerDefinition?> FindAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = await db.ListenerDefinitions.AsNoTracking()
            .FirstOrDefaultAsync(l => l.Id == id, cancellationToken);
        return stored is null ? null : ToDefinition(stored);
    }

    public async Task<IReadOnlyList<ListenerDefinition>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        var all = await db.ListenerDefinitions.AsNoTracking()
            .OrderBy(l => l.CreatedAt)
            .ToListAsync(cancellationToken);
        return all.Select(ToDefinition).ToArray();
    }

    public async Task<IReadOnlyList<ListenerDefinition>> ListByEngagementAsync(
        EngagementId engagementId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        var mine = await db.ListenerDefinitions.AsNoTracking()
            .Where(l => l.EngagementId == engagementId)
            .OrderBy(l => l.CreatedAt)
            .ToListAsync(cancellationToken);
        return mine.Select(ToDefinition).ToArray();
    }

    public async Task<bool> RemoveAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = await db.ListenerDefinitions.FindAsync(new object[] { id }, cancellationToken);
        if (stored is null)
            return false;
        db.ListenerDefinitions.Remove(stored);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static StoredListenerDefinition FromDefinition(ListenerDefinition definition)
        => new()
        {
            Id = definition.Id,
            EngagementId = definition.EngagementId,
            Name = definition.Name,
            Transport = definition.Transport,
            BindAddress = definition.BindAddress,
            PublicEndpoint = definition.PublicEndpoint,
            CreatedAt = definition.CreatedAt,
            RepointedAt = definition.RepointedAt,
            TrustPosture = definition.TrustPosture,
            FrontsJson = ListenerFrontsJson.Of(definition.Fronts),
            PackageName = definition.PackageName,
            PackageVersion = definition.PackageVersion,
            SealTier = definition.SealTier,
            ParamsJson = definition.ParamsJson,
        };

    private static ListenerDefinition ToDefinition(StoredListenerDefinition stored)
        => new(
            stored.Id,
            stored.EngagementId,
            stored.Name,
            stored.Transport,
            stored.BindAddress,
            stored.PublicEndpoint,
            stored.CreatedAt,
            stored.RepointedAt,
            // Rows predating the column read as the pinned default.
            stored.TrustPosture ?? "pinned",
            ListenerFrontsJson.Parse(stored.FrontsJson),
            stored.PackageName,
            stored.PackageVersion,
            stored.SealTier,
            stored.ParamsJson);
}
