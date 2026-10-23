namespace Rod.CoreState.Recon;

/// <summary>
/// In-memory <see cref="IReconAssetStore"/>: the process-lifetime default
/// behind the port, swapped for the Postgres twin at the composition root
/// when the connection string is set.
/// </summary>
public sealed class InMemoryReconAssetStore : IReconAssetStore
{
    private readonly object _lock = new();
    private readonly Dictionary<ReconAssetId, ReconAsset> _assets = new();

    public Task<bool> AddAsync(ReconAsset asset, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (_assets.Values.Any(a =>
                    a.EngagementId == asset.EngagementId
                    && a.Kind == asset.Kind
                    && string.Equals(a.Value, asset.Value, StringComparison.Ordinal)))
            {
                return Task.FromResult(false);
            }

            _assets[asset.Id] = asset;
            return Task.FromResult(true);
        }
    }

    public Task<ReconAsset?> FindAsync(
        ReconAssetId id,
        EngagementId engagement,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            return Task.FromResult(
                _assets.TryGetValue(id, out var asset) && asset.EngagementId == engagement
                    ? asset
                    : null);
        }
    }

    public Task<ReconAsset?> FindAsync(
        EngagementId engagement,
        ReconAssetKind kind,
        string value,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            return Task.FromResult(
                _assets.Values.SingleOrDefault(a =>
                    a.EngagementId == engagement
                    && a.Kind == kind
                    && string.Equals(a.Value, value, StringComparison.Ordinal)));
        }
    }

    public Task<IReadOnlyList<ReconAsset>> ListByEngagementAsync(
        EngagementId engagement,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            return Task.FromResult<IReadOnlyList<ReconAsset>>(
                _assets.Values
                    .Where(a => a.EngagementId == engagement)
                    .OrderBy(a => a.CreatedAt)
                    .ToList());
        }
    }

    public Task<bool> RemoveAsync(
        ReconAssetId id,
        EngagementId engagement,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            return Task.FromResult(
                _assets.TryGetValue(id, out var asset)
                && asset.EngagementId == engagement
                && _assets.Remove(id));
        }
    }
}
