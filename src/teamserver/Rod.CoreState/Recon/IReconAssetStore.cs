namespace Rod.CoreState.Recon;

/// <summary>
/// The durable home for recon assets (architecture.md Sec 15.4):
/// engagement-scoped target rows like campaigns and launchers, in-memory
/// by default and Postgres-backed when the connection string is set.
/// Reads list by engagement and resolve by id. Deletion is refused by the
/// referencing foreign key while a campaign target row still names the
/// asset; the endpoint pre-checks that (a friendly 409) and the durable
/// twin's constraint is the race's backstop.
/// </summary>
public interface IReconAssetStore
{
    /// <summary>
    /// Stores a new asset row. Returns false when the engagement already
    /// carries the (kind, value) identity -- the caller answers the
    /// duplicate, and the store's own pre-check plus the durable twin's
    /// unique index close the same race from both ends.
    /// </summary>
    Task<bool> AddAsync(ReconAsset asset, CancellationToken cancellationToken = default);

    /// <summary>The asset, or null when unknown or outside the
    /// engagement.</summary>
    Task<ReconAsset?> FindAsync(
        ReconAssetId id,
        EngagementId engagement,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The engagement's asset carrying the given identity, or null -- the
    /// duplicate check a recording route answers 409 with, against the
    /// same (engagement, kind, value) the store's unique index holds.
    /// </summary>
    Task<ReconAsset?> FindAsync(
        EngagementId engagement,
        ReconAssetKind kind,
        string value,
        CancellationToken cancellationToken = default);

    /// <summary>The engagement's assets, oldest first.</summary>
    Task<IReadOnlyList<ReconAsset>> ListByEngagementAsync(
        EngagementId engagement,
        CancellationToken cancellationToken = default);

    /// <summary>Removes the asset. Returns false when it was unknown or
    /// outside the engagement; a still-referenced asset surfaces as the
    /// constraint's own refusal.</summary>
    Task<bool> RemoveAsync(
        ReconAssetId id,
        EngagementId engagement,
        CancellationToken cancellationToken = default);
}
