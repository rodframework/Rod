using Microsoft.EntityFrameworkCore;
using Rod.CoreState;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Deployment;
using Rod.Persistence.Configurations;

namespace Rod.Persistence.Stores;

/// <summary>
/// Durable <see cref="ICampaignStore"/> over PostgreSQL: campaigns and
/// their recipients as EF rows behind the context factory, every mutation
/// a conditional <c>ExecuteUpdate</c> whose WHERE clause carries the same
/// guards the entity's transition methods hold (the deploy-token store's
/// redeem pattern) -- Postgres row locking keeps concurrent engine arcs
/// and public-edge evidence stamps from racing, without the store holding
/// any lock of its own.
/// </summary>
internal sealed class PostgresCampaignStore : ICampaignStore
{
    private readonly IDbContextFactory<RodPersistenceDbContext> _factory;

    public PostgresCampaignStore(IDbContextFactory<RodPersistenceDbContext> factory)
    {
        _factory = factory;
    }

    public async Task SaveAsync(Campaign campaign, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var existing = await context.Campaigns
            .Include(c => c.Recipients)
            .FirstOrDefaultAsync(c => c.Id == campaign.Id, cancellationToken);
        if (existing is null)
        {
            context.Campaigns.Add(StoredCampaign.From(campaign));
        }
        else
        {
            // The aggregate is written whole only at creation; this replace
            // path exists so the port stays an upsert. Live mutations ride
            // the targeted operations below. Delete-and-reinsert rather
            // than SetValues: the row carries the recipient collection as
            // a navigation, and a wholesale replace is easier to see
            // correct than a partial copy.
            context.Campaigns.Remove(existing);
            context.Campaigns.Add(StoredCampaign.From(campaign));
        }
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<Campaign?> FindAsync(CampaignId id, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = await context.Campaigns.AsNoTracking()
            .Include(c => c.Recipients)
            .FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        return stored?.ToDomain();
    }

    public async Task<Campaign?> FindAsync(CampaignId id, EngagementId engagementId, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = await context.Campaigns.AsNoTracking()
            .Include(c => c.Recipients)
            .FirstOrDefaultAsync(c => c.Id == id && c.EngagementId == engagementId, cancellationToken);
        return stored?.ToDomain();
    }

    public async Task<IReadOnlyList<Campaign>> ListByEngagementAsync(EngagementId engagementId, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = await context.Campaigns.AsNoTracking()
            .Include(c => c.Recipients)
            .Where(c => c.EngagementId == engagementId)
            .OrderByDescending(c => c.CreatedAt)
            .ToArrayAsync(cancellationToken);
        return stored.Select(c => c.ToDomain()).ToArray();
    }

    public async Task<IReadOnlyList<Campaign>> ListLaunchedAsync(CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var stored = await context.Campaigns.AsNoTracking()
            .Include(c => c.Recipients)
            .Where(c => c.State == (int)CampaignState.Launched)
            .ToArrayAsync(cancellationToken);
        return stored.Select(c => c.ToDomain()).ToArray();
    }

    public async Task<CampaignLure?> FindByLureAsync(Guid lureId, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var row = await context.CampaignRecipients.AsNoTracking()
            .Include(r => r.Campaign)
            .FirstOrDefaultAsync(r => r.LureId == lureId, cancellationToken);
        return row is null ? null : ToLure(row);
    }

    public async Task<CampaignAttribution?> FindByEnrollTokenAsync(DeployTokenId tokenId, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        var row = await context.CampaignRecipients.AsNoTracking()
            .Include(r => r.Campaign)
            .FirstOrDefaultAsync(r => r.EnrollTokenId == tokenId.Value, cancellationToken);
        return row is null
            ? null
            : new CampaignAttribution(
                row.CampaignId,
                row.Id,
                row.Campaign!.Name,
                row.Email);
    }

    public async Task<bool> LaunchAsync(CampaignId id, EngagementId engagementId, DateTimeOffset at, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        return await context.Campaigns
            .Where(c => c.Id == id && c.EngagementId == engagementId && c.State == (int)CampaignState.Draft)
            .ExecuteUpdateAsync(
                s => s.SetProperty(c => c.State, (int)CampaignState.Launched)
                    .SetProperty(c => c.LaunchedAt, at),
                cancellationToken) > 0;
    }

    public async Task<bool> RevokeAsync(CampaignId id, EngagementId engagementId, DateTimeOffset at, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        return await context.Campaigns
            .Where(c => c.Id == id && c.EngagementId == engagementId && c.State != (int)CampaignState.Revoked)
            .ExecuteUpdateAsync(
                s => s.SetProperty(c => c.State, (int)CampaignState.Revoked)
                    .SetProperty(c => c.RevokedAt, at),
                cancellationToken) > 0;
    }

    public async Task<bool> NoteBuildingAsync(CampaignId campaign, CampaignRecipientId recipient, DeployTokenId enrollToken, Guid jobId, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        return await context.CampaignRecipients
            .Where(r => r.Id == recipient && r.CampaignId == campaign
                && (r.Status == (int)CampaignRecipientStatus.Pending || r.Status == (int)CampaignRecipientStatus.Building))
            .ExecuteUpdateAsync(
                s => s.SetProperty(r => r.Status, (int)CampaignRecipientStatus.Building)
                    .SetProperty(r => r.EnrollTokenId, enrollToken.Value)
                    .SetProperty(r => r.JobId, jobId),
                cancellationToken) > 0;
    }

    public async Task<bool> NoteSentAsync(CampaignId campaign, CampaignRecipientId recipient, Guid payloadId, DateTimeOffset at, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        return await context.CampaignRecipients
            .Where(r => r.Id == recipient && r.CampaignId == campaign
                && r.Status == (int)CampaignRecipientStatus.Building)
            .ExecuteUpdateAsync(
                s => s.SetProperty(r => r.Status, (int)CampaignRecipientStatus.Sent)
                    .SetProperty(r => r.PayloadId, payloadId)
                    .SetProperty(r => r.SentAt, at),
                cancellationToken) > 0;
    }

    public async Task<bool> NoteFailedAsync(CampaignId campaign, CampaignRecipientId recipient, string reason, DateTimeOffset at, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        return await context.CampaignRecipients
            .Where(r => r.Id == recipient && r.CampaignId == campaign
                && r.Status != (int)CampaignRecipientStatus.Sent
                && r.Status != (int)CampaignRecipientStatus.Failed)
            .ExecuteUpdateAsync(
                s => s.SetProperty(r => r.Status, (int)CampaignRecipientStatus.Failed)
                    .SetProperty(r => r.Failure, Clamp(reason)),
                cancellationToken) > 0;
    }

    public async Task<bool> NoteOpenedAsync(CampaignId campaign, CampaignRecipientId recipient, DateTimeOffset at, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        return await context.CampaignRecipients
            .Where(r => r.Id == recipient && r.CampaignId == campaign && r.OpenedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.OpenedAt, at), cancellationToken) > 0;
    }

    public async Task<bool> NoteClickedAsync(CampaignId campaign, CampaignRecipientId recipient, DateTimeOffset at, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        return await context.CampaignRecipients
            .Where(r => r.Id == recipient && r.CampaignId == campaign && r.ClickedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.ClickedAt, at), cancellationToken) > 0;
    }

    public async Task<bool> NoteExecutedAsync(CampaignId campaign, CampaignRecipientId recipient, Guid implantId, DateTimeOffset at, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        return await context.CampaignRecipients
            .Where(r => r.Id == recipient && r.CampaignId == campaign && r.ExecutedAt == null)
            .ExecuteUpdateAsync(
                s => s.SetProperty(r => r.ExecutedAt, at)
                    .SetProperty(r => r.EnrolledImplantId, new ImplantId(implantId)),
                cancellationToken) > 0;
    }

    public async Task<bool> TryCompleteAsync(CampaignId id, DateTimeOffset at, CancellationToken cancellationToken = default)
    {
        await using var context = await _factory.CreateDbContextAsync(cancellationToken);
        return await context.Campaigns
            .Where(c => c.Id == id && c.State == (int)CampaignState.Launched
                && !c.Recipients.Any(r => r.Status == (int)CampaignRecipientStatus.Pending
                    || r.Status == (int)CampaignRecipientStatus.Building))
            .ExecuteUpdateAsync(
                s => s.SetProperty(c => c.State, (int)CampaignState.Completed)
                    .SetProperty(c => c.CompletedAt, at),
                cancellationToken) > 0;
    }

    private static CampaignLure ToLure(StoredCampaignRecipient row) => new(
        row.CampaignId,
        row.Campaign!.EngagementId,
        row.Id,
        row.Campaign.Name,
        row.Email,
        row.PayloadId);

    // The failure column is bounded; a deeper exception message is clamped
    // rather than dropped -- the row's reason stays readable and the write
    // never fails on its own evidence.
    private static string Clamp(string reason)
        => reason.Length <= CampaignLimits.MaxFailureBytes ? reason : reason[..CampaignLimits.MaxFailureBytes];
}
