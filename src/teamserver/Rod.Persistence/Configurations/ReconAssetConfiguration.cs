using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Rod.CoreState;
using Rod.CoreState.Recon;

namespace Rod.Persistence.Configurations;

/// <summary>
/// EF Core mapping for recon assets (architecture.md Sec 15.4): the
/// first-class target rows of the unified entity model. A
/// Persistence-owned mirror of core state's <see cref="ReconAsset"/> (the
/// domain stays free of any stored shape), like the campaign mirror
/// beside it.
/// </summary>
internal sealed class StoredReconAsset
{
    public ReconAssetId Id { get; set; }
    public EngagementId EngagementId { get; set; }
    public int Kind { get; set; }
    public string Value { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public Guid? SourceArtifactId { get; set; }
    public OperatorId CreatedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public static StoredReconAsset From(ReconAsset asset) => new()
    {
        Id = asset.Id,
        EngagementId = asset.EngagementId,
        Kind = (int)asset.Kind,
        Value = asset.Value,
        DisplayName = asset.DisplayName,
        SourceArtifactId = asset.SourceArtifactId,
        CreatedBy = asset.CreatedBy,
        CreatedAt = asset.CreatedAt,
    };

    public ReconAsset ToDomain() => new(
        Id,
        EngagementId,
        (ReconAssetKind)Kind,
        Value,
        DisplayName,
        SourceArtifactId,
        CreatedBy,
        CreatedAt);
}

internal sealed class ReconAssetConfiguration : IEntityTypeConfiguration<StoredReconAsset>
{
    // One address shape covers every kind: the email limit (320) is the
    // longest of the set -- a DNS name caps at 255 by its own protocol.
    private const int MaxValueBytes = 320;

    public void Configure(EntityTypeBuilder<StoredReconAsset> builder)
    {
        builder.ToTable("recon_assets");

        builder.HasKey(a => a.Id);
        builder.Property(a => a.Id)
            .HasConversion(IdConverters.ReconAssetId)
            .HasColumnName("recon_asset_id");

        builder.Property(a => a.EngagementId)
            .HasConversion(IdConverters.EngagementId)
            .HasColumnName("engagement_id");
        // Like every core-state enum column: int storage.
        builder.Property(a => a.Kind).HasConversion<int>().HasColumnName("kind");
        builder.Property(a => a.Value).HasColumnName("value").HasMaxLength(MaxValueBytes);
        builder.Property(a => a.DisplayName).HasColumnName("display_name").HasMaxLength(MaxValueBytes);
        builder.Property(a => a.SourceArtifactId).HasColumnName("source_artifact_id");
        builder.Property(a => a.CreatedBy)
            .HasConversion(IdConverters.OperatorId)
            .HasColumnName("created_by");
        builder.Property(a => a.CreatedAt).HasColumnName("created_at");

        builder.HasIndex(a => a.EngagementId).HasDatabaseName("ix_recon_assets_engagement_id");
        // Identity within the engagement: the same address twice is one
        // target, not two rows. The store's AddAsync lets the constraint
        // refuse a race the caller's pre-check missed.
        builder.HasIndex(a => new { a.EngagementId, a.Kind, a.Value })
            .IsUnique()
            .HasDatabaseName("ux_recon_assets_engagement_id_kind_value");

        // The (id, engagement) anchor the campaign-target foreign keys
        // land on: a referencing recipient row carries both columns, so a
        // selection cannot cross engagements by constraint, not by query
        // discipline.
        builder.HasAlternateKey(a => new { a.Id, a.EngagementId })
            .HasName("ux_recon_assets_id_engagement_id");
    }
}
