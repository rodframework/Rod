using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Rod.Persistence.Configurations;

/// <summary>
/// EF Core mapping for <see cref="StoredPayload"/>: the payload library's
/// durable rows. Reads are scoped by engagement (the library listing), by
/// id, by the envelope key id (the sealed-contact decode), and by the baked
/// token id (the enroll path's key resolution) -- one index each, the four
/// lookup shapes the port names.
/// </summary>
internal sealed class StoredPayloadConfiguration : IEntityTypeConfiguration<StoredPayload>
{
    public void Configure(EntityTypeBuilder<StoredPayload> builder)
    {
        builder.ToTable("payloads");

        builder.HasKey(p => p.PayloadId);
        builder.Property(p => p.PayloadId).HasColumnName("payload_id");
        builder.Property(p => p.EngagementId).HasColumnName("engagement_id");
        builder.Property(p => p.Class).HasColumnName("class").HasMaxLength(64).IsRequired();
        builder.Property(p => p.UnitId).HasColumnName("language").HasMaxLength(64).IsRequired();
        builder.Property(p => p.ContentType).HasColumnName("content_type").HasMaxLength(256).IsRequired();
        builder.Property(p => p.Fingerprint).HasColumnName("fingerprint").HasMaxLength(128).IsRequired();
        builder.Property(p => p.Content).HasColumnName("content").IsRequired();
        builder.Property(p => p.Size).HasColumnName("size");
        builder.Property(p => p.BuiltAt).HasColumnName("built_at");
        builder.Property(p => p.Target).HasColumnName("target").HasMaxLength(128);
        builder.Property(p => p.Endpoint).HasColumnName("endpoint").HasMaxLength(2048);
        builder.Property(p => p.TokenId).HasColumnName("token_id");
        builder.Property(p => p.EnvelopeKeyId).HasColumnName("envelope_key_id");
        builder.Property(p => p.EnvelopeKey).HasColumnName("envelope_key");
        builder.Property(p => p.WireGuardPublicKey).HasColumnName("wireguard_public_key");
        builder.Property(p => p.BuildJson).HasColumnName("build_profile");
        builder.Property(p => p.DeliversPayloadId).HasColumnName("delivers_payload_id");

        builder.HasIndex(p => p.EngagementId).HasDatabaseName("ix_payloads_engagement_id");
        builder.HasIndex(p => p.EnvelopeKeyId).HasDatabaseName("ix_payloads_envelope_key_id");
        builder.HasIndex(p => p.TokenId).HasDatabaseName("ix_payloads_token_id");
    }
}
