using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Rod.CoreState;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Deployment;
using Rod.CoreState.Implants;

namespace Rod.Persistence.Configurations;

/// <summary>
/// EF Core mapping for delivery campaigns (architecture.md Sec 11.5): one
/// row per campaign plus one row per recipient under it. The recipient
/// rows carry the attribution binding (the baked token id) and the
/// evidence stamps the public edge writes, which is why they are a table
/// of their own rather than a JSON column -- the enroll lookup and the
/// lure resolution are indexed single-row reads, not aggregate
/// deserializations. A Persistence-owned mirror of core state's
/// <see cref="Campaign"/> aggregate (the domain stays free of any stored
/// shape).
///
/// The link set of the unified entity model (architecture.md Sec 15.4)
/// lives here as explicit foreign keys, each one composite with the
/// engagement id: a row cannot reference across engagements, the
/// isolation the application layer keeps by query now also holds by
/// constraint.
/// </summary>
internal sealed class StoredCampaign
{
    public CampaignId Id { get; set; }
    public EngagementId EngagementId { get; set; }
    public string Name { get; set; } = string.Empty;
    public OperatorId CreatedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public int State { get; set; }
    public string RelayHost { get; set; } = string.Empty;
    public int RelayPort { get; set; }
    public int RelayTls { get; set; }
    public string? RelayUsername { get; set; }
    public string? RelayPassword { get; set; }
    public string FromAddress { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;
    public bool BodyIsHtml { get; set; }
    public string BuildRequestJson { get; set; } = string.Empty;
    public Guid ListenerId { get; set; }
    public DateTimeOffset? LaunchedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }

    public List<StoredCampaignRecipient> Recipients { get; set; } = [];

    public static StoredCampaign From(Campaign campaign) => new()
    {
        Id = campaign.Id,
        EngagementId = campaign.EngagementId,
        Name = campaign.Name,
        CreatedBy = campaign.CreatedBy,
        CreatedAt = campaign.CreatedAt,
        State = (int)campaign.State,
        RelayHost = campaign.RelayHost,
        RelayPort = campaign.RelayPort,
        RelayTls = (int)campaign.RelayTls,
        RelayUsername = campaign.RelayUsername,
        RelayPassword = campaign.RelayPassword,
        FromAddress = campaign.FromAddress,
        Subject = campaign.Subject,
        Body = campaign.Body,
        BodyIsHtml = campaign.BodyIsHtml,
        BuildRequestJson = campaign.BuildRequestJson,
        ListenerId = campaign.ListenerId,
        LaunchedAt = campaign.LaunchedAt,
        CompletedAt = campaign.CompletedAt,
        RevokedAt = campaign.RevokedAt,
        // The recipient rows carry the campaign's engagement and creator:
        // every entity of the model answers both on its own row
        // (architecture.md Sec 15.4), and the recipients below read them
        // from the aggregate's head, their one source of truth.
        Recipients = campaign.Recipients
            .Select(r => StoredCampaignRecipient.From(campaign, r))
            .ToList(),
    };

    public Campaign ToDomain() => new(
        Id,
        EngagementId,
        Name,
        CreatedBy,
        CreatedAt,
        RelayHost,
        RelayPort,
        (CampaignRelayTls)RelayTls,
        RelayUsername,
        RelayPassword,
        FromAddress,
        Subject,
        Body,
        BodyIsHtml,
        BuildRequestJson,
        ListenerId,
        Recipients.Select(r => r.ToDomain()).ToList(),
        (CampaignState)State,
        LaunchedAt,
        CompletedAt,
        RevokedAt);
}

/// <summary>
/// One recipient row. The status/failure/evidence columns are written by
/// the store's targeted operations, never by re-saving the aggregate --
/// the recipient table is the concurrent edge of the campaign, and the
/// targeted updates are what keep the engine's arcs from racing the
/// public edge's stamps.
///
/// <see cref="EngagementId"/> and <see cref="CreatedBy"/> are denormalized
/// off the campaign head so the row answers its engagement and operator on
/// its own (Sec 15.4); the target-selection link
/// (<see cref="ReconAssetId"/>) and the enrollment binding
/// (<see cref="EnrolledImplantId"/>) are explicit composite foreign keys,
/// which is what makes a cross-engagement reference impossible at the
/// database rather than merely unqueried.
/// </summary>
internal sealed class StoredCampaignRecipient
{
    public CampaignRecipientId Id { get; set; }
    public CampaignId CampaignId { get; set; }
    public StoredCampaign? Campaign { get; set; }
    public EngagementId EngagementId { get; set; }
    public OperatorId CreatedBy { get; set; }
    public string Email { get; set; } = string.Empty;
    public string? Name { get; set; }
    public Rod.CoreState.ReconAssetId? ReconAssetId { get; set; }
    public Guid LureId { get; set; }
    public int Status { get; set; }
    public string? Failure { get; set; }
    public Guid? JobId { get; set; }
    public Guid? EnrollTokenId { get; set; }
    public Guid? PayloadId { get; set; }
    public DateTimeOffset? SentAt { get; set; }
    public DateTimeOffset? OpenedAt { get; set; }
    public DateTimeOffset? ClickedAt { get; set; }
    public DateTimeOffset? ExecutedAt { get; set; }
    public ImplantId? EnrolledImplantId { get; set; }

    public static StoredCampaignRecipient From(Campaign campaign, CampaignRecipient recipient) => new()
    {
        Id = recipient.Id,
        CampaignId = campaign.Id,
        EngagementId = campaign.EngagementId,
        CreatedBy = campaign.CreatedBy,
        Email = recipient.Email,
        Name = recipient.Name,
        ReconAssetId = recipient.ReconAssetId,
        LureId = recipient.LureId,
        Status = (int)recipient.Status,
        Failure = recipient.Failure,
        JobId = recipient.JobId,
        EnrollTokenId = recipient.EnrollTokenId?.Value,
        PayloadId = recipient.PayloadId,
        SentAt = recipient.SentAt,
        OpenedAt = recipient.OpenedAt,
        ClickedAt = recipient.ClickedAt,
        ExecutedAt = recipient.ExecutedAt,
        EnrolledImplantId = recipient.EnrolledImplantId is { } enrolled ? new ImplantId(enrolled) : null,
    };

    public CampaignRecipient ToDomain() => new(
        Id,
        Email,
        Name,
        LureId,
        (CampaignRecipientStatus)Status,
        Failure,
        JobId,
        EnrollTokenId is { } token ? new DeployTokenId(token) : null,
        PayloadId,
        SentAt,
        OpenedAt,
        ClickedAt,
        ExecutedAt,
        EnrolledImplantId is { } enrolled ? enrolled.Value : null,
        ReconAssetId);
}

internal sealed class CampaignConfiguration : IEntityTypeConfiguration<StoredCampaign>
{
    public void Configure(EntityTypeBuilder<StoredCampaign> builder)
    {
        builder.ToTable("campaigns");

        builder.HasKey(c => c.Id);
        builder.Property(c => c.Id)
            .HasConversion(IdConverters.CampaignId)
            .HasColumnName("campaign_id");

        builder.Property(c => c.EngagementId)
            .HasConversion(IdConverters.EngagementId)
            .HasColumnName("engagement_id");
        builder.Property(c => c.Name).HasColumnName("name").HasMaxLength(CampaignLimits.MaxNameBytes);
        builder.Property(c => c.CreatedBy)
            .HasConversion(IdConverters.OperatorId)
            .HasColumnName("created_by");
        builder.Property(c => c.CreatedAt).HasColumnName("created_at");
        builder.Property(c => c.State).HasConversion<int>().HasColumnName("state");
        builder.Property(c => c.RelayHost).HasColumnName("relay_host").HasMaxLength(255);
        builder.Property(c => c.RelayPort).HasColumnName("relay_port");
        builder.Property(c => c.RelayTls).HasConversion<int>().HasColumnName("relay_tls");
        builder.Property(c => c.RelayUsername).HasColumnName("relay_username").HasMaxLength(255);
        builder.Property(c => c.RelayPassword).HasColumnName("relay_password").HasMaxLength(255);
        builder.Property(c => c.FromAddress).HasColumnName("from_address").HasMaxLength(CampaignLimits.MaxAddressBytes);
        builder.Property(c => c.Subject).HasColumnName("subject").HasMaxLength(CampaignLimits.MaxSubjectBytes);
        builder.Property(c => c.Body).HasColumnName("body").HasMaxLength(CampaignLimits.MaxBodyBytes);
        builder.Property(c => c.BodyIsHtml).HasColumnName("body_is_html");
        builder.Property(c => c.BuildRequestJson).HasColumnName("build_request_json").HasMaxLength(CampaignLimits.MaxBuildRequestBytes);
        builder.Property(c => c.ListenerId).HasColumnName("listener_id");
        builder.Property(c => c.LaunchedAt).HasColumnName("launched_at");
        builder.Property(c => c.CompletedAt).HasColumnName("completed_at");
        builder.Property(c => c.RevokedAt).HasColumnName("revoked_at");

        // The operator API lists by engagement; the send engine scans the
        // launched set across engagements.
        builder.HasIndex(c => c.EngagementId).HasDatabaseName("ix_campaigns_engagement_id");
        builder.HasIndex(c => c.State).HasDatabaseName("ix_campaigns_state");

        // The (id, engagement) pair the composite inbound foreign keys
        // anchor on: referencing rows carry both columns, so the database
        // itself rejects a reference that crosses engagements.
        builder.HasAlternateKey(c => new { c.Id, c.EngagementId })
            .HasName("ux_campaigns_id_engagement_id");

        builder.HasMany(c => c.Recipients)
            .WithOne(r => r.Campaign)
            .HasForeignKey(r => r.CampaignId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class CampaignRecipientConfiguration : IEntityTypeConfiguration<StoredCampaignRecipient>
{
    public void Configure(EntityTypeBuilder<StoredCampaignRecipient> builder)
    {
        builder.ToTable("campaign_recipients");

        builder.HasKey(r => r.Id);
        builder.Property(r => r.Id)
            .HasConversion(IdConverters.CampaignRecipientId)
            .HasColumnName("campaign_recipient_id");

        builder.Property(r => r.CampaignId)
            .HasConversion(IdConverters.CampaignId)
            .HasColumnName("campaign_id");
        builder.Property(r => r.EngagementId)
            .HasConversion(IdConverters.EngagementId)
            .HasColumnName("engagement_id");
        builder.Property(r => r.CreatedBy)
            .HasConversion(IdConverters.OperatorId)
            .HasColumnName("created_by");
        builder.Property(r => r.Email).HasColumnName("email").HasMaxLength(CampaignLimits.MaxAddressBytes);
        builder.Property(r => r.Name).HasColumnName("name").HasMaxLength(CampaignLimits.MaxAddressBytes);
        builder.Property(r => r.ReconAssetId)
            .HasConversion(IdConverters.ReconAssetId)
            .HasColumnName("recon_asset_id");
        builder.Property(r => r.LureId).HasColumnName("lure_id");
        builder.Property(r => r.Status).HasConversion<int>().HasColumnName("status");
        builder.Property(r => r.Failure).HasColumnName("failure").HasMaxLength(CampaignLimits.MaxFailureBytes);
        builder.Property(r => r.JobId).HasColumnName("job_id");
        builder.Property(r => r.EnrollTokenId).HasColumnName("enroll_token_id");
        builder.Property(r => r.PayloadId).HasColumnName("payload_id");
        builder.Property(r => r.SentAt).HasColumnName("sent_at");
        builder.Property(r => r.OpenedAt).HasColumnName("opened_at");
        builder.Property(r => r.ClickedAt).HasColumnName("clicked_at");
        builder.Property(r => r.ExecutedAt).HasColumnName("executed_at");
        builder.Property(r => r.EnrolledImplantId)
            .HasConversion(IdConverters.ImplantId)
            .HasColumnName("enrolled_implant_id");

        // The public edge resolves a lure by its unguessable id alone; the
        // enrollment path resolves attribution by the baked token. Both are
        // single-row reads, and both ids are unique by construction.
        builder.HasIndex(r => r.LureId).IsUnique().HasDatabaseName("ux_campaign_recipients_lure_id");
        builder.HasIndex(r => r.EnrollTokenId).IsUnique()
            .HasDatabaseName("ux_campaign_recipients_enroll_token_id")
            // A partial index: rows before the engine's mint (and recipients
            // of a Draft campaign) carry no token, and a full unique index
            // would admit only one NULL under the default b-tree semantics.
            .HasFilter("enroll_token_id IS NOT NULL");
        // The asset-delete check walks this index (which recipients named a
        // given asset); without it the delete would scan the table.
        builder.HasIndex(r => new { r.ReconAssetId, r.EngagementId })
            .HasDatabaseName("ix_campaign_recipients_recon_asset_id_engagement_id")
            .HasFilter("recon_asset_id IS NOT NULL");

        // The (id, engagement) anchor for the implant rows that reference a
        // recipient as their enrollment attribution.
        builder.HasAlternateKey(r => new { r.Id, r.EngagementId })
            .HasName("ux_campaign_recipients_id_engagement_id");

        // The target-selection link (Sec 15.4): the asset the recipient was
        // selected from. Restrict, not cascade -- a target an engagement
        // already aimed at stays on the books while the campaign row lives.
        builder.HasOne<StoredReconAsset>()
            .WithMany()
            .HasForeignKey(r => new { r.ReconAssetId, r.EngagementId })
            .HasPrincipalKey("Id", "EngagementId")
            .HasConstraintName("fk_recipients_recon_asset")
            .OnDelete(DeleteBehavior.Restrict);
        // The executed binding, the read side of the implant's campaign
        // attribution. Restrict: implant rows never delete, so the guard
        // only ever refuses a recipient-side anomaly.
        builder.HasOne<Rod.CoreState.Implants.Implant>()
            .WithMany()
            .HasForeignKey(r => new { r.EnrolledImplantId, r.EngagementId })
            .HasPrincipalKey("Id", "EngagementId")
            .HasConstraintName("fk_recipients_enrolled_implant")
            .OnDelete(DeleteBehavior.Restrict);
    }
}
