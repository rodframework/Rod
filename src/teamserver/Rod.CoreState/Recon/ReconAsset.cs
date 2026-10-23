namespace Rod.CoreState.Recon;

/// <summary>
/// What kind of address a recon asset names (architecture.md Sec 15.4).
/// The kind decides which references the asset can carry: an email asset
/// is selectable as a campaign target; the network kinds serve the recon
/// picture and future consumers (ROE scoping, topology joins).
/// </summary>
public enum ReconAssetKind
{
    /// <summary>A mailbox address -- the campaign-target kind.</summary>
    Email,

    /// <summary>A registered domain ("target.example").</summary>
    Domain,

    /// <summary>A named host ("mail.target.example").</summary>
    Host,

    /// <summary>An IP literal ("203.0.113.7").</summary>
    Address,
}

/// <summary>
/// One first-class target entity of the unified entity model
/// (architecture.md Sec 15.4): an address the recon workbench surfaced or
/// an operator recorded, carried as a referenceable row rather than a
/// finding buried in an artifact -- so the load-bearing link "a recon
/// asset selects directly as a campaign target" has something to point
/// at. The workbench's findings artifacts stay the evidence (Sec 11.4);
/// an asset row is the operator's curatorial act of promoting an address
/// to a tracked target, with <see cref="SourceArtifactId"/> naming the
/// finding it came from when it came from one.
///
/// Identity within an engagement is (kind, value): the same address
/// twice is one target, not two rows.
/// </summary>
public sealed class ReconAsset
{
    public ReconAssetId Id { get; }
    public EngagementId EngagementId { get; }

    public ReconAssetKind Kind { get; }
    public string Value { get; }

    /// <summary>
    /// The human-facing label for the asset (a person's name for an email
    /// target, a role for a host) -- the display name a campaign target
    /// selection defaults its merge field <c>{{name}}</c> to. Null when
    /// the asset carries none.
    /// </summary>
    public string? DisplayName { get; }

    /// <summary>
    /// The workbench findings artifact the asset was promoted from
    /// (architecture.md Sec 11.4), when it was -- null for an
    /// operator-recorded asset with no finding behind it. The artifact
    /// keeps the evidence; this reference keeps the provenance.
    /// </summary>
    public Guid? SourceArtifactId { get; }

    /// <summary>The operator who recorded the asset.</summary>
    public OperatorId CreatedBy { get; }
    public DateTimeOffset CreatedAt { get; }

    public ReconAsset(
        ReconAssetId id,
        EngagementId engagementId,
        ReconAssetKind kind,
        string value,
        string? displayName,
        Guid? sourceArtifactId,
        OperatorId createdBy,
        DateTimeOffset createdAt)
    {
        Id = id;
        EngagementId = engagementId;
        Kind = kind;
        Value = value;
        DisplayName = displayName;
        SourceArtifactId = sourceArtifactId;
        CreatedBy = createdBy;
        CreatedAt = createdAt;
    }
}
