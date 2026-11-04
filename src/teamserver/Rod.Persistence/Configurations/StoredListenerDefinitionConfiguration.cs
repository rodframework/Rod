using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Listeners;

namespace Rod.Persistence.Configurations;

/// <summary>
/// EF Core mapping for the engagement-scoped listener definitions (ADR 0003).
/// One row per runtime-created listener: the engagement it answers for, the
/// transport's wire name, the bind address the teamserver re-opens on restart,
/// and the public endpoint implants dial. The durable analogue of core state's
/// <see cref="ListenerDefinition"/> record; it lives here so the domain stays
/// free of any stored shape.
/// </summary>
internal sealed class StoredListenerDefinition
{
    public Guid Id { get; set; }
    public EngagementId EngagementId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Transport { get; set; } = string.Empty;
    public string BindAddress { get; set; } = string.Empty;
    public string PublicEndpoint { get; set; } = string.Empty;

    /// <summary>Whose certificate the front presents ("pinned"/"public") --
    /// the fact builds inherit as their TLS roots (architecture.md Sec 9).
    /// Nullable only for rows predating the column; reads as pinned.</summary>
    public string? TrustPosture { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RepointedAt { get; set; }

    /// <summary>
    /// The ordered front list as JSON (architecture.md Sec 8). Null is the
    /// hand-fronted listener -- no enrolled fronts. The list is small (a
    /// listener fronts through a handful of nodes) and read whole with the
    /// row, so a JSON column beats a child table here.
    /// </summary>
    public string? FrontsJson { get; set; }

    /// <summary>
    /// The installed listener package a package-backed listener binds
    /// (ADR-025), by name and version; null on a provider-backed listener.
    /// The stored transport column carries the package's own name here.
    /// </summary>
    public string? PackageName { get; set; }
    public string? PackageVersion { get; set; }

    /// <summary>The bound package's declared seal tier ("sealed"/"id-only",
    /// ADR-025); null on a provider-backed listener.</summary>
    public string? SealTier { get; set; }

    /// <summary>
    /// The medium parameters the operator set at creation, as JSON
    /// (ADR-025) -- the values the restart respawns the process with.
    /// </summary>
    public string? ParamsJson { get; set; }
}

// The JSON shape of a stored front: strings all the way down, so the stored
// form never depends on the domain record's serialization shape.
internal sealed record StoredListenerFront(
    string FrontId,
    string NodeId,
    string ListenEndpoint,
    string PublicEndpoint,
    string? AllowList,
    DateTimeOffset AttachedAt);

internal static class ListenerFrontsJson
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    public static string? Of(IReadOnlyList<ListenerFront>? fronts)
    {
        if (fronts is null || fronts.Count == 0)
            return null;
        return JsonSerializer.Serialize(
            fronts.Select(f => new StoredListenerFront(
                f.FrontId.ToString(),
                f.NodeId.ToString(),
                f.ListenEndpoint,
                f.PublicEndpoint,
                f.AllowList,
                f.AttachedAt)),
            Options);
    }

    public static IReadOnlyList<ListenerFront> Parse(string? json)
    {
        if (string.IsNullOrEmpty(json))
            return [];
        var stored = JsonSerializer.Deserialize<List<StoredListenerFront>>(json, Options);
        if (stored is null || stored.Count == 0)
            return [];
        var fronts = new List<ListenerFront>(stored.Count);
        foreach (var f in stored)
        {
            // A row a newer teamserver wrote (a shape this one cannot parse)
            // drops its front rather than failing the whole restore; the
            // node converges on the next rule push.
            if (!Guid.TryParse(f.FrontId, out var frontId)
                || !RedirectorNodeId.TryParse(f.NodeId, out var nodeId))
                continue;
            fronts.Add(new ListenerFront(
                frontId, nodeId, f.ListenEndpoint, f.PublicEndpoint, f.AllowList, f.AttachedAt));
        }

        return fronts;
    }
}

internal sealed class StoredListenerDefinitionConfiguration : IEntityTypeConfiguration<StoredListenerDefinition>
{
    public void Configure(EntityTypeBuilder<StoredListenerDefinition> builder)
    {
        builder.ToTable("listener_definitions");

        builder.HasKey(l => l.Id);
        builder.Property(l => l.Id).HasColumnName("listener_id");

        builder.Property(l => l.EngagementId)
            .HasConversion(IdConverters.EngagementId)
            .HasColumnName("engagement_id");
        builder.Property(l => l.Name).HasColumnName("name").HasMaxLength(200);
        // A package-backed listener stores the package's own name here
        // (ADR-025), so the column holds a package name's full length.
        builder.Property(l => l.Transport).HasColumnName("transport").HasMaxLength(128);
        builder.Property(l => l.BindAddress).HasColumnName("bind_address").HasMaxLength(200);
        builder.Property(l => l.PublicEndpoint).HasColumnName("public_endpoint").HasMaxLength(500);
        builder.Property(l => l.TrustPosture).HasColumnName("trust_posture").HasMaxLength(16);
        builder.Property(l => l.CreatedAt).HasColumnName("created_at");
        builder.Property(l => l.RepointedAt).HasColumnName("repointed_at");
        builder.Property(l => l.FrontsJson).HasColumnName("fronts_json");
        builder.Property(l => l.PackageName).HasColumnName("package_name").HasMaxLength(128);
        builder.Property(l => l.PackageVersion).HasColumnName("package_version").HasMaxLength(32);
        builder.Property(l => l.SealTier).HasColumnName("seal_tier").HasMaxLength(16);
        builder.Property(l => l.ParamsJson).HasColumnName("params_json");

        // The engagement's listener listing reads by engagement; the port-
        // uniqueness pre-check reads them all.
        builder.HasIndex(l => l.EngagementId).HasDatabaseName("ix_listener_definitions_engagement_id");
    }
}
