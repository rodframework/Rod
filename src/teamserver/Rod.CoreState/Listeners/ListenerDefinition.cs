namespace Rod.CoreState.Listeners;

/// <summary>
/// The durable record of an engagement-scoped listener (architecture.md Sec 8).
/// Runtime-created listeners belong to exactly one engagement -- their socket
/// is that engagement's private ingress -- and the record outlives the process
/// so a restart rebinds what the operator built. The transport rides as its
/// wire name (e.g. "mtls"): core state stores the association, the transport
/// layer owns the enum and the socket. The trust posture records whose
/// certificate the front presents, the fact builds inherit as their TLS
/// roots (architecture.md Sec 9): "pinned" (the engagement CA) or "public"
/// (a real-domain chain an operator-run edge terminates); https fronts alone
/// may name public. A package-backed listener (ADR-025) names the installed
/// package it binds -- name, version, declared seal tier -- and the medium
/// parameters the operator set at creation, so the restart resolves the
/// package and respawns its process; those fields are null on a
/// provider-backed listener (the in-tree families).
/// </summary>
public sealed record ListenerDefinition(
    Guid Id,
    EngagementId EngagementId,
    string Name,
    string Transport,
    string BindAddress,
    string PublicEndpoint,
    DateTimeOffset CreatedAt,
    DateTimeOffset? RepointedAt = null,
    string TrustPosture = "pinned",
    IReadOnlyList<ListenerFront>? Fronts = null,
    string? PackageName = null,
    string? PackageVersion = null,
    string? SealTier = null,
    string? ParamsJson = null)
{
    /// <summary>
    /// The ordered front list, empty when the listener is fronted by nothing
    /// (hand-deployed redirectors, or no redirector at all). Index zero is
    /// the primary front: its public endpoint is what the listener reports.
    /// </summary>
    public IReadOnlyList<ListenerFront> FrontList => Fronts ?? [];
}
