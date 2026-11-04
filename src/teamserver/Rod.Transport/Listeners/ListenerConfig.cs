using Rod.CoreState;

namespace Rod.Transport.Listeners;

/// <summary>
/// One listener's configuration shape (architecture.md Sec 8): what the runtime
/// manager binds for an engagement, and what the startup <c>Listeners</c>
/// section names for the operator tier. This is configuration shape only -- it
/// is not a <see cref="Listener"/> until the host (or the manager) has bound
/// the socket and registered the result.
/// </summary>
/// <param name="Transport">
/// The transport this listener terminates, by its wire name (the registry key
/// a provider registers under). Validated against the provider registry at
/// every entry -- the runtime create, the startup section, the restore -- so a
/// transport added later is nameable without this shape changing.
/// </param>
/// <param name="EngagementId">
/// The engagement this listener answers for. Required on a runtime create --
/// an engagement's ingress is its own, and enrollment through it checks the
/// presented token against this id. Null is the startup-configuration tier:
/// the operator front (and any deliberately shared ingress a deployment
/// fronts), which serves any engagement the token itself names.
/// </param>
/// <param name="TrustPosture">
/// Whose certificate the front presents ("pinned" the engagement CA -- the
/// default; "public" a real-domain chain an operator-run edge terminates).
/// A fact of the front that builds inherit as their TLS roots, so it rides
/// the listener rather than the build request (architecture.md Sec 9).
/// Only the https transport may name public.
/// </param>
public sealed record ListenerConfig(
    string Name,
    string Transport,
    string BindAddress,
    string PublicEndpoint,
    EngagementId? EngagementId = null,
    string TrustPosture = "pinned",
    string? PackageName = null,
    string? PackageVersion = null,
    IReadOnlyDictionary<string, string>? Params = null);
