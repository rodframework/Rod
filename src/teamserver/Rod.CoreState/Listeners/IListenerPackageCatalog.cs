namespace Rod.CoreState.Listeners;

/// <summary>
/// The seal tiers a listener package may declare (ADR-025): the spellings
/// the manifest carries and the catalog forwards -- strings, not an
/// enumeration, the same posture the trust postures keep. <c>sealed</c> is
/// the end-to-end per-artifact-key seal; <c>id-only</c> is the handshake's
/// identity alone, the posture a point-to-point carrier on an operated
/// segment may honestly take. A carrier whose bytes rest on third-party
/// infrastructure may not take it -- the catalog refuses the package.
/// </summary>
public static class ListenerSealTiers
{
    public const string Sealed = "sealed";
    public const string IdOnly = "id-only";
}

/// <summary>
/// The endpoint shapes a listener package may declare (ADR-025): the
/// spellings the manifest carries and the catalog forwards. <c>web-dial</c>
/// is the absolute http(s) URL implants dial; <c>dns-zone</c> is the zone a
/// DNS medium's queries answer under -- the kernel validates the listener's
/// public endpoint by the shape instead of assuming a web dial.
/// </summary>
public static class ListenerEndpointShapes
{
    public const string WebDial = "web-dial";
    public const string DnsZone = "dns-zone";
}

/// <summary>
/// The TLS postures a listener package's front may declare (ADR-025):
/// <c>by-endpoint</c> defers to the web dial's scheme, <c>always</c>
/// terminates TLS whatever the dial shape, <c>never</c> serves the medium
/// in the clear. The kernel reads the posture to decide whether to hand the
/// process a CA-issued leaf.
/// </summary>
public static class ListenerTlsPostures
{
    public const string ByEndpoint = "by-endpoint";
    public const string Always = "always";
    public const string Never = "never";
}

/// <summary>
/// One config-schema row a listener package declares: a medium parameter an
/// operator sets at listener creation (the manifest's
/// <c>[[listener.params]]</c> row). A secret row is one the console never
/// echoes back.
/// </summary>
public sealed record ListenerPackageParam(
    string Name,
    string Kind,
    bool Required,
    string? Description,
    bool Secret);

/// <summary>
/// The resolved facts of one installed listener package (ADR-025): what the
/// supervisor and the listener manager need to bind a listener against it --
/// the medium contract (seal tier, channel honesty, carriers, endpoint
/// shape, TLS posture) and the spawn contract (the process command and its
/// static arguments, run inside the installed package directory). Plain
/// data on purpose: core state owns the shape so the transport layer can
/// consume it without reaching the module ecosystem's layers, the same seam
/// every cross-layer port keeps.
/// </summary>
public sealed record ListenerPackageInfo(
    string Name,
    string Version,
    string SealTier,
    bool ThirdPartyMedium,
    string Channel,
    IReadOnlyList<string> Carriers,
    string ProcessCommand,
    IReadOnlyList<string> ProcessArgs,
    IReadOnlyList<ListenerPackageParam> Params,
    string RootDirectory,
    string EndpointShape = ListenerEndpointShapes.WebDial,
    string Tls = ListenerTlsPostures.ByEndpoint)
{
    /// <summary>
    /// The third-party-medium seal rule, stated where both spellings live:
    /// a carrier whose bytes rest on third-party infrastructure must carry
    /// the end-to-end seal. The manifest refuses such a package at publish;
    /// this is the kernel-side half of the same rule.
    /// </summary>
    public bool SealRuleSatisfied
        => !ThirdPartyMedium || string.Equals(SealTier, ListenerSealTiers.Sealed, StringComparison.Ordinal);
}

/// <summary>
/// Resolves installed listener packages by name (ADR-025). The transport
/// layer's listener manager and supervisor consume this port; the module
/// ecosystem's layers implement it over the installed-module store. The
/// default implementation (no module store configured) answers null for
/// every name -- no package, no package-backed listener, the open-not-on
/// posture every module seam keeps.
/// </summary>
public interface IListenerPackageCatalog
{
    /// <summary>
    /// The installed package, or null when no such name (or version) is
    /// installed. A null <paramref name="version"/> resolves the latest
    /// installed version of the name.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The package violates the third-party-medium seal rule -- refused
    /// here as it was at publish, so a store that drifted past validation
    /// cannot serve it anyway.
    /// </exception>
    ListenerPackageInfo? Resolve(
        string name,
        string? version = null,
        CancellationToken cancellationToken = default);
}
