using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Listeners;
using Rod.CoreState.Pki;
using Rod.Transport.Listeners.Providers;

namespace Rod.Transport.Listeners;

/// <summary>
/// Runtime listener management: create and remove C2 ingress while the
/// teamserver serves, the operator-API counterpart to the startup
/// <c>Listeners</c> configuration (architecture.md Sec 8). The manager owns
/// the shared create/remove flow -- validation mapping, port reservation,
/// engagement scoping, persistence, the runtime roster -- and delegates each
/// transport's bind to its provider (<see cref="TransportProviders"/>, keyed
/// by wire name). Two provider shapes cover the in-tree six:
///
/// - <see cref="KestrelEndpointProvider"/>: the HTTP family
///   (<c>Http</c>, <c>Https</c>, <c>Doh</c>) rides Kestrel's
///   endpoint-configuration reloader -- the provider publishes the bind
///   address as an endpoint URL into a push-only configuration source the
///   host registered with <c>KestrelServerOptions.Configure(..., reloadOnChange:
///   true)</c> and Kestrel binds (create) or drains and unbinds (remove) the
///   socket in response, under the transport's TLS posture. A create confirms
///   the bind by probing the port before reporting the listener as running --
///   the reloader's errors are logs, not exceptions, so the provider observes
///   the outcome instead of assuming it.
///
/// - <see cref="HostedServiceTransportProvider"/>: the socket-owning
///   transports (<c>Dns</c>, <c>Tcp</c>, <c>ShellCatch</c>) run their sockets in
///   per-listener hosted services; the provider starts and stops one service
///   per listener on demand, the same services the startup path registers.
///
/// Runtime listeners are engagement-scoped: each create names the engagement
/// the listener answers for, and its definition is persisted once the socket
/// binds, so a restart rebinds what the operator built (the restore keeps the
/// listener's id). Removing a startup-bound listener is refused (the reloader
/// only touches endpoints it owns); the configuration is the owner of those,
/// and they carry no engagement -- the shared tier.
/// </summary>
public sealed class ListenerManager
{
    private readonly IServiceProvider _services;
    private readonly IListenerRegistry _listeners;
    private readonly IListenerStore _definitions;
    private readonly IEngagementRepository _engagements;
    private readonly TimeProvider _clock;
    private readonly ILogger<ListenerManager> _logger;
    private readonly DynamicEndpointsConfiguration _endpoints = new();
    private readonly ConcurrentDictionary<ListenerId, RuntimeEntry> _runtime = new();

    private sealed record RuntimeEntry(
        Listener Listener,
        IHostedService? Service,
        Bridge.SupervisedListener? Supervised = null,
        IReadOnlyDictionary<string, string>? PackageParams = null);

    public ListenerManager(
        IServiceProvider services,
        IListenerRegistry listeners,
        IListenerStore definitions,
        IEngagementRepository engagements,
        TimeProvider clock,
        ILogger<ListenerManager> logger)
    {
        _services = services;
        _listeners = listeners;
        _definitions = definitions;
        _engagements = engagements;
        _clock = clock;
        _logger = logger;
    }

    /// <summary>The Kestrel section carrying runtime endpoint entries; the host hands it to <c>Configure</c> with reload on change.</summary>
    internal IConfiguration KestrelSection => _endpoints.KestrelSection;

    /// <summary>
    /// The HTTPS defaults for runtime-created TLS endpoints -- the termination
    /// every transport shares: the CA-issued server leaf, and chain-to-CA
    /// validation for whatever client certificate a transport asks to see.
    /// The certificate mode is deliberately not set here:
    /// <c>ConfigureHttpsDefaults</c> runs for every endpoint alike and would
    /// flatten the one HTTPS knob the transports differ on, so each published
    /// endpoint carries its own per-endpoint <c>ClientCertificateMode</c> in
    /// the configuration (the provider's
    /// <see cref="Providers.ListenerTlsPosture">TLS posture</see>): the
    /// mTLS-shaped listeners request the certificate, and every other TLS
    /// endpoint -- the https transport's fingerprint rule, no request at all
    /// -- leaves it at the Kestrel default.
    /// </summary>
    internal void ApplyDynamicHttpsDefaults(HttpsConnectionAdapterOptions https)
    {
        // The leaf must name what the client dialed (the reference implant's
        // rustls client verifies the server name against the SAN), and the
        // selector's only per-connection clue is the local endpoint: the port
        // names the bind, the bind names the runtime listener, and its live
        // public endpoint names the host implants dial -- a repoint flows
        // straight through without rebinding. An unmapped port (a front this
        // manager does not own) falls back to the SNI name, then to the
        // legacy nameless shape.
        https.ServerCertificateSelector = (context, sni) =>
            _services.GetRequiredService<IImplantCertificateAuthority>()
                .GetServerCertificate(HostOfListenerOn((context?.LocalEndPoint as IPEndPoint)?.Port) ?? sni ?? "");
        https.CheckCertificateRevocation = false;
    }

    // The public-endpoint host of the runtime listener that owns a bound
    // port, if any does.
    private string? HostOfListenerOn(int? port)
    {
        if (port is not { } bound)
            return null;
        foreach (var entry in _runtime.Values)
        {
            var bind = entry.Listener.BindAddress;
            var separator = bind.LastIndexOf(':');
            if (separator >= 0
                && int.TryParse(bind[(separator + 1)..], out var bindPort)
                && bindPort == bound)
            {
                // The web family is dialed at its public endpoint, but a
                // zone-shaped front (DoH) is dialed at its bind: the bake
                // names the resolver it dials, and the zone names only the
                // queries -- so the leaf must cover the bind's host, or the
                // first rustls handshake fails name validation.
                return TransportProviders.Find(entry.Listener.Transport)
                           is KestrelEndpointProvider { EndpointShape: PublicEndpointShape.DnsZone }
                    ? bind[..separator]
                    : ServerLeaf.HostOf(entry.Listener.PublicEndpoint);
            }
        }
        return null;
    }

    /// <summary>
    /// Creates and binds an engagement-scoped listener and persists its
    /// definition, so a restart rebinds it. Returns the registered (running)
    /// listener. Throws <see cref="ArgumentException"/> for a malformed
    /// request (bad bind address for the transport, missing or unknown
    /// engagement) and <see cref="InvalidOperationException"/> when the bind is
    /// refused (port in use) -- the caller maps those to 400 and 409.
    /// </summary>
    public async Task<Listener> CreateAsync(ListenerConfig config, CancellationToken cancellationToken = default)
    {
        if (config.EngagementId is not { } engagementId)
            throw new ArgumentException(
                "A runtime listener belongs to one engagement; supply its id.", nameof(config));

        var engagement = await _engagements.FindAsync(engagementId, cancellationToken);
        if (engagement is null)
            throw new ArgumentException(
                $"Engagement {engagementId} does not exist.", nameof(config));

        var listener = await BindAsync(config, id: null, cancellationToken);

        // Persist only once the socket is bound: a definition for a listener
        // that never opened would resurrect as a phantom on every restart.
        await _definitions.SaveAsync(DefinitionOf(listener), cancellationToken);
        return listener;
    }

    /// <summary>
    /// Rebinds a persisted definition at startup: the same bind path as
    /// <see cref="CreateAsync"/> with the definition's own id, and no re-save
    /// (the record is already the truth being restored). A definition whose
    /// port no longer binds is logged and skipped -- the roster shows what is
    /// actually listening -- instead of failing the whole boot.
    /// </summary>
    public async Task<Listener?> RestoreAsync(ListenerDefinition definition, CancellationToken cancellationToken = default)
    {
        // The stored transport is the wire name a provider registered under,
        // case-insensitive. The retired https-envelope entry maps to its
        // nearest surviving transport, https -- the bind and the TLS
        // termination it always shared -- so a definition saved before the
        // retirement rebinds under its migrated shape instead of dying as
        // unknown. A package-backed definition (ADR-025) names no provider:
        // its transport field carries the package's own name and the bind
        // resolves the package through the catalog instead.
        if (definition.PackageName is not null)
        {
            var catalog = _services.GetRequiredService<Rod.CoreState.Listeners.IListenerPackageCatalog>();
            if (catalog.Resolve(definition.PackageName, definition.PackageVersion, cancellationToken) is null)
            {
                _logger.LogWarning(
                    "Stored listener {ListenerId} ({Name}) binds package '{Package}@{Version}' that is no longer installed; skipped. "
                    + "Reinstall the package or delete the listener.",
                    definition.Id, definition.Name, definition.PackageName, definition.PackageVersion);
                return null;
            }

            try
            {
                var parameters = definition.ParamsJson is null
                    ? null
                    : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(
                        definition.ParamsJson, System.Text.Json.JsonSerializerOptions.Web);
                var config = new ListenerConfig(
                    definition.Name, definition.Transport, definition.BindAddress, definition.PublicEndpoint,
                    definition.EngagementId, definition.TrustPosture,
                    definition.PackageName, definition.PackageVersion, parameters);
                var listener = await BindAsync(config, new ListenerId(definition.Id), cancellationToken);
                listener.RestoreFronts(definition.FrontList);
                return listener;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException)
            {
                _logger.LogWarning(ex,
                    "Stored listener {ListenerId} ({Name}) could not rebind its package '{Package}'; skipped.",
                    definition.Id, definition.Name, definition.PackageName);
                return null;
            }
        }

        var transport = definition.Transport.Trim();
        if (transport.Replace("-", "").Equals("httpsenvelope", StringComparison.OrdinalIgnoreCase))
        {
            transport = "https";
            _logger.LogInformation(
                "Stored listener {ListenerId} ({Name}) carries the retired https-envelope transport; rebinding as https.",
                definition.Id, definition.Name);
        }
        else if (TransportProviders.Find(transport) is null)
        {
            _logger.LogWarning(
                "Stored listener {ListenerId} carries unknown transport '{Transport}'; skipped.",
                definition.Id, definition.Transport);
            return null;
        }

        try
        {
            var config = new ListenerConfig(
                definition.Name, transport, definition.BindAddress, definition.PublicEndpoint, definition.EngagementId,
                definition.TrustPosture);
            var listener = await BindAsync(config, new ListenerId(definition.Id), cancellationToken);
            // The front list rides the definition, not the bind path (a
            // fresh bind has none); the stored public endpoint already
            // reflects the primary, so restoring fronts repoints nothing.
            listener.RestoreFronts(definition.FrontList);
            return listener;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Stored listener {ListenerId} ({Name}) could not rebind {BindAddress}; skipped. "
                + "Free the port or delete the listener and recreate it.",
                definition.Id, definition.Name, definition.BindAddress);
            return null;
        }
    }

    // The shared bind path: validate, reserve the port, bind per transport
    // shape, and register. A null id mints a fresh one (a create); a given id
    // is honored (a restore, so listener ids survive restarts).
    private async Task<Listener> BindAsync(ListenerConfig config, ListenerId? id, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(config.Name))
            throw new ArgumentException("Listener name is required.", nameof(config));
        if (string.IsNullOrWhiteSpace(config.BindAddress))
            throw new ArgumentException("Listener bind address is required.", nameof(config));

        // A package-backed listener (ADR-025) binds no transport of its own:
        // the medium is the installed package's process, supervised over
        // the bridge. The provider path below stays the in-tree families'.
        if (config.PackageName is not null)
            return await BindPackagedAsync(config, id, cancellationToken).ConfigureAwait(false);

        // A malformed bind address is an operator mistake (400, not 409): the
        // parse shapes are shared with the startup path, rethrown as
        // ArgumentException to say so. The port reservation that follows
        // stays an InvalidOperationException -- a bind refused for an address
        // in use is a conflict (409), not a malformed request.
        // The provider serving the transport's wire name owns everything the
        // bind needs beyond the shared reservation flow below: the shape
        // validation, the reservation, and the bind body itself. An unknown
        // name is a malformed request -- the registry is the authority for
        // what a runtime listener may name.
        var provider = TransportProviders.Find(config.Transport)
            ?? throw new ArgumentException(
                $"Transport '{config.Transport}' is not supported for runtime listeners.", nameof(config));
        try
        {
            provider.Validate(config);
        }
        catch (InvalidOperationException ex)
        {
            throw new ArgumentException(ex.Message, nameof(config));
        }

        provider.ReserveBind(config);

        // The same non-loopback plain-HTTP warning the startup path logs: a
        // deliberate posture choice, named rather than silent.
        if (string.Equals(config.Transport, "http", StringComparison.OrdinalIgnoreCase))
        {
            var (host, _) = TransportHost.ParseBindAddress(config.BindAddress);
            if (!IPAddress.IsLoopback(host))
            {
                _logger.LogWarning(
                    "Runtime listener '{ListenerName}' binds plain HTTP on non-loopback {BindAddress}: "
                    + "the beacon identifies implants by their handshake id alone and the operator API "
                    + "rides the same socket in the clear. Keep plain HTTP on loopback unless a "
                    + "TLS-terminating edge fronts this host (architecture.md Sec 8).",
                    config.Name, config.BindAddress);
            }
        }

        var bound = await provider.BindAsync(
            new TransportBindContext(config, id, _services, _listeners, _endpoints, _clock, _logger),
            cancellationToken).ConfigureAwait(false);
        _runtime[bound.Listener.Id] = new RuntimeEntry(bound.Listener, bound.Service);
        return bound.Listener;
    }

    // The package-backed bind path (ADR-025): resolve the installed package
    // through the catalog, validate the medium parameters against its
    // declared schema, then let the supervisor own the runtime -- the
    // bridge socket and the spawned process. The kernel opens no medium
    // socket of its own; the listener's bind address is the record of what
    // the medium front binds, and its public endpoint is what builds bake.
    private async Task<Listener> BindPackagedAsync(
        ListenerConfig config, ListenerId? id, CancellationToken cancellationToken)
    {
        var catalog = _services.GetRequiredService<Rod.CoreState.Listeners.IListenerPackageCatalog>();
        var package = catalog.Resolve(config.PackageName!, config.PackageVersion, cancellationToken)
            ?? throw new ArgumentException(
                $"No installed listener package '{config.PackageName}'"
                + (config.PackageVersion is null ? "" : $" at version '{config.PackageVersion}'")
                + "; install it into the module store first.", nameof(config));

        if (config.Params is not null)
        {
            var schema = package.Params.ToDictionary(p => p.Name, StringComparer.Ordinal);
            foreach (var name in config.Params.Keys)
            {
                if (!schema.ContainsKey(name))
                    throw new ArgumentException(
                        $"Parameter '{name}' is not one package '{package.Name}' declares; its schema is: "
                        + (schema.Count == 0 ? "(none)" : string.Join(", ", schema.Keys.OrderBy(k => k, StringComparer.Ordinal))) + ".",
                        nameof(config));
            }
        }

        foreach (var required in package.Params.Where(p => p.Required))
        {
            if (config.Params is null || !config.Params.TryGetValue(required.Name, out var value) || string.IsNullOrWhiteSpace(value))
                throw new ArgumentException(
                    $"Parameter '{required.Name}' is required by package '{package.Name}'.", nameof(config));
        }

        // The public endpoint's shape is the package's to declare, not the
        // kernel's to assume: a web-dial package bakes the absolute http(s)
        // URL implants dial (and its scheme is the by-endpoint TLS
        // posture's own answer), a dns-zone package answers for the zone
        // its queries carry -- the same rule the in-tree providers keep,
        // read off the declaration instead of the transport table.
        if (string.Equals(package.EndpointShape, ListenerEndpointShapes.DnsZone, StringComparison.Ordinal))
        {
            if (!PublicEndpointShapes.IsDnsZone(config.PublicEndpoint.Trim().TrimEnd('.')))
            {
                throw new ArgumentException(
                    $"The listener's public endpoint '{config.PublicEndpoint}' must be the DNS zone this package "
                    + "answers for (e.g. c2.example.test); the package declares a dns-zone dial.",
                    nameof(config));
            }
        }
        else if (!Uri.TryCreate(config.PublicEndpoint, UriKind.Absolute, out var publicEndpoint)
            || (publicEndpoint.Scheme != "http" && publicEndpoint.Scheme != "https"))
        {
            throw new ArgumentException(
                $"The listener's public endpoint '{config.PublicEndpoint}' must be an absolute http(s) URL -- "
                + "it is the address builds bake and the bridge's cleartext posture keys off its scheme.",
                nameof(config));
        }
        else if (string.Equals(package.Tls, ListenerTlsPostures.Always, StringComparison.Ordinal)
            && publicEndpoint.Scheme != "https")
        {
            throw new ArgumentException(
                $"The listener's public endpoint '{config.PublicEndpoint}' must be https://: the package declares "
                + "an always-TLS front, so a cleartext dial contradicts the medium.",
                nameof(config));
        }

        var listenerId = id ?? new ListenerId(Guid.NewGuid());
        var parameters = (IReadOnlyDictionary<string, string>?)config.Params
            ?? new Dictionary<string, string>(StringComparer.Ordinal);
        var listener = Listener.DefinePackaged(
            listenerId,
            config.Name,
            package.Name,
            package.Version,
            package.SealTier,
            config.BindAddress,
            config.PublicEndpoint,
            _clock.GetUtcNow(),
            config.EngagementId!.Value);

        var supervisor = _services.GetRequiredService<Bridge.ListenerSupervisor>();
        var options = _services.GetRequiredService<Microsoft.Extensions.Options.IOptions<Bridge.ListenerBridgeOptions>>().Value;
        var supervised = await supervisor.StartAsync(listener, package, parameters, options).ConfigureAwait(false);
        _runtime[listener.Id] = new RuntimeEntry(listener, Service: null, supervised, parameters);
        await _listeners.RegisterAsync(listener, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation(
            "Package-backed listener {ListenerId} ({Name}) bound: package {Package}@{Version}, seal {SealTier}.",
            listener.Id, listener.Name, package.Name, package.Version, package.SealTier);
        return listener;
    }

    /// <summary>
    /// Removes a runtime-created listener: unbinds its socket (stopping its
    /// stream service, or withdrawing its Kestrel endpoint -- Kestrel drains
    /// the socket for up to its shutdown timeout first), takes it out of the
    /// registry, and deletes its persisted definition so a restart does not
    /// resurrect it. Returns false when the listener is not runtime-managed.
    /// </summary>
    public async Task<bool> RemoveAsync(ListenerId listener, CancellationToken cancellationToken = default)
    {
        if (!_runtime.TryRemove(listener, out var entry))
            return false;

        await TearDownAsync(entry.Listener.Id, entry, cancellationToken).ConfigureAwait(false);
        await _definitions.RemoveAsync(listener.Value, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation(
            "Runtime listener {ListenerId} ({Name}) removed.", listener, entry.Listener.Name);
        return true;
    }

    /// <summary>
    /// Unbinds every runtime listener an engagement owns -- retirement closes
    /// the engagement's ingress for good, so its sockets come down with it.
    /// The persisted definitions stay: retirement seals records, it does not
    /// erase them, and the restore path skips a retired engagement's
    /// definitions instead of rebinding them.
    /// </summary>
    public async Task<int> TearDownEngagementAsync(EngagementId engagement, CancellationToken cancellationToken = default)
    {
        var tornDown = 0;
        foreach (var (id, entry) in _runtime.ToArray())
        {
            if (entry.Listener.EngagementId != engagement)
                continue;
            if (!_runtime.TryRemove(id, out _))
                continue;
            await TearDownAsync(id, entry, cancellationToken).ConfigureAwait(false);
            tornDown++;
            _logger.LogInformation(
                "Runtime listener {ListenerId} ({Name}) torn down: engagement retired.", id, entry.Listener.Name);
        }
        return tornDown;
    }

    // The bind teardown shared by removal and retirement: stop the stream
    // service (or withdraw the Kestrel endpoint -- Kestrel drains and unbinds
    // on its own schedule, so the registry entry goes now to stop the roster
    // reporting it), stop the supervised process on a package-backed
    // listener (the child dies with the kernel that spawned it), then drop
    // it from the registry.
    private async Task TearDownAsync(ListenerId id, RuntimeEntry entry, CancellationToken cancellationToken)
    {
        if (entry.Supervised is not null)
        {
            await entry.Supervised.DisposeAsync().ConfigureAwait(false);
        }
        else if (entry.Service is not null)
        {
            await entry.Service.StopAsync(cancellationToken).ConfigureAwait(false);
            if (entry.Service is IAsyncDisposable asyncDisposable)
            {
                await asyncDisposable.DisposeAsync().ConfigureAwait(false);
            }
            else if (entry.Service is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
        else
        {
            // The Kestrel reloader drains and unbinds the endpoint on its own
            // schedule (seconds); the registry entry goes now so the roster
            // stops reporting it immediately.
            _endpoints.WithdrawEndpoint(KestrelEndpointProvider.EndpointKey(id));
        }

        await _listeners.RemoveAsync(id, cancellationToken).ConfigureAwait(false);
    }

    // The persisted shape of a bound, engagement-scoped listener. A
    // package-backed listener carries its package facts and the medium
    // parameters the restart respawns with; a provider-backed one carries
    // none of them.
    private ListenerDefinition DefinitionOf(Listener listener)
    {
        IReadOnlyDictionary<string, string>? parameters = null;
        if (_runtime.TryGetValue(listener.Id, out var entry))
            parameters = entry.PackageParams;
        return new ListenerDefinition(
            listener.Id.Value,
            listener.EngagementId!.Value,
            listener.Name,
            listener.Transport,
            listener.BindAddress,
            listener.PublicEndpoint,
            listener.CreatedAt,
            listener.RepointedAt,
            listener.TrustPosture,
            listener.Fronts,
            listener.PackageName,
            listener.PackageVersion,
            listener.SealTier,
            parameters is null
                ? null
                : System.Text.Json.JsonSerializer.Serialize(parameters, System.Text.Json.JsonSerializerOptions.Web));
    }
}
