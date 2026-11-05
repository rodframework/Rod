using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Listeners;
using Rod.Transport.Listeners;
using Rod.Transport.Listeners.Providers;
using Rod.CoreState.Operators;

namespace Rod.Transport.Endpoints;

/// <summary>
/// The engagement's listener endpoints: the C2 ingress this one engagement
/// owns. Every listener is engagement-scoped -- created here against the
/// engagement in the path, persisted so a restart rebinds it, and enforced at
/// enrollment (a token minted for any other engagement is refused whole on its
/// socket). The bind address is decoupled from the public endpoint implants
/// dial (typically a redirector, architecture.md Sec 8), and a repoint swaps a
/// burned front at runtime without touching the backend. The operator front
/// the UI and API ride is startup configuration, not a listener in this sense:
/// it carries no implant ingress and never appears here.
/// </summary>
public static class ListenerEndpoints
{
    public static IEndpointRouteBuilder MapListenerEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Operator-facing: listener views and actions require an authenticated
        // operator session.
        var group = endpoints
            .MapGroup("/engagements/{engagementId}/listeners")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));

        group.MapGet("/", ListListenersAsync).WithName(nameof(ListListenersAsync));
        group.MapPost("/", CreateListenerAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(CreateListenerAsync));
        group.MapPost("/{id}:repoint", RepointAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(RepointAsync));
        group.MapDelete("/{id}", DeleteListenerAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(DeleteListenerAsync));

        // The enrolled-front management the control plane rides
        // (architecture.md Sec 8): attach a front to an enrolled redirector
        // node (the control channel provisions it with the forwarding rule),
        // detach one, and promote one to primary -- the rotation op that
        // replaces repointing for enrolled fleets.
        group.MapPost("/{id}/fronts", AttachFrontAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(AttachFrontAsync));
        group.MapDelete("/{id}/fronts/{frontId}", DetachFrontAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(DetachFrontAsync));
        group.MapPost("/{id}/fronts/{frontId}:primary", PromoteFrontAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(PromoteFrontAsync));

        return endpoints;
    }

    private static async Task<IResult> AttachFrontAsync(
        string engagementId,
        string id,
        AttachFrontRequest body,
        ClaimsPrincipal user,
        IListenerRegistry listeners,
        IListenerStore definitions,
        CoreState.Redirectors.IRedirectorFleet fleet,
        Redirectors.RedirectorControlHub hub,
        Audit.IAuditStore audit,
        CancellationToken cancellationToken)
    {
        var (error, engagementValue, listenerId) = Resolve(engagementId, id);
        if (error is not null)
            return error;
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();

        var listener = await listeners.FindAsync(listenerId, cancellationToken);
        if (!Owns(listener, engagementValue))
            return Results.NotFound(new Problem("Listener does not exist in this engagement."));

        // The node must be enrolled and live -- a front pointing at a node
        // that cannot receive its rule is a dead endpoint baked into builds.
        if (!RedirectorNodeId.TryParse(body.NodeId, out var nodeId))
            return Results.BadRequest(new Problem("Node id is not a valid identifier."));
        var node = await fleet.FindAsync(nodeId, cancellationToken);
        if (node is null)
            return Results.NotFound(new Problem($"Redirector node {body.NodeId} is not enrolled."));
        if (node.RetiredAt is not null)
            return Results.Conflict(new Problem($"Redirector node {body.NodeId} has been retired."));

        // The datagram relay the dns front rides lands with the DNS-front
        // leg; every other family splices TCP today.
        if (string.Equals(listener!.Transport, "shellcatch", StringComparison.OrdinalIgnoreCase))
            return Results.BadRequest(new Problem(
                "The shellcatch transport fronts no implant dial; fronting is for payload ingress."));

        if (!TryParseListenEndpoint(body.ListenEndpoint, out var listenHost, out var listenPort))
            return Results.BadRequest(new Problem(
                "Listen endpoint must be host:port -- the bind the node opens (a literal IP or wildcard)."));

        // One socket per node: a second front on a port a node already binds
        // would fail at the node, so it is refused here, across every
        // engagement -- the port is the node's, not any engagement's.
        foreach (var other in await listeners.ListAsync(cancellationToken))
        {
            var clash = other.FrontFor(nodeId);
            if (clash is not null && TryParseListenEndpoint(clash.ListenEndpoint, out _, out var clashPort)
                && clashPort == listenPort && other.Id != listenerId)
            {
                return Results.Conflict(new Problem(
                    $"Node {body.NodeId} already binds port {listenPort} for listener '{other.Name}' " +
                    $"({other.Id}) -- a node opens one socket per port."));
            }
        }

        var (publicEndpoint, endpointError) = CompleteFrontPublicEndpoint(listener, listenPort, body.PublicEndpoint);
        if (endpointError is not null || publicEndpoint is null)
            return Results.BadRequest(new Problem(endpointError ?? "The front's public endpoint is required."));

        var front = new CoreState.Listeners.ListenerFront(
            Guid.NewGuid(), nodeId, body.ListenEndpoint.Trim(), publicEndpoint,
            string.IsNullOrWhiteSpace(body.AllowList) ? null : body.AllowList.Trim(), DateTimeOffset.UtcNow);
        listener.AttachFront(front, body.Primary is true, front.AttachedAt);
        await SaveDefinitionAsync(definitions, listener, cancellationToken);
        await hub.PushRulesAsync(nodeId, cancellationToken);
        await audit.AppendAsync(
            Audit.AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagementValue,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "listener.front-attached",
                kind: Audit.AuditEventKind.ListenerFrontChanged,
                payload: $"node='{node.Name}' listen={front.ListenEndpoint} public={front.PublicEndpoint}",
                output: null,
                outcome: front.FrontId.ToString(),
                front.AttachedAt),
            cancellationToken);

        return Results.Created(
            $"/engagements/{engagementId}/listeners/{listenerId}/fronts/{front.FrontId}",
            ListenerFrontResponse.Of(front, isPrimary: listener.Fronts[0].FrontId == front.FrontId, node.Name));
    }

    private static async Task<IResult> DetachFrontAsync(
        string engagementId,
        string id,
        string frontId,
        ClaimsPrincipal user,
        IListenerRegistry listeners,
        IListenerStore definitions,
        Redirectors.RedirectorControlHub hub,
        Audit.IAuditStore audit,
        CancellationToken cancellationToken)
    {
        var (error, engagementValue, listenerId) = Resolve(engagementId, id);
        if (error is not null)
            return error;
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(frontId, out var frontValue))
            return Results.BadRequest(new Problem("Front id is not a valid identifier."));

        var listener = await listeners.FindAsync(listenerId, cancellationToken);
        if (!Owns(listener, engagementValue))
            return Results.NotFound(new Problem("Listener does not exist in this engagement."));

        var front = listener!.Fronts.FirstOrDefault(f => f.FrontId == frontValue);
        if (front is null)
            return Results.NotFound(new Problem("Front does not exist on this listener."));

        listener.DetachFront(frontValue, DateTimeOffset.UtcNow);
        await SaveDefinitionAsync(definitions, listener, cancellationToken);
        await hub.PushRulesAsync(front.NodeId, cancellationToken);
        await audit.AppendAsync(
            Audit.AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagementValue,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "listener.front-detached",
                kind: Audit.AuditEventKind.ListenerFrontChanged,
                payload: $"node={front.NodeId} listen={front.ListenEndpoint} public={front.PublicEndpoint}",
                output: null,
                outcome: front.FrontId.ToString(),
                DateTimeOffset.UtcNow),
            cancellationToken);

        return Results.NoContent();
    }

    private static async Task<IResult> PromoteFrontAsync(
        string engagementId,
        string id,
        string frontId,
        ClaimsPrincipal user,
        IListenerRegistry listeners,
        IListenerStore definitions,
        Audit.IAuditStore audit,
        CancellationToken cancellationToken)
    {
        var (error, engagementValue, listenerId) = Resolve(engagementId, id);
        if (error is not null)
            return error;
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!Guid.TryParse(frontId, out var frontValue))
            return Results.BadRequest(new Problem("Front id is not a valid identifier."));

        var listener = await listeners.FindAsync(listenerId, cancellationToken);
        if (!Owns(listener, engagementValue))
            return Results.NotFound(new Problem("Listener does not exist in this engagement."));

        if (!listener!.PromoteFront(frontValue, DateTimeOffset.UtcNow))
            return Results.NotFound(new Problem("Front does not exist on this listener."));

        // The promotion moved the public endpoint builds bake; the rule set
        // is unchanged (rules are per front, not per primarity), so nothing
        // is pushed.
        await SaveDefinitionAsync(definitions, listener, cancellationToken);
        var front = listener.Fronts[0];
        await audit.AppendAsync(
            Audit.AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagementValue,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "listener.front-primary",
                kind: Audit.AuditEventKind.ListenerFrontChanged,
                payload: $"node={front.NodeId} listen={front.ListenEndpoint} public={front.PublicEndpoint}",
                output: null,
                outcome: front.FrontId.ToString(),
                DateTimeOffset.UtcNow),
            cancellationToken);

        return Results.Ok(ListenerFrontResponse.Of(front, isPrimary: true));
    }

    // The definition follows every front change, so the restore pass after a
    // restart rebinds the same front list -- the same property repointing
    // keeps for the public endpoint.
    private static Task SaveDefinitionAsync(IListenerStore definitions, Listener listener, CancellationToken cancellationToken)
        => definitions.SaveAsync(
            new CoreState.Listeners.ListenerDefinition(
                listener.Id.Value,
                listener.EngagementId!.Value,
                listener.Name,
                listener.Transport,
                listener.BindAddress,
                listener.PublicEndpoint,
                listener.CreatedAt,
                listener.RepointedAt,
                listener.TrustPosture,
                listener.Fronts),
            cancellationToken);

    // A front's public endpoint completes exactly like the listener's own:
    // the web-dial family derives from the node's listen port, every other
    // family demands the shape spelled out. The DNS family is the
    // exception by meaning: a front of a dns or doh listener names the
    // RESOLVER implants dial (host or host:port -- the listener's own
    // public endpoint stays the zone), so it never completes and never
    // takes a scheme.
    private static (string? Endpoint, string? Error) CompleteFrontPublicEndpoint(
        Listener listener,
        int listenPort,
        string? input)
    {
        var value = input?.Trim() ?? "";

        if (listener.Transport.Equals("dns", StringComparison.OrdinalIgnoreCase)
            || listener.Transport.Equals("doh", StringComparison.OrdinalIgnoreCase))
        {
            if (value.Length == 0)
                return (null,
                    "The front of a dns or doh listener names the resolver implants dial " +
                    "(host or host:port) -- the zone stays the listener's own public endpoint.");
            if (value.Contains("://") || value.Contains('/'))
                return (null,
                    $"The resolver address '{value}' is a bare host or host:port -- the zone rides the listener record, not the front.");
            if (value.Contains(':') && !PublicEndpointShapes.IsHostPort(value))
                return (null, $"The resolver address '{value}' is not a host:port pair.");
            return (value, null);
        }

        var provider = TransportProviders.Find(listener.Transport);
        if (provider is KestrelEndpointProvider { EndpointShape: PublicEndpointShape.WebDial })
        {
            if (value.Length == 0)
            {
                return (null,
                    "The front's public endpoint is required -- name the host implants dial through this node " +
                    "(its scheme and port complete from the listen endpoint).");
            }

            if (PublicEndpointShapes.IsAbsoluteHttpUrl(value))
                return (value, null);
            if (PublicEndpointShapes.IsHostPort(value))
                return ($"{provider.PublicEndpointScheme}://{value}", null);
            if (value.Contains(':'))
                return (null,
                    $"The public endpoint '{value}' is neither an absolute http(s) URL nor a host:port pair.");
            return ($"{provider.PublicEndpointScheme}://{value}:{listenPort}", null);
        }

        if (value.Length == 0)
            return (null,
                $"The front's public endpoint is required for the {listener.Transport} transport: " +
                "the zone or host:port implants dial cannot be derived from the node's listen endpoint.");
        if (!provider!.AcceptsPublicEndpoint(value))
            return (null, provider.DescribePublicEndpointRule(value));
        return (value, null);
    }

    private static bool TryParseListenEndpoint(string? endpoint, out string host, out int port)
    {
        host = "";
        port = 0;
        if (string.IsNullOrWhiteSpace(endpoint))
            return false;
        var value = endpoint.Trim();
        var colon = value.LastIndexOf(':');
        if (colon <= 0 || colon == value.Length - 1)
            return false;
        host = value[..colon].TrimStart('[').TrimEnd(']');
        return host.Length > 0 && int.TryParse(value[(colon + 1)..], out port) && port is > 0 and <= 65535;
    }

    private static async Task<IResult> CreateListenerAsync(
        string engagementId,
        CreateListenerRequest body,
        ClaimsPrincipal user,
        ListenerManager manager,
        IEngagementRepository engagements,
        Audit.IAuditStore audit,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(body.Name))
            return Results.BadRequest(new Problem("Listener name is required."));

        // A package-backed listener (ADR-025) names an installed listener
        // package, not a transport: the medium is the package's process,
        // supervised over the bridge, and nothing here derives from a
        // provider. The bind address is the record of what the medium front
        // binds; the public endpoint is what builds bake, spelled in the
        // shape the package declares -- a web dial's absolute http(s) URL or
        // a DNS medium's zone -- a fact only the resolved package can state,
        // so the manager's bind path is the authority (its refusals map to
        // the operator's 400s below).
        if (!string.IsNullOrWhiteSpace(body.Package))
        {
            if (!Guid.TryParse(engagementId, out var packagedEngagement))
                return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
            if (await engagements.FindAsync(new EngagementId(packagedEngagement), cancellationToken) is null)
                return Results.NotFound(new Problem("Engagement does not exist."));
            if (string.IsNullOrWhiteSpace(body.BindAddress))
                return Results.BadRequest(new Problem("Bind address is required (what the medium front binds)."));
            if (string.IsNullOrWhiteSpace(body.PublicEndpoint))
                return Results.BadRequest(new Problem(
                    "The public endpoint is required -- it is the address builds bake, in the shape the package declares."));

            try
            {
                var packaged = await manager.CreateAsync(
                    new ListenerConfig(
                        body.Name.Trim(), body.Package.Trim(), body.BindAddress.Trim(), body.PublicEndpoint!.Trim(),
                        new EngagementId(packagedEngagement),
                        Params: body.Params is null
                            ? null
                            : new Dictionary<string, string>(body.Params, StringComparer.Ordinal),
                        PackageName: body.Package.Trim(),
                        PackageVersion: body.PackageVersion?.Trim() is { Length: > 0 } version ? version : null),
                    cancellationToken);

                var packagedOperator = user.TryGetOperatorId();
                if (packagedOperator is not null)
                {
                    await audit.AppendAsync(
                        Audit.AuditEvent.Fact(
                            eventId: Guid.NewGuid(),
                            engagementId: packagedEngagement,
                            operatorId: packagedOperator.Value.Value,
                            implantId: Guid.Empty,
                            taskId: Guid.Empty,
                            verb: "listener.created",
                            kind: Audit.AuditEventKind.ListenerChanged,
                            payload: $"'{packaged.Name}' package={packaged.PackageName}@{packaged.PackageVersion} "
                                + $"seal={packaged.SealTier} bind={packaged.BindAddress} public={packaged.PublicEndpoint}",
                            output: null,
                            outcome: packaged.Id.ToString(),
                            packaged.CreatedAt),
                        cancellationToken);
                }

                return Results.Created(
                    $"/engagements/{engagementId}/listeners/{packaged.Id}", Response.Of(packaged));
            }
            catch (ArgumentException ex)
            {
                // An unknown package, a parameter the schema does not carry:
                // an operator mistake.
                return Results.BadRequest(new Problem(ex.Message));
            }
            catch (InvalidOperationException ex)
            {
                // The package violates the seal rule, or its process refused
                // to start: a conflict-shaped refusal.
                return Results.Conflict(new Problem(ex.Message));
            }
            catch (IOException ex)
            {
                // The bridge socket could not bind.
                return Results.Conflict(new Problem(ex.Message));
            }
        }

        var provider = TransportProviders.Find(body.Transport?.Trim());
        if (provider is null)
            return Results.BadRequest(new Problem(
                "Transport is not recognized. Use one of: " +
                string.Join(", ", TransportProviders.Names()) + "."));
        if (string.IsNullOrWhiteSpace(body.BindAddress))
            return Results.BadRequest(new Problem("Bind address is required."));
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (await engagements.FindAsync(new EngagementId(engagementValue), cancellationToken) is null)
            return Results.NotFound(new Problem("Engagement does not exist."));

        // The public endpoint is what a payload dials, so an incomplete value
        // must not ride into builds -- but incompleteness is cheap to fix
        // here. On the HTTP-shaped transports a blank endpoint means "implants
        // dial this bind itself" (the no-redirector shape) and derives from
        // the bind; a bare hostname takes the transport's scheme and the
        // listener's own bind port; a host:port pair is completed with the
        // transport's scheme; an absolute URL passes through verbatim. The
        // stored form is always complete, so the roster and every build read
        // one uniform shape. The stream transports cannot derive -- a DNS
        // zone or pipe path is not a function of the bind -- so they require
        // it spelled out.
        string publicEndpoint;
        // Only the web-dial Kestrel family derives its endpoint from the
        // bind; a zone-shaped Kestrel transport (DoH) requires the zone
        // spelled out, exactly like the socket-owning zone transport.
        if (provider is KestrelEndpointProvider { EndpointShape: PublicEndpointShape.WebDial })
        {
            var derived = DeriveHttpPublicEndpoint(provider, body.BindAddress.Trim(), body.PublicEndpoint);
            if (derived is not null)
            {
                publicEndpoint = derived;
            }
            else if (string.IsNullOrWhiteSpace(body.PublicEndpoint))
            {
                // The one blank the derivation refuses: a wildcard bind is
                // every interface, not an address anything can dial. Name
                // that instead of restating the endpoint rule the operator
                // just followed. (A malformed bind also lands here and falls
                // through, so the manager's bind validation names it.)
                if (IsWildcardBind(body.BindAddress.Trim()))
                {
                    return Results.BadRequest(new Problem(
                        "A wildcard bind (0.0.0.0 or ::) is every interface, not an address implants can "
                        + "dial, so the public endpoint cannot be left empty for it -- type the hostname "
                        + "implants should reach (e.g. c2.example.test)."));
                }
                publicEndpoint = "";
            }
            else if (PublicEndpointShapes.IsAbsoluteHttpUrl(body.PublicEndpoint.Trim()))
            {
                // A complete endpoint with an underivable bind: the manager's
                // bind validation names the real problem (a 400 with its
                // message), so fall through instead of blaming the endpoint.
                publicEndpoint = body.PublicEndpoint.Trim();
            }
            else if (PublicEndpointShapes.IsHostPort(body.PublicEndpoint.Trim()))
            {
                // The same completion the derivation applies, kept for the
                // underivable-bind fall-through so a host:port never rides
                // into builds scheme-less.
                publicEndpoint = $"{provider.PublicEndpointScheme}://{body.PublicEndpoint.Trim()}";
            }
            else
            {
                return Results.BadRequest(new Problem(
                    provider.DescribePublicEndpointRule(body.PublicEndpoint ?? "")));
            }
        }
        else
        {
            if (string.IsNullOrWhiteSpace(body.PublicEndpoint))
                return Results.BadRequest(new Problem(
                    $"Public endpoint is required for the {provider.Transport} transport: the zone or path implants dial cannot be derived from the bind."));
            if (!provider.AcceptsPublicEndpoint(body.PublicEndpoint))
                return Results.BadRequest(new Problem(provider.DescribePublicEndpointRule(body.PublicEndpoint)));
            publicEndpoint = body.PublicEndpoint.Trim();
        }

        // Whose certificate the front presents -- the fact builds inherit as
        // their TLS roots (architecture.md Sec 9). The listener owns it
        // because the certificate is deployed where the listener is: the
        // engagement CA terminates a pinned front, an operator-run edge with
        // a real-domain certificate terminates a public one. Public rides an
        // https dial alone -- the posture only has meaning where the implant
        // performs a handshake it must verify.
        var trust = body.Trust?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(trust))
            trust = "pinned";
        if (trust is not ("pinned" or "public"))
            return Results.BadRequest(new Problem(
                "Trust must be 'pinned' (the default -- the engagement CA terminates the front) "
                + "or 'public' (a real-domain front whose certificate an operator-run edge terminates)."));
        if (trust == "public"
            && (!Uri.TryCreate(publicEndpoint, UriKind.Absolute, out var dial)
                || dial.Scheme != Uri.UriSchemeHttps))
            return Results.BadRequest(new Problem(
                "Trust 'public' rides an https dial -- the public endpoint must name the real domain "
                + "an operator-run edge terminates (https://...); leave Trust unset for the engagement CA."));

        try
        {
            var listener = await manager.CreateAsync(
                new ListenerConfig(
                    body.Name.Trim(), provider.Transport, body.BindAddress.Trim(), publicEndpoint,
                    new EngagementId(engagementValue), trust),
                cancellationToken);

            // The lifecycle fact the front changes already write (Sec 8):
            // what came onto the wire, where it binds, and what implants
            // dial -- the trail must outlive the listener it names.
            var operatorId = user.TryGetOperatorId();
            if (operatorId is not null)
            {
                await audit.AppendAsync(
                    Audit.AuditEvent.Fact(
                        eventId: Guid.NewGuid(),
                        engagementId: engagementValue,
                        operatorId: operatorId.Value.Value,
                        implantId: Guid.Empty,
                        taskId: Guid.Empty,
                        verb: "listener.created",
                        kind: Audit.AuditEventKind.ListenerChanged,
                        payload: $"'{listener.Name}' transport={listener.Transport} bind={listener.BindAddress} public={listener.PublicEndpoint} trust={trust}",
                        output: null,
                        outcome: listener.Id.ToString(),
                        listener.CreatedAt),
                    cancellationToken);
            }

            return Results.Created($"/engagements/{engagementId}/listeners/{listener.Id}", Response.Of(listener));
        }
        catch (ArgumentException ex)
        {
            // A malformed bind address or an unknown engagement: an operator
            // mistake.
            return Results.BadRequest(new Problem(ex.Message));
        }
        catch (InvalidOperationException ex)
        {
            // The bind was refused (address in use, socket never opened).
            return Results.Conflict(new Problem(ex.Message));
        }
    }

    // Deleting a listener that live implants enrolled through cuts their
    // ingress: they keep dialing an endpoint nobody serves and go dark. The
    // guard counts those implants (retired ones are out of operation and do
    // not count) and refuses with the count unless the caller forces -- the
    // two-step delete the operator UI walks.
    private static async Task<IResult> DeleteListenerAsync(
        string engagementId,
        string id,
        bool? force,
        ClaimsPrincipal user,
        ListenerManager manager,
        IListenerRegistry listeners,
        IImplantRepository implants,
        Audit.IAuditStore audit,
        CancellationToken cancellationToken)
    {
        var (error, engagementIdValue, listenerId) = Resolve(engagementId, id);
        if (error is not null)
            return error;

        var listener = await listeners.FindAsync(listenerId, cancellationToken);
        if (!Owns(listener, engagementIdValue))
            return Results.NotFound(new Problem("Listener does not exist in this engagement."));

        if (force is not true)
        {
            var enrolled = (await implants.ListByEngagementAsync(
                    new EngagementId(engagementIdValue), cancellationToken))
                .Where(i => i.EnrolledViaListenerId == listenerId.Value && !i.IsRetired)
                .ToArray();
            if (enrolled.Length > 0)
            {
                var names = string.Join(", ", enrolled
                    .Select(i => i.Hostname ?? i.Id.ToString())
                    .Take(3));
                return Results.Conflict(new Problem(
                    $"{enrolled.Length} live implant{(enrolled.Length == 1 ? "" : "s")} enrolled through listener " +
                    $"'{listener!.Name}' ({names}{(enrolled.Length > 3 ? ", …" : "")}) lose this ingress and go " +
                    "dark. Delete anyway with force=true."));
            }
        }

        await manager.RemoveAsync(listenerId, cancellationToken);

        // The trail outlives the listener: the deletion names what went
        // away and whether the operator forced it past the live-implant
        // guard.
        var operatorId = user.TryGetOperatorId();
        if (operatorId is not null)
        {
            await audit.AppendAsync(
                Audit.AuditEvent.Fact(
                    eventId: Guid.NewGuid(),
                    engagementId: engagementIdValue,
                    operatorId: operatorId.Value.Value,
                    implantId: Guid.Empty,
                    taskId: Guid.Empty,
                    verb: "listener.deleted",
                    kind: Audit.AuditEventKind.ListenerChanged,
                    payload: $"'{listener!.Name}' transport={listener.Transport} bind={listener.BindAddress} public={listener.PublicEndpoint} forced={force is true}",
                    output: null,
                    outcome: listener.Id.ToString(),
                    DateTimeOffset.UtcNow),
                cancellationToken);
        }

        return Results.NoContent();
    }

    private static async Task<IResult> ListListenersAsync(
        string engagementId,
        IListenerRegistry listeners,
        CoreState.Redirectors.IRedirectorFleet fleet,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        // Each front row names its redirector; one roster read serves the
        // whole listing (the attach response carries the name, the listing
        // must too or the roster shows bare ids after every refresh).
        var nodeNames = (await fleet.ListNodesAsync(cancellationToken))
            .ToDictionary(n => n.Id, n => n.Name);
        var owned = (await listeners.ListAsync(cancellationToken))
            .Where(l => l.EngagementId == new EngagementId(engagementValue))
            .Select(l => Response.Of(l, nodeNames))
            .ToArray();
        return Results.Ok(owned);
    }

    private static async Task<IResult> RepointAsync(
        string engagementId,
        string id,
        RepointListenerRequest body,
        ClaimsPrincipal user,
        IListenerRegistry listeners,
        IListenerStore definitions,
        Audit.IAuditStore audit,
        CancellationToken cancellationToken)
    {
        var (error, engagementIdValue, listenerId) = Resolve(engagementId, id);
        if (error is not null)
            return error;

        var existing = await listeners.FindAsync(listenerId, cancellationToken);
        if (existing is null || existing.EngagementId != new EngagementId(engagementIdValue))
            return Results.NotFound(new Problem("Listener does not exist in this engagement."));
        if (string.IsNullOrWhiteSpace(body.PublicEndpoint))
            return Results.BadRequest(new Problem("Public endpoint is required."));

        // A stored endpoint is always complete: an absolute http(s) URL
        // passes through, a bare hostname takes the transport's scheme and
        // the listener's own bind port, and a host:port pair takes the
        // transport's scheme -- the same completion a create applies, so a
        // repoint never demands more typing than a create and the roster
        // keeps one uniform shape.
        var endpoint = body.PublicEndpoint.Trim();
        if (!PublicEndpointShapes.IsAbsoluteHttpUrl(endpoint))
        {
            var scheme = TransportProviders.Find(existing.Transport)?.PublicEndpointScheme ?? "https";
            var completed = PublicEndpointShapes.IsHostPort(endpoint)
                ? $"{scheme}://{endpoint}"
                : CompleteBareHost(existing, endpoint);
            if (completed is null)
                return Results.BadRequest(new Problem(
                    "Public endpoint must be an absolute http(s) URL, a host:port pair, or a bare "
                    + $"hostname -- each completed with the listener's scheme and port -- got '{body.PublicEndpoint}'."));
            endpoint = completed;
        }

        // Repoint swaps the public endpoint -- the redirector implants dial --
        // without touching the bound socket (architecture.md Sec 7/8). The
        // bind address stays put, so a live listener keeps serving; the registry's
        // public-endpoint lookup now resolves the new endpoint and no longer
        // resolves the old one (a burned redirector is severed). The old
        // endpoint is captured before the swap -- the registry hands back
        // the same mutable entity the repoint rewrites.
        var severedEndpoint = existing.PublicEndpoint;
        var listener = await listeners.RepointAsync(listenerId, endpoint, cancellationToken);
        if (listener is null)
            return Results.NotFound(new Problem("Listener does not exist in this engagement."));

        // The definition follows the repoint, so the restore pass after a
        // restart rebinds the current front, not the burned one.
        await definitions.SaveAsync(
            new ListenerDefinition(
                listener!.Id.Value,
                listener.EngagementId!.Value,
                listener.Name,
                listener.Transport,
                listener.BindAddress,
                listener.PublicEndpoint,
                listener.CreatedAt,
                listener.RepointedAt,
                listener.TrustPosture,
                listener.Fronts),
            cancellationToken);

        // The burn-handling move is the one fact an engagement review most
        // needs placed in time: which endpoint was severed, for which
        // listener, by whom.
        var operatorId = user.TryGetOperatorId();
        if (operatorId is not null)
        {
            await audit.AppendAsync(
                Audit.AuditEvent.Fact(
                    eventId: Guid.NewGuid(),
                    engagementId: engagementIdValue,
                    operatorId: operatorId.Value.Value,
                    implantId: Guid.Empty,
                    taskId: Guid.Empty,
                    verb: "listener.repointed",
                    kind: Audit.AuditEventKind.ListenerChanged,
                    payload: $"'{listener.Name}' public {severedEndpoint} -> {listener.PublicEndpoint}",
                    output: null,
                    outcome: listener.Id.ToString(),
                    listener.RepointedAt ?? DateTimeOffset.UtcNow),
                cancellationToken);
        }

        return Results.Ok(Response.Of(listener));
    }

    // Shared id resolution for the scoped routes: both ids parse or the
    // request is a 400 before anything is touched.
    private static (IResult? Error, Guid EngagementId, ListenerId ListenerIdValue) Resolve(
        string engagementId, string id)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return (Results.BadRequest(new Problem("Engagement id is not a valid identifier.")), Guid.Empty, default);
        if (!ListenerId.TryParse(id, out var listenerId))
            return (Results.BadRequest(new Problem("Listener id is not a valid identifier.")), Guid.Empty, default);
        return (null, engagementValue, listenerId);
    }

    // A listener answers for the engagement when it is scoped to it; anything
    // else (another engagement's, or the startup-configuration tier) reads as
    // not-existing from this engagement's routes.
    private static bool Owns(Listener? listener, Guid engagementId)
        => listener?.EngagementId == new EngagementId(engagementId);

    // The create-time completion for the HTTP-shaped transports: blank
    // derives the whole endpoint from the bind (implants dial this server
    // directly -- the no-redirector shape), a bare hostname takes the
    // transport's scheme and the listener's own bind port, a host:port pair
    // takes the transport's scheme, and an absolute URL passes through
    // verbatim. Returns null when nothing honest can be derived (a wildcard
    // bind has no dialable name) or the value is not a dialable shape at all.
    private static string? DeriveHttpPublicEndpoint(
        ITransportProvider provider, string bindAddress, string? publicEndpoint)
    {
        (IPAddress Host, int Port) bind;
        try
        {
            bind = TransportHost.ParseBindAddress(bindAddress);
        }
        catch
        {
            // A malformed bind is the manager's refusal to name (or the
            // fall-through above passes a complete endpoint to it); nothing
            // to derive from here.
            return null;
        }

        var value = publicEndpoint?.Trim() ?? "";
        if (value.Length == 0)
        {
            if (IsWildcard(bind.Host))
                return null;
            return $"{provider.PublicEndpointScheme}://{HostText(bind.Host)}:{bind.Port}";
        }

        if (PublicEndpointShapes.IsAbsoluteHttpUrl(value))
            return value;

        if (PublicEndpointShapes.IsHostPort(value))
            return $"{provider.PublicEndpointScheme}://{value}";

        if (PublicEndpointShapes.IsBareHost(value))
            return $"{provider.PublicEndpointScheme}://{value}:{bind.Port}";

        return null;
    }

    // The repoint-time completion: a bare hostname takes the listener's
    // transport scheme and its own bind port.
    private static string? CompleteBareHost(Listener listener, string endpoint)
    {
        var scheme = TransportProviders.Find(listener.Transport)?.PublicEndpointScheme ?? "https";
        return PublicEndpointShapes.IsBareHost(endpoint)
            ? $"{scheme}://{endpoint}:{BindPortOf(listener.BindAddress)}"
            : null;
    }

    // A wildcard bind covers every interface, which is a legitimate way to
    // open the socket -- but it names no single address, so nothing can dial
    // it and no public endpoint derives from it.
    private static bool IsWildcard(IPAddress host)
        => host.Equals(IPAddress.Any) || host.Equals(IPAddress.IPv6Any);

    private static bool IsWildcardBind(string bindAddress)
    {
        try
        {
            return IsWildcard(TransportHost.ParseBindAddress(bindAddress).Host);
        }
        catch
        {
            return false;
        }
    }

    // IPv6 authorities need their brackets; everything else stringifies as
    // dialable.
    private static string HostText(IPAddress host)
        => host.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{host}]"
            : host.ToString();

    private static int BindPortOf(string bindAddress)
    {
        var colon = bindAddress.LastIndexOf(':');
        return int.TryParse(bindAddress[(colon + 1)..], out var port) ? port : 0;
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    /// <summary>
    /// Request to create one of this engagement's listeners. The transport
    /// names a registered provider's wire name (case-insensitive); the bind
    /// address is the socket this server opens (host:port for every network
    /// transport, a bare pipe name for SMB); the public endpoint is the
    /// address implants dial. The engagement comes from the route, never the
    /// body. The definition is persisted, so a restart rebinds it.
    /// </summary>
    public sealed record CreateListenerRequest(
        string Name,
        string Transport,
        string BindAddress,
        string PublicEndpoint,
        string? Trust = null,
        string? Package = null,
        string? PackageVersion = null,
        IReadOnlyDictionary<string, string>? Params = null);

    /// <summary>
    /// Request to repoint a listener's public endpoint. The new endpoint is the
    /// redirector or host-header implants should dial after the swap.
    /// </summary>
    public sealed record RepointListenerRequest(string PublicEndpoint);

    public sealed record ListenerResponse(
        string Id,
        string Name,
        string Transport,
        string BindAddress,
        string PublicEndpoint,
        string TrustPosture,
        string State,
        DateTimeOffset CreatedAt,
        DateTimeOffset? RepointedAt,
        IReadOnlyList<ListenerFrontResponse> Fronts,
        string? Package = null,
        string? PackageVersion = null,
        string? SealTier = null);

    /// <summary>
    /// Request to attach a front to an enrolled redirector node. The node
    /// binds <see cref="ListenEndpoint"/> and splices it to the listener's
    /// bind; implants dial <see cref="PublicEndpoint"/> (completed like the
    /// listener's own for the transport family). <see cref="Primary"/>
    /// inserts at the head of the front list and repoints the listener;
    /// without it the front appends.
    /// </summary>
    public sealed record AttachFrontRequest(
        string NodeId,
        string ListenEndpoint,
        string? PublicEndpoint = null,
        string? AllowList = null,
        bool? Primary = null);

    public sealed record ListenerFrontResponse(
        string FrontId,
        string NodeId,
        string NodeName,
        string ListenEndpoint,
        string PublicEndpoint,
        string? AllowList,
        bool IsPrimary,
        DateTimeOffset AttachedAt)
    {
        public static ListenerFrontResponse Of(CoreState.Listeners.ListenerFront front, bool isPrimary, string nodeName = "")
            => new(
                front.FrontId.ToString(),
                front.NodeId.ToString(),
                nodeName,
                front.ListenEndpoint,
                front.PublicEndpoint,
                front.AllowList,
                isPrimary,
                front.AttachedAt);
    }

    private static class Response
    {
        public static ListenerResponse Of(
            Listener l,
            IReadOnlyDictionary<CoreState.RedirectorNodeId, string>? nodeNames = null)
        {
            nodeNames ??= new Dictionary<CoreState.RedirectorNodeId, string>();
            return new ListenerResponse(
                l.Id.ToString(),
                l.Name,
                // The transport's wire name (the registry key a provider
                // registered under), which the listing and the operator UI
                // render verbatim.
                l.Transport,
                l.BindAddress,
                l.PublicEndpoint,
                l.TrustPosture,
                l.State.ToString().ToLowerInvariant(),
                l.CreatedAt,
                l.RepointedAt,
                l.Fronts.Select(f => ListenerFrontResponse.Of(
                    f,
                    isPrimary: f.FrontId == l.Fronts.FirstOrDefault()?.FrontId,
                    nodeNames.GetValueOrDefault(f.NodeId, ""))).ToList(),
                l.PackageName,
                l.PackageVersion,
                l.SealTier);
        }
    }

}
