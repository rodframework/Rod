using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Operators;
using Rod.Operators.Workbench;

namespace Rod.Operators.Endpoints;

/// <summary>
/// The external recon workbench's routes (architecture.md Sec 11.4): the
/// pre-foothold scoping surface. Three actions, all Task-scope gated --
/// each acts on the engagement (egress under its attribution, evidence
/// written to its trail), the artifact-attach posture rather than the read
/// projection's -- and all refused while the engagement is closed, because
/// a frozen trail is final and the workbench appends to it like any other
/// act:
///
/// <list type="bullet">
/// <item><c>POST /engagements/{id}/recon:rdap</c> -- registration data for
/// a named domain, captured as a JSON artifact.</item>
/// <item><c>POST /engagements/{id}/recon:subdomains</c> -- the CT-log name
/// census under a domain, captured as JSON-lines findings.</item>
/// <item><c>POST /engagements/{id}/recon:resolve</c> -- names (or one
/// name, or an address for its PTR) through the configured resolver, the
/// answers captured as address-bearing host lines.</item>
/// <item><c>POST /engagements/{id}/recon:portscan</c> -- a TCP connect
/// scan, gated on the engagement's ROE target scope before any connection
/// opens, captured as JSON-lines findings.</item>
/// </list>
///
/// The egress is config-gated per half (the LLM client's opt-in
/// discipline): an unset service base or scan origin answers 503 naming
/// the configuration section and the runbook, never a silent default.
/// Every attempt -- succeeded, failed, or ROE-refused -- lands in the
/// trail; the runbook records the decisions this surface delegates
/// (docs/operations/recon.md).
/// </summary>
public static class ReconWorkbenchEndpoints
{
    public static IEndpointRouteBuilder MapReconWorkbenchEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/engagements/{engagementId}/recon:rdap", RdapAsync)
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(RdapAsync));
        endpoints.MapPost("/engagements/{engagementId}/recon:subdomains", SubdomainsAsync)
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(SubdomainsAsync));
        endpoints.MapPost("/engagements/{engagementId}/recon:portscan", PortscanAsync)
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(PortscanAsync));
        endpoints.MapPost("/engagements/{engagementId}/recon:resolve", ResolveAsync)
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(ResolveAsync));
        return endpoints;
    }

    private static async Task<IResult> RdapAsync(
        string engagementId,
        ReconLookupRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        ReconWorkbenchService workbench,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var gate = await ResolveEngagementAsync(engagementId, body.Target, user, engagements, allowAddress: false, cancellationToken);
        if (gate.Response is { } refused)
            return refused;
        if (!workbench.RdapConfigured)
            return Unconfigured("RDAP lookup", "Recon:RdapBaseUrl");

        var result = await workbench.RdapLookupAsync(
            gate.EngagementId!.Value, gate.OperatorId!.Value, gate.Target!, cancellationToken);

        // Whois behind the RDAP flag (Sec 11.4): a registry without the
        // domain on record -- the ccTLD half of the world that never built
        // RDAP -- falls back to the configured whois server. One event
        // covers the run, its lookup name carrying the fallback.
        var lookup = "rdap";
        if (!result.Succeeded && result.RegistryMiss && workbench.WhoisConfigured)
        {
            result = await workbench.WhoisLookupAsync(
                gate.EngagementId!.Value, gate.OperatorId!.Value, gate.Target!, cancellationToken);
            lookup = "rdap>whois";
        }

        return await RespondAsync(
            gate, result, lookup, AuditEventKind.ReconLookupCompleted, audit, clock, cancellationToken);
    }

    private static async Task<IResult> SubdomainsAsync(
        string engagementId,
        ReconLookupRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        ReconWorkbenchService workbench,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var gate = await ResolveEngagementAsync(engagementId, body.Target, user, engagements, allowAddress: false, cancellationToken);
        if (gate.Response is { } refused)
            return refused;
        if (!workbench.CtConfigured)
            return Unconfigured("certificate-transparency lookup", "Recon:CtBaseUrl");

        var result = await workbench.EnumerateSubdomainsAsync(
            gate.EngagementId!.Value, gate.OperatorId!.Value, gate.Target!, cancellationToken);
        return await RespondAsync(
            gate, result, "subdomains", AuditEventKind.ReconLookupCompleted, audit, clock, cancellationToken);
    }

    private static async Task<IResult> PortscanAsync(
        string engagementId,
        ReconScanRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        ReconWorkbenchService workbench,
        IAuditStore audit,
        TimeProvider clock,
        IOptions<ReconWorkbenchOptions> options,
        CancellationToken cancellationToken)
    {
        var gate = await ResolveEngagementAsync(engagementId, body.Target, user, engagements, allowAddress: true, cancellationToken);
        if (gate.Response is { } refused)
            return refused;

        // Authorization precedes capability: the ROE target-scope gate runs
        // before the origin check, and a target outside the profile is
        // refused and audited even on a teamserver whose scan origin is not
        // configured -- the refusal is a fact about the engagement's scope,
        // not about this host's setup.
        var violated = gate.Roe!.EvaluateTarget(gate.Target!);
        if (violated is not null)
        {
            await audit.AppendAsync(
                AuditEvent.Fact(
                    eventId: Guid.NewGuid(),
                    engagementId: gate.EngagementId!.Value,
                    operatorId: gate.OperatorId!.Value,
                    implantId: Guid.Empty,
                    taskId: Guid.Empty,
                    verb: "recon.portscan",
                    kind: AuditEventKind.ReconScanRefused,
                    payload: $"portscan;{gate.Target};{PortsLabel(body.Ports)}",
                    output: null,
                    outcome: violated,
                    at: clock.GetUtcNow()),
                cancellationToken);
            return Results.Json(
                new Problem(violated),
                statusCode: StatusCodes.Status422UnprocessableEntity);
        }

        // The scan origin is the OPSEC decision this route refuses to make
        // silently: unnamed, or named but not a shape this teamserver ships,
        // the route stays closed and the message points at the runbook.
        var scanOptions = options.Value;
        if (scanOptions.ScanOriginUnsupported)
            return Results.Json(
                new Problem($"Scan origin '{scanOptions.ScanOrigin}' is not supported by this teamserver. Set Recon:ScanOrigin to a supported origin (Teamserver); see docs/operations/recon.md."),
                statusCode: StatusCodes.Status503ServiceUnavailable);
        if (!scanOptions.ScanConfigured)
            return Unconfigured("scan", "Recon:ScanOrigin (Teamserver)");

        if (TryParsePorts(body.Ports, scanOptions.ScanMaxPorts) is not { Count: > 0 } ports)
            return Results.BadRequest(new Problem(
                $"Ports must be a comma list with optional hyphen ranges (e.g. '22,80,443' or '1-1024'), at most {scanOptions.ScanMaxPorts} ports, each 1-65535; omit for the default top-ports set."));

        var result = await workbench.ScanAsync(
            gate.EngagementId!.Value, gate.OperatorId!.Value, gate.Target!, ports,
            PortsLabel(body.Ports), cancellationToken);
        return await RespondAsync(
            gate, result, "portscan", AuditEventKind.ReconScanCompleted, audit, clock, cancellationToken);
    }

    // The resolution route (Sec 11.4's "which of the enumerated names
    // live"): one target or a bounded list of them, each a hostname (its
    // addresses, the alias along for the chain) or an IP literal (its PTR
    // name). Passive like its lookup siblings -- ungated by the ROE target
    // scope, because the scope is often what the answers inform.
    private static async Task<IResult> ResolveAsync(
        string engagementId,
        ReconResolveRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        ReconWorkbenchService workbench,
        IAuditStore audit,
        TimeProvider clock,
        IOptions<ReconWorkbenchOptions> options,
        CancellationToken cancellationToken)
    {
        // Exactly one of target or targets names the ask.
        var hasTarget = !string.IsNullOrWhiteSpace(body.Target);
        var hasTargets = body.Targets is { Count: > 0 };
        if (hasTarget == hasTargets)
            return Results.BadRequest(new Problem("Name exactly one of 'target' or 'targets'."));

        // The first name walks the shared ladder (engagement, closed,
        // target grammar); the rest get the same grammar check below.
        var gate = await ResolveEngagementAsync(
            engagementId,
            hasTarget ? body.Target : body.Targets![0],
            user, engagements, allowAddress: true, cancellationToken);
        if (gate.Response is { } refused)
            return refused;
        if (!workbench.DohConfigured)
            return Unconfigured("name resolution", "Recon:DohBaseUrl");

        IReadOnlyList<string> targets;
        if (hasTarget)
        {
            targets = [gate.Target!];
        }
        else
        {
            if (body.Targets!.Count > Math.Max(1, options.Value.MaxResolveTargets))
                return Results.BadRequest(new Problem(
                    $"At most {options.Value.MaxResolveTargets} names per resolution; split the census into walks."));
            targets = body.Targets
                .Select(t => (t ?? string.Empty).Trim().ToLowerInvariant())
                .Where(t => t.Length > 0)
                .ToArray();
            foreach (var name in targets)
            {
                if (string.IsNullOrEmpty(name)
                    || (!IsDomainName(name) && !System.Net.IPAddress.TryParse(name, out _)))
                {
                    return Results.BadRequest(new Problem("Each target must be a hostname or an IP address."));
                }
            }
        }

        var result = await workbench.ResolveAsync(
            gate.EngagementId!.Value, gate.OperatorId!.Value, targets, cancellationToken);
        var targetLabel = targets.Count == 1 ? targets[0] : $"{targets.Count} names";
        return await RespondAsync(
            gate, result, "resolve", AuditEventKind.ReconLookupCompleted, audit, clock, cancellationToken,
            payloadTarget: targetLabel);
    }

    // The shared ladder every workbench route walks: operator, engagement,
    // closed-engagement refusal, and target validation. The passive
    // lookups take a domain; a scan target may also name an address.
    private sealed record Gate(
        Guid? EngagementId,
        Guid? OperatorId,
        string? Target,
        RoeProfile? Roe,
        IResult? Response);

    private static async Task<Gate> ResolveEngagementAsync(
        string engagementId,
        string? target,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        bool allowAddress,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return new Gate(null, null, null, null, Results.Unauthorized());
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return new Gate(null, null, null, null,
                Results.BadRequest(new Problem("Engagement id is not a valid identifier.")));

        var engagement = await engagements.FindAsync(new EngagementId(engagementValue), cancellationToken);
        if (engagement is null)
            return new Gate(null, null, null, null, Results.NotFound(new Problem("No such engagement.")));
        if (engagement.IsClosed)
            return new Gate(null, null, null, null,
                Results.Json(
                    new Problem("The engagement is closed; its trail is final and accepts no new workbench findings."),
                    statusCode: StatusCodes.Status422UnprocessableEntity));

        var trimmed = target?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(trimmed))
            return new Gate(null, null, null, null, Results.BadRequest(new Problem("Target is required.")));
        if (!IsDomainName(trimmed) && !(allowAddress && System.Net.IPAddress.TryParse(trimmed, out _)))
            return new Gate(null, null, null, null,
                Results.BadRequest(allowAddress
                    ? new Problem("Target must be a hostname or an IP address.")
                    : new Problem("Target must be a domain name.")));

        return new Gate(engagementValue, operatorId.Value.Value, trimmed, engagement.Roe, null);
    }

    private static IResult Unconfigured(string what, string setting)
        => Results.Json(
            new Problem($"The {what} is not configured. Set {setting} to enable it; see docs/operations/recon.md."),
            statusCode: StatusCodes.Status503ServiceUnavailable);

    private static async Task<IResult> RespondAsync(
        Gate gate,
        ReconWorkbenchService.Result result,
        string lookup,
        AuditEventKind kind,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken,
        string? payloadTarget = null)
    {
        // Every attempt lands in the trail: the egress itself is the act,
        // succeeded or failed. The payload names the lookup and the target
        // but never the egress endpoint -- configuration names the endpoint,
        // the runbook the decision (the LLM event's posture).
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: gate.EngagementId!.Value,
                operatorId: gate.OperatorId!.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: $"recon.{lookup}",
                kind: kind,
                payload: $"{lookup};{payloadTarget ?? gate.Target}",
                output: result.Succeeded ? result.Summary : null,
                outcome: result.Succeeded
                    ? result.ArtifactId!.Value.ToString("N")
                    : $"failed:{result.Reason}",
                at: clock.GetUtcNow()),
            cancellationToken);

        if (!result.Succeeded)
            return Results.Json(
                new Problem($"The {lookup} run failed: {result.Reason}"),
                statusCode: StatusCodes.Status502BadGateway);

        return Results.Ok(new ReconWorkbenchResponse(
            result.ArtifactId!.Value.ToString("N"),
            result.Name!,
            result.ContentType!,
            result.Findings,
            result.Size,
            result.Summary));
    }

    // The shared target grammar (the asset endpoints own the one copy):
    // a DNS label sequence, loose and honest -- no resolution, no scheme,
    // no path.
    private static bool IsDomainName(string target) => ReconAssetEndpoints.IsDomainName(target);

    internal static string PortsLabel(string? ports)
        => string.IsNullOrWhiteSpace(ports) ? "default" : ports.Trim();

    // The ports grammar the operator-facing scan accepts: a comma list with
    // optional hyphen ranges, the vocabulary the recon family already
    // speaks. Unparsable or over-cap specs return null -- a 400 at the
    // route, never a silent truncation.
    internal static IReadOnlyList<int>? TryParsePorts(string? spec, int cap)
    {
        if (string.IsNullOrWhiteSpace(spec))
            return DefaultPorts;

        var ports = new SortedSet<int>();
        foreach (var token in spec.Split(','))
        {
            var trimmed = token.Trim();
            if (trimmed.Length == 0)
                return null;

            var separator = trimmed.IndexOf('-');
            if (separator < 0)
            {
                if (!int.TryParse(trimmed, out var port) || port is < 1 or > 65535)
                    return null;
                ports.Add(port);
                continue;
            }

            if (!int.TryParse(trimmed[..separator], out var low)
                || !int.TryParse(trimmed[(separator + 1)..], out var high)
                || low < 1 || high < low || high > 65535)
            {
                return null;
            }
            for (var port = low; port <= high; port++)
                ports.Add(port);
        }

        return ports.Count == 0 || ports.Count > cap ? null : ports.ToList();
    }

    // The default scan set when the request names no ports: the commonly
    // operative TCP services, curated and stable so two scans of the same
    // host with no spec are comparable. Name `ports` for anything else --
    // this set is a starting point, not a ceiling.
    internal static readonly IReadOnlyList<int> DefaultPorts =
    [
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
        465, 500, 502, 512, 513, 514, 515, 548, 554, 587, 593, 623, 631,
        636, 873, 993, 995, 1025, 1080, 1099, 1433, 1521, 1723, 1883, 1935,
        2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376,
        2379, 2380, 3000, 3128, 3260, 3306, 3389, 3690, 4444, 4848, 5000,
        5060, 5222, 5269, 5432, 5672, 5900, 5985, 5986, 6379, 6667, 7001,
        8000, 8008, 8009, 8080, 8443, 8500, 9090, 9200, 10000, 11211,
        15672, 27017, 50000,
    ];

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    public sealed record ReconLookupRequest(string Target);

    // The scan's ports spec: comma list with optional hyphen ranges, or
    // omitted for the documented default set.
    public sealed record ReconScanRequest(string Target, string? Ports = null);

    // The resolution ask: one name, or a bounded list of them (the census's
    // follow-up). A name may be a hostname or an IP literal for its PTR.
    public sealed record ReconResolveRequest(string? Target = null, IReadOnlyList<string>? Targets = null);

    // One workbench run's answer: the artifact its findings landed as, with
    // the one-line summary the trail's event carries beside it.
    public sealed record ReconWorkbenchResponse(
        string ArtifactId,
        string Name,
        string ContentType,
        int Findings,
        long Size,
        string Summary);
}
