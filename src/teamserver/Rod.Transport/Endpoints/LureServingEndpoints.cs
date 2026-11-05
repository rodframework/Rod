using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Live;
using Rod.Transport.Listeners;

namespace Rod.Transport.Endpoints;

// The lure serving edge (architecture.md Sec 11.5, Sec 8): the public route
// a campaign recipient's message points at. The unguessable route id is the
// credential -- the same capability-URL shape the hook serving edge keeps --
// so the route serves without a header or a token, the shape a link click
// can carry. The link route both records the click and delivers the
// recipient's built artifact (the click is the evidence and the delivery);
// the pixel route records the open and answers a 1x1 gif. Both run the same
// ingress scope refusal the enroll and fetch routes run, so a shared-tier
// socket (the operator front) carries no lure, and a revoked campaign's
// lures are indistinguishable from nonexistent ones.
//
// The serve itself lives in LureServingCore: the transport-neutral half the
// listener bridge's route-forward carriage drives beside this route.

/// <summary>
/// Maps the lure serving routes onto the implant family.
/// </summary>
public static class LureServingEndpoints
{
    /// <summary>The lure route, in the implant family with enroll and hooks.</summary>
    public const string Route = "/implants/lures/{lureId}";

    public static IEndpointRouteBuilder MapLureServingEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(Route, FetchLureAsync).WithName(nameof(FetchLureAsync));
        endpoints.MapGet(Route + "/open", FetchLurePixelAsync).WithName(nameof(FetchLurePixelAsync));
        return endpoints;
    }

    private static async Task<IResult> FetchLureAsync(
        string lureId,
        HttpRequest http,
        ICampaignStore campaigns,
        IListenerRegistry listeners,
        IPayloadStore payloads,
        IAuditStore audit,
        ILiveEventBus live,
        TimeProvider clock,
        CancellationToken cancellationToken)
        => await ServeAsync(lureId, pixel: false, http, campaigns, listeners, payloads, audit, live, clock, cancellationToken);

    private static async Task<IResult> FetchLurePixelAsync(
        string lureId,
        HttpRequest http,
        ICampaignStore campaigns,
        IListenerRegistry listeners,
        IPayloadStore payloads,
        IAuditStore audit,
        ILiveEventBus live,
        TimeProvider clock,
        CancellationToken cancellationToken)
        => await ServeAsync(lureId, pixel: true, http, campaigns, listeners, payloads, audit, live, clock, cancellationToken);

    private static async Task<IResult> ServeAsync(
        string lureId,
        bool pixel,
        HttpRequest http,
        ICampaignStore campaigns,
        IListenerRegistry listeners,
        IPayloadStore payloads,
        IAuditStore audit,
        ILiveEventBus live,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(lureId, out var lureValue))
            return Results.BadRequest(new Problem("Lure id is not a valid identifier."));

        var facts = HttpRouteFacts.Of(http);
        var ingress = await listeners.FindByLocalPortAsync(
            http.HttpContext.Connection.LocalPort, cancellationToken);
        var served = await LureServingCore.ServeAsync(
            lureValue, pixel, ingress, facts, campaigns, payloads, audit, live, clock, cancellationToken);

        return served.Write(http.HttpContext);
    }
}
