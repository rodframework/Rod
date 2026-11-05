using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Deployment;
using Rod.CoreState.Live;
using Rod.Transport.Listeners;
using Rod.Transport.Payloads;

namespace Rod.Transport.Endpoints;

// The payload fetch core (architecture.md Sec 6): the transport-neutral half
// of the pre-enroll delivery -- an artifact presents the deployment
// credential its own build baked, each served fetch spending one use of it,
// and receives the payload bytes it then runs. The token resolves the
// engagement; the payload must exist in that engagement, so a token for one
// engagement never reaches another engagement's payloads; and the fetch
// REDEEMS one use of the token only when bytes actually leave -- every
// refusal leaves the budget whole. Every fetch a resolvable credential
// gate-keeps lands on the audit trail, served or refused, attributed to the
// system with what the wire showed; a credential whose secret resolves to
// no engagement leaves no record: it belongs to nobody.
//
// The loader tier is the same governance with one addition: the bytes leave
// sealed, an R1 body under the loader payload AAD and a fresh nonce, so
// nothing on the wire between front and target is readable or forgeable
// without the loader's own baked key.

/// <summary>
/// Serves one payload fetch -- the plain artifact or the loader's sealed
/// delivery (<paramref name="loaderTier"/>). The scope is the ingress
/// listener -- null keeps the permissive in-memory-harness shape the HTTP
/// routes ran before the extraction.
/// </summary>
internal static class PayloadFetchCore
{
    public static async Task<ServedRoute> ServeAsync(
        Guid payloadId,
        string secret,
        bool loaderTier,
        Listener? ingress,
        RouteWireFacts facts,
        IDeployTokenService tokens,
        IPayloadStore payloads,
        IAuditStore audit,
        ILiveEventBus live,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(secret))
            return ServedRoute.Problem(401, "X-Deploy-Token header is required.");

        var fetcher = $"remote={facts.Peer} {facts.ListenerFact} "
            + $"ua={(string.IsNullOrWhiteSpace(facts.UserAgent) ? "none" : facts.UserAgent)}";

        try
        {
            // Resolve without spending first: every refusal below (a foreign
            // socket, an unknown payload) must leave the budget whole, and
            // only a fetch that actually serves bytes redeems its use.
            var token = await tokens.VerifyAsync(secret, clock.GetUtcNow(), cancellationToken);

            // The scope check an engagement's own listener enforces: the
            // token must belong to the engagement this front answers for, so
            // a leaked token from another engagement is refused here, before
            // any bytes leave -- and a shared-tier front refuses implant
            // ingress outright.
            if (ingress is not null && ingress.EngagementId != token.EngagementId)
            {
                await RecordFetchAsync(audit, clock, token.EngagementId, token.Id, payloadId,
                    fetcher, "refused:scope", cancellationToken: cancellationToken);
                return ServedRoute.Problem(401, "Deploy token was not accepted.");
            }

            if (loaderTier)
            {
                // The loader record: the id a loader bakes is its own, and
                // the record's stage reference is what makes it a loader.
                // Anything else on this route is a plain payload id on the
                // wrong path -- indistinguishable from nonexistent, same as
                // the payload fetch's engagement rule.
                var loader = await payloads.FindAsync(payloadId, token.EngagementId.Value, cancellationToken);
                if (loader?.DeliversPayloadId is not { } deliversId)
                {
                    await RecordFetchAsync(audit, clock, token.EngagementId, token.Id, payloadId,
                        fetcher, "refused:not-loader", cancellationToken: cancellationToken);
                    return ServedRoute.Problem(404, "Payload does not exist in this engagement.");
                }
                var delivered = await payloads.FindAsync(deliversId, token.EngagementId.Value, cancellationToken);
                if (delivered is null || loader.EnvelopeKeyId is not { } keyId || loader.EnvelopeKey is not { } key)
                {
                    await RecordFetchAsync(audit, clock, token.EngagementId, token.Id, payloadId,
                        fetcher, "refused:seal", delivered?.Fingerprint, cancellationToken);
                    return ServedRoute.Problem(404, "Payload does not exist in this engagement.");
                }

                var redeemed = await tokens.RedeemAsync(secret, clock.GetUtcNow(), cancellationToken);

                // Sealed under the loader's own key, a fresh nonce per serve:
                // the loader is the only party that can open what this route
                // hands out, and no two serves share ciphertext.
                var sealedPayload = AesGcmEnvelope.WrapBody(delivered.Content, keyId, key, AesGcmEnvelope.LoaderPayloadAad);
                await RecordFetchAsync(audit, clock, redeemed.EngagementId, redeemed.Id, payloadId,
                    fetcher, "delivered", delivered.Fingerprint, cancellationToken);
                await live.PublishAsync(
                    LiveEvent.PayloadFetched(
                        redeemed.EngagementId,
                        $"{fetcher} delivered={delivered.Fingerprint} sealed",
                        clock.GetUtcNow()),
                    cancellationToken);
                return new ServedRoute(200, "application/octet-stream", sealedPayload, $"rod-delivered-{deliversId:N}.bin");
            }

            // Scoped by the token's engagement: a payload id from another
            // engagement is indistinguishable from a nonexistent one.
            var payload = await payloads.FindAsync(payloadId, token.EngagementId.Value, cancellationToken);
            if (payload is null)
            {
                await RecordFetchAsync(audit, clock, token.EngagementId, token.Id, payloadId,
                    fetcher, "refused:payload", cancellationToken: cancellationToken);
                return ServedRoute.Problem(404, "Payload does not exist in this engagement.");
            }

            // The download's redemption, after every refusal: one served
            // fetch spends one use, and a token at zero serves no more.
            var spent = await tokens.RedeemAsync(secret, clock.GetUtcNow(), cancellationToken);

            // The serve is the deployment's first observable footprint. The
            // same frame reaches connected operators live, so a launcher
            // row's remaining budget moves the moment a target pulls it. The
            // enrollment that may follow is the identity-bearing half of the
            // exchange; a burned one-liner pulled by a scanner enrolls never,
            // and this is the only record it leaves.
            await RecordFetchAsync(audit, clock, spent.EngagementId, spent.Id, payloadId,
                fetcher, "served", payload.Fingerprint, cancellationToken);
            await live.PublishAsync(
                LiveEvent.PayloadFetched(
                    spent.EngagementId,
                    $"{fetcher} payload={payload.Fingerprint} served",
                    clock.GetUtcNow()),
                cancellationToken);

            return new ServedRoute(200, payload.ContentType, payload.Content, $"rod-payload-{payloadId:N}.bin");
        }
        catch (DeployTokenRedeemException ex)
        {
            // A credential that still resolves keeps its attempts on the
            // trail: expired, spent, or revoked, the fact says who came back
            // and why it was refused -- the budget-burned retry is exactly
            // the fact an operator wants while the launcher row lives. The
            // wire answer stays uniform: no distinction between unknown,
            // expired, spent, and revoked for the fetcher to read.
            if (ex.EngagementId is { } engagement && ex.TokenId is { } tokenId)
                await RecordFetchAsync(audit, clock, engagement, tokenId, payloadId,
                    fetcher, $"refused:{ex.Reason.ToString().ToLowerInvariant()}",
                    cancellationToken: cancellationToken);
            return ServedRoute.Problem(401, "Deploy token was not accepted.");
        }
    }

    // The one fetch fact: what the wire showed, which credential gated it,
    // and how it ended. The payload names itself in the library's
    // vocabulary -- the fingerprint the Payloads tab matches on -- with the
    // bare artifact id beside it for correlating a pasted command's URL;
    // a fetch that never resolved a payload can name only the id it asked
    // for. Audit-only -- the live push rides the served frame alone,
    // because a refusal moves no state an operator's row displays.
    private static async Task RecordFetchAsync(
        IAuditStore audit,
        TimeProvider clock,
        EngagementId engagement,
        DeployTokenId tokenId,
        Guid payloadId,
        string fetcher,
        string outcome,
        string? fingerprint = null,
        CancellationToken cancellationToken = default)
    {
        var payloadText = fingerprint is null
            ? $"payload={payloadId:N}"
            : $"payload={fingerprint} id={payloadId:N}";
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: OperatorId.Empty.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "payload.fetched",
                kind: AuditEventKind.PayloadFetched,
                payload: $"{fetcher} {payloadText} token={tokenId}",
                output: null,
                outcome,
                at: clock.GetUtcNow()),
            cancellationToken);
    }
}
