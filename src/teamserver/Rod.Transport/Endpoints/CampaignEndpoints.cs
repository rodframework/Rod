using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using MimeKit;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Engagements;
using Rod.CoreState.Live;
using Rod.CoreState.Operators;
using Rod.Transport.Campaigns;
using Rod.Transport.Listeners;

namespace Rod.Transport.Endpoints;

// The operator surface of the delivery campaign (architecture.md Sec 11.5):
// create (validated to refusal at the seam -- the template's grammar, the
// relay's shape, the build profile through the build pipeline's own
// parser), launch, revoke, and the list/detail reads the console watches.
// The engine half lives in Rod.Transport.Campaigns; the public half (the
// lure routes) in LureServingEndpoints.

/// <summary>
/// Maps the engagement's delivery-campaign endpoints.
/// </summary>
public static class CampaignEndpoints
{
    public static IEndpointRouteBuilder MapCampaignEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints
            .MapGroup("/engagements/{engagementId}/campaigns")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));

        group.MapPost("/", CreateCampaignAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(CreateCampaignAsync));
        group.MapGet("/", ListCampaignsAsync).WithName(nameof(ListCampaignsAsync));
        group.MapGet("/{campaignId}", GetCampaignAsync).WithName(nameof(GetCampaignAsync));
        group.MapPost("/{campaignId}:launch", LaunchCampaignAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(LaunchCampaignAsync));
        group.MapPost("/{campaignId}:revoke", RevokeCampaignAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(RevokeCampaignAsync));

        return endpoints;
    }

    private static async Task<IResult> CreateCampaignAsync(
        string engagementId,
        CreateCampaignRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        ICampaignStore campaigns,
        IListenerRegistry listeners,
        Rod.CoreState.Pki.IImplantCertificateAuthority ca,
        IPayloadStore payloads,
        Rod.CoreState.Recon.IReconAssetStore reconAssets,
        IAuditStore audit,
        Rod.CoreState.Assets.IModuleAssetStore assets,
        TimeProvider clock,
        Listeners.WireGuard.WireGuardOptions wireGuard,
        Listeners.WireGuard.WireGuardTunnelRegistry wireGuardTunnels,
        CancellationToken cancellationToken)
    {
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));

        var engagementRow = await engagements.FindAsync(engagement, cancellationToken);
        if (engagementRow is null)
            return Results.NotFound(new Problem("Engagement does not exist."));
        if (engagementRow.IsClosed)
            return Results.Conflict(new Problem("The engagement is closed to new deployments."));

        // --- The name. ---
        var name = body.Name?.Trim();
        if (string.IsNullOrEmpty(name))
            return Results.BadRequest(new Problem("The campaign needs a name."));
        if (name.Length > CampaignLimits.MaxNameBytes)
            return Results.BadRequest(new Problem($"The name exceeds {CampaignLimits.MaxNameBytes} bytes."));

        // --- The listener whose public endpoint fronts the lure and whose
        //     engagement scopes the serving socket. ---
        if (!Guid.TryParse(body.ListenerId, out var listenerValue))
            return Results.BadRequest(new Problem("Listener id is not a valid identifier."));
        var listener = await listeners.FindAsync(new ListenerId(listenerValue), cancellationToken);
        if (listener is null || listener.EngagementId != engagement)
            return Results.BadRequest(new Problem("Listener does not serve this engagement."));
        if (listener.Transport is not ("http" or "https"))
            return Results.BadRequest(new Problem("The lure rides the web family; name an http or https listener."));

        // --- The sending profile. The TLS posture is named, never defaulted
        //     from configuration: which relay and whose chain a campaign's
        //     mail leaves under is the runbook's egress decision. ---
        if (body.Relay is null)
            return Results.BadRequest(new Problem("The campaign needs a relay."));
        var relay = body.Relay;
        if (string.IsNullOrWhiteSpace(relay.Host) || relay.Host.Length > 255)
            return Results.BadRequest(new Problem("The relay host must be 1-255 bytes."));
        if (relay.Port is < 1 or > 65535)
            return Results.BadRequest(new Problem("The relay port must be 1-65535."));
        var tls = ParseTls(relay.Tls);
        if (tls is null)
            return Results.BadRequest(new Problem("Relay Tls must be 'startTls' (the default), 'implicit', or 'none'."));
        if (relay.Username?.Length > 255 || relay.Password?.Length > 255)
            return Results.BadRequest(new Problem("The relay credentials exceed 255 bytes."));
        if (string.IsNullOrWhiteSpace(relay.Username) != string.IsNullOrEmpty(relay.Password)
            && !string.IsNullOrWhiteSpace(relay.Username))
            return Results.BadRequest(new Problem("The relay password needs its username."));

        // --- The envelope sender: one address, parsed like a mail client
        //     reads it, so what the trail shows is what the wire sends. ---
        var from = body.From?.Trim();
        if (string.IsNullOrEmpty(from) || !MailboxAddress.TryParse(from, out _) || from.Length > CampaignLimits.MaxAddressBytes)
            return Results.BadRequest(new Problem("From must be one valid email address."));

        // --- The template: inline or by module reference, grammar validated
        //     here, never at delivery. ---
        if (body.Template is null)
            return Results.BadRequest(new Problem("The campaign needs a template."));
        string templateSubject;
        string templateBody;
        bool templateIsHtml;
        var templateRef = body.Template.Ref?.Trim();
        if (templateRef is { Length: > 0 })
        {
            if (body.Template.Subject is not null || body.Template.Body is not null)
                return Results.BadRequest(new Problem("The template carries both a module reference and inline text; pick one."));

            // The module layer's content seam (Sec 15.1): a reusable lure
            // template resolves from an installed asset module, and the
            // campaign row stores the resolved text -- what was sent stays
            // on the row regardless of what later happens to the module.
            var (module, asset, refProblem) = ParseTemplateRef(templateRef);
            if (refProblem is not null)
                return Results.BadRequest(new Problem(refProblem));
            if (!assets.TryRead(module!, asset!, out var templateAsset))
                return Results.BadRequest(new Problem($"Template '{templateRef}' is not carried by a listed asset module; deploy one and list it under Capabilities:AssetModules."));
            var parsedTemplate = CampaignTemplateAsset.Parse(templateAsset);
            if (parsedTemplate is null)
                return Results.BadRequest(new Problem($"Template '{templateRef}' is not a campaign template: it needs a 'Subject: ' first line, a blank line, and a body."));
            (templateSubject, templateBody, templateIsHtml) = parsedTemplate.Value;
        }
        else
        {
            templateSubject = body.Template.Subject ?? "";
            templateBody = body.Template.Body ?? "";
            templateIsHtml = body.Template.BodyIsHtml ?? false;
        }
        var templateError = CampaignLimits.ValidateTemplate(templateSubject, templateBody);
        if (templateError is not null)
            return Results.BadRequest(new Problem(templateError));

        // --- The recipients: spear-phish scale by construction (one build
        //     per recipient is the attribution price), unique, one address
        //     each. Each entry names its address one way (Sec 15.4's target
        //     link): typed, or by reference to a recon asset on the
        //     engagement's target list -- never both, never neither. ---
        if (body.Recipients is null || body.Recipients.Count == 0)
            return Results.BadRequest(new Problem("The campaign needs at least one recipient."));
        if (body.Recipients.Count > CampaignLimits.MaxRecipients)
            return Results.BadRequest(new Problem($"A campaign carries at most {CampaignLimits.MaxRecipients} recipients."));
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var recipients = new List<CampaignRecipient>();
        var selectedTargets = 0;
        foreach (var entry in body.Recipients)
        {
            var byReference = entry.ReconAssetId?.Trim();
            var typed = entry.Email?.Trim();
            if (string.IsNullOrWhiteSpace(byReference) == string.IsNullOrWhiteSpace(typed))
                return Results.BadRequest(new Problem(
                    "Each recipient names exactly one of 'email' or 'reconAssetId'."));

            string email;
            Rod.CoreState.ReconAssetId? reconAssetId = null;
            string? display;
            if (byReference is { Length: > 0 })
            {
                if (!Rod.CoreState.ReconAssetId.TryParse(byReference, out var assetId))
                    return Results.BadRequest(new Problem($"Recon asset id '{byReference}' is not a valid identifier."));
                var asset = await reconAssets.FindAsync(assetId, engagement, cancellationToken);
                if (asset is null)
                    return Results.NotFound(new Problem(
                        $"Recon asset '{byReference}' does not exist in this engagement."));
                if (asset.Kind != Rod.CoreState.Recon.ReconAssetKind.Email)
                    return Results.Json(
                        new Problem($"Recon asset '{byReference}' is a {asset.Kind.ToString().ToLowerInvariant()}, not an email target; a campaign recipient is a mailbox."),
                        statusCode: StatusCodes.Status422UnprocessableEntity);

                // The selection resolves now, at creation: the row carries
                // the address it will mail, and the asset reference is the
                // record of where the target came from -- the delivery arc
                // never depends on the asset row staying alive.
                email = asset.Value;
                reconAssetId = asset.Id;
                display = string.IsNullOrWhiteSpace(entry.Name) ? asset.DisplayName : entry.Name.Trim();
                selectedTargets++;
            }
            else
            {
                email = typed!;
                display = entry.Name?.Trim();
            }

            if (string.IsNullOrEmpty(email)
                || !MailboxAddress.TryParse(email, out var address)
                || address.Domain.Length == 0
                || email.Length > CampaignLimits.MaxAddressBytes)
            {
                return Results.BadRequest(new Problem($"Recipient '{email}' is not one valid email address."));
            }
            if (!seen.Add(email))
                return Results.BadRequest(new Problem($"Recipient '{email}' appears twice; a lure is per recipient."));
            if (display?.Length > CampaignLimits.MaxAddressBytes)
                display = display[..CampaignLimits.MaxAddressBytes];
            recipients.Add(new CampaignRecipient(
                CampaignRecipientId.New(), email, string.IsNullOrEmpty(display) ? null : display, Guid.NewGuid(),
                reconAssetId: reconAssetId));
        }

        // --- The build profile: the same body a payload build takes, minus
        //     the token knobs (the campaign mints its own per-recipient,
        //     single-use) and minus nothing else. Parsed here with the
        //     pipeline's own parser so a refusal lands at creation, and
        //     stored as JSON so the pipeline's parser stays the only
        //     statement of what a build means. ---
        if (body.Build is null)
            return Results.BadRequest(new Problem("The campaign needs a build profile."));
        if (body.Build.TokenMaxUses is not null || body.Build.TokenLifetimeSeconds is not null)
            return Results.BadRequest(new Problem("A campaign mints its own per-recipient credential; the token knobs are not settable here."));
        var buildJson = JsonSerializer.Serialize(body.Build, CampaignSendEngine.JsonOptions);
        if (buildJson.Length > CampaignLimits.MaxBuildRequestBytes)
            return Results.BadRequest(new Problem($"The build profile exceeds {CampaignLimits.MaxBuildRequestBytes} bytes."));
        var (parsed, parseError) = await Payloads.PayloadBuildRequestParser.ParseAsync(
            body.Build, engagement, operatorId.Value, listeners, ca, payloads, cancellationToken,
            // Validation only: the stored profile re-parses -- and mints its
            // per-recipient pair -- when the send engine drives each build,
            // so the creation pass registers no dead peer.
            wireGuard, wireGuardTunnels, mintWireGuard: false);
        if (parseError is not null)
            return Results.BadRequest(new Problem($"Build profile: {parseError}"));

        var at = clock.GetUtcNow();
        var campaign = new Campaign(
            CampaignId.New(), engagement, name, operatorId.Value, at,
            relay.Host.Trim(), relay.Port!.Value, tls.Value,
            string.IsNullOrWhiteSpace(relay.Username) ? null : relay.Username.Trim(),
            string.IsNullOrEmpty(relay.Password) ? null : relay.Password,
            from,
            templateSubject.Trim(), templateBody,
            templateIsHtml,
            buildJson,
            listenerValue,
            recipients);
        await campaigns.SaveAsync(campaign, cancellationToken);

        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: operatorId.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "campaign.created",
                kind: AuditEventKind.CampaignStateChanged,
                payload: $"name='{name}' recipients={recipients.Count} relay={relay.Host.Trim()}:{relay.Port} "
                    + $"tls={tls.Value.ToString().ToLowerInvariant()} listener={listener.Name} "
                    + $"template={(templateRef is { Length: > 0 } ? templateRef : "inline")} "
                    + $"reconTargets={selectedTargets}",
                output: null,
                outcome: campaign.Id.ToString(),
                at),
            cancellationToken);

        return Results.Created(
            $"/engagements/{engagement}/campaigns/{campaign.Id}",
            CampaignResponse.Of(campaign, listener, includeRecipients: true));
    }

    private static async Task<IResult> ListCampaignsAsync(
        string engagementId,
        IEngagementRepository engagements,
        ICampaignStore campaigns,
        IListenerRegistry listeners,
        CancellationToken cancellationToken)
    {
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (await engagements.FindAsync(engagement, cancellationToken) is null)
            return Results.NotFound(new Problem("Engagement does not exist."));

        var rows = await campaigns.ListByEngagementAsync(engagement, cancellationToken);
        var bodies = new List<CampaignResponse>();
        foreach (var campaign in rows)
        {
            var listener = campaign.ListenerId == Guid.Empty
                ? null
                : await listeners.FindAsync(new ListenerId(campaign.ListenerId), cancellationToken);
            bodies.Add(CampaignResponse.Of(campaign, listener, includeRecipients: false));
        }
        return Results.Ok(bodies);
    }

    private static async Task<IResult> GetCampaignAsync(
        string engagementId,
        string campaignId,
        IEngagementRepository engagements,
        ICampaignStore campaigns,
        IListenerRegistry listeners,
        CancellationToken cancellationToken)
    {
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (await engagements.FindAsync(engagement, cancellationToken) is null)
            return Results.NotFound(new Problem("Engagement does not exist."));
        if (!CampaignId.TryParse(campaignId, out var campaign))
            return Results.BadRequest(new Problem("Campaign id is not a valid identifier."));

        var row = await campaigns.FindAsync(campaign, engagement, cancellationToken);
        if (row is null)
            return Results.NotFound(new Problem("Campaign does not exist in this engagement."));

        var listener = await listeners.FindAsync(new ListenerId(row.ListenerId), cancellationToken);
        return Results.Ok(CampaignResponse.Of(row, listener, includeRecipients: true));
    }

    private static async Task<IResult> LaunchCampaignAsync(
        string engagementId,
        string campaignId,
        ClaimsPrincipal user,
        ICampaignStore campaigns,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var (campaign, problem) = await ResolveOwnedAsync(engagementId, campaignId, campaigns, cancellationToken);
        if (problem is not null)
            return problem;
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();

        if (!await campaigns.LaunchAsync(campaign!.Id, campaign.EngagementId, clock.GetUtcNow(), cancellationToken))
            return Results.Conflict(new Problem("The campaign is not in the draft state; it cannot launch."));

        await audit.AppendAsync(StateFact(campaign, operatorId.Value, "campaign.launched", $"recipients={campaign.Recipients.Count}", clock.GetUtcNow()), cancellationToken);
        return Results.Ok(new CampaignActionResponse(campaign.Id.ToString(), "launched"));
    }

    private static async Task<IResult> RevokeCampaignAsync(
        string engagementId,
        string campaignId,
        ClaimsPrincipal user,
        ICampaignStore campaigns,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var (campaign, problem) = await ResolveOwnedAsync(engagementId, campaignId, campaigns, cancellationToken);
        if (problem is not null)
            return problem;
        var operatorId = user.TryGetOperatorId();
        if (operatorId is null)
            return Results.Unauthorized();

        if (!await campaigns.RevokeAsync(campaign!.Id, campaign.EngagementId, clock.GetUtcNow(), cancellationToken))
            return Results.Conflict(new Problem("The campaign is already revoked."));

        await audit.AppendAsync(StateFact(campaign, operatorId.Value, "campaign.revoked", $"recipients={campaign.Recipients.Count}", clock.GetUtcNow()), cancellationToken);
        return Results.Ok(new CampaignActionResponse(campaign.Id.ToString(), "revoked"));
    }

    private static async Task<(Campaign? Campaign, IResult? Problem)> ResolveOwnedAsync(
        string engagementId,
        string campaignId,
        ICampaignStore campaigns,
        CancellationToken cancellationToken)
    {
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return (null, Results.BadRequest(new Problem("Engagement id is not a valid identifier.")));
        if (!CampaignId.TryParse(campaignId, out var campaign))
            return (null, Results.BadRequest(new Problem("Campaign id is not a valid identifier.")));
        var row = await campaigns.FindAsync(campaign, engagement, cancellationToken);
        if (row is null)
            return (null, Results.NotFound(new Problem("Campaign does not exist in this engagement.")));
        return (row, null);
    }

    private static AuditEvent StateFact(
        Campaign campaign, OperatorId actor, string verb, string detail, DateTimeOffset at)
        => AuditEvent.Fact(
            eventId: Guid.NewGuid(),
            engagementId: campaign.EngagementId.Value,
            operatorId: actor.Value,
            implantId: Guid.Empty,
            taskId: Guid.Empty,
            verb,
            kind: AuditEventKind.CampaignStateChanged,
            payload: $"name='{campaign.Name}' {detail}",
            output: null,
            outcome: campaign.Id.ToString(),
            at);

    // "module/asset", both parts kebab-shaped by the manifest's own grammar;
    // anything else is refused naming the ref, not the parts.
    private static (string? Module, string? Asset, string? Problem) ParseTemplateRef(string templateRef)
    {
        var separator = templateRef.IndexOf('/');
        if (separator <= 0 || separator == templateRef.Length - 1 || templateRef.IndexOf('/', separator + 1) >= 0)
            return (null, null, $"Template reference '{templateRef}' must be 'module/asset'.");
        return (templateRef[..separator], templateRef[(separator + 1)..], null);
    }

    private static CampaignRelayTls? ParseTls(string? tls) => tls?.Trim().ToLowerInvariant() switch
    {
        null or "" => CampaignRelayTls.StartTls,
        "starttls" => CampaignRelayTls.StartTls,
        "implicit" => CampaignRelayTls.ImplicitTls,
        "none" => CampaignRelayTls.None,
        _ => null,
    };

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    public sealed record CreateCampaignRequest(
        string? Name,
        string? ListenerId,
        CampaignRelayRequest? Relay,
        string? From,
        CampaignTemplateRequest? Template,
        List<CampaignRecipientRequest>? Recipients,
        PayloadEndpoints.BuildPayloadRequest? Build);

    public sealed record CampaignRelayRequest(
        string? Host,
        int? Port,
        string? Tls = null,
        string? Username = null,
        string? Password = null);

    /// <summary>
    /// The message template: inline text, or <paramref name="Ref"/> naming a
    /// campaign template asset as <c>module/asset</c> (e.g.
    /// <c>lure-templates/document-review</c>) -- resolved from the listed
    /// asset modules at creation and stored resolved, so the campaign row
    /// carries exactly what will be sent.
    /// </summary>
    public sealed record CampaignTemplateRequest(
        string? Subject,
        string? Body,
        bool? BodyIsHtml = null,
        string? Ref = null);

    /// <summary>
    /// One target entry: the address typed (<paramref name="Email"/>), or
    /// a recon asset selected by id (<paramref name="ReconAssetId"/> -- the
    /// unified entity model's target link, Sec 15.4; the asset must be an
    /// email target of this engagement). Exactly one of the two.
    /// </summary>
    public sealed record CampaignRecipientRequest(
        string? Email,
        string? Name = null,
        string? ReconAssetId = null);

    public sealed record CampaignActionResponse(string CampaignId, string State);

    /// <summary>
    /// The campaign row as the console reads it. The relay password never
    /// appears: it is held in the clear on the row only because the server
    /// must present it again, and read-back keeps the launcher-secret
    /// discipline -- the trail and the API both name the relay, neither
    /// ever carries its credential.
    /// </summary>
    public sealed record CampaignResponse(
        string CampaignId,
        string Name,
        string State,
        string ListenerId,
        string? ListenerName,
        string From,
        string RelayHost,
        int RelayPort,
        string RelayTls,
        string? RelayUsername,
        bool BodyIsHtml,
        int Total,
        int Sent,
        int Failed,
        int Opened,
        int Clicked,
        int Executed,
        DateTimeOffset CreatedAt,
        DateTimeOffset? LaunchedAt,
        DateTimeOffset? CompletedAt,
        DateTimeOffset? RevokedAt,
        List<CampaignRecipientResponse>? Recipients = null)
    {
        public static CampaignResponse Of(Campaign campaign, Listener? listener, bool includeRecipients) => new(
            campaign.Id.ToString(),
            campaign.Name,
            campaign.State.ToString().ToLowerInvariant(),
            campaign.ListenerId.ToString("N"),
            listener?.Name,
            campaign.FromAddress,
            campaign.RelayHost,
            campaign.RelayPort,
            campaign.RelayTls.ToString().ToLowerInvariant(),
            campaign.RelayUsername,
            campaign.BodyIsHtml,
            campaign.Recipients.Count,
            campaign.Recipients.Count(r => r.Status == CampaignRecipientStatus.Sent),
            campaign.Recipients.Count(r => r.Status == CampaignRecipientStatus.Failed),
            campaign.Recipients.Count(r => r.OpenedAt is not null),
            campaign.Recipients.Count(r => r.ClickedAt is not null),
            campaign.Recipients.Count(r => r.ExecutedAt is not null),
            campaign.CreatedAt,
            campaign.LaunchedAt,
            campaign.CompletedAt,
            campaign.RevokedAt,
            Recipients: includeRecipients
                ? campaign.Recipients
                    .Select(r => CampaignRecipientResponse.Of(r, listener))
                    .ToList()
                : null);
    }

    public sealed record CampaignRecipientResponse(
        string RecipientId,
        string Email,
        string? Name,
        string Status,
        string? Failure,
        string LureId,
        string? LureUrl,
        string? TokenId,
        string? PayloadId,
        DateTimeOffset? SentAt,
        DateTimeOffset? OpenedAt,
        DateTimeOffset? ClickedAt,
        DateTimeOffset? ExecutedAt,
        string? EnrolledImplantId,
        string? ReconAssetId = null)
    {
        public static CampaignRecipientResponse Of(CampaignRecipient recipient, Listener? listener)
        {
            var endpoint = listener?.PublicEndpoint.TrimEnd('/');
            return new(
                recipient.Id.ToString(),
                recipient.Email,
                recipient.Name,
                recipient.Status.ToString().ToLowerInvariant(),
                recipient.Failure,
                recipient.LureId.ToString("N"),
                endpoint is null ? null : $"{endpoint}/implants/lures/{recipient.LureId:N}",
                recipient.EnrollTokenId?.ToString(),
                recipient.PayloadId?.ToString(),
                recipient.SentAt,
                recipient.OpenedAt,
                recipient.ClickedAt,
                recipient.ExecutedAt,
                recipient.EnrolledImplantId?.ToString("N"),
                recipient.ReconAssetId?.ToString());
        }
    }
}
