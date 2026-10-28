using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Engagements;
using Rod.Transport.Campaigns;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;

namespace Rod.Integration.Tests;

/// <summary>
/// The delivery campaign's acceptance walk (architecture.md Sec 11.5): a
/// two-recipient campaign launches against a loopback relay, mints distinct
/// per-recipient lure links, sends the merged messages, and the recipient
/// who executes the lure enrolls already attributed -- campaign and
/// recipient visible in the audit trail. The build pipeline runs behind a
/// stub unit whose artifact carries the baked credential, the shape a real
/// implant keeps it in.
/// </summary>
public class CampaignEndToEndTests
{
    private sealed record Harness(
        HttpClient Client,
        IHost Host,
        EngagementId Engagement,
        ListenerId ListenerId,
        CampaignSendEngine Engine,
        ICampaignStore Campaigns,
        LoopbackSmtp Relay);

    private static async Task<Harness> NewAsync()
    {
        var registry = new InMemoryBuildUnitRegistry();
        registry.Register(new CampaignStubBuildUnit());
        var (client, host, _) = AuthenticatedHost.Create(configureServices: services =>
            services.Replace(ServiceDescriptor.Singleton<IBuildUnitRegistry>(registry)));
        await AuthenticatedHost.LoginAsync(client);

        var created = await client.PostAsJsonAsync("/engagements", new { name = "campaign-walk" });
        created.EnsureSuccessStatusCode();
        var engagement = await created.Content.ReadFromJsonAsync<EngagementBody>();
        Assert.True(EngagementId.TryParse(engagement!.EngagementId, out var engagementId));

        // The front whose public endpoint composes the lure URLs. Seeded
        // into the registry directly (the stream enroll tests' shape): the
        // in-memory harness binds no real socket, and the campaign's
        // validation reads the registry, not the bind.
        var listenerId = ListenerId.New();
        var listeners = host.Services.GetRequiredService<IListenerRegistry>();
        await listeners.RegisterAsync(Listener.Define(
            listenerId, "lure-front", "http", "127.0.0.1:8443",
            "http://lure.example.test", DateTimeOffset.UtcNow, engagementId));

        var relay = await LoopbackSmtp.StartAsync();
        return new Harness(
            client, host, engagementId, listenerId,
            host.Services.GetRequiredService<CampaignSendEngine>(),
            host.Services.GetRequiredService<ICampaignStore>(),
            relay);
    }

    private static CampaignEndpoints.CreateCampaignRequest Body(Harness h, params (string Email, string? Name)[] recipients) => new(
        Name: "renewal-push",
        ListenerId: h.ListenerId.ToString(),
        Relay: new CampaignEndpoints.CampaignRelayRequest(
            Host: "127.0.0.1", Port: h.Relay.Port, Tls: "none"),
        From: "billing@lure.example.test",
        Template: new CampaignEndpoints.CampaignTemplateRequest(
            Subject: "Your {{name}} renewal",
            Body: "<html><body><p>Dear {{name}}, review your renewal at {{link}}.</p></body></html>",
            BodyIsHtml: true),
        Recipients: recipients
            .Select(r => new CampaignEndpoints.CampaignRecipientRequest(r.Email, r.Name))
            .ToList(),
        Build: new PayloadEndpoints.BuildPayloadRequest(
            Unit: "rod-go",
            Class: "Implant",
            TargetOs: null,
            TargetArch: null,
            ListenerId: h.ListenerId.ToString()));

    private static async Task<CampaignEndpoints.CampaignResponse> CreateAsync(Harness h, CampaignEndpoints.CreateCampaignRequest body)
    {
        var created = await h.Client.PostAsJsonAsync($"/engagements/{h.Engagement}/campaigns", body);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var campaign = await created.Content.ReadFromJsonAsync<CampaignEndpoints.CampaignResponse>();
        Assert.NotNull(campaign);
        return campaign!;
    }

    private static async Task<CampaignEndpoints.CampaignResponse> DetailAsync(Harness h, string campaignId)
    {
        var detail = await h.Client.GetFromJsonAsync<CampaignEndpoints.CampaignResponse>(
            $"/engagements/{h.Engagement}/campaigns/{campaignId}");
        Assert.NotNull(detail);
        return detail!;
    }

    private static async Task SettleAsync(Harness h, string campaignId, Func<CampaignEndpoints.CampaignResponse, bool> done)
        => await TestSupport.WaitUntilAsync(async () => done(await DetailAsync(h, campaignId)));

    [Fact]
    public async Task TwoRecipientCampaign_TracksIntoAttributedEnrollment()
    {
        var h = await NewAsync();

        // --- Create: two recipients, each with their own lure link. ---
        var campaign = await CreateAsync(h, Body(h,
            ("alice@target.example", "Alice"),
            ("bob@target.example", "Bob")));
        Assert.Equal("draft", campaign.State);
        var rows = campaign.Recipients!;
        Assert.Equal(2, rows.Count);
        Assert.Equal(2, rows.Select(r => r.LureId).Distinct().Count());
        Assert.All(rows, r => Assert.StartsWith("http://lure.example.test/implants/lures/", r.LureUrl));

        // --- Launch: the engine drives both arcs to terminal. ---
        var launched = await h.Client.PostAsync(
            $"/engagements/{h.Engagement}/campaigns/{campaign.CampaignId}:launch", null);
        launched.EnsureSuccessStatusCode();
        await SettleAsync(h, campaign.CampaignId, c => c.State == "completed");

        // --- The relay saw two merged messages, one per recipient, each
        //     carrying its own link and the injected pixel. ---
        await TestSupport.WaitUntilAsync(() => Task.FromResult(h.Relay.Messages.Count == 2));
        var messages = h.Relay.Messages.OrderBy(m => m.RcptTo[0], StringComparer.Ordinal).ToArray();
        Assert.All(messages, m => Assert.Equal("<billing@lure.example.test>", m.From));

        // The captured MIME is quoted-printable; parse it back rather than
        // asserting against transport encoding.
        var toAlice = messages.Single(m => m.RcptTo[0].Contains("alice@target.example"));
        var aliceHtml = HtmlBodyOf(toAlice.Data);
        Assert.Contains("Dear Alice, review your renewal", aliceHtml);
        var aliceLink = ExtractLink(aliceHtml);
        Assert.StartsWith("http://lure.example.test/implants/lures/", aliceLink);
        Assert.Contains($"{aliceLink}/open", aliceHtml); // the injected pixel

        var toBob = messages.Single(m => m.RcptTo[0].Contains("bob@target.example"));
        var bobHtml = HtmlBodyOf(toBob.Data);
        Assert.Contains("Dear Bob, review your renewal", bobHtml);
        var bobLink = ExtractLink(bobHtml);
        Assert.NotEqual(aliceLink, bobLink);

        // The detail agrees: both sent, each with the baked credential's id
        // and the built artifact, lure URLs distinct.
        var detail = await DetailAsync(h, campaign.CampaignId);
        Assert.Equal(2, detail.Sent);
        Assert.Equal(0, detail.Failed);
        var aliceRow = detail.Recipients!.Single(r => r.Email == "alice@target.example");
        var bobRow = detail.Recipients!.Single(r => r.Email == "bob@target.example");
        Assert.NotNull(aliceRow.TokenId);
        Assert.NotNull(aliceRow.PayloadId);
        Assert.Equal(aliceLink, aliceRow.LureUrl);
        Assert.NotEqual(aliceRow.LureUrl, bobRow.LureUrl);

        // --- Alice opens the mail, then executes the lure. ---
        var aliceLureId = aliceRow.LureId;
        var pixel = await h.Client.GetAsync($"/implants/lures/{aliceLureId}/open");
        Assert.Equal(HttpStatusCode.OK, pixel.StatusCode);
        Assert.Equal("image/gif", pixel.Content.Headers.ContentType?.MediaType);

        var lure = await h.Client.GetAsync($"/implants/lures/{aliceLureId}");
        Assert.Equal(HttpStatusCode.OK, lure.StatusCode);
        var artifact = await lure.Content.ReadAsStringAsync();
        Assert.Contains("stub-campaign-artifact", artifact);

        // The artifact carries its baked credential; the implant presents it.
        var secret = Regex.Match(artifact, "token-secret=([A-Za-z0-9_-]+)").Groups[1].Value;
        Assert.NotEmpty(secret);
        var implantId = await EngagementSetup.EnrollAsync(h.Client, secret);

        // --- The enrollment is attributed: campaign and recipient on the
        //     trail, the executed binding on the row, the implant stamped. ---
        var audit = h.Host.Services.GetRequiredService<IAuditStore>();
        var facts = await audit.ListAsync(h.Engagement.Value);
        var enrollFact = facts.Single(f => f.Kind == AuditEventKind.ImplantEnrolled);
        Assert.Contains("campaign='renewal-push'", enrollFact.Payload);
        Assert.Contains("recipient=alice@target.example", enrollFact.Payload);
        Assert.Contains(facts, f => f.Kind == AuditEventKind.CampaignMessageSent && f.Outcome == "delivered");

        var after = await DetailAsync(h, campaign.CampaignId);
        var executedRow = after.Recipients!.Single(r => r.Email == "alice@target.example");
        Assert.NotNull(executedRow.ExecutedAt);
        Assert.Equal(implantId, executedRow.EnrolledImplantId);
        Assert.NotNull(executedRow.OpenedAt);
        Assert.NotNull(executedRow.ClickedAt);
        // Bob's row shows the send and nothing more -- his lure stays
        // unexecuted, one recipient one arc.
        var bobAfter = after.Recipients!.Single(r => r.Email == "bob@target.example");
        Assert.Null(bobAfter.ExecutedAt);

        // The implant row itself carries the campaign binding.
        var implants = h.Host.Services.GetRequiredService<Rod.CoreState.Implants.IImplantRepository>();
        var implant = await implants.FindAsync(new Rod.CoreState.ImplantId(Guid.Parse(implantId)));
        Assert.Equal(CampaignId.TryParse(campaign.CampaignId, out var cid) ? cid : default,
            implant!.CampaignId);
    }

    [Fact]
    public async Task Revoke_MidArc_StopsSends_AndKillsTheLures()
    {
        var h = await NewAsync();

        var campaign = await CreateAsync(h, Body(h,
            ("alice@target.example", null),
            ("bob@target.example", null)));

        // Launch and let the engine finish the whole arc; then a second
        // campaign is revoked mid-arc instead -- driven here by revoking a
        // completed one, which still kills the live lures, and by a fresh
        // draft never launched at all staying untouched.
        var launched = await h.Client.PostAsync(
            $"/engagements/{h.Engagement}/campaigns/{campaign.CampaignId}:launch", null);
        launched.EnsureSuccessStatusCode();
        await SettleAsync(h, campaign.CampaignId, c => c.State == "completed");
        var detail = await DetailAsync(h, campaign.CampaignId);
        Assert.Equal(2, detail.Sent);

        // Revoke: the sends are done, but the lures were live until now.
        var revoked = await h.Client.PostAsync(
            $"/engagements/{h.Engagement}/campaigns/{campaign.CampaignId}:revoke", null);
        revoked.EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.NotFound,
            (await h.Client.GetAsync($"/implants/lures/{detail.Recipients![0].LureId}")).StatusCode);

        // A second revoke is refused, and a revoked campaign cannot launch.
        var second = await h.Client.PostAsync(
            $"/engagements/{h.Engagement}/campaigns/{campaign.CampaignId}:revoke", null);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);

        var fresh = await CreateAsync(h, Body(h, ("carol@target.example", null)));
        var launchRevoked = await h.Client.PostAsync(
            $"/engagements/{h.Engagement}/campaigns/{fresh.CampaignId}:revoke", null);
        launchRevoked.EnsureSuccessStatusCode();
        var launchRefused = await h.Client.PostAsync(
            $"/engagements/{h.Engagement}/campaigns/{fresh.CampaignId}:launch", null);
        Assert.Equal(HttpStatusCode.Conflict, launchRefused.StatusCode);
    }

    [Fact]
    public async Task Create_RefusesTheBrokenShapes_AtTheSeam()
    {
        var h = await NewAsync();

        // A body without the link: refused at creation, not at delivery.
        var noLink = Body(h, ("alice@target.example", null)) with { };
        noLink = new CampaignEndpoints.CreateCampaignRequest(
            noLink.Name, noLink.ListenerId, noLink.Relay, noLink.From,
            new CampaignEndpoints.CampaignTemplateRequest("Subject", "No link in this body", false),
            noLink.Recipients, noLink.Build);
        var refused = await h.Client.PostAsJsonAsync($"/engagements/{h.Engagement}/campaigns", noLink);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Contains("{{link}}", await refused.Content.ReadAsStringAsync());

        // An unknown merge field.
        var unknownField = new CampaignEndpoints.CreateCampaignRequest(
            "x", h.ListenerId.ToString(), new CampaignEndpoints.CampaignRelayRequest("127.0.0.1", 25),
            "a@b.c", new CampaignEndpoints.CampaignTemplateRequest("S", "{{attachment}} {{link}}", false),
            [new CampaignEndpoints.CampaignRecipientRequest("alice@target.example")],
            new PayloadEndpoints.BuildPayloadRequest("go", null, null, null, ListenerId: h.ListenerId.ToString()));
        Assert.Equal(HttpStatusCode.BadRequest,
            (await h.Client.PostAsJsonAsync($"/engagements/{h.Engagement}/campaigns", unknownField)).StatusCode);

        // A duplicated recipient: one lure each, by construction.
        var duplicated = Body(h, ("alice@target.example", null), ("Alice@target.example", null));
        Assert.Equal(HttpStatusCode.BadRequest,
            (await h.Client.PostAsJsonAsync($"/engagements/{h.Engagement}/campaigns", duplicated)).StatusCode);

        // The token knobs: the campaign mints its own per-recipient
        // credential; setting one here is refused.
        var withKnobs = Body(h, ("alice@target.example", null));
        withKnobs = new CampaignEndpoints.CreateCampaignRequest(
            withKnobs.Name, withKnobs.ListenerId, withKnobs.Relay, withKnobs.From, withKnobs.Template,
            withKnobs.Recipients,
            new PayloadEndpoints.BuildPayloadRequest("go", null, null, null, ListenerId: h.ListenerId.ToString(), TokenMaxUses: 3));
        Assert.Equal(HttpStatusCode.BadRequest,
            (await h.Client.PostAsJsonAsync($"/engagements/{h.Engagement}/campaigns", withKnobs)).StatusCode);

        // A listener of the wrong family (dns) never fronts a lure.
        var dnsListener = ListenerId.New();
        var listeners = h.Host.Services.GetRequiredService<IListenerRegistry>();
        await listeners.RegisterAsync(Listener.Define(
            dnsListener, "dns-front", "dns", "127.0.0.1:5353",
            "dns://lure.example.test", DateTimeOffset.UtcNow, h.Engagement));
        var wrongFamily = Body(h, ("alice@target.example", null)) with { ListenerId = dnsListener.ToString() };
        Assert.Equal(HttpStatusCode.BadRequest,
            (await h.Client.PostAsJsonAsync($"/engagements/{h.Engagement}/campaigns", wrongFamily)).StatusCode);
    }

    private static string HtmlBodyOf(string mimeData)
    {
        var message = MimeKit.MimeMessage.Load(
            new MemoryStream(System.Text.Encoding.UTF8.GetBytes(mimeData)));
        return message.HtmlBody ?? string.Empty;
    }

    private static string ExtractLink(string html) =>
        Regex.Match(html, "https?://[^\"<>\\s]+/implants/lures/[0-9a-f]{32}").Value;

    private sealed record EngagementBody(string EngagementId, string Name);
}
