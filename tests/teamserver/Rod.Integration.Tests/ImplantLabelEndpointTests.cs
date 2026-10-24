using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Rod.Audit;
using Rod.CoreState.Operators;
using Rod.Transport.Endpoints;
using static Rod.Integration.Tests.EngagementSetup;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: implant labels -- the marker vocabulary the intel layer groups
/// and filters by (architecture.md Sec 11.2). A label set or cleared through
/// the operator HTTP API is attributed to the acting operator and recorded as
/// an ImplantLabeled audit event; the listing is the last-wins reduction over
/// those events, so the append-only trail changes a label without rewriting
/// history. The label's only storage is the trail -- the same mechanism the
/// notes tests pin, so no restart leg repeats here.
/// </summary>
public sealed class ImplantLabelEndpointTests
{
    [Fact]
    public async Task Labels_Set_Clear_And_Reduce_LastWins()
    {
        var (client, host, operatorId) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var secret = await MintDeployTokenAsync(client, engagementId);
            var implantId = await EnrollAsync(client, secret);

            var first = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels",
                new ImplantEndpoints.SetLabelRequest(Label: "jump"));
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);
            var firstLabel = await first.Content.ReadFromJsonAsync<ImplantEndpoints.ImplantLabelResponse>();
            Assert.NotNull(firstLabel);
            Assert.Equal("jump", firstLabel!.Label);
            Assert.Equal(operatorId.ToString(), firstLabel.SetBy);
            Assert.Equal(AuthenticatedHost.Handle, firstLabel.SetByHandle);

            var second = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels",
                new ImplantEndpoints.SetLabelRequest(Label: "watch-edr"));
            second.EnsureSuccessStatusCode();

            // The listing is the reduced set: both labels, attributed -- and
            // naming the setter by handle, resolved on the read the way the
            // member role needs (it cannot walk the operator roster).
            var listed = await client.GetFromJsonAsync<ImplantEndpoints.ImplantLabelResponse[]>(
                $"/engagements/{engagementId}/implants/{implantId}/labels");
            Assert.NotNull(listed);
            Assert.Equal(new[] { "jump", "watch-edr" }, listed!.Select(l => l.Label).ToArray());
            Assert.All(listed, l => Assert.Equal(operatorId.ToString(), l.SetBy));
            Assert.All(listed, l => Assert.Equal(AuthenticatedHost.Handle, l.SetByHandle));

            // Clearing one drops it from the reduced set.
            var cleared = await client.DeleteAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels/jump");
            Assert.Equal(HttpStatusCode.NoContent, cleared.StatusCode);
            var afterClear = await client.GetFromJsonAsync<ImplantEndpoints.ImplantLabelResponse[]>(
                $"/engagements/{engagementId}/implants/{implantId}/labels");
            Assert.Equal(new[] { "watch-edr" }, afterClear!.Select(l => l.Label).ToArray());

            // The trail holds every action -- two sets and one clear -- each
            // attributed to the acting operator and bound to the implant
            // (architecture.md Sec 11.2).
            var audit = host.Services.GetRequiredService<IAuditStore>();
            var events = (await audit.ListAsync(Guid.Parse(engagementId)))
                .Where(e => e.Kind == AuditEventKind.ImplantLabeled)
                .ToArray();
            Assert.Equal(3, events.Length);
            Assert.All(events, e => Assert.Equal(Guid.Parse(implantId), e.ImplantId));
            Assert.All(events, e => Assert.Equal(operatorId.Value, e.OperatorId));
            Assert.Contains(events, e => e.Payload == "jump" && e.Outcome == "cleared");
        }
    }

    [Fact]
    public async Task Labels_AreCaseInsensitiveMarkers()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var secret = await MintDeployTokenAsync(client, engagementId);
            var implantId = await EnrollAsync(client, secret);

            await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels",
                new ImplantEndpoints.SetLabelRequest(Label: "web"));
            await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels",
                new ImplantEndpoints.SetLabelRequest(Label: "Web"));

            // "web" and "Web" are the same marker: the second set wins the
            // reduction slot rather than adding a twin, and clearing either
            // spelling clears the marker.
            var listed = await client.GetFromJsonAsync<ImplantEndpoints.ImplantLabelResponse[]>(
                $"/engagements/{engagementId}/implants/{implantId}/labels");
            var label = Assert.Single(listed!);
            Assert.Equal("Web", label.Label);

            var cleared = await client.DeleteAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels/web");
            Assert.Equal(HttpStatusCode.NoContent, cleared.StatusCode);
            var afterClear = await client.GetFromJsonAsync<ImplantEndpoints.ImplantLabelResponse[]>(
                $"/engagements/{engagementId}/implants/{implantId}/labels");
            Assert.Empty(afterClear!);
        }
    }

    [Fact]
    public async Task SetLabel_ValidatesTheRequest()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var otherEngagementId = await CreateEngagementAsync(client);
            var secret = await MintDeployTokenAsync(client, engagementId);
            var implantId = await EnrollAsync(client, secret);

            // Blank text is malformed.
            var blank = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels",
                new ImplantEndpoints.SetLabelRequest(Label: "  "));
            Assert.Equal(HttpStatusCode.BadRequest, blank.StatusCode);

            // A label is a marker, not a sentence.
            var oversized = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels",
                new ImplantEndpoints.SetLabelRequest(Label: new string('x', 65)));
            Assert.Equal(HttpStatusCode.BadRequest, oversized.StatusCode);

            // An unknown implant is a routing failure.
            var unknown = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/implants/{Guid.NewGuid()}/labels",
                new ImplantEndpoints.SetLabelRequest(Label: "jump"));
            Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);

            // The implant exists, but not in this engagement -- cross-engagement
            // access is impossible by construction (architecture.md Sec 3).
            var foreign = await client.PostAsJsonAsync(
                $"/engagements/{otherEngagementId}/implants/{implantId}/labels",
                new ImplantEndpoints.SetLabelRequest(Label: "jump"));
            Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);

            // The per-implant cap: the 33rd distinct marker is refused, the
            // cap leaves the picture a picture (architecture.md Sec 11.2).
            for (var i = 0; i < 32; i++)
            {
                var set = await client.PostAsJsonAsync(
                    $"/engagements/{engagementId}/implants/{implantId}/labels",
                    new ImplantEndpoints.SetLabelRequest(Label: $"tag-{i}"));
                Assert.True(set.IsSuccessStatusCode, $"label {i} should have been accepted");
            }

            var overCap = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels",
                new ImplantEndpoints.SetLabelRequest(Label: "one-too-many"));
            Assert.Equal(HttpStatusCode.UnprocessableEntity, overCap.StatusCode);

            // Re-setting a carried label never trips the cap.
            var reSet = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels",
                new ImplantEndpoints.SetLabelRequest(Label: "tag-0"));
            Assert.Equal(HttpStatusCode.Created, reSet.StatusCode);

            // Nothing from the refused posts landed in the trail.
            var audit = host.Services.GetRequiredService<IAuditStore>();
            var events = (await audit.ListAsync(Guid.Parse(engagementId)))
                .Where(e => e.Kind == AuditEventKind.ImplantLabeled)
                .ToArray();
            Assert.DoesNotContain(events, e => e.Payload == "one-too-many");
        }
    }

    [Fact]
    public async Task ClearLabel_IsIdempotentAndAttributed()
    {
        var (client, host, operatorId) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var secret = await MintDeployTokenAsync(client, engagementId);
            var implantId = await EnrollAsync(client, secret);

            // Clearing a label the implant never carried still appends: the
            // trail reflects each operator action, idempotent like retirement.
            var first = await client.DeleteAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels/ghost");
            var second = await client.DeleteAsync(
                $"/engagements/{engagementId}/implants/{implantId}/labels/ghost");
            Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, second.StatusCode);

            var audit = host.Services.GetRequiredService<IAuditStore>();
            var events = (await audit.ListAsync(Guid.Parse(engagementId)))
                .Where(e => e.Kind == AuditEventKind.ImplantLabeled)
                .ToArray();
            Assert.Equal(2, events.Length);
            Assert.All(events, e => Assert.Equal("ghost", e.Payload));
            Assert.All(events, e => Assert.Equal("cleared", e.Outcome));
            Assert.All(events, e => Assert.Equal(operatorId.Value, e.OperatorId));
        }
    }
}
