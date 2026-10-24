using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Rod.Audit;
using Rod.CoreState.Operators;
using Rod.Transport.Endpoints;
using static Rod.Integration.Tests.EngagementSetup;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: the host picture -- the device dimension of the intel layer
/// (architecture.md Sec 11.2). Implants group under the hostname they report
/// at enroll; operator notes and labels on a host are attributed audit events
/// read back from the trail; and the host key is case-insensitive, so
/// "WEB01" and "web01" are one host in every view. No host entity exists --
/// these tests pin that the grouping and the facts are all read-side over the
/// stores that already hold them.
/// </summary>
public sealed class HostIntelEndpointsTests
{
    private static async Task<string> EnrollWithHostnameAsync(HttpClient client, string secret, string hostname)
    {
        var response = await client.PostAsJsonAsync("/implants/enroll",
            new EnrollmentEndpoints.EnrollRequest(
                DeployTokenSecret: secret, Hostname: hostname, Os: "linux", Arch: "x86_64"));
        response.EnsureSuccessStatusCode();
        var enrolled = await response.Content.ReadFromJsonAsync<EnrollmentEndpoints.EnrollmentResponse>();
        return enrolled!.ImplantId!;
    }

    [Fact]
    public async Task Hosts_GroupImplantsByHostname_AndCarryTrailFacts()
    {
        var (client, host, operatorId) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var firstSecret = await MintDeployTokenAsync(client, engagementId);
            var secondSecret = await MintDeployTokenAsync(client, engagementId);
            var thirdSecret = await MintDeployTokenAsync(client, engagementId);
            var webA = await EnrollWithHostnameAsync(client, firstSecret, "web01");
            var webB = await EnrollWithHostnameAsync(client, secondSecret, "WEB01");
            var nameless = await EnrollAsync(client, thirdSecret);

            // A note and a label on the host, written against a different
            // spelling than the implants reported -- the key folds them
            // together.
            var noted = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/hosts/Web01/notes",
                new HostEndpoints.AddHostNoteRequest(Text: "edge web tier, HVXC"));
            Assert.Equal(HttpStatusCode.Created, noted.StatusCode);
            var labeled = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/hosts/web01/labels",
                new HostEndpoints.SetHostLabelRequest(Label: "dmz"));
            Assert.Equal(HttpStatusCode.Created, labeled.StatusCode);

            var body = await client.GetFromJsonAsync<HostEndpoints.HostsResponse>(
                $"/engagements/{engagementId}/hosts");
            Assert.NotNull(body);

            // Two implants that spelled the host differently group together;
            // the one that reported no hostname stays ungrouped rather than
            // pinned to an invented host.
            var web01 = Assert.Single(body!.Hosts, h => h.Host == "web01");
            Assert.Equal(2, web01.ImplantIds.Length);
            Assert.Contains(webA, web01.ImplantIds);
            Assert.Contains(webB, web01.ImplantIds);
            Assert.Equal("linux", web01.Os);
            Assert.Equal(1, web01.NoteCount);
            Assert.Equal(new[] { "dmz" }, web01.Labels);
            Assert.Equal(new[] { nameless }, body.UngroupedImplantIds);

            // The facts carry attribution in the trail (the AC's leg):
            // HostNoteAdded and HostLabeled events attributed to the writer.
            var audit = host.Services.GetRequiredService<IAuditStore>();
            var trail = await audit.ListAsync(Guid.Parse(engagementId));
            var note = Assert.Single(trail, e => e.Kind == AuditEventKind.HostNoteAdded);
            Assert.Equal(operatorId.Value, note.OperatorId);
            var label = Assert.Single(trail, e => e.Kind == AuditEventKind.HostLabeled);
            Assert.Equal(operatorId.Value, label.OperatorId);
            Assert.Contains("\"host\":\"web01\"", label.Payload);
        }
    }

    [Fact]
    public async Task Host_NotesAndLabels_ReadBackAndReduce()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            // A host only a fact names -- recon has seen it, nothing occupies
            // it -- still holds notes and labels; the picture spans more than
            // the fleet.
            var first = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/hosts/db-internal/notes",
                new HostEndpoints.AddHostNoteRequest(Text: "seen in portscan, no implant yet"));
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);
            var note = await first.Content.ReadFromJsonAsync<HostEndpoints.HostNoteResponse>();
            Assert.NotNull(note);
            Assert.Equal("db-internal", note!.Host);
            Assert.Equal(AuthenticatedHost.Handle, note.AuthorHandle);

            await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/hosts/db-internal/labels",
                new HostEndpoints.SetHostLabelRequest(Label: "tier-2"));
            await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/hosts/DB-Internal/labels",
                new HostEndpoints.SetHostLabelRequest(Label: "owned"));
            var cleared = await client.DeleteAsync(
                $"/engagements/{engagementId}/hosts/db-internal/labels/tier-2");
            Assert.Equal(HttpStatusCode.NoContent, cleared.StatusCode);

            var notes = await client.GetFromJsonAsync<HostEndpoints.HostNoteResponse[]>(
                $"/engagements/{engagementId}/hosts/DB-INTERNAL/notes");
            var readBack = Assert.Single(notes!);
            Assert.Equal(note.NoteId, readBack.NoteId);
            Assert.Equal("db-internal", readBack.Host);
            Assert.Equal(AuthenticatedHost.Handle, readBack.AuthorHandle);

            var labels = await client.GetFromJsonAsync<HostEndpoints.HostLabelResponse[]>(
                $"/engagements/{engagementId}/hosts/db-internal/labels");
            var owned = Assert.Single(labels!);
            Assert.Equal("owned", owned.Label);
            Assert.Equal(AuthenticatedHost.Handle, owned.SetByHandle);

            // A host only a note names -- no label, no implant, no
            // observation -- still holds its place in the listing: the
            // picture spans what the crew has written down, not only what
            // carries a marker.
            await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/hosts/fw-edge/notes",
                new HostEndpoints.AddHostNoteRequest(Text: "perimeter firewall, no agent possible"));

            var listing = await client.GetFromJsonAsync<HostEndpoints.HostsResponse>(
                $"/engagements/{engagementId}/hosts");
            Assert.Equal(2, listing!.Hosts.Length);
            var entry = Assert.Single(listing.Hosts, h => h.Host == "db-internal");
            Assert.Equal("db-internal", entry.Host);
            Assert.Equal(1, entry.NoteCount);
            Assert.Equal(new[] { "owned" }, entry.Labels);
            Assert.Empty(entry.ImplantIds);
            var noteOnly = Assert.Single(listing.Hosts, h => h.Host == "fw-edge");
            Assert.Equal(1, noteOnly.NoteCount);
            Assert.Empty(noteOnly.Labels);
            Assert.Empty(noteOnly.ImplantIds);
        }
    }

    [Fact]
    public async Task HostFacts_ValidateTheRequest()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            // A blank host cannot be named.
            var blankHost = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/hosts/%20/notes",
                new HostEndpoints.AddHostNoteRequest(Text: "note"));
            Assert.Equal(HttpStatusCode.BadRequest, blankHost.StatusCode);

            // Blank note text is malformed; an oversized note is refused.
            var blankNote = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/hosts/web01/notes",
                new HostEndpoints.AddHostNoteRequest(Text: " "));
            Assert.Equal(HttpStatusCode.BadRequest, blankNote.StatusCode);
            var oversized = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/hosts/web01/notes",
                new HostEndpoints.AddHostNoteRequest(Text: new string('x', 8 * 1024 + 1)));
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oversized.StatusCode);

            // Label bounds match the implant-side vocabulary.
            var oversizedLabel = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/hosts/web01/labels",
                new HostEndpoints.SetHostLabelRequest(Label: new string('x', 65)));
            Assert.Equal(HttpStatusCode.BadRequest, oversizedLabel.StatusCode);

            // An unknown engagement is the scoped-read 404 ladder.
            var foreign = await client.PostAsJsonAsync(
                $"/engagements/{Guid.NewGuid()}/hosts/web01/notes",
                new HostEndpoints.AddHostNoteRequest(Text: "note"));
            Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
            var foreignList = await client.GetAsync($"/engagements/{Guid.NewGuid()}/hosts");
            Assert.Equal(HttpStatusCode.NotFound, foreignList.StatusCode);

            // Nothing from the refused posts landed in the trail.
            var audit = host.Services.GetRequiredService<IAuditStore>();
            Assert.DoesNotContain(
                await audit.ListAsync(Guid.Parse(engagementId)),
                e => e.Kind is AuditEventKind.HostNoteAdded or AuditEventKind.HostLabeled);
        }
    }
}
