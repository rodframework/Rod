using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.Transport.Endpoints;
using static Rod.Integration.Tests.EngagementSetup;
using Rod.BuildPipeline.PayloadBuild;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: requesting a payload invokes a build unit and returns
/// an artifact, fingerprinted and recorded. Drives the full slice end-to-end
/// through the in-memory TestServer -- the operator POSTs a build request, the
/// build pipeline invokes the in-tree .NET build unit (ADR 0009; the real
/// reference unit for the .NET slot), and the operator gets back a fingerprinted
/// artifact while a PayloadBuilt audit event is appended to the engagement's
/// hash-chained trail.
/// The build service is audit-agnostic by design; the transport endpoint composes
/// the recording (architecture.md Sec 6, Sec 11), the same way the beacon stream
/// records task completion. The requesting operator is the logged-in operator,
/// recorded by the server off the session principal, so the audit attributes the
/// build to that identity regardless of the request body.
/// </summary>
public class PayloadBuildTests
{
    // The API names a listener for a web or socket front, and so do these
    // tests. The socket family's tcp front: it binds its own socket (the web
    // family rides the Kestrel endpoint reloader, which this TestServer host
    // does not wire), and its baked dial is the public endpoint verbatim --
    // exactly what the assertions read.
    private static async Task<string> CreateFrontListenerAsync(
        HttpClient client, string engagementId,
        string transport = "tcp", string publicEndpoint = "c2.example.test:443")
    {
        var created = await client.PostAsJsonAsync(
            $"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: $"build-front-{transport}",
                Transport: transport,
                BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
                PublicEndpoint: publicEndpoint));
        created.EnsureSuccessStatusCode();
        var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        return listener!.Id;
    }

    [RustFact]
    public async Task BuildPayload_InvokesBuildUnit_ReturnsFingerprintedArtifact()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var listenerId = await CreateFrontListenerAsync(client, engagementId);

            var response = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust,
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    ListenerId: listenerId,
                    UriPath: "/beacon",
                    SleepSeconds: 30,
                    JitterSeconds: 10,
                    KillDate: null));

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<PayloadEndpoints.BuildPayloadResponse>();
            Assert.NotNull(body);
            Assert.False(string.IsNullOrWhiteSpace(body!.ArtifactId));
            Assert.Equal("Implant", body.Class);
            Assert.Equal(BuildUnitIds.Rust, body.UnitId);
            Assert.False(string.IsNullOrWhiteSpace(body.ContentType));
            Assert.True(body.Size > 0);
            // SHA-256 lowercase hex, 64 chars.
            Assert.Equal(64, body.Fingerprint.Length);
            Assert.True(body.Fingerprint.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f'));
            // The Location is the new artifact's URI (relative in TestServer).
            Assert.EndsWith($"/payloads/{body.ArtifactId}", response.Headers.Location!.ToString());
        }
    }

    [Fact]
    public async Task BuildPayload_RefusesAnEndpointTheImplantCannotDial()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var listenerId = await CreateFrontListenerAsync(client, engagementId);

            // A typed endpoint is the DNS family's dial alone, and garbage is
            // refused before anything builds -- a payload that phones nowhere
            // is the silent failure an operator discovers on target.
            var garbage = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust,
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    Endpoint: "not a url",
                    UriPath: "/beacon",
                    SleepSeconds: 30,
                    JitterSeconds: 10,
                    KillDate: null));
            Assert.Equal(HttpStatusCode.BadRequest, garbage.StatusCode);

            // A malformed fallback entry is refused the same way, even when
            // the primary endpoint is fine.
            var garbageFallback = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust,
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    ListenerId: listenerId,
                    UriPath: "/beacon",
                    SleepSeconds: 30,
                    JitterSeconds: 10,
                    KillDate: null,
                    FallbackEndpoints: new List<string> { "http://alt.example.test", "666" }));
            Assert.Equal(HttpStatusCode.BadRequest, garbageFallback.StatusCode);
        }
    }

    [Fact]
    public async Task BuildPayload_RefusesAFallbackOutsideTheFrontsSchemeFamily()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var tcpListenerId = await CreateFrontListenerAsync(client, engagementId);

            // One build rides one protocol: the fallback list is the
            // front's own family in walk order, never a mix -- one refusal
            // per family pairing, both directions of the socket family
            // included. The DNS front stays typed: the DNS family's dial is
            // the one a typed endpoint still names.
            var tcpFrontWithDnsFallback = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust,
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    ListenerId: tcpListenerId,
                    UriPath: "/beacon",
                    SleepSeconds: 30,
                    JitterSeconds: 10,
                    KillDate: null,
                    FallbackEndpoints: new List<string> { "dns://alt.example.test" }));
            Assert.Equal(HttpStatusCode.BadRequest, tcpFrontWithDnsFallback.StatusCode);

            var tcpFrontWithWebFallback = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust,
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    ListenerId: tcpListenerId,
                    UriPath: "/beacon",
                    SleepSeconds: 30,
                    JitterSeconds: 10,
                    KillDate: null,
                    FallbackEndpoints: new List<string> { "http://alt.example.test" }));
            Assert.Equal(HttpStatusCode.BadRequest, tcpFrontWithWebFallback.StatusCode);

            var dnsFrontWithWebFallback = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust,
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    Endpoint: "dns://c2.example.test",
                    UriPath: "/beacon",
                    SleepSeconds: 30,
                    JitterSeconds: 10,
                    KillDate: null,
                    Mode: "poll",
                    FallbackEndpoints: new List<string> { "https://alt.example.test" }));
            Assert.Equal(HttpStatusCode.BadRequest, dnsFrontWithWebFallback.StatusCode);
        }
    }

    [RustFact]
    public async Task BuildPayload_BakesSameFamilyFallbacks()
    {
        // The same-family walk is the fallback list's whole contract: the
        // web pair (http/https), the DNS pair (dns/doh), the raw socket. A
        // front with its own family's fallback builds -- the walk order
        // survives to the baked profile.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var listenerId = await CreateFrontListenerAsync(client, engagementId);

            var response = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust,
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    ListenerId: listenerId,
                    UriPath: "/beacon",
                    SleepSeconds: 30,
                    JitterSeconds: 10,
                    KillDate: null,
                    FallbackEndpoints: new List<string> { "tcp://alt.example.test:443" }));
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        }
    }

    [RustFact]
    public async Task BuiltPayload_IsRetrievableFromItsLocation()
    {
        // The build response's Location resolves to a real download route: the
        // operator retrieves the compiled bytes, engagement-scoped, with a
        // content disposition naming the payload.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var built = await PostBuildAsync(client, engagementId);
            Assert.NotNull(built);

            var download = await client.GetAsync($"/engagements/{engagementId}/payloads/{built!.ArtifactId}");
            Assert.Equal(HttpStatusCode.OK, download.StatusCode);
            Assert.Equal(built.ContentType, download.Content.Headers.ContentType!.MediaType);
            Assert.StartsWith("attachment;", download.Content.Headers.ContentDisposition!.ToString());
            var bytes = await download.Content.ReadAsByteArrayAsync();
            Assert.Equal(built.Size, bytes.Length);
        }
    }

    [RustFact]
    public async Task PayloadLibrary_ListsAndDeletes_WithAnAuditFact()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var audit = host.Services.GetRequiredService<IAuditStore>();

            var built = await PostBuildAsync(client, engagementId);

            // The library row carries the build's own metadata -- target,
            // endpoint, and the baked credential's id for revocation -- so the
            // durable store reads like the build that made it. The budget
            // columns are the token's live state (default mint: one use, one
            // hour), joined at list time rather than stored on the row.
            var listed = await client.GetFromJsonAsync<PayloadEndpoints.PayloadSummaryResponse[]>(
                $"/engagements/{engagementId}/payloads");
            var row = Assert.Single(listed!);
            Assert.Equal(built!.ArtifactId, row.ArtifactId);
            Assert.Equal("linux/amd64", row.Target);
            Assert.Equal("tcp://c2.example.test:443", row.Endpoint);
            Assert.Equal(built.TokenId, row.TokenId);
            Assert.Equal(1, row.TokenMaxUses);
            Assert.Equal(1, row.TokenRemainingUses);
            Assert.NotNull(row.TokenExpiresAt);

            // The build-parameter snapshot: what the form carried when the
            // artifact was generated, read back from the library row. The
            // request named no mode, so the snapshot carries the default the
            // parser applied -- poll, the posture every front serves.
            Assert.NotNull(row.Build);
            Assert.Equal("poll", row.Build!.Mode);
            Assert.Equal(30, row.Build.SleepSeconds);
            Assert.Equal(10, row.Build.JitterSeconds);
            Assert.Equal(1, row.Build.TokenMaxUses);
            Assert.Equal("AesGcm", row.Build.Envelope);
            Assert.True(row.Build.ContactProtection);

            // The join is live: revoking the baked credential removes the
            // token, and the next listing keeps the historical id but reads
            // no budget -- "no enrollments left" on the operator's row.
            var tokens = host.Services.GetRequiredService<Rod.CoreState.Deployment.IDeployTokenService>();
            Assert.True(await tokens.RevokeAsync(
                new Rod.CoreState.DeployTokenId(Guid.Parse(built.TokenId!))));
            var revoked = await client.GetFromJsonAsync<PayloadEndpoints.PayloadSummaryResponse[]>(
                $"/engagements/{engagementId}/payloads");
            var revokedRow = Assert.Single(revoked!);
            Assert.Equal(built.TokenId, revokedRow.TokenId);
            Assert.Null(revokedRow.TokenMaxUses);
            Assert.Null(revokedRow.TokenRemainingUses);
            Assert.Null(revokedRow.TokenExpiresAt);

            // Deleting is the kill switch for hosted bytes: the row and the
            // download are gone, a second delete 404s, and the trail records
            // what was removed by whom.
            var deleted = await client.DeleteAsync($"/engagements/{engagementId}/payloads/{built.ArtifactId}");
            Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
            var emptied = await client.GetFromJsonAsync<PayloadEndpoints.PayloadSummaryResponse[]>(
                $"/engagements/{engagementId}/payloads");
            Assert.NotNull(emptied);
            Assert.Empty(emptied!);
            Assert.Equal(HttpStatusCode.NotFound,
                (await client.GetAsync($"/engagements/{engagementId}/payloads/{built.ArtifactId}")).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound,
                (await client.DeleteAsync($"/engagements/{engagementId}/payloads/{built.ArtifactId}")).StatusCode);

            var trail = await audit.ListAsync(Guid.Parse(engagementId));
            var deletion = Assert.Single(trail, e => e.Kind == AuditEventKind.PayloadDeleted);
            Assert.Equal("payload.delete", deletion.Verb);
            Assert.Equal(built.Fingerprint, deletion.Outcome);
            Assert.Null(AuditChain.VerifyTrail(trail));
        }
    }

    [Fact]
    public async Task BuildPayload_RefusesAKillDateInThePast()
    {
        // A past fuse can only be a mistake -- the artifact would refuse to run
        // the moment it landed -- so it is refused at parse time, before any
        // build work, instead of silently baking a dead payload.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var listenerId = await CreateFrontListenerAsync(client, engagementId);

            var response = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust,
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    ListenerId: listenerId,
                    UriPath: "/beacon",
                    SleepSeconds: 30,
                    JitterSeconds: 10,
                    KillDate: DateTimeOffset.UtcNow.AddDays(-1)));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [RustFact]
    public async Task BuildPayload_MintsAnUnlimitedCredential_WhenMaxUsesIsZero()
    {
        // Zero max uses is the unlimited budget: the mint records it, the
        // library join reads 0/0 ("not counted", never "spent"), and an
        // open-ended build (no kill date) keeps the 30-day collection window
        // -- an implant may run for years, a dropped credential should not
        // stay redeemable for them.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var listenerId = await CreateFrontListenerAsync(client, engagementId);

            var response = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust,
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    ListenerId: listenerId,
                    UriPath: "/beacon",
                    SleepSeconds: 30,
                    JitterSeconds: 10,
                    KillDate: null,
                    TokenMaxUses: 0));
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var built = await response.Content.ReadFromJsonAsync<PayloadEndpoints.BuildPayloadResponse>();
            Assert.NotNull(built);

            var listed = await client.GetFromJsonAsync<PayloadEndpoints.PayloadSummaryResponse[]>(
                $"/engagements/{engagementId}/payloads");
            var row = Assert.Single(listed!);
            Assert.Equal(built!.TokenId, row.TokenId);
            Assert.Equal(0, row.TokenMaxUses);
            Assert.Equal(0, row.TokenRemainingUses);
            Assert.NotNull(row.TokenExpiresAt);
            Assert.True(row.TokenExpiresAt!.Value <= DateTimeOffset.UtcNow.AddDays(31));
            // The open-ended snapshot: no fuse recorded on the row.
            Assert.Null(row.Build!.KillDate);
        }
    }

    [Fact]
    public async Task BuiltPayload_IsInvisibleToAnotherEngagement()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var first = await CreateEngagementAsync(client);
            var second = await CreateEngagementAsync(client);

            var built = await PostBuildAsync(client, first);

            var download = await client.GetAsync($"/engagements/{second}/payloads/{built!.ArtifactId}");
            Assert.Equal(HttpStatusCode.NotFound, download.StatusCode);
        }
    }

    [RustFact]
    public async Task TwoBuilds_WithIdenticalRequest_ProduceDifferentArtifacts()
    {
        // Per-implant material is generated at request time, so two builds of the
        // same request never share a key and never share a fingerprint
        // (architecture.md Sec 6/Sec 5.1).
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var first = await PostBuildAsync(client, engagementId);
            var second = await PostBuildAsync(client, engagementId);

            Assert.NotEqual(first!.ArtifactId, second!.ArtifactId);
            Assert.NotEqual(first.Fingerprint, second.Fingerprint);
        }
    }

    private static async Task<PayloadEndpoints.BuildPayloadResponse?> PostBuildAsync(
        HttpClient client, string engagementId)
    {
        var listenerId = await CreateFrontListenerAsync(client, engagementId);
        var response = await client.PostAsJsonAsync(
            $"/engagements/{engagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Unit: BuildUnitIds.Rust,
                Class: "Implant",
                TargetOs: "linux",
                TargetArch: "amd64",
                ListenerId: listenerId,
                UriPath: "/beacon",
                SleepSeconds: 30,
                JitterSeconds: 10,
                KillDate: null));
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<PayloadEndpoints.BuildPayloadResponse>();
    }

    [RustFact]
    public async Task BuildPayload_RecordsPayloadBuiltAuditEvent_OnTheChain()
    {
        var (client, host, operatorId) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);
            var listenerId = await CreateFrontListenerAsync(client, engagementId);
            var audit = host.Services.GetRequiredService<IAuditStore>();

            var response = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: BuildUnitIds.Rust,
                    Class: "Implant",
                    TargetOs: "linux",
                    TargetArch: "amd64",
                    ListenerId: listenerId,
                    UriPath: "/beacon",
                    SleepSeconds: 30,
                    JitterSeconds: 10,
                    KillDate: null));
            var body = await response.Content.ReadFromJsonAsync<PayloadEndpoints.BuildPayloadResponse>();

            // The build is recorded: the engagement's trail holds a PayloadBuilt
            // event carrying the class and the artifact's fingerprint, and the
            // chain is intact. The trail also carries the engagement's own
            // creation event ( genesis), so it is no longer a single entry.
            var trail = await audit.ListAsync(Guid.Parse(engagementId));
            var evt = Assert.Single(trail, e => e.Kind == AuditEventKind.PayloadBuilt);
            Assert.Equal("payload.build", evt.Verb);
            Assert.Equal(body!.Fingerprint, evt.Outcome);
            // The audit attributes the build to the authenticated operator, not any
            // client-supplied identity.
            Assert.Equal(operatorId.Value, evt.OperatorId);
            Assert.Null(AuditChain.VerifyTrail(trail));
        }
    }

    [Fact]
    public async Task BuildPayload_Returns400_ForMalformedEngagementId()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);

            var response = await client.PostAsJsonAsync(
                "/engagements/not-a-guid/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: null,
                    Class: null,
                    TargetOs: null,
                    TargetArch: null,
                    Endpoint: null,
                    UriPath: null,
                    SleepSeconds: null,
                    JitterSeconds: null,
                    KillDate: null));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task BuildPayload_Returns400_ForAMalformedUnitId()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var response = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: "Not A Unit Id", // not a well-formed kebab id; an
                                           // unregistered-but-well-formed id is the job's own failure, not a 400
                    Class: null,
                    TargetOs: null,
                    TargetArch: null,
                    Endpoint: null,
                    UriPath: null,
                    SleepSeconds: null,
                    JitterSeconds: null,
                    KillDate: null));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task BuildPayload_Returns400_ForUnknownFormat()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var response = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: null,
                    Class: null,
                    TargetOs: null,
                    TargetArch: null,
                    Endpoint: null,
                    UriPath: null,
                    SleepSeconds: null,
                    JitterSeconds: null,
                    KillDate: null,
                    Format: "shellcode")); // not a form factor

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task BuildPayload_Returns400_ForTheServedBrowserClass()
    {
        // The browser class's artifact is a rendered hook script served by
        // the teamserver (architecture.md Sec 8), so the compiled-build
        // contract refuses the spelling and names the mint that owns it.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var response = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: null,
                    Class: "Browser",
                    TargetOs: null,
                    TargetArch: null,
                    Endpoint: null,
                    UriPath: null,
                    SleepSeconds: null,
                    JitterSeconds: null,
                    KillDate: null));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task BuildPayload_Returns400_ForTheRetiredStagerClass()
    {
        // The stager class retired with the .NET trees; the request answers
        // with the current delivery story instead of building a loader.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var response = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: null,
                    Class: "Stager",
                    TargetOs: null,
                    TargetArch: null,
                    Endpoint: null,
                    UriPath: null,
                    SleepSeconds: null,
                    JitterSeconds: null,
                    KillDate: null));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task BuildPayload_Returns400_ForTheRetiredDllFormat()
    {
        // The dll bundle was the .NET in-memory shape; with the .NET implant
        // gone there is no producer, and the parse says so.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            await AuthenticatedHost.LoginAsync(client);
            var engagementId = await CreateEngagementAsync(client);

            var response = await client.PostAsJsonAsync(
                $"/engagements/{engagementId}/payloads",
                new PayloadEndpoints.BuildPayloadRequest(
                    Unit: null,
                    Class: null,
                    TargetOs: null,
                    TargetArch: null,
                    Endpoint: null,
                    UriPath: null,
                    SleepSeconds: null,
                    JitterSeconds: null,
                    KillDate: null,
                    Format: "dll"));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }
}
