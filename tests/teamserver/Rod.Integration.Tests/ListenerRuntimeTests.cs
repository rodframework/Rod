using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Listeners;
using Rod.CoreState.Deployment;
using Rod.Transport;
using Rod.Transport.Endpoints;
using Rod.Transport.Listeners;
using static Rod.Integration.Tests.EngagementSetup;
using Rod.BuildPipeline.PayloadBuild;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: an engagement's listeners are created and deleted through the
/// engagement-scoped operator API, over the same real Kestrel sockets the
/// startup configuration binds. A created HTTP listener actually serves; a
/// created stream (raw TCP) listener accepts connections; deleting either
/// unbinds its socket. The startup-configuration tier (the operator front) is
/// invisible to these routes and refuses implant ingress: enrollment rides an
/// engagement's own listener or nothing, and a token minted for another
/// engagement is refused whole (unspent) there.
/// </summary>
public class ListenerRuntimeTests
{
    [Fact]
    public async Task NetworkInterfaces_ListTheBindableAddresses_AndRequireASession()
    {
        var (client, host, _) = AuthenticatedHost.Create();
        using var _ = host;

        // Anonymous reads the 401 every operator surface answers with.
        var anonymous = await client.GetAsync("/network/interfaces");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        // Authenticated, the host's own interfaces read back -- loopback
        // always among them, the shape the bind dropdown offers.
        await AuthenticatedHost.LoginAsync(client);
        var listed = await client.GetFromJsonAsync<NetworkEndpoints.InterfaceResponse[]>(
            "/network/interfaces");
        Assert.NotNull(listed);
        Assert.Contains(listed!, i => i.Address == "127.0.0.1");
    }

    [Fact]
    public async Task HttpListener_CreatedAtRuntime_ServesAndDeletes()
    {
        var extraPort = TestSupport.GetFreeTcpPort();
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "runtime-http",
                Transport: "http",
                BindAddress: $"127.0.0.1:{extraPort}",
                PublicEndpoint: "http://runtime.example.test"));
        created.EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.NotNull(listener);
        Assert.Equal("running", listener!.State);

        // The created listener is a real ingress: the app answers on its
        // socket (the anonymous health probe rides every listener).
        using (var probe = new HttpClient())
        {
            var health = await probe.GetAsync($"http://127.0.0.1:{extraPort}/health");
            health.EnsureSuccessStatusCode();
        }

        // The engagement's listing reports it; the operator front never
        // appears -- the startup tier is configuration plumbing, not a
        // listener the engagement owns.
        var roster = await env.Http.GetFromJsonAsync<ListenerEndpoints.ListenerResponse[]>(
            $"/engagements/{engagementId}/listeners");
        Assert.NotNull(roster);
        var recorded = Assert.Single(roster!);
        Assert.Equal("runtime-http", recorded.Name);
        Assert.Equal("running", recorded.State);

        // Delete: the listing drops it immediately, and the socket drains and
        // unbinds (Kestrel allows seconds for in-flight requests).
        var deleted = await env.Http.DeleteAsync($"/engagements/{engagementId}/listeners/{listener.Id}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        var afterDelete = await env.Http.GetFromJsonAsync<ListenerEndpoints.ListenerResponse[]>(
            $"/engagements/{engagementId}/listeners");
        Assert.NotNull(afterDelete);
        Assert.Empty(afterDelete!);

        await WaitForRefusedAsync(extraPort);
    }

    [Fact]
    public async Task HttpsListener_ServesBothHalvesWithoutAClientCertificateAtTLS()
    {
        // The single-port https shape (the mainstream C2 listener): TLS
        // terminates with the CA-issued leaf and never requests a client
        // certificate -- the handshake is indistinguishable from an ordinary
        // website's (a TLS CertificateRequest is itself an IDS fingerprint),
        // and both halves authenticate at the application layer: enrollment
        // on the deploy token, contacts under the per-artifact key the
        // build baked (architecture.md Sec 8/9). One socket, both halves.
        var port = TestSupport.GetFreeTcpPort();
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "single-port-https",
                Transport: "https",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"127.0.0.1:{port}"));
        created.EnsureSuccessStatusCode();
        var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.NotNull(listener);
        Assert.Equal("running", listener!.State);

        // A client that carries no certificate and trusts only the
        // teamserver's own CA -- the shape a fresh implant's enroll client
        // has. It deliberately OFFERS a self-signed certificate: if the
        // listener ever asked to see one, the offered cert would fail the
        // chain-to-CA validation and kill the TLS handshake, so any HTTP
        // answer below is also the wire-level proof no CertificateRequest
        // rode the handshake.
        var ca = env.Host.Services
            .GetRequiredService<Rod.CoreState.Pki.IImplantCertificateAuthority>()
            .GetCaCertificate();
        using var offered = TestSupport.OfferedCertificate();
        using var handler = new SocketsHttpHandler
        {
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                ClientCertificates =
                    new System.Security.Cryptography.X509Certificates.X509CertificateCollection { offered },
                RemoteCertificateValidationCallback = TestSupport.PinTo(ca),
            },
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri($"https://127.0.0.1:{port}") };

        // Enrollment reaches its route over TLS without a client certificate
        // (the bad token's 401 proves the route answered, not the TLS layer --
        // and that the handshake above never asked for the offered one).
        var enroll = await client.PostAsJsonAsync("/implants/enroll",
            new EnrollmentEndpoints.EnrollRequest(DeployTokenSecret: "not-a-token", Class: null));
        Assert.Equal(HttpStatusCode.Unauthorized, enroll.StatusCode);

        // The contact route answers the certificate-less connection too --
        // a body whose single frame is not a handshake gets the refused
        // handshake status in the response envelope, never a TLS-layer or
        // identity 401: the key a real artifact seals with is the identity
        // here, and this body carries none.
        var beacon = await client.PostAsync("/implants/beacon",
            new ByteArrayContent(new byte[] { 0x00 }));
        Assert.Equal(HttpStatusCode.OK, beacon.StatusCode);
        var frames = ParseFrames(await beacon.Content.ReadAsByteArrayAsync());
        var handshake = Rod.V1.HandshakeResponse.Parser.ParseFrom(frames[0].Payload);
        Assert.Equal(Rod.V1.HandshakeStatus.VersionMismatch, handshake.Status);
    }

    [Fact]
    public async Task HttpsListener_Enrollment_StampsItsListenerId_AndRefusesAForeignEngagementsToken()
    {
        // The enrollment-ingress lookup once matched only the http and mtls
        // wire names, so an enrollment riding an https listener resolved no
        // ingress: the implant record carried no listener id (the delete
        // guard could not see it) and the token's engagement-scope check
        // against the socket was skipped. Both halves of that gap are pinned
        // here, over the same certificate-less TLS shape the test above
        // rides.
        var port = TestSupport.GetFreeTcpPort();
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);

        // Two engagements; the https listener belongs to the first.
        var owning = await CreateEngagementAsync(env.Http);
        var foreign = await CreateEngagementAsync(env.Http);
        var created = await env.Http.PostAsJsonAsync($"/engagements/{owning}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "scoped-https",
                Transport: "https",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"127.0.0.1:{port}"));
        created.EnsureSuccessStatusCode();
        var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.NotNull(listener);

        // A client that trusts only the teamserver's own CA -- the TLS shape
        // a fresh implant's enroll client has.
        var ca = env.Host.Services
            .GetRequiredService<Rod.CoreState.Pki.IImplantCertificateAuthority>()
            .GetCaCertificate();
        using var handler = new SocketsHttpHandler
        {
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = TestSupport.PinTo(ca),
            },
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri($"https://127.0.0.1:{port}") };

        // The foreign engagement's token is refused on the scoped socket --
        // whole, its single use intact for the listener it was minted for.
        var foreignSecret = await MintTokenAsync(env.Http, foreign);
        var refused = await client.PostAsJsonAsync("/implants/enroll",
            new EnrollmentEndpoints.EnrollRequest(DeployTokenSecret: foreignSecret, Class: null));
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        var tokens = env.Host.Services.GetRequiredService<IDeployTokenService>();
        Assert.True(EngagementId.TryParse(foreign, out var foreignId));
        var redeemed = await tokens.RedeemAsync(foreignSecret, DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Equal(foreignId, redeemed.EngagementId);

        // The owning engagement's token enrolls through the same socket, and
        // the implant record carries the https listener's id -- the ingress
        // stamp the listener-delete guard counts.
        var owningSecret = await MintTokenAsync(env.Http, owning);
        var enrolled = await client.PostAsJsonAsync("/implants/enroll",
            new EnrollmentEndpoints.EnrollRequest(DeployTokenSecret: owningSecret, Class: null));
        enrolled.EnsureSuccessStatusCode();
        var body = await enrolled.Content.ReadFromJsonAsync<EnrollmentEndpoints.EnrollmentResponse>();
        Assert.NotNull(body);
        Assert.True(Guid.TryParse(body!.ImplantId, out var implantValue));

        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        var record = await implants.FindAsync(new ImplantId(implantValue));
        Assert.NotNull(record);
        Assert.Equal(listener!.Id, record!.EnrolledViaListenerId?.ToString("N"));
    }

    [Fact]
    public async Task ScopedListener_RefusesAForeignEngagementsToken_AndTheFrontRefusesImplants()
    {
        var scopedPort = TestSupport.GetFreeTcpPort();
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);

        // Two engagements; the scoped listener belongs to the first.
        var owning = await CreateEngagementAsync(env.Http);
        var foreign = await CreateEngagementAsync(env.Http);
        var created = await env.Http.PostAsJsonAsync($"/engagements/{owning}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "scoped-http",
                Transport: "http",
                BindAddress: $"127.0.0.1:{scopedPort}",
                PublicEndpoint: "http://scoped.example.test"));
        created.EnsureSuccessStatusCode();

        // The foreign engagement's token is refused on the scoped socket --
        // whole, before the redeem spends it.
        var foreignSecret = await MintTokenAsync(env.Http, foreign);
        using var scoped = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{scopedPort}") };
        var refused = await scoped.PostAsJsonAsync("/implants/enroll",
            new EnrollmentEndpoints.EnrollRequest(DeployTokenSecret: foreignSecret, Class: null));
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);

        // The operator front refuses implant ingress outright: it carries no
        // enrollment at all, whatever token is presented.
        var onFront = await env.Http.PostAsJsonAsync("/implants/enroll",
            new EnrollmentEndpoints.EnrollRequest(DeployTokenSecret: foreignSecret, Class: null));
        Assert.Equal(HttpStatusCode.Unauthorized, onFront.StatusCode);

        // The owning engagement's token enrolls through the scoped socket --
        // the one path into the engagement.
        var owningSecret = await MintTokenAsync(env.Http, owning);
        var scopedEnroll = await scoped.PostAsJsonAsync("/implants/enroll",
            new EnrollmentEndpoints.EnrollRequest(DeployTokenSecret: owningSecret, Class: null));
        scopedEnroll.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Create_UnknownEngagement_IsRejected()
    {
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);

        var created = await env.Http.PostAsJsonAsync($"/engagements/{Guid.NewGuid()}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "orphan",
                Transport: "http",
                BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
                PublicEndpoint: "http://orphan.example.test"));
        Assert.Equal(HttpStatusCode.NotFound, created.StatusCode);
    }

    [Fact]
    public async Task StoredHttpsEnvelopeDefinition_RebindsAsHttps_AndTheRetiredEntryIsRefused()
    {
        var port = TestSupport.GetFreeTcpPort();
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        // The create form no longer knows the retired entry, and its refusal
        // names exactly the six surviving transports.
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "late-envelope",
                Transport: "https-envelope",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"127.0.0.1:{port}"));
        Assert.Equal(HttpStatusCode.BadRequest, created.StatusCode);
        var problem = await created.Content.ReadFromJsonAsync<Problem>();
        Assert.NotNull(problem);
        // The refusal names the registered transports -- each in-tree member
        // appears, whatever order the registry lists or what later
        // registrations a test suite has added around them.
        foreach (var transport in new[] { "http", "https", "dns", "tcp" })
            Assert.Contains(transport, problem!.Error);

        // A definition saved before the retirement runs the restore path (what
        // a restart runs per definition) and rebinds under its migrated shape:
        // the entry always shared mtls's bind and termination, so the same id
        // comes back as an https listener on the same port.
        Assert.True(EngagementId.TryParse(engagementId, out var owning));
        var definition = new ListenerDefinition(
            Guid.NewGuid(), owning, "envelope-front",
            "https-envelope", $"127.0.0.1:{port}", $"https://envelope.example.test:{port}",
            DateTimeOffset.UtcNow);
        var manager = env.Host.Services.GetRequiredService<ListenerManager>();
        var restored = await manager.RestoreAsync(definition);
        Assert.NotNull(restored);
        Assert.Equal("https", restored!.Transport);

        var registry = env.Host.Services.GetRequiredService<IListenerRegistry>();
        var bound = await registry.FindAsync(new ListenerId(definition.Id));
        Assert.NotNull(bound);
        Assert.Equal("https", bound!.Transport);
        Assert.Equal("running", bound.State.ToString().ToLowerInvariant());

        // The migrated shape is a real socket: the port accepts connections.
        using (var probe = new TcpClient())
        {
            await probe.ConnectAsync(IPAddress.Loopback, port, CancellationToken.None);
        }
    }

    [Fact]
    public async Task StoredKestrelDefinition_RebindsOnHostStartup()
    {
        // A restart must bring the persisted HTTP-family listeners back: the
        // restore runs at ApplicationStarted, after the web server exists.
        // Restoring from StartAsync instead probed the Kestrel-published
        // endpoints before the endpoint reloader was live, timed out, and
        // withdrew them -- every https and doh listener stayed down after
        // every restart.
        var port = TestSupport.GetFreeTcpPort();
        var operatorPort = TestSupport.GetFreeTcpPort();

        var config = AuthenticatedHost.BuildConfig();
        using var host = TransportHost.CreateHostBuilder(
                configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                configuration: config)
            .ConfigureWebHost(webBuilder => webBuilder.UseRodListeners(new[]
            {
                new ListenerConfig("operator-http", "http", $"127.0.0.1:{operatorPort}",
                    "http://localhost:5080"),
            }))
            .Build();

        // The store holds the definition before the start -- the state a
        // restart finds -- so the restore path runs inside this StartAsync.
        // The definition names a real engagement (seeded through the
        // repository, since the wire is not serving yet): the restore skips
        // the listeners of retired or missing engagements, so a random id
        // would never rebind.
        var engagements = host.Services.GetRequiredService<IEngagementRepository>();
        var clock = host.Services.GetRequiredService<TimeProvider>();
        var engagement = Engagement.Create(
            EngagementId.New(), "stored-definition-lab", OperatorId.New(), clock.GetUtcNow());
        await engagements.SaveAsync(engagement);
        var definitionId = Guid.NewGuid();
        var store = host.Services.GetRequiredService<IListenerStore>();
        await store.SaveAsync(new ListenerDefinition(
            definitionId, engagement.Id, "stored-https", "https",
            $"127.0.0.1:{port}", $"https://127.0.0.1:{port}", DateTimeOffset.UtcNow));

        await host.StartAsync();

        // The restore rides the started callback asynchronously; the roster
        // turns running once the endpoint reloader has bound the socket.
        var registry = host.Services.GetRequiredService<IListenerRegistry>();
        Listener? bound = null;
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            bound = await registry.FindAsync(new ListenerId(definitionId));
            if (bound is not null && bound.State.ToString() == "Running")
                break;
            await Task.Delay(100);
        }
        Assert.NotNull(bound);
        Assert.Equal("running", bound!.State.ToString().ToLowerInvariant());

        // The restored endpoint is a real socket: the port accepts.
        using (var probe = new TcpClient())
        {
            await probe.ConnectAsync(IPAddress.Loopback, port, CancellationToken.None);
        }
    }

    [Fact]
    public async Task TcpListener_CreatedAtRuntime_AcceptsAndStops()
    {
        var port = TestSupport.GetFreeTcpPort();
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "pivot-tcp",
                Transport: "tcp",
                BindAddress: $"127.0.0.1:{port}",
                PublicEndpoint: $"203.0.113.10:{port}"));
        created.EnsureSuccessStatusCode();
        var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.NotNull(listener);

        // The stream service bound its socket: a TCP connection is accepted
        // (the contact grammar answers; a bare connect succeeding is enough).
        using (var probe = new TcpClient())
        {
            await probe.ConnectAsync(IPAddress.Loopback, port);
            Assert.True(probe.Connected);
        }

        var deleted = await env.Http.DeleteAsync($"/engagements/{engagementId}/listeners/{listener!.Id}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        await WaitForRefusedAsync(port);
    }

    [Fact]
    public async Task Delete_FrontsAndForeignListeners_AreInvisibleToTheEngagement()
    {
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        // The operator front is bound and serving, but the engagement's
        // routes do not see it: neither listable nor deletable, whatever its
        // registry id.
        var registry = env.Host.Services.GetRequiredService<IListenerRegistry>();
        var front = Assert.Single(await registry.ListAsync());
        var roster = await env.Http.GetFromJsonAsync<ListenerEndpoints.ListenerResponse[]>(
            $"/engagements/{engagementId}/listeners");
        Assert.NotNull(roster);
        Assert.Empty(roster!);

        var deleteFront = await env.Http.DeleteAsync($"/engagements/{engagementId}/listeners/{front.Id}");
        Assert.Equal(HttpStatusCode.NotFound, deleteFront.StatusCode);

        // And it keeps serving the operator API after the refused delete.
        var after = await env.Http.GetFromJsonAsync<ListenerEndpoints.ListenerResponse[]>(
            $"/engagements/{engagementId}/listeners");
        Assert.NotNull(after);
        Assert.Empty(after!);
    }

    [Fact]
    public async Task Create_PortAlreadyInUse_IsRefused()
    {
        var taken = TestSupport.GetFreeTcpPort();
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{taken}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        // The operator front holds the port; a runtime create that asks for
        // the same socket is refused, not silently dropped -- whatever the
        // engagement asking.
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "collide",
                Transport: "http",
                BindAddress: $"127.0.0.1:{taken}",
                PublicEndpoint: "http://collide.example.test"));
        Assert.Equal(HttpStatusCode.Conflict, created.StatusCode);

        var roster = await env.Http.GetFromJsonAsync<ListenerEndpoints.ListenerResponse[]>(
            $"/engagements/{engagementId}/listeners");
        Assert.NotNull(roster);
        Assert.Empty(roster!);
    }

    [Fact]
    public async Task Create_MalformedRequest_IsRejected()
    {
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        var badTransport = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "x", Transport: "carrier-pigeon", BindAddress: "127.0.0.1:9999", PublicEndpoint: "http://x.test"));
        Assert.Equal(HttpStatusCode.BadRequest, badTransport.StatusCode);

        var badBind = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "x", Transport: "http", BindAddress: "not an address", PublicEndpoint: "http://x.test"));
        Assert.Equal(HttpStatusCode.BadRequest, badBind.StatusCode);

        var badEndpoint = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "x", Transport: "http", BindAddress: "127.0.0.1:9999", PublicEndpoint: "not a url"));
        Assert.Equal(HttpStatusCode.BadRequest, badEndpoint.StatusCode);

        // A port typed alone is not a hostname; accepting it would bake a
        // payload that dials a number.
        var barePort = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "x", Transport: "http", BindAddress: "127.0.0.1:9999", PublicEndpoint: "666"));
        Assert.Equal(HttpStatusCode.BadRequest, barePort.StatusCode);
    }

    [Fact]
    public async Task PublicEndpoint_BlankAndBareHostnames_AreCompletedFromTheListener()
    {
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        // Blank means "implants dial the bind itself": the whole endpoint
        // derives from the bind, scheme by transport.
        var directPort = TestSupport.GetFreeTcpPort();
        var direct = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "direct", Transport: "http",
                BindAddress: $"127.0.0.1:{directPort}", PublicEndpoint: ""));
        direct.EnsureSuccessStatusCode();
        var directListener = await direct.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.Equal($"http://127.0.0.1:{directPort}", directListener!.PublicEndpoint);

        // The one blank the derivation refuses: a wildcard bind is every
        // interface, not an address anything can dial, and the refusal names
        // that fact instead of restating the endpoint rule.
        var wildcard = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "wild", Transport: "http",
                BindAddress: $"0.0.0.0:{TestSupport.GetFreeTcpPort()}", PublicEndpoint: ""));
        Assert.Equal(HttpStatusCode.BadRequest, wildcard.StatusCode);
        var wildcardBody = await wildcard.Content.ReadFromJsonAsync<Problem>();
        Assert.Contains("wildcard", wildcardBody!.Error);

        // A bare hostname takes the transport's scheme and the listener's own
        // bind port -- "tmp" is a complete dialable endpoint now.
        var aliasPort = TestSupport.GetFreeTcpPort();
        var aliased = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "aliased", Transport: "http",
                BindAddress: $"127.0.0.1:{aliasPort}", PublicEndpoint: "tmp"));
        aliased.EnsureSuccessStatusCode();
        var aliasListener = await aliased.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.Equal($"http://tmp:{aliasPort}", aliasListener!.PublicEndpoint);

        // The TLS-shaped transports complete with https.
        var httpsPort = TestSupport.GetFreeTcpPort();
        var fronted = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "tls-front", Transport: "https",
                BindAddress: $"127.0.0.1:{httpsPort}", PublicEndpoint: "front.internal"));
        fronted.EnsureSuccessStatusCode();
        var frontListener = await fronted.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.Equal($"https://front.internal:{httpsPort}", frontListener!.PublicEndpoint);

        // A host:port pair is completed with the transport's scheme too: the
        // stored form is always a full URL, never a scheme-less authority,
        // so the roster and every build read one uniform shape.
        var paired = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "redirector", Transport: "http",
                BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}", PublicEndpoint: "203.0.113.10:443"));
        paired.EnsureSuccessStatusCode();
        var pairListener = await paired.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.Equal("http://203.0.113.10:443", pairListener!.PublicEndpoint);

        // The stream transports cannot derive: a DNS listener requires its
        // zone spelled out.
        var zoneless = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "zone", Transport: "dns",
                BindAddress: "0.0.0.0:5333", PublicEndpoint: ""));
        Assert.Equal(HttpStatusCode.BadRequest, zoneless.StatusCode);

        // A repoint completes a bare hostname the same way, so swapping a
        // front never demands more typing than creating one did.
        var repointed = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/listeners/{directListener.Id}:repoint",
            new ListenerEndpoints.RepointListenerRequest(PublicEndpoint: "newfront"));
        repointed.EnsureSuccessStatusCode();
        var repointBody = await repointed.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.Equal($"http://newfront:{directPort}", repointBody!.PublicEndpoint);

        // And a host:port repoint completes the same way -- the roster stays
        // uniform across creates and repoints.
        var repointedPair = await env.Http.PostAsJsonAsync(
            $"/engagements/{engagementId}/listeners/{directListener.Id}:repoint",
            new ListenerEndpoints.RepointListenerRequest(PublicEndpoint: "203.0.113.11:8443"));
        repointedPair.EnsureSuccessStatusCode();
        var repointPairBody = await repointedPair.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        Assert.Equal("http://203.0.113.11:8443", repointPairBody!.PublicEndpoint);
    }

    [Fact]
    public async Task ANamedListener_SuppliesTheBuildEndpoint()
    {
        await using var env = await TestEnv.StartAsync(new ListenerConfig(
            Name: "operator-http",
            Transport: "http",
            BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
            PublicEndpoint: "http://localhost:5080"));
        await AuthenticatedHost.LoginAsync(env.Http);
        var engagementId = await CreateEngagementAsync(env.Http);

        // The listener publishes the bare host:port redirector shape; a build
        // naming it dials that shape with the transport's scheme. The front
        // carries enroll and contact on one socket.
        var created = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "build-front",
                Transport: "https",
                BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
                PublicEndpoint: "203.0.113.10:8443"));
        created.EnsureSuccessStatusCode();
        var listener = await created.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();

        var built = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Unit: BuildUnitIds.Rust,
                Class: "Implant",
                TargetOs: "linux",
                TargetArch: "amd64",
                Endpoint: null,
                UriPath: "/beacon",
                SleepSeconds: 30,
                JitterSeconds: 10,
                KillDate: null,
                ListenerId: listener!.Id));
        Assert.Equal(HttpStatusCode.Created, built.StatusCode);

        // Another engagement's listener is refused: an artifact dials its own
        // engagement's ingress or nothing.
        var foreignEngagement = await CreateEngagementAsync(env.Http);
        var foreign = await env.Http.PostAsJsonAsync($"/engagements/{foreignEngagement}/listeners",
            new ListenerEndpoints.CreateListenerRequest(
                Name: "foreign-front",
                Transport: "http",
                BindAddress: $"127.0.0.1:{TestSupport.GetFreeTcpPort()}",
                PublicEndpoint: "203.0.113.11:8080"));
        var foreignListener = await foreign.Content.ReadFromJsonAsync<ListenerEndpoints.ListenerResponse>();
        var wrongEngagement = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Unit: BuildUnitIds.Rust, Class: "Implant", TargetOs: "linux", TargetArch: "amd64",
                Endpoint: null, UriPath: "/beacon", SleepSeconds: 30, JitterSeconds: 10,
                KillDate: null, ListenerId: foreignListener!.Id));
        Assert.Equal(HttpStatusCode.BadRequest, wrongEngagement.StatusCode);

        // The operator front is not implant ingress either: naming it is
        // refused with the same plain answer.
        var registry = env.Host.Services.GetRequiredService<IListenerRegistry>();
        var front = Assert.Single(await registry.ListAsync(), l => l.EngagementId is null);
        var frontNamed = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Unit: BuildUnitIds.Rust, Class: "Implant", TargetOs: "linux", TargetArch: "amd64",
                Endpoint: null, UriPath: "/beacon", SleepSeconds: 30, JitterSeconds: 10,
                KillDate: null, ListenerId: front.Id.ToString()));
        Assert.Equal(HttpStatusCode.BadRequest, frontNamed.StatusCode);

        // And a request naming both a listener and an endpoint is refused
        // rather than silently preferring one.
        var both = await env.Http.PostAsJsonAsync($"/engagements/{engagementId}/payloads",
            new PayloadEndpoints.BuildPayloadRequest(
                Unit: BuildUnitIds.Rust, Class: "Implant", TargetOs: "linux", TargetArch: "amd64",
                Endpoint: "http://typed.example.test", UriPath: "/beacon", SleepSeconds: 30,
                JitterSeconds: 10, KillDate: null, ListenerId: listener.Id));
        Assert.Equal(HttpStatusCode.BadRequest, both.StatusCode);
    }

    // Splits a delimited envelope body (a varint length ahead of each
    // marshaled rod.v1 Frame) back into its frames -- enough of the wire
    // grammar to read a contact response's handshake status.
    private static List<Rod.V1.Frame> ParseFrames(byte[] body)
    {
        var frames = new List<Rod.V1.Frame>();
        var position = 0;
        while (position < body.Length)
        {
            uint length = 0;
            var shift = 0;
            while (true)
            {
                var b = body[position++];
                length |= (uint)(b & 0x7f) << shift;
                if ((b & 0x80) == 0)
                    break;
                shift += 7;
            }
            frames.Add(Rod.V1.Frame.Parser.ParseFrom(body, position, (int)length));
            position += (int)length;
        }
        return frames;
    }

    private static async Task<string> MintTokenAsync(HttpClient client, string engagementId)
    {
        var response = await client.PostAsync($"/engagements/{engagementId}/deploy-tokens", null);
        response.EnsureSuccessStatusCode();
        var minted = await response.Content.ReadFromJsonAsync<EngagementEndpoints.DeployTokenResponse>();
        return minted!.Secret;
    }

    // The port must stop accepting once the listener is gone; Kestrel allows
    // seconds to drain in-flight requests first, so poll rather than assert.
    private static async Task WaitForRefusedAsync(int port)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(15);
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                using var probe = new TcpClient();
                await probe.ConnectAsync(IPAddress.Loopback, port, CancellationToken.None);
            }
            catch (SocketException)
            {
                return; // refused: the socket is unbound.
            }
            await Task.Delay(250);
        }

        throw new Xunit.Sdk.XunitException($"Port {port} still accepts connections after the listener was deleted.");
    }

    /// <summary>
    /// A real Kestrel teamserver with one startup HTTP listener carrying the
    /// operator API, plus the authenticated operator session on it. The
    /// engagement's listeners bind their own sockets beside it.
    /// </summary>
    private sealed class TestEnv : IAsyncDisposable
    {
        public IHost Host { get; private set; } = null!;
        public HttpClient Http { get; private set; } = null!;

        public static async Task<TestEnv> StartAsync(ListenerConfig httpListener)
        {
            var env = new TestEnv();
            // Bound exactly as passed: tests allocate their free ports up
            // front (and some cases deliberately reuse one).
            var config = AuthenticatedHost.BuildConfig();
            env.Host = TransportHost.CreateHostBuilder(
                    configureServices: services => AuthenticatedHost.ComposeServices(services, config),
                    mapEndpoints: endpoints => AuthenticatedHost.ComposeEndpoints(endpoints),
                    configuration: config)
                .ConfigureWebHost(webBuilder => webBuilder.UseRodListeners(new[] { httpListener }))
                .Build();
            await env.Host.StartAsync();

            var handler = new SocketsHttpHandler();
            env.Http = new HttpClient(new CookieHandler(handler))
            {
                BaseAddress = new Uri($"http://{httpListener.BindAddress}"),
            };
            return env;
        }

        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            if (Host is not null)
            {
                await Host.StopAsync();
                Host.Dispose();
            }
        }
    }
}
