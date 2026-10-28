using Microsoft.EntityFrameworkCore;
using Rod.Audit;
using Rod.Operators;
using Rod.Operators.Auth;
using Rod.Operators.Mcp;
using Rod.Persistence;
using Rod.TeamServer;
using Rod.Capabilities;
using Rod.Transport;
using Rod.Transport.Listeners;

// The offline evidence verifier (architecture.md Sec 11): `--verify-evidence
// <package.zip>` checks a closed engagement's exported package on a host with
// no Rod infrastructure running. Handled before the host is built -- the
// verifier needs no listeners, no stores, and no configuration.
if (args is ["--verify-evidence", var packagePath, "--chain-key", var chainKey])
{
    return await EvidenceVerifier.RunAsync(packagePath, chainKey);
}
if (args is ["--verify-evidence", { } barePath])
{
    return await EvidenceVerifier.RunAsync(barePath);
}

// The teamserver composition root (architecture.md Sec 4). This is
// the single runnable .NET process: it wires the transport layer's services and
// operator/implant endpoints, binds the configured listeners, serves
// the built operator UI (Vite output under wwwroot), and falls any non-file,
// non-API request back to index.html so the client-side router owns deep links. UI
// <-> data goes over the HTTP API; the host itself adds no domain logic.

var builder = WebApplication.CreateBuilder(args);
// Pass configuration through so the composition root can select the durable
// audit/artifact stores when the Audit:DataDirectory section is present
//  -- the engagement trail outlives a restart and infrastructure teardown.
// Absent, the in-memory adapters stay in place.
builder.Services.AddRodTransport(builder.Configuration);
// Layer in the operator layer: the live-event bus that fans task
// and presence events out to connected operator sessions, the presence
// roster, the MCP server over the operator surface, and the opt-in LLM
// triage client (bound from the Llm configuration section). Transport
// cannot reference Rod.Operators (architecture test
// LayerDependencyTests), so the composition root assembles it here.
builder.Services.AddRodOperators(builder.Configuration);
// Wire the capabilities layer onto the live task path (architecture.md Sec 10.3):
// the capability registry and the registry-backed task resolver that replaces
// core state's strict class-table default, plus the capability modules the
// configuration lists -- the in-tree reference set under
// Capabilities:DescriptorModules (pure manifests, ADR-018) and an operator's
// external assemblies under Capabilities:Modules alike (Sec 10.2, Sec 15.1)
// -- each replaces the placeholder for its verb, so adding one never edits
// this composition root.
// Transport cannot reference Rod.Capabilities (architecture test
// LayerDependencyTests), so the composition root assembles it here -- the same
// reason as AddRodOperators.
builder.Services.AddRodCapabilities(builder.Configuration);
// The module lifecycle's build-side hooks (ADR-023): the capabilities layer
// cannot reference the build pipeline, so the hook that registers an
// installed external unit (into the build units) or extension package (into
// the catalog) is wired here -- the one composition point where both layers
// are visible. Registered as a post-configuration so it replaces the
// hook-less default AddRodCapabilities installed when a store is
// configured.
if (!string.IsNullOrWhiteSpace(builder.Configuration[Rod.Capabilities.Lifecycle.ModuleStore.StoreSectionKey]))
{
    builder.Services.AddSingleton<Rod.Capabilities.Lifecycle.ModuleLifecycleService>(sp =>
    {
        return new Rod.Capabilities.Lifecycle.ModuleLifecycleService(
            sp.GetRequiredService<Rod.Capabilities.Lifecycle.ModuleStore>(),
            sp.GetRequiredService<Rod.Capabilities.Registry.ICapabilityRegistry>(),
            sp.GetRequiredService<Rod.Audit.IAuditStore>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetService<Rod.Capabilities.Registry.ModuleAssetStore>(),
            registerBuildSide: (name, directory) =>
            {
                var (manifest, errors) = Rod.Packaging.ManifestToml.LoadFile(
                    System.IO.Path.Combine(directory, Rod.Packaging.ManifestToml.FileName));
                if (manifest is null)
                    throw new InvalidOperationException(
                        $"The installed package for '{name}' lost its manifest: {string.Join(" ", errors)}");
                if (manifest.Entry == Rod.Packaging.ModuleEntryKind.BuildUnit)
                    sp.GetRequiredService<Rod.BuildPipeline.PayloadBuild.IBuildUnitRegistry>()
                        .Register(Rod.BuildPipeline.PayloadBuild.ExternalBuildUnit.Load(directory));
                if (manifest.Entry == Rod.Packaging.ModuleEntryKind.Extension)
                    sp.GetRequiredService<Rod.BuildPipeline.PayloadBuild.ExtensionCatalog>()
                        .Add(directory);
                return Task.CompletedTask;
            },
            unregisterBuildSide: name =>
            {
                sp.GetRequiredService<Rod.BuildPipeline.PayloadBuild.ExtensionCatalog>().Remove(name);
                return Task.CompletedTask;
            });
    });
}
// Wire the durable PostgreSQL store (architecture.md Sec 12, ADR 0003):
// when ConnectionStrings:Postgres is set, this registers the EF Core
// DbContext and replaces the in-memory core-state ports whose durable adapters
// are implemented with the Postgres-backed pair, so state survives a restart.
// Rod.Persistence cannot be referenced by Rod.Transport (architecture test
// LayerDependencyTests), so the composition root assembles it here -- the same
// reason as AddRodOperators/AddRodCapabilities above. Absent the connection
// string, it registers nothing and the in-memory adapters stay in place.
builder.Services.AddRodPersistence(builder.Configuration);
// Layer in operator authentication (architecture.md Sec 4): the cookie
// session scheme, the password hasher, the login service, and the bootstrap
// account seed that provisions the first operator.
// Transport cannot reference Rod.Operators (architecture test
// LayerDependencyTests), so the composition root assembles it here -- the same
// reason as AddRodOperators above.
builder.Services.AddRodOperatorAuth(builder.Configuration);

// Bind the operator front (architecture.md Sec 8). Configuration names the
// shared tier only -- the loopback socket the operator UI and API ride (and
// any deliberately shared ingress a deployment fronts); the implant-facing
// listeners are engagement-scoped, created through the operator API, and
// persisted so a restart rebinds them. When the section is absent the host
// falls back to a single loopback listener so `dotnet run` still works out of
// the box.
var listenerConfigs = builder.Configuration.GetSection("Listeners").Get<List<ListenerConfig>>();
if (listenerConfigs is null || listenerConfigs.Count == 0)
{
    listenerConfigs = new List<ListenerConfig>
    {
        new("operator-http", "http", "127.0.0.1:59443", "http://localhost:59443"),
    };
}
builder.WebHost.UseRodListeners(listenerConfigs);

var app = builder.Build();

// Self-report provenance: the startup line names the exact source tree this
// binary was built from, so an installed teamserver introduces itself by commit
// instead of a hand-declared source path in configuration. GET /build reports
// the same pair on request (BuildStampEndpoints).
app.Logger.LogInformation(
    "Rod teamserver {Version} (commit {Commit})", BuildStamp.Version, BuildStamp.SourceCommit);

// The durable store's schema must match the model before any traffic is
// served: a database restored without its constraints boots apparently healthy
// and fails at the first task dispatch instead. The same fail-loudly posture
// as the CA and listener validation, run once per boot (Rod.Persistence owns
// the Postgres knowledge; the composition root just pulls the trigger).
if (app.Services.GetService<IDbContextFactory<RodPersistenceDbContext>>() is { } persistenceFactory)
{
    await PostgresSchemaGuard.VerifyAsync(persistenceFactory);
}

// Defense-in-depth response headers (architecture.md Sec 9). The operator UI
// renders implant-controlled strings (task output, audit payloads), so a strict
// CSP backs React's escaping: no inline scripts exist in the bundle, which
// keeps the script policy tight. Styles carry 'unsafe-inline' for a concrete
// need: the terminal emulator (xterm) positions its cursor, selection, and
// scroll surfaces by writing style attributes on DOM elements, and a
// style-src without it silently strips them -- a console whose caret and
// selection render nowhere. Style injection is a far weaker primitive than
// script injection, and scripts stay locked down. img-src admits blob: for
// the loot view's screenshot previews -- object URLs the page builds from
// bytes it fetched same-origin, so the allowance adds no remote source.
// Embedding and MIME-sniffing controls round it out. Applied to every
// response, including the API, so a stray HTML-shaped API response is still
// covered.
app.Use(async (context, next) =>
{
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next(context);
});

// The versioned operator-API alias (architecture.md Sec 15.3, ADR-006):
// /api/v1/<path> addresses the same operator endpoints the console reaches
// unversioned. The rewrite must precede route resolution, so routing is pinned
// here explicitly instead of left to WebApplication's leading implicit
// insertion (which would resolve the route before the alias could version it).
app.UseOperatorApiVersionAlias();
app.UseRouting();

// Serve the built operator UI (Vite output under wwwroot). index.html is
// no-cache because it references hashed asset names and must be fresh after a
// rebuild; the hashed /assets/* files are immutable and cache for a year.
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = staticContext =>
    {
        var headers = staticContext.Context.Response.Headers;
        if (string.Equals(staticContext.File.Name, "index.html", StringComparison.OrdinalIgnoreCase))
        {
            headers.CacheControl = "no-cache";
        }
        else if (staticContext.File.PhysicalPath is { } path &&
                 path.Contains($"{Path.DirectorySeparatorChar}assets{Path.DirectorySeparatorChar}"))
        {
            headers.CacheControl = "public,max-age=31536000,immutable";
        }
    },
});
// The transport-critical middleware core (WebSocket upgrade support plus
// the operator session pair), shared with the test hosts through
// TransportHost so this pipeline cannot drift from the one the suites
// exercise. After routing (implicit in WebApplication), before the mapped
// endpoints below.
app.UseRodTransportCore();
app.MapRodEndpoints();
// The operator layer's SSE event stream: mapped alongside the
// transport endpoints from the composition root for the same layer-separation
// reason as AddRodOperators above.
app.MapOperatorEndpoints();
// The operator layer's MCP server: mapped here, deliberately, because the
// SDK's endpoint mapping pins the host's configuration root -- harmless for
// this one long-lived host, hostile to a test process that churns hosts. See
// RodMcpHost's doc for the posture.
app.MapRodMcp();
// The operator session endpoints (login/logout/me): mapped alongside the other
// operator-layer endpoints from the composition root for the same layer-
// separation reason as AddRodOperators above.
app.MapOperatorAuthEndpoints();
// The build-report endpoint (GET /build): the binary's own provenance, mapped
// from the composition root because the stamp is a property of this executable,
// not of any layer.
app.MapBuildStampEndpoints();
// The capabilities layer's capability catalog: mapped from the
// composition root for the same layer-separation reason as AddRodCapabilities --
// transport cannot reference Rod.Capabilities, so the catalog endpoint is exposed
// from the layer that owns the registry. Lets the operator UI surface every
// capability category as tasking from the registry rather than a hardcoded verb
// table.
app.MapCapabilityEndpoints();
// The module lifecycle endpoints (ADR-023): browse, install, uninstall --
// the operator console's day-2 module workflow. Mapped from the
// capabilities layer for the same layer-separation reason as the catalog.
Rod.Capabilities.Endpoints.ModuleEndpoints.MapRodModuleEndpoints(app);
// The built-in diagnostics endpoint (architecture.md Sec 15.3, ADR-008):
// mapped from the composition root for the same layer-separation reason as
// the catalog above -- its five dimensions live across transport, core
// state, the operator layer, the build pipeline, and the capabilities
// layer, and only the composition root sees them all. The deployment
// admin's read; outside the versioned OpenAPI contract like the catalog.
app.MapDiagnosticsEndpoints();

// The operator UI shell. The SPA is hash-routed, so the browser only ever
// requests the root from the server -- there is no catch-all fallback that
// would turn unknown API paths into a 200 HTML response. When the bundle is
// missing (a backend-only checkout without Node), say so plainly instead of
// failing at request time with a file error.
app.MapGet("/", async context =>
{
    var index = app.Environment.WebRootFileProvider.GetFileInfo("index.html");
    if (!index.Exists)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        await context.Response.WriteAsync(
            "Operator UI bundle not found. Build it once with " +
            "`npm ci && npm run build` " +
            "in src/teamserver/Rod.TeamServer/Client (Node.js required), then restart the teamserver.");
        return;
    }
    context.Response.ContentType = "text/html";
    context.Response.Headers.CacheControl = "no-cache";
    await using var stream = index.CreateReadStream();
    await stream.CopyToAsync(context.Response.Body, context.RequestAborted);
});

// Seed the module registries from the installed store (ADR-023): every
// package the lock carries registers the same way a fresh install would,
// so a restart and an install land in one state. Best-effort ordering
// against the hosted services is fine -- installs re-register idempotently.
if (app.Services.GetService<Rod.Capabilities.Lifecycle.ModuleLifecycleService>() is { } moduleLifecycle)
{
    await moduleLifecycle.SeedFromStoreAsync();
}

app.Run();
return 0;
