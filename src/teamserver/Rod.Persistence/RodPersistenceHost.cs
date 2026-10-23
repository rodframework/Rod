using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Rod.Audit;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Listeners;
using Rod.CoreState.Operators;
using Rod.CoreState.Sessions;
using Rod.CoreState.ShellSessions;
using Rod.CoreState.WebShells;
using Rod.CoreState.Deployment;
using Rod.CoreState.Tasks;
using Rod.Persistence.Stores;

namespace Rod.Persistence;

/// <summary>
/// Composition-root wiring for the durable PostgreSQL store (ADR 0003).
/// When the <c>ConnectionStrings:Postgres</c> section is present, this
/// registers the EF Core <see cref="RodPersistenceDbContext"/> against the Npgsql
/// provider and <b>replaces</b> the in-memory port registrations added by
/// <c>AddRodTransport</c> with the Postgres-backed adapters, for whichever stores
/// have a durable implementation.
/// </summary>
/// <remarks>
/// The replace pattern mirrors <c>Rod.Operators</c> swapping
/// <c>NullLiveEventBus</c> for <c>InMemoryLiveEventBus</c>: the inner-layer host
/// registers a default, and an outer layer wired at the composition root replaces
/// it. Stores whose durable adapter is not yet implemented keep their in-memory
/// registration untouched, so the opt-in is incremental and a partial rollout is
/// safe. With the connection string absent, this method registers nothing and
/// every existing test stays on the in-memory path unchanged.
/// </remarks>
public static class RodPersistenceHost
{
    /// <summary>
    /// The configuration key the durable adapters are selected by. Mirrors the
    /// <c>Audit:DataDirectory</c> precedent: presence opts in, absence keeps the
    /// in-memory defaults.
    /// </summary>
    public const string ConnectionStringKey = "ConnectionStrings:Postgres";

    public static IServiceCollection AddRodPersistence(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var connectionString = configuration[ConnectionStringKey];
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            // No connection string -> the in-memory adapters registered by
            // AddRodTransport stay in place. Nothing to do.
            return services;
        }

        // A DbContext is not safe for concurrent use, but the application
        // services that hold these ports (EngagementService, etc.) are registered
        // as singletons and the teamserver fans task/beacon work across threads.
        // Registering a factory (a singleton-safe source of short-lived contexts)
        // lets each adapter own its per-operation context without the
        // captive-dependency hazard a scoped DbContext under a singleton would
        // create. AddDbContextFactory also pools contexts by default.
        services.AddDbContextFactory<RodPersistenceDbContext>(options =>
            options.UseNpgsql(connectionString));

        // Replace the in-memory core-state ports whose durable adapters are
        // implemented. Each adapter is a singleton that resolves the factory and
        // creates a fresh context per call, matching the singleton lifetime of the
        // application services that consume the ports. All core-state and
        // audit/artifact/payload ports are Postgres-backed when this extension
        // runs: operators, operator credentials, operator API tokens,
        // engagements, memberships, implants, sessions, tasks, deploy tokens,
        // listener definitions, launchers, automation rules, webhook
        // subscriptions, task snippets, campaigns, the redirector fleet,
        // audit, artifacts, and payloads.
        services.Replace(ServiceDescriptor.Singleton<IOperatorRepository, PostgresOperatorRepository>());
        // The operator password verifier: the in-memory adapter registered by
        // AddRodTransport is replaced by its durable twin so a provisioned
        // password survives a teamserver restart. The port is hash-only and the
        // bootstrap seed / login path consume it unchanged.
        services.Replace(ServiceDescriptor.Singleton<IOperatorCredentialStore, PostgresOperatorCredentialStore>());
        // The operator API tokens: the same durable twin, so a minted token
        // survives a teamserver restart and revocation lands in the database.
        services.Replace(ServiceDescriptor.Singleton<IOperatorApiTokenStore, PostgresOperatorApiTokenStore>());
        services.Replace(ServiceDescriptor.Singleton<IEngagementRepository, PostgresEngagementRepository>());
        // Engagement memberships: the durable twin, so the access an owner
        // granted survives a restart (architecture.md Sec 3).
        services.Replace(ServiceDescriptor.Singleton<IEngagementMembershipStore, Stores.PostgresEngagementMembershipStore>());
        services.Replace(ServiceDescriptor.Singleton<IImplantRepository, PostgresImplantRepository>());
        // The Postgres session registry keeps the last-seen decorator the
        // in-memory registration wears (the durable stamp is written through
        // the Postgres implant repository resolved above).
        services.Replace(ServiceDescriptor.Singleton<ISessionRegistry>(sp => new LastSeenSessionRegistry(
            new PostgresSessionRegistry(sp.GetRequiredService<IDbContextFactory<RodPersistenceDbContext>>()),
            sp.GetRequiredService<IImplantRepository>())));
        // The caught reverse-shell registry and the web-shell profile
        // store: the durable twins, so the engagement's shell history and
        // endpoint registrations survive a restart.
        services.Replace(ServiceDescriptor.Singleton<IShellSessionRegistry, Stores.PostgresShellSessionRegistry>());
        services.Replace(ServiceDescriptor.Singleton<CoreState.WebShells.IWebShellProfileRepository, Stores.PostgresWebShellProfileRepository>());
        services.Replace(ServiceDescriptor.Singleton<ITaskRepository, PostgresTaskRepository>());
        services.Replace(ServiceDescriptor.Singleton<IDeployTokenService, PostgresDeployTokenService>());
        // Engagement-scoped listener definitions: the durable pair so a restart
        // rebinds the listeners the operator created per engagement.
        services.Replace(ServiceDescriptor.Singleton<IListenerStore, PostgresListenerStore>());
        // The rendered launcher rows: the durable twin so a credential with a
        // long window stays re-copyable and revocable across a restart.
        services.Replace(ServiceDescriptor.Singleton<CoreState.Launchers.ILauncherStore, Stores.PostgresLauncherStore>());
        // Engagement-scoped automation rules: the durable twin so a rule's
        // cadence (next-fire stamp riding the row) survives a restart --
        // the durability time triggers are designed around (Sec 10.4).
        services.Replace(ServiceDescriptor.Singleton<CoreState.Automation.IAutomationRuleStore, Stores.PostgresAutomationRuleStore>());
        // Engagement-scoped webhook subscriptions: the durable twin so a
        // registered channel survives a restart with its delivery
        // bookkeeping (Sec 4.4).
        services.Replace(ServiceDescriptor.Singleton<CoreState.Webhooks.IWebhookSubscriptionStore, Stores.PostgresWebhookSubscriptionStore>());
        // Engagement-scoped task snippets: the durable twin so a saved
        // command sequence survives a restart for every operator on the
        // engagement.
        services.Replace(ServiceDescriptor.Singleton<CoreState.Snippets.ITaskSnippetStore, Stores.PostgresTaskSnippetStore>());
        // Engagement-scoped collaboration surfaces (architecture.md
        // Sec 15.3, ADR-005): the durable twins so comments, chat, and
        // harvested-credential rows survive a restart -- mutable process
        // knowledge with its own tables, never audit-chain content. The
        // search swap moves the query from the in-memory sweep to the
        // tsvector + GIN indexes the collaboration migration builds.
        services.Replace(ServiceDescriptor.Singleton<CoreState.Collaboration.ICommentStore, Stores.PostgresCommentStore>());
        services.Replace(ServiceDescriptor.Singleton<CoreState.Collaboration.IChatStore, Stores.PostgresChatStore>());
        services.Replace(ServiceDescriptor.Singleton<CoreState.Collaboration.ICredentialStore, Stores.PostgresCredentialStore>());
        services.Replace(ServiceDescriptor.Singleton<CoreState.Collaboration.IEngagementSearch, Stores.PostgresEngagementSearch>());
        // Engagement-scoped delivery campaigns (architecture.md Sec 11.5):
        // the durable twin so a launched campaign's recipient arcs and
        // evidence stamps survive a restart -- the attribution binding on
        // the recipient rows included, which is what re-attributes an
        // enrollment that lands after the restart.
        services.Replace(ServiceDescriptor.Singleton<CoreState.Campaigns.ICampaignStore, Stores.PostgresCampaignStore>());
        // Engagement-scoped recon assets (architecture.md Sec 15.4): the
        // durable twin so the engagement's target list survives a restart
        // with the (engagement, kind, value) identity and the composite
        // foreign keys the campaign-target link anchors on.
        services.Replace(ServiceDescriptor.Singleton<CoreState.Recon.IReconAssetStore, Stores.PostgresReconAssetStore>());
        services.Replace(ServiceDescriptor.Singleton<CoreState.Redirectors.IRedirectorFleet, Stores.PostgresRedirectorFleet>());
        // The audit chain key (Audit:ChainKey, base64) rides the Postgres
        // audit store the same way it rides the in-memory and file ones:
        // keyed links when held, bare SHA when not.
        var chainKey = Rod.Audit.AuditPersistenceOptions.ParseChainKey(configuration["Audit:ChainKey"]);
        services.Replace(ServiceDescriptor.Singleton<IAuditStore>(sp => new PostgresAuditStore(
            sp.GetRequiredService<IDbContextFactory<RodPersistenceDbContext>>(), chainKey)));
        services.Replace(ServiceDescriptor.Singleton<IArtifactStore, PostgresArtifactStore>());
        // The built-payload library: the durable twin so a stored artifact,
        // its loader delivery route, and its sealed-contact key binding
        // survive a restart -- without it a Postgres deployment kept every
        // other engagement state but lost the payloads on reboot.
        services.Replace(ServiceDescriptor.Singleton<IPayloadStore, Stores.PostgresPayloadStore>());

        return services;
    }
}
