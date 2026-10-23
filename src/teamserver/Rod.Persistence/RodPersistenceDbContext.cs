using Microsoft.EntityFrameworkCore;
using Rod.Audit;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Sessions;
using Rod.Persistence.Configurations;
using Task = Rod.CoreState.Tasks.Task;

namespace Rod.Persistence;

/// <summary>
/// The durable store's EF Core <see cref="DbContext"/> for teamserver state and
/// the audit trail (ADR 0003). Every aggregate and audit/artifact entity is
/// mapped here through its <see cref="IEntityTypeConfiguration{TEntity}"/> in
/// <c>Configurations/</c>; the migrations and the Postgres-backed adapters share
/// this one context.
/// </summary>
/// <remarks>
/// The context holds no domain logic: it is the persistence detail the ports
/// hide. Concurrency lives at the adapters (deploy-token redeem, task FIFO), not
/// on the entities, so the domain model stays persistence-ignorant.
/// </remarks>
public sealed class RodPersistenceDbContext : DbContext
{
    public RodPersistenceDbContext(DbContextOptions<RodPersistenceDbContext> options)
        : base(options)
    {
    }

    public DbSet<Operator> Operators => Set<Operator>();
    internal DbSet<StoredOperatorCredential> OperatorCredentials => Set<StoredOperatorCredential>();
    internal DbSet<StoredOperatorApiToken> OperatorApiTokens => Set<StoredOperatorApiToken>();
    public DbSet<Engagement> Engagements => Set<Engagement>();
    internal DbSet<Configurations.StoredEngagementMembership> EngagementMembers => Set<Configurations.StoredEngagementMembership>();
    public DbSet<Implant> Implants => Set<Implant>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<Rod.CoreState.ShellSessions.ShellSession> ShellSessions => Set<Rod.CoreState.ShellSessions.ShellSession>();
    public DbSet<Rod.CoreState.WebShells.WebShellProfile> WebShellProfiles => Set<Rod.CoreState.WebShells.WebShellProfile>();
    public DbSet<Rod.CoreState.Launchers.Launcher> Launchers => Set<Rod.CoreState.Launchers.Launcher>();
    public DbSet<Task> Tasks => Set<Task>();
    internal DbSet<StoredImplantTaskNonce> ImplantTaskNonces => Set<StoredImplantTaskNonce>();
    internal DbSet<StoredDeployToken> DeployTokens => Set<StoredDeployToken>();
    internal DbSet<StoredListenerDefinition> ListenerDefinitions => Set<StoredListenerDefinition>();
    internal DbSet<Configurations.StoredAutomationRule> AutomationRules => Set<Configurations.StoredAutomationRule>();
    internal DbSet<Configurations.StoredWebhookSubscription> WebhookSubscriptions => Set<Configurations.StoredWebhookSubscription>();
    internal DbSet<Configurations.StoredTaskSnippet> TaskSnippets => Set<Configurations.StoredTaskSnippet>();
    internal DbSet<Configurations.StoredComment> Comments => Set<Configurations.StoredComment>();
    internal DbSet<Configurations.StoredChatChannel> ChatChannels => Set<Configurations.StoredChatChannel>();
    internal DbSet<Configurations.StoredChatMessage> ChatMessages => Set<Configurations.StoredChatMessage>();
    internal DbSet<Configurations.StoredCredential> Credentials => Set<Configurations.StoredCredential>();
    internal DbSet<Configurations.StoredCampaign> Campaigns => Set<Configurations.StoredCampaign>();
    internal DbSet<Configurations.StoredCampaignRecipient> CampaignRecipients => Set<Configurations.StoredCampaignRecipient>();
    internal DbSet<Configurations.StoredReconAsset> ReconAssets => Set<Configurations.StoredReconAsset>();
    internal DbSet<Configurations.StoredRedirectorNode> RedirectorNodes => Set<Configurations.StoredRedirectorNode>();
    internal DbSet<Configurations.StoredRedirectorCredential> RedirectorCredentials => Set<Configurations.StoredRedirectorCredential>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<Artifact> Artifacts => Set<Artifact>();
    internal DbSet<StoredPayload> Payloads => Set<StoredPayload>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Apply every IEntityTypeConfiguration<> in this assembly (the
        // Configurations/ classes). This keeps OnModelCreating a single line:
        // adding an entity means adding a configuration class, nothing here.
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(RodPersistenceDbContext).Assembly);

        // All core-state enum columns store as int by convention (the audit hash
        // canonical form already uses (int)Kind), so nothing here overrides that.
    }
}
