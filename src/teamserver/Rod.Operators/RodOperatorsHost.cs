using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Rod.CoreState.Live;
using Rod.Operators.Automation;
using Rod.Operators.Collaboration;
using Rod.Operators.Endpoints;
using Rod.Operators.Live;
using Rod.Operators.Llm;
using Rod.Operators.Mcp;
using Rod.Operators.Presence;
using Rod.Operators.Snippets;
using Rod.Operators.Webhooks;
using Rod.Operators.Workbench;
using System.Net.Http;

namespace Rod.Operators;

/// <summary>
/// Composition-root hooks for the operator layer. The transport
/// layer terminates the operator API but is constrained by the architecture
/// tests to core state / protocol / audit only -- it cannot reference
/// <c>Rod.Operators</c>. So the operator layer exposes its own service and
/// endpoint registration here, and the composition root
/// (<c>Rod.TeamServer.Program</c> and the transport test host) calls these
/// alongside <c>AddRodTransport</c> / <c>MapRodEndpoints</c>. The layer rule
/// stays inward-only: dependency direction is operators -> core state / audit,
/// never the reverse.
/// </summary>
public static class RodOperatorsHost
{
    /// <summary>
    /// Registers the operator layer's services: the live-event bus (an
    /// in-memory, channel-backed fan-out, one stream per engagement), the
    /// operator presence roster, and the automation engine beside them
    /// (architecture.md Sec 10.4) with its rule-management use cases. Call
    /// after <c>AddRodTransport</c>. The bus registration replaces the no-op
    /// default <see cref="AddRodTransport"/> installed; presence and
    /// automation are operator-layer-only.
    /// </summary>
    public static IServiceCollection AddRodOperators(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        // Replace the no-op bus the transport host registered by default with the
        // real, channel-backed fan-out. Replace (not Add) so there is exactly one
        // ILiveEventBus and every consumer (TaskService, BeaconEndpoint, the SSE
        // endpoint) shares it.
        services.Replace(ServiceDescriptor.Singleton<ILiveEventBus, InMemoryLiveEventBus>());
        services.TryAddSingleton<OperatorPresenceService>();

        // The automation engine and its surface: the rule CRUD use cases the
        // endpoints call, and the hosted engine itself (a fixed-delay tick plus
        // per-engagement bus subscriptions) that turns rules into tasking.
        // Options bind when configuration is supplied; the defaults stand alone.
        if (configuration is not null)
        {
            services.AddOptions<AutomationOptions>().Bind(configuration.GetSection(AutomationOptions.SectionName));
        }
        else
        {
            services.AddOptions<AutomationOptions>();
        }
        services.TryAddSingleton<AutomationService>();
        services.TryAddSingleton<AutomationEngine>();
        services.AddHostedService(sp => sp.GetRequiredService<AutomationEngine>());

        // The notification forwarder and its surface (architecture.md
        // Sec 4.4): the subscription CRUD use cases the endpoints call, the
        // pusher that owns the outbound client (its own named client so the
        // budget and redirects stay push-shaped, the webshells pattern), and
        // the hosted forwarder (a fixed-delay tick plus per-engagement bus
        // subscriptions) that turns events into pushes. Options bind when
        // configuration is supplied; the defaults stand alone.
        if (configuration is not null)
        {
            services.AddOptions<WebhookOptions>().Bind(configuration.GetSection(WebhookOptions.SectionName));
        }
        else
        {
            services.AddOptions<WebhookOptions>();
        }
        services.AddHttpClient("webhooks", (sp, client) =>
        {
            var delivery = sp.GetRequiredService<IOptions<WebhookOptions>>().Value;
            client.Timeout = TimeSpan.FromSeconds(Math.Max(1, delivery.DeliveryTimeoutSeconds));
        });
        // The pusher takes its client lazily from the factory (see its doc):
        // registering the forwarder must not activate the handler cache in
        // hosts that never push.
        services.TryAddSingleton<WebhookPusher>();
        services.TryAddSingleton<WebhookService>();
        services.TryAddSingleton<WebhookDeliveryEngine>();
        services.AddHostedService(sp => sp.GetRequiredService<WebhookDeliveryEngine>());

        // The task-snippet use cases (the console's saved command
        // sequences): plain CRUD -- replay happens in the console, which
        // issues each step through the ordinary tasking path, so there is
        // no engine and no run endpoint here.
        services.TryAddSingleton<TaskSnippetService>();

        // The collaboration surfaces (architecture.md Sec 15.3, ADR-005):
        // the comment and chat use cases over the core-state stores, and
        // the engagement search -- in-memory sweep by default, Postgres
        // tsvector when the connection string is set (the persistence
        // layer swaps the adapter). Options bind when configuration is
        // supplied; the edit window's default stands alone.
        if (configuration is not null)
        {
            services.AddOptions<CollaborationOptions>().Bind(configuration.GetSection(CollaborationOptions.SectionName));
        }
        else
        {
            services.AddOptions<CollaborationOptions>();
        }
        services.TryAddSingleton<CommentService>();
        services.TryAddSingleton<ChatService>();
        services.TryAddSingleton<Rod.CoreState.Collaboration.IEngagementSearch, InMemoryEngagementSearch>();

        // The LLM triage client (architecture.md Sec 11): opt-in and
        // OpenAI-compatible, its client built lazily on first call with the
        // request budget on the client pipeline. Options bind when
        // configuration is supplied; the defaults stand alone (and disabled).
        if (configuration is not null)
        {
            services.AddOptions<LlmOptions>().Bind(configuration.GetSection(LlmOptions.SectionName));
        }
        else
        {
            services.AddOptions<LlmOptions>();
        }
        services.TryAddSingleton<LlmSummarizer>();

        // The external recon workbench (architecture.md Sec 11.4): the
        // pre-foothold lookups and the scan, opt-in per half like the LLM
        // client -- an unset service base or scan origin leaves its route
        // answering 503, never a silent default. The lookups ride their own
        // named client (the webhook-pusher pattern); the service takes it
        // lazily so registering the workbench activates nothing in hosts
        // that never run one.
        if (configuration is not null)
        {
            services.AddOptions<ReconWorkbenchOptions>().Bind(configuration.GetSection(ReconWorkbenchOptions.SectionName));
        }
        else
        {
            services.AddOptions<ReconWorkbenchOptions>();
        }
        services.AddHttpClient("recon", (sp, client) =>
        {
            var recon = sp.GetRequiredService<IOptions<ReconWorkbenchOptions>>().Value;
            client.Timeout = TimeSpan.FromSeconds(Math.Max(1, recon.RequestTimeoutSeconds));
        });
        services.TryAddSingleton<ReconWorkbenchService>();

        // The MCP server over the operator surface (architecture.md Sec 4,
        // the agent tooling seam): read-only tools, Streamable HTTP, mapped
        // at /mcp behind the operator token auth. Registered here so every
        // host that composes the operator layer carries it; unmapped, the
        // registration is inert. The write gate (Mcp:AllowWriteTools) rides
        // the same configuration the rest of the layer binds.
        services.AddRodMcp(configuration);

        return services;
    }

    /// <summary>
    /// Maps the operator layer's endpoints: the SSE event stream that keeps an
    /// operator session live per engagement and pushes every engagement event,
    /// the automation-rule surface, the webhook-subscription surface, the
    /// task-snippet surface, the collaboration surfaces (comments, chat,
    /// search), the LLM summarize route, and the recon workbench. Call
    /// alongside <c>MapRodEndpoints</c>. The MCP endpoint is deliberately not
    /// folded in here -- <c>MapRodMcp</c> is a composition-root act (see its
    /// doc).
    /// </summary>
    public static IEndpointRouteBuilder MapOperatorEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapOperatorEventEndpoints();
        endpoints.MapAutomationRuleEndpoints();
        endpoints.MapWebhookSubscriptionEndpoints();
        endpoints.MapTaskSnippetEndpoints();
        endpoints.MapCommentEndpoints();
        endpoints.MapChatEndpoints();
        endpoints.MapSearchEndpoints();
        endpoints.MapLlmEndpoints();
        endpoints.MapReconWorkbenchEndpoints();
        endpoints.MapReconAssetEndpoints();
        return endpoints;
    }
}
