using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Rod.Capabilities.Lifecycle;

/// <summary>
/// Seeds the live registries from the module store as the host starts
/// (ADR-023): every lock entry whose package still exists registers exactly
/// the way a fresh install would, so a restart and an install land in one
/// state. A hosted service rather than a composition-root call so every
/// host composition -- the teamserver, a test host, any assembly that opts
/// into <c>AddRodCapabilities</c> with a <c>Modules:Store</c> -- starts in
/// the same state; the service resolves the container's final
/// <see cref="ModuleLifecycleService"/> registration, build-side hooks
/// included.
/// </summary>
internal sealed class ModuleLifecycleSeedingService(
    IServiceProvider services) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Present only when Modules:Store is configured; the registration
        // below never resolves otherwise.
        var lifecycle = services.GetRequiredService<ModuleLifecycleService>();
        await lifecycle.SeedFromStoreAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
