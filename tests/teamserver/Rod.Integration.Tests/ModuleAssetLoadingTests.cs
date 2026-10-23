using Microsoft.Extensions.DependencyInjection;
using Rod.Capabilities;
using Rod.Capabilities.Registry;
using Rod.CoreState.Assets;

namespace Rod.Integration.Tests;

/// <summary>
/// The asset-module acceptance (architecture.md Sec 15.1), beside the
/// assembly-module one in <see cref="InTreeModuleLoadingTests"/>: a content
/// module reaches the process through exactly the path an operator's module
/// takes -- a directory with a <c>rod-module.toml</c> listed under
/// <c>Capabilities:AssetModules</c> -- and the composed host resolves its
/// assets by module and asset name. A host that does not opt in runs on the
/// empty default: every lookup fails, the open-not-on posture.
/// </summary>
public class ModuleAssetLoadingTests
{
    [Fact]
    public void AListedAssetModule_ResolvesThroughTheComposedHost()
    {
        var root = Path.Combine(Path.GetTempPath(), "rod-asset-load-" + Guid.NewGuid().ToString("N"));
        var module = Path.Combine(root, "browserhook");
        Directory.CreateDirectory(Path.Combine(module, "assets"));
        File.WriteAllText(Path.Combine(module, "rod-module.toml"), """
            [module]
            name = "browser-hook"

            [compatibility]
            teamserver = "1.0.0"

            [[assets]]
            name = "hook"
            path = "assets/hook.js"
            """);
        File.WriteAllText(Path.Combine(module, "assets", "hook.js"), "// the hook");

        try
        {
            var (client, host, _) = AuthenticatedHost.Create(
                extendConfig: settings => settings["Capabilities:AssetModules:0"] = module,
                configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config));
            using (client)
            using (host)
            {
                var assets = host.Services.GetRequiredService<IModuleAssetStore>();

                Assert.True(assets.TryRead("browser-hook", "hook", out var hook));
                Assert.Equal("// the hook", System.Text.Encoding.UTF8.GetString(hook.Content));
                Assert.False(assets.TryRead("browser-hook", "absent", out _));
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void AHostThatDoesNotOptIn_RunsOnTheEmptyStore()
    {
        // No AddRodCapabilities, no Capabilities:AssetModules: the transport
        // default serves nothing, and the default is the named empty store
        // (not an unregistered service error) so consuming endpoints can
        // always resolve the port and answer their loud refusal.
        var (client, host, _) = AuthenticatedHost.Create();
        using (client)
        using (host)
        {
            var assets = host.Services.GetRequiredService<IModuleAssetStore>();

            Assert.IsType<NoModuleAssets>(assets);
            Assert.False(assets.TryRead("browser-hook", "hook", out _));
        }
    }
}
