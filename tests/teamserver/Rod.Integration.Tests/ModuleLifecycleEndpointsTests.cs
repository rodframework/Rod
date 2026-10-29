using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.Capabilities;
using Rod.Capabilities.Endpoints;
using Rod.Capabilities.Registry;
using Rod.CoreState;
using Rod.CoreState.Operators;
using Rod.Packaging;

namespace Rod.Integration.Tests;

/// <summary>
/// The /modules lifecycle endpoints over HTTP (ADR-023): the operator
/// console's day-2 workflow -- browse the registry, install from it or
/// from an upload, uninstall -- against a real host with the capabilities
/// layer composed, packages built and signed through Rod.Packaging's own
/// primitives (the same shape a publisher produces). Every install and
/// removal lands in the deployment audit bucket under the empty
/// engagement id, attributed to the acting operator; a restart replays
/// the store through the seeding hosted service; the install bounds
/// refuse over-ceiling packages with the reason named.
/// </summary>
public class ModuleLifecycleEndpointsTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rod-modules-http-" + Guid.NewGuid().ToString("N"));
    private readonly string _storeRoot;
    private readonly string _registryRoot;
    private readonly Ed25519.KeyPair _publisherKeys = Ed25519.GenerateKeyPair();

    public ModuleLifecycleEndpointsTests()
    {
        _storeRoot = Path.Combine(_root, "store");
        _registryRoot = Path.Combine(_root, "registry");
        Directory.CreateDirectory(_storeRoot);
        Directory.CreateDirectory(Path.Combine(_registryRoot, "modules"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }

    private ModulesHost Host(string? maxPackageBytes = null)
    {
        var (client, host, operatorId) = AuthenticatedHost.Create(
            extendConfig: settings =>
            {
                settings["Modules:Store"] = _storeRoot;
                settings["Modules:Registry"] = _registryRoot;
                if (maxPackageBytes is not null)
                    settings["Modules:MaxPackageBytes"] = maxPackageBytes;
            },
            configureServicesWithConfig: (services, config) => services.AddRodCapabilities(config),
            mapEndpoints: endpoints => endpoints.MapRodModuleEndpoints());
        return new ModulesHost(client, host, operatorId);
    }

    /// <summary>Authors, packs, and signs one descriptor module, drops its
    /// index entry into the local registry, and returns the package bytes
    /// plus the signing material an upload needs.</summary>
    private async Task<(string Name, string Version, byte[] Package, string PublicKey, string Signature, string Fingerprint)>
        PublishAsync(string name = "sweep", string version = "1.0.0", int payloadBytes = 32)
    {
        var source = Path.Combine(_root, "src", name + "-" + version);
        Directory.CreateDirectory(source);
        File.WriteAllText(Path.Combine(source, ManifestToml.FileName), $"""
            [module]
            name = "{name}"
            version = "{version}"
            entry = "server"
            license = "Apache-2.0"
            description = "A sweep module."

            [compatibility]
            teamserver = "1.0.0"

            [opsec]
            lands-on-disk = false

            [[verbs]]
            name = "recon.sweep"
            version = "1.0.0"
            category = "recon"
            output-kind = "text"
            """);
        // Random bytes: the ceiling has to bite on the packed size, so the
        // payload must not deflate away to nothing.
        await File.WriteAllBytesAsync(
            Path.Combine(source, "payload.bin"), System.Security.Cryptography.RandomNumberGenerator.GetBytes(payloadBytes));

        var selection = ModulePackage.SelectFiles(source, null);
        var zip = Path.Combine(_root, "dist", $"{name}-{version}.zip");
        Directory.CreateDirectory(Path.GetDirectoryName(zip)!);
        var (_, sha256) = await ModulePackage.WriteZipAsync(selection, zip);

        var (manifest, _) = ManifestToml.LoadFile(Path.Combine(source, ManifestToml.FileName));
        var canonical = CanonicalForm.Build(manifest!, CanonicalForm.DigestPayload(source));
        var signature = Convert.ToBase64String(
            Ed25519.Sign(_publisherKeys.SecretKey, Encoding.UTF8.GetBytes(canonical)));
        var publicKey = Convert.ToBase64String(_publisherKeys.PublicKey);
        var fingerprint = Ed25519.Fingerprint(_publisherKeys.PublicKey);

        var entryPath = Path.Combine(_registryRoot, "modules", name + ".json");
        var entry = new RegistryEntry(
            name, "server", "A sweep module.", "Apache-2.0", null,
            new RegistryEntry.OpsecInfo(false, null), [], []);
        entry = entry with
        {
            Versions =
            [
                new RegistryVersion(
                    version, DateTimeOffset.UtcNow.ToString("O"), zip, sha256, signature, publicKey, fingerprint,
                    new RegistryVersion.CompatibilityInfo("1.0.0", [])),
            ],
        };
        await File.WriteAllTextAsync(entryPath, RegistryJson.SaveEntry(entry));
        return (name, version, await File.ReadAllBytesAsync(zip), publicKey, signature, fingerprint);
    }

    private static async Task<InstalledBody[]> ListInstalledAsync(HttpClient client)
        => await client.GetFromJsonAsync<InstalledBody[]>("/modules") ?? [];

    private static async Task<string> ProblemDetailAsync(HttpResponseMessage response)
    {
        var problem = await response.Content.ReadFromJsonAsync<ProblemBody>();
        return problem?.Detail ?? "";
    }

    private sealed record InstalledBody(string Name, string Version, string Entry, string Fingerprint, string InstalledAt);
    private sealed record ProblemBody(string Detail);

    private sealed record InstalledRecord(
        string Name, string Version, string Entry, string Path, string Url,
        string Sha256, string Signature, string PublicKey, string Fingerprint, string Installed);

    private sealed record ModulesHost(HttpClient Http, IHost Host, OperatorId Operator) : IDisposable
    {
        public void Dispose()
        {
            Http.Dispose();
            Host.Dispose();
        }
    }

    [Fact]
    public async Task ARegistryInstall_RidesTheEndpoints_AndAuditsToTheOperator()
    {
        var (name, version, _, _, _, fingerprint) = await PublishAsync();
        using var modules = Host();
        await AuthenticatedHost.LoginAsync(modules.Http);

        // The marketplace listing carries the entry.
        var browse = await modules.Http.GetFromJsonAsync<JsonElement>("/modules/registry");
        Assert.Equal(name, browse![0].GetProperty("name").GetString());

        var install = await modules.Http.PostAsJsonAsync("/modules/install", new { name });
        Assert.Equal(HttpStatusCode.OK, install.StatusCode);
        var record = await install.Content.ReadFromJsonAsync<InstalledRecord>();
        Assert.NotNull(record);
        Assert.Equal(version, record!.Version);
        Assert.Equal(fingerprint, record.Fingerprint);

        // The installed list names it, and the hot registration answers.
        var installed = await ListInstalledAsync(modules.Http);
        var held = Assert.Single(installed, i => i.Name == name);
        Assert.Equal(version, held.Version);
        var capabilities = modules.Host.Services.GetRequiredService<ICapabilityRegistry>();
        Assert.NotNull(await capabilities.FindAsync("recon.sweep"));

        // The lock records the adoption beside the tree.
        Assert.True(Directory.Exists(Path.Combine(_storeRoot, "modules", name, version)));
        var locked = ModuleLock.Load(Path.Combine(_storeRoot, ModuleLock.FileName));
        Assert.Equal(version, locked.Module(name)!.Version);
    }

    [Fact]
    public async Task AnUploadedPackage_InstallsThroughTheSameChain()
    {
        var (name, version, package, publicKey, signature, fingerprint) = await PublishAsync();
        using var modules = Host();
        await AuthenticatedHost.LoginAsync(modules.Http);

        using var form = new MultipartFormDataContent();
        var packageContent = new ByteArrayContent(package);
        packageContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/zip");
        form.Add(packageContent, "package", $"{name}-{version}.zip");
        form.Add(new StringContent(publicKey), "publicKey");
        form.Add(new StringContent(signature), "signature");

        var upload = await modules.Http.PostAsync("/modules/upload", form);
        Assert.Equal(HttpStatusCode.OK, upload.StatusCode);
        var record = await upload.Content.ReadFromJsonAsync<InstalledRecord>();
        Assert.Equal(fingerprint, record!.Fingerprint);

        var installed = await ListInstalledAsync(modules.Http);
        Assert.Contains(installed, i => i.Name == name && i.Version == version);
        Assert.True(Directory.Exists(Path.Combine(_storeRoot, "modules", name, version)));
    }

    [Fact]
    public async Task AnUninstall_RetractsTheModule_AndBothActionsChainInTheDeploymentBucket()
    {
        var (name, version, _, _, _, _) = await PublishAsync();
        using var modules = Host();
        await AuthenticatedHost.LoginAsync(modules.Http);
        Assert.Equal(HttpStatusCode.OK,
            (await modules.Http.PostAsJsonAsync("/modules/install", new { name })).StatusCode);

        var uninstall = await modules.Http.PostAsync($"/modules/{name}/uninstall", content: null);
        Assert.Equal(HttpStatusCode.NoContent, uninstall.StatusCode);

        // The tree and the lock entry are gone.
        Assert.Empty(await ListInstalledAsync(modules.Http));
        Assert.False(Directory.Exists(Path.Combine(_storeRoot, "modules", name)));

        // Both actions chained under the empty engagement id -- the
        // deployment-global bucket, the operator-account precedent -- and
        // the acting operator is the attribution on each fact. The whole
        // trail still verifies after the pair.
        var audit = modules.Host.Services.GetRequiredService<IAuditStore>();
        var trail = await audit.ListAsync(Guid.Empty);
        var installed = Assert.Single(trail, e => e.Kind == AuditEventKind.ModuleInstalled);
        var removed = Assert.Single(trail, e => e.Kind == AuditEventKind.ModuleRemoved);
        foreach (var fact in new[] { installed, removed })
        {
            Assert.Equal(Guid.Empty, fact.EngagementId);
            Assert.Equal(modules.Operator.Value, fact.OperatorId);
        }
        Assert.Equal("module.install", installed.Verb);
        Assert.Equal("module.remove", removed.Verb);
        Assert.Contains($"\"name\":\"{name}\"", installed.Payload);
        Assert.Contains($"\"version\":\"{version}\"", removed.Payload);
        Assert.Null(AuditChain.VerifyTrail(trail));
    }

    [Fact]
    public async Task ARestart_SeedsTheStoreBackIntoTheLiveRegistries()
    {
        var (name, version, _, _, _, _) = await PublishAsync();
        using (var first = Host())
        {
            await AuthenticatedHost.LoginAsync(first.Http);
            Assert.Equal(HttpStatusCode.OK,
                (await first.Http.PostAsJsonAsync("/modules/install", new { name })).StatusCode);
            var firstCapabilities = first.Host.Services.GetRequiredService<ICapabilityRegistry>();
            Assert.NotNull(await firstCapabilities.FindAsync("recon.sweep"));
        }

        // A fresh host over the same store: the seeding hosted service
        // replays the lock exactly the way a fresh install would, with no
        // call from the test -- restart and install land in one state.
        using var second = Host();
        await AuthenticatedHost.LoginAsync(second.Http);
        var installed = await ListInstalledAsync(second.Http);
        Assert.Contains(installed, i => i.Name == name && i.Version == version);
        var secondCapabilities = second.Host.Services.GetRequiredService<ICapabilityRegistry>();
        Assert.NotNull(await secondCapabilities.FindAsync("recon.sweep"));
    }

    [Fact]
    public async Task AnOverCeilingUpload_IsRefusedWith413AndTheReason()
    {
        var (_, _, package, publicKey, signature, _) = await PublishAsync(payloadBytes: 4096);
        using var modules = Host(maxPackageBytes: "1024");
        await AuthenticatedHost.LoginAsync(modules.Http);

        using var form = new MultipartFormDataContent();
        form.Add(new ByteArrayContent(package), "package", "sweep-1.0.0.zip");
        form.Add(new StringContent(publicKey), "publicKey");
        form.Add(new StringContent(signature), "signature");
        var upload = await modules.Http.PostAsync("/modules/upload", form);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, upload.StatusCode);
        Assert.Contains("Modules:MaxPackageBytes", await ProblemDetailAsync(upload));
        Assert.Empty(await ListInstalledAsync(modules.Http));
        var audit = modules.Host.Services.GetRequiredService<IAuditStore>();
        Assert.DoesNotContain(await audit.ListAsync(Guid.Empty), e => e.Kind == AuditEventKind.ModuleInstalled);
    }

    [Fact]
    public async Task AnOverCeilingRegistryPackage_IsRefusedWith413AndTheReason()
    {
        await PublishAsync(payloadBytes: 4096);
        using var modules = Host(maxPackageBytes: "1024");
        await AuthenticatedHost.LoginAsync(modules.Http);

        var install = await modules.Http.PostAsJsonAsync("/modules/install", new { name = "sweep" });

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, install.StatusCode);
        Assert.Contains("Modules:MaxPackageBytes", await ProblemDetailAsync(install));
        Assert.Empty(await ListInstalledAsync(modules.Http));
    }

    [Fact]
    public async Task AnUnknownModuleName_IsA400NamingTheRefusal()
    {
        using var modules = Host();
        await AuthenticatedHost.LoginAsync(modules.Http);

        var install = await modules.Http.PostAsJsonAsync("/modules/install", new { name = "no-such-module" });

        Assert.Equal(HttpStatusCode.BadRequest, install.StatusCode);
        Assert.Contains("carries no module named", await ProblemDetailAsync(install));
    }

    [Fact]
    public async Task TheSurface_RequiresAnAuthenticatedOperator()
    {
        using var modules = Host();

        Assert.Equal(HttpStatusCode.Unauthorized, (await modules.Http.GetAsync("/modules")).StatusCode);
    }
}
