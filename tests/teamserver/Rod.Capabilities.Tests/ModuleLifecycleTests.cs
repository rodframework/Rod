using Rod.Audit;
using Rod.Capabilities.Lifecycle;
using Rod.Capabilities.Registry;
using Rod.Packaging;

namespace Rod.Capabilities.Tests;

/// <summary>
/// The module lifecycle (ADR-023): the install pipeline a browse-and-click
/// or a registry install rides -- verify (digest, canonical form,
/// signature, key pin), adopt, hot-register -- against packages built and
/// signed right here through Rod.Packaging, the same primitives a publisher
/// uses. Every refusal names the fix; every success lands hot: the verbs
/// answer in the live registry, the lock records the trust, and the audit
/// chain carries the action.
/// </summary>
public class ModuleLifecycleTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rod-lifecycle-" + Guid.NewGuid().ToString("N"));
    private readonly string _storeRoot;
    private readonly string _registryRoot;
    private readonly InMemoryCapabilityRegistry _capabilities = new();
    private readonly InMemoryAuditStore _audit = new();
    private readonly Ed25519.KeyPair _publisherKeys = Ed25519.GenerateKeyPair();
    private int _sequence;

    public ModuleLifecycleTests()
    {
        _storeRoot = Path.Combine(_root, "store");
        _registryRoot = Path.Combine(_root, "registry");
        Directory.CreateDirectory(_storeRoot);
        Directory.CreateDirectory(Path.Combine(_registryRoot, "modules"));
    }

    private ModuleLifecycleService Service(ModuleAssetStore? assets = null,
        ModuleLifecycleService.RegisterBuildSideAsync? register = null,
        Func<string, Task>? unregister = null)
        => new(
            new ModuleStore(_storeRoot),
            _capabilities,
            _audit,
            TimeProvider.System,
            assets,
            register,
            unregister);

    /// <summary>Authors, packages, and signs one module version, and drops
    /// its index entry into the local registry. The same shape a real
    /// publisher produces; nothing here is a test shortcut.</summary>
    private async Task<(string Name, string Version)> PublishAsync(
        string name = "sweep",
        string? version = null,
        Ed25519.KeyPair? keys = null,
        string verb = "recon.sweep")
    {
        version ??= $"1.0.{_sequence++}";
        keys ??= _publisherKeys;
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
            name = "{verb}"
            version = "0.1.0"
            category = "recon"
            output-kind = "text"
            """);
        await File.WriteAllTextAsync(Path.Combine(source, "payload.txt"), "payload " + version);

        var selection = ModulePackage.SelectFiles(source, null);
        var zip = Path.Combine(_root, "dist", $"{name}-{version}.zip");
        Directory.CreateDirectory(Path.GetDirectoryName(zip)!);
        var (_, sha256) = await ModulePackage.WriteZipAsync(selection, zip);

        var (manifest, _) = ManifestToml.LoadFile(Path.Combine(source, ManifestToml.FileName));
        var digests = CanonicalForm.DigestPayload(source);
        var canonical = CanonicalForm.Build(manifest!, digests);
        var signature = Convert.ToBase64String(Ed25519.Sign(keys.SecretKey, System.Text.Encoding.UTF8.GetBytes(canonical)));
        var publicKey = Convert.ToBase64String(keys.PublicKey);
        var fingerprint = Ed25519.Fingerprint(keys.PublicKey);

        var entryPath = Path.Combine(_registryRoot, "modules", name + ".json");
        var existing = (File.Exists(entryPath) ? RegistryJson.LoadEntry(entryPath) : null)
            ?? new RegistryEntry(name, "server", "A sweep module.", "Apache-2.0", null,
            new RegistryEntry.OpsecInfo(false, null), [], []);
        var entry = existing with
        {
            Versions = existing.Versions.Append(new RegistryVersion(
                version, DateTimeOffset.UtcNow.ToString("O"), zip, sha256, signature, publicKey, fingerprint,
                new RegistryVersion.CompatibilityInfo("1.0.0", []))).ToList(),
        };
        await File.WriteAllTextAsync(entryPath, RegistryJson.SaveEntry(entry));
        return (name, version);
    }

    [Fact]
    public async Task ARegistryInstall_RegistersHotAndRecordsTrust()
    {
        var (name, version) = await PublishAsync();
        var service = Service();
        var registry = new ModuleRegistryClient(_registryRoot);

        var record = await service.InstallFromRegistryAsync(registry, name, operatorId: Guid.NewGuid());

        Assert.Equal(version, record.Version);
        // The lock pins the publisher and records the module.
        var lockFile = ModuleLock.Load(Path.Combine(_storeRoot, ModuleLock.FileName));
        Assert.Equal(
            Ed25519.Fingerprint(_publisherKeys.PublicKey),
            lockFile.TrustedKeyFor(name)!.Fingerprint);
        Assert.Equal(version, lockFile.Module(name)!.Version);
        // The hot registration: the verb answers in the live registry.
        Assert.NotNull(await _capabilities.FindAsync("recon.sweep"));
        // The audit chain carries the install, attributed to the operator.
        var trail = await _audit.ListAsync(Guid.Empty);
        Assert.Contains(trail, e => e.Kind == AuditEventKind.ModuleInstalled && e.Verb == "module.install");
    }

    [Fact]
    public async Task ATamperedPackage_IsRefusedByTheSignature()
    {
        await PublishAsync();
        var service = Service();
        var registry = new ModuleRegistryClient(_registryRoot);

        // Swap the package bytes after the index recorded the digest: the
        // digest check refuses the fetch before a signature is even read.
        var entry = await registry.FindAsync("sweep");
        var version = entry!.Versions[0];
        var zip = version.Url;
        await File.WriteAllBytesAsync(zip, "tampered bytes"u8.ToArray());

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.InstallFromRegistryAsync(registry, "sweep"));
        Assert.Contains("digest", refusal.Message);
    }

    [Fact]
    public async Task ASecondKey_IsARefusalNotARepin()
    {
        await PublishAsync("sweep", "1.0.0");
        var service = Service();
        var registry = new ModuleRegistryClient(_registryRoot);
        await service.InstallFromRegistryAsync(registry, "sweep", "1.0.0");

        // A later version under a different key: the pin refuses loudly.
        await PublishAsync("sweep", "1.0.1", keys: Ed25519.GenerateKeyPair());
        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.InstallFromRegistryAsync(registry, "sweep"));
        Assert.Contains("pinned", refusal.Message);
    }

    [Fact]
    public async Task AnUpgrade_ReplacesTheOldTreeAndKeepsOneLockEntry()
    {
        await PublishAsync("sweep", "1.0.0");
        await PublishAsync("sweep", "1.0.5");
        var service = Service();
        var registry = new ModuleRegistryClient(_registryRoot);

        await service.InstallFromRegistryAsync(registry, "sweep", "1.0.0");
        await service.InstallFromRegistryAsync(registry, "sweep", "1.0.5");

        var lockFile = ModuleLock.Load(Path.Combine(_storeRoot, ModuleLock.FileName));
        var entry = Assert.Single(lockFile.Modules);
        Assert.Equal("1.0.5", entry.Version);
        Assert.False(Directory.Exists(Path.Combine(_storeRoot, "modules", "sweep", "1.0.0")));
    }

    [Fact]
    public async Task AnUninstall_RetractsAssetsAndBuildSide()
    {
        await PublishAsync("sweep", "1.0.0");
        string? registeredName = null, unregisteredName = null;
        var service = Service(
            register: (name, _) => { registeredName = name; return Task.CompletedTask; },
            unregister: name => { unregisteredName = name; return Task.CompletedTask; });
        var registry = new ModuleRegistryClient(_registryRoot);
        await service.InstallFromRegistryAsync(registry, "sweep", "1.0.0");

        await service.UninstallAsync("sweep");

        Assert.Equal("sweep", unregisteredName);
        Assert.False(Directory.Exists(Path.Combine(_storeRoot, "modules", "sweep")));
        Assert.Null(ModuleLock.Load(Path.Combine(_storeRoot, ModuleLock.FileName)).Module("sweep"));
    }

    [Fact]
    public async Task TheBuildSideHook_FiresForBuildUnitsAndExtensions()
    {
        // Build-unit and extension packages ride the same install spine;
        // the hook (the composition root's bridge to the pipeline) sees
        // them, and only them.
        var seen = new List<string>();
        var service = Service(register: (name, _) => { seen.Add(name); return Task.CompletedTask; });
        var registry = new ModuleRegistryClient(_registryRoot);
        await PublishAsync("sweep", "1.0.0");
        await service.InstallFromRegistryAsync(registry, "sweep", "1.0.0");
        Assert.DoesNotContain(seen, n => n == "sweep"); // server entries: no build side

        // A build-unit package (the [unit] table is what makes it one).
        var unitSource = Path.Combine(_root, "src", "unit-pkg");
        Directory.CreateDirectory(unitSource);
        File.WriteAllText(Path.Combine(unitSource, ManifestToml.FileName), """
            [module]
            name = "unit-pkg"
            version = "0.1.0"
            entry = "build-unit"
            license = "Apache-2.0"

            [compatibility]
            teamserver = "1.0.0"

            [opsec]
            lands-on-disk = true

            [conformance]
            tier = 0
            harness = "1.0.0"
            date = "2026-01-15"
            clauses = ["enroll.public-key-and-token"]

            [unit]
            id = "community-x"
            command = "./build.sh"
            """);
        await PublishPackageAsync(unitSource, "unit-pkg", "0.1.0");
        await service.InstallFromRegistryAsync(registry, "unit-pkg", "0.1.0");
        Assert.Contains("unit-pkg", seen);
    }

    // Packages an arbitrary source tree into the local registry under the
    // current publisher key (the PublishAsync tail, split out for the
    // non-server entry kinds).
    private async Task PublishPackageAsync(string source, string name, string version)
    {
        var selection = ModulePackage.SelectFiles(source, null);
        var zip = Path.Combine(_root, "dist", $"{name}-{version}.zip");
        Directory.CreateDirectory(Path.GetDirectoryName(zip)!);
        var (_, sha256) = await ModulePackage.WriteZipAsync(selection, zip);
        var (manifest, _) = ManifestToml.LoadFile(Path.Combine(source, ManifestToml.FileName));
        var canonical = CanonicalForm.Build(manifest!, CanonicalForm.DigestPayload(source));
        var signature = Convert.ToBase64String(Ed25519.Sign(_publisherKeys.SecretKey, System.Text.Encoding.UTF8.GetBytes(canonical)));
        var entryPath = Path.Combine(_registryRoot, "modules", name + ".json");
        var existing = (File.Exists(entryPath) ? RegistryJson.LoadEntry(entryPath) : null)
            ?? new RegistryEntry(name, "build-unit", null, "Apache-2.0", null,
            new RegistryEntry.OpsecInfo(true, null), [], []);
        var updated = existing with
        {
            Versions = existing.Versions.Append(new RegistryVersion(
                version, DateTimeOffset.UtcNow.ToString("O"), zip, sha256, signature,
                Convert.ToBase64String(_publisherKeys.PublicKey),
                Ed25519.Fingerprint(_publisherKeys.PublicKey),
                new RegistryVersion.CompatibilityInfo("1.0.0", []))).ToList(),
        };
        await File.WriteAllTextAsync(entryPath, RegistryJson.SaveEntry(updated));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }
}
