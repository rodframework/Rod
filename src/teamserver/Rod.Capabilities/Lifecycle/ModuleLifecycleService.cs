using Rod.Audit;
using Rod.Capabilities.Registry;
using Rod.Packaging;

namespace Rod.Capabilities.Lifecycle;

/// <summary>
/// The module lifecycle service (ADR-023): the operator-facing half of the
/// ecosystem -- install, upgrade, uninstall, browse -- with every step
/// verified through Rod.Packaging's one implementation of the trust chain
/// (package digest, canonical form, Ed25519 signature, key pinning) and
/// every action audit-chained to the operator that took it. Installs are
/// hot: descriptor rows register into the live capability registry, asset
/// rows join the live asset store, and the build side (external units,
/// extension packages) registers through the hooks the composition root
/// injects -- a module lands without a restart, which is the whole point of
/// the operator experience.
/// </summary>
/// <remarks>
/// The policy line: this surface installs data packages only. The
/// in-proc assembly path (<c>Capabilities:Modules</c>) stays a deployment
/// owner's config-listed decision -- code that runs inside the teamserver
/// is never a browse-and-click away ("open is not on", architecture.md
/// Sec 15.1).
/// </remarks>
public sealed class ModuleLifecycleService
{
    private readonly ModuleStore _store;
    private readonly ICapabilityRegistry _capabilities;
    private readonly ModuleAssetStore? _assets;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;
    private readonly long _maxPackageBytes;

    // The build-side hooks the composition root injects (ADR-023): the
    // capabilities layer cannot reference the build pipeline, so external
    // unit and extension registration arrives as delegates -- TransportHost
    // wires them to the build unit registry and the extension catalog.
    private readonly RegisterBuildSideAsync? _registerBuildSide;
    private readonly Func<string, Task>? _unregisterBuildSide;

    /// <summary>The build-side registration hook: the composition root
    /// hands the store-installed package to the build pipeline's own
    /// registries (an external unit joins the build units, an extension
    /// package joins the catalog). The capabilities layer cannot reference
    /// the pipeline, so the hook is a delegate.</summary>
    public delegate Task RegisterBuildSideAsync(string name, string directory);

    public ModuleLifecycleService(
        ModuleStore store,
        ICapabilityRegistry capabilities,
        IAuditStore audit,
        TimeProvider clock,
        ModuleAssetStore? assets = null,
        RegisterBuildSideAsync? registerBuildSide = null,
        Func<string, Task>? unregisterBuildSide = null,
        long? maxPackageBytes = null)
    {
        _store = store;
        _capabilities = capabilities;
        _assets = assets;
        _audit = audit;
        _clock = clock;
        _registerBuildSide = registerBuildSide;
        _unregisterBuildSide = unregisterBuildSide;
        _maxPackageBytes = maxPackageBytes ?? ModuleLimits.DefaultMaxPackageBytes;
    }

    /// <summary>The package ceiling this service enforces at its spine --
    /// the number the upload endpoint streams against, surfaced so the
    /// endpoint and the install refuse at one bound.</summary>
    public long MaxPackageBytes => _maxPackageBytes;

    /// <summary>The installed set, name-sorted, with each package's
    /// manifest.</summary>
    public IReadOnlyList<(ModuleLock.LockedModule Module, ModuleManifest Manifest)> Installed()
        => _store.Installed()
            .Select(held => (held.Module, held.Manifest))
            .OrderBy(held => held.Manifest.Name, StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// Installs one version of a module from the registry: fetch, verify the
    /// digest against the index, extract, re-derive the canonical form from
    /// the extracted bytes and verify the signature, pin the key (first use)
    /// or check it (every later install), then hot-register. Answers the
    /// installed record. Every refusal throws with the fix named.
    /// </summary>
    public async Task<ModuleLock.LockedModule> InstallFromRegistryAsync(
        ModuleRegistryClient registry,
        string name,
        string? version = null,
        Guid? operatorId = null,
        CancellationToken cancellationToken = default)
    {
        var entry = await registry.FindAsync(name, cancellationToken)
            ?? throw new InvalidOperationException(
                $"The registry carries no module named '{name}'.");

        RegistryVersion picked;
        if (string.IsNullOrWhiteSpace(version))
        {
            picked = entry.Versions.FirstOrDefault()
                ?? throw new InvalidOperationException(
                    $"The registry entry for '{name}' carries no versions.");
        }
        else
        {
            picked = entry.Versions.FirstOrDefault(v => v.Version == version)
                ?? throw new InvalidOperationException(
                    $"The registry entry for '{name}' carries no version '{version}'.");
        }

        var bytes = await registry.DownloadAsync(picked, cancellationToken);
        var digest = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
        if (!digest.Equals(picked.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"Package for {name}@{picked.Version} does not match the index digest; the registry or the route is lying.");

        var installed = await InstallVerifiedPackageAsync(
            bytes, name, picked.Version,
            Convert.FromBase64String(picked.PublicKey.Trim()),
            Convert.FromBase64String(picked.Signature.Trim()),
            picked.Fingerprint,
            picked.Url, operatorId, cancellationToken);
        return installed;
    }

    /// <summary>
    /// Installs an uploaded package (the operator's own build, or an
    /// out-of-band download): the same verification over the caller-supplied
    /// key and signature, so an upload is never a trust bypass -- it is the
    /// registry flow with the transport removed.
    /// </summary>
    public Task<ModuleLock.LockedModule> InstallUploadedAsync(
        byte[] packageBytes,
        string publicKeyBase64,
        string signatureBase64,
        Guid? operatorId = null,
        CancellationToken cancellationToken = default)
    {
        var publicKey = Convert.FromBase64String(publicKeyBase64.Trim());
        var signature = Convert.FromBase64String(signatureBase64.Trim());
        var fingerprint = Ed25519.Fingerprint(publicKey);
        return InstallVerifiedPackageAsync(
            packageBytes, manifestName: null, version: null,
            publicKey, signature, fingerprint,
            url: "upload", operatorId, cancellationToken);
    }

    // The shared spine: verify the package whole, adopt it into the store,
    // pin the key, hot-register everything the package carries.
    private async Task<ModuleLock.LockedModule> InstallVerifiedPackageAsync(
        byte[] packageBytes,
        string? manifestName,
        string? version,
        byte[] publicKey,
        byte[] signature,
        string fingerprint,
        string url,
        Guid? operatorId,
        CancellationToken cancellationToken)
    {
        // The one ceiling every entrance shares: an upload buffered by the
        // endpoint and a registry download already checked on its way in
        // both stop here, so no path can grow an unbounded byte[].
        if (packageBytes.Length > _maxPackageBytes)
            throw new ModulePackageTooLargeException(
                $"The package is {packageBytes.Length} bytes, over the configured " +
                $"{ModuleLimits.MaxPackageBytesKey} of {_maxPackageBytes} bytes; refusing the install.");

        // Extract into a staging directory first; nothing moves into the
        // store until every check passed.
        var staging = Path.Combine(Path.GetTempPath(), "rod-module-install-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);
        string directory;
        ModuleManifest manifest;
        try
        {
            var archive = Path.Combine(staging, "package.zip");
            await File.WriteAllBytesAsync(archive, packageBytes, cancellationToken);
            // The extraction target sits beside the archive, never around
            // it -- a tree that contained its own zip would digest it and
            // break the canonical form against the publisher's.
            var extracted = Path.Combine(staging, "package");
            ModulePackage.ExtractSafe(archive, extracted);

            var manifestPath = FindManifest(extracted)
                ?? throw new InvalidOperationException(
                    "The package carries no rod-module.toml; a Rod module's manifest is its contract.");
            var (parsed, errors) = ManifestToml.LoadFile(manifestPath);
            if (parsed is null)
                throw new InvalidOperationException(
                    $"The package's manifest does not parse: {string.Join(" ", errors)}");
            manifest = parsed;
            if (manifestName is not null && !string.Equals(manifest.Name, manifestName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    $"The package names module '{manifest.Name}', not '{manifestName}'; the index and the package disagree.");
            if (version is not null && manifest.Version.ToString() != version)
                throw new InvalidOperationException(
                    $"The package names version {manifest.Version}, not '{version}'; the index and the package disagree.");

            // The canonical form re-derived from the extracted tree: a
            // tampered byte, field, or file breaks the signature here,
            // before anything registers.
            var digests = CanonicalForm.DigestPayload(Path.GetDirectoryName(manifestPath)!);
            var canonical = CanonicalForm.Build(manifest, digests);
            if (!Ed25519.Verify(publicKey, signature, System.Text.Encoding.UTF8.GetBytes(canonical)))
                throw new InvalidOperationException(
                    $"The package's signature does not verify against its publisher key ({fingerprint}); refusing.");

            directory = _store.Adopt(Path.GetDirectoryName(manifestPath)!, manifest);
        }
        finally
        {
            try { Directory.Delete(staging, recursive: true); } catch { }
        }

        // The pin: first install of a name pins its key; a later version
        // under a different key is a loud refusal, the CLI's own rule.
        var lockFile = _store.LoadLock();
        var pinned = lockFile.TrustedKeyFor(manifest.Name);
        if (pinned is not null && !string.Equals(pinned.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            _store.Remove(lockFile.Module(manifest.Name)!);
            throw new InvalidOperationException(
                $"Module '{manifest.Name}' is pinned to key {pinned.Fingerprint}; this package signs under {fingerprint}. " +
                "A new key is a new identity -- verify the change out of band before trusting it.");
        }
        if (pinned is null)
        {
            lockFile = lockFile with
            {
                TrustedKeys = lockFile.TrustedKeys.Append(new ModuleLock.TrustedKey(
                    manifest.Name, fingerprint, Convert.ToBase64String(publicKey))).ToList(),
            };
        }

        // The upgrade posture: the newer tree replaces the older one, and
        // the lock is the record.
        var older = lockFile.Module(manifest.Name);
        if (older is not null)
            _store.Remove(older);
        var record = new ModuleLock.LockedModule
        {
            Name = manifest.Name,
            Version = manifest.Version.ToString(),
            Entry = ModuleEntryKindNames.ToString(manifest.Entry),
            Path = "modules/" + manifest.Name + "/" + manifest.Version,
            Url = url,
            Sha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(packageBytes)),
            Signature = Convert.ToBase64String(signature),
            PublicKey = Convert.ToBase64String(publicKey),
            Fingerprint = fingerprint,
            Installed = _clock.GetUtcNow().ToString("O"),
        };
        lockFile = lockFile with
        {
            Modules = lockFile.Modules.Where(m => !string.Equals(m.Name, manifest.Name, StringComparison.OrdinalIgnoreCase))
                .Append(record)
                .ToList(),
        };
        _store.SaveLock(lockFile);

        await HotRegisterAsync(manifest, directory, cancellationToken);
        await WriteAuditAsync(AuditEventKind.ModuleInstalled, operatorId, manifest.Name, manifest.Version.ToString());
        return record;
    }

    /// <summary>
    /// Uninstalls a module: the tree drops, the lock forgets, and every
    /// live registration it held retracts (its verbs keep their last
    /// registration -- another module may own them now -- but its assets and
    /// build-side registrations go).
    /// </summary>
    public async Task UninstallAsync(string name, Guid? operatorId = null, CancellationToken cancellationToken = default)
    {
        var lockFile = _store.LoadLock();
        var record = lockFile.Module(name)
            ?? throw new InvalidOperationException($"No installed module named '{name}'.");

        _store.Remove(record);
        lockFile = lockFile with
        {
            Modules = lockFile.Modules.Where(m => !string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase)).ToList(),
        };
        _store.SaveLock(lockFile);

        _assets?.RemoveModule(name);
        if (_unregisterBuildSide is not null)
            await _unregisterBuildSide(name);
        await WriteAuditAsync(AuditEventKind.ModuleRemoved, operatorId, name, record.Version);
    }

    /// <summary>
    /// Seeds the live registries from the store at startup: every lock entry
    /// whose package still exists registers exactly the way a fresh install
    /// would, so a restart and an install land in the same state.
    /// </summary>
    public async Task SeedFromStoreAsync(CancellationToken cancellationToken = default)
    {
        foreach (var (_, directory, manifest) in _store.Installed())
            await HotRegisterAsync(manifest, directory, cancellationToken);
    }

    // The hot-registration spine: descriptor rows join the capability
    // registry through the same loader a config-listed directory rides,
    // assets join the live store, and the build side registers through the
    // injected hook.
    private async Task HotRegisterAsync(ModuleManifest manifest, string directory, CancellationToken cancellationToken)
    {
        if (manifest.Verbs.Count > 0)
        {
            // DescriptorModuleLoader registers one module per verb row and
            // enforces whole rows; a plugin or extension package's rows ride
            // the same path (its server half is the rows).
            await DescriptorModuleLoader.LoadModuleAsync(directory, _capabilities, cancellationToken);
        }
        if (manifest.Entry == ModuleEntryKind.Assets)
        {
            _assets?.LoadModule(directory);
        }
        if (_registerBuildSide is not null
            && manifest.Entry is ModuleEntryKind.BuildUnit or ModuleEntryKind.Extension or ModuleEntryKind.Plugin)
        {
            await _registerBuildSide(manifest.Name, directory);
        }
    }

    private async Task WriteAuditAsync(AuditEventKind kind, Guid? operatorId, string name, string version)
    {
        // Deployment-global facts chain under the empty engagement id, the
        // operator-account precedent (architecture.md Sec 11); the acting
        // operator is the attribution, the module name and version the
        // payload.
        var fact = AuditEvent.Fact(
            Guid.NewGuid(),
            Guid.Empty,
            operatorId ?? Guid.Empty,
            Guid.Empty,
            Guid.Empty,
            "module." + (kind == AuditEventKind.ModuleInstalled ? "install" : "remove"),
            kind,
            $$"""{"name":"{{name}}","version":"{{version}}"}""",
            null,
            "succeeded",
            _clock.GetUtcNow());
        await _audit.AppendAsync(fact, CancellationToken.None);
    }

    private static string? FindManifest(string root)
    {
        var direct = Path.Combine(root, ManifestToml.FileName);
        if (File.Exists(direct))
            return direct;
        foreach (var file in Directory.EnumerateFiles(root, ManifestToml.FileName, SearchOption.AllDirectories))
            return file;
        return null;
    }
}
