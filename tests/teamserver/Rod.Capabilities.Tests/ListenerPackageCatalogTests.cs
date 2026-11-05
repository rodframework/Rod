using Rod.Audit;
using Rod.Capabilities.Lifecycle;
using Rod.Capabilities.Registry;
using Rod.Packaging;

namespace Rod.Capabilities.Tests;

/// <summary>
/// The listener package catalog (ADR-025): what a package-backed listener
/// resolves against -- the medium contract, the spawn contract, the
/// installed directory -- over the real install path (a package built and
/// signed here, installed through the lifecycle service), and the resolve-
/// side half of the third-party-medium seal rule.
/// </summary>
public class ListenerPackageCatalogTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rod-listener-catalog-" + Guid.NewGuid().ToString("N"));
    private readonly string _storeRoot;
    private readonly string _registryRoot;
    private readonly InMemoryCapabilityRegistry _capabilities = new();
    private readonly InMemoryAuditStore _audit = new();
    private readonly Ed25519.KeyPair _publisherKeys = Ed25519.GenerateKeyPair();
    private int _sequence;

    public ListenerPackageCatalogTests()
    {
        _storeRoot = Path.Combine(_root, "store");
        _registryRoot = Path.Combine(_root, "registry");
        Directory.CreateDirectory(_storeRoot);
        Directory.CreateDirectory(Path.Combine(_registryRoot, "modules"));
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);

    /// <summary>Authors, packages, signs, registers, and installs one
    /// listener package version; answers the catalog over the store it
    /// landed in. The same primitives a real publisher uses.</summary>
    private async Task<ListenerPackageCatalog> PublishAndInstallAsync(
        string name = "rod-listener-demo",
        string? sealTier = null,
        bool? thirdParty = null,
        string? endpointShape = null,
        string? tls = null)
    {
        var version = $"1.0.{_sequence++}";
        sealTier ??= "id-only";
        var source = Path.Combine(_root, "src", name + "-" + version);
        Directory.CreateDirectory(source);
        var frontRows = (endpointShape, tls) switch
        {
            (null, null) => "",
            _ => "\n"
                + (endpointShape is null ? "" : $"public-endpoint-shape = \"{endpointShape}\"\n")
                + (tls is null ? "" : $"tls = \"{tls}\""),
        };
        await File.WriteAllTextAsync(Path.Combine(source, ManifestToml.FileName), $"""
            [module]
            name = "{name}"
            version = "{version}"
            entry = "listener"
            license = "Apache-2.0"
            description = "A demonstration listener package."

            [compatibility]
            teamserver = "1.0.0"

            [opsec]
            lands-on-disk = false

            [listener]
            seal-tier = "{sealTier}"
            third-party-medium = {(thirdParty ?? sealTier == "sealed") switch { true => "true", false => "false" }}
            channel = "degraded"
            carriers = ["envelope"]
            command = "python3"
            args = ["server.py"]{frontRows}

            [[listener.params]]
            name = "bind"
            kind = "string"
            required = true
            description = "The address the medium front binds."
            """);
        await File.WriteAllTextAsync(Path.Combine(source, "server.py"), "# the byte pipe\n");

        var selection = ModulePackage.SelectFiles(source, null);
        var zip = Path.Combine(_root, "dist", $"{name}-{version}.zip");
        Directory.CreateDirectory(Path.GetDirectoryName(zip)!);
        var (_, sha256) = await ModulePackage.WriteZipAsync(selection, zip);

        var (manifest, _) = ManifestToml.LoadFile(Path.Combine(source, ManifestToml.FileName));
        var canonical = CanonicalForm.Build(manifest!, CanonicalForm.DigestPayload(source));
        var signature = Convert.ToBase64String(Ed25519.Sign(_publisherKeys.SecretKey, System.Text.Encoding.UTF8.GetBytes(canonical)));
        var publicKey = Convert.ToBase64String(_publisherKeys.PublicKey);
        var fingerprint = Ed25519.Fingerprint(_publisherKeys.PublicKey);

        var entryPath = Path.Combine(_registryRoot, "modules", name + ".json");
        var existing = (File.Exists(entryPath) ? RegistryJson.LoadEntry(entryPath) : null)
            ?? new RegistryEntry(name, "listener", "A demonstration listener package.", "Apache-2.0", null,
                new RegistryEntry.OpsecInfo(false, null), [], []);
        var entry = existing with
        {
            Versions = existing.Versions.Append(new RegistryVersion(
                version, DateTimeOffset.UtcNow.ToString("O"), zip, sha256, signature, publicKey, fingerprint,
                new RegistryVersion.CompatibilityInfo("1.0.0", []))).ToList(),
        };
        await File.WriteAllTextAsync(entryPath, RegistryJson.SaveEntry(entry));

        var store = new ModuleStore(_storeRoot);
        var service = new ModuleLifecycleService(
            store, _capabilities, _audit, TimeProvider.System, assets: null);
        await service.InstallFromRegistryAsync(new ModuleRegistryClient(_registryRoot), name, operatorId: Guid.NewGuid());
        return new ListenerPackageCatalog(store);
    }

    [Fact]
    public async Task AnInstalledListenerPackage_ResolvesItsWholeContract()
    {
        var catalog = await PublishAndInstallAsync();

        var resolved = catalog.Resolve("rod-listener-demo");

        Assert.NotNull(resolved);
        Assert.Equal("rod-listener-demo", resolved!.Name);
        Assert.Equal("1.0.0", resolved.Version);
        Assert.Equal(Rod.CoreState.Listeners.ListenerSealTiers.IdOnly, resolved.SealTier);
        Assert.False(resolved.ThirdPartyMedium);
        Assert.Equal("degraded", resolved.Channel);
        Assert.Equal(["envelope"], resolved.Carriers);
        Assert.Equal("python3", resolved.ProcessCommand);
        Assert.Equal(["server.py"], resolved.ProcessArgs);
        var parameter = Assert.Single(resolved.Params);
        Assert.Equal("bind", parameter.Name);
        Assert.True(parameter.Required);
        // The spawn contract runs inside the installed package directory.
        Assert.Equal(
            Path.Combine(_storeRoot, "modules", "rod-listener-demo", "1.0.0"),
            resolved.RootDirectory);
        Assert.True(File.Exists(Path.Combine(resolved.RootDirectory, "server.py")));
    }

    [Fact]
    public async Task ANullVersion_ResolvesTheLatestInstalledVersion()
    {
        var catalog = await PublishAndInstallAsync();
        await PublishAndInstallAsync();

        var resolved = catalog.Resolve("rod-listener-demo");

        // The store holds one tree per name (the upgrade posture: an install
        // removes the older version), so the latest -- and only the latest --
        // answers.
        Assert.Equal("1.0.1", resolved!.Version);
        Assert.Null(catalog.Resolve("rod-listener-demo", "1.0.0"));
        Assert.Null(catalog.Resolve("rod-listener-demo", "9.9.9"));
    }

    [Fact]
    public async Task ANonListenerPackage_OrAnUnknownName_ResolvesNull()
    {
        var catalog = await PublishAndInstallAsync();

        Assert.Null(catalog.Resolve("rod-listener-absent"));
    }

    [Fact]
    public async Task ADeclaredFront_ShapeAndTlsPosture_RideTheResolve()
    {
        // The endpoint shape and the TLS posture are what the manager
        // validates the public endpoint by and the supervisor issues a leaf
        // by: undeclared they keep the web dial and its by-endpoint posture,
        // declared they reach the resolve whole.
        var web = await PublishAndInstallAsync();
        var webResolved = web.Resolve("rod-listener-demo");
        Assert.Equal(Rod.CoreState.Listeners.ListenerEndpointShapes.WebDial, webResolved!.EndpointShape);
        Assert.Equal(Rod.CoreState.Listeners.ListenerTlsPostures.ByEndpoint, webResolved.Tls);

        var doh = await PublishAndInstallAsync(endpointShape: "dns-zone", tls: "always");
        var dohResolved = doh.Resolve("rod-listener-demo");
        Assert.Equal(Rod.CoreState.Listeners.ListenerEndpointShapes.DnsZone, dohResolved!.EndpointShape);
        Assert.Equal(Rod.CoreState.Listeners.ListenerTlsPostures.Always, dohResolved.Tls);
    }

    [Fact]
    public async Task ADriftedStore_CannotServeAThirdPartyIdOnlyPackage()
    {
        // Publish refuses the posture at the manifest's own validation, so
        // the drift this test plants is a hand-edited installed tree: the
        // store's manifest re-parses on every resolve, and the catalog
        // refuses to serve what validation would have refused.
        var catalog = await PublishAndInstallAsync(sealTier: "sealed", thirdParty: true);
        var manifestPath = Path.Combine(
            _storeRoot, "modules", "rod-listener-demo", "1.0.0", ManifestToml.FileName);
        File.WriteAllText(manifestPath, File.ReadAllText(manifestPath)
            .Replace("seal-tier = \"sealed\"", "seal-tier = \"id-only\""));

        Assert.Throws<InvalidOperationException>(() => catalog.Resolve("rod-listener-demo"));
    }
}
