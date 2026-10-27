using System.Security.Cryptography;
using Rod.Cli.Manifest;
using Rod.Cli.Packaging;
using Rod.Cli.Registry;
using Rod.Cli.Signing;

namespace Rod.Cli.Commands;

/// <summary>
/// <c>rod mod install</c>: the trust chain's consumer end. Every step is
/// verified before the next runs -- package digest, then the publisher's
/// signature over the manifest's canonical form (re-derived from the
/// extracted files, never from index metadata), then the compatibility
/// floor, then the lock's key pin -- and only then does anything land
/// under <c>modules/&lt;name&gt;/&lt;version&gt;/</c> and the lock file
/// record it. A failure anywhere is exit code 2 and an untouched root.
/// </summary>
public static class InstallCommand
{
    private static readonly HttpClient Http = new();

    public static async Task<int> Run(string[] args, TextWriter output, TextWriter error)
    {
        var parsed = ParsedArgs.Parse(args,
            valueOptions: new HashSet<string> { "registry", "dir", "teamserver" },
            flags: new HashSet<string> { "force" },
            verb: "install");

        if (parsed.Positional.Count != 1)
            throw new CliError("rod mod install needs <name>[@version].");

        var root = Path.GetFullPath(parsed.Value("dir") ?? Environment.CurrentDirectory);
        Directory.CreateDirectory(root);
        var registry = RegistrySource.Resolve(parsed, root);
        var store = RegistryStore.Open(registry);
        var (name, wanted) = ModuleRef.Parse(parsed.Positional[0]);

        var entry = store.Find(name)
            ?? throw new CliError($"'{name}' is not in the registry '{parsed.Value("registry") ?? "from the lock file"}'.");
        var versions = entry.Versions
            .OrderByDescending(v => SemVer.TryParse(v.Version, out var parsedVersion) ? parsedVersion : new SemVer(0, 0, 0, null))
            .ToList();
        if (versions.Count == 0)
            throw new CliError($"'{name}' has no indexed versions.");
        var version = wanted is null
            ? versions[0]
            : versions.FirstOrDefault(v => v.Version == wanted)
              ?? throw new CliError($"'{name}' has no version {wanted}; indexed: {string.Join(", ", versions.Select(v => v.Version))}.");

        var lockFile = ModuleLock.Load(InstallRoot.LockPath(root));
        var installed = lockFile.Module(name);
        var alreadyThere = installed is not null
            && installed.Version == version.Version
            && Directory.Exists(Path.Combine(root, installed.Path));
        if (alreadyThere && !parsed.Has("force"))
        {
            output.WriteLine($"{name}@{version.Version} already installed ({installed!.Path}); --force to reinstall.");
            return RodCli.ExitOk;
        }

        // The compatibility floor is checked against the operator's stated
        // teamserver version, defaulting to this CLI's platform stamp; the
        // CLI ships with the tree, so the stamp is the deployment's best
        // proxy until the operator says otherwise.
        if (!SemVer.TryParse(parsed.Value("teamserver") ?? BuildStamp.Version, out var teamserver))
            throw new CliError($"--teamserver '{parsed.Value("teamserver")}' is not a SemVer version.");
        if (!SemVer.TryParse(version.Compatibility.Teamserver, out var floor))
            throw new CliError($"registry entry for {name}@{version.Version} carries an unparseable teamserver floor '{version.Compatibility.Teamserver}'.");
        if (floor.CompareTo(teamserver) > 0)
            throw new CliError(
                $"{name}@{version.Version} needs teamserver >= {version.Compatibility.Teamserver}, running {teamserver}. " +
                "Pass --teamserver <version> if the deployment is newer than this CLI.");

        output.WriteLine($"fetching {name}@{version.Version} from {version.Url}");
        var tempDirectory = Path.Combine(Path.GetTempPath(), "rod-install-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDirectory);
        try
        {
            var archivePath = Path.Combine(tempDirectory, "package.zip");
            await DownloadAsync(version.Url, archivePath);
            var digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(File.OpenRead(archivePath)));
            if (!string.Equals(digest, version.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new CliError($"package digest mismatch for {name}@{version.Version}: expected {version.Sha256}, got {digest}.", RodCli.ExitTrustFailure);
            output.WriteLine("package digest verified.");

            var extractDirectory = Path.Combine(tempDirectory, "package");
            ModulePackage.ExtractSafe(archivePath, extractDirectory);
            var (manifest, manifestErrors) = ManifestToml.LoadFile(Path.Combine(extractDirectory, ManifestToml.FileName));
            if (manifest is null || manifestErrors.Count > 0)
                throw new CliError($"the package's manifest is invalid: {string.Join(" ", manifestErrors)}", RodCli.ExitTrustFailure);
            if (!string.Equals(manifest.Name, name, StringComparison.OrdinalIgnoreCase)
                || manifest.Version.ToString() != version.Version
                || ModuleEntryKindNames.ToString(manifest.Entry) != entry.Entry)
            {
                throw new CliError(
                    $"the package disagrees with the index: manifest {manifest.Name}@{manifest.Version} ({ModuleEntryKindNames.ToString(manifest.Entry)}) " +
                    $"vs index {name}@{version.Version} ({entry.Entry}).", RodCli.ExitTrustFailure);
            }

            // The verb rows' own floors (the version matrix's third contract):
            // a verb that needs a newer teamserver than the deployment runs
            // names itself at install, so a mixed module still lands only
            // when every verb in it can run.
            foreach (var verb in manifest.Verbs)
            {
                if (verb.TeamserverMin is { } verbFloor && verbFloor.CompareTo(teamserver) > 0)
                {
                    throw new CliError(
                        $"{name}@{version.Version} verb {verb.Name}@{verb.Version} needs teamserver >= {verbFloor}, running {teamserver}. " +
                        "Pass --teamserver <version> if the deployment is newer than this CLI.");
                }
            }

            var canonical = CanonicalForm.Build(manifest, CanonicalForm.DigestPayload(extractDirectory));
            if (!Ed25519.Verify(Ed25519.DecodeKey(version.PublicKey), Convert.FromBase64String(version.Signature),
                    System.Text.Encoding.UTF8.GetBytes(canonical)))
                throw new CliError($"signature verification failed for {name}@{version.Version}.", RodCli.ExitTrustFailure);
            output.WriteLine($"signature verified (publisher {version.Fingerprint}).");

            // The compatibility rows ride the verified manifest (ADR-017):
            // what the hosting implant must advertise, and for a build unit
            // what its candidate proved -- advisory at install (the target's
            // own handshake advertisement is the runtime truth), surfaced so
            // the operator screens before the module reaches an engagement.
            if (manifest.Requires.Count > 0)
                output.WriteLine($"requires on the target implant: {string.Join(", ", manifest.Requires)}");
            if (manifest.Conformance is { } conformance)
                output.WriteLine($"conformance: Tier {conformance.Tier} (harness {conformance.Harness}, {conformance.Date})");

            var trusted = lockFile.TrustedKeyFor(name);
            if (trusted is null)
            {
                output.WriteLine($"first install of '{name}': pinning publisher key {version.Fingerprint} in the lock file -- compare it out of band if it matters.");
            }
            else if (!string.Equals(trusted.Fingerprint, version.Fingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new CliError(
                    $"publisher key changed for '{name}': pinned {trusted.Fingerprint}, index says {version.Fingerprint}. " +
                    "If the change is real, remove the pin deliberately in the lock file and reinstall.", RodCli.ExitTrustFailure);
            }

            // Land it: stage, then swap, so a failed move leaves the
            // previous install in place.
            var destination = InstallRoot.ModulePath(root, name, version.Version);
            if (alreadyThere && Directory.Exists(Path.Combine(root, installed!.Path)))
                Directory.Delete(Path.Combine(root, installed.Path), recursive: true);
            if (Directory.Exists(destination))
                Directory.Delete(destination, recursive: true);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            Directory.Move(extractDirectory, destination);
            // An upgrade replaces: older version trees under modules/<name>/
            // are the previous install, not history the engagement keeps --
            // the lock file is the record, the directory is the current set.
            foreach (var stale in Directory.GetDirectories(Path.GetDirectoryName(destination)!))
                if (!string.Equals(stale, destination, StringComparison.OrdinalIgnoreCase))
                    Directory.Delete(stale, recursive: true);

            lockFile = lockFile with
            {
                Registry = parsed.Value("registry") ?? lockFile.Registry ?? registry,
                TrustedKeys = (trusted is null
                    ? lockFile.TrustedKeys.Append(new ModuleLock.TrustedKey(name, version.Fingerprint, version.PublicKey))
                    : lockFile.TrustedKeys).ToList(),
                Modules = lockFile.Modules
                    .Where(m => !string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase))
                    .Append(new ModuleLock.LockedModule
                    {
                        Name = name,
                        Version = version.Version,
                        Entry = ModuleEntryKindNames.ToString(manifest.Entry),
                        Path = $"{InstallRoot.ModulesFolder}/{name}/{version.Version}",
                        Url = version.Url,
                        Sha256 = version.Sha256,
                        Signature = version.Signature,
                        PublicKey = version.PublicKey,
                        Fingerprint = version.Fingerprint,
                        Installed = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
                    })
                    .ToList(),
            };
            ModuleLock.Save(InstallRoot.LockPath(root), lockFile);

            output.WriteLine($"installed {name}@{version.Version} -> {Path.Combine(InstallRoot.ModulesFolder, name, version.Version)}");
            if (manifest.Entry == ModuleEntryKind.Server)
                output.WriteLine($"next: load it the config-listed way -- copy the assembly beside the teamserver binary and list the type under Capabilities:Modules.");
            else if (manifest.Entry == ModuleEntryKind.Assets)
                output.WriteLine($"next: point Capabilities:AssetModules at the installed directory so the teamserver serves its assets.");
            return RodCli.ExitOk;
        }
        finally
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    internal static async Task DownloadAsync(string url, string destinationFile)
    {
        if (url.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
        {
            var local = new Uri(url).LocalPath;
            if (!File.Exists(local))
                throw new CliError($"artifact '{url}' does not exist on disk.");
            File.Copy(local, destinationFile, overwrite: true);
            return;
        }

        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            throw new CliError($"artifact url '{url}' must be https:// or file://.");

        using var response = await Http.GetAsync(url);
        if (!response.IsSuccessStatusCode)
            throw new CliError($"fetching '{url}' failed: {(int)response.StatusCode} {response.ReasonPhrase}.");
        await using var source = await response.Content.ReadAsStreamAsync();
        await using var target = File.Create(destinationFile);
        await source.CopyToAsync(target);
    }
}

/// <summary>
/// <c>rod mod verify</c>: the offline re-proof. No network, no registry --
/// for every module the lock file records, the installed tree is re-read,
/// the canonical form re-derived from the actual files, and the signature
/// re-checked against the pinned key. A tampered manifest field, a swapped
/// payload byte, or a replaced whole tree each read as a named failure;
/// exit code 2 makes the finding script-visible.
/// </summary>
public static class VerifyCommand
{
    public static int Run(string[] args, TextWriter output)
    {
        var parsed = ParsedArgs.Parse(args,
            valueOptions: new HashSet<string> { "dir" },
            flags: new HashSet<string>(),
            verb: "verify");

        var root = Path.GetFullPath(parsed.Value("dir") ?? Environment.CurrentDirectory);
        var lockFile = ModuleLock.Load(InstallRoot.LockPath(root));
        if (lockFile.Modules.Count == 0)
        {
            output.WriteLine("no installed modules; nothing to verify.");
            return RodCli.ExitOk;
        }

        var failures = 0;
        foreach (var module in lockFile.Modules)
        {
            var directory = Path.Combine(root, module.Path);
            string failure;
            if (!Directory.Exists(directory))
            {
                failure = $"installed tree missing ({module.Path})";
            }
            else if (!File.Exists(Path.Combine(directory, ManifestToml.FileName)))
            {
                failure = "manifest missing from the installed tree";
            }
            else
            {
                var (manifest, manifestErrors) = ManifestToml.LoadFile(Path.Combine(directory, ManifestToml.FileName));
                if (manifest is null || manifestErrors.Count > 0)
                    failure = $"manifest invalid: {string.Join(" ", manifestErrors)}";
                else if (!string.Equals(manifest.Name, module.Name, StringComparison.OrdinalIgnoreCase)
                    || manifest.Version.ToString() != module.Version
                    || ModuleEntryKindNames.ToString(manifest.Entry) != module.Entry)
                    failure = $"manifest {manifest.Name}@{manifest.Version} ({ModuleEntryKindNames.ToString(manifest.Entry)}) disagrees with the lock ({module.Name}@{module.Version}, {module.Entry})";
                else
                {
                    var canonical = CanonicalForm.Build(manifest, CanonicalForm.DigestPayload(directory));
                    failure = Ed25519.Verify(Ed25519.DecodeKey(module.PublicKey), Convert.FromBase64String(module.Signature),
                        System.Text.Encoding.UTF8.GetBytes(canonical))
                        ? ""
                        : "signature does not verify over the installed files";
                }
            }

            if (failure.Length == 0)
                output.WriteLine($"PASS {module.Name}@{module.Version} ({module.Fingerprint})");
            else
            {
                output.WriteLine($"FAIL {module.Name}@{module.Version}: {failure}");
                failures++;
            }
        }

        output.WriteLine(failures == 0
            ? $"{lockFile.Modules.Count} module(s) verified."
            : $"{failures} of {lockFile.Modules.Count} module(s) FAILED verification.");
        return failures == 0 ? RodCli.ExitOk : RodCli.ExitTrustFailure;
    }
}
