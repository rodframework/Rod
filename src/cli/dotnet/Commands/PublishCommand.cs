using System.Security.Cryptography;
using Rod.Cli.Manifest;
using Rod.Cli.Packaging;
using Rod.Cli.Registry;
using Rod.Cli.Signing;

namespace Rod.Cli.Commands;

/// <summary>
/// <c>rod mod publish</c>: the producer end of the trust chain. Packs the
/// module per its manifest rules, builds the canonical form over the
/// manifest fields and every selected payload file's digest, signs it with
/// the publisher's secret key, and emits the deterministic package plus
/// the version's index entry. With <c>--registry</c> pointing at a local
/// rod-registry checkout the entry is written for the pull request --
/// publication is a commit a human sends, never a push the tool makes
/// (the git shape's governance, architecture.md Sec 15.2).
/// </summary>
public static class PublishCommand
{
    public static async Task<int> Run(string[] args, TextWriter output)
    {
        var parsed = ParsedArgs.Parse(args,
            valueOptions: new HashSet<string> { "path", "registry", "key", "out" },
            flags: new HashSet<string>(),
            verb: "publish");

        var moduleDirectory = Path.GetFullPath(parsed.Value("path") ?? Environment.CurrentDirectory);
        var manifestPath = Path.Combine(moduleDirectory, ManifestToml.FileName);
        if (!File.Exists(manifestPath))
            throw new CliError($"no {ManifestToml.FileName} in '{moduleDirectory}' -- 'rod mod init' scaffolds one.");

        var (manifest, errors) = ManifestToml.LoadFile(manifestPath);
        if (manifest is null || errors.Count > 0)
            throw new CliError($"the manifest is invalid:\n  {string.Join("\n  ", errors)}");

        if (string.Equals(manifest.License, "UNLICENSED", StringComparison.OrdinalIgnoreCase))
            throw new CliError("module.license is still UNLICENSED; set a real SPDX identifier before publishing.");

        var selection = ModulePackage.SelectFiles(moduleDirectory, manifest.Package);
        // The safety net over the hard excludes: a key that reached the
        // selection means the rules said so, and the answer is to stop and
        // ask, never to publish the secret.
        if (selection.Files.Any(f => f.EndsWith(".key", StringComparison.OrdinalIgnoreCase)))
            throw new CliError(
                $"the packaging rules would include key material ({string.Join(", ", selection.Files.Where(f => f.EndsWith(".key", StringComparison.OrdinalIgnoreCase)))}); " +
                "exclude it in rod-module.toml's [package].");
        if (selection.Files.Count <= 1)
            throw new CliError("the package would be empty beyond the manifest; check the [package] rules.");

        var distDirectory = Path.GetFullPath(parsed.Value("out") ?? Path.Combine(moduleDirectory, "dist"));
        Directory.CreateDirectory(distDirectory);
        var archivePath = Path.Combine(distDirectory, $"{manifest.Name}-{manifest.Version}.zip");
        var registry = parsed.Value("registry");
        var (_, sha256) = await ModulePackage.WriteZipAsync(selection, archivePath);

        var keyPath = parsed.Value("key") ?? Path.Combine(moduleDirectory, KeyFiles.SecretFileName);
        if (!File.Exists(keyPath))
            throw new CliError(
                $"no signing key at '{keyPath}'. Keep the one 'rod mod init' generated; a fresh key is a new publisher identity " +
                "(every install that pinned the old key will refuse the new one).");
        var secret = KeyFiles.LoadSecret(keyPath);
        var publicKey = Ed25519.PublicFromSecret(secret);
        var fingerprint = Ed25519.Fingerprint(publicKey);

        var payload = selection.Files
            .Where(f => f != ManifestToml.FileName)
            .ToDictionary(
                f => f,
                f => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(moduleDirectory, f)))),
                StringComparer.Ordinal);
        var canonical = CanonicalForm.Build(manifest, payload);
        var signature = Convert.ToBase64String(Ed25519.Sign(secret, System.Text.Encoding.UTF8.GetBytes(canonical)));

        var url = registry is not null
            ? new Uri(archivePath).AbsoluteUri
            : $"https://example.invalid/{manifest.Name}-{manifest.Version}.zip";
        var version = new RegistryVersion(
            Version: manifest.Version.ToString(),
            Published: DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            Url: url,
            Sha256: sha256,
            Signature: signature,
            PublicKey: Convert.ToBase64String(publicKey),
            Fingerprint: fingerprint,
            Compatibility: new RegistryVersion.CompatibilityInfo(
                manifest.TeamserverMin.ToString(),
                manifest.Targets
                    .Select(t => new RegistryVersion.TargetInfo(t.ImplantClass, t.Platform, t.Arch))
                    .ToList()),
            Verbs: manifest.Verbs
                .Select(v => new RegistryVersion.VerbInfo(v.Name, v.Version.ToString(), v.TeamserverMin?.ToString()))
                .ToList(),
            Assets: manifest.Assets.Count == 0
                ? null
                : manifest.Assets.Select(a => a.Name).ToList());

        var fragmentPath = Path.Combine(distDirectory, $"{manifest.Name}-{manifest.Version}.json");
        File.WriteAllText(fragmentPath, RegistryJson.SaveVersion(version));

        var template = new RegistryEntry(
            Name: manifest.Name,
            Entry: ModuleEntryKindNames.ToString(manifest.Entry),
            Description: manifest.Description,
            License: manifest.License,
            Homepage: manifest.Homepage,
            Opsec: new RegistryEntry.OpsecInfo(manifest.Opsec.LandsOnDisk, manifest.Opsec.Notes),
            Attack: manifest.Techniques.ToList(),
            Versions: []);

        if (registry is not null)
        {
            var store = RegistryStore.Open(registry, createIfLocal: true);
            store.UpsertVersion(manifest.Name, template, version, output);
            output.WriteLine($"registry entry written: {store.Root}");
            output.WriteLine("next: in the registry checkout, git add modules/ commit, and open the pull request -- publication is the PR, not a push.");
        }
        else
        {
            output.WriteLine(RegistryJson.SaveVersion(version).TrimEnd());
            output.WriteLine();
            output.WriteLine($"version entry written: {fragmentPath}");
            output.WriteLine("upload the package, set the url in the entry to its download location, then send the pull request against rod-registry.");
        }

        output.WriteLine($"package:  {archivePath}");
        output.WriteLine($"  size:     {new FileInfo(archivePath).Length} bytes");
        output.WriteLine($"  sha256:   {sha256}");
        output.WriteLine($"  signed by {fingerprint}");
        return RodCli.ExitOk;
    }
}
