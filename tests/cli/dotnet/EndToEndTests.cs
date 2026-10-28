using Rod.Packaging;
using System.Text.Json;

namespace Rod.Cli.Tests;

/// <summary>
/// The acceptance run for the ecosystem item (todo's AC: template
/// repository through publish to install, end to end): init scaffolds the
/// template repository, publish packages and signs it into a local
/// rod-registry, search and info read the index back, install fetches,
/// verifies, and lands it under the lock, and verify re-proves the tree --
/// then the same machinery proves the negative paths: a tampered tree, a
/// hostile publisher key, and a stale version pin.
/// </summary>
public class EndToEndTests
{
    [Fact]
    public void TemplateRepositoryThroughPublishToInstall_RunsEndToEnd()
    {
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        var registry = root["registry"];
        var install = root["install"];

        // init: the template repository.
        var init = CliRun.Run("mod", "init", "demo-sweep", "--path", module, "--entry", "server");
        Assert.True(init.Code == 0, init.Error);
        Assert.True(File.Exists(Path.Combine(module, "rod-module.toml")));
        Assert.True(File.Exists(Path.Combine(module, Rod.Packaging.KeyFiles.SecretFileName)));
        Assert.True(File.Exists(Path.Combine(module, Rod.Packaging.KeyFiles.PublicFileName)));

        // Author the module: a real license, a version, a payload file.
        var manifestPath = Path.Combine(module, "rod-module.toml");
        var manifest = File.ReadAllText(manifestPath)
            .Replace("license = \"UNLICENSED\"", "license = \"MIT\"")
            .Replace("version = \"0.1.0\"", "version = \"1.0.0\"")
            .Replace("techniques = []", "techniques = [\"T1082\"]");
        File.WriteAllText(manifestPath, manifest);
        Directory.CreateDirectory(Path.Combine(module, "src"));
        File.WriteAllText(Path.Combine(module, "src", "payload.cs"), "payload-v1");
        File.WriteAllText(Path.Combine(module, "unrelated.key"), "should never ship");

        // publish: package, sign, index entry into the local registry.
        var publish = CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        Assert.True(publish.Code == 0, publish.Error);
        Assert.True(File.Exists(Path.Combine(registry, "modules", "demo-sweep.json")));
        Assert.True(File.Exists(Path.Combine(module, "dist", "demo-sweep-1.0.0.zip")));
        Assert.Contains("signed by", publish.Output);

        // search and info: the catalog over the static index.
        var search = CliRun.Run("mod", "search", "sweep", "--registry", registry);
        Assert.True(search.Code == 0, search.Error);
        Assert.Contains("demo-sweep", search.Output);
        Assert.Contains("disk", search.Output); // the OPSEC mark rides the listing

        var info = CliRun.Run("mod", "info", "demo-sweep", "--registry", registry);
        Assert.True(info.Code == 0, info.Error);
        Assert.Contains("T1082", info.Output);
        Assert.Contains("MIT", info.Output);

        // install: fetch, digest, signature, compat, pin, land.
        var installRun = CliRun.Run("mod", "install", "demo-sweep", "--registry", registry,
            "--dir", install, "--teamserver", "1.0.0");
        Assert.True(installRun.Code == 0, installRun.Error);
        var installedManifest = Path.Combine(install, "modules", "demo-sweep", "1.0.0", "rod-module.toml");
        Assert.True(File.Exists(installedManifest));
        Assert.True(File.Exists(Path.Combine(install, "modules", "demo-sweep", "1.0.0", "src", "payload.cs")));
        Assert.False(File.Exists(Path.Combine(install, "modules", "demo-sweep", "1.0.0", "unrelated.key")));

        var lockFile = ModuleLock.Load(Path.Combine(install, ModuleLock.FileName));
        var locked = lockFile.Module("demo-sweep");
        Assert.NotNull(locked);
        Assert.Equal("1.0.0", locked!.Version);
        Assert.Equal("server", locked.Entry);
        Assert.NotNull(lockFile.TrustedKeyFor("demo-sweep"));
        Assert.Equal(registry, lockFile.Registry);

        // verify: the offline re-proof.
        var verify = CliRun.Run("mod", "verify", "--dir", install);
        Assert.True(verify.Code == 0, verify.Error);
        Assert.Contains("PASS demo-sweep@1.0.0", verify.Output);

        // A tampered payload byte reads as a failure with exit code 2.
        File.WriteAllText(Path.Combine(install, "modules", "demo-sweep", "1.0.0", "src", "payload.cs"), "tampered");
        var tampered = CliRun.Run("mod", "verify", "--dir", install);
        Assert.Equal(RodCli.ExitTrustFailure, tampered.Code);
        Assert.Contains("FAIL demo-sweep@1.0.0", tampered.Output);
    }

    [Fact]
    public void Reinstalling_IsIdempotent_UpgradesReplace_RepublishingRefusesDrift()
    {
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        var registry = root["registry"];
        var install = root["install"];
        CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        Author(module, "1.0.0", "payload-v1");
        CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        CliRun.Run("mod", "install", "demo-sweep", "--registry", registry, "--dir", install, "--teamserver", "1.0.0");

        // Same tree, same version: the registry entry is unchanged.
        var again = CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        Assert.True(again.Code == 0, again.Error);
        Assert.Contains("already indexed with this digest", again.Output);

        // Same version, different content: the registry refuses the drift.
        File.WriteAllText(Path.Combine(module, "src", "payload.cs"), "payload-v1-EDITED");
        var drifted = CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        Assert.Equal(RodCli.ExitUsage, drifted.Code);
        Assert.Contains("bump module.version", drifted.Error);

        // A bumped version installs as an upgrade: one row in the lock, one
        // directory on disk -- the lock is the record, not the directory.
        Author(module, "1.1.0", "payload-v2");
        var upgrade = CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        Assert.True(upgrade.Code == 0, upgrade.Error);
        var installUpgrade = CliRun.Run("mod", "install", "demo-sweep@1.1.0", "--registry", registry,
            "--dir", install, "--teamserver", "1.0.0");
        Assert.True(installUpgrade.Code == 0, installUpgrade.Error);
        Assert.True(Directory.Exists(Path.Combine(install, "modules", "demo-sweep", "1.1.0")));
        Assert.False(Directory.Exists(Path.Combine(install, "modules", "demo-sweep", "1.0.0")));
        var lockFile = ModuleLock.Load(Path.Combine(install, ModuleLock.FileName));
        Assert.Equal("1.1.0", lockFile.Module("demo-sweep")!.Version);
        Assert.Single(lockFile.Modules);
    }

    [Fact]
    public void AHostilePublisherKey_IsRefusedByThePin()
    {
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        var hostile = root["hostile"];
        var keySeed = root["keyseed"];
        var registry = root["registry"];
        var install = root["install"];

        CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        Author(module, "1.0.0", "payload-v1");
        CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        var first = CliRun.Run("mod", "install", "demo-sweep", "--registry", registry, "--dir", install, "--teamserver", "1.0.0");
        Assert.True(first.Code == 0, first.Error);

        // The same module name under a different key: an attacker (or a
        // lost key) publishing 1.1.0.
        CopyDirectory(module, hostile);
        Directory.Delete(Path.Combine(hostile, "dist"), recursive: true);
        CliRun.Run("mod", "init", "seed", "--path", keySeed); // generates a second identity
        File.Copy(Path.Combine(keySeed, "rod-module.key"), Path.Combine(hostile, "rod-module.key"), overwrite: true);
        File.Copy(Path.Combine(keySeed, "rod-module.pub"), Path.Combine(hostile, "rod-module.pub"), overwrite: true);
        Author(hostile, "1.1.0", "payload-hostile");
        var publish = CliRun.Run("mod", "publish", "--path", hostile, "--registry", registry);
        Assert.True(publish.Code == 0, publish.Error);

        var second = CliRun.Run("mod", "install", "demo-sweep@1.1.0", "--registry", registry,
            "--dir", install, "--teamserver", "1.0.0");
        Assert.Equal(RodCli.ExitTrustFailure, second.Code);
        Assert.Contains("publisher key changed", second.Error);
        // Nothing landed.
        Assert.False(Directory.Exists(Path.Combine(install, "modules", "demo-sweep", "1.1.0")));
    }

    [Fact]
    public void APackageDigestMismatch_IsRefusedBeforeAnythingLands()
    {
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        var registry = root["registry"];
        var install = root["install"];

        CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        Author(module, "1.0.0", "payload-v1");
        CliRun.Run("mod", "publish", "--path", module, "--registry", registry);

        // Corrupt the artifact the index points at: digest check fires
        // before signature or compatibility run.
        var entryPath = Path.Combine(registry, "modules", "demo-sweep.json");
        var entry = JsonDocument.Parse(File.ReadAllText(entryPath));
        var url = entry.RootElement.GetProperty("versions")[0].GetProperty("url").GetString()!;
        File.WriteAllText(url.Replace("file://", ""), "corrupted bytes");

        var installRun = CliRun.Run("mod", "install", "demo-sweep", "--registry", registry,
            "--dir", install, "--teamserver", "1.0.0");
        Assert.Equal(RodCli.ExitTrustFailure, installRun.Code);
        Assert.Contains("digest mismatch", installRun.Error);
    }

    [Fact]
    public void ACompatibilityFloor_AboveTheTeamserver_RefusesInstall()
    {
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        var registry = root["registry"];

        CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        Author(module, "1.0.0", "payload-v1", teamserver: "2.0.0");
        var publish = CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        Assert.True(publish.Code == 0, publish.Error);

        var install = CliRun.Run("mod", "install", "demo-sweep", "--registry", registry,
            "--dir", root["install"], "--teamserver", "1.5.0");
        Assert.Equal(RodCli.ExitUsage, install.Code);
        Assert.Contains("needs teamserver >= 2.0.0", install.Error);
    }

    [Fact]
    public void PublishRefuses_UnlicensedModules_AndEmptyPackages()
    {
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        var registry = root["registry"];

        CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        // The scaffold ships UNLICENSED; publish must refuse it.
        var unlicensed = CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        Assert.Equal(RodCli.ExitUsage, unlicensed.Code);
        Assert.Contains("UNLICENSED", unlicensed.Error);

        // A license but packaging rules that select nothing: an empty
        // package is a mistake, not a module. The manifest-alone exemption
        // belongs to server-entry descriptor rows (ADR-018 -- the rows are
        // the whole module); an extension module carries its crate as
        // payload, so rules that select nothing stay a refusal.
        Author(module, "1.0.0", payload: null);
        var toml = File.ReadAllText(Path.Combine(module, "rod-module.toml"))
            .Replace("entry = \"server\"", "entry = \"extension\"")
            .Replace("""
                # [[compatibility.targets]]
                # implant-class = "implant"
                # platform = "linux"
                # arch = "amd64"
                """, """
                [[compatibility.targets]]
                implant-class = "implant"
                build-unit = "rod-rust"
                platform = "linux"
                arch = "amd64"
                """)
            + "\n[package]\ninclude = [\"nothing/**\"]\n";
        File.WriteAllText(Path.Combine(module, "rod-module.toml"), toml);
        var empty = CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        Assert.Equal(RodCli.ExitUsage, empty.Code);
        Assert.Contains("empty beyond the manifest", empty.Error);
    }

    [Fact]
    public void SearchFinds_AttackTechniquesAndDescriptions()
    {
        using var root = new TempRoot();
        var module = root["cred-sweep"];
        var registry = root["registry"];
        CliRun.Run("mod", "init", "cred-sweep", "--path", module);
        Author(module, "1.0.0", "payload", description: "Credential store sweep");
        var toml = File.ReadAllText(Path.Combine(module, "rod-module.toml"))
            .Replace("techniques = []", "techniques = [\"T1555\"]");
        File.WriteAllText(Path.Combine(module, "rod-module.toml"), toml);
        CliRun.Run("mod", "publish", "--path", module, "--registry", registry);

        Assert.Contains("cred-sweep", CliRun.Run("mod", "search", "T1555", "--registry", registry).Output);
        Assert.Contains("cred-sweep", CliRun.Run("mod", "search", "credential", "--registry", registry).Output);
        Assert.Contains("cred-sweep", CliRun.Run("mod", "search", "CRED", "--registry", registry).Output);
        Assert.DoesNotContain("cred-sweep", CliRun.Run("mod", "search", "nonexistent-term", "--registry", registry).Output);
    }

    [Fact]
    public void TheVersionMatrix_RidesScaffoldPublishInstallAndVerify()
    {
        // The contract trilogy's third contract (architecture.md Sec 15.2):
        // the scaffold carries verb rows, the registry entry mirrors them,
        // info reads them back, install checks their per-verb floors, and
        // verify's re-derived canonical form covers them -- a tampered verb
        // version reads as a trust failure exactly like a tampered payload
        // byte.
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        var registry = root["registry"];
        var install = root["install"];

        var init = CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        Assert.True(init.Code == 0, init.Error);
        var scaffolded = File.ReadAllText(Path.Combine(module, "rod-module.toml"));
        Assert.Contains("[[verbs]]", scaffolded);
        Assert.Contains("name = \"demo-sweep.run\"", scaffolded);

        Author(module, "1.0.0", "payload-v1");
        // Author's version rewrite also retargets the scaffolded verb row, so
        // the module ships one row at 1.0.0; the second verb arrives with its
        // own version and a per-verb floor.
        var toml = File.ReadAllText(Path.Combine(module, "rod-module.toml")) + """
            [[verbs]]
            name = "demo-sweep.deep"
            version = "0.2.0"
            teamserver = "1.4.0"
            """;
        File.WriteAllText(Path.Combine(module, "rod-module.toml"), toml);

        var publish = CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        Assert.True(publish.Code == 0, publish.Error);

        // The catalog answers verb questions: search finds the module by a
        // verb name, info lists the rows with their floors.
        Assert.Contains("demo-sweep", CliRun.Run("mod", "search", "demo-sweep.deep", "--registry", registry).Output);
        var info = CliRun.Run("mod", "info", "demo-sweep", "--registry", registry);
        Assert.Contains("demo-sweep.deep@0.2.0 (teamserver >= 1.4.0)", info.Output);
        Assert.Contains("demo-sweep.run@1.0.0", info.Output);

        // The per-verb floor refuses an install the module-wide floor would
        // have admitted, naming the verb that needs the newer teamserver.
        var refused = CliRun.Run("mod", "install", "demo-sweep", "--registry", registry,
            "--dir", install, "--teamserver", "1.2.0");
        Assert.Equal(RodCli.ExitUsage, refused.Code);
        Assert.Contains("demo-sweep.deep@0.2.0 needs teamserver >= 1.4.0", refused.Error);

        // On a teamserver that satisfies every floor, the install lands and
        // verify re-proves the tree -- including the verb rows.
        var installed = CliRun.Run("mod", "install", "demo-sweep", "--registry", registry,
            "--dir", install, "--teamserver", "1.5.0");
        Assert.True(installed.Code == 0, installed.Error);
        var verify = CliRun.Run("mod", "verify", "--dir", install);
        Assert.True(verify.Code == 0, verify.Error);
        Assert.Contains("PASS demo-sweep@1.0.0", verify.Output);

        // A tampered verb version in the installed tree breaks the canonical
        // form and therefore the signature: exit 2, the trust failure.
        var installedManifest = Path.Combine(install, "modules", "demo-sweep", "1.0.0", "rod-module.toml");
        File.WriteAllText(installedManifest,
            File.ReadAllText(installedManifest).Replace("demo-sweep.deep\"\nversion = \"0.2.0\"", "demo-sweep.deep\"\nversion = \"9.9.9\""));
        var tampered = CliRun.Run("mod", "verify", "--dir", install);
        Assert.Equal(RodCli.ExitTrustFailure, tampered.Code);
        Assert.Contains("FAIL demo-sweep@1.0.0", tampered.Output);
    }

    [Fact]
    public void VerbTechniques_RideTheRegistryMirror_AndSearchFindsThem()
    {
        // ADR-007's advancement mechanism: the verb row's technique declaration
        // is the authoritative coverage claim, and the registry index mirrors
        // it beside the version matrix -- so coverage questions (search, the
        // release matrix) never unpack a package to answer.
        using var root = new TempRoot();
        var module = root["demo-sweep"];
        var registry = root["registry"];
        CliRun.Run("mod", "init", "demo-sweep", "--path", module);
        Author(module, "1.0.0", "payload-v1");
        var toml = File.ReadAllText(Path.Combine(module, "rod-module.toml"))
            .Replace("techniques = []", "techniques = [\"T1615\"]") + """
            [[verbs]]
            name = "demo-sweep.deep"
            version = "0.2.0"
            techniques = ["T1615"]
            """;
        File.WriteAllText(Path.Combine(module, "rod-module.toml"), toml);

        var publish = CliRun.Run("mod", "publish", "--path", module, "--registry", registry);
        Assert.True(publish.Code == 0, publish.Error);

        // The index entry carries the row's techniques beside the version matrix.
        var entry = Rod.Packaging.RegistryJson.LoadEntry(
            Path.Combine(registry, "modules", "demo-sweep.json"));
        var row = Assert.Single(
            entry!.Versions.Single(v => v.Version == "1.0.0").Verbs!,
            v => v.Name == "demo-sweep.deep");
        Assert.Equal(new[] { "T1615" }, row.Techniques);

        // Search answers a technique query, and info shows the ids on the row.
        Assert.Contains("demo-sweep", CliRun.Run("mod", "search", "T1615", "--registry", registry).Output);
        var info = CliRun.Run("mod", "info", "demo-sweep", "--registry", registry);
        Assert.Contains("demo-sweep.deep@0.2.0 [T1615]", info.Output);
    }

    [Fact]
    public void CapabilityRequirementsAndConformance_RideTheChain()
    {
        // ADR-017's compatibility collapse: a plugin's requires rows and a
        // build unit's conformance report ride the scaffold, the signed
        // canonical form, the registry mirror, info, and install -- and a
        // tampered requirement in the installed tree reads as a trust
        // failure exactly like a tampered payload byte.
        using var root = new TempRoot();
        var plugin = root["demo-sweep"];
        var unit = root["demo-agent"];
        var registry = root["registry"];
        var install = root["install"];

        // A paired module whose execution half is a plugin: it requires the
        // loader plus the bulk-output tier its sweep returns.
        CliRun.Run("mod", "init", "demo-sweep", "--path", plugin);
        Author(plugin, "1.0.0", "payload-v1");
        var pluginToml = File.ReadAllText(Path.Combine(plugin, "rod-module.toml"))
            .Replace("# requires = [\"plugin-loader/exec-v1\"]", "requires = [\"plugin-loader/exec-v1\", \"exfil-chunks\"]");
        File.WriteAllText(Path.Combine(plugin, "rod-module.toml"), pluginToml);
        var publish = CliRun.Run("mod", "publish", "--path", plugin, "--registry", registry);
        Assert.True(publish.Code == 0, publish.Error);

        // The index mirrors the requirement set beside the target matrix.
        var entry = Rod.Packaging.RegistryJson.LoadEntry(
            Path.Combine(registry, "modules", "demo-sweep.json"));
        Assert.Equal(["plugin-loader/exec-v1", "exfil-chunks"],
            entry!.Versions.Single(v => v.Version == "1.0.0").Compatibility.Requires);

        // The catalog surfaces it, and install repeats it as the advisory it
        // is (the target's handshake advertisement is the runtime truth).
        var info = CliRun.Run("mod", "info", "demo-sweep", "--registry", registry);
        Assert.Contains("requires on the target: plugin-loader/exec-v1 exfil-chunks", info.Output);
        Assert.Contains("plugin-loader/exec-v1", CliRun.Run("mod", "search", "exfil-chunks", "--registry", registry).Output);

        var pluginInstall = CliRun.Run("mod", "install", "demo-sweep", "--registry", registry,
            "--dir", install, "--teamserver", "1.0.0");
        Assert.True(pluginInstall.Code == 0, pluginInstall.Error);
        Assert.Contains("requires on the target implant: plugin-loader/exec-v1, exfil-chunks", pluginInstall.Output);

        // A build unit carries the conformance report instead: what its
        // candidate proved against the harness.
        CliRun.Run("mod", "init", "demo-agent", "--path", unit, "--entry", "build-unit");
        Author(unit, "0.1.0", "payload");
        var unitToml = File.ReadAllText(Path.Combine(unit, "rod-module.toml")) + """

            [conformance]
            tier = 1
            harness = "1.0.0"
            date = "2026-01-15"
            clauses = ["enroll.public-key-and-token", "handshake.first-frame-ok", "task.round-trip", "signature.verification"]
            """;
        File.WriteAllText(Path.Combine(unit, "rod-module.toml"), unitToml);
        var unitPublish = CliRun.Run("mod", "publish", "--path", unit, "--registry", registry);
        Assert.True(unitPublish.Code == 0, unitPublish.Error);

        var unitEntry = Rod.Packaging.RegistryJson.LoadEntry(
            Path.Combine(registry, "modules", "demo-agent.json"));
        var report = unitEntry!.Versions[0].Conformance;
        Assert.NotNull(report);
        Assert.Equal(1, report!.Tier);
        Assert.Equal(4, report.Clauses.Count);

        var unitInfo = CliRun.Run("mod", "info", "demo-agent", "--registry", registry);
        Assert.Contains("conformance: Tier 1 (harness 1.0.0, 2026-01-15)", unitInfo.Output);
        Assert.Contains("signature.verification", unitInfo.Output);

        var unitInstall = CliRun.Run("mod", "install", "demo-agent", "--registry", registry,
            "--dir", install, "--teamserver", "1.0.0");
        Assert.True(unitInstall.Code == 0, unitInstall.Error);
        Assert.Contains("conformance: Tier 1", unitInstall.Output);

        // A tampered requirement breaks the canonical form and therefore the
        // signature: exit 2, the trust failure.
        var installedManifest = Path.Combine(install, "modules", "demo-sweep", "1.0.0", "rod-module.toml");
        File.WriteAllText(installedManifest,
            File.ReadAllText(installedManifest).Replace("requires = [\"plugin-loader/exec-v1\", \"exfil-chunks\"]", "requires = []"));
        var tampered = CliRun.Run("mod", "verify", "--dir", install);
        Assert.Equal(RodCli.ExitTrustFailure, tampered.Code);
        Assert.Contains("FAIL demo-sweep@1.0.0", tampered.Output);
    }

    [Fact]
    public void PluginPackages_MirrorTheirArtifactsIntoTheIndex()
    {
        // ADR-020's packaging half: the scaffold's sample artifact row rides
        // the manifest, the placeholder binary rides the package, and the
        // index mirrors platform/arch/path/abi so the server-side browser
        // answers "which loaders does this plugin ride" without unpacking.
        using var root = new TempRoot();
        var plugin = root["demo-plugin"];
        var registry = root["registry"];
        CliRun.Run("mod", "init", "demo-plugin", "--path", plugin, "--entry", "plugin");
        Author(plugin, "1.0.0", payload: null);
        var publish = CliRun.Run("mod", "publish", "--path", plugin, "--registry", registry);
        Assert.True(publish.Code == 0, publish.Error);

        var entry = Rod.Packaging.RegistryJson.LoadEntry(
            Path.Combine(registry, "modules", "demo-plugin.json"));
        var version = entry!.Versions.Single(v => v.Version == "1.0.0");
        var artifact = Assert.Single(version.PluginArtifacts!);
        Assert.Equal("linux", artifact.Platform);
        Assert.Equal("amd64", artifact.Arch);
        Assert.Equal("plugin/demo-plugin-linux-amd64", artifact.Path);
        Assert.Equal("exec-v1", artifact.Abi);
        Assert.Equal(["plugin-loader/exec-v1"], version.Compatibility.Requires);

        // The all-entries roll-up the https browser reads (ADR-023).
        var rollUp = System.Text.Json.JsonSerializer.Deserialize<string[]>(
            File.ReadAllText(Path.Combine(registry, "modules", "registry.json")))
            ?? [];
        Assert.Contains("demo-plugin", rollUp);

        // A reserved ABI is a refusal: nothing ships a loader for it yet.
        var manifestPath = Path.Combine(plugin, "rod-module.toml");
        File.WriteAllText(manifestPath,
            File.ReadAllText(manifestPath).Replace("abi = \"exec-v1\"", "abi = \"coff-v1\"")
                .Replace("plugin-loader/exec-v1", "plugin-loader/coff-v1"));
        var reserved = CliRun.Run("mod", "publish", "--path", plugin, "--registry", registry);
        Assert.Equal(RodCli.ExitUsage, reserved.Code);
        Assert.Contains("reserved", reserved.Error);
    }

    private static void Author(string module, string version, string? payload, string teamserver = "1.0.0", string? description = null)
    {
        // Regex edits rather than Replace(): the scaffold fills version and
        // description itself, so later authoring passes see lines the naive
        // Replace() patterns no longer match.
        var toml = File.ReadAllText(Path.Combine(module, "rod-module.toml"));
        toml = System.Text.RegularExpressions.Regex.Replace(toml, @"^version = .*$", $"version = \"{version}\"", System.Text.RegularExpressions.RegexOptions.Multiline);
        toml = System.Text.RegularExpressions.Regex.Replace(toml, @"^teamserver = .*$", $"teamserver = \"{teamserver}\"", System.Text.RegularExpressions.RegexOptions.Multiline);
        toml = System.Text.RegularExpressions.Regex.Replace(toml, @"^description = .*$", $"description = \"{description ?? "A test module."}\"", System.Text.RegularExpressions.RegexOptions.Multiline);
        toml = toml.Replace("license = \"UNLICENSED\"", "license = \"MIT\"");
        File.WriteAllText(Path.Combine(module, "rod-module.toml"), toml);
        if (payload is not null)
        {
            Directory.CreateDirectory(Path.Combine(module, "src"));
            File.WriteAllText(Path.Combine(module, "src", "payload.cs"), payload);
        }
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, file);
            var target = Path.Combine(destination, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }
    }
}
