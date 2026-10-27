using Rod.Cli.Manifest;
using Rod.Cli.Signing;

namespace Rod.Cli.Commands;

/// <summary>
/// <c>rod mod init</c>: the template repository (architecture.md Sec 15.2)
/// -- a manifest with honest defaults, entry-kind source to copy from, and
/// the publisher's Ed25519 keypair. The scaffold is the contribution
/// threshold: one directory, one manifest, one key, and <c>rod mod
/// publish</c> does the rest.
/// </summary>
public static class InitCommand
{
    public static int Run(string[] args, TextWriter output)
    {
        var parsed = ParsedArgs.Parse(args,
            valueOptions: new HashSet<string> { "path", "entry", "license", "teamserver" },
            flags: new HashSet<string>(),
            command: "mod init");

        if (parsed.Positional.Count != 1)
            throw new CliError("rod mod init needs a module name.");
        var name = parsed.Positional[0];

        if (!ModuleManifest.ValidName(name))
            throw new CliError($"module name '{name}' must be kebab-case: lowercase letters, digits, hyphens, at most 64 characters.");

        var entry = ModuleEntryKind.Server;
        if (parsed.Has("entry") && !ModuleEntryKindNames.TryParse(parsed.Require("entry", "entry kind"), out entry))
            throw new CliError("--entry must be server, implant, build-unit, or assets.");

        var directory = parsed.Value("path") ?? name;
        if (File.Exists(Path.Combine(directory, ManifestToml.FileName)))
            throw new CliError($"'{directory}' already carries a {ManifestToml.FileName}.");

        // The compatibility floor defaults to this CLI's platform version
        // (it ships with the tree), so a scaffold is installable against
        // the teamserver generation it was written on.
        SemVer.TryParse(BuildStamp.Version, out var stamped);
        var floor = SemVer.TryParse(parsed.Value("teamserver") ?? "", out var requested)
            ? requested
            : stamped with { Prerelease = null };

        var license = parsed.Value("license") ?? "UNLICENSED";
        Directory.CreateDirectory(directory);

        var manifest = ManifestToml.RenderTemplate(
            name,
            new SemVer(0, 1, 0, null),
            entry,
            license,
            floor,
            landsOnDisk: true,
            description: $"One line on what {name} does.");
        File.WriteAllText(Path.Combine(directory, ManifestToml.FileName), manifest);
        ScaffoldSource(directory, name, entry);
        WriteReadme(directory, name, entry);
        EnsureGitignore(directory);

        if (!File.Exists(Path.Combine(directory, KeyFiles.SecretFileName)))
        {
            var pair = KeyFiles.Generate(directory);
            output.WriteLine($"signing key generated: {KeyFiles.PublicFileName} ({Ed25519.Fingerprint(pair.PublicKey)}), secret in {KeyFiles.SecretFileName} -- keep it.");
        }
        else
        {
            output.WriteLine("existing signing key reused.");
        }

        output.WriteLine($"module scaffolded: {directory} (entry {ModuleEntryKindNames.ToString(entry)})");
        output.WriteLine($"next: fill in {ManifestToml.FileName}, set a real license, then 'rod mod publish'.");
        return RodCli.ExitOk;
    }

    private static void ScaffoldSource(string directory, string name, ModuleEntryKind entry)
    {
        var pascal = string.Concat(name.Split('-').Select(s => s.Length == 0 ? "" : char.ToUpperInvariant(s[0]) + s[1..]));
        switch (entry)
        {
            case ModuleEntryKind.Server:
                // Zero code by design (ADR-018): a server-entry module's
                // whole half is the manifest's descriptor rows -- category,
                // OPSEC flags, the parameter schema, the output kind -- so
                // the scaffold carries no source to compile. An author who
                // wants a .NET assembly instead writes it against the
                // Rod.Capabilities contract and lists the type under
                // Capabilities:Modules; the manifest rows stay the packaging
                // truth either way.
                break;
            case ModuleEntryKind.Implant:
                {
                    var source = Path.Combine(directory, "src");
                    Directory.CreateDirectory(source);
                    File.WriteAllText(Path.Combine(source, "plugin.rs"), $$"""
                    // The implant-side half of {{name}}: a plugin module built against the
                    // rod-plugin-sdk crate (cargo new --lib, then depend on it). See the
                    // upstream module guide for the loader contract this compiles into.
                    //
                    // use rod_plugin_sdk::{rod_plugin, Plugin, Verb};
                    //
                    // pub struct {{pascal}};
                    //
                    // impl Plugin for {{pascal}} {
                    //     fn name(&self) -> &'static str { "{{name}}" }
                    //     fn verbs(&self) -> Vec<Verb> {
                    //         vec![Verb::new("{{name}}.run", run)]
                    //     }
                    // }
                    //
                    // fn run(arguments: &str) -> Result<String, String> {
                    //     Ok(arguments.to_string())
                    // }
                    //
                    // rod_plugin!({{pascal}});
                    """);
                    break;
                }
            case ModuleEntryKind.BuildUnit:
                {
                    var source = Path.Combine(directory, "src");
                    Directory.CreateDirectory(source);
                    File.WriteAllText(Path.Combine(source, "README.md"), $"""
                    # {name} -- build unit

                    A build unit compiles implants of its language through the uniform
                    build contract (architecture.md Sec 6): the teamserver drives it as
                    an external tool with hermetic staging and a baked profile, and
                    the wire protocol -- not the teamserver's language -- is the contract.

                    Implement the contract against the version pinned in
                    rod-module.toml's compatibility floor, and register the unit with
                    the teamserver's build configuration.
                    """);
                    break;
                }
            case ModuleEntryKind.Assets:
                {
                    // Pure content, no code: the scaffold's one asset is the
                    // worked example of the file shape each consumer contract
                    // documents (the teamserver's asset host serves the bytes;
                    // what the bytes mean is the consumer's contract, never
                    // the CLI's).
                    Directory.CreateDirectory(Path.Combine(directory, "assets"));
                    File.WriteAllText(Path.Combine(directory, "assets", $"{name}.txt"), $"""
                    Subject: One line the consumer reads as the subject

                    The body is everything after the first blank line; this scaffold
                    carries no consumer contract -- replace it with the file shape
                    your consumer documents (modules.md, "Asset modules").
                    """);
                    break;
                }
        }
    }

    private static void WriteReadme(string directory, string name, ModuleEntryKind entry)
    {
        File.WriteAllText(Path.Combine(directory, "README.md"), $"""
            # {name}

            A Rod capability module (entry kind: {ModuleEntryKindNames.ToString(entry)}).
            The manifest `rod-module.toml` is the contract: fill in honest OPSEC
            metadata and the ATT&CK techniques this module covers -- both ride the
            signed canonical form and the registry catalog.

            Publish with `rod mod publish`; the output `dist/` carries the package
            and the registry entry for a pull request against rod-registry.
            """);
    }

    private static void EnsureGitignore(string directory)
    {
        var path = Path.Combine(directory, ".gitignore");
        var existing = File.Exists(path)
            ? File.ReadAllLines(path).Where(l => l.Trim().Length > 0).ToList()
            : [];
        foreach (var line in new[] { "dist/", KeyFiles.SecretFileName, "*.key" })
            if (!existing.Contains(line, StringComparer.Ordinal))
                existing.Add(line);
        File.WriteAllText(path, string.Join("\n", existing) + "\n");
    }
}
