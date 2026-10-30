using Rod.Cli.Commands;
using Rod.Packaging;

namespace Rod.Cli;

/// <summary>
/// The <c>rod mod</c> verb table. Every verb is a static command class
/// taking the parsed options, the output writer, and returning an exit
/// code -- the shape that keeps the suite testable in-process (the tests
/// drive the same entry the binary does).
/// </summary>
public static class ModCommand
{
    private static readonly IReadOnlyDictionary<string, Func<string[], TextWriter, TextWriter, Task<int>>> Verbs =
        new Dictionary<string, Func<string[], TextWriter, TextWriter, Task<int>>>(StringComparer.Ordinal)
        {
            ["init"] = (args, output, _) => Task.FromResult(InitCommand.Run(args, output)),
            ["search"] = (args, output, _) => Task.FromResult(SearchCommand.Run(args, output)),
            ["info"] = (args, output, _) => Task.FromResult(InfoCommand.Run(args, output)),
            ["install"] = (args, output, error) => InstallCommand.Run(args, output, error),
            ["verify"] = (args, output, _) => Task.FromResult(VerifyCommand.Run(args, output)),
            ["publish"] = (args, output, _) => PublishCommand.Run(args, output),
            ["coverage"] = (args, output, _) => Task.FromResult(CoverageCommand.Run(args, output)),
        };

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
        {
            foreach (var (verb, _) in Verbs)
                output.WriteLine($"  {verb,-20} {VerbHelp[verb]}");
            output.WriteLine();
            output.WriteLine("usage: rod mod <verb> [options] -- 'rod mod help <verb>' for details.");
            return args.Length == 0 ? RodCli.ExitUsage : RodCli.ExitOk;
        }

        if (args[0] == "help" && args.Length > 1 && VerbHelp.ContainsKey("help:" + args[1]))
        {
            output.WriteLine(VerbHelp["help:" + args[1]]);
            return RodCli.ExitOk;
        }

        if (!Verbs.TryGetValue(args[0], out var runner))
        {
            error.WriteLine($"unknown mod verb '{args[0]}'; 'rod mod help' lists them.");
            return RodCli.ExitUsage;
        }

        return await runner(args[1..], output, error);
    }

    private static readonly IReadOnlyDictionary<string, string> VerbHelp = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["init"] = "scaffold a module repository: manifest, template source, signing key",
        ["search"] = "search the registry by name, description, or ATT&CK technique",
        ["info"] = "show a module's registry entry, all versions",
        ["install"] = "fetch, verify, and install name@version; pin it in the lock file",
        ["verify"] = "re-verify every installed module against the lock file",
        ["publish"] = "package and sign the module; write a registry entry for a pull request",
        ["coverage"] = "render the ATT&CK coverage matrix a module tree's declarations produce",
        ["help:init"] = """
            rod mod init <name> [--path <dir>] [--entry server|implant|build-unit]
                         [--license <spdx>] [--teamserver <version>]

            Scaffolds a module repository: rod-module.toml with honest defaults,
            template source for the entry kind, .gitignore, and an Ed25519
            signing keypair (rod-module.key / rod-module.pub). Keep the secret
            key; a new one is a new publisher identity.
            """,
        ["help:search"] = """
            rod mod search [term] [--registry <dir|url>] [--json]

            Lists registry modules matching term (name, description, or ATT&CK
            technique); no term lists all. OPSEC marks show beside each result.
            """,
        ["help:info"] = """
            rod mod info <name>[@version] [--registry <dir|url>]

            Shows a module's catalog metadata and every indexed version with
            its digest and key fingerprint. No version picks the latest.
            """,
        ["help:install"] = """
            rod mod install <name>[@version] [--registry <dir|url>] [--dir <root>]
                            [--teamserver <version>] [--force]

            Downloads the package, checks its digest and the publisher's
            signature over the manifest's canonical form, checks the
            compatibility floor, and installs under <root>/modules/<name>/<version>.
            First install of a name pins its key in rod.modules.lock.json; a
            later version under a different key fails. --force reinstalls.
            """,
        ["help:verify"] = """
            rod mod verify [--dir <root>]

            Re-proves every installed module against the lock file -- no
            network, no registry: files re-hashed, canonical form re-signed,
            signature re-checked. Exit code 2 on any failure.
            """,
        ["help:publish"] = """
            rod mod publish [--path <module-dir>] [--registry <registry-dir>]
                            [--key <key-file>] [--out <dist-dir>]

            Packs the module per rod-module.toml's rules (default: everything
            except bin/obj/dist and key material), signs the canonical form,
            writes dist/<name>-<version>.zip plus the version's index-entry
            JSON, and --registry writes it into a local rod-registry checkout
            (commit and open the pull request yourself). Publish refuses
            UNLICENSED and any version already indexed with a different digest.
            """,
        ["help:coverage"] = """
            rod mod coverage [--path <dir>] [--catalog <attack-coverage.json>] [--json]

            Sweeps a tree for module manifests, validates every one, and
            renders the ATT&CK coverage matrix their verb declarations
            produce (markdown by default, --json machine-readable). With
            --catalog the kernel's own verb mapping folds in, names and
            tactics come from the catalog, and the output stamps the ATT&CK
            version; a technique the catalog lacks renders by id alone --
            coverage advances without a kernel edit. An invalid manifest
            fails the sweep.
            """,
    };
}
