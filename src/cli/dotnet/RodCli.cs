namespace Rod.Cli;

/// <summary>
/// Command-line entry: <c>rod [--version] [help] mod &lt;verb&gt; …</c>.
/// Parsing is a hand-rolled single-dash-free grammar (long options only,
/// <c>--opt value</c> or <c>--opt=value</c>) -- the suite is six verbs
/// deep and a parser dependency would buy nothing. Exit codes carry
/// meaning to scripts: 0 success, 1 usage or input error, 2 a trust or
/// verification failure -- the one an engagement pipeline must treat as
/// red.
/// </summary>
public static class RodCli
{
    public const int ExitOk = 0;
    public const int ExitUsage = 1;
    public const int ExitTrustFailure = 2;

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error)
    {
        try
        {
            if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
            {
                PrintUsage(output);
                return args.Length == 0 ? ExitUsage : ExitOk;
            }

            if (args[0] is "--version" or "version")
            {
                output.WriteLine($"rod {BuildStamp.Version} ({BuildStamp.SourceCommit})");
                return ExitOk;
            }

            if (args[0] == "mod")
                return await ModCommand.RunAsync(args[1..], output, error);

            if (args[0] == "conform")
                return await ConformCommand.RunAsync(args[1..], output, error);

            error.WriteLine($"unknown command '{args[0]}'.");
            PrintUsage(error);
            return ExitUsage;
        }
        catch (CliError failure)
        {
            error.WriteLine($"rod: {failure.Message}");
            return failure.ExitCode;
        }
        catch (Exception failure) when (failure is InvalidOperationException or IOException
            or UnauthorizedAccessException or FormatException)
        {
            error.WriteLine($"rod: {failure.Message}");
            return ExitUsage;
        }
    }

    public static void PrintUsage(TextWriter output)
    {
        output.WriteLine("""
            rod -- the Rod operator CLI

            usage: rod mod <verb> [options]
                   rod conform <candidate> [options]

            verbs:
              init <name>          scaffold a module repository (manifest, template, signing key)
              search [term]        search the module registry
              info <name>[@ver]    show a module's registry entry
              install <name>[@ver] download, verify, and install a module
              verify               re-verify every installed module against the lock file
              publish              package and sign the module in the current directory
              coverage             render the ATT&CK coverage matrix a module tree declares

            commands:
              conform <candidate>  run the Tier 0 conformance clauses against a candidate
                                   implant binary (needs the rod-conform runner; --selftest
                                   runs the harness's own example instead)

            common options:
              --registry <dir|url>   the registry to use (default: the lock file's)
              --dir <path>           install root (default: the working directory)
              --json                 machine-readable output (search)

            'rod mod help <verb>' prints the verb's options; 'rod conform --help'
            prints the conform command's.
            """);
    }
}

/// <summary>A failure with an explicit process exit code; thrown by
/// command implementations, rendered once at the top.</summary>
public sealed class CliError(string message, int exitCode = RodCli.ExitUsage) : Exception(message)
{
    public int ExitCode { get; } = exitCode;
}

/// <summary>Parses long options against a command's declared option set:
/// value options take <c>--opt value</c> or <c>--opt=value</c>, repeatable
/// options collect every occurrence, flags stand alone. Anything else is a
/// usage error naming the offending token.</summary>
internal sealed class ParsedArgs
{
    private readonly Dictionary<string, string> _options = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<string>> _repeated = new(StringComparer.Ordinal);

    public List<string> Positional { get; } = [];

    public bool Has(string option) => _options.ContainsKey(option);

    public string? Value(string option) => _options.GetValueOrDefault(option);

    /// <summary>Every occurrence of a repeatable option, in order.</summary>
    public IReadOnlyList<string> Values(string option)
        => _repeated.GetValueOrDefault(option) ?? [];

    public string Require(string option, string what)
        => _options.TryGetValue(option, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new CliError($"{what} is required (--{option}).");

    public static ParsedArgs Parse(
        string[] args,
        IReadOnlySet<string> valueOptions,
        IReadOnlySet<string> flags,
        string command,
        IReadOnlySet<string>? repeatableOptions = null)
    {
        var parsed = new ParsedArgs();
        for (var i = 0; i < args.Length; i++)
        {
            var token = args[i];
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                parsed.Positional.Add(token);
                continue;
            }

            var body = token[2..];
            string name;
            string? inlineValue = null;
            var equals = body.IndexOf('=');
            if (equals >= 0)
            {
                name = body[..equals];
                inlineValue = body[(equals + 1)..];
            }
            else
            {
                name = body;
            }
            if (name.Length == 0)
                throw new CliError($"'rod {command}': bare '--' is not an option.");

            if (valueOptions.Contains(name))
            {
                var value = inlineValue ?? (i + 1 < args.Length ? args[++i] : null);
                if (string.IsNullOrEmpty(value))
                    throw new CliError($"'rod {command}': --{name} needs a value.");
                parsed._options[name] = value;
            }
            else if (repeatableOptions?.Contains(name) == true)
            {
                var value = inlineValue ?? (i + 1 < args.Length ? args[++i] : null);
                if (string.IsNullOrEmpty(value))
                    throw new CliError($"'rod {command}': --{name} needs a value.");
                if (!parsed._repeated.TryGetValue(name, out var occurrences))
                    parsed._repeated[name] = occurrences = [];
                occurrences.Add(value);
            }
            else if (flags.Contains(name) && inlineValue is null)
            {
                parsed._options[name] = "true";
            }
            else
            {
                throw new CliError($"'rod {command}': unknown option '--{name}'.");
            }
        }
        return parsed;
    }
}
