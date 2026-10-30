using System.Net;

namespace Rod.Redirector;

// Carries the single forwarding rule the reference redirector runs with
// (architecture.md Sec 8, ADR 0011). The full design lets an operator run one
// process per fronted port -- near-stateless, cheap, and more robust than one
// process holding several listeners (a burned port does not drag the others
// down) -- so a single rule covers the canonical "one redirector fronts one
// listener" deployment. Multi-port fronting is one process per port, not one
// rule list here.

/// <summary>
/// Everything the reference redirector needs to forward one TCP endpoint to an
/// upstream teamserver listener. Mirrors the implant's hand-rolled config.Config:
/// flags win over the matching ROD_* env, required fields that stay empty after
/// both are rejected with a usage error, and -h prints usage and exits.
/// </summary>
internal sealed class RedirectorConfig
{
    /// <summary>
    /// The bind host (a literal IP, or "*" / "0.0.0.0" / "::" for any). DNS
    /// hostnames are not supported for the bind side -- a bind needs an interface
    /// address -- so a name is rejected at validation. See <see cref="ListenAddress"/>.
    /// </summary>
    public string ListenHost { get; private set; } = string.Empty;

    /// <summary>The TCP port to listen on.</summary>
    public int ListenPort { get; private set; }

    /// <summary>
    /// The upstream host (DNS name or literal IP) the redirector splices to --
    /// typically the teamserver listener's bind address.
    /// </summary>
    public string UpstreamHost { get; private set; } = string.Empty;

    /// <summary>The upstream TCP port to splice to.</summary>
    public int UpstreamPort { get; private set; }

    /// <summary>
    /// The source-IP allow-list. Empty (the default) allows every source: the
    /// redirector is typically fronted by a VPS firewall and the real identity
    /// gate is the teamserver's mTLS handshake (architecture.md Sec 9), so the
    /// allow-list is a deployment-time tightening, not the security boundary.
    /// </summary>
    public CidrAllowList Allow { get; private set; } = CidrAllowList.AllowAll;

    /// <summary>
    /// The control channel's WebSocket URL (architecture.md Sec 8) -- the
    /// enrolled mode's dial-home target on the teamserver's shared tier.
    /// Present selects enrolled mode; absent keeps the manual single rule.
    /// </summary>
    public string? ControlUri { get; private set; }

    /// <summary>
    /// The enrollment credential (enroll-once, single-use): presented the
    /// first time only -- afterwards the identity persisted in the state
    /// file reconnects.
    /// </summary>
    public string? Credential { get; private set; }

    /// <summary>
    /// Where the enrolled identity lives. Default: beside the working
    /// directory. The file is the credential (it carries the node secret).
    /// </summary>
    public string StatePath { get; private set; } = "rod-redirector.state.json";

    /// <summary>True when the config selects the enrolled (control-plane) mode.</summary>
    public bool HasControl => ControlUri is not null;

    /// <summary>
    /// The resolved bind address. "*" / "0.0.0.0" resolve to IPv4 any, "::" /
    /// "::0" to IPv6 any; any other value must parse as a literal IP address (a
    /// DNS hostname here is a config error -- the bind side needs an address).
    /// </summary>
    public IPAddress ListenAddress =>
        ListenHost is "*" or "0.0.0.0" ? IPAddress.Any
        : ListenHost is "::" or "::0" ? IPAddress.IPv6Any
        : IPAddress.Parse(ListenHost);

    /// <summary>
    /// Builds a RedirectorConfig from command-line flags, falling back to the
    /// matching ROD_* environment variable for each. Flags win over env. Required
    /// fields that are still empty after both are rejected with a usage error.
    /// </summary>
    public static RedirectorConfig Parse(string[] args)
    {
        var config = new RedirectorConfig
        {
            ListenHost = Env("ROD_LISTEN", null) ?? string.Empty,
            UpstreamHost = Env("ROD_UPSTREAM", null) ?? string.Empty,
            ControlUri = Env("ROD_CONTROL", null),
            Credential = Env("ROD_CREDENTIAL", null),
            StatePath = Env("ROD_STATE", null) ?? "rod-redirector.state.json",
        };
        var allowRaw = Env("ROD_ALLOW", string.Empty) ?? string.Empty;

        // Hand-rolled parse: no System.CommandLine dependency, matching the
        // "no ceremony" style of the implant's flag set. Each flag takes the next
        // arg as its value; -h prints usage and exits with code 2.
        for (var i = 0; i < args.Length; i++)
        {
            var flag = args[i];
            switch (flag)
            {
                case "-h":
                case "--help":
                    Console.Error.WriteLine(Usage);
                    throw new ExitProgramException(2);
                case "-version":
                case "--version":
                    // The stamp is the answer to "which tree is this binary
                    // from?"; stdout (not stderr) so a runbook can pipe it.
                    Console.Out.WriteLine(
                        $"rod-redirector {BuildStamp.Version} (commit {BuildStamp.SourceCommit})");
                    throw new ExitProgramException(0);
                case "-listen":
                case "--listen":
                    config.ListenHost = TakeValue(args, ref i, flag);
                    break;
                case "-upstream":
                case "--upstream":
                    config.UpstreamHost = TakeValue(args, ref i, flag);
                    break;
                case "-allow":
                case "--allow":
                    allowRaw = TakeValue(args, ref i, flag);
                    break;
                case "-control":
                case "--control":
                    config.ControlUri = TakeValue(args, ref i, flag);
                    break;
                case "-credential":
                case "--credential":
                    config.Credential = TakeValue(args, ref i, flag);
                    break;
                case "-state":
                case "--state":
                    config.StatePath = TakeValue(args, ref i, flag);
                    break;
                default:
                    throw new ExitProgramException(2, $"unknown flag: {flag}\n{Usage}");
            }
        }

        try
        {
            config.Allow = CidrAllowList.Parse(allowRaw.Length == 0 ? null : new[] { allowRaw });
        }
        catch (ArgumentException ex)
        {
            throw new ExitProgramException(2, $"-allow: {ex.Message}\n{Usage}");
        }

        config.Validate();
        return config;
    }

    /// <summary>
    /// Enforces the mode split: the enrolled mode names the control URL and
    /// nothing else (rules arrive from the control plane), the manual mode
    /// names listen and upstream and no control URL. Mixing the two is a
    /// usage error -- a manual rule beside pushed rules would read as
    /// engagement plumbing the operator never attached.
    /// </summary>
    private void Validate()
    {
        if (ControlUri is not null)
        {
            var manual = new List<string>();
            if (ListenHost.Length > 0)
                manual.Add("-listen");
            if (UpstreamHost.Length > 0)
                manual.Add("-upstream");
            if (manual.Count > 0)
                throw new ExitProgramException(2,
                    $"enrolled mode (-control) takes no manual flags: {string.Join(", ", manual)}\n{Usage}");
            if (!Uri.TryCreate(ControlUri, UriKind.Absolute, out var uri))
            {
                throw new ExitProgramException(2, $"-control: '{ControlUri}' is not a URL\n{Usage}");
            }

            if (uri.Scheme != "ws" && uri.Scheme != "wss")
            {
                throw new ExitProgramException(2,
                    $"-control: '{ControlUri}' is not a ws:// or wss:// URL\n{Usage}");
            }

            return;
        }

        var missing = new List<string>();
        if (ListenHost.Length == 0)
            missing.Add("-listen/ROD_LISTEN");
        if (UpstreamHost.Length == 0)
            missing.Add("-upstream/ROD_UPSTREAM");
        if (missing.Count > 0)
            throw new ExitProgramException(2, $"missing required config: {string.Join(", ", missing)}\n{Usage}");

        (ListenHost, ListenPort) = SplitHostPort(ListenHost, "listen");
        (UpstreamHost, UpstreamPort) = SplitHostPort(UpstreamHost, "upstream");

        try
        {
            _ = ListenAddress;
        }
        catch (FormatException)
        {
            throw new ExitProgramException(
                2, $"listen: '{ListenHost}' is not a bindable IP address (use * for any)\n{Usage}");
        }
    }

    // Splits "host:port" into host and port. IPv6 literals must be bracketed
    // ([::1]:443) so the trailing :port is unambiguous; a bare IPv6 literal with
    // colons would otherwise split wrong.
    private static (string Host, int Port) SplitHostPort(string raw, string field)
    {
        if (raw.StartsWith('['))
        {
            var close = raw.IndexOf(']');
            if (close < 0 || close + 1 >= raw.Length || raw[close + 1] != ':')
                throw new ExitProgramException(2, $"{field}: '{raw}' is not [host]:port\n{Usage}");
            var host = raw[1..close];
            var port = ParsePort(raw[(close + 2)..], field);
            return (host, port);
        }

        var colon = raw.LastIndexOf(':');
        if (colon <= 0 || colon == raw.Length - 1)
            throw new ExitProgramException(2, $"{field}: '{raw}' is not host:port\n{Usage}");
        return (raw[..colon], ParsePort(raw[(colon + 1)..], field));
    }

    private static int ParsePort(string text, string field)
    {
        if (!int.TryParse(text, out var port) || port < 1 || port > 65535)
            throw new ExitProgramException(2, $"{field}: '{text}' is not a valid port\n{Usage}");
        return port;
    }

    private const string Usage = """
        usage: rod-redirector [flags]

        Manual mode (one hand-configured rule):

          -listen string    bind endpoint (host:port; host may be * for any, or a literal IP)
          -upstream string  teamserver listener endpoint (host:port; host may be a DNS name)
          -allow string     optional comma-separated source CIDR allow-list (e.g. 10.0.0.0/8)

        Enrolled mode (rules arrive from the teamserver's control plane,
        architecture.md Sec 8):

          -control string   control channel URL (ws:// or wss://) on the teamserver's
                            shared tier, e.g. wss://teamserver:59443/redirectors/control
          -credential string  enrollment credential, presented once; the minted node
                            identity persists in the state file and reconnects after
          -state string     where the node identity lives (default rod-redirector.state.json)

          -version          print version and source commit, then exit

        Each flag falls back to the matching ROD_LISTEN / ROD_UPSTREAM / ROD_ALLOW /
        ROD_CONTROL / ROD_CREDENTIAL / ROD_STATE environment variable. The redirector
        forwards opaque bytes and never terminates transport; swap a burned
        redirector by deploying a fresh one and repointing the listener.
        """;

    private static string? Env(string key, string? fallback)
        => Environment.GetEnvironmentVariable(key) is { Length: > 0 } v ? v : fallback;

    // Returns the value for the flag at index i, advancing i past it. Throws a
    // usage error when the flag has no following value.
    private static string TakeValue(string[] args, ref int i, string flag)
    {
        if (i + 1 >= args.Length)
            throw new ExitProgramException(2, $"flag needs an argument: {flag}\n{Usage}");
        i++;
        return args[i];
    }
}

/// <summary>
/// Thrown to request a clean exit with a specific code and message (usage error
/// or -h). The program's top level catches it, prints the message, and exits.
/// Mirrors the implant's ExitProgramException so the two binaries behave the same
/// way on a bad flag.
/// </summary>
internal sealed class ExitProgramException : Exception
{
    public int ExitCode { get; }

    // Tracks whether the caller supplied an explicit message. The base Message
    // property returns the type name when none was set, which the caller would
    // then print as noise; HasMessage lets "-h already printed usage" paths pass
    // null and stay quiet.
    public bool HasMessage { get; }
    public override string Message => HasMessage ? base.Message : string.Empty;

    public ExitProgramException(int exitCode, string? message = null)
        : base(message)
    {
        ExitCode = exitCode;
        HasMessage = message is not null;
    }
}
