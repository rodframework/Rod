namespace Rod.CoreState.Implants;

/// <summary>
/// The wire capability names a module's requirement rows draw from
/// (architecture.md Sec 15.2, ADR-017): a plugin declares what the hosting
/// implant must support, and the runtime half of the collapse checks the
/// declaration against the session's handshake advertisement (Sec 5.4 -- the
/// advertisement is the truth the static rows approximate). A closed
/// vocabulary stated by the packaging contract library (Rod.Packaging, the
/// grammar every manifest parses through) and this runtime gate; the CLI
/// test suite pins the two statements equal so one cannot drift.
/// </summary>
/// <remarks>
/// <para>
/// The names are the wire tiers' own features (extending/implants.md, Tier
/// 2): they grow additively with the tiers, and an unknown name is a refused
/// manifest or a refused module registration -- never a silent mismatch.
/// </para>
/// <para>
/// The loader family carries an ABI suffix naming the loading contract a
/// plugin's artifact was built against (ADR-020): <c>exec-v1</c> is the
/// out-of-process stdio loader, <c>native-v1</c> the in-process
/// <c>rod_plugin_*</c> C ABI, <c>coff-v1</c> the Windows COFF object
/// loader (the BOF corpus, against a Beacon-compatible host table), and
/// <c>wasm-v1</c> is reserved for a loader no reference implant ships
/// yet -- the vocabulary is the opening, the loaders land with their
/// implants.
/// </para>
/// </remarks>
public static class WireCapabilities
{
    /// <summary>The ABI family prefix: every loader capability name starts
    /// with this and an ABI id.</summary>
    public const string PluginLoaderPrefix = "plugin-loader/";

    /// <summary>
    /// The out-of-process loader ABI: the plugin half is a self-contained
    /// executable the implant runs per exchange over the stdio protocol.
    /// </summary>
    public const string PluginLoaderExec = PluginLoaderPrefix + "exec-v1";

    /// <summary>
    /// The in-process loader ABI: the plugin half is a library exporting the
    /// <c>rod_plugin_*</c> C symbol family the implant maps and calls.
    /// </summary>
    public const string PluginLoaderNative = PluginLoaderPrefix + "native-v1";

    /// <summary>
    /// The COFF/BOF loader ABI: the Windows floor loads a bare COFF object
    /// (the BOF corpus's shape) against a Beacon-compatible host table --
    /// architecture.md Sec 5.4, the loading contract extending/modules.md
    /// documents.
    /// </summary>
    public const string PluginLoaderCoff = PluginLoaderPrefix + "coff-v1";

    /// <summary>
    /// The wasm loader ABI. Reserved: no in-tree implant embeds a wasm
    /// runtime yet; the name exists so the contract can name the tier.
    /// </summary>
    public const string PluginLoaderWasm = PluginLoaderPrefix + "wasm-v1";

    /// <summary>Bulk output through <c>ExfilChunk</c> frames (Tier 2).</summary>
    public const string ExfilChunks = "exfil-chunks";

    /// <summary>
    /// Downstream bulk through the <c>StagedPull</c>/<c>StagedChunk</c> demand
    /// path (Tier 2).
    /// </summary>
    public const string StagedUploads = "staged-uploads";

    /// <summary>
    /// The names a module's requirement rows may carry. Grows additively with
    /// the wire tiers.
    /// </summary>
    public static readonly IReadOnlyList<string> Requirable =
        [PluginLoaderExec, PluginLoaderNative, PluginLoaderCoff, PluginLoaderWasm, ExfilChunks, StagedUploads];

    /// <summary>Whether <paramref name="name"/> belongs to the vocabulary.</summary>
    public static bool IsRequirable(string name)
        => Requirable.Contains(name, StringComparer.Ordinal);

    /// <summary>Whether <paramref name="name"/> names a loader ABI (any
    /// generation): the loader family's requirement rows.</summary>
    public static bool IsPluginLoaderAbi(string name)
        => name.StartsWith(PluginLoaderPrefix, StringComparison.Ordinal);

    /// <summary>
    /// Whether <paramref name="advertised"/> -- a session's handshake
    /// advertisement, the capability strings the implant claims -- covers the
    /// capability <paramref name="name"/>. The bulk tiers' task-path face is
    /// the verb whose reference handler carries their frames (advertising the
    /// verb claims the wire shape); the loader ABIs are covered by the
    /// advertisement carrying the ABI name itself (ADR-020): the implant
    /// states which loaders this build hosts -- <c>plugin-loader/exec-v1</c>
    /// beside the verbs -- so the runtime gate checks the loader a plugin
    /// needs, not merely that some loader exists. A Tier 0 build that
    /// degrades a bulk arm still passes its check, and the module degrades
    /// with it at run time -- visibly, never silently.
    /// </summary>
    public static bool Covers(IEnumerable<string> advertised, string name)
    {
        var coveringVerb = name switch
        {
            ExfilChunks => FilePullVerb,
            StagedUploads => FilePushVerb,
            _ when IsPluginLoaderAbi(name) => name,
            _ => null,
        };
        return coveringVerb is not null
            && advertised.Contains(coveringVerb, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The module family's loading verb: the task-path face of every loader
    /// ABI, and the verb whose issuance the runtime requirement gate hangs
    /// on.
    /// </summary>
    public const string ModuleLoadVerb = "module.load";

    private const string FilePullVerb = "file.pull";
    private const string FilePushVerb = "file.push";
}
