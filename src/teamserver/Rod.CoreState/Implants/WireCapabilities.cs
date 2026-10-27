namespace Rod.CoreState.Implants;

/// <summary>
/// The wire capability names a module's requirement rows draw from
/// (architecture.md Sec 15.2, ADR-017): a plugin declares what the hosting
/// implant must support, and the runtime half of the collapse checks the
/// declaration against the session's handshake advertisement (Sec 5.4 -- the
/// advertisement is the truth the static rows approximate). A closed
/// vocabulary shared by two sides of a file contract: the module manifest's
/// <c>compatibility.requires</c> names (parsed by the <c>rod</c> CLI, which
/// references nothing in-house) and this runtime gate each state it, and the
/// CLI test suite pins the two statements equal so one cannot drift.
/// </summary>
/// <remarks>
/// The names are the wire tiers' own features (extending/implants.md, Tier
/// 2): they grow additively with the tiers, and an unknown name is a refused
/// manifest or a refused module registration -- never a silent mismatch.
/// </remarks>
public static class WireCapabilities
{
    /// <summary>
    /// The <c>module.load</c> family (architecture.md Sec 5.4): the implant
    /// half hosts plugins. Covered by a session advertising the family's
    /// loading verb.
    /// </summary>
    public const string PluginLoader = "plugin-loader";

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
        [PluginLoader, ExfilChunks, StagedUploads];

    /// <summary>Whether <paramref name="name"/> belongs to the vocabulary.</summary>
    public static bool IsRequirable(string name)
        => Requirable.Contains(name, StringComparer.Ordinal);

    /// <summary>
    /// Whether <paramref name="advertised"/> -- a session's handshake
    /// advertisement, the verb strings the implant claims -- covers the
    /// capability <paramref name="name"/>. Each tier's task-path face is the
    /// verb whose reference handler carries its frames, so advertising the
    /// verb claims its wire shape: the loader family is its own loading verb,
    /// bulk output rides the pull verb past its inline cap, and downstream
    /// bulk rides the push verb through the staged arm. A Tier 0 build that
    /// degrades a verb's bulk arm still passes this check, and the module
    /// degrades with it at run time -- visibly, never silently.
    /// </summary>
    public static bool Covers(IEnumerable<string> advertised, string name)
    {
        var coveringVerb = name switch
        {
            PluginLoader => ModuleLoadVerb,
            ExfilChunks => FilePullVerb,
            StagedUploads => FilePushVerb,
            _ => null,
        };
        return coveringVerb is not null
            && advertised.Contains(coveringVerb, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The module family's loading verb: the task-path face of the loader the
    /// <see cref="PluginLoader"/> capability names, and the verb whose
    /// issuance the runtime requirement gate hangs on.
    /// </summary>
    public const string ModuleLoadVerb = "module.load";

    private const string FilePullVerb = "file.pull";
    private const string FilePushVerb = "file.push";
}
