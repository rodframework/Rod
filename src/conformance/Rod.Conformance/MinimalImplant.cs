namespace Rod.Conformance;

/// <summary>
/// The deliberate defects the harness's minimal implant can carry. Each one
/// breaks exactly one contract clause; the rest of the implementation stays
/// conforming, so a failing clause is attributable to its defect and the
/// harness names it. The names are shared surface: the runner's
/// <c>--defect</c> and the example implant's <c>ROD_DEFECTS</c> both speak
/// them, so a broken run can be reproduced from either side.
/// </summary>
public sealed record ImplantDefects(
    bool SkipSignatureVerification = false,
    bool SpeakHandshakeSecond = false,
    bool ScrambleChunkSequences = false)
{
    /// <summary>The kebab-case name of every switchable defect.</summary>
    public static readonly string[] Names =
        ["skip-signature-verification", "speak-handshake-second", "scramble-chunk-sequences"];

    /// <summary>
    /// Maps defect names onto the switches; an unknown name refuses rather
    /// than silently meaning "unbroken".
    /// </summary>
    public static bool TryParse(
        IEnumerable<string> names, out ImplantDefects defects, out string? unknown)
    {
        var switches = names.ToHashSet(StringComparer.Ordinal);
        unknown = switches.FirstOrDefault(name => !Names.Contains(name));
        if (unknown is not null)
        {
            defects = new ImplantDefects();
            return false;
        }
        defects = new ImplantDefects(
            SkipSignatureVerification: switches.Contains(Names[0]),
            SpeakHandshakeSecond: switches.Contains(Names[1]),
            ScrambleChunkSequences: switches.Contains(Names[2]));
        return true;
    }
}

/// <summary>
/// A minimal Tier 0/Tier 1 implant written straight from the contract doc,
/// in-process so the harness can switch defects on and off: ECDSA P-256
/// enroll, the plain-HTTP envelope contact (one POST per poll cycle, the
/// plaintext lab posture), canonical tasking-signature verification,
/// shell.exec execution, and chunked file.pull exfil. The deliberately
/// broken candidates the acceptance criterion names are this implant with
/// one defect flipped on. The wire behavior lives in
/// <see cref="MinimalImplantLoop"/>; the example implant a process-mode run
/// spawns (<c>rod-minimal-implant</c>) runs the same loop from environment.
/// </summary>
public sealed class MinimalImplant(ImplantDefects defects) : IImplantCandidate
{
    private readonly ImplantDefects _defects = defects;
    private CancellationTokenSource? _running;
    private Task? _loop;

    public bool HasExited => _loop is null || _loop.IsCompleted;

    public Task StartAsync(ConformanceTarget target)
    {
        if (_running is not null)
            throw new InvalidOperationException("The candidate is already running.");
        _running = new CancellationTokenSource();
        // A fresh loop per phase: each phase enrolls a fresh identity, so the
        // replay-nonce floor and the negotiation arm start over with it.
        _loop = Task.Run(() => new MinimalImplantLoop(_defects).RunAsync(target, _running.Token));
        return Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        _running?.Cancel();
        if (_loop is not null)
        {
            try
            {
                await _loop;
            }
            catch (OperationCanceledException)
            {
            }
            catch (HttpRequestException)
            {
                // A failed contact surfaces here; the stop is the intent.
            }
        }
        _loop = null;
        _running = null;
    }

    public void Dispose()
    {
    }
}
