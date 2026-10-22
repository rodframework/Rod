namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// The build pipeline's duration record (architecture.md Sec 15.3, ADR-008):
/// what the last <see cref="Window"/> builds cost and whether they succeeded,
/// so an operator asking why artifacts are slow sees the recent distribution
/// without reading job logs. An in-process ring -- no Prometheus, no
/// exporter (ADR-008's posture); a restart starts a fresh window, which is
/// the honest lifecycle of a latency sample.
/// </summary>
/// <remarks>
/// The window carries no engagement dimension: a build's duration is a
/// toolchain fact, and the diagnostics face's red line is aggregates only.
/// Failures are recorded with the same duration as successes -- a toolchain
/// that fails fast and a toolchain that succeeds slowly are different
/// problems, and the pair of numbers is what tells them apart.
/// </remarks>
public sealed class BuildDiagnostics
{
    /// <summary>How many recent builds the ring retains.</summary>
    public const int Window = 100;

    private readonly Lock _gate = new();
    private readonly TimeSpan[] _ring = new TimeSpan[Window];
    private readonly bool[] _outcomes = new bool[Window];
    private int _next;
    private int _count;
    private int _inFlight;

    /// <summary>
    /// Marks a build as started (waiting on the concurrency gate counts -- an
    /// operator staring at a queued build wants the diagnostics to say so).
    /// Paired with <see cref="Record"/>; in-flight is the difference of the
    /// two calls, not a gauge the reader resets.
    /// </summary>
    public void Started()
    {
        lock (_gate)
        {
            _inFlight++;
        }
    }

    /// <summary>Records one finished build -- succeeded or failed -- into the ring.</summary>
    public void Record(TimeSpan duration, bool succeeded)
    {
        lock (_gate)
        {
            _inFlight--;
            _ring[_next] = duration;
            _outcomes[_next] = succeeded;
            _next = (_next + 1) % _ring.Length;
            _count = Math.Min(_count + 1, _ring.Length);
        }
    }

    /// <summary>
    /// The retained window's rollup: sample counts by outcome, the min/mean/
    /// max/p95 of successful build durations, and the in-flight count. An
    /// empty window reports zero everywhere except in-flight.
    /// </summary>
    public BuildWindowSnapshot Snapshot()
    {
        lock (_gate)
        {
            var succeeded = Enumerable.Range(0, _count)
                .Where(i => _outcomes[i])
                .Select(i => _ring[i].TotalMilliseconds)
                .OrderBy(ms => ms)
                .ToArray();
            return new BuildWindowSnapshot(
                InFlight: _inFlight,
                Total: _count,
                Succeeded: succeeded.Length,
                Failed: _count - succeeded.Length,
                MinMs: succeeded.Length > 0 ? succeeded[0] : null,
                MeanMs: succeeded.Length > 0 ? succeeded.Average() : null,
                MaxMs: succeeded.Length > 0 ? succeeded[^1] : null,
                // Nearest-rank percentile on the ordered durations; the window
                // is small enough that the exact-rank answer is the honest one.
                P95Ms: succeeded.Length > 0 ? succeeded[(int)Math.Ceiling(0.95 * succeeded.Length) - 1] : null);
        }
    }
}

/// <summary>The retained window's rollup for the diagnostics face.</summary>
public sealed record BuildWindowSnapshot(
    int InFlight,
    int Total,
    int Succeeded,
    int Failed,
    double? MinMs,
    double? MeanMs,
    double? MaxMs,
    double? P95Ms);
