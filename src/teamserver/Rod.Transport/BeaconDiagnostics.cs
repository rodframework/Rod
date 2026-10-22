namespace Rod.Transport;

/// <summary>
/// The beacon-path latency histogram (architecture.md Sec 15.3, ADR-008): how
/// long the teamserver takes to turn one upstream beacon frame around, from
/// the frame reaching the shared ingest to its handler completing. Every
/// transport carriage funnels its upstream frames through the same ingest, so
/// one seam observes them all. The distribution is deployment-wide by
/// construction -- no engagement or implant dimension rides along, matching
/// the diagnostics face's aggregate-only red line.
/// </summary>
/// <remarks>
/// An in-process counter (ADR-008: no Prometheus, no exporter -- export, if
/// an engagement ever demands it, arrives as a module): a fixed set of
/// millisecond buckets incremented with <see cref="Interlocked"/>, cumulative
/// since process start. A restart resets it, which is the honest lifecycle of
/// a server-side turnaround measure; the durable facts about beacons live in
/// the audit trail, not here.
/// </remarks>
public sealed class BeaconDiagnostics
{
    // Upper bounds in milliseconds; the last bucket is everything above its
    // bound. Coarse on purpose: the question is "is the server turning frames
    // around in single-digit milliseconds or dragging", not a percentile
    // service-level objective.
    private static readonly long[] Bounds = [1, 5, 10, 25, 50, 100, 250, 500, 1000];

    private readonly long[] _buckets = new long[Bounds.Length + 1];

    /// <summary>Records one frame's ingest latency into its bucket.</summary>
    public void Observe(TimeSpan latency)
    {
        // Stopwatch timestamps are ticks of 100ns; milliseconds with fraction
        // preserved, so a 0.4ms frame lands in the <=1ms bucket, not bucket 0
        // by truncation-to-zero.
        var millis = latency.TotalMilliseconds;
        int index;
        for (index = 0; index < Bounds.Length; index++)
        {
            if (millis <= Bounds[index])
                break;
        }
        Interlocked.Increment(ref _buckets[index]);
    }

    /// <summary>
    /// The cumulative bucket counts, oldest bound first, with a final
    /// overflow bucket labeled past its bound. A snapshot copy: the counts
    /// keep moving while the reader holds the array.
    /// </summary>
    public IReadOnlyList<BeaconLatencyBucket> Snapshot()
    {
        var snapshot = new BeaconLatencyBucket[_buckets.Length];
        for (var i = 0; i < Bounds.Length; i++)
            snapshot[i] = new BeaconLatencyBucket($"<= {Bounds[i]}ms", Volatile.Read(ref _buckets[i]));
        snapshot[Bounds.Length] = new BeaconLatencyBucket($"> {Bounds[^1]}ms", Volatile.Read(ref _buckets[Bounds.Length]));
        return snapshot;
    }
}

/// <summary>One histogram bucket: its inclusive label and cumulative count.</summary>
public sealed record BeaconLatencyBucket(string Label, long Count);
