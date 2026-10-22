using Rod.Transport;

namespace Rod.Integration.Tests;

/// <summary>
/// The beacon latency histogram's bucketing (architecture.md Sec 15.3,
/// ADR-008): boundaries are inclusive on the upper bound, sub-millisecond
/// frames land in the first bucket by fraction rather than truncation, and
/// everything past the last bound lands in the overflow bucket. The counts
/// are cumulative -- the snapshot reads what was observed since process
/// start, never a window reset.
/// </summary>
public class BeaconDiagnosticsTests
{
    [Fact]
    public void Observe_BucketsByUpperBound_Inclusively()
    {
        var histogram = new BeaconDiagnostics();

        histogram.Observe(TimeSpan.FromMilliseconds(0.4));
        histogram.Observe(TimeSpan.FromMilliseconds(1));
        histogram.Observe(TimeSpan.FromMilliseconds(1.2));
        histogram.Observe(TimeSpan.FromMilliseconds(25));
        histogram.Observe(TimeSpan.FromMilliseconds(26));
        histogram.Observe(TimeSpan.FromSeconds(4));

        var buckets = histogram.Snapshot();
        Assert.Equal("<= 1ms", buckets[0].Label);
        Assert.Equal(2, buckets[0].Count); // 0.4 by fraction, 1 on the bound.
        Assert.Equal(1, buckets[1].Count); // 1.2 into <= 5ms.
        Assert.Equal(1, buckets[3].Count); // 25 on the <= 25ms bound.
        Assert.Equal(1, buckets[4].Count); // 26 into <= 50ms.
        var overflow = buckets[^1];
        Assert.Equal("> 1000ms", overflow.Label);
        Assert.Equal(1, overflow.Count);
    }

    [Fact]
    public void Snapshot_IsACopy_TheCountsKeepMoving()
    {
        var histogram = new BeaconDiagnostics();
        histogram.Observe(TimeSpan.FromMilliseconds(2));

        var first = histogram.Snapshot();
        histogram.Observe(TimeSpan.FromMilliseconds(2));

        var second = histogram.Snapshot();
        Assert.Equal(1, first[1].Count);
        Assert.Equal(2, second[1].Count);
    }
}
