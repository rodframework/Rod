using Rod.BuildPipeline.PayloadBuild;

namespace Rod.Build.Tests;

/// <summary>
/// The build duration ring (architecture.md Sec 15.3, ADR-008): successes and
/// failures land in the same window with their durations, in-flight is the
/// difference of started and finished builds, and the rollup's percentiles
/// read off the successful samples only -- a toolchain that fails fast and
/// one that succeeds slowly are different problems.
/// </summary>
public class BuildDiagnosticsTests
{
    [Fact]
    public void Snapshot_RollsUpTheWindow_OverSuccessesOnlyForDuration()
    {
        var ring = new BuildDiagnostics();
        ring.Started();
        ring.Record(TimeSpan.FromSeconds(10), succeeded: true);
        ring.Started();
        ring.Record(TimeSpan.FromSeconds(30), succeeded: true);
        ring.Started();
        ring.Record(TimeSpan.FromSeconds(2), succeeded: false);

        var snapshot = ring.Snapshot();

        Assert.Equal(0, snapshot.InFlight);
        Assert.Equal(3, snapshot.Total);
        Assert.Equal(2, snapshot.Succeeded);
        Assert.Equal(1, snapshot.Failed);
        Assert.Equal(10_000, snapshot.MinMs);
        Assert.Equal(20_000, snapshot.MeanMs);
        Assert.Equal(30_000, snapshot.MaxMs);
        // Nearest-rank p95 of two samples is the second (the max).
        Assert.Equal(30_000, snapshot.P95Ms);
    }

    [Fact]
    public void AnEmptyWindow_ReportsZeroEverywhereExceptInFlight()
    {
        var ring = new BuildDiagnostics();
        ring.Started();
        ring.Started();

        var snapshot = ring.Snapshot();

        Assert.Equal(2, snapshot.InFlight);
        Assert.Equal(0, snapshot.Total);
        Assert.Null(snapshot.MinMs);
        Assert.Null(snapshot.MeanMs);
        Assert.Null(snapshot.MaxMs);
        Assert.Null(snapshot.P95Ms);
    }

    [Fact]
    public void TheRing_RetainsOnlyTheLastWindow()
    {
        var ring = new BuildDiagnostics();
        // One past full: the first recorded build (1s) must fall out.
        for (var i = 0; i <= BuildDiagnostics.Window; i++)
        {
            ring.Started();
            ring.Record(TimeSpan.FromSeconds(i + 1), succeeded: true);
        }

        var snapshot = ring.Snapshot();

        Assert.Equal(BuildDiagnostics.Window, snapshot.Total);
        Assert.Equal(2_000, snapshot.MinMs); // The 1s sample is gone; 2s is oldest.
        Assert.Equal((double)(BuildDiagnostics.Window + 1) * 1000, snapshot.MaxMs);
    }
}
