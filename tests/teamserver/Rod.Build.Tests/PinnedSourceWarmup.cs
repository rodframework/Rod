using Rod.BuildPipeline.PayloadBuild;

namespace Rod.Build.Tests;

/// <summary>
/// Warms the pinned-source cache before a real-build test's readiness gate
/// runs. A cold cache reads "unavailable" in the environment report -- the
/// report is a read-only probe by design, and the unit fetches lazily at
/// first build -- so without this the real-build tests would pass vacuously
/// on a host whose cache is cold, never reaching the build they exist to
/// run. A fetch failure is swallowed: the gate then decides, and a host
/// with no lock, no mirror, and no network keeps its skip.
/// </summary>
internal static class PinnedSourceWarmup
{
    public static void Warm(string language)
    {
        try
        {
            PinnedImplantSource.EnsurePinnedTree(language);
        }
        catch (InvalidOperationException)
        {
        }
    }
}
