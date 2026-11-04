using Rod.CoreState.Listeners;

namespace Rod.Transport.Listeners.Bridge;

/// <summary>
/// The no-store default of <see cref="IListenerPackageCatalog"/>: every
/// resolve answers null. A deployment without <c>Modules:Store</c> names no
/// listener package, so no package-backed listener can be created -- the
/// open-not-on posture every module seam keeps.
/// </summary>
internal sealed class NullListenerPackageCatalog : IListenerPackageCatalog
{
    public ListenerPackageInfo? Resolve(
        string name,
        string? version = null,
        CancellationToken cancellationToken = default)
        => null;
}
