using Rod.CoreState.Listeners;
using Rod.Packaging;

namespace Rod.Capabilities.Lifecycle;

/// <summary>
/// The installed-store face of the listener package catalog (ADR-025): one
/// query over <see cref="ModuleStore.Installed"/>, filtered to listener
/// entries. The manifest's own validation refused a third-party medium
/// declaring id-only at publish; the resolve-side check is the belt to
/// that braces -- a store that drifted past validation (a hand-planted
/// tree, a lock edited by hand) still cannot serve the package.
/// </summary>
public sealed class ListenerPackageCatalog : IListenerPackageCatalog
{
    private readonly ModuleStore _store;

    public ListenerPackageCatalog(ModuleStore store)
    {
        _store = store;
    }

    public ListenerPackageInfo? Resolve(
        string name,
        string? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(name);

        var candidates = _store.Installed()
            .Where(held => held.Manifest.Entry == ModuleEntryKind.Listener
                && string.Equals(held.Manifest.Name, name, StringComparison.Ordinal))
            .OrderByDescending(held => held.Manifest.Version)
            .ToList();
        // A null version resolves the latest installed version of the name:
        // the same highest-wins rule the registry's version ordering carries.
        var held = version is null
            ? candidates.FirstOrDefault()
            : candidates.FirstOrDefault(c =>
                string.Equals(c.Manifest.Version.ToString(), version.Trim(), StringComparison.Ordinal));
        if (held.Module is null)
            return null;

        var declaration = held.Manifest.Listener!;
        var info = new ListenerPackageInfo(
            held.Manifest.Name,
            held.Manifest.Version.ToString(),
            ListenerSealTierNames.ToString(declaration.SealTier),
            declaration.ThirdPartyMedium,
            declaration.Channel,
            declaration.Carriers,
            declaration.ProcessCommand,
            declaration.ProcessArgs,
            declaration.Params
                .Select(p => new ListenerPackageParam(p.Name, p.Kind, p.Required, p.Description, p.Secret))
                .ToList(),
            held.Directory);
        if (!info.SealRuleSatisfied)
            throw new InvalidOperationException(
                $"Listener package '{held.Manifest.Name}@{held.Manifest.Version}' declares an id-only seal on a "
                + "third-party medium; the kernel refuses to serve it.");
        return info;
    }
}
