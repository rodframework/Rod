namespace Rod.CoreState.Assets;

/// <summary>One asset a module carries: the file's bytes and the path the
/// manifest declared for them (package-relative, '/' separators). The path
/// rides along because consumers key file-shape decisions on it -- a
/// campaign template's extension selects plain text against HTML -- without
/// the store itself knowing anything about the content it serves.</summary>
public sealed record ModuleAsset(byte[] Content, string Path);

/// <summary>
/// The module layer's content seam (architecture.md Sec 15.1): named,
/// read-only bytes an asset module ships -- the browser hook script, the
/// phishing templates -- resolved by module name plus asset name, the
/// address a consumer's contract fixes the way a verb string fixes a
/// capability. The teamserver never executes any of it; the consumers
/// render, serve, or parse the bytes under their own contracts.
/// </summary>
/// <remarks>
/// The port lives in core state for the same reason the resolver ports do:
/// transport (whose endpoints consume assets) cannot reference the
/// capabilities layer (which loads them), so both sides meet at this
/// interface. The transport host registers <see cref="NoModuleAssets"/> --
/// the open-not-on default, every lookup refusing -- and
/// <c>AddRodCapabilities</c> replaces it with the module-backed store built
/// from the <c>Capabilities:AssetModules</c> configuration list.
/// </remarks>
public interface IModuleAssetStore
{
    /// <summary>
    /// Resolves one asset. False when no loaded module carries
    /// <paramref name="moduleName"/>/<paramref name="assetName"/> -- the
    /// consumer decides how loudly that refusal reads at its surface.
    /// </summary>
    bool TryRead(string moduleName, string assetName, out ModuleAsset asset);
}

/// <summary>
/// The empty store: the default every host runs with until an operator
/// deploys asset modules and lists them. Lookups always fail, so the
/// consumers that need an asset answer their loud refusal (a mint that
/// cannot render, a template reference that cannot resolve) instead of
/// serving anything -- the same default-off posture the sensitive
/// capabilities keep (architecture.md Sec 7, Sec 15).
/// </summary>
public sealed class NoModuleAssets : IModuleAssetStore
{
    public bool TryRead(string moduleName, string assetName, out ModuleAsset asset)
    {
        asset = null!;
        return false;
    }
}
