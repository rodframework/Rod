namespace Rod.Capabilities.Lifecycle;

/// <summary>
/// The install path's bounds (ADR-023): a package is a zip read whole into
/// memory before the trust chain runs, and a registry download is an
/// outbound fetch an install request triggers -- both need a ceiling the
/// deployment owns rather than whatever a framework default leaves in
/// place. The defaults bound a package of several platform artifacts with
/// generous headroom; both knobs sit under <c>Modules:</c> beside the
/// store and registry keys.
/// </summary>
public static class ModuleLimits
{
    /// <summary>The configuration key the package ceiling (bytes) lives
    /// under. Applies to uploads, registry downloads, and the shared
    /// install spine alike -- one number, every entrance.</summary>
    public const string MaxPackageBytesKey = "Modules:MaxPackageBytes";

    /// <summary>The configuration key the registry download timeout
    /// (seconds) lives under. Covers the index fetches and the package
    /// download; a registry that cannot answer inside it is a refused
    /// install, never a hung request.</summary>
    public const string DownloadTimeoutSecondsKey = "Modules:DownloadTimeoutSeconds";

    public const long DefaultMaxPackageBytes = 128L * 1024 * 1024;

    public const int DefaultDownloadTimeoutSeconds = 60;

    /// <summary>Reads the configured ceiling, falling back to the default
    /// when unset or malformed -- a bad knob degrades to the bound, never
    /// past it.</summary>
    public static long MaxPackageBytes(string? configured)
        => long.TryParse(configured, out var bytes) && bytes > 0
            ? bytes
            : DefaultMaxPackageBytes;

    /// <summary>Reads the configured download timeout the same way.</summary>
    public static TimeSpan DownloadTimeout(string? configured)
        => int.TryParse(configured, out var seconds) && seconds > 0
            ? TimeSpan.FromSeconds(seconds)
            : TimeSpan.FromSeconds(DefaultDownloadTimeoutSeconds);
}

/// <summary>
/// A package (uploaded or downloaded) crossed the configured ceiling. The
/// install is refused before anything is extracted or registered; the
/// endpoints answer 413 with the ceiling and the actual size named.
/// </summary>
public sealed class ModulePackageTooLargeException(string reason) : InvalidOperationException(reason);

/// <summary>
/// The registry did not answer inside the configured download timeout. The
/// endpoints answer 504: the registry is a dependency the install asked
/// for, and a silent hang is not an outcome an operator can act on.
/// </summary>
public sealed class ModuleDownloadTimeoutException(string reason) : InvalidOperationException(reason);
