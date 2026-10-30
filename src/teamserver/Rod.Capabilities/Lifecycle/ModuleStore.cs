using Rod.Packaging;

namespace Rod.Capabilities.Lifecycle;

/// <summary>
/// The installed-module store (ADR-023): the deployment's server-side half
/// of the module ecosystem, rooted at <c>Modules:Store</c>. Packages land
/// under <c>&lt;store&gt;/&lt;name&gt;/&lt;version&gt;/</c> beside a
/// <c>rod.modules.lock.json</c> carrying the same trust record the rod CLI
/// writes on an operator workstation -- pinned keys, digests, signatures --
/// so the two installation surfaces (the CLI against a checkout, the
/// teamserver against its store) share one lock format and one verification
/// implementation, Rod.Packaging's. Startup seeds the live registries from
/// the lock; the lifecycle service mutates both afterwards.
/// </summary>
public sealed class ModuleStore
{
    /// <summary>The configuration key the store's root directory lives
    /// under.</summary>
    public const string StoreSectionKey = "Modules:Store";

    private readonly string _root;

    public ModuleStore(string root)
    {
        // A relative root names a directory beside the binary -- the same
        // base the config-listed module paths resolve against -- so the
        // shipped default lands deterministically no matter the working
        // directory the process started in.
        _root = Path.GetFullPath(root, AppContext.BaseDirectory);
        Directory.CreateDirectory(_root);
    }

    public string Root => _root;

    public string LockPath => Path.Combine(_root, ModuleLock.FileName);

    public ModuleLock LoadLock() => ModuleLock.Load(LockPath);

    public void SaveLock(ModuleLock lockFile) => ModuleLock.Save(LockPath, lockFile);

    /// <summary>The installed package directory for one lock entry.</summary>
    public string DirectoryFor(ModuleLock.LockedModule module)
        => Path.Combine(_root, module.Path);

    /// <summary>Every lock entry whose package directory still
    /// exists.</summary>
    public IReadOnlyList<(ModuleLock.LockedModule Module, string Directory, ModuleManifest Manifest)> Installed()
    {
        var installed = new List<(ModuleLock.LockedModule, string, ModuleManifest)>();
        foreach (var module in LoadLock().Modules)
        {
            var directory = DirectoryFor(module);
            var manifestPath = Path.Combine(directory, ManifestToml.FileName);
            if (!File.Exists(manifestPath))
                continue;
            var (manifest, _) = ManifestToml.LoadFile(manifestPath);
            if (manifest is not null)
                installed.Add((module, directory, manifest));
        }
        return installed;
    }

    /// <summary>
    /// Stages a verified package directory into the store: an
    /// install-and-swap under <c>&lt;name&gt;/&lt;version&gt;/</c>, the
    /// older version tree of the same name removed (the upgrade posture the
    /// CLI holds -- the lock is the record, not the directory). The caller
    /// has already verified the bytes; this is bookkeeping.
    /// </summary>
    public string Adopt(string extractedDirectory, ModuleManifest manifest)
    {
        var destination = Path.Combine(_root, "modules", manifest.Name, manifest.Version.ToString());
        if (Directory.Exists(destination))
            Directory.Delete(destination, recursive: true);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        Directory.Move(extractedDirectory, destination);
        return destination;
    }

    /// <summary>Removes an installed package's tree -- and its name folder
    /// when the last version under it went with it; the lock entry is the
    /// caller's to drop.</summary>
    public void Remove(ModuleLock.LockedModule module)
    {
        var directory = DirectoryFor(module);
        if (Directory.Exists(directory))
            Directory.Delete(directory, recursive: true);
        var nameFolder = Path.GetDirectoryName(directory);
        if (nameFolder is not null
            && Directory.Exists(nameFolder)
            && !Directory.EnumerateFileSystemEntries(nameFolder).Any())
            Directory.Delete(nameFolder);
    }

    /// <summary>
    /// The platform-matched artifact a <c>module.load</c> task stages for an
    /// installed plugin package: the row whose platform and arch equal the
    /// implant's own. Answers the row and its bytes, or null when the
    /// package serves no such target.
    /// </summary>
    public (PluginArtifact Artifact, byte[] Content)? ResolvePluginArtifact(
        ModuleManifest manifest, string platform, string arch)
    {
        if (manifest.Entry != ModuleEntryKind.Plugin)
            return null;
        var row = manifest.PluginArtifacts.FirstOrDefault(a =>
            string.Equals(a.Platform, platform, StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.Arch, arch, StringComparison.OrdinalIgnoreCase));
        if (row is null)
            return null;

        var directory = Installed()
            .FirstOrDefault(held => held.Manifest.Name == manifest.Name)
            .Directory;
        if (directory is null)
            return null;
        var file = Path.Combine(directory, row.Path.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(file))
            return null;
        return (row, File.ReadAllBytes(file));
    }
}
