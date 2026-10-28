using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Rod.Packaging;

/// <summary>
/// Package assembly for <c>rod mod publish</c> and disassembly for
/// <c>rod mod install</c>. One package is a zip holding the manifest plus
/// the payload files the manifest's packaging rules select; zips are built
/// deterministically (sorted entries, fixed timestamps) so republishing an
/// unchanged tree yields an identical digest -- the property that makes a
/// registry entry's pinned sha256 re-checkable by anyone.
/// </summary>
public static class ModulePackage
{
    // Always excluded, whatever the manifest says: VCS internals, build
    // outputs, the publish output itself, and secret key material. The key
    // exclusion is a safety net, not the mechanism -- publish refuses any
    // *.key it still sees afterwards rather than silently dropping it.
    private static readonly string[] HardExcludes =
    [
        ".git/**",
        "**/bin/**",
        "**/obj/**",
        "dist/**",
        "**/*.key",
    ];

    public sealed record Selection(IReadOnlyList<string> Files, string Root);

    /// <summary>Selects the files publish packs: the manifest itself, plus
    /// everything under the module directory the include/exclude rules
    /// admit. Symlinks are skipped -- a package that followed them would
    /// pack whatever the link happens to point at.</summary>
    public static Selection SelectFiles(string moduleRoot, PackageRules? rules)
    {
        var include = rules?.Include.Count > 0 ? rules.Include : ["**"];
        var exclude = (rules?.Exclude ?? []).Concat(HardExcludes).Distinct(StringComparer.Ordinal).ToArray();

        var files = new List<string>();
        foreach (var file in Directory.EnumerateFiles(moduleRoot, "*", SearchOption.AllDirectories))
        {
            var info = new FileInfo(file);
            if (info.LinkTarget is not null)
                continue;
            var relative = Path.GetRelativePath(moduleRoot, file).Replace('\\', '/');
            if (relative == ManifestToml.FileName)
            {
                files.Add(relative);
                continue;
            }
            if (include.Any(pattern => GlobMatches(pattern, relative)) &&
                !exclude.Any(pattern => GlobMatches(pattern, relative)))
            {
                files.Add(relative);
            }
        }

        files.Sort(StringComparer.Ordinal);
        return new Selection(files, moduleRoot);
    }

    /// <summary>Writes the deterministic zip and returns its SHA-256. The
    /// zip epoch timestamp keeps every entry stable across machines and
    /// clocks; deflate at a fixed level keeps the bytes stable across
    /// repacks on the same runtime.</summary>
    public static async Task<(string Path, string Sha256)> WriteZipAsync(
        Selection selection, string destinationPath)
    {
        using (var stream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            var epoch = new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);

            foreach (var relative in selection.Files)
            {
                var entry = archive.CreateEntry(relative, CompressionLevel.Optimal);
                entry.LastWriteTime = epoch;
                await using var source = File.OpenRead(Path.Combine(selection.Root, relative));
                await using var target = entry.Open();
                await source.CopyToAsync(target);
            }
        }

        using var completed = File.Open(destinationPath, FileMode.Open, FileAccess.Read);
        return (destinationPath, Convert.ToHexStringLower(await SHA256.HashDataAsync(completed)));
    }

    /// <summary>Extracts a package into a fresh directory, refusing entries
    /// that escape it (zip-slip): no rooted paths, no parent traversal, no
    /// drive letters.</summary>
    public static void ExtractSafe(string archivePath, string destinationDirectory)
    {
        Directory.CreateDirectory(destinationDirectory);
        using var archive = ZipFile.OpenRead(archivePath);
        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName.Replace('\\', '/');
            if (name.Length == 0)
                continue;
            if (name.StartsWith('/') || (name.Length > 1 && name[1] == ':'))
                throw new IOException($"package entry '{entry.FullName}' is rooted; refusing.");
            var segments = name.Split('/');
            if (segments.Any(s => s == ".."))
                throw new IOException($"package entry '{entry.FullName}' escapes the package root; refusing.");

            var destination = Path.Combine(destinationDirectory, Path.Combine(segments));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            entry.ExtractToFile(destination, overwrite: true);
        }
    }

    /// <summary>Glob matching with <c>**</c> (any depth), <c>*</c> (within a
    /// segment), and <c>?</c> (one character), matched against '/'-separated
    /// relative paths.</summary>
    public static bool GlobMatches(string pattern, string path)
    {
        var regex = Regex.Escape(pattern)
            .Replace(@"\*\*/", "(?:.*/)?")
            .Replace(@"\*\*", ".*")
            .Replace(@"\*", "[^/]*")
            .Replace(@"\?", "[^/]");
        return Regex.IsMatch(path, "^" + regex + "$", RegexOptions.IgnoreCase);
    }
}
