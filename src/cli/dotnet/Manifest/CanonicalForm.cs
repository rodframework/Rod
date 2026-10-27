using System.Security.Cryptography;
using System.Text;

namespace Rod.Cli.Manifest;

/// <summary>
/// The canonical form of a module: the deterministic serialization that
/// gets signed at publish and re-derived and checked at install and verify
/// (architecture.md Sec 15.2). Every manifest field participates, so a
/// tampered OPSEC mark or compatibility floor breaks the signature, and
/// every payload file participates by digest, so a tampered byte breaks it
/// too. The manifest file's own bytes do not participate -- two
/// byte-different manifests with the same fields verify identically, which
/// is the correct semantics: the fields are the contract, comments and
/// whitespace are not.
/// </summary>
public static class CanonicalForm
{
    // v2 adds the compatibility rows (requires, the conformance report)
    // to the signed field set -- the form's identity names its own shape,
    // so a field-set change is a version bump, never a silent mismatch.
    public const string VersionLine = "rod-module-manifest-v2";

    /// <summary>Builds the signed message: one line per field in fixed
    /// order, then one digest line per payload file sorted by path. Lines
    /// join with '\n' and the last line carries no trailing newline.</summary>
    public static string Build(ModuleManifest manifest, IReadOnlyDictionary<string, string> payloadDigests)
    {
        var sb = new StringBuilder();
        void Line(string key, string value) => sb.Append(key).Append('=').Append(value).Append('\n');

        sb.Append(VersionLine).Append('\n');
        Line("name", manifest.Name);
        Line("version", manifest.Version.ToString());
        Line("entry", ModuleEntryKindNames.ToString(manifest.Entry));
        Line("license", manifest.License);
        Line("description", manifest.Description ?? "");
        Line("homepage", manifest.Homepage ?? "");
        Line("teamserver", manifest.TeamserverMin.ToString());
        Line("lands-on-disk", manifest.Opsec.LandsOnDisk ? "true" : "false");
        Line("opsec-notes", manifest.Opsec.Notes ?? "");
        Line("techniques", manifest.Techniques.Count == 0
            ? "-"
            : string.Join(",", manifest.Techniques.Select(t => t.ToUpperInvariant()).Distinct().OrderBy(t => t, StringComparer.Ordinal)));
        Line("targets", manifest.Targets.Count == 0
            ? "-"
            : string.Join(",", manifest.Targets
                .Select(t => $"{t.ImplantClass}/{t.Platform}/{t.Arch}")
                .Distinct(StringComparer.Ordinal)
                .OrderBy(t => t, StringComparer.Ordinal)));

        // The compatibility rows (ADR-017) ride the form like every other
        // field: a tampered requirement or conformance claim breaks the
        // signature exactly like a tampered OPSEC mark.
        Line("requires", manifest.Requires.Count == 0
            ? "-"
            : string.Join(",", manifest.Requires.Distinct().OrderBy(r => r, StringComparer.Ordinal)));
        Line("conformance", manifest.Conformance is { } report
            ? $"{report.Tier}/{report.Harness}/{report.Date}"
            : "-");
        Line("conformance-clauses", manifest.Conformance is { } withClauses && withClauses.Clauses.Count > 0
            ? string.Join(",", withClauses.Clauses.Distinct().OrderBy(c => c, StringComparer.Ordinal))
            : "-");

        // The verb version matrix rides one line per verb, name-sorted, with
        // a per-verb floor and the row's ATT&CK techniques folded in -- so a
        // tampered verb version, floor, or technique list breaks the
        // signature exactly like a tampered OPSEC mark.
        foreach (var verb in manifest.Verbs
                     .GroupBy(v => v.Name, StringComparer.Ordinal)
                     .Select(g => g.OrderByDescending(v => v.Version).First())
                     .OrderBy(v => v.Name, StringComparer.Ordinal))
        {
            var value = verb.TeamserverMin is { } floor
                ? $"{verb.Version} teamserver={floor}"
                : verb.Version.ToString();
            if (verb.Techniques is { Count: > 0 })
            {
                value += " techniques="
                    + string.Join(",", verb.Techniques.Select(t => t.ToUpperInvariant()).Distinct().OrderBy(t => t, StringComparer.Ordinal));
            }

            Line("verb/" + verb.Name, value);
        }

        // The asset rows ride one line per asset, name-sorted: the logical
        // name bound to the declared path, so a tampered mapping (pointing a
        // known asset name at a different file) breaks the signature exactly
        // like a tampered payload byte does through the digest lines below.
        foreach (var asset in manifest.Assets.OrderBy(a => a.Name, StringComparer.Ordinal))
            Line("asset/" + asset.Name, asset.Path.Replace('\\', '/'));

        // Payload paths use '/' separators and the 'file/' prefix so a
        // payload named like a field key can never collide with one.
        foreach (var path in payloadDigests.Keys.OrderBy(p => p, StringComparer.Ordinal))
            Line("file/" + path.Replace('\\', '/'), payloadDigests[path]);

        if (sb.Length > 0 && sb[^1] == '\n')
            sb.Length -= 1;
        return sb.ToString();
    }

    /// <summary>Digests every payload file (all files under the package
    /// tree except the manifest itself), keyed by path relative to the
    /// package root with '/' separators.</summary>
    public static IReadOnlyDictionary<string, string> DigestPayload(string root)
    {
        var digests = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).OrderBy(p => p, StringComparer.Ordinal))
        {
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (relative == ManifestToml.FileName)
                continue;
            digests[relative] = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(file)));
        }
        return digests;
    }
}
