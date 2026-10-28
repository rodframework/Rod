using System.Text.Json;
using System.Text.Json.Serialization;

namespace Rod.Packaging;

/// <summary>
/// The registry index's data model: one JSON file per module under
/// <c>modules/</c> in the rod-registry git repository (the Homebrew-tap
/// shape, architecture.md Sec 15.2). The entry mirrors the manifest's
/// catalog metadata for search and carries, per version, the artifact URL,
/// the package digest, the publisher's public key, and the signature over
/// the package's canonical form. The mirror is a convenience for browsing;
/// install re-reads the manifest inside the package and cross-checks it,
/// so the package stays the source of truth and the index stays a pointer
/// set with signatures attached.
/// </summary>
public sealed record RegistryEntry(
    string Name,
    string Entry,
    string? Description,
    string License,
    string? Homepage,
    RegistryEntry.OpsecInfo Opsec,
    IReadOnlyList<string> Attack,
    IReadOnlyList<RegistryVersion> Versions)
{
    public sealed record OpsecInfo(bool LandsOnDisk, string? Notes);
}

public sealed record RegistryVersion(
    string Version,
    string Published,
    string Url,
    string Sha256,
    string Signature,
    string PublicKey,
    string Fingerprint,
    RegistryVersion.CompatibilityInfo Compatibility,
    IReadOnlyList<RegistryVersion.VerbInfo>? Verbs = null,
    IReadOnlyList<string>? Assets = null,
    IReadOnlyList<RegistryVersion.PluginArtifactInfo>? PluginArtifacts = null,
    string? UnitId = null,
    RegistryVersion.ConformanceInfo? Conformance = null)
{
    public sealed record CompatibilityInfo(
        string Teamserver,
        IReadOnlyList<TargetInfo> Targets,
        IReadOnlyList<string>? Requires = null);

    public sealed record TargetInfo(
        string ImplantClass,
        string Platform,
        string Arch,
        string? BuildUnit = null,
        string? UnitRange = null);

    /// <summary>One <c>[[plugin.artifacts]]</c> row mirrored from the manifest
    /// (ADR-020): the platform and arch the artifact serves, its
    /// package-relative path, and the loader ABI it was built against --
    /// mirrored so the catalog answers "which loaders does this plugin ride,
    /// on which targets" without unpacking the package.</summary>
    public sealed record PluginArtifactInfo(
        string Platform,
        string Arch,
        string Path,
        string Abi);

    /// <summary>The build unit's conformance report, mirrored from the
    /// manifest (ADR-017): the tier its candidate proved, the harness
    /// generation, the date, and the clauses that passed -- a publisher's
    /// signature-bound claim, carried in the index so the catalog answers
    /// "what does this implant run" without unpacking the package.</summary>
    public sealed record ConformanceInfo(
        int Tier,
        string Harness,
        string Date,
        IReadOnlyList<string> Clauses);

    /// <summary>One verb row of the version matrix (architecture.md Sec 15.2's
    /// third contract): the verb, its module-scoped version, its optional
    /// per-verb teamserver floor, and the row's ATT&CK techniques -- the same
    /// ids the signed canonical form carries, mirrored so the index answers
    /// coverage questions (search, the release matrix) without unpacking the
    /// package.</summary>
    public sealed record VerbInfo(
        string Name,
        string Version,
        string? Teamserver,
        IReadOnlyList<string>? Techniques = null);
}

public static class RegistryJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    static RegistryJson()
    {
        // Reading tolerates hand-editing (a registry is a git repository
        // humans send pull requests against); writing stays canonical.
        Options.PropertyNameCaseInsensitive = true;
        Options.Converters.Add(new TargetInfoConverter());
    }

    // TargetInfo is positional (a table row), so it needs a converter to
    // ride the camelCase policy instead of default property serialization.
    private sealed class TargetInfoConverter : JsonConverter<RegistryVersion.TargetInfo>
    {
        public override RegistryVersion.TargetInfo Read(
            ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string? implantClass = null, platform = null, arch = null, buildUnit = null, unitRange = null;
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                    break;
                if (reader.TokenType != JsonTokenType.PropertyName)
                    continue;
                var key = reader.GetString();
                reader.Read();
                var value = reader.GetString() ?? "";
                switch (key)
                {
                    case "implantClass": implantClass = value; break;
                    case "platform": platform = value; break;
                    case "arch": arch = value; break;
                    case "buildUnit": buildUnit = value; break;
                    case "unitRange": unitRange = value; break;
                }
            }
            return new RegistryVersion.TargetInfo(
                implantClass ?? "", platform ?? "", arch ?? "",
                string.IsNullOrEmpty(buildUnit) ? null : buildUnit,
                string.IsNullOrEmpty(unitRange) ? null : unitRange);
        }

        public override void Write(
            Utf8JsonWriter writer, RegistryVersion.TargetInfo value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("implantClass", value.ImplantClass);
            writer.WriteString("platform", value.Platform);
            writer.WriteString("arch", value.Arch);
            if (value.BuildUnit is not null)
                writer.WriteString("buildUnit", value.BuildUnit);
            if (value.UnitRange is not null)
                writer.WriteString("unitRange", value.UnitRange);
            writer.WriteEndObject();
        }
    }

    public static RegistryEntry? LoadEntry(string path)
        => JsonSerializer.Deserialize<RegistryEntry>(File.ReadAllText(path), Options);

    public static string SaveVersion(RegistryVersion version)
        => JsonSerializer.Serialize(version, Options) + "\n";

    public static string SaveEntry(RegistryEntry entry)
    {
        entry = entry with
        {
            Versions = entry.Versions
                .OrderByDescending(v => SemVer.TryParse(v.Version, out var parsed) ? parsed : new SemVer(0, 0, 0, null))
                .ThenBy(v => v.Version, StringComparer.Ordinal)
                .ToList(),
        };
        return JsonSerializer.Serialize(entry, Options) + "\n";
    }
}
