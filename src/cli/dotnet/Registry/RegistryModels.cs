using System.Text.Json;
using System.Text.Json.Serialization;
using Rod.Cli.Manifest;

namespace Rod.Cli.Registry;

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
    IReadOnlyList<string>? Assets = null)
{
    public sealed record CompatibilityInfo(
        string Teamserver,
        IReadOnlyList<TargetInfo> Targets);

    public sealed record TargetInfo(string ImplantClass, string Platform, string Arch);

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
            string? implantClass = null, platform = null, arch = null;
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
                }
            }
            return new RegistryVersion.TargetInfo(implantClass ?? "", platform ?? "", arch ?? "");
        }

        public override void Write(
            Utf8JsonWriter writer, RegistryVersion.TargetInfo value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("implantClass", value.ImplantClass);
            writer.WriteString("platform", value.Platform);
            writer.WriteString("arch", value.Arch);
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
