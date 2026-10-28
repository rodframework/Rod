using System.Text.Json;
using Rod.Packaging;

namespace Rod.Capabilities.Lifecycle;

/// <summary>
/// The registry browsing client (ADR-023): reads the static module index a
/// rod-registry publishes -- the same per-module JSON files the rod CLI's
/// git tap carries, served over plain https (a Pages-shaped publication) or
/// read straight off a local checkout. No git, no server: the index is
/// files, and the browser is a fetch.
/// </summary>
public sealed class ModuleRegistryClient
{
    /// <summary>The configuration key the registry base (an https URL or a
    /// local directory) lives under.</summary>
    public const string RegistrySectionKey = "Modules:Registry";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly string _base;
    private readonly HttpMessageHandler _handler;

    public ModuleRegistryClient(string @base, HttpMessageHandler? handler = null)
    {
        _base = @base.Trim().TrimEnd('/');
        _handler = handler ?? new SocketsHttpHandler();
    }

    public bool IsLocal => !_base.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Every entry the index carries. A local base lists its
    /// <c>modules/*.json</c> directly; an https base reads
    /// <c>registry.json</c> -- the all-entries roll-up the registry's
    /// publish step maintains beside the per-module files.
    /// </summary>
    public async Task<IReadOnlyList<RegistryEntry>> ListAsync(CancellationToken cancellationToken = default)
    {
        if (IsLocal)
        {
            var folder = Path.Combine(_base, "modules");
            if (!Directory.Exists(folder))
                return [];
            var entries = new List<RegistryEntry>();
            foreach (var file in Directory.GetFiles(folder, "*.json").OrderBy(p => p, StringComparer.Ordinal))
            {
                // The roll-up is a name list, not an entry.
                if (Path.GetFileName(file).Equals("registry.json", StringComparison.OrdinalIgnoreCase))
                    continue;
                var entry = await ReadEntryFileAsync(file, cancellationToken);
                if (entry is not null)
                    entries.Add(entry);
            }
            return entries;
        }

        var index = await FetchJsonAsync($"{_base}/registry.json", cancellationToken);
        if (index is null)
            return [];
        using var document = JsonDocument.Parse(index);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            return [];
        var names = document.RootElement.EnumerateArray()
            .Select(element => element.GetString())
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .ToList();
        var listed = new List<RegistryEntry>();
        foreach (var name in names)
        {
            var entry = await FindAsync(name!, cancellationToken);
            if (entry is not null)
                listed.Add(entry);
        }
        return listed;
    }

    /// <summary>The index entry for one module, or null when the registry
    /// does not carry it.</summary>
    public async Task<RegistryEntry?> FindAsync(string name, CancellationToken cancellationToken = default)
    {
        var json = IsLocal
            ? await ReadFileAsync(Path.Combine(_base, "modules", name + ".json"), cancellationToken)
            : await FetchJsonAsync($"{_base}/modules/{name}.json", cancellationToken);
        if (json is null)
            return null;
        try
        {
            return JsonSerializer.Deserialize<RegistryEntry>(json, JsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Downloads a package's bytes by the index version's URL --
    /// https or the file:// shape a local registry carries.</summary>
    public async Task<byte[]> DownloadAsync(RegistryVersion version, CancellationToken cancellationToken = default)
    {
        if (version.Url.StartsWith("file://", StringComparison.Ordinal))
            return await File.ReadAllBytesAsync(version.Url["file://".Length..].TrimStart('/'), cancellationToken);
        if (IsLocal && !version.Url.Contains("://", StringComparison.Ordinal))
            return await File.ReadAllBytesAsync(version.Url, cancellationToken);
        using var client = new HttpClient(_handler, disposeHandler: false);
        return await client.GetByteArrayAsync(version.Url, cancellationToken);
    }

    private async Task<string?> FetchJsonAsync(string url, CancellationToken cancellationToken)
    {
        using var client = new HttpClient(_handler, disposeHandler: false);
        try
        {
            return await client.GetStringAsync(url, cancellationToken);
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }

    private static async Task<string?> ReadFileAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
            return null;
        return await File.ReadAllTextAsync(path, cancellationToken);
    }

    private static async Task<RegistryEntry?> ReadEntryFileAsync(string path, CancellationToken cancellationToken)
    {
        var json = await ReadFileAsync(path, cancellationToken);
        if (json is null)
            return null;
        try
        {
            return JsonSerializer.Deserialize<RegistryEntry>(json, JsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
