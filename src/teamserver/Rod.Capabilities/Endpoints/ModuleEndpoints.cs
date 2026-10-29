using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Net.Http.Headers;
using Rod.CoreState.Operators;
using Rod.Capabilities.Lifecycle;
using Rod.Packaging;

namespace Rod.Capabilities.Endpoints;

/// <summary>
/// The operator-facing module lifecycle endpoints (ADR-023): browse the
/// registry, list what the deployment holds, install (from the registry or
/// as an uploaded package), and uninstall -- the whole day-2 module
/// workflow from the operator console, every action verified through the
/// trust chain and audit-chained to the acting operator. Mapped by the
/// composition root beside <see cref="MapCapabilityEndpoints"/> for the
/// same layer-separation reason.
/// </summary>
/// <remarks>
/// The surface installs data packages only: descriptor rows, plugin
/// artifacts, extension sources, build-unit tables, asset files. The in-proc
/// assembly path stays config-listed by the deployment owner -- code that
/// runs inside the teamserver is never a click away.
/// </remarks>
public static class ModuleEndpoints
{
    public static IEndpointRouteBuilder MapRodModuleEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/modules").RequireAuthorization();
        group.MapGet("/", ListInstalled).WithName("ListInstalledModules");
        group.MapGet("/registry", BrowseRegistry).WithName("BrowseModuleRegistry");
        group.MapGet("/registry/{name}", RegistryDetail).WithName("ModuleRegistryDetail");
        group.MapPost("/install", InstallFromRegistry).WithName("InstallModule");
        group.MapPost("/upload", InstallUploaded).WithName("UploadModule");
        group.MapPost("/{name}/uninstall", Uninstall).WithName("UninstallModule");
        group.MapGet("/{name}/artifact", PluginArtifact).WithName("ModulePluginArtifact");
        return endpoints;
    }

    public sealed record InstalledModuleResponse(
        string Name, string Version, string Entry, string Fingerprint, string InstalledAt);

    private static async Task<IResult> ListInstalled(ModuleLifecycleService lifecycle)
    {
        var installed = lifecycle.Installed()
            .Select(held => new InstalledModuleResponse(
                held.Manifest.Name,
                held.Manifest.Version.ToString(),
                ModuleEntryKindNames.ToString(held.Manifest.Entry),
                held.Module.Fingerprint,
                held.Module.Installed))
            .ToList();
        return TypedResults.Ok(installed);
    }

    private static async Task<IResult> BrowseRegistry(
        IServiceProvider services, CancellationToken cancellationToken)
    {
        var client = services.GetService<ModuleRegistryClient>();
        if (client is null)
            return TypedResults.BadRequest(new Problem("No module registry configured (Modules:Registry)."));
        var entries = await client.ListAsync(cancellationToken);
        return TypedResults.Ok(entries.Select(entry => new
        {
            entry.Name,
            Entry = entry.Entry,
            entry.Description,
            entry.License,
            Latest = entry.Versions.FirstOrDefault()?.Version,
        }));
    }

    private static async Task<IResult> RegistryDetail(
        string name, IServiceProvider services, CancellationToken cancellationToken)
    {
        var client = services.GetService<ModuleRegistryClient>();
        if (client is null)
            return TypedResults.BadRequest(new Problem("No module registry configured (Modules:Registry)."));
        var entry = await client.FindAsync(name, cancellationToken);
        return entry is null
            ? TypedResults.NotFound(new Problem($"The registry carries no module named '{name}'."))
            : TypedResults.Ok(entry);
    }

    public sealed record InstallRequest(string Name, string? Version = null);

    private static async Task<IResult> InstallFromRegistry(
        InstallRequest body,
        HttpContext context,
        ModuleLifecycleService lifecycle,
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(body.Name))
            return TypedResults.BadRequest(new Problem("Name is required."));
        var client = services.GetService<ModuleRegistryClient>();
        if (client is null)
            return TypedResults.BadRequest(new Problem("No module registry configured (Modules:Registry)."));

        var operatorId = context.User.TryGetOperatorId()?.Value;
        try
        {
            var record = await lifecycle.InstallFromRegistryAsync(
                client, body.Name.Trim(), body.Version, operatorId, cancellationToken);
            return TypedResults.Ok(record);
        }
        catch (InvalidOperationException ex)
        {
            return Rejected(ex);
        }
        catch (System.Net.Http.HttpRequestException ex)
        {
            // The registry did not serve what its index pointed at -- a
            // dependency failure, not a server bug.
            return TypedResults.Json(
                new Problem($"The registry did not serve the package: {ex.Message}"),
                statusCode: StatusCodes.Status502BadGateway);
        }
    }

    private static async Task<IResult> InstallUploaded(
        HttpContext context,
        ModuleLifecycleService lifecycle,
        HttpRequest request,
        CancellationToken cancellationToken)
    {
        // The upload shape: multipart with the package zip, the publisher's
        // public key, and the detached signature -- the trust chain travels
        // with the bytes, and the server verifies it exactly as it would a
        // registry package's.
        if (!request.HasFormContentType)
            return TypedResults.BadRequest(new Problem(
                "Upload the package as multipart form data: a 'package' file, a 'publicKey' field, and a 'signature' field."));
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var media)
            || string.IsNullOrEmpty(media.Boundary.Value))
            return TypedResults.BadRequest(new Problem("The multipart request carries no boundary."));
        var boundary = media.Boundary.Value;

        // The package ceiling is the one the install spine enforces, so the
        // refusal an over-limit upload sees carries the reason here rather
        // than a framework body limit upstream. The slack covers the
        // multipart framing; the spine's ceiling still fires first.
        var ceiling = lifecycle.MaxPackageBytes;
        context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>()
            ?.MaxRequestBodySize = ceiling + 64 * 1024;

        byte[]? package = null;
        string? publicKey = null;
        string? signature = null;
        string? fieldsRefusal = null;
        var reader = new MultipartReader(boundary, request.Body)
        {
            // A boundary line and the section headers are metadata, not
            // payload; a few kilobytes is generous and a megabyte is not.
            HeadersLengthLimit = 32 * 1024,
        };
        while (await reader.ReadNextSectionAsync(cancellationToken) is { } section)
        {
            string? fieldName = null;
            if (ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var disposition)
                && disposition.Name.HasValue)
                fieldName = disposition.Name.ToString();
            if (fieldName is null)
                continue;
            if (fieldName == "package")
            {
                // Streamed with the ceiling, not buffered whole: a lying
                // or absent Content-Length cannot grow the byte[].
                using var buffered = new MemoryStream();
                var buffer = new byte[64 * 1024];
                while (true)
                {
                    var read = await section.Body.ReadAsync(buffer, cancellationToken);
                    if (read == 0)
                        break;
                    if (buffered.Length + read > ceiling)
                        return TypedResults.Json(
                            new Problem(
                                $"The uploaded package is over the configured {ModuleLimits.MaxPackageBytesKey} " +
                                $"of {ceiling} bytes; refusing the install."),
                            statusCode: StatusCodes.Status413PayloadTooLarge);
                    await buffered.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
                package = buffered.ToArray();
            }
            else if (fieldName is "publicKey" or "signature")
            {
                // The small string fields ride the same sections; 64 KB is
                // far past any real key or signature and keeps a hostile
                // field from being an unbounded read.
                var value = await ReadFieldAsync(section, MaxFieldBytes, cancellationToken);
                if (value is null)
                    fieldsRefusal =
                        $"The '{fieldName}' field exceeds the {MaxFieldBytes / 1024} KB field limit.";
                else if (fieldName == "publicKey")
                    publicKey = value;
                else
                    signature = value;
            }
        }
        if (fieldsRefusal is not null)
            return TypedResults.BadRequest(new Problem(fieldsRefusal));
        if (package is null || package.Length == 0 || publicKey is null || signature is null)
            return TypedResults.BadRequest(new Problem(
                "Upload the package as multipart form data: a 'package' file, a 'publicKey' field, and a 'signature' field."));

        var operatorId = context.User.TryGetOperatorId()?.Value;
        try
        {
            var record = await lifecycle.InstallUploadedAsync(
                package, publicKey, signature, operatorId, cancellationToken);
            return TypedResults.Ok(record);
        }
        catch (InvalidOperationException ex)
        {
            return Rejected(ex);
        }
    }

    // The ceiling for the small string fields an upload carries beside the
    // package. Answers null when the field crossed it, so the caller
    // refuses with the reason instead of the read throwing.
    private const int MaxFieldBytes = 64 * 1024;

    private static async Task<string?> ReadFieldAsync(
        MultipartSection section, int limit, CancellationToken cancellationToken)
    {
        using var buffered = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await section.Body.ReadAsync(buffer, cancellationToken);
            if (read == 0)
                break;
            if (buffered.Length + read > limit)
                return null;
            await buffered.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
        return System.Text.Encoding.UTF8.GetString(buffered.ToArray());
    }

    // The install refusals that carry their own status: an over-ceiling
    // package is the caller's bytes (413), a registry that would not answer
    // in time is a dependency timeout (504). Everything else stays the
    // lifecycle's plain 400-with-reason.
    private static IResult Rejected(InvalidOperationException ex) => ex switch
    {
        ModulePackageTooLargeException => TypedResults.Json(
            new Problem(ex.Message), statusCode: StatusCodes.Status413PayloadTooLarge),
        ModuleDownloadTimeoutException => TypedResults.Json(
            new Problem(ex.Message), statusCode: StatusCodes.Status504GatewayTimeout),
        _ => TypedResults.BadRequest(new Problem(ex.Message)),
    };

    private static async Task<IResult> Uninstall(
        string name, HttpContext context, ModuleLifecycleService lifecycle)
    {
        var operatorId = context.User.TryGetOperatorId()?.Value;
        try
        {
            await lifecycle.UninstallAsync(name, operatorId);
            return TypedResults.NoContent();
        }
        catch (InvalidOperationException ex)
        {
            return Rejected(ex);
        }
    }

    /// <summary>
    /// The platform-matched plugin artifact a module.load task stages: the
    /// installed package's row for the implant's platform and arch. The
    /// operator console fetches these bytes and attaches them as the task's
    /// content -- the staging path stays the one every module.load already
    /// rode, and the transport layer needs no module knowledge.
    /// </summary>
    private static IResult PluginArtifact(
        string name, string platform, string arch, ModuleStore store)
    {
        if (string.IsNullOrWhiteSpace(platform) || string.IsNullOrWhiteSpace(arch))
            return TypedResults.BadRequest(new Problem("Platform and arch are required (the implant's own)."));
        var installed = store.Installed()
            .FirstOrDefault(held => string.Equals(held.Manifest.Name, name, StringComparison.OrdinalIgnoreCase));
        if (installed.Manifest is null)
            return TypedResults.NotFound(new Problem($"No installed module named '{name}'."));

        var resolved = store.ResolvePluginArtifact(installed.Manifest, platform.Trim(), arch.Trim());
        if (resolved is null)
            return TypedResults.NotFound(new Problem(
                $"Module '{name}' carries no plugin artifact for {platform}/{arch}."));
        return TypedResults.File(
            resolved.Value.Content,
            "application/octet-stream",
            fileDownloadName: Path.GetFileName(resolved.Value.Artifact.Path));
    }

    public sealed record Problem(string Detail);
}
