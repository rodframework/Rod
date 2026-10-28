using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
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
            return TypedResults.BadRequest(new Problem(ex.Message));
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
        if (!request.HasFormContentType
            || request.Form.Files.GetFiles("package").Count == 0
            || request.Form.TryGetValue("publicKey", out var publicKey) == false
            || request.Form.TryGetValue("signature", out var signature) == false)
        {
            return TypedResults.BadRequest(new Problem(
                "Upload the package as multipart form data: a 'package' file, a 'publicKey' field, and a 'signature' field."));
        }

        var operatorId = context.User.TryGetOperatorId()?.Value;
        using var stream = new MemoryStream();
        await request.Form.Files.GetFiles("package")[0].CopyToAsync(stream, cancellationToken);
        try
        {
            var record = await lifecycle.InstallUploadedAsync(
                stream.ToArray(), publicKey!, signature!, operatorId, cancellationToken);
            return TypedResults.Ok(record);
        }
        catch (InvalidOperationException ex)
        {
            return TypedResults.BadRequest(new Problem(ex.Message));
        }
    }

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
            return TypedResults.BadRequest(new Problem(ex.Message));
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
