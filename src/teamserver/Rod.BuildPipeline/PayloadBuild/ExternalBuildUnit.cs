using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Rod.Packaging;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// The external build unit (architecture.md Sec 6, ADR-021): a community
/// implant's build driver loaded from a build-unit module package. The
/// package's manifest declares its <c>[unit]</c> table -- the id the
/// pipeline routes by and the command it spawns -- and this unit is the
/// whole of the teamserver's involvement: it writes the request file, runs
/// the command, and reads the result. A new language's implant registers by
/// listing its package under <c>Build:ExternalUnits</c>; the teamserver
/// compiles none of it.
/// </summary>
/// <remarks>
/// <para>
/// The file contract: the command runs with its package directory as the
/// working directory, the request file's path in <c>ROD_BUILD_REQUEST</c>
/// (and as its first argument), and the result file's expected path in
/// <c>ROD_BUILD_RESULT</c>. The request (<see cref="ExternalBuildRequest"/>)
/// carries the unit id, the format and kind names, the target, the rendered
/// baked profile (the same <c>rod.profile.json</c> bytes the in-tree units
/// stage -- the language-neutral contract), and the resolved extension
/// overlays with their on-host source directories. The result
/// (<see cref="ExternalBuildResult"/>) names the artifact file relative to
/// the working directory; the pipeline reads the bytes and fingerprints
/// them itself, so a claimed digest is never trusted.
/// </para>
/// <para>
/// Failures are loud: a nonzero exit is a
/// <see cref="BuildUnitFailureException"/> carrying the command's output,
/// and a missing or malformed result file likewise. The timeout defaults to
/// twenty minutes (the in-tree Rust unit's own posture) and comes from the
/// manifest's <c>timeout-minutes</c>.
/// </para>
/// </remarks>
public sealed class ExternalBuildUnit : IBuildUnit
{
    /// <summary>The configuration key the external build-unit package
    /// directory list lives under.</summary>
    public const string ExternalUnitsSectionKey = "Build:ExternalUnits";

    private const int DefaultTimeoutMinutes = 20;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
    };

    private readonly string _id;
    private readonly string _command;
    private readonly int _timeoutMinutes;
    private readonly string _packageDirectory;

    private ExternalBuildUnit(string id, string command, int timeoutMinutes, string packageDirectory)
    {
        _id = id;
        _command = command;
        _timeoutMinutes = timeoutMinutes;
        _packageDirectory = packageDirectory;
    }

    public string UnitId => _id;

    /// <summary>
    /// Loads one external unit from its package directory: the manifest must
    /// parse whole and carry the <c>[unit]</c> table. Anything broken throws,
    /// naming the package and the field.
    /// </summary>
    public static ExternalBuildUnit Load(string directory)
    {
        var absolute = Path.GetFullPath(directory);
        var manifestPath = Path.Combine(absolute, ManifestToml.FileName);
        if (!File.Exists(manifestPath))
            throw new InvalidOperationException(
                $"External build unit directory '{absolute}' carries no {ManifestToml.FileName}; an entry in " +
                $"'{ExternalUnitsSectionKey}' must name a build-unit package.");

        var (manifest, errors) = ManifestToml.LoadFile(manifestPath);
        if (manifest is null)
            throw new InvalidOperationException(
                $"External build unit manifest '{manifestPath}' does not parse: {string.Join(" ", errors)}");

        if (manifest.Entry != ModuleEntryKind.BuildUnit)
            throw new InvalidOperationException(
                $"'{absolute}' is a {ModuleEntryKindNames.ToString(manifest.Entry)} package; " +
                $"{ExternalUnitsSectionKey} lists build-unit packages only.");

        var unit = manifest.Unit
            ?? throw new InvalidOperationException(
                $"External build unit '{manifest.Name}' carries no [unit] table; the id and the command are the spawn contract.");

        return new ExternalBuildUnit(
            unit.Id,
            unit.Command,
            unit.TimeoutMinutes ?? DefaultTimeoutMinutes,
            absolute);
    }

    public async Task<BuildArtifact> BuildAsync(BuildParams @params, CancellationToken cancellationToken = default)
    {
        var workDir = Path.Combine(Path.GetTempPath(), "rod-external-build-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workDir);
        try
        {
            // The request file: everything a unit needs, in the profile's own
            // neutral spelling -- the unit bakes the profile file itself, the
            // way the in-tree units stage it verbatim.
            var request = new ExternalBuildRequest(
                UnitId,
                ArtifactFormats.Name(@params.Format),
                PayloadKinds.Name(@params.Kind),
                @params.Target.OperatingSystem,
                @params.Target.Architecture,
                JsonNode.Parse(ProfileBake.Render(@params))!.AsObject(),
                (@params.Extensions ?? []).Select(e => new ExternalBuildExtension(
                    e.Name, e.Directory, e.Verbs.ToList())).ToList());
            var requestPath = Path.Combine(workDir, "rod.build.request.json");
            await File.WriteAllTextAsync(
                requestPath, JsonSerializer.Serialize(request, JsonOptions), cancellationToken);

            var resultPath = Path.Combine(workDir, "rod.build.result.json");

            // The spawn: the package directory is the working directory, the
            // request and result paths ride the environment, and the command
            // line is the shell's to interpret -- a build driver may be a
            // script, a container wrapper, or a binary with its own flags.
            var start = new ProcessStartInfo
            {
                FileName = OperatingSystem.IsWindows() ? "cmd" : "/bin/sh",
                WorkingDirectory = _packageDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.ArgumentList.Add(OperatingSystem.IsWindows() ? "/c" : "-c");
            start.ArgumentList.Add(_command);
            start.Environment["ROD_BUILD_REQUEST"] = requestPath;
            start.Environment["ROD_BUILD_RESULT"] = resultPath;

            using var process = Process.Start(start)
                ?? throw new BuildUnitFailureException(
                    $"External unit '{UnitId}': the shell could not start its command.");
            var reading = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var readingErrors = process.StandardError.ReadToEndAsync(cancellationToken);
            try
            {
                await process.WaitForExitAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                throw;
            }
            if (process.ExitCode != 0)
            {
                var output = await reading;
                var errorsText = await readingErrors;
                throw new BuildUnitFailureException(
                    $"External unit '{UnitId}' failed (exit {process.ExitCode}):\n{output}\n{errorsText}".Trim());
            }

            if (!File.Exists(resultPath))
                throw new BuildUnitFailureException(
                    $"External unit '{UnitId}' wrote no result at '{resultPath}'; the contract answers ROD_BUILD_RESULT.");

            var result = JsonSerializer.Deserialize<ExternalBuildResult>(
                    await File.ReadAllTextAsync(resultPath, cancellationToken), JsonOptions)
                ?? throw new BuildUnitFailureException(
                    $"External unit '{UnitId}' produced an unreadable result file.");

            var artifactPath = Path.IsPathRooted(result.ArtifactPath)
                ? result.ArtifactPath
                : Path.Combine(_packageDirectory, result.ArtifactPath);
            if (!File.Exists(artifactPath))
                throw new BuildUnitFailureException(
                    $"External unit '{UnitId}' named artifact '{result.ArtifactPath}', which does not exist.");

            var content = await File.ReadAllBytesAsync(artifactPath, cancellationToken);
            return BuildArtifact.Of(
                UnitId,
                artifactId: Guid.NewGuid(),
                @params,
                content,
                result.ContentType ?? "application/octet-stream",
                DateTimeOffset.UtcNow);
        }
        finally
        {
            try { Directory.Delete(workDir, recursive: true); } catch { }
        }
    }
}

/// <summary>
/// The request file an external build unit reads: the unit id, the format
/// and kind names, the target pair, the rendered baked profile (the same
/// JSON the artifact embeds as <c>rod.profile.json</c>), and the resolved
/// extension overlays with their on-host source directories.
/// </summary>
public sealed record ExternalBuildRequest(
    string UnitId,
    string Format,
    string Kind,
    string TargetOs,
    string TargetArch,
    JsonObject Profile,
    IReadOnlyList<ExternalBuildExtension> Extensions);

/// <summary>One extension overlay the request compiles in: the package
/// name, its source directory on this host, and the verbs it
/// registers.</summary>
public sealed record ExternalBuildExtension(
    string Name,
    string Directory,
    IReadOnlyList<string> Verbs);

/// <summary>
/// The result file an external build unit answers with: the artifact's path
/// (absolute, or relative to the package directory), its MIME hint, and the
/// build log lines the operator reads. The pipeline fingerprints the bytes
/// itself -- nothing here is trusted on trust.
/// </summary>
public sealed record ExternalBuildResult(
    string ArtifactPath,
    string? ContentType = null,
    IReadOnlyList<string>? BuildLog = null,
    IReadOnlyList<string>? Warnings = null);
