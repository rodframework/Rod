using System.Text;
using Rod.BuildPipeline.PayloadBuild;

namespace Rod.Integration.Tests;

/// <summary>
/// A build unit for the campaign tests: compiles nothing, answers with a
/// text artifact that names its bake -- including the enrollment
/// credential's secret, so a test playing the recipient can extract it from
/// the served artifact exactly the way a real implant carries it baked
/// inside. Registers as Go so it never collides with the Rust unit the
/// production host carries; the campaign tests swap the registry.
/// </summary>
internal sealed class CampaignStubBuildUnit : IBuildUnit
{
    public string UnitId => BuildUnitIds.Go;

    public Task<BuildArtifact> BuildAsync(BuildParams @params, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var manifest = new StringBuilder()
            .AppendLine("stub-campaign-artifact")
            .AppendLine($"class={@params.Class}")
            .AppendLine($"target={@params.Target.OperatingSystem}/{@params.Target.Architecture}")
            .AppendLine($"endpoint={@params.Transport.Endpoint}")
            .AppendLine($"token-secret={@params.TokenSecret}")
            .Append($"built-at={now:O}");
        var content = Encoding.UTF8.GetBytes(manifest.ToString());

        return Task.FromResult(BuildArtifact.Of(
            UnitId,
            artifactId: Guid.NewGuid(),
            @params,
            content,
            contentType: "application/octet-stream",
            builtAt: now));
    }
}
