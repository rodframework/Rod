using System.Text.Json;
using System.Text.Json.Serialization;

namespace Rod.Redirector;

/// <summary>
/// The node's durable identity: the id and secret its enrollment minted,
/// persisted beside the binary so enrollment happens exactly once per
/// credential ("enroll once", architecture.md Sec 8). The file is the
/// credential -- it carries the node secret -- so it is written with
/// owner-only permissions where the platform supports them.
/// </summary>
internal sealed record NodeState(
    [property: JsonPropertyName("nodeId")] string NodeId,
    [property: JsonPropertyName("nodeSecret")] string NodeSecret)
{
    public static NodeState? Load(string path)
    {
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(path), ControlJson.Default.NodeState);
        }
        catch (JsonException)
        {
            // A corrupt state file reads as absent: the operator re-enrolls
            // with a fresh credential rather than the process crashing on a
            // file it cannot use.
            return null;
        }
    }

    public void Save(string path)
    {
        File.WriteAllText(path, JsonSerializer.Serialize(this, ControlJson.Default.NodeState));
        TryOwnerOnly(path);
    }

    // Best-effort tightening on the Unix deployments (the runbook's shape);
    // a no-op where the platform has no such notion.
    private static void TryOwnerOnly(string path)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return;
        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
