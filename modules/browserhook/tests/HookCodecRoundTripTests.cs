using System.Diagnostics;
using System.Text.Json;

namespace Rod.Modules.BrowserHook.Tests;

/// <summary>
/// A fact that runs only when a Node runtime is on PATH: the golden-vector
/// smoke that pins the hook script's hand-rolled JavaScript codec against
/// the same wire bytes the .NET side produces.
/// </summary>
public sealed class NodeFactAttribute : FactAttribute
{
    public NodeFactAttribute()
    {
        try
        {
            var probe = Process.Start(new ProcessStartInfo
            {
                FileName = "node",
                ArgumentList = { "--version" },
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            probe?.WaitForExit(5000);
            if (probe is null || probe.ExitCode != 0)
                Skip = "node is not usable on PATH";
        }
        catch
        {
            Skip = "node is not on PATH";
        }
    }
}

/// <summary>
/// The codec's cross-language conformance, pinned against golden vectors:
/// contact bodies (handshake, result, exfil chunk frames) and a dispatched
/// task, encoded once by the .NET side of the wire contract and baked here
/// as constants. The script's codec -- sliced verbatim from the module's
/// own template between its marker comments, the whole dependency-free
/// region -- must parse and re-encode them byte-for-byte. The test rides
/// with the module: it pins module content against the wire contract, and
/// it holds the module to standing alone (no in-house references).
/// </summary>
public class HookCodecRoundTripTests
{
    // Encoded by Rod.Transport's frame encoder over the same messages; a
    // change on the .NET side that alters these bytes is a wire change, and
    // this test is where it must be felt deliberately.
    private const string ContactBody =
        "cRJvCgIIARIkMDEyMzQ1NjctODlhYi1jZGVmLTAxMjMtNDU2Nzg5YWJjZGVmGhNicm93c2VyLmZpbmdlcnByaW50Gg9icm93c2VyLmNvb2tpZXMaC2Jyb3dzZXIuZG9tMQAAAAAAAClAOQAAAAAAAPg/RBJCCiQxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEQARoYeyJ1c2VyQWdlbnQiOiJyb2QtdGVzdCJ9TRJJCiQxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTESDnNjcmVlbnNob3QucG5nGglpbWFnZS9wbmcoATIEAQIDBBgC";
    private const string TaskFrame =
        "TRJLCiQyMjIyMjIyMi0yMjIyLTIyMjItMjIyMi0yMjIyMjIyMjIyMjISDmJyb3dzZXIucHJvbXB0GhNFbnRlciB5b3VyIHBhc3N3b3Jk";

    [NodeFact]
    public async Task TheCodec_RoundTripsTheWireBytesTheDotNetSideProduces()
    {
        var template = await File.ReadAllTextAsync(Path.Combine(ModuleRoot(), "assets", "hook.js"));
        var start = template.IndexOf("// ---- byte helpers", StringComparison.Ordinal);
        var end = template.IndexOf("// ---- seal", StringComparison.Ordinal);
        Assert.True(start > 0 && end > start);
        var codec = template[start..end];

        var result = await NodeRunner.RunAsync($$"""
            const section = {{JsonSerializer.Serialize(codec)}};
            const vectors = {
              contactBody: {{JsonSerializer.Serialize(ContactBody)}},
              taskFrame: {{JsonSerializer.Serialize(TaskFrame)}},
            };
            eval(section);

            function bytes(b64) {
              return Uint8Array.from(Buffer.from(b64, 'base64'));
            }
            function b64(u8) {
              return Buffer.from(u8).toString('base64');
            }

            const frames = parseFrames(bytes(vectors.contactBody));
            const kinds = frames.map(f => f.kind);
            const reEncoded = b64(encodeFrames(frames));
            const task = parseTaskRequest(parseFrames(bytes(vectors.taskFrame))[0].payload);
            const handshake = parseHandshakeResponse(frames[0].payload);
            const resultBytes = taskResultBytes('33333333-3333-3333-3333-333333333333', true, 'out');
            console.log(JSON.stringify({
              frameCount: frames.length,
              kinds: kinds,
              roundTripExact: reEncoded === vectors.contactBody,
              taskVerb: task.verb,
              taskArguments: task.arguments,
              taskId: task.taskId,
              handshakeStatus: handshake.status,
              resultLen: resultBytes.length > 0,
            }));
            """);

        using var document = JsonDocument.Parse(result);
        var verdict = document.RootElement;
        Assert.Equal(3, verdict.GetProperty("frameCount").GetInt32());
        Assert.Equal(new[] { 0, 0, 2 }, verdict.GetProperty("kinds").EnumerateArray().Select(k => k.GetInt32()));
        Assert.True(verdict.GetProperty("roundTripExact").GetBoolean());
        Assert.Equal("browser.prompt", verdict.GetProperty("taskVerb").GetString());
        Assert.Equal("Enter your password", verdict.GetProperty("taskArguments").GetString());
        Assert.Equal("22222222-2222-2222-2222-222222222222", verdict.GetProperty("taskId").GetString());
        Assert.Equal(0, verdict.GetProperty("handshakeStatus").GetInt32());
        Assert.True(verdict.GetProperty("resultLen").GetBoolean());
    }

    private static string ModuleRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent!)
        {
            if (File.Exists(Path.Combine(directory.FullName, "rod-module.toml")))
                return directory.FullName;
        }
        throw new InvalidOperationException("Could not locate the module root from the test assembly.");
    }
}

file static class NodeRunner
{
    public static async Task<string> RunAsync(string script)
    {
        var file = Path.Combine(Path.GetTempPath(), $"rod-hook-smoke-{Guid.NewGuid():N}.cjs");
        await File.WriteAllTextAsync(file, script);
        try
        {
            var start = new ProcessStartInfo
            {
                FileName = "node",
                ArgumentList = { file },
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var process = Process.Start(start)!;
            var stdout = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            Assert.True(process.ExitCode == 0, $"node exited {process.ExitCode}: {await process.StandardError.ReadToEndAsync()}");
            return stdout.Trim();
        }
        finally
        {
            File.Delete(file);
        }
    }
}
