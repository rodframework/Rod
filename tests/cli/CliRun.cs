namespace Rod.Cli.Tests;

/// <summary>
/// Drives the CLI's real entry in-process with captured writers, the same
/// <see cref="RodCli.RunAsync"/> the binary calls. Every path-taking verb
/// gets explicit paths from the test (never the working directory), so
/// parallel test classes cannot race through it.
/// </summary>
public sealed record CliRun(int Code, string Output, string Error)
{
    public static CliRun Run(params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var code = RodCli.RunAsync(args, output, error).GetAwaiter().GetResult();
        return new CliRun(code, output.ToString(), error.ToString());
    }
}

public sealed class TempRoot : IDisposable
{
    public string Path { get; }

    public TempRoot()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "rod-cli-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string this[params string[] parts] => System.IO.Path.Combine([Path, .. parts]);

    public void Dispose() => Directory.Delete(Path, recursive: true);
}
