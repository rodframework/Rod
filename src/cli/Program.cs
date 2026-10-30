namespace Rod.Cli;

/// <summary>The rod binary's entry; everything real happens in
/// <see cref="RodCli"/> so the tests drive the identical path in-process.</summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
        => await RodCli.RunAsync(args, Console.Out, Console.Error);
}
