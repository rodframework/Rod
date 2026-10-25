using System.Runtime.InteropServices;

namespace Rod.Integration.Tests;

/// <summary>
/// The host this suite runs on, as one cell of the build contract's target
/// grid: the CI matrix stands a runner on each OS/arch pair, and the e2e
/// legs that build an artifact for -- and run it on -- the host name their
/// target through this instead of a hard-coded linux/amd64. The same suite
/// then proves whichever cell it lands on (architecture.md Sec 12.2, the
/// end-to-end legs).
/// </summary>
internal static class TestCell
{
    /// The contract's spelling of the host OS. The build units normalize
    /// the synonyms; this is the one every cell agrees on.
    public static readonly string Os =
        OperatingSystem.IsWindows() ? "windows"
        : OperatingSystem.IsMacOS() ? "macos"
        : "linux";

    public static readonly string Arch =
        RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "amd64",
            Architecture.Arm64 => "arm64",
            _ => throw new InvalidOperationException(
                $"the implant e2e grid carries no {RuntimeInformation.ProcessArchitecture} cell"),
        };

    /// The executable suffix the host expects: a Windows cell runs PE
    /// files whatever they are named, but the .exe suffix keeps the
    /// dev-shape builds and the artifact downloads the names the platform
    /// itself would give them.
    public static readonly string ExeSuffix = OperatingSystem.IsWindows() ? ".exe" : "";
}
