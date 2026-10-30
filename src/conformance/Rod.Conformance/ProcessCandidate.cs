using System.Diagnostics;

namespace Rod.Conformance;

/// <summary>
/// A candidate as an arbitrary process -- the shape the standalone runner
/// drives. The target rides the documented candidate environment
/// (extending/implants.md, "Conformance harness"): <c>ROD_ENROLL_URL</c>,
/// <c>ROD_DEPLOY_TOKEN</c>, and -- for the kill-date phase --
/// <c>ROD_KILL_DATE</c> -- the same dev shape the reference implant reads.
/// Extra environment tunes the candidate's own knobs; the target variables
/// are applied after it and win, so a candidate is always pointed at the
/// phase's own front and credential.
/// </summary>
public sealed class ProcessCandidate : IImplantCandidate
{
    private readonly string _binary;
    private readonly IReadOnlyDictionary<string, string> _environment;
    private Process? _process;

    public ProcessCandidate(string binary, IReadOnlyDictionary<string, string>? environment = null)
    {
        _binary = binary;
        _environment = environment ?? new Dictionary<string, string>();
    }

    public Task StartAsync(ConformanceTarget target)
    {
        if (_process is { HasExited: false })
            throw new InvalidOperationException("The candidate is already running.");

        var psi = new ProcessStartInfo
        {
            FileName = _binary,
            // The candidate's own directory: a candidate loading sibling
            // files finds them without a tree checkout around it.
            WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(_binary))!,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var (key, value) in _environment)
            psi.Environment[key] = value;
        psi.Environment["ROD_ENROLL_URL"] = target.EnrollUrl;
        psi.Environment["ROD_DEPLOY_TOKEN"] = target.DeployToken;
        if (target.KillDate is { } killDate)
            psi.Environment["ROD_KILL_DATE"] = killDate.ToString("O");
        _process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start the candidate '{_binary}'.");
        // Drain both pipes so a chatty candidate cannot stall on a full one;
        // nothing consumes the lines -- a failed clause's verdict names the
        // cause, and a quiet candidate is the conforming posture.
        _process.OutputDataReceived += (_, _) => { };
        _process.BeginOutputReadLine();
        _process.ErrorDataReceived += (_, _) => { };
        _process.BeginErrorReadLine();
        return Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        if (_process is null)
            return;
        if (!_process.HasExited)
        {
            try { _process.Kill(entireProcessTree: true); } catch { }
            await _process.WaitForExitAsync(CancellationToken.None);
        }
        _process.Dispose();
        _process = null;
    }

    public bool HasExited => _process is null || _process.HasExited;

    public void Dispose() => StopAsync().GetAwaiter().GetResult();
}
