// Rod.Redirector is the in-tree reference redirector (architecture.md Sec 8,
// ADR 0009/0011). It is a near-stateless, opaque L4 TCP forwarder that fronts a
// teamserver listener: an implant dials this redirector's public endpoint, and
// the redirector splices the byte stream to the listener's bind address without
// inspecting or altering it. Because it forwards at L4, the mTLS beacon channel
// (HTTP/2 + client cert) and the HTTPS enroll request both pass through end to
// end -- the redirector never terminates transport, so it cannot break the
// client-certificate authentication the beacon depends on.
//
// This is benign plumbing: a standard TCP relay (socat/rinetd semantics) on the
// mainstream-technique side of the boundary (architecture.md Sec 13): no evasion, no payload awareness. A burned
// redirector is swapped by deploying a fresh one and repointing the listener
// (POST /listeners/{id}:repoint); this binary is the missing half of that
// rotation, the teamserver-side repoint being the other.

using System.Net;
using Rod.Redirector;

using var cts = new CancellationTokenSource();
// Ctrl-C / SIGTERM stop the accept loop so in-flight copies drain. The handlers
// guard against ObjectDisposedException: on a normal exit the `using` disposes
// cts before Main returns, and ProcessExit then fires after disposal, so a bare
// Cancel would throw on the way out. Swallowing that keeps every exit path clean.
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    TryCancel(cts);
};
AppDomain.CurrentDomain.ProcessExit += (_, _) => TryCancel(cts);

static void TryCancel(CancellationTokenSource cts)
{
    try
    {
        cts.Cancel();
    }
    catch (ObjectDisposedException)
    {
    }
}

RedirectorConfig config;
try
{
    config = RedirectorConfig.Parse(args);
}
catch (ExitProgramException ex)
{
    // ExitProgramException carries an explicit message only when there is
    // something to print beyond what Parse already wrote (e.g. -h already
    // printed usage). An empty message means "already reported, stay quiet".
    if (ex.Message is { Length: > 0 } msg)
        Console.Error.WriteLine("rod-redirector: " + msg);
    return ex.ExitCode;
}

// Self-report provenance: the first log line names the exact source tree this
// binary was built from, so a deployed redirector identifies itself instead of
// relying on deployment notes. The same pair answers on the -version flag.
Console.Error.WriteLine($"rod-redirector {BuildStamp.Version} (commit {BuildStamp.SourceCommit})");

if (config.HasControl)
{
    // Enrolled mode (architecture.md Sec 8): dial home, enroll once, serve
    // the pushed rules. The process outlives link drops -- the forwarders
    // keep splicing the last applied rules while the control client
    // reconnects with backoff.
    await using var forwarders = new ForwarderSet(Console.Error);
    var client = new ControlClient(
        new Uri(config.ControlUri!), config.Credential, config.StatePath, forwarders, Console.Error);
    return await client.RunAsync(cts.Token);
}

var forwarder = new Forwarder(
    new IPEndPoint(config.ListenAddress, config.ListenPort),
    config.UpstreamHost,
    config.UpstreamPort,
    config.Allow,
    Console.Error);

forwarder.Start();
try
{
    await forwarder.RunAsync(cts.Token);
}
catch (OperationCanceledException)
{
    // Clean shutdown via Ctrl-C/SIGTERM.
}
return 0;
