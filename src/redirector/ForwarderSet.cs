using System.Net;
using System.Net.Sockets;

namespace Rod.Redirector;

/// <summary>
/// One running rule server, whatever carriage it rides. The TCP forwarder
/// and the datagram relay share exactly this shape: bind in <see cref="Start"/>,
/// serve until the token cancels, and own nothing shared.
/// </summary>
internal interface IRuleServer
{
    /// <summary>Binds and returns the actual bound endpoint.</summary>
    IPEndPoint Start();

    Task RunAsync(CancellationToken cancellationToken);
}

/// <summary>
/// The rule-driven fleet of forwarders (architecture.md Sec 8): one server
/// per rule the control plane pushes -- the opaque L4 TCP splice, or the
/// datagram relay a dns front rides -- reconciled against the previous set:
/// new rules start, gone rules stop, changed rules restart. The set only
/// decides which sockets are open; every server stays protocol-blind.
/// </summary>
internal sealed class ForwarderSet : IAsyncDisposable
{
    private readonly TextWriter _log;
    private readonly Dictionary<string, Running> _running = [];

    private sealed record Running(IRuleServer Server, Task Run, CancellationTokenSource Stop, ForwardingRuleWire Rule);

    public ForwarderSet(TextWriter log)
    {
        _log = log;
    }

    public int RunningCount => _running.Count;

    /// <summary>
    /// Reconciles the running set against the pushed rules. Idempotent: a
    /// rule whose id and shape match one already running is left alone.
    /// Transports this binary cannot serve log and skip -- the set stays
    /// useful the day the control plane grows a carriage this build
    /// predates.
    /// </summary>
    public async Task ApplyAsync(IReadOnlyList<ForwardingRuleWire> rules)
    {
        var wanted = new Dictionary<string, ForwardingRuleWire>();
        foreach (var rule in rules)
        {
            if (!IsCarried(rule.Transport))
            {
                _ = _log.WriteLineAsync($"rod-redirector: rule {rule.RuleId} names transport '{rule.Transport}', which this build does not carry; skipped");
                continue;
            }

            wanted[rule.RuleId] = rule;
        }

        // Stop the gone and the changed first, so a relocated listen port
        // never collides with its own previous bind.
        foreach (var (id, running) in _running.ToList())
        {
            if (wanted.TryGetValue(id, out var rule) && running.Rule == rule)
                continue;

            _running.Remove(id);
            await StopAsync(running);
        }

        foreach (var (id, rule) in wanted)
        {
            if (_running.ContainsKey(id))
                continue;

            var server = ServerFor(rule);
            var stop = new CancellationTokenSource();
            try
            {
                server.Start();
            }
            catch (SocketException ex)
            {
                // A bind that fails (the port is taken, the address is not
                // this host's) kills that rule alone; the rest of the set and
                // the control channel stay up, and the next push retries.
                stop.Dispose();
                _ = _log.WriteLineAsync($"rod-redirector: rule {id} could not bind {rule.ListenHost}:{rule.ListenPort}: {ex.Message}");
                continue;
            }

            var run = Task.Run(() => server.RunAsync(stop.Token));
            _running[id] = new Running(server, run, stop, rule);
        }
    }

    /// <summary>Stops every server and drains its serve loop.</summary>
    public async Task StopAllAsync()
    {
        foreach (var (id, running) in _running.ToList())
        {
            _running.Remove(id);
            await StopAsync(running);
        }
    }

    public async ValueTask DisposeAsync() => await StopAllAsync();

    private static bool IsCarried(string transport)
        => transport.Equals("tcp", StringComparison.OrdinalIgnoreCase)
            || transport.Equals("udp", StringComparison.OrdinalIgnoreCase);

    private IRuleServer ServerFor(ForwardingRuleWire rule)
    {
        var listen = new IPEndPoint(ParseListenAddress(rule.ListenHost), rule.ListenPort);
        var allow = SplitAllow(rule.AllowList) is { } entries
            ? CidrAllowList.Parse(entries)
            : CidrAllowList.AllowAll;
        return rule.Transport.Equals("udp", StringComparison.OrdinalIgnoreCase)
            ? new UdpForwarder(listen, rule.UpstreamHost, rule.UpstreamPort, allow, _log)
            : new Forwarder(listen, rule.UpstreamHost, rule.UpstreamPort, allow, _log);
    }

    private static async Task StopAsync(Running running)
    {
        running.Stop.Cancel();
        try
        {
            await running.Run;
        }
        catch (OperationCanceledException)
        {
            // The serve loop's clean exit.
        }

        running.Stop.Dispose();
    }

    private static string[]? SplitAllow(string? allowList)
        => string.IsNullOrWhiteSpace(allowList) ? null : allowList.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

    private static IPAddress ParseListenAddress(string host)
        => host is "*" or "0.0.0.0" ? IPAddress.Any
            : host is "::" or "::0" ? IPAddress.IPv6Any
            : IPAddress.Parse(host.TrimStart('[').TrimEnd(']'));
}
