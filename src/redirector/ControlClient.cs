using System.Net.WebSockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;

namespace Rod.Redirector;

/// <summary>
/// The enrolled-mode control client (architecture.md Sec 8): dial home over
/// an outbound-only WebSocket, enroll once against the pre-provisioned
/// credential (persisting the minted node identity so enrollment never
/// repeats), then serve whatever rule sets arrive -- heartbeating build
/// provenance, reconnecting with a capped backoff when the link drops. A
/// named refusal (spent, revoked, retired) is terminal: the operator
/// intervenes, the process does not flap.
/// </summary>
internal sealed class ControlClient
{
    private static readonly TimeSpan Heartbeat = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan MinBackoff = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(60);

    private readonly Uri _controlUri;
    private readonly string? _credential;
    private readonly string _statePath;
    private readonly ForwarderSet _forwarders;
    private readonly TextWriter _log;
    private string? _appliedDigest;

    public ControlClient(
        Uri controlUri,
        string? credential,
        string statePath,
        ForwarderSet forwarders,
        TextWriter log)
    {
        _controlUri = controlUri;
        _credential = credential;
        _statePath = statePath;
        _forwarders = forwarders;
        _log = log;
    }

    /// <summary>
    /// Runs until cancelled or refused. Returns an exit code: 0 on a clean
    /// stop, 2 on a terminal refusal.
    /// </summary>
    public async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        var identity = NodeState.Load(_statePath);
        if (identity is null && _credential is null)
        {
            _log.WriteLine("rod-redirector: no state file and no -credential: nothing to enroll with.");
            return 2;
        }

        var backoff = MinBackoff;
        while (!cancellationToken.IsCancellationRequested)
        {
            var outcome = await ConnectOnceAsync(identity, _credential, cancellationToken);
            switch (outcome)
            {
                case Refused refused:
                    _log.WriteLine($"rod-redirector: the control plane refused this node ({refused.Reason}); retiring the process.");
                    await _forwarders.StopAllAsync();
                    return 2;

                case Enrolled enrolled:
                    // Carry the minted identity into the next connection:
                    // the credential is spent, so a fresh-enroll link that
                    // drops must reconnect with hello, not enroll again (a
                    // re-enroll answers "spent", which reads as terminal).
                    identity = enrolled.State;
                    backoff = MinBackoff;
                    continue;

                default:
                    // A dropped link: reconnect with backoff. The forwarders
                    // keep serving the last applied rules -- the data plane
                    // does not depend on the control plane being up.
                    break;
            }

            try
            {
                await Task.Delay(backoff, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            backoff = backoff + backoff > MaxBackoff ? MaxBackoff : backoff + backoff;
        }

        await _forwarders.StopAllAsync();
        return 0;
    }

    // The wrapper's message ("Unable to connect to the remote server") names
    // neither a refused port nor a failed handshake; walk the chain so each
    // layer's own sentence shows. Wrappers often re-quote the inner message,
    // so repeats collapse to one.
    private static string DescribeChain(Exception ex)
    {
        var parts = new List<string>();
        for (var e = ex; e is not null; e = e.InnerException)
        {
            var message = e.Message.Trim();
            if (!parts.Contains(message))
                parts.Add(message);
        }
        return string.Join(": ", parts);
    }

    private static bool IsTlsFailure(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
            if (e is AuthenticationException)
                return true;
        return false;
    }

    private abstract record Outcome;
    private sealed record Enrolled(NodeState State) : Outcome;
    private sealed record Refused(string Reason) : Outcome;
    private sealed record Dropped : Outcome;

    private async Task<Outcome> ConnectOnceAsync(NodeState? identity, string? credential, CancellationToken cancellationToken)
    {
        using var socket = new ClientWebSocket();
        try
        {
            await socket.ConnectAsync(_controlUri, cancellationToken);
        }
        catch (Exception ex) when (ex is WebSocketException or InvalidOperationException or OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
                return new Dropped();
            _log.WriteLine($"rod-redirector: control connect failed ({DescribeChain(ex)}); retrying");
            // The common lab failure that chain hides behind a wrapper: a
            // wss:// dial at the plain-HTTP shared tier. Name the fix in
            // operator terms rather than leaving "wrong version number" to
            // be decoded.
            if (string.Equals(_controlUri.Scheme, "wss", StringComparison.OrdinalIgnoreCase) && IsTlsFailure(ex))
                _log.WriteLine(
                    "rod-redirector: this looks like a TLS handshake against a plain-HTTP endpoint; the lab posture is ws:// (docs/operations/redirectors.md)");
            return new Dropped();
        }

        try
        {
            // The first message establishes identity: reconnect with the
            // persisted node secret, or enroll with the credential when no
            // identity exists yet.
            ControlMessage? first;
            NodeState? established = null;
            if (identity is not null)
            {
                await SendAsync(socket, new ControlMessage("hello",
                    NodeId: identity.NodeId, NodeSecret: identity.NodeSecret,
                    Version: BuildStamp.Version, Commit: BuildStamp.SourceCommit), cancellationToken);
                first = await ReceiveAsync(socket, cancellationToken);
                if (first?.Type == "refused")
                    return new Refused(first.Reason ?? "unknown");
                if (first is null || first.Type != "welcome")
                    return new Dropped();

            }
            else
            {
                await SendAsync(socket, new ControlMessage("enroll",
                    Credential: credential, Version: BuildStamp.Version, Commit: BuildStamp.SourceCommit), cancellationToken);
                first = await ReceiveAsync(socket, cancellationToken);
                if (first?.Type == "refused")
                    return new Refused(first.Reason ?? "unknown");
                if (first is null || first.Type != "enrolled" || first.NodeId is null || first.NodeSecret is null)
                    return new Dropped();
                established = new NodeState(first.NodeId, first.NodeSecret);
                // Persist the moment enrollment answers: the credential is
                // spent, so an identity that only exists in memory would
                // leave the node unenrollable after a crash.
                established.Save(_statePath);
                _log.WriteLine($"rod-redirector: enrolled as node {established.NodeId}; identity persisted to {_statePath}");
            }

            await ApplyRulesAsync(first!.Rules, socket, cancellationToken);

            // The steady state: heartbeats keep the server's stamps fresh,
            // incoming rule sets reconcile the forwarders. Unknown message
            // types are ignored -- the grammar grows only by addition.
            using var heartbeats = new CancellationTokenSource();
            var heartbeatTask = HeartbeatAsync(socket, heartbeats.Token);
            var receiveTask = Task.Run(async () =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var message = await ReceiveAsync(socket, cancellationToken);
                    if (message is null)
                        return;
                    if (message.Type == "rules")
                        await ApplyRulesAsync(message.Rules, socket, cancellationToken);
                }
            }, cancellationToken);

            await Task.WhenAny(receiveTask, heartbeatTask);
            heartbeats.Cancel();
            return established is not null ? new Enrolled(established) : new Dropped();
        }
        catch (WebSocketException)
        {
            return new Dropped();
        }
        catch (OperationCanceledException)
        {
            return new Dropped();
        }
    }

    private async Task ApplyRulesAsync(RuleSetWire? rules, ClientWebSocket socket, CancellationToken cancellationToken)
    {
        if (rules?.Rules is null)
            return;

        // The digest is the reconcile key: a re-delivered set with the digest
        // already applied is a no-op, so pushes the node missed converge on
        // the next one and nothing restarts needlessly.
        if (rules.Digest is { Length: > 0 } digest && digest == _appliedDigest)
            return;

        await _forwarders.ApplyAsync(rules.Rules);
        _appliedDigest = rules.Digest;
        _log.WriteLine($"rod-redirector: applied {rules.Rules.Count} rule(s), digest {rules.Digest}");
        if (rules.Digest is { Length: > 0 } acked)
            await SendAsync(socket, new ControlMessage("ack", Digest: acked), cancellationToken);
    }

    private async Task HeartbeatAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(Heartbeat, cancellationToken);
            await SendAsync(socket,
                new ControlMessage("heartbeat", Version: BuildStamp.Version, Commit: BuildStamp.SourceCommit),
                cancellationToken);
        }
    }

    private static async Task SendAsync(ClientWebSocket socket, ControlMessage message, CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message, ControlJson.Default.ControlMessage);
        await socket.SendAsync(bytes, WebSocketMessageType.Text, true, cancellationToken);
    }

    // Returns null when the socket closed cleanly (the server hung up).
    private static async Task<ControlMessage?> ReceiveAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        while (true)
        {
            var received = await socket.ReceiveAsync(new ArraySegment<byte>(chunk), cancellationToken);
            if (received.MessageType == WebSocketMessageType.Close)
                return null;

            buffer.Write(chunk, 0, received.Count);
            if (received.EndOfMessage)
                return JsonSerializer.Deserialize(Encoding.UTF8.GetString(buffer.ToArray()), ControlJson.Default.ControlMessage);
        }
    }
}
