using Rod.CoreState.Implants;

namespace Rod.CoreState.Tasks;

/// <summary>
/// The verbs whose tasks run as live channels rather than one-shot round
/// trips (architecture.md Sec 10.3, the streaming task shape). A channel task
/// is dispatched like any other -- the same signed TaskRequest, the same
/// queue -- but its TaskRequest opens a channel instead of a completion:
/// output streams back as ChannelOutput frames and operator input flows down
/// as ChannelInput frames on the beacon stream that carried the task, until
/// the final TaskResult closes it.
///
/// The set lives in core state because two outer layers need the same answer:
/// the DNS bridge must not claim a channel task (a datagram poll carries no
/// stream to run a channel on), and the operator input route admits input
/// only for a task whose verb is one of these. It is the wire-contract
/// companion of <see cref="ImplantClassCapabilities"/> -- the class table
/// says which implant may run a verb, this says how the verb's task behaves
/// once issued.
/// </summary>
public static class ChannelVerbs
{
    /// <summary>
    /// The interactive shell: <c>shell.exec</c>'s streaming shape. The
    /// arguments string is an optional initial command; the channel then
    /// carries the operator's input and the shell's output until the operator
    /// closes stdin or the shell exits.
    /// </summary>
    public const string ShellInteract = "shell.interact";

    /// <summary>
    /// The port-forward tunnel (architecture.md Sec 5.2, Sec 14): the
    /// arguments string is <c>&lt;host&gt; &lt;port&gt;</c>; the channel then
    /// bridges the operator's bytes to a TCP connection the implant opens from
    /// its own vantage and streams the peer's answers back, until the peer
    /// closes or the beacon stream ends. The same shape the shell rides -- the
    /// channel is byte-transparent, so the traffic's protocol is none of the
    /// wire contract's business.
    /// </summary>
    public const string TunnelForward = "tunnel.forward";

    /// <summary>
    /// The SOCKS proxy tunnel (architecture.md Sec 5.2, Sec 14): the channel's
    /// byte stream is the proxy's own connection-multiplexed grammar -- each
    /// proxied connection rides the one channel under a connection id, with
    /// each SOCKS CONNECT's destination carried in an open packet -- so
    /// unmodified tooling reaches arbitrary hosts through a single task. The
    /// operator side is a SOCKS listener bound onto the dispatched channel
    /// (the relay bind's proxy shape, Sec 10.1).
    /// </summary>
    public const string TunnelSocks = "tunnel.socks";

    /// <summary>
    /// The chained-contact bind (architecture.md Sec 5.2, the pivot model's
    /// implant-side half): the arguments string is <c>&lt;host&gt;
    /// &lt;port&gt;</c>, and the channel's byte stream is the link's own
    /// connection-multiplexed grammar -- the first packet reports the
    /// listener's actual address, each accepted connection rides the channel
    /// under its id, and the teamserver runs each as a contact server-side.
    /// A chained implant is an ordinary raw-TCP client of the listener, so
    /// the chain composes level over level toward the host that reaches the
    /// edge.
    /// </summary>
    public const string TunnelBind = "tunnel.bind";

    private static readonly string[] All = { ShellInteract, TunnelForward, TunnelSocks, TunnelBind };

    /// <summary>
    /// Whether <paramref name="verb"/>'s tasks run as live channels. Verb
    /// matching is case-insensitive, the same rule the class table and the
    /// registries honor.
    /// </summary>
    public static bool IsChannelVerb(string? verb)
    {
        if (string.IsNullOrWhiteSpace(verb))
            return false;
        foreach (var candidate in All)
        {
            if (string.Equals(candidate, verb, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
