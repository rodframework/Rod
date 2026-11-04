
namespace Rod.Capabilities.Tunnel;

/// <summary>
/// The tunnel capability verbs (architecture.md Sec 5.2, Sec 14): bridging
/// operator traffic through an implant to hosts reachable only from the
/// implant's vantage -- the reach a pivot exists to provide. These verbs run
/// as live channels (architecture.md Sec 10.3, the streaming task shape): the
/// task's channel carries the tunnel's bytes both ways, so the traffic rides
/// the beacon stream the signed TaskRequest opened and is attributed to the
/// task end to end.
/// </summary>
/// <remarks>
/// Concrete behavior for these verbs is not part of this repository -- it lives
/// in the implant and is captured as task output over the beacon stream
/// (architecture.md Sec 10.3). Here they are descriptors only: enough for the
/// registry to know the verb exists and for the task-issuance gate to resolve
/// it. The tunnel verbs carry a <c>touches-network</c> OPSEC attribute
/// (architecture.md Sec 7) since each opens a network connection from the
/// target.
/// </remarks>
public static class TunnelCapabilities
{
    /// <summary>
    /// Forward a TCP connection: the arguments are <c>&lt;host&gt;
    /// &lt;port&gt;</c>; the implant connects from its own vantage and the
    /// task's channel bridges the operator's bytes to the peer.
    /// </summary>
    public const string Forward = "tunnel.forward";

    /// <summary>
    /// Run a SOCKS proxy over the channel: the arguments are empty (each
    /// proxied connection's destination arrives in the channel's own
    /// connection-multiplexed grammar, one open packet per connection); the
    /// implant dials each destination from its own vantage and the channel
    /// carries every connection under its id, so unmodified tooling reaches
    /// arbitrary hosts through the one task (Sec 14).
    /// </summary>
    public const string Socks = "tunnel.socks";

    /// <summary>
    /// Bind a chained-contact listener: the arguments are <c>&lt;host&gt;
    /// &lt;port&gt;</c> (port 0 asks the stack to pick; the channel's first
    /// packet reports the actual address). The implant listens on its own
    /// vantage and the channel fronts the session it rides -- each accepted
    /// connection is one contact an implant on the far side of an egress-less
    /// segment runs against this teamserver, so the chain composes level over
    /// level toward the one host that reaches the edge (Sec 5.2, the pivot
    /// model's implant-side half).
    /// </summary>
    public const string Bind = "tunnel.bind";

    private static readonly IReadOnlyDictionary<string, string> TouchesNetwork =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["touches-network"] = "true",
        };

    /// <summary>
    /// Descriptors for every tunnel verb, in declared order. The composition
    /// root registers these so the registry lists the full tunnel set.
    /// </summary>
    public static readonly CapabilityDescriptor[] All =
    {
        CapabilityDescriptor.Of(Forward, CapabilityCategory.Tunnel, "1.0", TouchesNetwork),
        CapabilityDescriptor.Of(Socks, CapabilityCategory.Tunnel, "1.0", TouchesNetwork),
        CapabilityDescriptor.Of(Bind, CapabilityCategory.Tunnel, "1.0", TouchesNetwork),
    };

    /// <summary>Every tunnel verb string, in declared order.</summary>
    public static readonly string[] Verbs =
    {
        Forward,
        Socks,
        Bind,
    };
}
