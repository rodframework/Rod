using System.Collections.Concurrent;
using Rod.CoreState.Tasks;

namespace Rod.CoreState.Transports;

// The tasking-capability truth for the contact carriers (architecture.md
// Sec 8, Sec 10.3). The set lives in core state for the same reason
// ChannelVerbs does: the transport layer's claim gates, the build pipeline's
// beacon validation, and the operator UI all need the same answer without a
// cross-layer dependency. The in-tree carriers declare themselves here; a
// carrier added beyond the in-tree set registers the same way, so the table
// stays open where a closed enumeration would force an edit per protocol.

/// <summary>
/// Whether a contact carrier can run a task that behaves as a live channel
/// (architecture.md Sec 10.3): a channel's input half needs a writer the
/// server can push to while the task runs. A native carrier holds one for
/// the connection's life; a degraded carrier is a poll shape that opts into
/// the store-and-forward discipline instead -- operator input parks until
/// the next contact delivers it, output batches the same way, and the
/// channel's latency is the contact interval (the deliberate, named
/// tradeoff, never a silent one).
/// </summary>
public enum ChannelSupport
{
    /// <summary>
    /// The carrier holds a live stream for the connection's life (the
    /// WebSocket beacon, the held pipe session): channel tasks claim natively,
    /// their input and output riding the stream that carried the task.
    /// </summary>
    Native,

    /// <summary>
    /// The carrier is a poll shape whose unit can carry channel traffic both
    /// ways (the envelope's request and response bodies): a channel verb may
    /// claim against it when the implant opted into the degraded discipline
    /// -- the admission the dispatch path takes from the session's
    /// advertisement, so a poll build that never opted in keeps the
    /// queue-for-a-native-carrier behavior.
    /// </summary>
    Degraded,

    /// <summary>
    /// The carrier is a poll shape whose unit cannot carry channel traffic
    /// (a datagram budget): a channel task is requeued untouched for a
    /// capable carrier to claim.
    /// </summary>
    None,
}

/// <summary>
/// The tasking capabilities one contact carrier declares. The per-response
/// frame budget stays on the carrier itself (a wire-format property), while
/// the claim policy is the table's -- the two decisions every poll path
/// makes, split where each half's truth lives.
/// </summary>
/// <param name="Channels">The carrier's channel support level.</param>
public sealed record CarrierCapabilities(ChannelSupport Channels);

/// <summary>
/// The outcome of the claim evaluation a poll carrier runs before taking a
/// dispatched task into its contact response.
/// </summary>
public enum ClaimDecision
{
    /// <summary>The carrier claims the task into this contact.</summary>
    Claim,

    /// <summary>
    /// The verb runs as a live channel and this carrier holds no stream to
    /// run one on: the task is requeued untouched for a native carrier to
    /// claim (architecture.md Sec 10.3).
    /// </summary>
    NeedsLiveChannel,

    /// <summary>
    /// The marshaled task exceeds the carrier's per-response budget: the
    /// task is requeued for a carrier whose framing can carry it.
    /// </summary>
    Oversize,
}

/// <summary>
/// The carrier capability table and the claim evaluation shared by every
/// poll path (the envelope contact, the DNS bridge, the message-pipe
/// bridge). One policy point instead of one copy per carrier: the deferral
/// reasons stay stable, and a carrier arriving later declares itself rather
/// than duplicating the gate.
/// </summary>
public static class TransportCapabilities
{
    /// <summary>The wire name of <see cref="BeaconStream"/>.</summary>
    public const string BeaconStreamName = "beacon-stream";

    /// <summary>The wire name of <see cref="Envelope"/>.</summary>
    public const string EnvelopeName = "envelope";

    /// <summary>The wire name of <see cref="Dns"/>.</summary>
    public const string DnsName = "dns";

    /// <summary>The wire name of <see cref="MessagePipe"/>.</summary>
    public const string MessagePipeName = "message-pipe";

    /// <summary>The wire name of <see cref="WireGuard"/>.</summary>
    public const string WireGuardName = "wireguard";

    /// <summary>The live beacon stream (the WebSocket beacon, the held
    /// socket session): the native channel carrier.</summary>
    public static readonly CarrierCapabilities BeaconStream = new(ChannelSupport.Native);

    /// <summary>The plain-HTTP envelope POST cycle: store-and-forward
    /// channels, carried on every contact (the artifact always advertises
    /// the capability).</summary>
    public static readonly CarrierCapabilities Envelope = new(ChannelSupport.Degraded);

    /// <summary>The DNS TXT datagram contact: poll only, datagram-sized --
    /// channels store-and-forward on the polls, the input riding TXT
    /// answers and the output chunking up as queries.</summary>
    public static readonly CarrierCapabilities Dns = new(ChannelSupport.Degraded);

    /// <summary>
    /// The self-delimited message framing the named-pipe and raw-TCP
    /// listeners share: a poll-mode build cycles one connection per contact
    /// with the store-and-forward channels carried on every exchange, and a
    /// stream-mode build holds the live session instead -- the handshake's
    /// live advertisement switches the server to the shared session runner.
    /// The poll shape is the degraded baseline this entry declares.
    /// </summary>
    public static readonly CarrierCapabilities MessagePipe = new(ChannelSupport.Degraded);

    /// <summary>The optional WireGuard transport's datagram contact: the
    /// envelope's frames sealed inside WireGuard-encrypted UDP, one exchange
    /// per contact -- the poll discipline on the datagram budget, with the
    /// store-and-forward channels riding the contacts (Sec 8, Sec 15.3
    /// ADR-004 as amended). Default-disabled; the carrier registers with the
    /// transport that serves it.</summary>
    public static readonly CarrierCapabilities WireGuard = new(ChannelSupport.Degraded);

    // Keyed by carrier wire name so a carrier the core does not know can
    // declare itself without editing this file; case-insensitive because the
    // name crosses operator input and persistence as a plain string.
    private static readonly ConcurrentDictionary<string, CarrierCapabilities> Carriers =
        new(StringComparer.OrdinalIgnoreCase)
        {
            [BeaconStreamName] = BeaconStream,
            [EnvelopeName] = Envelope,
            [DnsName] = Dns,
            [MessagePipeName] = MessagePipe,
            [WireGuardName] = WireGuard,
        };

    /// <summary>
    /// Declares a carrier's capabilities. An identical re-declaration is a
    /// no-op (a double registration is harmless); a conflicting one throws,
    /// because silently replacing a live carrier's capabilities would hide
    /// the mistake until dispatch.
    /// </summary>
    public static void Register(string carrier, CarrierCapabilities capabilities)
    {
        if (string.IsNullOrWhiteSpace(carrier))
            throw new ArgumentException("A carrier name is required.", nameof(carrier));
        ArgumentNullException.ThrowIfNull(capabilities);

        var existing = Carriers.GetOrAdd(carrier, capabilities);
        if (existing != capabilities)
            throw new InvalidOperationException(
                $"The carrier '{carrier}' is already declared with different capabilities.");
    }

    /// <summary>
    /// Looks a carrier up by wire name. An unknown name falls back to
    /// <see cref="ChannelSupport.None"/>: a carrier that never declared
    /// itself must not silently gain channel claiming -- the conservative
    /// answer is the safe one.
    /// </summary>
    public static CarrierCapabilities Find(string carrier)
    {
        if (!string.IsNullOrWhiteSpace(carrier) && Carriers.TryGetValue(carrier, out var found))
            return found;
        return new CarrierCapabilities(ChannelSupport.None);
    }

    /// <summary>
    /// Whether a dispatched task fits this carrier's contact: a channel verb
    /// needs a carrier that holds a live stream -- or, on a degraded carrier,
    /// the session's live advertisement, which the dispatch path passes as
    /// <paramref name="degradedChannels"/> (every current poll artifact
    /// advertises it; an artifact that does not keeps the deferral) --
    /// and the marshaled task must fit the carrier's per-response budget.
    /// The channel deferral wins over size, so the reason an operator reads
    /// never depends on which bound the task tripped first.
    /// </summary>
    public static ClaimDecision EvaluateClaim(
        CarrierCapabilities carrier,
        string verb,
        int wireSize,
        int maxBytes,
        bool degradedChannels = false)
    {
        if (ChannelVerbs.IsChannelVerb(verb)
            && carrier.Channels == ChannelSupport.None
            || ChannelVerbs.IsChannelVerb(verb)
                && carrier.Channels == ChannelSupport.Degraded
                && !degradedChannels)
            return ClaimDecision.NeedsLiveChannel;
        if (wireSize > maxBytes)
            return ClaimDecision.Oversize;
        return ClaimDecision.Claim;
    }
}
