using Rod.CoreState.Transports;
using Rod.Transport.Endpoints;

namespace Rod.Transport.Listeners.WireGuard;

// The wireguard transport's contact composition (architecture.md Sec 8,
// Sec 15.3 ADR-004 as amended): the envelope's own frames and seal riding
// WireGuard-encrypted UDP. One datagram is one poll contact -- the request
// payload is the envelope body (sealed under the per-artifact key by
// default), the answer the same composition the HTTP route serves, sealed
// back over the session the contact's handshake opened. The composition
// itself is the shared <see cref="EnvelopeContactCore"/>; this bridge names
// the carrier's facts: the datagram-sized dispatch budget, the wireguard
// capability entry, and the presence stamp the session records.

/// <summary>
/// Answers one wireguard contact payload. A refused contact (a body that
/// does not verify, a replayed counter) answers null: a datagram carrier
/// drops what the HTTP half would answer with a status code -- there is no
/// code space on the wire and no channel to explain on.
/// </summary>
internal sealed class WireGuardBeaconBridge
{
    /// <summary>
    /// The dispatched-tasking budget for one datagram: a WireGuard data
    /// packet carries at most 65,507 inner bytes (the IP packet's 16-bit
    /// total length less the 20-byte header and the tunnel's 32-byte
    /// overhead), and the response rides the same bound. Tasking beyond it
    /// stays queued for the next contact -- the DNS discipline, not the
    /// envelope's megabyte body budget.
    /// </summary>
    public const int MaxDispatchBytes = 60 * 1024;

    private readonly EnvelopeContactCore _core;

    public WireGuardBeaconBridge(EnvelopeContactCore core)
    {
        _core = core;
    }

    /// <summary>
    /// Runs one contact: the decapsulated inner payload in, the sealed
    /// answer out, or null when the contact is refused.
    /// </summary>
    public async Task<byte[]?> AnswerAsync(byte[] payload, CancellationToken cancellationToken)
    {
        var result = await _core.ContactAsync(
            payload,
            new EnvelopeContactOptions(
                MaxDispatchBytes,
                TransportCapabilities.Find(TransportCapabilities.WireGuardName),
                "wireguard",
                // No TLS notion rides a datagram socket: the seal
                // authenticates a keyed artifact, and an implant no key was
                // ever bound to stands by its handshake id -- the cleartext
                // lab posture, named as such.
                CleartextIdentityFallback: true),
            cancellationToken);

        return result.Status == 200 ? result.Body : null;
    }
}
