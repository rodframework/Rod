# Adding a transport

The transport extension contract: how a new C2 carrier joins Rod, in-tree
or out. The design authority is [architecture.md Sec 8](../architecture.md);
this document is the builder's manual for the seams that section names.

## The model

A transport is three declarations, not a switch arm:

1. **The bind behavior** — `ITransportProvider`
   (`Rod.Transport.Listeners.Providers`): how a listener of this transport
   opens its socket, validates its bind address, reserves its port, and
   shapes its public endpoint.
2. **The carriers it serves** — wire names from the core-state capability
   table (`Rod.CoreState.Transports.TransportCapabilities`): what contact
   shapes the transport can carry, which is what the
   issuance gate reads.
3. **The registry entries** — `TransportProviders.Register(provider)` for
   the bind, `TransportCapabilities.Register` for any new carrier. Both are
   name-keyed, conflict-refusing, and conservative toward what never
   registered: an unregistered name answers "no channels" and binds
   nothing.

The in-tree five (`http`, `https`, `dns`, `tcp`,
`doh`) register in the static constructors and are the reference
implementations.
The optional sixth (`wireguard`) registers only when the deployment
enables it -- the default-disabled posture the platform's open-not-on
rule takes -- and is otherwise the same shape: a hosted-service provider
over the native router, the envelope's own frames inside the tunnel
([implants.md](implants.md)'s WireGuard section is its contract).
The listener record, the operator API, the persistence, and the restore path
all speak the wire name -- a registered transport is nameable the moment it
registers, with no core edits.

## The provider contract

```csharp
public interface ITransportProvider
{
    string Transport { get; }                     // the wire name
    IReadOnlyList<string> Carriers { get; }       // carriers served, by wire name
    string PublicEndpointScheme { get; }          // scheme for endpoint completion
    bool AcceptsPublicEndpoint(string text);      // the dial shape's validation
    string DescribePublicEndpointRule(string got);// the refusal that teaches
    void Validate(ListenerConfig config);         // 400-class bind-address checks
    void ReserveBind(ListenerConfig config);      // 409-class port reservation
    Task<BoundListener> BindAsync(                // bind, register, return
        TransportBindContext context, CancellationToken cancellationToken);
}
```

Two shared shapes cover the current family, and a transport that fits
neither implements the interface directly:

- **`KestrelEndpointProvider`** — the HTTP family: the listener rides
  Kestrel's endpoint-configuration reloader under a declared
  `ListenerTlsPosture` (scheme as data: plain or server-TLS). The
  per-transport
  differences are constructor parameters: the posture, the carriers, and
  (optionally) a public-endpoint shape other than the web dial.
- **`HostedServiceTransportProvider`** — the socket-owning family: each
  listener runs a hosted service built by a factory, with the bind shape
  (host:port, UDP vs TCP reservation) and the public-endpoint dial shape
  as data.

## The carrier table

```csharp
ChannelSupport: Native | Degraded | None
```

- **Native** — the transport holds a live stream; channel verbs claim on
  it.
- **Degraded** — a poll shape whose unit can carry channel traffic both
  ways by the store-and-forward discipline; every poll artifact
  advertises the handshake capability `channels.poll`, so channel verbs
  claim against any of its sessions. The DNS grammar rides here: input
  on the TXT answers, output as chunked queries.
- **None** — a carrier that cannot carry channel traffic at all; channel
  verbs never claim on it. No in-tree carrier declares this -- it is the
  registration slot for a shape the discipline genuinely cannot serve.

Registering a new carrier (`TransportCapabilities.Register(name, new
CarrierCapabilities(...))`) is the whole registration: everything
downstream -- the issuance gate, the enrollment's baked-carrier stamp --
reads the table, so no other edit is needed for that half.

The same split decides the dispatch strand (architecture.md Sec 10.3): a
transport that runs its contacts through `BeaconSessionRunner` -- the live
session shape -- carries the receive-ack ledger for free, requeueing
ack-less dispatches when the stream ends; a poll shape answers whole or
not at all, keeps no ack ledger, and accepts the `TaskAck` frame inertly
through the shared ingest. Both read the one wire contract; neither edits
core state.

## Identity and auth

A transport declares which of the two identity models its contacts
carry, by construction rather than by registry entry:

- **Application-layer key** (the web family and the keyed socket/datagram
  shapes): the per-artifact key seals the contact bodies; possession is
  the authentication.
- **Id alone** (the DNS/TCP family's plaintext posture): the
  egress-restricted tradeoff, documented in the contract per transport --
  the sealed shapes pair it with the application-layer seal, so the wire
  carries no frame bytes in the clear even where no TLS rides it.

A new transport picks one and says so in its XML docs and its
`extending/implants.md` section; the wire contract is the product, and the
contract doc is where an implant author reads what your transport promises.

## In-tree or out

The same registration serves both. In-tree transports follow the
sensitive-capability discipline (architecture.md Sec 13): standard,
documented, mainstream techniques ship in the core; anything novel --
protocol mimicry, unpublished evasion -- registers out-of-tree against
this same contract and never touches the repository. An out-of-tree
provider links `Rod.Transport` (or reimplements against the registry
semantics), registers at startup, and is nameable: the string spine makes
the core indifferent to who registered the name.

## Checklist

1. Pick the wire name and the carriers it serves.
2. Implement or parameterize a provider; register it in
   `TransportProviders` (in-tree) or at host start (out-of-tree).
3. Register any new carrier in `TransportCapabilities` with its honest
   `ChannelSupport`.
4. Write the wire contract section in `extending/implants.md` -- the
   frames, the auth, the bounds. The transport changes; the frame paths
   never do.
5. Pin it: a registry test for the carriers, a listener round-trip for
   the bind, and -- if the carrier is native -- an issuance test that
   claims a channel verb over a build against the new transport's front.
