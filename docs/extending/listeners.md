# Adding a listener

The listener extension contract: how a new C2 carrier joins Rod, in any
language, without touching the kernel. The design authority is
[architecture.md Sec 8](../architecture.md) and ADR-025 (Sec 15.3); this
document is the builder's manual for the shape they name.

> **Transition note.** This is the ADR-025 target contract. Until the
> migration completes, the in-tree families still run on the in-process
> provider seam documented in [transports.md](transports.md); that document
> retires when the kernel's implant ingress does.

## The model

One noun, two stages. The **listener package** is the published, static
artifact -- the protocol implementation, authored in any language, released
like any other ecosystem package (`rod-listener-<name>`, ADR-024). The
**listener** is the running instance an operator starts against an
engagement: the package plus its medium parameters, its engagement scope,
and its audit trail. The console, the API, and the audit events speak
"listener" only; "package" names what the registry distributes.

A listener process is a **per-peer byte pipe**. It turns its medium into
byte streams and nothing more:

- one distinguishable medium peer -- a chat user, a mail sender, an ICMP
  id, a held socket -- is one bridge stream, opened when the peer first
  appears and closed when it goes;
- bytes cross both ways opaquely; the listener process parses no rod.v1
  grammar, holds no engagement key, learns no implant identity, and
  carries no engagement data;
- the medium's own credentials (a bot token, an account) are the
  listener's configuration and its alone.

The application-layer seal crosses the pipe intact. That is the design's
security position, the same wall the L4 redirector data plane kept: the
kernel decrypts, the listener carries. A listener's compromise exposes its
medium credentials and nothing else -- no keys, no sessions, no engagement
data to leak.

## The bridge

The listener process speaks the bridge carriage to the kernel over its
per-listener local socket: a duplex stream of self-delimited messages
(the same varint-length-prefixed framing the raw-TCP family carries), one
connection per medium peer. The peer's first byte selects the carriage:

- **`C` -- the contact stream.** The rod.v1 `Beacon.Contact` carriage:
  each message is one contact body (the same delimited-frame bodies the
  envelope carries, sealed or plaintext), served by the same bridge core
  the raw-TCP family runs. Enrollment rides the opening message as an
  `EnrollRequest` frame -- no second interface, no second protocol. A
  held-stream build (the live session) holds the connection instead of
  cycling it. A byte-pipe listener relays these bodies without parsing
  them; a listener whose medium natively carries them (a held socket)
  splices.
- **`R` -- the route-forward carriage.** The https shape: one
  request/answer unit per message, and a unit is a **field map** -- a
  counted run of length-prefixed, string-keyed fields with opaque byte
  values, nothing positional. The request carries `method`, `path`, and
  `body` beside the medium's observed peer facts (`peer`, `ua`, whatever
  the medium honestly observes -- an unknown key rides through ignored,
  so a new medium names a new fact without a format change); the kernel
  routes by path onto the same cores its own routes drive (the JSON
  enroll exchange, the envelope contact, and the web families' asset
  routes -- hooks, lures, artifact fetch) and answers `status`,
  `content-type`, and `body`. The listener terminates the medium's HTTP
  face and carries bytes; the kernel never sees the medium socket.

Why not gRPC: the repository dropped the HTTP/2 requirement when the
envelope endpoint retired the gRPC service, and the bridge keeps that
posture -- sealed contact bodies are opaque byte units (a `Contact(stream
Frame)` grammar cannot carry them without a listener that parses), and a
byte-pipe listener in any language implements the delimited carriage from
its standard library alone. The `service Beacon` declaration in
`src/teamserver/Rod.Protocol/protos/rod.proto` stays the logical
contract; the bridge carries the same stream over the same framing the
in-tree stream family runs.

- **Local child (the default):** the kernel spawns the listener process
  with the bridge socket in its environment; the socket is a Unix domain
  socket (a named pipe on Windows), permission-restricted to the kernel's
  user -- no port, no network stack, nothing for another process or host
  to reach. The environment carries three variables:
  `ROD_BRIDGE_SOCKET` (the socket to dial), `ROD_LISTENER_ID` (the
  listener's id), and `ROD_LISTENER_PARAMS` (the medium parameters the
  operator set at creation, as a JSON object).
- **Remote host (the edge):** the listener process faces the same local
  socket it always faces -- on an edge, the socket belongs to the edge
  host's own supervisor, and the process cannot tell an edge from the
  kernel. The one cross-network connection is the edge's single
  multiplexed TLS link to the kernel, carrying every listener's every
  peer stream, and its direction is a deployment choice, not an
  assumption: **edge dials home** (the default, the redirector fleet's
  model) or **kernel dials out** -- the teamserver initiates outbound to
  an edge that listens on two faces, its bridge and its implants'
  contacts, so a teamserver sited on an internal network with no inbound
  reach still serves a public edge; the target network only ever sees the
  edge, and a burned edge is replaced without touching the internal
  server. Both directions authenticate mutually, on the fleet's
  enrollment and credential model. A dropped link closes the bridge
  streams and nothing else -- the listener processes keep running, the
  kernel loses no session state, and the reconnect re-establishes both.

Lifecycle is process management, not protocol: the kernel spawns,
restarts on exit, and reads the exit code as the health signal. A crashed
listener process marks its listener unhealthy and nothing else -- no
session state lived in it, so a restart loses nothing the next contact
does not re-establish. Connection parameters (edge address, direction,
credentials) live on the deployment's node record; an engagement's
listener only attaches to the node, inheriting the redirector fleet's
separation -- deployment capacity, attachment grants scope.

The web families' asset routes (hooks, lures, artifact fetch) are the one
addition: the `https` listener forwards them to the kernel's operator tier
by path. A carrier with no asset surface ignores this entirely.

## The four-piece package

A listener package is four artifacts, and none of them is implant-side
code:

1. **The server process** -- the byte pipe over your medium, in any
   language that can speak gRPC.
2. **The medium contract** -- the document an implant author reads to
   write their own dial glue: how bytes are packaged into the medium
   (packing rule, encoding), how peers are distinguished, what the contact
   cadence parameters mean, and what the carrier cannot carry (live
   channels if the medium is store-and-forward). This is the package's
   contract the way each family's section in
   [implants.md](implants.md) is the wire contract's.
3. **The config schema** -- the medium parameters a listener carries
   (name, type, secret or not, description). These become listener
   configuration and, where per-artifact, config-block fields.
4. **The conformance test** -- a script driving the package's own medium
   contract against the bridge: enroll, contact, task round trip. The
   `rod conform` provider lane runs it before a package may name itself a
   carrier.

Implant-side dial code is deliberately absent. The per-language half that
is worth maintaining is the **language kit** (below) -- one per language,
shared by every listener package; the per-package half is an implant
author's few dozen lines of medium glue written from the medium contract.
An author may publish reference glue for a favorite language as a
convenience; it is not part of the contract, and conformance never
requires it.

## Declarations the kernel enforces

Three declarations ride the package manifest (`[listener]` in
`rod-module.toml`, entry kind `listener`), and the kernel checks them
rather than trusting them:

- **Identity and seal tier** -- `sealed` (contacts carry the per-artifact
  key's seal end to end) or `id-only`. A carrier whose bytes rest on
  third-party infrastructure (`third-party-medium = true`: chat, mail,
  CDN) must declare `sealed`; the manifest is refused at publish and the
  kernel's catalog refuses it again at resolve. Point-to-point carriers
  on an operated segment may declare `id-only`, with the posture
  documented in the medium contract.
- **Channel support** -- `native` (a live stream), `degraded`
  (store-and-forward over the poll unit), or `none`, the same honesty the
  carrier table kept: channel verbs claim only on a carrier that can
  carry them, and the roster badges the difference.
- **The spawn contract** -- `command` and `args`: the process the
  supervisor runs inside the installed package directory. The
  `[[listener.params]]` rows beside them are the config schema, the
  medium parameters an operator sets at listener creation (a `secret`
  row is one the console never echoes back).

Enrollment is a listener tier, not a package's: `strict` (deploy-token
redemption, the default) or `open` (anonymous, scoped by the listener's
engagement -- the shellcatch exposure model, marked in the console).

## Language kits

The implant-side half of every listener package is one kit per language:
rod.v1 protobuf code generation, the seal (AES-256-GCM, the counter floor,
the session-key arm), frame assembly, and the shared task grammar -- the
parts identical for every carrier. Official kits: Rust and Go, extracted
from the reference implants. Community kits claim `rod-kit-<lang>` and
serve every package equally. A from-scratch implant is a kit plus medium
glue plus tradecraft; that is the whole wire obligation
([implants.md](implants.md) carries the tier detail).

## Checklist

1. Pick the wire name, the seal tier, and the channel support your medium
   honestly has.
2. Write the server process against the bridge; it carries bytes, nothing
   else.
3. Write the medium contract -- an implant author builds from this
   document alone.
4. Declare the config schema and register the package
   (`rod-listener-<name>`, `rod mod publish`).
5. Ship the conformance test; the provider lane must pass before the
   package names itself a carrier.
