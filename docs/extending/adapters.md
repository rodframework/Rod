# Adding a listener adapter

The listener extension contract: how a new C2 carrier joins Rod, in any
language, without touching the kernel. The design authority is
[architecture.md Sec 8](../architecture.md) and ADR-025 (Sec 15.3); this
document is the builder's manual for the shape they name.

> **Transition note.** This is the ADR-025 target contract. Until the
> migration completes, the in-tree families still run on the in-process
> provider seam documented in [transports.md](transports.md); that document
> retires when the kernel's implant ingress does.

## The model

Two nouns, two audiences. The **adapter** is the registry package -- the
protocol implementation, authored in any language, published like any other
ecosystem package (`rod-adapter-<name>`, ADR-024). The **listener** is the
operator's word: a running binding of one adapter, its medium parameters,
its engagement scope, and its audit trail -- the image-to-container
relationship. The console, the API, and the audit events speak "listener"
only; "adapter" lives in documents like this one.

An adapter is a **per-peer byte pipe**. It turns its medium into byte
streams and nothing more:

- one distinguishable medium peer -- a chat user, a mail sender, an ICMP
  id, a held socket -- is one bridge stream, opened when the peer first
  appears and closed when it goes;
- bytes cross both ways opaquely; the adapter parses no rod.v1 grammar,
  holds no engagement key, learns no implant identity, and carries no
  engagement data;
- the medium's own credentials (a bot token, an account) are the adapter's
  configuration and its alone.

The application-layer seal crosses the pipe intact. That is the design's
security position, the same wall the L4 redirector data plane kept: the
kernel decrypts, the adapter carries. An adapter's compromise exposes its
medium credentials and nothing else -- no keys, no sessions, no engagement
data to leak.

## The bridge

The adapter speaks gRPC to the kernel: the `rod.v1 Beacon.Contact` stream
already defined in `src/teamserver/Rod.Protocol/protos/rod.proto` (compile
it with your own toolchain). Enrollment rides the same stream as an
`EnrollRequest` frame -- there is no second interface and no second
protocol to learn.

- **Local child (the default):** the kernel spawns the adapter with the
  bridge socket path in its environment; the socket is a Unix domain socket
  (a named pipe on Windows), permission-restricted to the kernel's user.
- **Remote host (the edge):** the same stream over TLS, carried by the edge
  node's control connection (ADR-025).

Lifecycle is process management, not protocol: the kernel spawns, restarts
on exit, and reads the exit code as the health signal. A crashed adapter
marks its listener unhealthy and nothing else -- no session state lived in
it, so a restart loses nothing the next contact does not re-establish.

The web families' asset routes (hooks, lures, artifact fetch) are the one
addition: the `https` adapter forwards them to the kernel's operator tier
by path. An adapter carrying no asset surface ignores this entirely.

## The four-piece package

An adapter package is four artifacts, and none of them is implant-side
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
shared by every adapter; the per-adapter half is an implant author's few
dozen lines of medium glue written from the medium contract. An author may
publish reference glue for a favorite language as a convenience; it is not
part of the contract, and conformance never requires it.

## Declarations the kernel enforces

Two declarations ride the package manifest, and the kernel checks both
rather than trusting either:

- **Identity and seal tier** -- `sealed` (contacts carry the per-artifact
  key's seal end to end) or `id-only`. A carrier whose bytes rest on
  third-party infrastructure (chat, mail, CDN) must declare `sealed`; the
  kernel refuses the package otherwise. Point-to-point carriers on an
  operated segment may declare `id-only`, with the posture documented in
  the medium contract.
- **Channel support** -- `native` (a live stream), `degraded`
  (store-and-forward over the poll unit), or `none`, the same honesty the
  carrier table kept: channel verbs claim only on a carrier that can carry
  them, and the roster badges the difference.

Enrollment is a listener tier, not a package's: `strict` (deploy-token
redemption, the default) or `open` (anonymous, scoped by the listener's
engagement -- the shellcatch exposure model, marked in the console).

## Language kits

The implant-side half of every adapter is one kit per language:
rod.v1 protobuf code generation, the seal (AES-256-GCM, the counter floor,
the session-key arm), frame assembly, and the shared task grammar -- the
parts identical for every carrier. Official kits: Rust and Go, extracted
from the reference implants. Community kits claim `rod-kit-<lang>` and
serve every adapter equally. A from-scratch implant is a kit plus medium
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
   (`rod-adapter-<name>`, `rod mod publish`).
5. Ship the conformance test; the provider lane must pass before the
   package names itself a carrier.
