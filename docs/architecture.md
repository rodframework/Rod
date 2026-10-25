# Rod -- Architecture & Design

> **Status:** Living document. This is the agreed architecture for Rod as an
> authorized-use red-team operations platform. The repository
> holds the teamserver (the .NET control plane) and the Rust reference implant, with a Postgres persistence
> layer; [todo.md](todo.md) tracks open work. Sections marked _(future)_ are
> designed for but not yet implemented; Sec 15 records the program
> decisions (ADR-001 through ADR-015) that the todo queue serves.

## 1. Overview

Rod is an **authorized-use red-team operations platform** for
penetration tests and security research. A team of
operators drives a fleet of short-lived, disposable implants on authorized
targets from a central teamserver, reaching hosts behind NAT and firewalls over
implant-initiated connections; the external recon workbench scopes those
targets from the teamserver before the first foothold. Command-and-control
remains the load-bearing core -- the wire protocol, the implant fleet, the
listener tier -- but the platform's span runs from pre-foothold scoping to
the close-out evidence package, the span Sec 14's capability bar already
describes.

The design follows from a few load-bearing priorities, and the rest of this
document is their consequence. Implants are short-lived and untrusted by default,
each carrying a unique key -- never a global shared secret. OPSEC and evasion are
first-class design axes, not feature flags. Every action is attributed to an
operator and recorded in an immutable, hash-chained audit trail that doubles as
the report source. A lost implant fails safe: a baked-in kill date
self-terminates it. And the **Engagement** -- one authorized operation -- is the
unit of tenancy, isolation, authorization, and evidence.

## 2. Operational lifecycle (the organizing axis)

The architecture is organized around the red-team operational lifecycle, not
around "managed components". Each phase states what the platform must support.

1. **Planning and engagement setup.** Define the engagement: scope, ROE,
   and the member roster -- who works it, at which tier (Sec 4.5). The
   engagement is created as an isolation boundary.
2. **Infrastructure stand-up.** Provision teamserver, listeners, redirectors,
   domains, certificates. Infrastructure is **disposable and reprovisionable**;
   burn rate is expected, so it is config-driven and tear-down friendly.
3. **Payload generation and delivery.** Build per-implant artifacts with
   baked-in C2 endpoint, beacon parameters, and kill date; delivery rides the
   launcher one-liners.
4. **Delivery and initial access.** Rod delivers the lure itself where
   delivery is email-shaped: a tracked campaign (Sec 11.5) sends
   per-recipient messages whose links bind to per-recipient deploy tokens,
   so the first callback arrives already attributed to the campaign and
   the recipient. Host-interaction delivery (a dropped one-liner, manual
   execution) stays outside Rod; either way the platform must **ingest the
   first callback** and correlate it to the engagement. The content of
   social engineering -- pretext, evasion-grade lures, credential-harvest
   landing pages -- is module-domain work (Sec 13, Sec 15): the campaign
   carries the link and the attribution, not the tradecraft.
5. **Beaconing / contact.** The implant calls in; the teamserver authenticates
   it, queues tasks, and accepts results. Async beacon and interactive session
   are distinct modes.
6. **Post-exploitation tasking.** Operators issue tasks; the platform captures
   output and artifacts, attributes every action to an operator, and supports
   multiplayer.
7. **Lateral movement and persistence.** Spawn child implants, pivot, establish
   footholds -- treated as more generation plus more listeners, all recorded.
8. **Exfiltration.** Stage and transfer collected data over an audited path,
   every byte tied to a task and operator.
9. **Reporting and evidence.** The operation ends in a deliverable (timeline,
   findings, evidence). The audit trail is the **source for report generation**.
10. **Cleanup.** Retire implants, tear down infrastructure, **retain the
    immutable audit trail** -- it outlives the operation.

Every object (implant, task, artifact, infrastructure node) carries
`engagement_id` and `operator_id` from creation.

## 3. The Engagement model

Everything is organized around an **Engagement** -- the unit of tenancy,
isolation, authorization, and evidence. An engagement models one authorized
operation.

- An authenticated **Operator** creates an **Engagement**, recorded as its owner.
- **Implants** enrol into exactly one engagement; an implant's identity is bound
  to its engagement and is disposable with it.
- Access derives entirely from **membership** (Sec 4.5): the owner manages a
  member roster at two tiers -- `reader` (view everything, the live stream) and
  `writer` (task, operate, and manage the engagement's own surfaces) -- and a
  non-member cannot even see the engagement exists. Accountability still runs
  on the attributed audit trail; the membership model decides who gets to act,
  the trail records what they did.
- All domain data -- implants, sessions, tasks, results, artifacts, modules,
  audit -- is **scoped by engagement**. Cross-engagement access is impossible by
  construction.
- Identities, keys, and endpoints are **ephemeral per engagement**; there is no
  permanent enrollment. Tearing down an engagement severs its implants; the audit
  trail remains.

> Multi-tenancy is per-engagement isolation. An optional Organization layer
> above engagements can be added later without changing this boundary.

## 4. Component architecture -- monolithic kernel, layered

Rod is a **monolithic teamserver with strong internal logical layering**, plus
external build units and implants. A single .NET process (the teamserver) holds
the core; polyglot needs are met by decoupling at the build boundary (Sec. 6),
not by splitting the whole system into microservices.

A monolithic kernel gives a security-critical core one blast radius and one
state model, with low inter-component latency and the simplest deployment for a
small team. The parts that change most (implant builds, transports, tradecraft)
are already decoupled as build units, redirectors, and capability modules, so
hot-swapping is not lost; the alternative -- a container-per-concern split -- is
heavier to operate and secure for no current gain, so the strong *logical*
layering (enforced by architecture tests, below) is kept and a future move
toward services stays open. Polyglot implants are met by a uniform build
contract with one build unit per language (Sec. 6), so C#/.NET, Go, C/C++, and
Nim payloads compile from one language-agnostic control plane; a single implant
language was rejected because it forces one language onto every target class
(Windows in-memory tradecraft, cross-platform reach, and small footprint each
demand a different one). The stack itself is in Sec. 12.

### 4.1 The six internal layers

1. **Core state.** The implant/session registry, the task queue and history, and
   engagement/operator state. Authoritative and in-memory-or-DB-backed.
2. **Transport layer.** Listeners terminate C2 transports; redirectors front
   them. The listener and the public endpoint are decoupled so a burned
   redirector is replaceable without backend change. (Sec. 8.)
3. **Payload build pipeline.** Drives **external build units** to compile
   polyglot implants on demand through a uniform build contract. (Sec. 6.)
4. **Operator layer.** Authenticated, multiplayer operator sessions over the
   operator API; shared live engagement state; task ownership and attribution.
5. **Storage and audit.** Per-engagement, append-only, hash-chained audit and
   the artifact store. The evidence backbone. (Sec. 11.)
6. **Pluggable tradecraft.** Post-exploitation capability modules, including the
   evasion/exploit category contracts. (Sec. 10.)

Layers depend inward only: tradecraft and operator layers depend on core state
and audit; the build pipeline depends on core state; transport depends on core
state, the wire protocol, audit, and the build pipeline (it composes the audit
write and drives the build orchestrator); core state and audit depend on nothing
in-house. The dependency rule is enforced by architecture tests.

### 4.2 External components

- **Build units.** The in-tree build unit is Rust (`Rod.BuildPipeline`'s
  `RustBuildUnit`). It compiles the reference implant on demand and owns its
  toolchain, coupled to the teamserver only by the build contract. Other
  languages (Go, C/C++, Nim) stay available through that same contract and the
  `Language` enum, supplied as out-of-tree community units -- the project
  maintains one in-tree reference, not one per language (Sec 12.2).
- **Implants.** Target-resident, disposable, speaking the wire protocol and
  independent of the teamserver language. (Sec. 5.) The **reference Rust
  implant** lives in the `src/implant/rust` crate: a benign, readable
  long-haul implant that enrolls over any of the four families' fronts
  (submitting its own public key), contacts under the baked seal, and runs
  the standard-category verb set (Sec 10.1). The fielded artifact is
  terminal-silent by default -- nothing it prints on the host it runs on
  -- with diagnostics behind the `ROD_VERBOSE` opt-in for the operator's
  own testing (the e2e suite runs verbose so a failed leg's stderr says
  why). It
  compiles its wire bindings
  from the canonical `src/teamserver/Rod.Protocol/protos/rod.proto` at build time (no
  committed generated code), and `RustBuildUnit` bakes the per-implant
  profile in at compile time. The reference set it carries is the standard,
  documented tradecraft surface (Sec 13); anything beyond it arrives through
  the extension seams. The wire protocol is the language-neutral product, so a
  community
  implant in Go, C, or Nim builds against the same contract without coupling
  the teamserver to its language (Sec 12.2).
- **Redirectors.** Near-stateless forwarders (.NET, Native AOT, single static
  binary) for OPSEC
  and infra flexibility. No engagement state, no business logic. (Sec. 8.)
  The in-tree reference forwarder ships (`src/redirector/dotnet/`): an opaque
  L4 TCP splice published as a single static binary. Together with the
  server-side rotation path -- listener repoint
  (`POST /engagements/{engagementId}/listeners/{id}:repoint`)
  and retire with their audit writes -- a burned redirector is swapped
  end to end; see [operations/redirectors.md](operations/redirectors.md).
- **Operator CLI.** The `rod` binary (`src/cli/dotnet/`, .NET console):
  the `rod mod` module-lifecycle suite -- init, search, info, install,
  verify, publish -- over the ecosystem's file contracts (Sec 15.2). It
  references nothing in-house: like the redirector, it couples to the
  platform only through files (the manifest, the registry index, the lock
  file), so it builds and ships on its own and the contracts stay
  language-neutral.
- **Operator UI.** The web front end; lives in the teamserver project.

### 4.3 Source-tree map (`src/teamserver/`)

The teamserver is a single .NET solution (`Rod.slnx`) split into the projects
below. Six of them are the **internal layers** of §4.1; three are not layers and
sit alongside them -- `Rod.Protocol` (the language-neutral wire contract every
transport speaks), `Rod.Persistence` (the durable PostgreSQL adapters behind
the core-state and audit ports), and `Rod.TeamServer` (the single runnable
process and composition root). Each project's role, the layer rule it lives
under, and a note on its current state are listed.

| Project | Role | Layer rule (what it may depend on) | State |
|---------|------|------------------------------------|-------|
| `Rod.CoreState` | The teamserver's authoritative domain core: typed ids, the `Engagement` aggregate, operators, implants, tasks, deploy tokens, the implant session registry, the task queue and history, and the per-engagement implant certificate authority. The use cases (`EngagementService`, `EnrollmentService`, `HandshakeService`, `TaskService`, `ImplantService`) orchestrate these ports and define the operational behavior everything else consumes. The per-class reduced verb sets (`ImplantClassCapabilities`, Sec 5.2) live here as the inner-ring authority both the build pipeline and tradecraft read. | Inner ring -- depends on nothing in-house. | Implemented. In-memory adapters behind every port; the durable pair lives in `Rod.Persistence`. Task issuance gates each verb on the implant's class reduced set, enforces the kill date and retirement at handshake, and claims tasks atomically from the queue (Sec 5.2, Sec 10.3). |
| `Rod.Audit` | The append-only, per-engagement audit trail: hash-chained `AuditEvent` records and the `IAuditStore` port, plus the `IArtifactStore` for first-class evidence objects attached to tasks. The evidence backbone (Sec. 11); the source for timeline and report export. | Inner ring -- depends on nothing in-house (crosses the layer boundary with primitive `Guid` ids, never core-state types). | Implemented. In-memory and file-backed (`Audit:DataDirectory`) adapters for the trail and the artifact store; the file store verifies each engagement's chain on recovery and refuses a tampered trail. Also hosts the payload store for built artifacts (Sec 6). |
| `Rod.Protocol` | **Not a layer.** The protobuf wire protocol: frames and the enrollment/handshake/tasking messages (Sec. 8). The long-lived, language-neutral contract implants of every language build against. | Not a layer -- depends on nothing in-house; never leaks into `Rod.CoreState`. | Implemented. Versioned handshake (major.minor), a status code for every enrollment/handshake refusal, and the chunked exfil frame kind (Sec 8, Sec 10.1). |
| `Rod.Transport` | Listeners that terminate C2 transports and map core-state use cases onto the operator HTTP API and the implant beacon stream. Owns endpoint routing, TLS termination, and the mapping of use-case failures to wire status codes. | Layer 2 -- may depend on `Rod.CoreState`, `Rod.Protocol`, `Rod.Audit`, `Rod.BuildPipeline`. | Implemented. HTTP(S), DNS, and raw-TCP listeners with the bind decoupled from the public endpoint (a repoint swaps a burned redirector without touching the socket); the full operator API (engagements, deploy tokens, implants with notes and retirement, tasks with queued-task cancellation, artifacts, audit, timeline/report, payloads) and the beacon stream with bounded frames, capped resumable exfil reassembly, and atomic task dispatch (Sec 8, Sec 10.3, Sec 11); the browser hook's mint and guid-gated serving edge with the Origin-only CORS posture (Sec 5.2, Sec 8); the delivery-campaign surface (Sec 11.5) -- per-recipient lure builds through the build pipeline, the SMTP send engine, and the lure-serving public edge. The task, audit, and artifact listings are paged (limit + opaque cursor, newest window first) so a long engagement never grows a listing response without bound; the operator UI walks pages. The operator API also carries the versioned `/api/v1` prefix alias, the first-party OpenAPI 3.1 contract over it, and the token-scope floor gate (Sec 15.3, ADR-006). |
| `Rod.BuildPipeline` | Drives the external, per-language build units to compile polyglot implants on demand through the uniform build contract, fingerprinting and recording each artifact (Sec. 6). | Layer 3 -- may depend on `Rod.CoreState`. | Implemented. `RustBuildUnit` -- the sole in-tree unit (the .NET unit is deleted with the .NET implant) -- compiles the Rust reference implant in a per-build hermetic staging copy (the build target mapped onto a cargo triple; the retired stager class refused with the fix named at parse time), baking the profile (contact mode, beacon parameters, class verb set) without any key material; loader-tier requests compile the no_std loader crate beside it instead, baked with fetch constants and the delivery seal (Sec 6); the built bytes land in the payload store for operator download (Sec 6). |
| `Rod.Operators` | Multiplayer operator sessions over the operator API: shared live engagement state, task ownership and attribution, and real-time push to the operator UI. | Layer 4 -- may depend on `Rod.CoreState`, `Rod.Audit`. | Implemented. Cookie-authenticated operator sessions (login/logout/me; the bootstrap-seeded admin of Sec 4.5; hash-only credential port) and the per-engagement SSE live-event bus, with the automation engine (Sec 10.4) and the webhook forwarder (Sec 4.4) beside it as the bus's engine-side consumers. Cookies were chosen over JWT (no client-side token store for a same-origin SPA); ASP.NET Core Identity was rejected (its own user/role tables conflict with the layered stores). Access is the membership model of Sec 4.5 (per-engagement reader/writer tiers granted by the owner) beside the deployment-role split of the account machinery (bootstrap admin, console-created members); the exclusive interaction claims and activity presence mark who drives what; a per-handle login throttle slows brute force. The layer also owns the two agent-facing surfaces the operator front carries: the MCP server (`/mcp`, Streamable HTTP, stateless -- the toolset an external agent client drives through an operator API token: reads at any scope, task-issuing tools behind their own deployment gate, the operate scope floor, and Sec 10.4's unattended red line; runbook [operations/mcp.md](operations/mcp.md)) and the opt-in OpenAI-compatible LLM triage client behind `Microsoft.Extensions.AI`'s `IChatClient` (Sec 11.3; runbook [operations/llm.md](operations/llm.md)), plus the external recon workbench (Sec 11.4; runbook [operations/recon.md](operations/recon.md)) -- the pre-foothold lookups and scan whose findings land as task-less engagement artifacts. |
| `Rod.Capabilities` | Pluggable post-exploitation capability modules, including the evasion/exploit category contracts (Sec. 10, Sec. 13). Concrete implementations arrive as modules -- in-tree reference modules (`modules/`, loaded through the same path external modules take) or registry modules (Sec 15) -- over the contract, registration path, and gate this layer holds. | Layer 6 -- may depend on `Rod.CoreState`, `Rod.Audit`. | Implemented. The capability contract (`ICapabilityModule`, a registration-only contract: a descriptor, no execution surface -- Sec 10.2), the registry, and the registry-backed task-issuance resolver and sensitive-verb policy; every framework verb ships as a placeholder descriptor carrying its OPSEC attributes, and `GET /capabilities` exposes the catalog to the UI. The in-tree module host (Sec 15.1) is in place: reference modules deploy beside the binary by the teamserver build and load through the `Capabilities:Modules` config path exactly like external ones. Sensitive behavior arrives as modules and stays disabled by default (Sec 10.2, Sec 13, Sec 15). |
| `Rod.Persistence` | **Not a layer.** The durable PostgreSQL adapters behind the core-state and audit ports (operators, operator credentials, engagements, implants, sessions, tasks, deploy tokens, audit, artifacts, and the collaboration stores -- comments, chat, credentials, and the tsvector search), swapped in at the composition root when `ConnectionStrings:Postgres` is set (Sec 12.1). | Not a layer -- may depend on `Rod.CoreState` and `Rod.Audit`; wired only at the composition root, never by transport. | Implemented. EF Core 10 over Npgsql behind a context factory (singleton-safe), migrations, and the full adapter pair; absent the connection string the in-memory adapters stay registered. |
| `Rod.TeamServer` | **Not a layer.** The single runnable .NET process and composition root: it wires `Rod.Transport`'s services and endpoints, binds the listeners, and serves the built React operator UI same-origin with an SPA fallback. It is where the layers are assembled for `dotnet run`; the layer dependency tests do not constrain it. | Not a layer -- the composition root; depends inward on `Rod.Transport`, `Rod.Operators`, `Rod.Capabilities`, and `Rod.Persistence` (transport itself cannot reference the outer layers). | Implemented. Wires the layers, binds the configured listeners, and serves the built operator UI same-origin with hardening headers; the build runs the npm bundle first when it is missing (Sec 4.2). |

The dependency column is not aspirational: it is the rule the architecture tests
enforce. `LayerDependencyTests.cs` checks namespace usage, and
`ProjectReferenceTests.cs` checks the csproj reference edges themselves, so adding
a forbidden project reference fails the build even when no code uses it yet.

#### Former ADR index

Until 2026-08 the design decisions lived as numbered ADR files under
`docs/decisions/`; they were folded into this document and the files retired.
Comments in the source tree still cite the ids, so they resolve here:

| ADR | Folded into |
|-----|-------------|
| 0001 monolithic kernel | Sec 4 |
| 0002 .NET reference implant + wire protocol as the product | Sec 4.2, Sec 12.2 |
| 0003 PostgreSQL as the durable store | Sec 12.1 |
| 0004 offensive-tradecraft boundary | Sec 10.2, Sec 13 |
| 0005 (task argument shape) | Sec 10.3 |
| 0006 (capability-catalog endpoint placement) | Sec 4.3 |
| 0007 (placeholder-only verbs) | Sec 10.1 |
| 0008 operator authentication | Sec 4.1 layer 4 |
| 0009 single in-tree .NET toolchain | Sec 12.2 |
| 0010 production implant CA | Sec 9 |
| 0011 production redirector | Sec 4.2, Sec 8 |
| 0012 implant-side capability pluggability | Sec 5.3 |

One consequence of the layer rule: an endpoint backed by data in an outer layer
is exposed by that layer itself and mapped at the composition root, not hosted
in transport. `Rod.Operators` does this for its SSE
stream and `Rod.Capabilities` for `GET /capabilities` (the capability
catalog) and `GET /capabilities/coverage` (the ATT&CK coverage matrix,
ADR-007 -- registry metadata under the same rule): transport may depend on
neither, so each owns its endpoint the way it owns its
data. The catalog is a process-global read of the loaded module set -- registry
metadata, not engagement-scoped domain state -- so it earns no CoreState port
and no parallel DTO; an operator-scoped capability concern would be a *separate*
engagement-scoped endpoint, not a retrofit onto the global catalog.

### 4.4 Out-of-band event notifications

The live event bus reaches the operator at the console; an engagement does
not stop when the console closes. An implant that returns overnight, a caught
shell, a failed task are visible today only to connected operator sessions --
the operator who stepped away reconstructs the watch from the trail after the
fact. Notifications close that gap the way automation (Sec 10.4) closed
tasking: an engine **beside the operator layer, not a new one**, subscribing
to the same per-engagement bus and forwarding selected events to
operator-registered channels -- a webhook today; an IM bridge tomorrow is
configuration against that webhook (Slack, Discord, and Teams all expose
incoming-webhook URLs), never new code.

**Subscriptions.** A webhook subscription is engagement-scoped declarative
state (`WebhookSubscription` in `Rod.CoreState` behind the
`IWebhookSubscriptionStore` port, the same in-memory/Postgres adapter pair
every engagement-scoped row uses): a display name, a target URL, and a
non-empty selection of notifiable event kinds. The notifiable set is the
engagement's operational beats -- session opened or closed, task issued,
completed, or cancelled, implant retired, shell session opened or ended,
payload fetched. Operator presence is console chatter and channel output is a
per-chunk firehose, so neither is selectable, the exclusions automation's
trigger list makes for the same reasons. The shell kinds split the other way:
not triggerable there, but exactly what an off-console operator wants to hear
about, so they are notifiable here.

**The delivery path.** The engine subscribes once per engagement holding
enabled subscriptions and, for each matching event, POSTs one request whose
body is the SSE frame shape verbatim -- kind, engagement, operator, implant,
task ids, payload, timestamp -- so a channel receives exactly what a
connected console receives. Delivery is single-attempt with a per-request
timeout: no retry queue, no redelivery. Every attempt lands in the audit
trail (`WebhookDelivered`, outcome `delivered:{status}` /
`failed:{reason}` / `tested:{status}`), and the URL is never written there:
it is the subscription's bearer secret (the incoming-webhook convention),
so the trail names the subscription, never the address. What a push carries
is what a console sees, task output included, so where it is pointed -- a
self-hosted receiver or a third-party bridge -- is an OPSEC decision the
operations runbook records, not one the code makes. Registrations and
mutations land as `WebhookSubscriptionCreated`/`Updated`/`Deleted`
attributed to the acting operator; deliveries attribute to no operator: a
push mirrors an event, it does not act on the engagement.

**Guards.** A subscription whose deliveries fail consecutively
(`WebhookLimits.ConsecutiveFailureLimit`, three) disables itself with the
cause in the trail, the same self-parking posture a repeatedly-refused
automation rule holds. A URL must be absolute https -- plain http is
accepted only for loopback, the lab and self-hosted receivers -- and may
carry no userinfo or fragment. Kinds outside the notifiable set are refused
at creation, not silently dropped at delivery.

**Durability posture.** The subscription is durable -- it survives a restart
with the engagement, bookkeeping included. Delivery is not: events that fire
while the server is down never happened, process-local and drop-oldest under
a slow consumer with no replay, the bus's own posture, and the audit trail
stays the record.

**The operator surface.** Subscriptions are managed from the operator API at
`/engagements/{engagementId}/webhook-subscriptions` (create, list, read,
`:enable`, `:disable`, delete) beside the automation rules, in the operator
layer with the events endpoint -- transport may not reference the layer the
forwarder lives in. Creation validates eagerly (engagement open, kinds
notifiable, URL shape, per-engagement cap) so an operator's mistake is a 422
at registration instead of a quiet miss three hours later. A `:test` action
pushes one synthetic frame through the same delivery path: an operator who
registers a channel for the overnight watch verifies it before relying on
it, without manufacturing a real event.

**Shape of the engine.** One hosted background service with a fixed-delay
tick (default 5 s, `Webhooks:EngineTickSeconds`) that reconciles the
per-engagement subscriptions from the store -- at most one tick of latency
before a new subscription hears events, the same eventual-read posture the
automation engine and the staleness sweeper hold. Deliveries run
sequentially inside each engagement's pump under a per-request timeout
(`Webhooks:DeliveryTimeoutSeconds`, default 10 s): a slow receiver delays
later pushes to itself, never the bus and never a connected console, and the
bus's bounded per-subscriber buffer drops oldest under a truly stalled
forwarder -- the posture a best-effort channel owes its riders.

**Evolution notes.** Where later work plugs in, so nobody rediscovers it
from the code. Retry with backoff for a 5xx receiver, HMAC request signing
with a per-subscription secret (stored beside the URL, shown once), and a
per-subscription implant filter like an event rule's `OnlyImplant` condition
are the natural widenings -- each touches the entity, the engine's delivery
call, and nothing else. A channel needing a richer body than the frame shape
is a new delivery format on the same subscription, not a new subscription
kind.

### 4.5 Operator roles and interaction ownership

An account is identity plus exactly one deployment-level distinction: its
**deployment role** -- bootstrap-seeded `admin` or console-created
`member` -- which owns the deployment's management surface, everything
not scoped to an engagement (the account machinery, the redirector
fleet, the runtime settings). What an operator may see and do inside
engagements lives per engagement, as the memberships its owners granted
(Sec 3). Coordination on top of that grant closes the two-operator gap
-- who is working what -- with three pieces: memberships (what an
operator may do, per engagement), activity presence (who is working
what, soft), and interaction claims (who holds an interaction surface,
exclusive). The latter two are coordination discipline among trusted
operators, not a defense against a hostile one -- an operator is inside
the trust boundary by definition (Sec 9); they name responsibility, they
do not contain a compromise.

**Memberships.** An engagement's access derives entirely from membership,
never from a global grant. The owner is bound once at creation and holds
member management beside full write access; every other operator on the
engagement is a member at one of two tiers: `reader` (every
engagement-scoped read and the live event stream) or `writer` (every
engagement-scoped write: tasking, caught-shell interaction, implant
retirement and notes, the engagement's own management -- listeners,
payloads, launchers, ROE, snippets, automation, webhooks, closeout -- and
deploy-token minting). A stranger holds nothing and learns nothing: the
engagement's listing omits it and its routes answer the same 404 a missing
engagement does, because the engagement's existence is itself information.
Member management is the owner's alone (`GET/POST
/engagements/{id}/members`, `PUT/DELETE .../members/{operatorId}`, invites
by handle); the owner cannot be removed or re-tiered, an engagement keeps
exactly one. Membership is engagement state, so every grant, re-tier, and
removal lands in that engagement's own audit trail
(`EngagementMemberAdded` / `RoleChanged` / `Removed` -- kinds the earlier
scaffolding-era model never had) and beats one `MembershipChanged` live
event so connected consoles refresh.

**The account machinery and the deployment roles.** The bootstrap seed is
the deployment's root of trust: the seeded account comes up admin, and
every account created through the console (`POST /operators`) comes up a
member, permanently -- there is no promote or demote surface; the only
way a deployment grows another admin is the bootstrap at boot. Acting on
other operators' accounts is admin-only: provisioning, password
re-provision (`PUT /operators/{id}/credentials`), credential revoke,
token mint, list, and revoke, and the disable pair (`POST
/operators/{id}:disable` / `:enable` -- the admin's even on its own
account; the off switch is not self-service). Members keep self-service
over their own password and their own API tokens. The roster read stays
open to every operator, because engagement members are invited by
handle. The disable pair keeps two guards: disabling the last enabled
account is refused, because nobody could enable it back, and so is
disabling the last enabled admin, because the deployment would hold no
management path. Removal stays disable-shaped either way -- the row is
never deleted (its id anchors every attribution it ever collected) and
its memberships wait, so an enable restores exactly the reach the
account had; a disabled operator authenticates nowhere (login fails
indistinguishably from an unknown handle, live cookie sessions reject at
their next request, API tokens refuse). The same admin line gates the
other deployment-management surfaces: redirector credential mint/revoke
and node retire (Sec 8) and the runtime settings writes. The reads
(roster, fleet and ledger, settings, System) stay open to every
authenticated operator. The gate rides a deployment-role claim the login
and the token resolution stamp from the account row -- the role is fixed
at registration, so the claim cannot go stale; a member draws 403, an
anonymous request 401.

**Access mechanics.** One resolver -- owner check against the engagement's
own field, then membership against the store -- feeds every gate:
engagement-scoped routes carry an endpoint filter that reads the caller's
standing fresh on every request (a re-tier or removal takes effect at the
very next call; no claim or cookie carries permission), renders strangers
as 404, and refuses readers on write routes with 403. The gate lives at
the endpoint layer and the core use cases stay access-free: the automation
engine's synthetic operator never authenticates and works its
engagements' core-state calls directly, unaffected by construction. The
MCP read surface rides the same standing through the operator whose API
token backs the call.

**Activity presence.** The presence roster (who is online) extends to who
is driving which implant: every tasking action -- an issuance, a channel
input post -- notes activity against its implant, and the roster holds one
driving entry per implant (operator, last-at). A refresh by the current
driver publishes nothing; a change of driver publishes one `ImplantActivity`
live event, so tasking cadence never becomes a firehose and a hand-off is
one beat. The hello frame carries the driving map beside the roster, so a
late joiner sees who works what before any event arrives. Activity is soft
state -- it marks, it does not block.

**Interaction claims.** The exclusive half: one operator holds the claim on
an interaction surface, and the surfaces are exactly the typing halves -- a
live channel task (its input posts and relay binds; `shell.interact` and
the tunnels ride the same rule) and a caught shell session (its input).
Acquire is explicit (`POST /engagements/{id}/claims`, idempotent for the
holder, `409` naming the holder otherwise) and implicit: an input post or
relay bind against an unclaimed surface takes the claim as its first effect,
so the first keystroke is the claim and existing automation of the input
routes keeps working unclaimed-to-claimed. While another operator holds the
claim, the input routes refuse (`409`, the holder named) -- two operators
cannot type into one shell. Release is explicit (`DELETE` by the holder),
automatic on the holder's disconnect from the engagement's live stream
(the SSE close path that ends presence releases every claim the operator
holds -- the bus's own lifecycle is the reaper), and lazy on read: a claim
on a surface that ended is inert -- the task's state or the shell's status
refuses input before the claim is consulted -- and the claims listing drops
such claims when it sees them, so a dead claim never outlives its holder's
connection. Claims are visible on the live bus (`ClaimAcquired`,
`ClaimReleased`, holder and surface in the payload), in the claims listing,
and in the hello frame, so a late joiner sees every held claim on connect.
Teardown stays open to any writer on the engagement: closing a caught shell or
unbinding a relay are safety valves a colleague must always be able to
pull, and the upgrade render mints a credential without typing anything
(its paste rides the audited, claim-checked input route). Claims are
coordination state, not audit facts -- presence's own posture: ephemeral,
process-local, and already attributed downstream, because every input post
lands in the trail as it happens (`ChannelInput`, `ShellSessionInput`),
which is the forensic who-typed-what record.

**The console surface.** The interact panes render the claim: held by
another operator, the input line locks and names the holder; held by me or
unclaimed, typing proceeds (the first post taking the claim server-side),
and dismissing a pane I hold releases it. The roster shows the driving
badges from activity presence, and a reader sees a
read-only mark in the engagement -- the badge explains what the server already
refuses; it is not the enforcement.

**Evolution notes.** The deployment admin role is not the retired scope
model returning by another door: it is one administrative boundary on
the deployment-global surfaces (accounts, fleet, settings), not a
per-engagement capability bitmask. The sensitive-verb approval workflow
stays declined (owner decision); if it ever returns, its approver tier
would be a third membership role beside reader and writer -- an
engagement-scoped grant, not a global account flag.

## 5. Implants and profiles

An implant is a short-lived, disposable payload on a target. It is **untrusted by
default** and generates its own keypair at first run -- there is no global
shared secret, and no key material in the artifact at all.
What a from-scratch implant must implement to interoperate -- and what is
optional hardening or optional features -- is specified as a tier ladder in
[extending/implants.md](extending/implants.md); that ladder is the contract's
complexity budget, and its evolution rules bind every future protocol change.

### 5.1 Profiles are baked in at generation

A **profile** -- the contact mode, beacon parameters (sleep, jitter, kill
date), the transport profile, and the C2 endpoint list -- is embedded into the
artifact at build time, and the bake is the artifact's whole configuration:
the release build (what the pipeline publishes, and what lands on targets)
reads no flags and no environment, so a fielded executable cannot be
re-pointed or re-credentialed and runs bare -- zero arguments, console silent
beyond fatal one-liners. The debug build is the dev shape: flags and the
ROD_* environment drive the checked-in empty profile stub, and the run
narrates to stderr; a bake, when a debug build carries one, still overrides
both. This
is what makes per-implant OPSEC possible: no two implants look the same, and a
lost implant self-terminates at its kill date. No key material is baked: the
implant's cryptographic identity is the keypair it generates itself at first
run, bound to its engagement by the CA-signed leaf issued at enroll (Sec 9).
What a captured artifact does carry is the enrollment credential the build
minted for it (Sec 6): a deployment secret, not key material -- single-use by
default (a zero max-uses budget is unlimited), bounded by the artifact's own
kill window when one is pinned and 30 days when there is none, bound to its
engagement's
listener scope, revocable by id the moment it is known to have leaked. A build
that mints nothing bakes nothing, and the credential never passes through an
operator's hands.

The endpoint list is ordered: a primary callback endpoint plus optional
fallbacks of the front's own scheme family (the web pair, the DNS pair, or
the raw socket), walked client-side when an entry burns (Sec 8).

The bake-in is verified end-to-end: the configured sleep, jitter, and kill date
land in the decoded artifact the build unit emits, so a profile that is
silently dropped or defaulted fails the build-pipeline tests.

The kill date is optional: unset (the default) bakes an open-ended artifact --
the long-haul posture with no time fuse at all -- and the implant reports its
baked date at enroll so the teamserver's record mirrors the artifact's own.
It is enforced on both sides of the wire (Sec 7). The teamserver
refuses to open a session for an implant whose kill date has passed, returning
`HANDSHAKE_STATUS_KILL_DATE_EXPIRED` at handshake before any session or tasking
is recorded; the implant itself refuses to start past its kill date and
re-checks it at the top of each beacon cycle, so a long-running implant
self-terminates the moment the date passes rather than waiting for a reconnect
or restart.

The contact cadence reports the same way the kill date does: the enrollment
carries the artifact's baked sleep/jitter pair, and every contact's handshake
re-advertises the implant's current pair, so the teamserver's record tracks a
`beacon.sleep` retune at the next contact -- what the fleet's detail view
reads. An implant that reports no cadence (a pre-field client) records none;
the record shows the honest absence rather than an invented pair.

### 5.2 Implant classes (by operational purpose)

Implants differ by purpose, not by a "managed device flavor":

- **Implant class** -- the primary long-haul implant; full capability set and
  module support. (the Rust reference implant, cross-platform.)
- **Stager** -- retired as a build output, and with it the whole
  stage1/stage2 vocabulary: delivery rides the launcher one-liners (the disk
  families plus the Linux in-memory memfd family), which fetch the payload
  over the same credential-gated route a loader ever used. Nothing emits the
  class, no enum carries it, and the build contract refuses the spelling; a
  request naming it gets the current delivery answer. Prose and
  operator-facing copy say payload and artifact.
- **Web-shell class** -- a script placed in a web root, bound to the web
  transport; code execution over HTTP, no interactive PTY. The endpoint is
  operator-initiated in every phase: registration creates the class's
  anchor implant row directly (no enrollment, no handshake, no session --
  the register action itself is the engagement binding), and execution is
  the operator's request driving one adapter round trip synchronously
  (Sec 10.3's exception). The connection profile (URL, protocol adapter,
  credential, encoder pair) is the side table of the anchor row; the
  protocol adapter registry carries the two in-tree families -- the
  Rod-native one (a one-line placed script whose baked 256-bit key seals
  the channel as AES-256-GCM in both directions; the credential is that
  key, not a password) and the universal one-liner eval family (the
  classic `@eval($_POST[...])` shape every manager drives; scripts placed
  by hand or by another tool answer it because the one-liner itself is
  universal) -- and leaves any other family to module-domain tradecraft
  (Sec 13).
- **Ephemeral** -- a short-lived, TTL'd implant from a one-liner bootstrap; for
  one-off execution and temporary access.
- **Pivot** -- an implant that represents hosts which cannot run their own
  implant (network/OT gear), enrolling each as its own session and forwarding
  tasking. Its class set is the tunnel set (Sec 10.1): a Pivot-class build is
  the minimal tunneling artifact, and the parent-fronting shape for
  unplantable hosts rides the same set. Fronting ships: a Pivot child
  enrolled by a parent (`lateral.move`, this section) has no process of its
  own and never handshakes -- no session, no stream -- so its tasking is
  claimed by the parent's beacon stream (the fronting claim, Sec 10.3),
  arrives marked with the child's id, and executes in the parent with every
  record attributed to the child (Sec 9's signature already binds the
  target's id into the tuple; the frame's `target_implant_id` marking carries
  the routing). An implant that derives children fronts only what it
  enrolled -- keep the child ids from the enroll responses and refuse a
  frame naming anything else, the voucher the enrollment performed (the
  Tier 2 contract, extending/implants.md). The reference implant compiles
  no lateral handler (the long tail, Sec 13); the server-side claim is
  what ships in-tree, pinned by the core-state tests.
- **Browser class** -- a hooked browser, not a process: the artifact is a
  served hook script (`<script src>`) a script-injection foothold loads,
  and the implant it enrolls is the browser that executed it. The class
  turns the most common web-facing foothold into tasking inside the
  engagement trail -- today it needs a separate platform with its own
  operator surface, storage, and OPSEC story, disconnected from the
  attribution arc. Enrollment and contact ride the certificate-less
  envelope carrier (Sec 8) on the poll cadence the store-and-forward
  degraded discipline already models -- the hook speaks the same rod.v1
  frames over the same `POST /implants/beacon`, the wire codec carried in
  vanilla JavaScript inside the served script. Every hooked browser is an
  engagement-scoped implant entity like any other: attribution, live
  events, audit, and the automation engine treat it identically. The
  artifact is rendered by the teamserver (the web-shell generator's
  pattern, not the external build contract, which stays
  compiled-artifacts only) and served from the public edge under an
  unguessable route id (Sec 8). Identity is per browser tab: sessionStorage
  holds the implant id and the seal counter, so a reload resumes rather
  than re-enrolls; a storage-blocked context re-enrolls on reload, spending
  one token use each time -- the mint's token budget is the enrollment
  budget.

Each class carries a **reduced verb set** -- the subset of the verbs its
purpose justifies, defined in `Rod.CoreState.ImplantClassCapabilities` (the
inner ring both the build pipeline and the tradecraft layer read). The
Implant class carries the full core set (one-shot and interactive shell execution,
both-direction file transfer, directory listing, process termination, and
the beacon's own sleep control) plus the
tunnel set, the recon set, the lateral set, the persist set, the collect set,
and the exfil set (tunneling and process control join the implant's core
operations, and recon,
lateral movement, persistence, collection, and exfiltration are long-haul
activities that justify a long-haul footprint); a loader only `file.pull`s the
artifact it loads; a web-shell and an ephemeral run `shell.exec` over their
short-lived channels; a pivot carries exactly the tunnel set --
`tunnel.forward`, the port-forward verb, and `tunnel.socks`, the
multiplexed proxy (Sec 10.3) -- enough to forward traffic for hosts that
cannot run their own implant and nothing a long-haul footprint justifies; a
browser carries exactly the hook set -- `browser.fingerprint`,
`browser.cookies`, `browser.dom`, `browser.screenshot`, `browser.redirect`,
`browser.prompt` (Sec 10.1) -- the read-and-steer verbs a hooked page
justifies, with everything past them (input capture, browser-exploit
chaining) arriving as capability modules exactly like the evasion and
exploit families (Sec 13, Sec 15). No class but Implant carries a
recon, lateral, persist, collect, or exfil
verb. The set is the server's authority for what a class
may do: task issuance gates on it in core state (a verb outside the set is
refused before it is queued, Sec 10.3), and the build pipeline bakes it into
each artifact so a generated payload is self-describing.

Admission is not execution: a verb may be class-admissible (the class gate
does not refuse it) yet ship no built-in handler, running only when an
operator supplies a module (Sec 15). The `evasion` and `exploit`
categories in their entirety follow this shape (Sec 10.2); they are listed
in the capability catalog but carry no in-repo handler -- ungated contract
verbs the bake carries alongside the class set (Sec 5.3), so an artifact
compiled with a module's handler for one advertises it at handshake.

A capable implant can deploy another class on the same host (e.g. a web-shell
deriving a full implant) via a deployment verb; the child enrols into the same
engagement and records its parent. This is the lateral-movement path:
the `lateral.move` verb is the deployment verb that semantically means
"derive a child," and the child's enrollment records its `ParentImplantId` on
the implant entity. The child enrols through the same enrollment route a
top-level implant takes, naming its parent; the enrollment service resolves and
scope-checks the parent (it must exist, belong to the same engagement the
redeemed token resolved, and not be retired) before binding the child. The
parentage is surfaced on the operator implant listing so the UI can render
lineage; a top-level (launcher-derived) implant reports no parent.

### 5.3 Implant-side capability pluggability

The class verb set (Sec 5.2) is the server's authority; the implant's advertised
set is its own, and the two must agree. A reference implant advertises exactly
the verbs its build permits and its compiled handlers implement -- never a verb
it cannot run. The advertised beacon capability set is the intersection of the
baked verbs (the class set plus the ungated contract-only verbs) with the
compiled handler set, and dispatch routes through an
implant-side handler registry (the implant analog of the server's
`ICapabilityModule`) rather than a hard-coded `switch`, so adding a verb is a
handler plus a registration, not an edit to the runner. Registration is
compile-time -- no runtime library loading for *handler plugins* (a Rust
dylib boundary is not stable across compiler versions, and the capability
set is
decided per class at build time, so runtime discovery buys nothing).
Handlers beyond the compiled tree are the crate fork -- the build unit
pointed at the operator's own tree (Sec 6, extending/modules.md) -- with the C-ABI
plugin seam (Sec 5.4) as the in-process follow-on: per-engagement modules
that load on demand over the task channel, after deployment, inside the
artifact that never compiled them.

Rejected alternatives: runtime dynamic loading over a Rust dylib boundary
for *handler* plugins (no stable ABI across compiler versions, and the
compiled set is decided per class at build time, so discovery buys nothing
-- the scoped C-ABI seam of Sec 5.4 is what runtime loading is for, and it
arrives as its own design there); advertising the full baked class set regardless of implemented
handlers (recreates the unknown-verb-for-an-advertised-verb failure the
intersection exists to prevent); keeping the hard-coded switch and adding
`collect.keylog` in-repo behind a flag (bypasses the module contract and
leaves no growth seam); and making the implant class-aware but
keeping the switch (solves advertising but not extensibility -- the registry
is what makes the design durable).

The reference Rust implant implements this end to end: `handlers::dispatch`
is the implant's only dispatch path, and the run advertises the baked verb
set intersected with `handlers::COMPILED_VERBS` at every handshake -- the
same intersection rule, in the crate's own shape. An un-baked dev binary
 advertises its full compiled handler set. The end-to-end legs pin the
advertised behavior (the dev-shape run and the pipeline-built run each
complete dispatched tasking); the sensitive three compile only into Windows
builds, so a Linux artifact never advertises them.

The class verb set also bounds what a build runs, not only what it
advertises: the bake carries the class's verb list, and the run dispatches
the baked set intersected with the crate's compiled handlers -- a dispatch
for a verb the build does not carry fails cleanly at the handler table
with the grammar named. Whole-source trimming per class -- the deleted
.NET unit's `HandlerSelection` rewrite, which deleted unused handler
sources from each staging copy -- did not carry into the Rust unit: the
crate compiles one lean handler set per platform (the sensitive three
behind `cfg(windows)`), and per-class tailoring rides the baked verb list
instead, because the handler code is tens of kilobytes against a carriage
that dominates the artifact's size. Handlers beyond the compiled tree
arrive through the crate fork (extending/modules.md) and the C-ABI
plugin seam (Sec 5.4); the
plugin domain is the long tail -- recon sweeps, lateral
movement, persistence, credential and screen collection -- while the
channel verbs and the file/exec core stay compiled, because a plugin
cannot own a live channel or a carriage.

### 5.4 Implant-side plugin modules (the C-ABI seam)

The crate fork adds a capability at build time; the plugin seam adds one to
an artifact already deployed -- a per-engagement tradecraft module that
loads on demand over the task channel and never rides a standing artifact.
The domain is the stateless long tail (Sec 13): the recon set, lateral
movement, persistence, credential and screen collection -- string-in,
string-out work a module shape holds naturally. The channel verbs and the
file/exec core stay compiled, because a plugin cannot own a live channel or
a carriage.

**The boundary is ABI-stable, not compiler-stable.** A Rust dylib
boundary is not stable across compiler versions (the reason Sec 5.3 keeps
handler registration compile-time), so neither module shape couples the
module to the host's compiler. On Windows the interface is a handful of
`extern "C"` symbols over `#[repr(C)]` data -- the C ABI, the one
boundary every toolchain keeps. On Linux the interface is a byte protocol
over stdio: length-prefixed request/response frames carrying the same
string grammar, no dynamic loader and no libc in the picture at all. The
authoring surface is the `rod-plugin-sdk` crate
(`src/implant/rust/plugin-sdk/`) either way: a plain Rust trait -- a
module names itself and lists its verbs, each verb a `fn(&str) ->
Result<String, String>` over the shared task grammar -- plus the
`rod_plugin!` macro (the extern shims the Windows shape maps) and
`serve()` (the stdio loop the Linux shape execs). One module source
builds both artifacts: the cdylib for Windows, the executable for Linux
-- built against a musl triple, so it is static and runs from any
artifact with no libc coupling. The Windows exported family, of which
the SDK is the documented authority:

- `rod_plugin_abi() -> u32` -- the ABI version; a loader that does not
  recognize it refuses the module whole.
- `rod_plugin_name() -> RodStr` -- the module's self-declared name.
- `rod_plugin_init() -> u32` -- construct the plugin and register its verb
  table; answers the verb count.
- `rod_plugin_verb_name(index) -> RodStr` -- the verb at an index.
- `rod_plugin_run(index, RodStr, &mut RodStr) -> i32` -- execute one verb
  under the shared string grammar; 0 is success, 1 a handler failure whose
  output string carries the cause, negative a shim error. Panics are
  fenced at the boundary: the shim catches and reports, they never unwind
  into the host.
- `rod_plugin_free(ptr, len)` -- module-allocated strings die in the
  module's own allocator; the host never frees module memory itself.

On Windows strings cross as `RodStr`, a length-delimited `(ptr, len)`
pair -- not a NUL-terminated C string, because the argument grammar is
opaque bytes and cannot ride one. The Linux protocol frames carry the
same bytes length-prefixed, for the same reason.

**The carriage is the staged arm.** `module.load <name>` is issued with the
module bytes as the task's `Content`: the issuer stages them as a
task-bound artifact, binds their sha256 into the signed tasking tuple, and
sets the typed staged-bytes field (Sec 10's per-verb arm); the implant
demands the bytes with the same `StagedPull` a large `file.push` rides and
receives the same chunked run. Nothing new crosses the wire -- the module
arrives over the existing sealed task channel, integrity-bound by the same
signature, chunked under the same budget, its bytes resting server-side as
engagement-scoped evidence (Sec 11). The family's other verbs are plain
one-shot tasks: `module.list` reports the loaded modules and their verbs,
and `module.unload <name>` retracts one -- best-effort, because a library
in flight is the platform's business: verb routes drop immediately, a
handler mid-execution finishes. All three are Implant-class verbs (module
support is the Implant class's, Sec 5.2) registered as descriptors in the
tradecraft layer, `module.load` carrying the `executes-code` OPSEC
attribute: loading a module is running new code, so automation never fires
it unattended (Sec 10.4).

**The loader stages the bytes the way the launcher one-liners do.** On
Linux the bytes are written to a close-on-exec memfd and the module is
exec'd through the anonymous fd itself -- `execveat(AT_EMPTY_PATH)`, the
loader tier's own syscall (Sec 6), no `/proc` path involved, so the
shape holds wherever the kernel does -- one process per verb dispatch,
the request and its answer crossing stdio.
Nothing lands on the filesystem at any step, nothing dlopens, and the
shape carries no libc coupling: the static musl artifact -- every fielded
Linux build (Sec 12.2) -- loads modules exactly like any other, which is
the point of the exec shape; no platform split, no build knob for it.
Crash isolation is real -- a module that dies cannot take the implant
with it, and a `panic = "abort"` build merely reads as a dead child whose
task fails with the cause -- and the per-dispatch process event is the
shape's OPSEC entry, the same visibility a `shell.exec` child already
has. On Windows the bytes are a manually mapped PE -- allocate, copy
sections, apply base relocations, resolve imports against the system
DLLs through `LoadLibrary`/`GetProcAddress`, give the image its TLS
block on the loading thread, invoke the entry, then walk the export
table for the family -- because `LoadLibrary` wants a path and the seam
keeps modules off disk.

**The scope boundary is honest.** The two shapes divide the labor the
documented domain already draws. A Linux module answers one request per
process -- the stateless long tail made mechanical, no state carrying
between calls -- while the resident collectors (`collect.keylog`'s input
hook is the reference case) need a process that stays, which is the
Windows in-process shape's half. Unload keeps its best-effort meaning on
both: verb routes drop immediately, a dispatch in flight finishes; on
Linux the memfd closes once the table drops it, on Windows the mapped
image leaks by design (freeing pages under a live handler is worse than
the leak).

**Dispatch and advertisement.** A module verb reads exactly like a
compiled one: the one-shot dispatch path consults the compiled handler
table first and the module table second, the result rides the same
TaskResult (first-wins dedup, the audit arc of any task), and the module's
verbs join the advertised set at load, so the widened surface reports at
the next contact the way a cadence retune does (Sec 5.1). Registrations
are run-state, not persisted state: a restarted implant re-advertises
without them, and an operator who still needs the module re-loads it. The
loader refuses at load what a module cannot own -- a verb the artifact
compiles (the compiled arm would shadow it forever) and a channel verb
(Sec 10.3's live machinery is not reachable from a module) -- with the
refusal naming the verb and failing the task; verb names must follow the
`namespace.action` grammar every verb already follows. Replacement is
last-registration-wins: a later module's registration for a verb an
earlier one held replaces the route, the same rule the server-side seam
applies (Sec 10.2).

**The server-side pairing.** A module verb in a standard namespace --
recon, lateral, persist, collect, exfil -- is class-admissible for the
Implant class already (Sec 5.2), so it tasks with no server-side ceremony.
A module carrying a novel namespace pairs with a server-side descriptor
module (`ICapabilityModule`, extending/modules.md) that widens the
issuance gate -- the two halves of a capability the extending guide
teaches, now met by a real implant-side half instead of a fork. The
reference module in-tree (`src/implant/rust/modules/hostenum/`) is the
worked example: `recon.hostenum` against the SDK, benign and readable,
the shape every operator module copies.

## 6. Payload build pipeline (polyglot via decoupled build units)

The flow: **operator build request -> teamserver emits build params -> the
language's build unit compiles -> artifact returned -> fingerprinted and
recorded.**

- **Two in-tree build units (Rust the reference, Go the community slot); polyglot by contract.** `RustBuildUnit`
  drives cargo for the reference implant (Sec 12.2); `GoBuildUnit` drives
  the Go toolchain for the community-slot reference under
  `src/implant/go/` -- the same uniform build contract, the same baked
  base64url profile (overwritten into the staging copy's `baked.go`),
  vendored dependencies so a payload build never touches the network. The
  teamserver drives each unit through the **uniform build contract** and is
  coupled to it only by that contract, so a community build unit in Go,
  C/C++, or Nim can register and compile against the same contract with no
  in-language coupling (the `Language` enum keeps those slots, Sec 12.2).
  The Rust unit maps the target onto a cargo triple and
  refuses the stager class (retired with the .NET tree) with the fix
  named at parse time.
- **The format is a build request knob; over the Rust unit it is recorded
  metadata, not a compile mode.** `ArtifactFormat` rides the build
  contract beside the class and target, and the unit maps it onto one
  cargo invocation: **`exe`** (the default), **`exe-trimmed`**, and
  **`aot`** all produce the same native executable for the requested
  target (ELF or PE) -- Rust is always ahead-of-time, and the size
  posture lives in the crate's release profile (opt-level, LTO, strip),
  not a publish variant. The spellings are compatibility names over that
  one artifact: they survive the retired .NET unit's publish shapes
  (single-file, trimmed, NativeAOT) so the wire contract stayed stable
  across the toolchain switch, and a community unit maps them onto its
  own closest equivalents. The delivery posture the spellings once
  flagged -- disk versus in-memory -- belongs to the launcher step
  (below): the render offers the memfd family for every native Linux
  payload, so the operator picks per paste, not per build. **`so` and
  `apk`** are the android carrier's deployment shapes (Sec 12.2): the
  bare cdylib an engagement's own app loads, and the installable package
  the unit assembles from the carrier crate's manifest through the SDK's
  aapt2/apksigner -- android targets take this pair alone, and every
  other target refuses it. **`dll` and `shellcode`** stay contract slots
  the axis carries for the shapes a host process loads or an injector
  spends -- the PE shared library and the position-independent blob
  `inject.shellcode` runs -- named so a request and a library row can
  spell the delivery before the toolchain that produces them lands; the
  parser and the unit both refuse them with that state named until then.
  An unmappable target fails the build with the supported set named
  rather than silently building for the build host.
- **Build params** include the implant class, artifact format, target OS/arch,
  transport profile, and beacon parameters (mode, sleep, jitter, kill date).
  They are produced at request time so each artifact is unique -- this is
  essential for OPSEC. No key material crosses the build contract (Sec 5.1).
- **The implant-side extension seam is the crate fork.** The overlay the
  .NET unit once compiled (`Build:ImplantExtensionDirectory`, a directory of
  `.cs` handler sources) retired with the .NET implant it compiled. The Rust
  seam is the source tree itself: an operator points the unit at a fork that
  carries the extra handlers (`Build:RustSourceDirectory` names the tree on
  an installed teamserver), coupled to the teamserver only by the wire
  contracts -- no fork of the teamserver ([extending/modules.md](extending/modules.md)).
  The C-ABI plugin module (Sec 5.4) is the follow-on that drops the rebuild.
- **The bake names the transport each build dials.** The egress walk the
  profile bakes names URL shapes, and the implant picks its contact client
  by the dial's scheme at run: an `http(s)://` front runs the envelope POST
  cycle or dials the WebSocket beacon by the baked mode, a `tcp://` front
  the raw socket, a `dns://`/`doh://` front the datagram exchange. The
  Rust crate compiles every client into one lean binary -- the clients
  share the session, the seal, and the wire codec, and the unused ones
  cost tens of kilobytes each, so a per-build module trim buys nothing.
- **The bake bounds each build to the verbs it runs.** The class's verb set
  (Sec 5.2) is the server's authority for what an artifact may run, and the
  bake carries that set: the run dispatches the baked list intersected with
  the crate's compiled handlers (Sec 5.3). The whole-file trim the deleted
  .NET unit performed did not carry into the Rust unit -- the handler code
  is tens of kilobytes against a carriage that dominates the artifact --
  and a loader bake carries no verb list at all: a loader runs no handlers.
- **Delivery rides the launcher one-liners.** The loader class is
  retired with the .NET trees: the render families -- the disk fetch-and-run
  trio plus the Linux in-memory family, both for every payload (python3
  stages the bytes in a memfd and execs through /proc/self/fd, so nothing
  lands) -- deliver the artifact over the same
  engagement-scoped, token-gated fetch route (`GET /implants/payloads/{id}`,
  each served fetch spending one use), with the mints, budgets, and
  revocations the launchers endpoint already keeps. An https front
  terminates TLS against the engagement CA (Sec 9), an anchor no stock
  target toolchain trusts -- the implant pins it, curl and friends cannot
  -- so the one-liners render with each family's transport-verification
  bypass; the credential gates the fetch, and the fetched artifact's own
  enrollment pins the CA.
- **The loader tier delivers sealed, from memory.** The build
  request's kind axis names the tier: the implant (the default, the full
  product) or the **loader** -- a ~25 KB `no_std`, no-libc ELF the
  Rust unit compiles from the crate beside the implant, baked with fetch
  constants (a literal-IPv4 cleartext-http dial, the deploy token, the
  per-build AES-GCM key) instead of a contact profile. A loader build
  names the stored implant it delivers; the fetch route
  (`GET /implants/loaders/{loaderId}/payload`, the same credential gate,
  engagement scope, redemption, and audit as the payload fetch) serves that
  payload as an R1 body sealed under the loader's own key and the loader
  payload AAD, a fresh
  nonce per serve. The loader authenticates before it executes -- nothing
  runs that does not open under the baked key; a tampered or swapped
  response is a failed GCM authentication and an exit, never an exec --
  then writes the opened bytes to a memfd and execs them through the
  anonymous fd: the payload never lands on disk, and no interpreter
  dependency stands between the one-liner and the implant the way the
  python3 family needs one. The tier's trust posture is deliberately
  plain: cleartext HTTP on the dial (the parser refuses any other front
  for a loader build), the seal -- not the transport -- the boundary,
  the same stance as the cleartext contact posture. The loader's baked
  credential spends one use per execution (each run fetches the payload
  once), so a reboot-surviving loader needs a budgeted or unlimited
  token inside its kill window; deleting either artifact ends the
  delivery. Windows targets deliver through the one-liners today; the
  tier compiles for Linux amd64 and arm64 -- the aarch64 cross links
  through rust-lld from the toolchain itself (the host driver rejects
  that target's cortex fixup flag, and the loader has no C bits), and
  both arches are verified end to end: the sealed fetch, the memfd exec,
  and the fail-closed leg on tampered bytes, the aarch64 one under the
  kernel's binfmt with qemu-user on the build host.
- **Every build mints the enrollment credential it bakes.** The token is
  minted at build time (single use by default, inside the artifact's kill
  window), baked into the profile's `token` key, and reported by id only --
  the operator never handles the plaintext, and the leak answer is revocation
  by id (`POST /engagements/{id}/deploy-tokens/{tokenId}:revoke`, audited as
  `DeployTokenRevoked`). The manual mint stays for the rotation and re-entry
  flows (Sec 9), scoped per request to uses and window. A delivery campaign
  (Sec 11.5) mints through the same path once per recipient -- the campaign
  engine holds the mint, the baked credential stays plaintext-free
  everywhere an operator reads -- because a per-recipient token is what
  attributes the enrollment that redeems it.
- **The transform seam is post-build.** Build-time artifact transformation
  -- where MSF put its encoders and payload encryption -- is a
  config-listed `IPayloadTransform` chain (each transform owns its key
  material and decode contract end to end; against modern EDR the classic
  encoders are legacy anyway). Each transform names itself, receives the
  built bytes plus the build context, and returns transformed bytes plus
  metadata; the chain runs after the build unit and before anything is
  recorded, so the stored fingerprint covers exactly the transformed bytes
  and the `PayloadBuilt` audit event names every applied transform. No
  in-tree transform ships: the empty chain is the seam, exactly like the
  capability placeholders, and transforms arrive through the explicit
  `Build:Transforms` list (the same loading shape as `Capabilities:Modules`,
  [extending/modules.md](extending/modules.md)). A shellcode-form
  transform (turning a built artifact into position-independent bytes for
  the loaders that want them) is the seam's canonical occupant.
- **Artifact tracking.** Every generated artifact is fingerprinted and recorded
  (who, when, config) into the audit trail.

The build contract is the language-neutrality boundary; it is what lets the wire
protocol be "the product" while implants stay polyglot.

## 7. OPSEC -- a first-class design axis

OPSEC is a design axis, not a feature flag. The architecture bakes in:

- **Per-implant beacon profile, including the contact mode.** Two shapes ride
  the same stream contract: **stream** holds one long-lived connection (the
  interactive shape -- server-push tasking, no reconnect cost) and **poll**
  drains queued tasking, closes, and sleeps the interval with **jitter**
  (randomized delta) before the next contact -- the low-and-slow shape, since a
  persistent connection to a C2 endpoint is itself a loud signal. The mode is
  baked per implant at generation (`mode: stream|poll` on the build request;
  poll is the default -- every front serves it, and holding a connection is
  the shape an operator opts into), so one engagement can mix an interactive
  foothold with sleeping beacons.
- **Kill date.** A hard self-termination timestamp baked in per implant to limit
  exposure if lost. Enforced on both sides: the teamserver refuses a handshake
  past it (`HANDSHAKE_STATUS_KILL_DATE_EXPIRED`, no session opens), and the
  implant refuses to start past it and re-checks it each beacon cycle so a
  long-running implant self-terminates the moment the date passes.
- **Per-implant cryptographic identity.** Each implant generates its own ECDSA
  P-256 keypair at first run (effectively instantaneous, where RSA-2048 keygen
  costs ~100ms on-target and produces the larger leaf on the wire) and submits
  only the public half at enroll; the teamserver
  CA signs a leaf bound to (implant_id, engagement_id) over it. There is no
  shared secret anywhere, and the artifact carries no key material at all, so a
  captured payload compromises nothing. Compromise handling is the operational
  flow *retire the implant (refused at the next handshake), repoint its
  endpoint, and build a fresh artifact* (Sec 8) -- there is no live in-place
  key swap.
- **Malleable transport profiles.** Configurable URIs, a User-Agent, custom HTTP
  headers, a per-request timeout, and a body envelope baked in per implant so the
  enroll wire shape matches legitimate traffic and two implants do not look the
  same (Sec 8). The profile is part of the baked-in profile (Sec 5.1) and is
  applied by the reference implant's enroll client: it enrolls against the
  profile's URI path, presents the profile's User-Agent and headers, honors the
  timeout, and wraps the JSON body as a single base64 string when the envelope is
  set to base64.
- **Disposable infrastructure.** Keys, identities, and endpoints are ephemeral
  per engagement; burned redirectors are swappable at runtime (Sec 8).
- **Redirector decoupling.** Filter by User-Agent / URI / IP / OS; forward only
  real beacon traffic, send the rest to a decoy.
- **Per-command OPSEC metadata.** Commands carry OPSEC flags (e.g. "writes to
  disk") so operators and tradecraft filters can avoid risky actions.
- **Burn handling.** Retire an implant (it is refused at handshake and untaskable
  thereafter, its active session closed, the retire recorded in the audit trail);
  repoint a listener's public endpoint to swap a burned redirector without
  touching the backend, which severs the old endpoint.

> This section defines what the platform must **provide** for OPSEC. Concrete
> tradecraft beyond it is an operator-supplied capability module (Sec. 10).

## 8. Transports, listeners, and redirectors

- **Listeners come in two tiers, and only one of them is implant ingress.**
  The startup configuration names the shared tier -- the operator front the
  UI and API ride -- which carries **no implant ingress at all**: enrollment
  and the payload fetch are refused on it outright. Implant-facing listeners
  are **engagement-scoped**: created through the operator API against exactly
  one engagement, persisted (in-memory with the process, Postgres when
  configured; a restart rebinds them with the same ids), and enforced at
  enrollment -- enroll and the payload fetch resolve the listener a request
  arrived on, and anything but that engagement's own token is refused whole
  and unspent on that socket. Ports are unique across both tiers: the
  create-time bind check refuses a collision with a clear error before any
  socket opens. A payload build names its engagement's listener and the
  baked endpoint comes from the listener's record -- a typed endpoint is
  refused outright: this teamserver cannot verify an address no listener
  names, and a front that does not reach it only bakes an artifact that
  can never enroll. Fronting is the front list's job for every family,
  the DNS pair included (the primary front names the resolver; the record
  keeps the zone).
- Supported listener transports: **HTTP(S)** (the single-port shape: one
  TLS socket that requests no client certificate anywhere, so the handshake
  is indistinguishable from an ordinary website's -- enrollment rides the
  deploy token and contacts ride the sealed envelope under the per-artifact
  key, both authenticated at the application layer), **DNS**, **raw TCP**,
  and **DoH** (the DNS grammar over RFC 8484 HTTPS bodies -- the
  egress-restricted carrier behind a shape a restricted network already
  allows). This is the settled four-family surface: the web pair, the DNS
  family, and the raw socket, every engagement shape among them. The
  mTLS/gRPC, QUIC, and SMB transports are retired -- the client-cert gRPC
  stream was redundant with the WebSocket beacon (the same session runner
  on a front the redirector story already serves), QUIC's async-runtime
  cost only pays when an engagement's egress passes UDP but blocks TCP and
  names that need by hand, and SMB's named-pipe reach is covered better by
  the pivot model (a parent implant fronts its children's tasking over
  whatever carriage it holds, so no pipe exists to name). The frozen wire
  contract keeps the QUIC-only frame kinds reserved; a community unit
  reviving a family registers a provider against the same contracts.
  _(shipped)_ **WireGuard** is the in-tree optional transport over the
  provider seam the surface runs on (`ITransportProvider`; the
  registration manual is
  [extending/transports.md](extending/transports.md)): default-disabled,
  enabled by the deployment and named per build -- a build against a
  wireguard listener is the transport-enable set. The envelope's own
  frames and seal ride WireGuard-encrypted UDP, one datagram per contact
  on the datagram budget; enrollment rides the tunnel's opening exchange
  (the EnrollRequest frame promoted into the rod.v1 grammar, the same
  full-independence step the stream and DNS carriages took); the tunnel
  state is the native boringtun router behind a small C ABI, so no
  WireGuard cryptography exists in C#, and a build mints the artifact's
  X25519 pair -- the private half baked, the public half registered on
  the listener's router and restored from the payload store on a restart.
  The wire contract is [extending/implants.md](extending/implants.md)'s
  WireGuard section. mTLS stays retired with QUIC and SMB -- the
  reopening ADR-004 once carried is rescinded (Sec 15.3): the retirement's
  reasoning has only strengthened since, so an operator who wants it
  anyway takes the out-of-tree provider registration that is any
  community family's route in.
  Transport choice is a profile/deployment concern; the protocol semantics
  are transport-independent. The web family additionally serves the
  WebSocket beacon (`GET /implants/beacon/stream`,
  extending/implants.md): the same live session the socket family's held
  connection runs, over the envelope's own auth and frame grammar, so a
  web-fronted implant holds the interactive tier without any protocol
  stack beyond an HTTP client -- the reference implant's stream-mode web
  build dials it, and a poll-mode build keeps the envelope POST cycle.
  The web transports declare the beacon-stream carrier for issuance
  gating.
- **Plain HTTP is the loopback dev posture.** An `Http` listener entry binds a
  socket with no TLS and no client certificates, and every mapped route rides
  it: the operator API and UI in the clear, and contacts identified by the
  implant id in their handshake alone -- the DNS/TCP tradeoff, but on a
  socket anything with reach can present. The dev fallback binds loopback
  for exactly that reason, and a non-loopback plain-HTTP bind logs a startup
  warning naming this posture. The cleartext contact carrier is the
  envelope route (an ordinary HTTP/1.x POST), where the per-artifact key
  sealing the body is the identity -- no transport-layer client
  certificate exists anywhere in the surface, retired with the mTLS
  transport. A deployment that fronts the teamserver with its own
  TLS-terminating edge accepts the split knowingly; without such an edge,
  real binds are `Https`.
- **DNS is the egress-restricted contact transport, and it carries its own
  enrollment.** A DNS listener entry
  answers TXT queries under its public endpoint (the zone) over UDP: a poll
  (`p.<b32(implant-id)>.<zone>`) refreshes an implant's presence and returns
  the next queued tasking as a signed `TaskRequest` in TXT; result chunks
  (`r.<b32(task-id)>.<s|f>.<seq>.<t|m>.<b32(chunk)>.<b32(implant-id)>.<zone>`)
  report outcomes, reassembled server-side. The wire grammar is the DNS
  contact contract ([extending/implants.md](extending/implants.md)); the
  responses ride EDNS0 so a signed TaskRequest fits the datagram, and a task
  too large for the budget is not claimed over DNS: it stays queued for a
  stream transport. **Staged transfers ride the same grammar (ADR-010):** a
  staged task the poll claims is demanded at a byte offset with a SHA-256
  prefix proof (`s.<b32(task)>.<offset>.<b32(proof)|e>.<b32(implant)>`),
  answered by a token whose `d.` probes drain the remainder chunk by chunk --
  the same resume rule the frame carriages run, at the query-rate cadence,
  per-chunk sealed for a keyed artifact under the staged purpose tag. **The
  upload arm rides the same grammar's discipline, sealed-only
  (ADR-010):** an exfil run probes its seam
  (`x.<b32(task)>.<b32(sha128 of name)>.<b32(implant)>`, answered with the
  held byte count) and serves one datagram-sized blob per cycle as an
  e.-shaped `u.` upload stream -- a single sealed `ExfilChunk` slice under
  the `rod-dns-exfil-v1` tag placing at its offset in the shared per-task
  store, under a 1 MiB per-stream ceiling. The seal is the arm's
  spoofing boundary: the task id rides the query name in the clear, and a
  plaintext upload would forge evidence onto real tasks, so a blob no
  baked key verifies drops whole. **Delivery confirmation:** a lost chunk drops a
  report's reassembly whole, so the sender probes
  `n.<b32(task)>.<b32(sha128 of the plaintext)>.<b32(implant)>` after
  chunking and keeps the frame pending until the `y` answer -- the
  re-send rides later cycles idempotently (first-wins recording), the
  reliability shape a datagram carrier needs without a per-chunk ack
  protocol.
  **The record-type cover:** an A query anywhere under
  the zone answers one A record (the bind's own host, else a deterministic
  per-name address in 198.18.0.0/15) -- a zone answering TXT for random
  labels but NXDOMAIN for every A query would itself be the fingerprint,
  and an ordinary v4 zone answers its A records. AAAA and other types keep
  the NXDOMAIN a v4-only zone gives; out-of-zone queries stay REFUSED.
  **The store-and-forward channels ride the polls (Sec 10.3):** the poll
  answer carries a kind byte naming its frame -- a queued task, or the
  parked operator input the degraded hub drained (every frame the drain
  collected, length-prefixed, so a typing burst and its eof cross
  together) -- and the channel's output chunks up as `c.` queries,
  reassembled and ingested through the shared composition the beacon
  stream uses. The DNS carrier serves the degraded discipline: the
  slowest wire that carries the interactive verbs, carried anyway -- the
  operator's pick, at the query-rate cadence.
  **Enrollment over DNS (the full-independence step for a DNS-only
  target):** the enroll body uploads as chunked TXT queries
  (`e.<b32(stream)>.<seq>.<t|m>.<b32(chunk)>.<zone>`) keyed by a
  client-chosen stream id -- sealed under the baked per-artifact key when
  the artifact carries one, so the token secret never crosses the resolver
  chain in the clear -- and the assembled `EnrollResponse` chunks back down
  as token-keyed answers (`a.<b32(token)>.<seq>.<zone>`). The terminal
  chunk drives the shared `ScopedEnrollment` flow scoped by the answering
  listener's engagement, and an accepted DNS enrollment opens the session
  itself (no handshake exists to open it): the polls that follow refresh
  what it wrote. A DNS-only target runs its whole lifecycle on this one
  carrier -- the lightweight implant. **The contact carriage seals for a
  keyed artifact:** a build that baked an envelope key polls `k.`-named
  (the key id in the name, so the server resolves the seal statelessly and
  a restart re-derives it on the next poll), the poll answer rides as a
  raw R1 AES-GCM body under a DNS-purpose tag, and results and channel
  outputs seal whole before chunking under their own tags -- the resolver
  chain reads no frame bytes in the clear. The seal is confidentiality,
  not authority: the signature still gates execution, and the server
  refuses the plaintext downgrade for a key-bound implant (an empty
  `p.` answer, a dropped plaintext reassembly) so tasking is never handed
  down in the clear to an artifact known to carry a key. The transport's tradeoff is deliberate and documented: no
  handshake rides DNS, an implant is identified by its id alone
  on the contact path (the sealed enroll exchange authenticates by key
  possession). Downstream tasking keeps the full Sec 9 posture -- the
  TaskRequest carries the same command signature, and a DNS-delivered task
  verifies exactly like a stream-delivered one. The degraded-mode contract
  rides the session record: every contact stamps the carrier it rode (web,
  dns, pipe), the roster badges a dns-carried session as
  degraded, and a task the carrier cannot serve stays queued with its
  visible why -- capability is a property of the carrier at runtime, not of
  the artifact. The reference Rust implant carries this family end to end:
  classic UDP and DoH dials, the chunked enroll exchange, sealed polls, and
  the delivery-confirmed upstream chunks.
- An implant is always the **connection initiator** (reverse connection). The
  teamserver and redirectors never dial targets.
- **A redirector control plane rides over the manual fleet** _(shipped)_.
  A redirector enrolls as a managed node and is driven from the teamserver;
  the manual hand-deployed fleet remains a fully supported shape beside it.
  The settled decisions, as built:
  - **The redirector dials home.** The control channel is
    redirector-initiated and outbound-only: no management listener sits on
    the edge box, so the fleet adds no fingerprint beyond the beacon ports
    that must be open anyway, and nodes behind NAT or egress policy still
    reach the teamserver. The channel is a WebSocket on the deployment's
    shared tier (`GET /redirectors/control`), refused outright on the
    engagement-scoped implant ingress -- the same shape as the platform's
    own rule above (everything dials home), but a deployment-scoped surface
    that never rides an engagement's sockets.
  - **Nodes are deployment capacity; attachment grants scope.** A redirector
    node belongs to the deployment (the machine pool), and inherits an
    engagement's scope only by being attached to that engagement's listener.
    The fleet record carries no engagement data; identity is a single-use
    pre-provisioned enrollment credential (minted through the operator API,
    hash-stored, shown once) whose enrollment mints the node's durable
    secret -- reconnects ride that secret, retirement refuses them by name,
    and a wrong secret reads as unknown so the channel offers no existence
    oracle.
  - **A listener carries an ordered front list.** The record's single public
    endpoint became the primary front of `fronts[]`, each front an
    attachment to an enrolled redirector that the control plane provisions
    with the forwarding rule (listen on the front's endpoint, splice to the
    listener's bind) -- repoint is re-attaching or promoting the primary
    front, and one-bind-many-fronts needs one listener record, not one per
    front. Every front mutation is audited in the engagement's trail
    (`ListenerFrontChanged`); the node-side rule push is derived state, not
    a separate fact.
  - **The control protocol stays small.** Enroll once against the
    pre-provisioned credential, reconnect with the minted secret, heartbeat
    (build provenance and presence), and receive full-state rule pushes --
    digest-keyed, so a node that missed a push converges on the next one
    and its forwarders (one opaque L4 splice per rule, reconciled by the
    push) never restart needlessly. It is not a second wire protocol and
    grows no capability surface of its own.
  - **The data plane stays dumb.** The forwarder remains an opaque L4 TCP
    splice -- no TLS termination, no payload inspection, no engagement
    tenancy. The application-layer seal crosses it intact, which is the
    security model's load-bearing wall; the smarts live in the control
    plane only. The node's identity persists beside its binary and its
    data plane outlives the control link: a dropped connection reconnects
    with capped backoff while the forwarders keep splicing the last
    applied rules.
  This dissolved the recorded seams: the one-listener-per-front workaround
  and most of the manual deploy/rotate runbook (rotation is now
  promote/re-attach with no manual binary reconfiguration; the runbook
  keeps the manual fleet as the fallback shape), and -- with the datagram
  relay the node's rule set also carries -- the typed DNS dial: a dns or
  doh front attaches like any other, its public endpoint names the
  RESOLVER implants dial (host or host:port; the zone stays the listener
  record's own public endpoint, and the record's endpoint never follows
  the primary front the way the other families' does), the rule rides the
  node's UDP relay (source-keyed datagram forwarding, protocol-blind --
  the one carriage addition the data plane ever took), and a build against
  a fronted listener bakes `{scheme}://<front resolver>/<zone>`. The
  typed-endpoint escape in the build request is gone with it: fronting is
  the front list's job, a shape this teamserver can verify. The wire
  protocol, the implant, and the walk's family rules are untouched -- the
  whole feature is control plane.
- **Listener and public endpoint are decoupled, and the endpoint is repointable
  at runtime.** A redirector fronts the listener; a burned redirector is replaced
  without touching the backend by repointing the listener's public endpoint
  (`POST /engagements/{engagementId}/listeners/{id}:repoint`). The Kestrel
  bind is untouched; the old
  endpoint simply no longer resolves to any listener, which severs it. This
  decoupling is what makes disposable infrastructure practical. The in-tree
  reference redirector -- an opaque L4 TCP forwarder published as a Native AOT
  binary -- ships this rotation end to end; see
  the deploy/rotate runbook ([operations/redirectors.md](operations/redirectors.md)).
- **Fallback egress endpoints are baked in and walked client-side.** A build
  may carry an ordered endpoint list -- the primary plus fallbacks (Sec 5.1) --
  and the implant walks it on failed contacts: enroll retries and beacon
  cycles that never reach a handshake advance to the next entry, wrapping to
  the primary so a front that returns is picked up again. Every fallback
  dials the primary's own scheme family (http/https, dns/doh, or tcp): one
  build rides one protocol, and the TLS posture spans the walk (the artifact
  bakes one root set) -- the build refuses the mix rather than baking a list
  the operator cannot reason about. The walk is entirely
  client-side -- the Tier 0 frame grammar is untouched -- and it never touches
  identity: the implant presents the same enrolled leaf whichever entry it
  lands on, so its listener-side identity is unchanged and a listener cannot
  tell which front an implant arrived through. This is the implant-side answer
  to a burned front, complementing the server-side repoint above: repoint
  swaps the front for future builds, the baked walk keeps the already-deployed
  implant talking. Verified end to end by the implant subprocess tests (a dead
  primary, a live fallback, one identity).
- **Message sizing and flow control.** A single frame stays well under 1 MiB and
  never exceeds the negotiated maximum. Bulk data (files, output) is chunked.
- **Malleable transport profile (per implant).** Each implant carries a transport
  profile baked in at generation (Sec 5.1, Sec 7): an enroll URI path, a
  User-Agent, custom HTTP headers, a per-request timeout, and a body envelope. It
  is applied client-side at enroll -- the reference implant enrolls
  against the profile's path and presents its headers, timeout, and body shape --
  so a profile changes the wire shape. The teamserver's enroll route stays fixed
  at `/implants/enroll`; URI and header routing at the public endpoint is a
  redirector concern (Sec 7). Verified by the build-pipeline round-trip tests
  and the end-to-end legs that exercise a profiled enroll.
- **The plain-HTTP envelope contact is the implant-reach transport and the
  reference implant's web contact.** The same rod.v1 frames every carriage
  carries, marshaled as varint-length-delimited sequences in ordinary
  HTTP(S) request/response bodies -- one POST (`/implants/beacon`) is one
  poll contact: the request body carries the handshake first plus any
  results, exfil chunks, and staged pulls; the response carries the handshake
  response, the staged chunk runs answering the request's demands, and
  queued tasking while a 4 MiB dispatch budget lasts (what does not fit is
  requeued for the next contact). It changes the framing, not the protocol
  semantics: the route is mapped on every listener and the frame paths are
  the beacon compositions every transport shares (the retired
  `HttpsEnvelope` listener name said nothing the transport list did not;
  its stored definitions migrate to `https` on restore). Authentication is at the application
  layer, under the per-artifact key the build mints (Sec 9) -- the mainstream
  HTTP(S) C2 shape, and the reason the `http`/`https` listeners are
  single-port and request no TLS client certificate anywhere: a
  CertificateRequest is itself a fingerprint an IDS reads. The default body
  is that key sealing `counter || frames` as AES-256-GCM, and the response
  seals the same way, so the cleartext `http` posture carries confidential
  content, not just authenticated content; the counter is strictly increasing
  per attempt and the route refuses one at or below its floor (a replayed
  body turns away without a session or a touch), and an enrollment that
  redeemed a build-minted token is bound to that build's key, so its contacts
  cannot downgrade to the plaintext frame. The plaintext framed body is the
  lab-debug toggle's shape (contact protection off at build), served only
  for implants no key was ever bound to. The reference implant picks its
  contact client by the baked dial's shape: an `http(s)://` URL runs the
  envelope POST cycle on that port -- the mainstream single-port web
  posture, the build's derived default for `Http`/`Https` fronts. The
  WebSocket beacon hangs off the same schemed front. Tier 0 is reachable from any
  language with an HTTP client and a protobuf codec
  ([extending/implants.md](extending/implants.md)). A channel task claims
  over the envelope under the store-and-forward discipline every poll
  artifact advertises (Sec 10.3; only the DNS datagram poll refuses one).
  An exfil run rides the resumable upload arm (ADR-010): each body carries
  the slices its budget admits, the response's seam reports chain the
  contacts, and a run larger than one body spans them -- the
  one-request-body bound on exfil runs is gone.
- **The browser-hook serving edge is a public route on the implant-facing
  listeners, gated by an unguessable id.** A Browser-class hook (Sec 5.2)
  is minted per engagement (`POST /engagements/{id}/hooks`): the mint
  renders the hook script from the listed hook asset module (Sec 15.1; the
  mint refuses loudly while no module is listed) with the enroll URL,
  deploy token, seal key, cadence, and verb list baked in, and stores the
  rendered artifact as an engagement payload record, so the serving route
  reads the same store every artifact route does.
  `GET /implants/hooks/{hookId}` serves the script and
  `GET /implants/hooks/{hookId}/page` a minimal test page, both scoped by
  the ingress listener's engagement and gated by the route's unguessable
  id -- the shape where the capability URL is the credential -- with
  no-store caching and one `HookFetched` audit event per fetch recording
  the fetcher's wire facts, the first-touch attribution the fetching
  browser's enrollment then binds to an implant row. The token the bake
  carries is the enrollment budget: each hooked browser's enrollment spends
  one use, so the operator sizes the mint. Because the hook runs on the
  victim page's origin, its contacts are cross-origin: the hook routes (and
  the enroll and beacon routes they ride) answer
  `Access-Control-Allow-Origin: *` only when the request carries an
  `Origin` header -- a browser-only shape, so non-browser implant traffic
  and its fingerprint are unchanged -- and the hook stays a
  simple-request client (plain bodies, no custom headers), so no preflight
  is ever needed.
- **The lure serving edge is the hook shape carrying an artifact.** A
  delivery campaign's per-recipient link (Sec 11.5) is served from the
  same public family: `GET /implants/lures/{lureId}` and its
  `.../open` tracking pixel are gated by the route's unguessable id,
  scoped by the ingress listener's engagement with the same refusal the
  enroll and fetch routes run, answered `no-store`, and audited on every
  serve with the fetcher's wire facts. The link route serves the
  recipient's built artifact -- the click is both the evidence and the
  delivery -- so a redirector fronts it exactly as it fronts every other
  public edge: the listener's `publicEndpoint` composes the URL the
  template merges, and the backend socket never changes.
- **The raw-TCP listener answers weak-inspection egress.** It is the front
  for environments that permit arbitrary outbound sockets but put nothing
  between them and the internet -- no HTTP inspection to blend with, no
  TLS requirement to satisfy -- so a plain framed socket is the cheapest
  adequate shape. The Windows segment with no egress at all -- the reach
  the retired SMB family once served -- is covered better by the pivot
  posture: a parent implant
  holding the outward session derives children inside the segment
  (`lateral.move`, Sec 5.2), and the children's tasking rides fronted on
  the parent's carriage -- implant-to-implant reach that goes deeper into
  the environment as far as the parent chain goes, with no pipe to name
  and no second artifact shape to maintain. The listener carries
  the same rod.v1 frames the envelope carries -- one self-delimited message
  per direction (a varint byte length, then the envelope's delimited frame
  sequence), because a raw stream lacks the request boundary an HTTP body
  provides for free -- through the shared frame paths (`BeaconIngest`,
  `BeaconTasking`): a result captured over a pipe or socket is
  indistinguishable in core state, the audit trail, and the live bus from one
  captured over any other carriage. One connection is one poll contact, the
  envelope's cadence on the envelope's budget, and channel tasks claim under
  the store-and-forward discipline every poll artifact advertises (Sec 10.3)
  -- operator input parks server-side and rides the next connection's
  response.
  **Enrollment over the stream contact (the full-independence step):** the
  opening message may carry a kind-bearing
  `EnrollRequest` frame ahead of its handshake -- the enroll body the web
  route carries, promoted into the rod.v1 frame grammar -- answered by an
  `EnrollResponse` frame as its own message, the ordinary handshake
  following on the same connection. The shared `ScopedEnrollment` flow does
  the work, scoped by the listener's own engagement with the web route's
  refusal rules and audit arc, so a no-egress segment can enroll its first
  implant over the socket it already reaches. The reference Rust implant's
  raw-TCP carriage carries it end to end: the parser bakes the transport's
  own dial (`tcp://host:port`), the enroll exchange runs the frame grammar
  on the dial, and the poll cycles ride the envelope's own
  request/response shape over the message framing -- one connection is one
  contact, the interactive verbs on the shared store-and-forward carriage
  every poll client runs. **The stream mode holds the connection
  instead:** the handshake's live advertisement switches the server to the
  shared session runner (the WebSocket beacon's own), so a stream-mode
  bake over a socket gets
  server-push tasking and live channels on the held connection -- the same
  dial, the mode picking the client that dials it, and an older teamserver
  serving the connection as an ordinary poll contact when it does not
  know the advertisement. The sealed body rides by default: the enroll
  exchange and every contact message are AES-256-GCM under the baked
  per-artifact key (counter-floored on the contact side, purpose-tagged
  on both), the same application-layer seal the cleartext http posture
  carries -- a bare socket or pipe leaks no frame bytes either, and the
  token secret never crosses in the clear.
  The identity posture is the certificate-less one: no client certificate
  rides a raw socket, so the implant is identified by the id in its
  handshake -- the DNS tradeoff extended to a handshake-capable transport,
  with the enrolled, kill-date, and retired gates applying in full (a raw
  socket rides whatever segmentation protects it, and the sealed body means
  it leaks no frame bytes either).
  Dispatched tasking keeps the full Sec 9 posture: the TaskRequest carries
  the same command signature, and a stream-delivered task verifies exactly
  like any other. The entry is a hosted service owning its socket,
  registered into the listener registry the same bind-then-register way every
  transport follows (`StreamBeaconBridge` is the transport-blind contact
  flow); the wire grammar is the stream contact contract
  ([extending/implants.md](extending/implants.md)), pinned end to end by the
  stream-enroll acceptance tests (a from-scratch TCP client drives
  enroll-then-contact on one connection, and a foreign engagement's token is
  refused whole and unspent).
- **The shellcatch transport holds caught reverse shells.** Where the TCP
  listener serves contacts -- one connection, one rod.v1 exchange,
  closed -- the shellcatch listener (`"shellcatch"`) accepts connections
  that speak no Rod protocol at all: the peer is whatever reverse-shell
  one-liner the operator ran on the target (nc, a bash `/dev/tcp` pipe, a
  perl or python snippet), it never enrolls and carries no identity, so
  the catch is scoped the only way an anonymous arrival can be -- by the
  engagement-bound listener it landed on. The connection is held (not
  one-exchange-per-connection): output flows onto a bounded,
  sequence-coursed log the operator console long-polls by cursor, the
  first output chunks are fingerprinted server-side into an OS/shell
  guess that never downgrades, operator input rides the audited input
  route down the socket, and the ending is attributed to who ended it
  (Lost when the peer goes away, Closed when an operator asks). The
  shell session registry is the anonymous-arrival sibling of the implant
  session registry, engagement-scoped the same way by construction. The
  shell leaves the hub the moment its socket dies, before the durable
  marking, so no route resolves a dead socket. An upgrade render is
  advisory: it mints the engagement a single-use deploy token and returns
  paste-ready one-liners against the engagement's web listener -- the
  four families the launcher renderer emits (`unix-curl`, `unix-wget`,
  `windows-powershell`, and the Linux in-memory `unix-python-memfd` that
  stages the bytes in a memfd and execs through /proc/self/fd),
  filtered to the payload's target OS so the credential is never spent
  on a download that cannot run -- the paste is the operator's
  action through the input route, not a server-side write into the
  session. The standalone launchers endpoint renders the same one-liners
  without a caught shell -- the cut-ahead delivery surface, where the
  credential's use budget and lifetime are the operator's choice (the
  shell upgrade always mints single-use for thirty minutes: one paste,
  one download). Every render the endpoint cuts is kept as a launcher
  row -- url, credential, policy, provenance -- so the operator can
  re-copy a command at any time, watch the credential's budget, revoke
  it the moment it leaks, and delete the row when it is spent; the rows
  are engagement-scoped operator state, durable with the store.
  Shellcatch serves no contact carrier -- nothing here is
  implant ingress, and a build may never name it as its front. The
  exposure is inherent and named: a shellcatch port accepts whoever
  reaches it (the one-liner carries no secret); the mitigations are a
  fronting redirector's source allow-list, a non-default port, and a
  short-lived listener -- the same infrastructure discipline every
  ingress follows.
- Redirectors forward opaque payloads. The in-tree reference is an opaque L4 TCP
  forwarder (Native AOT) that never terminates transport, so the beacon
  channel and the HTTPS enroll request carry through end to end. It is L4, not
  L7, because the contacts are sealed at the application layer -- an L7
  peek would re-introduce
  transport-specific logic for marginal gain while breaking the AOT-clean,
  property. v1 runs one forwarding rule per process so a burned
  port does not drag the others down (rejected: a multi-rule single process as
  a single point of failure across ports). Source-IP allow-listing is the only
  routing an opaque L4 forwarder can do; malleable User-Agent/URI routing lives
  inside TLS and stays a TLS-terminating-edge concern an operator layers on. A
  deployment that needs such L7 routing terminates TLS at its own edge -- that
  is an operator deployment concern, not an in-tree capability.

## 9. Security model

Rod delivers remote code execution for its operators: a compromised teamserver is
fleet-wide code execution. Security is a first-class concern.

- **Identity.** Operator identities (credentials and API tokens) verified at
  login and per request; implant identities bound to their engagement by the
  transport they contact over -- the per-artifact contact key on every
  transport (below). What an operator may do inside engagements rides no
  credential at all: access derives from engagement memberships (Sec 4.5),
  resolved fresh against the store on every engagement-scoped request, so a
  re-tier or removal takes effect at the next request. The one privilege a
  credential does carry is the deployment role -- the claim the login and
  the token resolution stamp from the account row, fixed at registration,
  gating the deployment-management surfaces (Sec 4.5). API tokens are
  bearer credentials minted per operator
  through the operator API (shown once, stored as a digest), honored alongside
  cookie sessions through a front scheme that authenticates by what the
  request presents, and revocable by their own route with the same
  immediate-effect, no-restart shape. A token is independent of the password:
  each credential revokes through its own route, so rotating one never
  silently invalidates the other.
- **Contact keys.** The web transports authenticate implants at the
  application layer, not the TLS layer -- a TLS `CertificateRequest` is
  itself a fingerprint (an ordinary website never asks the visitor for one),
  which is why the `http`/`https` listeners never send one. Each build mints
  a per-artifact AES-256 key (the same envelope-key shape the opt-in AesGcm
  enroll body uses), bakes it into the artifact, and records it beside the
  stored payload: deleting the payload deletes the key, and that artifact's
  sealed bodies stop being decodable -- enroll included. Contact protection
  defaults on at build (its own Advanced knob beside the enroll-body
  envelope; off is the lab-debug plaintext frame), and every envelope
  contact body is then AES-256-GCM under that key covering a strictly
  increasing counter -- possession of the key is the authentication, the
  GCM tag binds the counter to the frames, the server keeps a per-implant
  floor and refuses a counter at or below it (a replayed body never opens a
  session or touches presence), and the response seals the same way, so the
  cleartext `http` posture carries confidential content, not just
  authenticated content -- the Cobalt Strike metadata model. Each direction
  binds to its own purpose tag, so one direction's ciphertext cannot be
  reflected as the other's. When the redeemed enroll token was the one the
  build minted, the enrollment binds the implant to that build's key: a
  plaintext body from a bound implant is refused whole (no downgrade to the
  lab shape) and another artifact's key does not impersonate it. The counter
  burns per POST attempt, not per delivery, so the batch retransmission
  after a lost response never trips the floor. The floor and the binding are
  process-local like the sessions they protect; the key itself lives exactly
  as long as its payload record.
- **Production implant CA.** The teamserver consumes an externally provisioned
  engagement CA; it does not generate the production CA. When
  `Pki:CaCertificatePath` and `Pki:CaPrivateKeyPath` are configured,
  `FileBackedCertificateAuthority` loads the CA certificate and its RSA private
  key (optionally passphrase-encrypted) from disk and issues the listeners'
  TLS server leaves with the same leaf construction the dev authority uses --
  only the issuer changes. Absent the config the dev self-signed authority
  stays. The authority is built
  eagerly at DI registration, so a missing file, an unparseable PEM, a non-RSA
  key, or a key/cert mismatch fails the host at startup, not the first
  enrollment; RSA is the only supported CA key type, the server-held signing
  key. Rotation is operational (replace the files and restart). Rejected:
  generating and persisting the CA from the teamserver (re-creates the dev
  posture -- key in the C2 -- at production privilege); and `IOptions<T>`
  binding for the `Pki` section (diverges from the audit store, the other
  config-selected adapter, which reads its key straight off `IConfiguration`).
  Each server leaf carries a SAN naming its front's public host (an IP literal
  as an IP SAN, a hostname as a DNS SAN): the reference implant's rustls client
  pins the CA but runs full webpki validation, server-name matching included,
  so a nameless leaf strands every https front -- an earlier draft rejected
  the SAN as separable hardening on the false premise that pinned clients do
  no name matching.
- **TLS trust is the front's posture, inherited by builds: pinned (the
  default) or public.** The listener records whose certificate its front
  presents -- the fact lives where the certificate is deployed -- and every
  build against that listener bakes the matching roots; the build request's
  old `Trust` knob may only agree with the front. Pinned
  is the self-sufficient shape: the baked CA is the only root the
  artifact's TLS dials trust -- no public-PKI or target-store dependence,
  and no public CA can mint an identity the artifact would accept; it works
  for any domain the operator points at the listener, because the CA mints
  the front's leaf with a SAN naming the listener's public host. Public is
  the real-domain posture for blends that
  must survive TLS inspection: the front is a genuine domain whose
  certificate a public CA issued (terminated at an operator-run edge
  holding the domain's certificate, in front of the teamserver's web front
  whose public endpoint then names the domain), and the artifact validates
  it like an ordinary client against the compiled-in Mozilla root set
  (`webpki-roots`; still no target-system-store dependence). The CA rides
  the bake under either posture -- it is the tasking signer; the posture
  says only which roots the TLS dials accept. Public is gated to https
  dials at listener creation, and the walk's fallback TLS fronts must
  share the posture -- the artifact bakes one root set, so
  a front presenting the other certificate is a dial the walk cannot
  verify, refused at parse time with the fix named.
- **Command signing.** Dispatched tasks are signed so an implant only acts on
  teamserver-authorized tasking. The beacon endpoint signs each dispatched
  `TaskRequest` with the tasking CA's RSA key (RSASSA-PSS over SHA-256, on a
  canonical length-prefixed encoding of `implant_id`, `task_id`, `verb`,
  `arguments` documented on the proto message -- not on the serialized
  message, so every implant language verifies identically without depending
  on protobuf field ordering). The implant id in the signed tuple is the
  target implant's own identity, binding tasking to its intended executor: a
  captured signed frame fails verification on any other implant under the
  same CA. The signing key is the same CA that issues implant leaves,
  reached through `SignTasking` on the CA port: the implant already holds
  that CA certificate from enrollment or its pinned bundle, so tasking trust
  rides enrollment trust and no new key distribution exists to protect. The
  implant verifies before any handler runs; an unsigned or wrongly signed
  task is reported `Failed` with the cause on the task itself, so the
  rejection is visible on the operator console and nothing executes.
  Deployment
  order matters: this implant rejects unsigned tasking, so the teamserver
  signs -- upgrade it before deploying implants built from this contract.
  Rejected: a dedicated task-signing key pair (a second teamserver-held
  secret to provision, rotate, and bake into artifacts, for no isolation
  gain while the CA key is already the server's signing identity); signing
  the serialized `TaskRequest` bytes (couples verification to one protobuf
  runtime's serialization behavior).
- **Tasking replay nonces.** Command signing binds tasking to its implant,
  but a captured signed frame used to verify on replay to the same implant.
  The arm is negotiated at handshake: an implant that sets
  `replay_nonces` on its `HandshakeRequest` gets every dispatched
  `TaskRequest` stamped with `task_nonce` -- a per-implant monotonic counter,
  increasing across dispatches, sessions, and transports -- and the tasking
  signature covers the five-element tuple (the original four plus the nonce's
  decimal string in the same length-prefixed form), so the nonce cannot be
  altered any more than the arguments can. The negotiation is sticky on the
  implant: once advertised, later handshakes cannot downgrade tasking back to
  the nonce-less shape. The implant tracks the highest nonce it accepted --
  for its whole run, not per connection -- and refuses any at or below it,
  reporting the refusal as the task's `Failed` result so a replayed frame
  surfaces on the task instead of silently re-executing; once negotiated, a
  nonce-less task is refused too. An implant that never advertises keeps the
  original four-element tuple byte-for-byte: the addition is negotiated, never
  imposed (the evolution rules, extending/implants.md). The nonce floor lives
  behind the task repository: the in-memory adapter's counter is per-process
  (a restarted teamserver restarts the count, which the signing posture
  already tolerates -- the threat is an untrusted transport hop, not a
  compromised teamserver, and the task queue is equally per-process in the
  in-memory adapters), while the durable adapter reserves each nonce with an
  atomic upsert-and-return on a persisted floor row, so a restarted
  teamserver's next dispatch for a negotiating implant continues past the
  pre-restart count. The reference implant advertises the arm, and the
  conformance harness's hostile probe replays a genuinely signed control frame
  to pin the refusal.
- **Sealing** _(future, deferred)_. End-to-end protection of task payloads so
  untrusted redirectors cannot read or alter them. Deferred because the
  concrete adversary is absent today: the reference redirector is an opaque
  L4 splice, and the contact bodies are already sealed at the application
  layer under the per-artifact key, so an untrusted hop sees only
  ciphertext -- and mainstream platforms ship nothing
  equivalent. Building it would put mandatory cryptography on every implant's
  task path (against the implant contract's evolution rules). If it is ever
  built -- for TLS-terminating edges such as domain fronting -- it must be
  handshake-negotiated with a plaintext fallback, so Tier 0 implants keep
  interoperating (see [extending/implants.md](extending/implants.md)).
- **Per-implant identity and rotation.** Each implant owns a keypair it
  generated itself; enrollment presents the public half as a Tier 0
  obligation the route validates (a malformed key is refused, and no
  transport certificate is minted for it -- that was the retired mTLS
  posture), and the server never sees the private half (Sec 7, Sec 9).
  Identity key material stays out
  of artifacts; the one symmetric key a build bakes is the per-artifact
  contact/envelope key above -- it seals wire bodies, not identity, and it
  is per-artifact and revocable with the payload it is recorded beside.
  Rotation is the operational flow *retire the compromised implant, repoint its
  endpoint, and build a fresh artifact*; there is no live in-place key swap.
- **Retirement.** An implant can be retired from the operator API
  (`POST /engagements/{engagementId}/implants/{implantId}:retire`); a retired
  implant is refused at handshake (`HANDSHAKE_STATUS_IMPLANT_RETIRED`, no session
  opens), is untaskable (`422`), and its active session is closed. Retirement is
  idempotent and recorded as an `ImplantRetired` audit event in the engagement
  trail; any queued tasks for it are left inert (no dispatch, no cancellation).
- **Certificate revocation.** Both credential halves revocate at the
  application layer and take effect on the next authentication attempt with no
  restart -- no CRL/OCSP plumbing, which would be heavier than the threat
  (no peer consults one, so a real CRL would be unenforced ceremony). The implant half is retirement itself: the refusal at the next
  handshake is the revocation, pinned by
  `HandshakeServiceTests.Handshake_RefusesRetiredImplant`. The operator half
  is `POST /operators/{operatorId}/credentials:revoke`: it deletes the stored
  password verifier (the account's own operator or a deployment admin may
  call it, per the role line of Sec 4.5; the action is idempotent), and
  login -- which reads the verifier fresh on every attempt --
  fails from then on. It ends the credential's live cookie sessions too: a
  cookie is self-contained, so every authenticated request revalidates the
  session stamp its login baked into the principal -- a digest of the stored
  verifier -- against the verifier the store holds now. A revoked credential
  (no verifier) or a re-provisioned one (a new password is a new generation)
  fails the comparison at the very request that presented the cookie; the
  stamp is a digest, so the cookie carries nothing usable. Re-provisioning
  the operator with a new password (`PUT /operators/{operatorId}/credentials`)
  restores login without resurrecting the revoked generation's sessions;
  `POST /operators` provisions new accounts the same two-step way -- the
  aggregate and the hash of its initial password -- so a created handle is
  loginable the moment the response returns, the management path the
  bootstrap seed stood in for (`GET /operators` lists the roster with
  whether a credential stands behind each account and the deployment role
  of each, open to every operator; the mutations draw the role line of
  Sec 4.5). A disabled account refuses its API tokens
  too (Sec 4.5) -- the token row stays valid, so an enable restores it with
  the rest of the account. Revocation is not recorded in the audit
  trail: the trail is engagement-scoped and an operator credential is global
  state, so it has no engagement to live in.
- **Kill-date enforcement.** Both sides refuse past the baked date, the
  discipline Sec 5.1 defines: the teamserver at handshake, the implant at
  startup and each beacon cycle.
- **Audit trail.** Every engagement-scoped privileged action -- tasking,
  listener and front lifecycle, automation rules, webhook subscriptions,
  snippets, membership, ROE changes -- produces an immutable, hash-chained
  `AuditEvent`, and tampering breaks the chain (Sec. 11). The chain is bare
  SHA-256 by default; configuring `Audit:ChainKey` switches new links to
  HMAC-SHA256, so a rewrite of the storage needs the key too, not just the
  write access. The boundary is honest: the key's custody is wherever it is
  kept, links written before the key stay unkeyed (a verifier holding the
  key tells a pre-key trail from a rewrite by verifying once without it),
  and full protection against rewriting pre-key history needs an
  out-of-band anchor this layer does not fake. Global state binds to no
  engagement, so it lands in the deployment bucket: operator accounts and
  their credentials (creation, disable/enable, password set, credential
  and API-token mint and revocation) and the redirector fleet's credential
  lifecycle record under the empty engagement id -- the same "none"
  convention the event's own implant and task ids already carry -- on
  their own chain in the same stores, read through the admin-only
  deployment trail route. Runtime settings stay in the server log: they
  are deployment plumbing, not identity-bearing actions.
- **Engagement isolation.** Enforced at the teamserver and by engagement binding
  in certificates; redirectors never enforce tenancy.
- **ROE guardrails.** Each engagement carries a rules-of-engagement profile
  the server enforces at task issuance, after the class gate and before the
  task is queued: `PermittedVerbs` (exact verbs or `namespace.*` wildcards)
  and `PermittedImplants` (exact implant ids), each dimension empty meaning
  unrestricted. A task outside the profile is refused with `422` and a
  `TaskRoeRefused` audit event naming the violated rule -- the refusal is
  part of the engagement's story, so it lands in the same trail as the
  tasking it blocked; the scope change itself is recorded as `RoeUpdated`.
  A third dimension, `PermittedTargets` (exact hostnames case-folded, exact
  IP literals, or CIDR blocks; empty meaning unrestricted, like the others),
  gates the recon workbench's scan (Sec 11.4) -- the target-facing dimension
  tasking never needed, because an implant task is already inside scope by
  construction, while a scan names a target from outside. A hostname
  matches by name, never by resolution: a DNS answer is not an
  authorization fact. Operators apply a profile over the API
  (`PUT /engagements/{id}/roe`); applying an empty profile reopens the
  engagement. The scope is pure
  server-side state on the engagement (JSON column in the durable store, the
  unrestricted default for records that predate it) -- the implant contract
  carries nothing for it (extending/implants.md, evolution rule 4). Warn-only
  modes and audit-history-driven rule suggestions stay future concerns; the
  shipped gate blocks, because a warning an operator can click through is
  not a rule of engagement.
- **No self-protection.** Rod ships no protection against its own detection by
  defenders. Stealth is a deployment and capability concern (Sec. 7), not a
  security boundary of the platform.

## 10. Capability model and tasking

A **capability** is a verb an implant advertises and the teamserver may dispatch,
namespaced `namespace.action`, each carrying a `version` and `attributes`. The
teamserver gates dispatch on the advertised verb.

A task's **arguments stay a single opaque `string` at every contract boundary**
-- the proto field, core state, the transport DTO, the dispatch contract, and
the implant's dispatch entrypoint. The verb is the typed discriminator; the string is
the verb's own grammar, parsed by the handler that owns it (whitespace tokens,
hyphen ranges, comma lists, trailing-command shapes -- deliberately diverse, no
shared parser). A `string` is the lowest-common-denominator shape every implant
language parses with its own stdlib, it keeps the server out of argument
validation (the server gates on the verb and passes the string through
untouched), and it keeps each language's parser free. The escape hatch is
per-verb, not global: when one verb's grammar outgrows a string (streaming
input, binary blobs, nested config) it gets its own typed proto arm, leaving the
opaque field and every other verb untouched. A shared typed-argument schema was
rejected because the grammar is per-verb, not per-system -- it would move the
grammar into the proto without removing it and couple every implant language to
one schema.

`file.push` is the first shipped arm. A push too large for the arguments string
(the inline shape caps at 1 MiB) is issued as staged content: the sha256 of the
bytes is appended to the arguments -- so the payload's integrity lands inside
the signed tasking tuple (Sec 9) exactly as the inline shape's does -- the bytes
themselves are staged as a task-bound artifact (Sec 11), and the TaskRequest
carries the staged size as a typed field. The implant demands the payload with
a `StagedPull` and the stream answers with a chunked run, the mirror of exfil
chunking in the other direction. Nothing bulk flows downstream unasked: an
implant that never implemented the arm ignores the unknown field and fails the
verb on its own grammar, so the addition costs a Tier 0 implant nothing
(extending/implants.md). The demand is resumable (Sec 15.3, ADR-010): an
interrupted run re-demands naming the bytes it holds with their SHA-256 as the
prefix proof, the answer serves only the unserved remainder (a proof it cannot
honor restarts the run whole, the first chunk's absolute offset the reset
signal), and the completing result carries the payload's hash, which the
server verifies against the artifact it served -- a staged task records
Succeeded only when both sides held the same bytes.

### 10.1 Capability categories

| Category | Example verbs | Summary |
|----------|---------------|---------|
| **core** | `shell.exec`, `shell.interact`, `file.push`, `file.pull`, `fs.list`, `proc.kill`, `beacon.sleep` | The mandatory-to-useful baseline: command execution (one-shot and interactive), file transfer in both directions, directory listing, process termination, and retiming the beacon's own cadence. `file.pull` returns small files inline and streams large ones into the artifact store; `file.push` lands an operator-supplied payload on disk -- inline base64 up to 1 MiB per task, larger uploads staged and streamed down in chunks on the implant's demand (Sec 10's typed arm); `fs.list` lists a directory for the file browser; `proc.kill` ends one process by pid, carrying a `kills-process` OPSEC flag for the picker to badge; `beacon.sleep` retunes the live contact cadence (sleep and jitter) from the next cycle. |
| **recon** | `recon.portscan`, `recon.hostenum`, `recon.service`, `recon.ps` | Target and network reconnaissance. `recon.ps` lists the local host's live processes -- pid, ppid, user, image. |
| **lateral** | `lateral.move`, `lateral.token`, `lateral.exec_remote` | Lateral movement within authorized scope. |
| **persist** | `persist.install`, `persist.remove`, `persist.list` | Persistence mechanisms. |
| **collect** | `collect.cred`, `collect.keylog`, `collect.screenshot`, `collect.minidump` | Credential, screen, input, and memory collection. Operator file transfer is a core verb (`file.push`/`file.pull`), not collection. `collect.screenshot` captures the display as a PNG artifact joined to its task (Sec 11). |
| **exfil** | `exfil.push`, `exfil.stage` | Exfiltration over the C2 channel. |
| **tunnel** | `tunnel.forward`, `tunnel.socks` | Network tunneling through an implant (Sec 14, core operations): `tunnel.forward` bridges a live channel to a TCP connection the implant opens from its own vantage, so operator traffic reaches hosts beyond it; `tunnel.socks` is the multiplexed arm -- the channel's byte stream is a connection-multiplexed grammar, so every proxied connection rides the one task and each destination arrives per connection. Both run as live channels (Sec 10.3); the pivot class carries exactly this set (Sec 5.2). A relay bind exposes either channel as a teamserver-side listener -- the raw one-connection bridge for `tunnel.forward`, a SOCKS5 listener for `tunnel.socks` -- so unmodified operator tooling rides the tunnel without per-byte API posts (Sec 10.3). |
| **module** | `module.load`, `module.unload`, `module.list` | The implant-side plugin seam's own verbs (Sec 5.4): `module.load` delivers an SDK module's bytes as the task's staged content and the implant's loader registers its verbs -- memfd and exec on Linux, the manual PE map on Windows -- `module.unload` retracts one best-effort, and `module.list` reports what is loaded. Implant-class gated (module support is the long-haul class's), and `module.load` carries `executes-code` so automation never fires it unattended (Sec 10.4). |
| **evasion** | `evasion.avoid`, `evasion.unload` *(contract only)*; `inject.shellcode` | Detection-evasion hooks. `evasion.avoid`/`evasion.unload` are contract and dispatch only; `inject.shellcode` is the category's in-tree exception -- Implant-class gated with a Windows reference handler (the classic VirtualAllocEx/WriteProcessMemory/CreateRemoteThread pattern), carrying `modifies-defenses` and `executes-code`. |
| **exploit** | `exploit.invoke`, `exploit.module` *(contract only)* | PoC/exploit integration point. Contract and dispatch only. |
| **browser** | `browser.fingerprint`, `browser.cookies`, `browser.dom`, `browser.screenshot`, `browser.redirect`, `browser.prompt` | The Browser class's hook set (Sec 5.2): the read-and-steer verbs a hooked page justifies. `browser.fingerprint` reports the navigator facts; `browser.cookies` reads the current origin's `document.cookie` (non-HttpOnly only -- the browser's own boundary, documented rather than worked around); `browser.dom` returns `outerHTML`, optionally narrowed by a CSS selector argument, truncated at 1 MiB; `browser.screenshot` rasterizes the DOM (the SVG foreignObject shape, cross-origin imagery stripped) into a PNG artifact through the exfil-chunk path (Sec 11); `browser.redirect` navigates the tab (the hook dies with the page it left); `browser.prompt` returns what the user answered, carrying `reads-input` so automation never fires it unattended (Sec 10.4). Input capture (keylogging, form-field harvesting) and browser-exploit chaining are not core verbs -- they arrive as capability modules (Sec 13, Sec 15). |

The recon verbs are registered through the tradecraft layer as first-class
descriptors (`Rod.Capabilities.Recon.ReconCapabilities`, category `Recon`); their
concrete behavior runs on an artifact that carries a handler for them and is
captured as task output over the beacon stream (Sec 10.3). Recon is a
long-haul activity, so the four verbs are gated to the Implant class at task
issuance -- a non-Implant class is refused before the task is queued (Sec 5.2).

The process verbs close the same operational gap from both ends
(`Rod.Capabilities.Core.CoreCapabilities` carries `proc.kill` -- an in-repo
reference handler that ends one pid through the standard kill path -- while
`recon.ps`, the local process listing over the documented OS process APIs,
rides the recon set's long-tail posture). Both are Implant-class gated like
their recon kin.

The lateral verbs are registered the same way
(`Rod.Capabilities.Lateral.LateralCapabilities`, category `Lateral`):
`lateral.move` carries a `derives-child` attribute and is the deployment verb
that means "derive a child implant"; `lateral.token` and `lateral.exec_remote`
carry `touches-credential` and `touches-network` attributes respectively. Like
recon they are gated to the Implant class at task issuance (Sec 5.2). The core provides
the parentage data model and the child-enrollment path -- the server records a
child's `ParentImplantId` and validates it against the redeemed token's
engagement, so a child derives only from a live parent in the same engagement.
The implant-side half is the long tail (Sec 13): an artifact whose tree
carries a `lateral.move` handler parses the child's deploy token from the
task arguments, generates a fresh child keypair, and enrolls a child naming
itself as parent -- the enroll clients thread parentage onto the request, and
the binary `EnrollResponse` carries `parent_implant_id` so the wire surface
mirrors the HTTP path. `lateral.token` (the calling process's access-token
context) and `lateral.exec_remote` (remote execution over scheduled tasks on
Windows, SSH on Linux) document the administration channels every mainstream
C2 exposes; the reference crate compiles none of them.

The persistence verbs are registered the same way
(`Rod.Capabilities.Persist.PersistCapabilities`, category `Persist`):
`persist.install` and `persist.remove` carry `writes-to-disk` attributes
(install additionally carries `persists`), and `persist.list` is a read that
carries no such flag, like the host-local `recon.hostenum`. Like recon and
lateral they are gated to the Implant class at task issuance (Sec 5.2). Persistence is a
long-haul activity over the standard, documented surfaces -- the Windows
`Run` registry key, scheduled tasks, and services, plus Linux cron and
systemd user units, the surfaces every system administrator and
offensive-security curriculum covers; novel or stealth persistence
arrives as operator-supplied modules (Sec 13). The handlers are long-tail
like the recon set: the reference crate compiles none, so the verbs task
against an artifact whose tree carries them.

The collection and exfiltration verbs are registered the same way
(`Rod.Capabilities.Collect.CollectCapabilities`, category `Collect`, and
`Rod.Capabilities.Exfil.ExfilCapabilities`, category `Exfil`): `collect.cred`
carries a `reads-credential` attribute, `collect.keylog` carries
`reads-input` and `persists` (it installs a resident input-capture hook), and
`collect.screenshot` carries `reads-screen` (it captures what the target's
display shows);
`exfil.push` carries a `touches-network` attribute (it transfers over the C2
channel), and `exfil.stage` is a read that carries no such flag, like
`persist.list` and the host-local `recon.hostenum` (it stages already-collected
data on the teamserver). Like recon, lateral, and persist they are gated to
the Implant class at task issuance (Sec 5.2). Collection and exfiltration are long-haul
activities. The reference crate's compiled set covers the core file verbs --
`file.pull` reads the target's filesystem (small files inline, large ones
chunked into the exfil channel) and `file.push` lands an operator-supplied
payload on disk (inline within the server's staging cap, larger uploads
staged and streamed down on the implant's demand) -- and the chunking
machinery they run is what every collection verb shares: bulk lands in the
engagement artifact store joined to its task, no new server-side path
(Sec 11). The long-tail collectors -- `collect.cred` (credential-store
listings, no secret material dumped), `collect.screenshot` (the display read
over the standard desktop-capture APIs, PNG-encoded and chunked to an
artifact), and `exfil.push` / `exfil.stage` -- run on an artifact whose tree
carries them. Two sensitive collection surfaces do ship in-repo, Windows-gated
(`cfg(windows)`, so a Linux artifact compiles neither): LSASS memory dumping
(`collect.minidump`, the dbghelp minidump path) and `collect.keylog` input
capture; on every platform the Rust build does not gate them in, each runs
only when an operator supplies a module for the verb.

The tunnel verbs are registered the same way
(`Rod.Capabilities.Tunnel.TunnelCapabilities`, category `Tunnel`):
`tunnel.forward` and `tunnel.socks` each carry a `touches-network` attribute,
since each opens network connections from the target. Unlike the categories
above they are gated to two classes: Implant (tunneling is a core operation,
Sec 14) and Pivot (Sec 5.2 -- the tunneling class). Their tasks run as live
channels (Sec 10.3) -- the channel carries the tunnel's bytes both ways -- so
the poll transports never claim them, and the reference implant ships both
channel handlers: `tunnel.forward` connects to the `<host> <port>` named in
the arguments from the implant's own vantage and bridges the channel to the
socket until the peer closes, with the relay summary as the task's final
output; `tunnel.socks` takes no arguments at all -- its channel's byte stream
is the proxy's own connection-multiplexed grammar (one `open` packet per
connection naming that connection's destination, `data` packets under each
connection id, `close` to end one, `opened` to answer a dial), the
verb-local escape hatch Sec 10 licenses, so every proxied connection rides
the one task and the implant dials each destination from its own vantage
until the operator's eof ends the proxy, with the destinations dialed and
the bytes moved as the task's final output. The traffic's attribution is end
to end: every byte crossed the channel the signed TaskRequest opened, the
input posts land as `ChannelInput` audit events, and the transcript plus
summary is the operator's record. Input posts are the manual shape: a
**relay bind** (`POST /engagements/{id}/tasks/{taskId}/relay`, tunnel-only,
loopback by default and an ephemeral port unless the operator names one)
starts a teamserver-side listener bridged onto the dispatched channel -- the
raw relay for `tunnel.forward` (one connection: the channel is one TCP
connection on the implant's side) or a SOCKS5 listener for `tunnel.socks`
(no auth, CONNECT only -- the surface a browser or proxychains speaks),
where each accepted SOCKS connection joins the channel under its id and
each CONNECT's destination travels as an open packet. Either listener's
reads enter the same channel-input enqueue the route uses, and the
channel's output chunks are handed back raw, before the transcript's UTF-8
decode, so the tool's bytes are the channel's bytes. The bind dies with the
task: the final result, the stream ending, or the operator unbinding each
close it and write the `RelayClosed` event with the relayed tallies, next
to the `RelayBound` event the bind wrote. The relayed traffic itself keeps
the channel's no-per-chunk discipline -- it rides the task's transcript,
so an unmodified tool reaches third hosts with zero operator API calls per
byte and the whole flow stays attributed to the task.

The evasion verbs are registered the same way
(`Rod.Capabilities.Evasion.EvasionCapabilities`, category `Evasion`):
`evasion.avoid` and `evasion.unload` each carry a `modifies-defenses`
attribute, since each alters the target's defensive or monitoring posture
(Sec 7). Unlike the recon, lateral, persist, collect, and exfil verbs they are
**not** gated to a class in `ImplantClassCapabilities` (Sec 5.2): the pair is
contract and dispatch only -- which class an evasion module runs on is decided
when an operator deploys the module, not by a baked-in class rule.
Their concrete behavior is operator-supplied tradecraft (Sec 10.2, Sec 13):
the core ships no bypass techniques or weaponized code, so each runs only
when an operator supplies a module for it. `inject.shellcode` is the
category's exception on both counts: it is gated to the Implant class like
every reference verb (the class table carries it), carries
`modifies-defenses` plus `executes-code`, and ships an in-repo Windows
reference handler on the Rust implant -- remote-process injection through the
documented classic pattern, `<pid> <base64>` arguments.

The exploit verbs are registered the same way
(`Rod.Capabilities.Exploit.ExploitCapabilities`, category `Exploit`): both
`exploit.invoke` and `exploit.module` carry an `exploits-target` attribute,
since each actively attacks a target to gain or widen access (Sec 7). Like the
evasion verbs they are **not** gated to a class in `ImplantClassCapabilities`
(Sec 5.2): exploit is contract and dispatch only -- which class an exploit
module runs on is decided when an operator deploys the module, not by
a baked-in class rule. Their concrete behavior is operator-supplied tradecraft
(Sec 10.2, Sec 13): the core ships no
weaponized exploit code or proof-of-concepts, so each verb runs only when an
operator supplies a module for it.

### 10.2 Capability modules (the operator-supplied seam)

`evasion` and `exploit` are first-class in the capability model -- they have
defined interfaces, registration, dispatch, and data shapes. Their **concrete
behavior is not the core's**: the core provides the contract and the plumbing;
the tradecraft is supplied as separate, opt-in `CapabilityModule`s --
in-tree reference modules or registry modules (Sec 15), every sensitive one
disabled by default until a build profile enables it (Sec 7). See Sec. 13.

Every built-in verb is registered in the default registry, contract-only ones
included: a contract-only verb is a real `PlaceholderCapabilityModule` that
satisfies the registry and the task gate until an operator supplies a module.
That makes the module path a *registration*, not a schema change -- a
module registered for `evasion.avoid` or `exploit.invoke` replaces the
placeholder (last-registration-wins) and is taskable through the same UI and
gate as any built-in verb. [extending/modules.md](extending/modules.md)
is the worked guide for module authors: both halves of a capability, the
registration paths, and the seams' current limits. The one runtime loader is config-listed and narrowly
bounded: the `Capabilities:Modules` section names each module as a
`Namespace.Type, AssemblyName` string, the assembly is resolved by that name
alone (already loaded, or a same-named dll in the application directory), and
the type is instantiated at startup and registered against the DI-resolved
registry (last-registration-wins). There is no directory scanning and no
arbitrary plugin path -- a module reaches the process exactly when an operator
built it, placed it next to the binary, and listed it, so adding one never
edits the composition root; a misconfigured entry fails startup loudly. The
capability contract is registration-only: `ICapabilityModule` carries its
`Descriptor` and nothing else -- there is no server-side
dispatcher surface to retire. The server only gates and forwards on the
live task path -- it never invokes a capability module server-side -- so
execution and dispatch stay on the implant (Sec 5.3), where the target's
filesystem, network, and credentials actually live.

### 10.3 Tasking lifecycle

`Task` -> dispatched to a `Session` -> `TaskExecution` (streams, result, status)
-> recorded in the engagement audit trail. Sensitive verbs additionally require
engagement authorization and are always audited.

A session is the implant's live channel, not one TCP connection: the handshake
**reuses** an implant's active session on a reconnect (a poll-mode contact or a
flapped stream refreshes capabilities and last-seen) and opens a new entity only
after the prior one closed, so a poll cadence neither churns session entities
nor floods the trail with `SessionOpened` records -- the audit write happens
only for a genuinely new session. Each beacon frame advances the session's
last-seen stamp, and a stream ending does not close it; liveness is last-seen
based. A stream that dies silently -- the implant vanishes mid-stream, or the
connection drops without a clean close -- leaves its session Active until the
hosted staleness sweeper closes every Active session whose last-seen stamp is
older than the configured `Sessions:Staleness:Threshold` (checked every
`Sessions:Staleness:SweepInterval`); retirement closes a session immediately.
The session's whole life is live on the operator event stream: opening a
genuinely new session fans out a `SessionOpened` event (the same flood guard
-- a poll contact reuses the active session and publishes nothing), so
connected operators watch an implant come online the moment it contacts
rather than on the next roster poll, and closing the session is what drops
it off the online roster; each swept
close also fans out a `SessionClosed` live event so connected operators see it
immediately, and the beacon stream's reader ends the connection on its next
frame so a recovered implant reconnects and re-handshakes instead of refreshing
a session it no longer holds.

Task issuance gates the verb through a capability resolver
(`ITaskCapabilityResolver`). The per-class reduced verb set (Sec 5.2) is the
primary authority; the composition root swaps in a registry-backed resolver
(`CapabilityRegistryTaskResolver` in `Rod.Capabilities`) so a verb no class set
gates is still dispatchable when a capability module is registered for it. The
registry only widens the gate -- it never narrows it, and it never re-gates a
verb a class set carries to another class -- and it is the
path that opens dispatch for the contract-and-dispatch-only categories (Sec
10.2): the evasion and exploit verbs are not class-gated, so they are admitted
when the registry holds a module for them (the built-in placeholder, or an
operator-supplied module). A verb outside both the class set and
the registry is refused before the task is queued. Verb execution itself stays
on the implant: the teamserver resolves the gate, hands the verb to the beacon
stream, and captures the result.

Dispatch onto the stream is push-based. Every accepted enqueue -- an issuance,
or a dispatch returned to the queue by a failed write -- releases a per-implant
wake that the stream's dispatch writer parks on, so a queued task is pushed
downstream the moment it is queued and an idle stream costs nothing: no poll
loop in the writer path. The wake is a hint, not a ledger: the writer claims
before it parks, so tasks queued while no stream was open are picked up on
connect without relying on the wake, and a stale permit costs one empty claim,
never a lost task.

**The synchronous exception.** A WebShell-class implant (Sec 5.2) never opens
a session, so no dispatch writer exists to claim its tasks: the operator's
execution request itself plays the beacon -- issue, claim, one protocol-adapter
round trip, record result, each with the audit beats the stream path makes.
The task therefore never parks queued (a failed round trip completes it
failed), and the claim the route makes is the only claimer there is; the
lifecycle, the audit arc, and the timeline read exactly like a beacon's
capture. This is the third claim exception beside the channel rules -- a
channel task is not claimed over DNS (a datagram poll carries no input
half) -- and it needs no gate of its
own: with no session there is no stream to claim from, by construction.

**The dispatch strand.** A written frame used to count as delivered, and below
the result no delivery evidence existed: a claimed task whose frame rode a
stream that died stayed Dispatched forever, because the failed-write requeue
covers only the write. The receive-ack arm closes that strand. An implant
whose handshake advertised `task_acks` gets the arm echoed, acks every parsed
`TaskRequest` with a `TaskAck` frame before executing it, and the live stream
transports (the WebSocket beacon, the held socket connection) hold each dispatched
task in a per-stream ledger until its ack crosses -- a stream that ends
holding an ack-less dispatch returns it to the queue, so the task rides the
next contact instead of stranding. Delivery is then at-least-once, and the
implant makes that safe: it recognizes a task it already held (a bounded
per-run ledger of parsed ids), re-acks it without running it twice, and
re-sends its cached result when the original delivery died with a stream.
Duplicate results are idempotent on the server -- the completion transition
is atomic in the task store, so the first result wins and a retransmit
changes nothing -- which is also what makes an eager implant safe: either the
original or the resend may land, never both. The negotiation is deliberately
per handshake, never sticky on the implant the way the replay-nonce flag is
(Sec 9): a handshake that stops advertising must drop the arm, or the server
would requeue dispatches an unupgraded implant already ran. Unupgraded
implants never advertise and keep today's semantics exactly -- a written
frame counts as delivered, a lost result leaves the task Dispatched -- and
the poll carriers (DNS, the plain-HTTP envelope, the pipe/TCP contacts)
keep their own posture: their response is answered whole or not at all, they
hold no ack ledger, and an ack they receive is accepted and inert.

A queued task can be retracted before the implant wakes:
`POST /engagements/{engagementId}/tasks/{taskId}:cancel` takes the operator's
own tasking back (the shell command issued in error, the target that went
quiet), terminal and claim-proof -- the retransition is atomic against the
dispatch claim, so a cancel racing a claim resolves one way, never both, and a
cancelled task is never handed to a stream. A task already dispatched is the
implant's to run: the cancel is a `409`, not a rewrite of history. The
retraction lands in the engagement trail as a `TaskCancelled` event attributed
to the cancelling operator, ending the task's audit arc with no dispatch
behind it, and a `TaskCancelled` live event drops it from every connected
operator's queue view the moment it is retracted.

**The fronting claim.** A beacon stream's writer claims for its own implant
first and, in widening order, for the Pivot children that implant fronts
(Sec 5.2): the claim spans the fronting set -- parent plus fronted children --
and hands out the oldest queued task across the set by issue order, with the
same claim-once guarantee a single-implant claim carries. Issuing to a pivot
child releases the fronting parent's wake too (the child has no writer of its
own to wake), and a fronted task returned by a failed write requeues the same
way. The claim is the stream transports' alone: DNS and the plain-HTTP
envelope keep the narrow claim, because a fronted channel's input half needs
the stream the fronting executor holds. A claimed fronted task is marshaled
with `target_implant_id` naming the child -- the signature still signs the
child's own id in the tuple (Sec 9), so verification on the parent binds
exactly what the server authorized -- and nonce-less, because the child never
handshakes and so never negotiated the replay-nonce arm. Upstream, a fronted
task's frames (channel output, staged pulls, results) are accepted on the
parent's stream when the task belongs to a fronted child, and the operator
input route reaches a fronted channel through the parent's sink; every record
-- issued, dispatched, each input post, completed -- attributes to the child.
The evolution rules hold: an implant that never implements fronting ignores
the unknown field, and a server never fronts tasking to one that does not
(enough: the field is absent on all its frames, the Tier 0 shape unchanged).

**The streaming task shape.** Not every verb is a one-shot round trip:
`shell.interact` -- `shell.exec`'s interactive shape -- and `tunnel.forward`
-- the port-forward bridge (Sec 5.2, Sec 14) -- run as live channels. A
TaskRequest dispatches like any other (same signature, same queue), but on
the implant it opens a channel instead of completing inline: output streams
back as ChannelOutput chunks that land on the task's transcript while it is
still Dispatched (an operator reads the shell live, over the same task read),
and the operator's typing flows down as ChannelInput frames -- routed from
the operator input route through a per-implant live-channel hub into the
stream's dispatch writer, so the stream's single-writer discipline holds. The
typing half is exclusively owned (Sec 4.5): input posts and relay binds
require holding the channel's interaction claim -- the first post takes the
claim on an unclaimed surface, and a surface another operator holds refuses
the input outright, so two operators cannot type into one shell. A
final ordinary TaskResult closes the task with the whole session as its
record; the operator's eof closes the shell's stdin, which is the natural end
of the session -- and for the tunnel it half-closes the TCP send side, the
channel ends when the tunneled peer closes. The channel is session-scoped by
construction: it lives on the beacon stream that carried its TaskRequest, so
a dropped stream kills the shell or the tunnel (the implant's write gate and
channel lifetime see to that) and the task stays dispatched -- and DNS never
claims a channel task at all, because a datagram poll has no stream to carry
the input half. The poll carriers have a third answer, the degraded
discipline, carried by every poll artifact: the artifact advertises the
store-and-forward capability in its handshake, and the interactive verbs
claim over its envelope contacts -- operator input parks server-side
(DegradedChannelHub, bounded per task) and rides the next cycle's response,
the handler's output batches upstream, and a channel the implant stops
collecting closes itself with a timeout result. The tradeoff is the
operator's to make, not the bake's: while a channel is open, the
interactive traffic runs at the contact cadence, every keystroke costing
up to one interval each way. The reference implant's shell channel runs the platform shell
under a pseudo-terminal on Unix -- the documented `script` wrapper -- so the
channel behaves like a real terminal: prompt, line editing, and the
interrupt byte becoming SIGINT for the foreground program. Where no PTY
wrapper exists (a stripped container, Windows pending ConPTY) it falls back
to the plain pipes shape -- byte-transparent, no prompt or line editing --
and a richer PTY handler is a drop-in over the same byte-transparent channel
contract. Its tunnel channel bridges the same contract to a TCP connection
of the implant's own -- the byte transparency is what lets one channel shape
carry stdio and sockets alike. The same transparency carries the tunnel's
machine half: a relay bind (Sec 10.1) bridges a teamserver-side TCP listener
onto the channel, so the byte-transparent contract serves an unmodified tool
exactly as it serves an operator's keystrokes -- the input route and the
relay are two producers of the same channel-input queue, and the transcript
plus the relay's own audit pair are the attributed record either way.

### 10.4 Server-side automation: triggers and scheduled tasking

An engagement keeps a watch when no operator does: the overnight screenshot
every 30 minutes, the triage batch on first contact, the chain that reads a
completed result and tasks the follow-up. Automation is an engine **beside
the operator layer, not a new one**: it lives in `Rod.Operators` beside the
live bus it subscribes to, issues everything through the same
`TaskService.IssueAsync` path an operator's console click rides, and holds
no behavior of its own beyond the rules and their guards.

**Rules.** An automation rule is engagement-scoped declarative state --
trigger, condition, action -- persisted with the engagement
(`AutomationRule` in `Rod.CoreState` behind the `IAutomationRuleStore`
port, the same in-memory/Postgres adapter pair every engagement-scoped row
uses). A **time trigger** is a fixed interval ("every 30 minutes"). An
**event trigger** names a live event kind (Sec 4.1, layer 4) from a
deliberately short list -- session opened or closed, task issued, completed,
or cancelled, implant retired -- with an optional condition narrowing it:
fire only for one implant's events, or (for completion triggers) only when
a named verb completed. Operator presence and channel-output events are
not triggerable -- the first is operator-console chatter, the second is a
per-chunk firehose. The action is one task issuance: a target implant, a
verb, arguments. Guards ride the rule itself: a minimum cooldown between
firings and a firing cap after which the rule disables itself and says so
in the trail.

**The firing path.** Every firing -- scheduled or event-driven -- goes
through `TaskService.IssueAsync` unchanged, so the class gate, the channel
carrier gate, ROE, and the closed-engagement gate hold exactly as they do
for an operator's issuance; the engine cannot bypass a gate, and a rule
whose firing the gates refuse is heard, not looped -- each refusal lands in
the audit trail, and a rule refused three consecutive times disables
itself rather than spinning overnight against a closed door. Firing
attributes to a **synthetic automation operator**: a well-known id seeded
idempotently at startup (handle `automation`, no credential -- it cannot
log in), so a firing's `TaskIssued` fact and everything downstream of it
read in the engagement trail as automation's work, distinguishable from
every human operator's. The engine writes the task's audit arc through the
same `onIssued` hook the transport endpoints use, so a fired task's trail
is shaped exactly like an operator-issued one, and each firing adds an
`AutomationRuleFired` fact naming the rule, the trigger, and the task that
resulted -- or the refusal reason.

**Guards.** The action's verb is bounded where automation has no business:
the channel verbs (an unattended firing cannot own an interactive input
half), and every verb the sensitivity policy names. That judgment is not
automation's to maintain: `ISensitiveVerbPolicy` is a core-state port whose
authoritative implementation is registry-backed -- a verb whose descriptor
sits in the evasion/exploit categories or carries the OPSEC attributes that
mean "never unattended" (`reads-input`, `reads-memory`, `executes-code`,
`modifies-defenses`) is sensitive, so every registered verb, the
framework's or a module's, acquires its automation posture at
registration and no parallel list exists to drift. A static floor (the
Windows-sensitive three, Sec 12.2, and the unregistered
evasion/exploit namespaces) stays loaded underneath and the registry may
only widen it, never narrow it. Blocked verbs are refused at rule
creation, not discovered at fire time. Chain depth is capped at one: a completed task the engine
itself issued never matches an event trigger, so automation chains
terminate by construction -- the chain an engagement actually wants, an
operator's task completing and automation following up, is depth zero and
fires normally. Firings serialize inside the engine, and cooldown and cap
are evaluated under that serialization, so a burst of matching events
yields one firing, not a storm.

**Durability posture.** Time triggers are durable: the next-fire stamp is
persisted with the rule and survives a teamserver restart, which picks the
schedule back up where it left off; fires missed while the server was down
are skipped, not made up -- a restarted server does not storm a quiet
implant with a backlog. Event triggers inherit the bus's best-effort
posture (Sec 4.1): process-local, drop-oldest under a slow consumer, no
replay; an event that fires while the server is down never happened, and
the audit trail stays the record. The causality map behind the chain guard
is process-local with them -- restart resets it, which can only make a
chain one link longer, never a loop.

**The operator surface.** Rules are managed from the operator API at
`/engagements/{engagementId}/automation-rules` (create, list, read,
`:enable`, `:disable`, delete); disabling is the cancel. The routes live in
the operator layer with the events endpoint -- transport may not reference
the engine's layer, and rules are the engine's domain the way the SSE
stream is the sessions'. Creation validates eagerly what it can -- the
engagement open, the target implant present and in the engagement, the
verb unblocked and inside the class set -- so an operator's mistake is a
422 at creation instead of a refusal audit three hours later; the issuance
gates at fire time remain the authority either way. Every rule mutation
lands in the trail (`AutomationRuleCreated`/`Updated`/`Deleted`) attributed
to the mutating operator; the engine's own auto-disables (cap reached,
repeated refusals) land as `AutomationRuleUpdated` facts attributed to the
automation operator with the cause in the payload, so a rule that went
quiet explains itself.

**Shape of the engine.** One hosted background service with a fixed-delay
tick (default 5 s, `Automation:EngineTickSeconds`): each tick scans the due
interval rules and reconciles the per-engagement event subscriptions (one
subscription per engagement holding enabled event rules, drained
sequentially), and rules reload from the store every tick so an operator's
mutation is seen on the next one -- at most one tick of latency, the same
eventual-read posture the staleness sweeper holds. A sandboxed script
front-end (JS/Lua) would be a possible follow-on evaluator over the same
firing path; declarative rules are the first and only evaluator here --
they are auditable, testable, and cover the needs engagements have shown.

**Evolution notes.** Where later work plugs in, so nobody rediscovers it
from the code. The sensitivity axis lives behind `ISensitiveVerbPolicy`
so every surface that needs the judgment reads one answer -- automation
refuses on it; the sensitive-verb approval queue the port was once shaped
to hand off to is declined (owner decision). A third trigger shape (a cron
expression, a compound condition) fans out to five places, all additive:
the `AutomationTrigger` hierarchy, the entity's schedule arithmetic
(`Create`/`RecordFire`/`RecordRefusal`/`Enable`), the engine's tick filter
and subscription reconcile, the stored row's columns and translation, and
the endpoint's trigger parsing. Nothing there is compiler-forced -- the
hierarchy is sealed but the readers filter with `is`-patterns, so a new
shape is silently ignored until each reader names it; the persistence
translation is the tripwire, since an unhandled shape lands in the wrong
column. Editing a rule's shape (the PUT the surface omits today) is
service-and-endpoint work only -- the entity is rebuilt whole on save.

## 11. Evidence and reporting -- a first-class output

A red-team operation ends in a deliverable: timeline, findings, and evidence. Rod
treats the audit trail as the **source for report generation**, not a post-hoc
scrape.

- **Every action is an immutable, attributed event**: `operator_id`,
  `engagement_id`, `implant_id`, `task_id`, `command`, `timestamp`, input
  parameters, and output/result. Linked artifacts are recorded as separate
  `ArtifactAttached` (operator attach) or `ExfilCaptured` (implant-side exfil)
  events whose outcome carries the artifact id -- artifacts live in the artifact
  store, joined by `task_id`, not as a field on every event. Operator notes on
  implants -- the free-text "whose beacon is this" memory -- are events too
  (`ImplantNoteAdded`, written through the implant's notes routes and read back
  as a query over the trail), so the note's only storage is the chain: it rides
  the same durability and chain-of-custody as every engagement fact, with no
  separate note store to keep consistent. This is the engagement timeline by
  construction.
- **The event log is append-only and per-engagement**; it is never deletable
  mid-operation (chain-of-custody).
- **Artifacts** (files, screenshots, command output) are first-class objects
  linked to the tasking that gathered them, not loose files -- task-joined
  when a task produced them, task-less when the evidence predates any
  foothold (the recon workbench's pre-foothold findings, Sec 11.4, carried
  under the acting operator's attribution).
- **Timeline and report export** are built-in consumers of the event + task +
  artifact store -- the audit trail renders directly into the deliverable.
- **The operator-facing listings are paged.** The task, audit, and artifact
  list endpoints accept a `limit` and an opaque cursor (the newest window
  first; each page's cursor walks one page older), and the operator UI walks
  pages, so a long engagement never grows a listing response without bound.
  Exports still read the full store -- the deliverable is the whole trail by
  design; only the interactive read views are paged.
- **The audit trail outlives the operation.** It is retained after infrastructure
  teardown; ROE guardrails read from the same store. When the composition root
  finds an `Audit:DataDirectory`, it swaps the in-memory
  `IAuditStore`/`IArtifactStore`/`IPayloadStore` for file-backed ones --
  JSON Lines for the trail and the artifact metadata, a
  blob per artifact -- so the per-engagement trail and its evidence survive a
  teamserver restart and infrastructure teardown. Each append writes and flushes
  one hash-chained record, and the store recovers each engagement's chain head on
  startup, so a restarted teamserver continues each engagement's trail off its
  last stored event and the reloaded chain still verifies. This stands in for Postgres
  behind the same ports; a managed store slots in the same way.
- **The close-out exports the evidence as one package.** A finished engagement
  leaves behind a deliverable that must survive teardown and re-verify with no
  Rod infrastructure running: `POST /engagements/{id}:evidence-package` writes a
  ZIP carrying the full hash-chained trail (`audit.jsonl`, the store encoding),
  the artifacts (`artifacts.jsonl`), and the report (`report.json`/`report.md`),
  pinned by a `manifest.json` that records every other file's size and SHA-256
  plus the event/artifact counts. The close-out path is ordered:
  **freeze** (`:freeze`) stops new tasking, enrollments, and token mints so the
  trail is final -- in-flight results still land, and re-export before retire
  carries them; a mistaken freeze is reversible before retirement
  (`:unfreeze` reopens the engagement); **export** builds and verifies the
  package server-side before it
  leaves; **retire** (`:retire`) completes the close-out, terminal, and is
  refused on an open engagement so the export cannot be skipped. Each step is an
  audited operator event (`EngagementFrozen`, `EvidenceExported`, whose outcome
  is the exported chain-head hash, `EngagementRetired`). Offline, the
  teamserver binary itself re-verifies a package --
  `Rod.TeamServer --verify-evidence <package.zip>` -- recomputing every digest,
  re-running the chain check, and validating the artifact records, with no
  listeners and no stores: the acceptance bar is that a closed engagement's
  package re-verifies byte-exact on a host with nothing Rod running on it.

### 11.1 Shift handoff digest

The trail holds everything that happened; an operator returning to the
console after an absence still reads it raw to reconstruct the watch. The
live bus is no help -- it has no replay, so events that fired while nobody
was connected never happened, console-side -- and the paged audit listing
and the full timeline are both noise-first at watch scale. The digest
closes the resume gap: a time-windowed, kind-filtered, ordered account of
the watch's operational beats, assembled by the reporting layer the
timeline, the report, and the closeout export already share. It is a read
of the trail, not a new store and not a replay bus.

**The window.** The digest is bounded by `from` and `to`, ISO 8601
timestamps on the request; `to` defaults to now and `from` to twelve hours
before it -- one long watch plus the handoff gap. An event belongs to the
window when its timestamp falls between the bounds, inclusive. `from` must
precede `to`, and the span is capped at thirty-one days so a single
ordered account stays bounded -- longer horizons are the timeline's job,
which pages.

**Content.** A fixed whitelist of kinds, the beats a returning operator
asks about: sessions opened and closed, implants enrolled and retired,
tasking issued with its outcomes (completed, cancelled), ROE refusals --
the sensitive boundary's trace on the trail today -- operator notes on
implants, and interactive shell sessions opened and ended. Everything else
the trail holds (dispatch plumbing, payload fetches, configuration churn)
stays out; the timeline remains the view for it. One trail gap closes to
make "closed" true: the staleness sweep lands a system-attributed
`SessionClosed` event per swept session -- a session that died silently
mid-watch is exactly what the returning operator needs to see, and until
now only the live bus knew. A session closed by supersession (a re-enroll
opening its successor) writes no close event; the successor's
`SessionOpened` is its trace.

**Assembly.** The reporting builder reads the engagement's full trail
once, verifies the hash chain, and enriches each event (operator handle,
implant class, task verb and outcome) -- the digest is a projection over
that same resolved context: window filter, whitelist, then the enriched
entries oldest-first under a summary count header. The reproducibility
discipline is the timeline's: a content hash over the canonical join of
the window bounds and the selected entries' own hashes, so two digests of
the same window are equal, and chain state surfaces the same way -- a
digest built over a broken chain says so rather than silently rendering.

**The operator surface.**
`GET /engagements/{engagementId}/handoff-digest?from=&to=`, JSON by
default for the console, `?format=markdown` for the human deliverable --
the handoff note an operator pastes to the next watch. Malformed bounds,
an inverted window, or an oversized span is a 400; an unknown or foreign
engagement is a 404 -- the ladder every engagement-scoped read holds.
Read-only like its siblings: nothing is composed onto the trail, and the
digest request itself is not audited -- a read of the evidence is not an
act on the engagement.

**Evolution notes.** An LLM narration over the digest is
the natural widening on the triage client Sec 11.3 ships -- the digest
stays a plain ordered account without it. No replay is implied in either
direction: the digest reads what the trail holds, and the trail is the
record.

### 11.2 Target intel and situational awareness

The trail holds everything that happened; the picture holds what the
engagement learned. Recon findings, loot, and host observations live
inside task output strings today, so an operator re-reads transcripts
instead of consulting a picture. The intel layer closes that gap the way
the digest closed the resume gap: read-side projections over the stores
that already exist, plus a small family of new attributed facts. It
organizes the trail; it does not become a second store of truth -- no new
entity, no parallel index, nothing to keep consistent -- and every write
it adds is an audit event like the ones beside it.

**Labels and notes on implants and hosts.** An implant already carries
operator notes (`ImplantNoteAdded`, read back as a query over the trail);
the layer widens that shape in two directions. Labels are short set/clear
markers (`ImplantLabeled`, payload the label text, outcome `set` or
`cleared`) reduced at read time last-wins per label, so an append-only
chain can change a label without rewriting history. Hosts are the device
dimension the enrollment's own hostname stamp groups (Sec 5.1): a host is
that grouping read-side -- no Host entity, no host store -- and host
facts key on the normalized hostname (trimmed, case-folded), the join
every view applies. `HostNoteAdded` and `HostLabeled` carry a small JSON
payload naming the host: the audit record's field set is frozen (the
chain's canonical form, above), so a new subject rides the free string
fields the way notes and artifact bindings already do rather than growing
the record. Labels are bounded per subject (length and count) at the
write route, the same eager validation the note cap applies.

**Typed loot views.** The artifact store already holds what the collection
verbs bring back -- screenshots as PNG artifacts, pulled files, dumps --
and the trail already binds each to its task and verb (`ExfilCaptured`,
`ArtifactAttached`). The loot view is the organizer that was missing: an
engagement-wide paged listing (the same limit-plus-cursor discipline every
listing holds) whose entries classify by the producing verb and content
type into screenshot, credential, and file, each entry carrying its
capture attribution. Classification is a read-time judgment over metadata;
nothing is stamped on the artifact. Inline task results (small
`file.pull`s) stay in transcripts -- loot organizes the artifact store,
not the task history.

**Topology.** The engagement's network picture is assembled, not stored:
hosts group from implant enrollments, pivot links from the parentage the
child-enrollment path records (Sec 5.2), and observed hosts and ports from
completed recon task outputs parsed at read time. The recon verbs'
handlers are module-domain (Sec 13), so the parse targets a documented
output contract the handler authors write for -- JSON lines, one finding
per line ([extending/modules.md](extending/modules.md)) -- and a
line that does not parse is not a finding: unparseable output stays in
the transcript instead of erroring the view. The external recon
workbench (Sec 11.4) lands its findings as engagement artifacts under
the same grammar, and the projection parses them the same way --
findings-as-artifacts is the seam.

**Evidence access is part of the story.** Reads of projections stay
unaudited (the digest's own posture: a read of the evidence is not an act
on the engagement). Retrieving evidence bytes is different -- an artifact
leaves the platform, the chain-of-custody question "who pulled what" --
so the artifact retrieve route records an `ArtifactViewed` event
attributed to the downloading operator, the same posture the payload
fetch route holds for delivered bytes.

**Evolution notes.** The intel kinds joining the digest's whitelist (a
label change is a watch beat), live events on label changes for connected
consoles, and an LLM narration over the picture (beside the digest's own
evolution note) are the natural widenings -- each is one view or one
whitelist entry, and no storage decision waits behind them.

### 11.3 LLM triage and reporting client

Attention is the scarce resource on watch; captured output accumulates
faster than it is read. The triage client compresses it: an opt-in,
OpenAI-compatible chat-completions client behind
`Microsoft.Extensions.AI`'s `IChatClient` (the call shape is the seam;
the compatibility format is the contract, not a vendor -- cloud or local
runtime), serving one read today, the summarize route
(`POST /engagements/{engagementId}/tasks/{taskId}:summarize`, read
scope): a completed task's captured output goes to the configured
endpoint and the summary comes back to the task read. Only a completed
task summarizes -- the final output is what a summary reads.

Disabled by default, and the disable is the posture: every request sends
engagement content off-platform, so the egress decision (which endpoint,
cloud or local, whose key) is the operator's, documented in the
operations runbook ([operations/llm.md](operations/llm.md)), never a
silent default. The key binds through configuration
(`Llm__ApiKey`), never a committed file. When the integration is off,
the route answers 503 naming the configuration section -- a refusal, not
an error.

Every request, succeeded or failed, lands in the engagement's trail as
an `LlmSummaryGenerated` event: attributed to the requesting operator,
bound to the summarized task, payload naming what was sent (verb,
captured size), output carrying the summary on success, outcome
`succeeded:{model}` or `failed:{reason}`. The endpoint and the key never
enter the trail -- configuration names the endpoint, the runbook records
the decision. Input is bounded (`MaxInputChars`, longer transcripts
truncate with a marker) and the response budget is configured
(`MaxOutputTokens` -- reasoning models spend tokens before answering).

**Evolution notes.** Narration over the digest (Sec 11.1) and the intel
picture (Sec 11.2), and report-section drafting from the attributed
trail, are the same shape widening -- read-side prompts over existing
projections, every request audited. The LLM *acting* on the platform is
deliberately not this surface: agency arrives through the MCP server's
write-tool gate (Sec 4.3, `Rod.Operators`), a separate design with its
own explicit authorization boundary.

### 11.4 External recon workbench

Scoping a target starts before the first foothold: registration data
(RDAP) and the subdomain surface (certificate transparency) are how the
operator aims the first implant, and until now that work left Rod for
ad-hoc tools whose findings never reached the engagement's attributed
record. The workbench closes the gap from the operator side, not the
implant side: the lookups run **on the teamserver** against external
services, engagement-scoped and audited, and their findings land as
engagement artifacts. Nothing about it is implant tasking -- there is no
implant yet -- so it lives in the operator layer (`Rod.Operators`,
Sec 4.3) behind four routes on the ordinary engagement-scoped ladder:
`POST /engagements/{id}/recon:rdap`, `POST /engagements/{id}/recon:subdomains`,
`POST /engagements/{id}/recon:resolve`,
`POST /engagements/{id}/recon:portscan`, all writer-gated (they act on
the engagement -- egress under its attribution, evidence written to its
trail -- the artifact-attach posture, not the read projection's) and
refused while the engagement is closed (a frozen trail is final; the
workbench appends to it like any other act).

**Findings are artifacts with no task.** The design bill the workbench
pays: artifacts were task-joined, and pre-foothold findings have no task.
The artifact's task reference is now nullable -- evidence gathered by
tasking carries the task as ever (implant exfil, operator attach, staged
push content), while workbench findings carry the acting operator instead
(the artifact's existing operator attribution) and nothing else. Every
other consumer reads by engagement or by artifact id, so a task-less
artifact changes no read path.

**Passive lookups.** `recon:rdap` queries the configured RDAP base for a
named domain and normalizes the registration record (registrar, status,
dates, nameservers, secureDNS) into a JSON artifact -- and when the
registry answers that it has no record for the domain (the ccTLD half of
the world that never built RDAP), falls back to the configured whois
server (port 43, the protocol RDAP replaced), capturing its answer
verbatim; one event covers the run, its lookup name carrying the
fallback. `recon:subdomains` queries the configured
certificate-transparency mirror for names under a domain and normalizes
the deduplicated name set into a JSON-lines artifact -- one
`{"host": name}` per line, the documented recon grammar
(extending/modules.md), so the topology projection (Sec 11.2) parses
the findings like any recon output. `recon:resolve` is the census's
follow-up -- which of the enumerated names live: names (one or a bounded
list) resolve through the configured DNS-over-HTTPS resolver, and an IP
literal asks for its PTR name; the answers land as address-bearing host
lines in the same grammar, so the picture carries the addresses. A
single negative answer (NXDOMAIN, no PTR) is a failed run with the
negative named; a bulk run counts its misses in the summary and records
only the names that answered. The egress is the operator's call,
never a silent default: each base URL is configuration
(`Recon:RdapBaseUrl`, `Recon:CtBaseUrl`), unset means the route answers
503 naming the section -- the LLM client's opt-in discipline (Sec 11.3),
because a lookup egresses the target's name under the teamserver's own
address. Which service each URL names -- a public redirector, a
registry-direct endpoint, or a fronted mirror -- is the runbook's
decision record ([operations/recon.md](operations/recon.md)). Passive
lookups carry **no ROE gate**: the target scope is often what the lookup
is building (enumerate the domain to decide what is in scope), so gating
the lookup on the scope it informs would deadlock the scoping flow.
Every attempt, succeeded or failed, writes a `ReconLookupCompleted`
audit event -- payload names the lookup and target, never the egress
endpoint (configuration names the endpoint, the runbook the decision),
outcome the findings artifact id or `failed:{reason}`.

**The scan, and the ROE target scope.** `recon:portscan` is the
workbench's active half: a TCP connect scan of a named host from the
teamserver itself, open ports reported as JSON-lines findings under the
same grammar (implant-side `recon.portscan` covers the inside-out view;
this is the pre-foothold map). Two guardrails are load-bearing:

- **ROE target scope.** The profile (Sec 9) grows a third allow-list
  dimension, `PermittedTargets`: exact hostnames (case-folded), exact IP
  literals, or CIDR blocks; empty means unrestricted, like the verb and
  implant dimensions. A hostname target matches by name, never by
  resolution -- a DNS answer is not an authorization fact, and the scope
  must not depend on what the target's own nameservers say. A scan
  outside the profile is refused with `422` and a `ReconScanRefused`
  event naming the violated rule -- the task gate's refusal posture
  (`TaskRoeRefused`) on the workbench's own kind, because no task exists
  to refuse. A scan that runs writes a `ReconScanCompleted` event with
  the findings artifact id as its outcome.
- **Scan origin is a decision, not a default.** Where a scan originates
  is OPSEC: the teamserver's own egress is one choice, a redirector or
  an implant already inside are others. The shipped origin is
  teamserver-direct, and it is **config-gated the same way the lookups
  are**: `Recon:ScanOrigin` must name `Teamserver` or the route answers
  503 naming the section and the runbook -- the scan never runs because
  an operator typed a route. The runbook records the tradeoff and the
  alternatives ([operations/recon.md](operations/recon.md)).

The scan is bounded the way every egress is: a per-connect timeout, a
concurrency cap, and a ports-per-request cap from the same `Recon`
section; the ports grammar is the operator-facing comma list with hyphen
ranges (`22,80,443` or `1-1024`), with a documented default top-ports
set when the request names none. The findings artifact joins the
topology projection beside the passive lookups, so the pre-foothold
picture and the post-foothold one are one view.

**Evolution notes.** Redirector- or implant-originated scans arrive as
new `ScanOrigin` choices with their own runbook decisions, not as
changes to this surface -- an implant-originated scan already exists as
ordinary `recon.portscan` tasking from inside, and a redirector-originated
one has a real design bill: the reference redirector is an opaque L4
splice with no control channel, so originating dials from it means a
control contract between teamserver and redirector that this surface
does not imply. Reverse-whois (registrant-driven discovery) would be a
fifth passive half, but no public reverse-whois service rides a stable
open contract -- it reopens when one does.

### 11.5 Delivery campaigns

The lifecycle's delivery step (Sec 2 item 4) inside Rod: an
engagement-scoped **campaign** sends per-recipient lure messages through
an SMTP relay and tracks each recipient into tasking, so the causal chain
from lure to implant lives in one tool and one trail -- before this
surface, the first foothold arrived by delivery that happened entirely
outside Rod, and the attribution story broke at the seam between the
mail platform and the first callback.

**The entity is the profile plus the list plus the template.** A campaign
row carries the sending profile (relay host, port, TLS mode, optional
credentials, and the from address), the recipient list (email and an
optional display name, capped -- spear-phish scale, not bulk; each entry
typed, or selected by reference from the engagement's recon-asset target
list, the address and display name resolving onto the row at creation --
Sec 15.4's target link), the message template (subject and body, plain or
HTML), the build profile, and the listener whose `publicEndpoint` fronts
the lure. The template
arrives either inline or as a `module/asset` reference into the listed
asset modules (Sec 15.1); a reference resolves to subject and body at
creation, and the row stores the resolved text -- the merge grammar below
stays the kernel's rendering contract either way. The template
merges per recipient and is validated at creation, not at delivery: an
unknown field or a body without the link field is refused when the
campaign is created, the same fail-at-the-seam discipline webhook
subscriptions keep (the merge-field inventory lives in the runbook).
The relay password is stored in the clear on the row the way a
launcher's download credential is (Sec 8): the server must present it
again, the row is engagement-scoped operator state deletable with the
campaign, it never enters the audit trail, and it is never returned on
read-back.

**One build per recipient is the price of enrollment attribution.** At
launch, the engine drives the build pipeline once per recipient and
bakes a per-recipient enrollment credential into each artifact -- the
credential the build mints through the ordinary path (Sec 6), minted
single-use and bound by id on the recipient's row. A shared build would
attribute the click (the lure is per recipient) but never the
enrollment: the baked token is the only thing an implant carries that
the server can attribute, so per-recipient tokens require per-recipient
builds. The artifact each lure serves is therefore unique to its
recipient, and the enrollment that follows stamps campaign and recipient
onto the implant row and into its `ImplantEnrolled` fact -- the
attribution the whole surface exists to keep.

**The lure is a capability URL on the public edge.**
`GET /implants/lures/{lureId}` serves the recipient's built artifact and
records the click; `GET /implants/lures/{lureId}/open` is the tracking
pixel (a 1×1 gif, `no-store`). Both ride the implant family with the
hook serving edge's posture (Sec 8): the unguessable route id is the
credential, the ingress listener's engagement scopes the socket, a
revoked campaign's lures answer 404, and every serve writes a
`CampaignLinkServed` fact carrying the fetcher's wire facts -- open or
click rides the payload, the same first-touch shape a hook fetch records.
The pixel is a merge field and `opened` stays best-effort by design:
mail clients that block remote images simply never fire it (the
placement rules live in the runbook).

**Tracking is evidence, and the enrollment is the only proof of
execution.** Each recipient carries the sent/opened/clicked timestamps
plus the executed binding: `executed` is stamped when an implant redeems
the recipient's baked credential, recording the enrolled implant's id on
the recipient row. A click proves a fetch, never a run; the enrollment
is the artifact's own testimony.

**The sending engine is a reconciler, not a queue.** One hosted
background service (the webhook engine's shape) ticks on a fixed delay,
walks launched campaigns, submits each pending recipient's build, and on
the build's completion renders and sends the message through the relay.
Delivery is single-attempt with no retry: a failure lands on the
recipient row with its reason and in the trail as `CampaignMessageSent`
(`failed:{reason}`), and a retry is a new campaign -- the trail stays
the record, exactly as webhook delivery keeps it. Builds ride the
process-local job registry; a job lost to a restart is re-requested with
a fresh credential, not reconstructed. Campaign states move
`Draft → Launched → Completed` (all recipients terminal), and `:revoke`
freezes both halves: no further sends, and every lure in the campaign
404s from that moment.

**Egress is a decision the runbook owns.** Which relay, whose IP the
mail leaves from, and the TLS posture are operator decisions with
OPSEC consequences -- a sending relay is infrastructure that can be
correlated. The runbook records the tradeoffs and the alternatives
([operations/campaigns.md](operations/campaigns.md)); the engine makes
none of them silently.

**Evolution notes.** Attachments (the message carrying the artifact
itself, not a link), a reusable sending-profile entity shared across
campaigns, a landing page behind the lure, and a test-send to a
lab address are the natural widenings -- each touches the template, the
engine's send step, and nothing else. A landing page that captures
credentials would follow the standard store's collection posture
(Sec 13), and evasion-grade social engineering stays module-domain
regardless (Sec 15): the campaign carries delivery and attribution,
never the lure's content tradecraft.

## 12. Technology stack and language boundaries

| Concern | Choice | Why |
|---------|--------|-----|
| Teamserver (monolithic kernel) | .NET 10 (LTS), ASP.NET Core | Strong async networking, strong typing, mature web UI. LTS to ~2028. |
| Data store | PostgreSQL (opt-in; in-memory default) | Authoritative teamserver state; per-engagement audit. PostgreSQL is the authoritative store when configured (`ConnectionStrings:Postgres`); absent it, in-memory adapters remain the default for tests and dev deployments (see Sec 12.1). |
| Build units | Rust and Go (in-tree references; Go is the first community-slot reference, Sec 12.2); C/C++/Nim via out-of-tree community units | Two in-tree toolchains sharing one build contract; polyglot by contract, no teamserver-language coupling. |
| Redirectors | .NET Native AOT (shipped), single static binary | Tiny VPS footprint, no runtime install. The opaque L4 forwarder ships in two postures -- the hand-deployed manual rule and the enrolled mode that dials home and serves pushed rules -- and the enrolled-fleet control plane (Sec 8) drives it from the teamserver; deploy/rotate runbook in [operations/redirectors.md](operations/redirectors.md). |
| Implants | Rust (the reference implant shipped; the Android carrier leg shipped with it -- `carrier/`, Sec 12.2); Go (the community-slot reference, `src/implant/go/`); C/C++/Nim via out-of-tree community units -- per target | One Rust reference implant, static and cross-platform, plus its in-process library leg for Android carriers; the Go reference proves the community slot against the same wire; community implants slot in by contract for targets neither fits. |
| Operator UI | Web (React + TypeScript, Vite), served same-origin by the teamserver | React sources in `src/teamserver/Rod.TeamServer/Client/`; the production build emits into the host's `wwwroot/`, served as static files with an SPA fallback so the client owns deep links, and Vite's dev server proxies the operator API in development. Chosen over Blazor for the larger React ecosystem and audience reach, trading away Blazor's .NET-native service reuse and adding a Node/Vite step to CI. The UI talks to the operator HTTP API over `fetch` (no direct .NET injection), keeping the API the single integration point. |

The wire protocol and capability registry are the long-lived, language-neutral
contract implants build against; the build contract is the language-neutrality
boundary for generation.

### 12.1 Data access (PostgreSQL via EF Core)

PostgreSQL is reached through **Entity Framework Core 10** over the Npgsql
provider, with all persistence code isolated in a dedicated `Rod.Persistence`
project that depends inward on `Rod.CoreState` and `Rod.Audit` only. The inner
ring (`Rod.CoreState`, `Rod.Audit`) is zero-package, so the EF/Npgsql dependency
cannot live there; `Rod.Persistence` is the structural answer, the same reason
`Rod.Operators` and `Rod.Capabilities` are separate projects wired at the
composition root. The domain model stays persistence-ignorant -- no EF
attributes, no concurrency fields on entities -- and ids map to Postgres `uuid`
through per-id value converters; enums are stored as `int` to keep the audit
chain's canonical `(int)Kind` hash stable. Concurrency (single-use deploy-token
redeem, task FIFO) lives at the adapter, not on the domain. The durable
adapters are selected at the composition root when `ConnectionStrings:Postgres`
is present, replacing the in-memory defaults through the same opt-in swap the
other ports use; absent it, the in-memory adapters stay and every existing test
is unchanged. The audit chain math stays in `Rod.Audit` and is untouched -- a
durable store recovers each engagement's chain head from the highest-sequence
row on startup and stamps new appends through the same `ComputeHash`. The
acceptance test provisions a live Postgres via Testcontainers, gated to skip
(not fail) when Docker is unavailable.

Rejected alternatives: **raw Npgsql** (loses migrations and the
value-converter/construction story across six aggregates, and contradicts the
EF-migration command the toolchain already commits to); **Dapper over Npgsql**
(same drawbacks for a smaller saving); and a **managed-Postgres-as-a-service
abstraction** (premature -- it defers the access question this answers without
resolving how the host reaches the database today).

### 12.2 Toolchain: .NET control plane, Rust implant

Rod ships two toolchains with one job each. The **control plane is .NET 10**
-- the teamserver, the transport, the persistence, the operator layer; the
C2's logic lives where a managed runtime costs nothing (it runs on the
operator's own infrastructure). The **implant is Rust**
(`src/implant/rust/`, built by `RustBuildUnit`): a ~2.25 MB static musl
binary for every target a managed runtime cannot serve -- routers,
appliances, 32-bit ARM IoT Linux -- with both web carriages (the envelope
POST cycle on poll bakes, the WebSocket stream on stream bakes), the
streaming channel layer (`shell.interact` under a pseudo-terminal,
`tunnel.forward`, and `tunnel.socks`'s connection-multiplexed proxy --
live on the stream carriage, the degraded park-and-drain discipline over
the poll cycle), the one-shot core verbs, the module family of the plugin
seam (Sec 5.4, compiled on every platform; Linux loads modules by
exec'ing them out of a memfd, so the static musl artifact loads them like
any other -- macOS keeps the family dormant the way the android leg does,
its kernel carrying no anonymous-fd exec at all), and the Windows
sensitive set
(inject.shellcode, collect.minidump, collect.keylog) that self-gate on
`cfg(windows)` so a Linux build compiles none of them. The mobile leg is
the same machine in a library: the crate's core is a lib target, and the
`carrier/` cdylib beside it (the loader tier's sibling) is the library
`android.app.NativeActivity` loads -- zero Java, the hand-declared
native_activity.h seam, the crate's manifest the whole app face, the
build unit crossing it for the `-linux-android` triples through the
NDK's clang and packaging the installable (`so`/`apk`, Sec 6) with the
SDK's aapt2/apksigner against a bionic floor of API 24. The module
family stays compiled-but-dormant on that leg: bionic below API 30
carries no memfd_create to link and the app SELinux domain denies
anonymous-fd exec, so the seam refuses rather than linking an artifact
that cannot open. The wire protocol is the language-neutral product
(rod.proto, the baked profile's base64url JSON, the sealed envelope); the
Rust implant is proven against it by the conformance harness (its
reference candidate) and the end-to-end legs (dev-shape and
pipeline-built, both contact modes; the android carrier rides the
emulator's amd64 leg through the same round trip, the aarch64 cross for
devices building on the Linux host unchanged --
[operations/android.md](operations/android.md)). The legs run as a
nightly six-cell matrix over the desktop grid -- linux, windows, and
macOS at amd64/arm64, one runner per cell building through the pipeline
and running the artifacts on its own OS and arch: the Apple pair and
ARM Windows's MSVC shape resolve natively on their own build hosts,
while Windows amd64 keeps its GNU cross for the Linux deployment shape. The `Language` enum
(Go/DotNet/Rust/C/Nim) and build contract stay, so a community implant in
any language registers a build unit and compiles against the same
contract. The Go slot carries its in-tree reference (the first community
slot, `src/implant/go/`, built by `GoBuildUnit`): a Tier 0 wire client --
enroll, the envelope POST cycle, tasking -- plus the ADR-010 exfil upload
arm with byte-offset resume, over the web family only, one static binary
per GOOS/GOARCH with the dependency set vendored (darwin included -- it
crosses from any host like every other GOOS under cgo-off, so it needs no
build host of its own). It couples to the platform through nothing but
rod.proto and the baked profile, and its
acceptance is the end-to-end arc -- enroll, task, and exfil against a
live teamserver, in both the dev shape and the pipeline-baked artifact
with sealed contacts -- on every cell the matrix stands.

The .NET implant and the .NET stager that preceded this shape are deleted:
their history is the commit record, and their delivery answers -- the
launcher one-liners, the token-gated payload fetch -- carry forward
unchanged. The staged-delivery idea returns as the loader tier done
natively (Sec 6): `src/implant/rust/loader/`, a ~25 KB `no_std` crate in
the same tree and the same build unit -- no second in-tree language, no C,
the dialer's whole footprint being ELF headers around a few hundred bytes
of code -- and the surface keeps speaking payload and deploy token: the
loader names what it `delivers`, the route serves the loader's payload,
and the retired stage1/stage2 spellings stay refused.

Rejected alternatives: **one language end to end** (neither .NET alone
reaches 32-bit ARM/MIPS IoT or a ~2 MB static footprint, nor Rust alone
carries the control plane's velocity); **Go for either half** (a runtime on
the implant side and an alien toolchain on the control side);
**asymmetric polyglot -- the reach implant out-of-tree** (the reach story is
the product's own, not a community add-on).

## 13. Capability surface statement

Rod's capability surface is governed by **contracts, not by a technique
allowlist**. The core defines the interfaces, registration, dispatch, and data
models for every capability family; concrete implementations are
**capability modules** -- reference modules shipped in-tree (the standard,
documented surface the framework maintains) or community modules through
the extension seams and the module registry (server-side modules, the
crate fork, the plugin seam, the transform chain; Sec 15). Nothing in
this repository maintains a list of which
technique kinds may exist -- an operator building for an authorized engagement
composes the surface they need from the reference set plus their own modules,
and the discipline that governs that work is the authorized-use premise below,
not a taxonomy curated here. Openness governs what may enter the repository,
never what a build carries: sensitive modules ship disabled and are enabled
explicitly per build profile (Sec 7, Sec 15).

The reference implant draws its own line the same way: the compiled core is
the machinery no plugin could own -- the carriages, the session and channel
layer, command execution (one-shot and interactive), file transfer both ways
with the staged and chunked arms, filesystem listing, process termination,
cadence retuning, and the tunnel pair -- plus the Windows-gated sensitive
set, while the long tail (recon sweeps, lateral movement, persistence,
credential and screen collection) is plugin-domain work for the C-ABI seam,
composed per engagement rather than compiled into every artifact. Transport
families beyond them -- QUIC above all -- return as optional providers
(in-tree or registry, Sec 15.3) against the same frozen contracts when an
engagement names the need.

The browser hook draws its line the same way: its compiled-in set is the
read-and-steer six (Sec 10.1), while input capture in a hooked page
(keylogging, form-field harvesting) and browser-exploit chaining are
capability modules, never core verbs -- the boundary Sec 5.2
carries in the class set itself.

- All use assumes an authorized context; see [SECURITY.md](../SECURITY.md).

## 14. Capability bar (design aspiration)

Rod is designed to meet or exceed the state of the art across the capability
dimensions a modern offensive platform is expected to cover. This is a standing
design constraint, not marketing: every capability area below must be planned and
built so that its reach, flexibility, and OPSEC qualities are at least on par
with -- and aim to surpass -- what established platforms offer in that area.

- **Core operations** -- shell execution (interactive and one-shot), file
  transfer, tunneling, host enumeration, process enumeration and termination:
  as capable and as OPSEC-tunable as the
  best available, with per-implant profiles baked in at generation.
- **Reconnaissance** -- port and service discovery, host and network
  enumeration: comprehensive, fast, and audited.
- **Lateral movement** -- token and credential reuse, remote execution, child
  implant derivation and pivoting: full coverage with parentage tracking.
- **Persistence** -- a broad, cross-platform set of mechanisms, installable and
  removable, all recorded.
- **Collection and exfiltration** -- file, credential, screen, and input
  collection, staged and transferred over the C2 channel, every byte
  attributed.
- **Evasion** -- the platform must provide the contracts, hooks, and per-implant
  tuning (profiles, jitter, kill dates, malleable transports, per-command OPSEC
  metadata) that let operators keep a low profile; concrete tradecraft is
  opt-in module work, off by default (Sec 15), but the substrate must be
  best-in-class.
- **Exploitation integration** -- a clean, extensible integration point for
  external exploit and payload modules, so new tradecraft plugs in without core
  changes.
- **OPSEC and infrastructure** -- disposable, reprovisionable infrastructure,
  redirector decoupling, burn handling, and per-implant identity as first-class.
- **Evidence and reporting** -- an immutable, attributed, hash-chained audit
  trail that is the source for timeline and report generation, surviving
  infrastructure teardown.

When a capability area falls short of this bar, the right response is to raise
the design, not to lower the bar. Concrete evasion techniques and exploit code
remain opt-in modules, disabled by default (Sec. 13, Sec 15); the bar above
concerns the platform's capability substrate, not what any build carries on
by default. The bar has one hard boundary it
may never cross: it applies to the teamserver substrate and the contract's
quality, never to the implant-side minimum. Capability reach grows in the
server, the tradecraft modules, and the build pipeline -- an addition that
would put mandatory new work on every implant's task path fails this bar
outright, whatever it adds (see [extending/implants.md](extending/implants.md)).

## 15. Open capabilities and the module ecosystem

> **Status:** Decided direction; [todo.md](todo.md) holds the queue. This
> section records the program decisions (ADR-001 through ADR-015), absorbed
> from the retired plan that first carried them. Unshipped pieces read as
> _(future)_.

Rod drew its capability boundary by sensitivity: the repository shipped
contracts, placeholders, and a benign reference set, and concrete tradecraft
lived out-of-tree in module repositories operators supplied. **That
boundary is cancelled.** The measured gap against Mythic and Sliver is not the
kernel -- the layered monolith, the hash-chained audit, engagement tenancy,
and the single-process deployment are already the stronger design -- but
ecosystem openness and interface surface, and that is where the program
spends itself. The bar is **full functional replacement of Mythic and
Sliver at the lightest deployment shape in the field**; the deployment
shape itself never moves: the teamserver process and PostgreSQL, nothing
else standing -- no Prometheus, Redis, RabbitMQ, message bus, or container
orchestration; observability, full-text search, and realtime push are PG
and in-process concerns, always.

Opening the repository does not open the defaults. Openness changes what
may sit in the tree, not what a build carries: sensitive capabilities stay
disabled by default and are enabled explicitly at build through profiles
(Sec 7's posture), and trust moves from physical separation (separate
repositories) to module signatures and registry governance.

### 15.1 Kernel narrow, module layer wide (ADR-001)

Cancelling the boundary leaves a layering question in its place: with any
capability allowed in-tree, what still belongs to the kernel? The test:
**take the capability away -- if an engagement can still run from delivery
to report with the audit chain intact, it is not kernel.** Everything else
grows in the module layer, and breadth (the ATT&CK ambition, ADR-007) is a
property of that layer, never of the kernel.

- **Kernel**: engagement isolation, operators and permissions, the audit
  hash chain, the task queue, `Rod.Protocol`, transport providers, the
  build pipeline, the module seams themselves, API/SSE/MCP, the report
  engine, the recon workbench, the SMTP campaign, and the browser and
  web-shell class-and-protocol support. These are slow-changing or deeply
  coupled to audit and engagement state -- keeping them in the kernel is
  the cheaper maintenance answer.
- **Module layer** (behind the contracts, growing slowly): the
  post-exploitation verb long tail (the bulk of ATT&CK coverage), browser
  hook scripts and lure assets, phishing templates and lure generators,
  task output renderers, payload wrappers. Browser-hook assets chase
  browser versions and phishing assets chase the SMTP ecosystem -- exactly
  the churn the module layer exists to absorb.

`Rod.Capabilities` is the contract registry plus the in-tree module host
(ADR-001; the rename from `Rod.Tradecraft` shipped with the host). Reference
modules live under `modules/` (server-side) and
`src/implant/rust/modules/` (implant-side) and load through **exactly the
path external modules load through** -- an assembly beside the binary plus
an entry under `Capabilities:Modules` in the shipped configuration; nothing
in the tree compile-references them, and the architecture tests hold that
line. The seams stay the public, stable contract, and the tree eats its own
dogfood. A kernel PR must answer *why it cannot be a module*.

The content half rides the same rule (**shipped**): the two asset families
this section names -- browser-hook scripts and phishing templates -- load
as **asset modules**, pure file trees (a `rod-module.toml` whose
`[[assets]]` rows name the files) listed under `Capabilities:AssetModules`,
with no assembly at all. `Rod.Capabilities` hosts them: it resolves bytes
by module name plus asset name at startup, fails loudly on anything listed
but broken, and resolves name collisions last-listed-wins -- the loading
contract the assembly seam already keeps. The kernel consumers stay thin:
the hook mint renders its bake into the `browser-hook` module's template
and refuses (503 naming the section) while no module is listed; campaign
creation resolves a `module/asset` template reference to subject and body
at the seam and stores the resolved text on the row, while the merge
grammar (`{{link}}` and friends, Sec 11.5) remains the kernel's rendering
contract. The in-tree reference set ships under `modules/browserhook` and
`modules/lure-templates`; nothing under `src/teamserver` embeds a script
or template asset (the architecture tests hold that line too), and the
content's tests travel with the module while the kernel suites pin the
seam.

### 15.2 The module ecosystem: registry, manifest, CLI (ADR-002, ADR-003, ADR-009)

The ecosystem ports Mythic's play -- independent module repositories,
dynamic install, a browsable catalog -- onto the constraint Mythic's
implementation breaks: **zero standing components**. Mythic's carrier is
Docker containers and a RabbitMQ bus; Rod's is a **static git index
repository** (`rod-registry`) in the Homebrew-tap shape -- no server, no
database, an optional GitHub Pages mirror -- plus signed manifests and a
CLI. The contribution threshold is one git repository and one manifest;
the trust chain is signatures, not platform vouching. Both of Mythic's
decoupling axes survive in Rod's own shape: transport providers and
implant languages are independent seams.

**Three extension points, one manifest, one CLI.** Server-side capability
modules (the `ICapabilityModule` contract), implant-side modules (the
C-ABI symbol family on Windows, the musl stdio byte protocol on Linux,
Sec 5.4), and build units (new implant languages) share the manifest shape
and the `rod mod` commands. A developer runs `rod mod init` (a template
repository), implements, signs, and `rod mod publish` (a pull request
against the index); an operator runs `rod mod search` and
`rod mod install name@version`, with signature and compatibility verified
at install and a lock file recording what landed. OPSEC metadata ("lands
on disk" / "memory only") shows at search and install, carrying the
per-verb OPSEC labeling into the catalog. **Shipped** (the `rod` CLI,
`src/cli/dotnet/`, standing beside the tree with no in-house references --
its contracts are files): the manifest, the canonical form, the signing
chain, the six commands, and the reference module
`modules/hostenum/rod-module.toml` riding the identical path, with the
end-to-end acceptance (template repository through publish to install)
encoded in `tests/cli/dotnet/`. The index's **governance model** is
decided: the canonical rod-registry is an **organization tap** -- hosted
under the GitHub organization ADR-011 creates, entries landing by pull
request with review, merge rights held by the organization. Third-party
taps remain available by construction (`--registry` takes any git URL
or local checkout); an organization tap is where the default registry
lives, not a monopoly on hosting.

**The trust chain** (ADR-002, ADR-009): publishers sign, the registry
vouches for nothing. `rod mod init` generates an Ed25519 keypair beside
the module (`rod-module.key` / `rod-module.pub`; raw 32/64-byte keys,
language-neutral -- any minisign-shaped verifier reads them). The
signature covers the manifest's **canonical form** -- every manifest
field in a fixed line order, one line per declared verb (name, version,
floor), then one SHA-256 line per payload file
sorted by path -- so a tampered OPSEC mark, compatibility floor, verb row,
or payload byte each break verification. The registry entry carries the
public key and signature beside the package digest; install verifies the
digest, re-derives the canonical form from the extracted files (never
from index metadata), checks the signature, checks the compatibility
floor, and **pins the publisher key per module name in
`rod.modules.lock.json`** (trust on first use, the fingerprint printed
at search, info, install, and publish for out-of-band comparison). A
later version arriving under a different key fails the install loudly;
`rod mod verify` re-proves every installed tree against the lock offline
(exit code 2 makes a tampered finding script-visible). Key management
is deliberately per-publisher and local: a lost key is a new identity
every pin will name, not a recovery flow the platform owes.

**The manifest** (`rod-module.toml`): name, version, a compatibility
matrix (implant class / platform / arch, minimum teamserver version),
OPSEC metadata, ATT&CK mapping, the entry kind (server module, implant
module, build unit, or asset module), the verb rows of the version matrix
(each verb's module-scoped version and optional per-verb teamserver
floor), the asset rows (`[[assets]]`, each binding a logical name a
consumer resolves as `module/asset` to a package-relative file -- they
ride the signed canonical form like verb rows, and the file bytes ride it
through the per-file digests), license, packaging rules, and signature. The
registry is a git repository in the Homebrew-tap shape -- one JSON file
per module under `modules/`, contributed by pull request, no server, no
database, an optional GitHub Pages mirror; the lock file
(`rod.modules.lock.json`) records per module the version, digest,
signature, pinned key, and installed path, and is the only thing
`rod mod install` ever changes.

**The contract trilogy** (ADR-003) is what makes a from-zero ecosystem
coherent -- Mythic's cross-agent consistency, re-implemented as contract
completeness instead of implementation uniformity:

1. **Verb parameter schemas.** Every verb declares its parameter types
   (enum, string, file, boolean, array, ...); the operator UI renders the
   tasking form generically from the schema, knowing nothing about the
   module behind it. The wire shape is untouched -- task arguments stay
   the opaque string of Sec 10, parsed by the verb's own handler; the
   schema is descriptor metadata for rendering and validation, not a new
   contract boundary.
2. **Structured output taxonomy.** Task results declare what they
   produced (credential, file, process list, screenshot, enumeration
   structure, plain text); the credential store, file browser, and process
   views are generic panels over any module's output. A module that types
   its output poorly degrades to plain text -- the UI keeps working, the
   module just earns no panels.
3. **Version compatibility.** The manifest declares the minimum
   teamserver version it runs against (checked at install and upgrade,
   ADR-009), and verbs carry module-scoped versions so modules iterate
   independently.

**Shipped** (the trilogy, over the descriptor and the manifest): the
`CapabilityDescriptor` carries its `Parameters` schema (kind, order,
required, choices, the trailing-remainder and inline/staged file flags) and
its `Output` taxonomy kind; the catalog (`GET /capabilities`) exposes both
so the operator UI renders the tasking form and the typed output panels
generically, no verb table anywhere in the client; the read-side
projections (topology, loot classification, the credentials view) resolve
a verb's kind through the core-state `IVerbOutputResolver` port with the
registry-backed implementation the composition root swaps in -- a module's
structured output reaches its panels at registration. The manifest's
`[[verbs]]` rows carry the module-scoped versions and optional per-verb
teamserver floors, ride the signed canonical form, mirror into the
registry entries, and are checked at install. The acceptance is encoded at
three levels: `tests/cli/dotnet` (scaffold through verify, including a
tampered verb row breaking the signature), the server-side
`ContractTrilogyTests` (a `sweep.*` module the framework never anticipated,
from registration to schema-rendered catalog to structured products in the
topology, credentials, and loot panels, zero framework changes), and the
client's vitest suite (the generic form builder and the taxonomy parsers
over a novel schema).

There is **no carry-over from existing ecosystems**: no BOF/COFF execution
layer, no Armory migration. The ecosystem accumulates from zero, quality
before quantity -- slowly, but every new module pays interest into the
contracts. The trilogy's acceptance bar: a module the framework never
anticipated goes from `rod mod init` to full UI interaction
(schema-rendered form, structured products landing in the right stores)
with **zero framework changes**.

**Cold start.** The tree ships seed modules -- the absorbed out-of-tree
candidates plus the common enumeration, credential, and tunneling sets --
so the registry is not an empty shelf on day one.

**Naming and license discipline.** Ecosystem components carry the `rod-`
prefix and avoid existing product names: the index repository is
`rod-registry` (Armory and Arsenal name Sliver's ecosystem factually,
never borrowed). Sliver is GPLv3; its code is never copied or ported under
any circumstance. Mythic-ecosystem agent repositories are licensed
variously -- each is checked before any code reference. Benchmarking takes
product and interaction conclusions only (ADR-012).

### 15.3 Platform widenings (ADR-004 through ADR-008, ADR-010)

Where the program touches the existing layers:

| Layer | Evolution |
|-------|--------------|
| `Rod.CoreState` | Verbs gain the ATT&CK technique mapping (ADR-007; shipped -- the kernel data file behind the `IVerbTechniqueResolver` port, with the class platform surface beside the class verb sets); comment and chat aggregates (ADR-005; shipped, with the credential landing store and the task-reference resolver); the output-taxonomy resolver port ships (shipped with Sec 15.2's trilogy). |
| `Rod.Audit` | Chain semantics tighten: mutable content never enters the chain (ADR-005). |
| `Rod.Protocol` | Frame-negotiation fields for the optional transports (ADR-004); the resumable-transfer fields, both arms (ADR-010; shipped). |
| `Rod.Transport` | `ITransportProvider` abstraction (shipped -- the in-tree families are its reference implementations); optional WireGuard, default-disabled, shipped (ADR-004, amended: mTLS stays retired). The `/api/v1` versioned alias, the OpenAPI 3.1 contract generation, and the token-scope floor gate (ADR-006; shipped). |
| `Rod.BuildPipeline` | The build contract's transport-enable set, shipped as the named front itself -- a build against a wireguard listener mints the per-artifact pair and enables the carriage's compile; a Go build unit joined the community slots (shipped). |
| `Rod.Operators` | Collaboration metadata APIs (ADR-005; shipped); MCP read-write under token scopes (ADR-006; shipped, the operate floor and Sec 10.4's unattended red line held at the tool level); token-scope claim stamping (ADR-006; shipped with the transport-side floor and gate). |
| `Rod.Capabilities` | Contract registry + in-tree module host (ADR-001; shipped, with the first reference module under `modules/`), plus the asset-module host behind `Capabilities:AssetModules` (Sec 15.1; shipped, carrying the hook and lure-template reference modules). |
| `Rod.Persistence` | `tsvector` full-text indexes; comment and chat tables (ADR-005; shipped, generated columns under GIN on tasks, comments, chat, credentials, and artifacts). |
| `Rod.TeamServer` | Mounts the new components; the built-in diagnostics endpoint (ADR-008). |
| `rod-cli` (shipped, `src/cli/dotnet/`) | `rod mod init/search/info/install/verify/publish` over the manifest, signature, registry, and lock contracts (ADR-002, ADR-009); no in-house references. |

- **Optional transports** (ADR-004; amended -- shipped). The
  `ITransportProvider` abstraction landed with the in-tree families as its
  reference implementations, out-of-tree registration included
  ([extending/transports.md](extending/transports.md)), and **WireGuard**
  is the in-tree optional transport it carries: disabled by default,
  enabled by the deployment (`WireGuard:Enabled`, the listener's server
  key provisioned under `WireGuard:ListenerKeys`), named per build. mTLS
  stays retired with QUIC and SMB: nothing has countered the retirement's
  reasoning (redundant with the WebSocket beacon, a `CertificateRequest`
  itself a fingerprint), and the per-artifact key seal has since covered
  a keyed artifact's mutual authentication on every carriage -- an
  operator who wants it regardless registers a provider out-of-tree
  against the same contracts. The WireGuard dependency PoC ADR-004
  required ran and became the shipped seam: boringtun 0.7.1
  (BSD-3-Clause) builds clean on all three implant cross targets with the
  full handshake and data path linked, and ships as the C-ABI cdylib
  (`rod_wg`) the .NET side drives without any in-tree novel crypto. The
  upstream is dormant; Mullvad's gotatun is the active lineage and the
  recorded migration watch-item -- its public API has moved behind its
  device machinery and its default crypto backend is C-compiled, so the
  migration is a deliberate port, not a version bump.
- **Collaboration metadata** (ADR-005; shipped). Mutable process knowledge is
  modeled apart from the immutable evidence: **comments** (on tasks,
  implants, artifacts, files, engagements, and operators, editable within
  a window), engagement-scoped **chat** channels, and **task references**
  -- `@task-<id>` and credential placeholders in comments and task input,
  resolved server-side at publish so the placeholder plaintext never
  lands. **Global search** covers task output, comments, artifact
  metadata, credentials, and chat through PG `tsvector` + GIN indexes; no
  external search engine. Comments and chat ride the timeline as ordinary
  events but **never enter the hash chain** -- the chain carries
  operational facts, and mutable content would break its semantics.
- **Versioned API and SDKs** (ADR-006; shipped). `/api/v1` is a
  before-routing prefix alias over the operator surface: the unversioned
  routes keep serving the console and the integration suites while
  programmatic consumers address one stable, versioned URL space -- and a
  breaking v2, when one exists, mounts real routes beside the alias
  instead of through it. The **OpenAPI 3.1 spec is the interface of
  record**: generated first-party off the final route table, scoped to
  the operator surface (the implant ingress, the DoH front, the
  redirector control channel, MCP, and the public edges stay out),
  committed as `sdk/openapi.v1.json`, and held to the served document by
  a drift gate -- an intended contract change lands as a reviewed spec
  diff. **Tokens carry scopes** (read / operate / admin): the mint names
  the floor (read by default), the claim rides the token principal, and
  a gate in the shared pipeline caps the credential below what the
  operator's session allows; cookie sessions are untouched. SSE stays.
  The official **Python SDK** (`sdk/python/`, standard library only)
  carries the acceptance arc -- login, create an engagement, issue a
  task, collect the artifact -- as an integration-tracked smoke. MCP
  widened from read-only to read-write under the same scopes (shipped):
  every write enters the audit chain like an operator's action, the
  write tools hold the operate floor at the tool level (the route gate
  cannot see tool names inside the JSON-RPC body), and the write face
  keeps Sec 10.4's unattended red line -- the sensitive and channel
  verbs refuse, the same answer the automation engine reads.
  This is the replacement for Mythic's scripting and Sliver's gRPC
  client libraries -- the integration hard floor.
- **ATT&CK coverage matrix** (ADR-007; shipped). The verb-to-technique
  mapping is first-class data -- a kernel data file in core state
  (verb -> technique ids, plus name/tactic reference metadata for the
  techniques it maps), reached through the `IVerbTechniqueResolver` port
  with a registry-backed implementation swapped in at the composition
  root, so a module's declaration replaces the kernel's whole entry for
  its verb and community contributions extend coverage without a kernel
  edit. The platform carries a **coverage matrix view** -- technique x
  platform x implementation status, naming the verb, module, and implant
  class that carry each technique (`GET /capabilities/coverage`, a global
  catalog concern under Sec 4.3's placement rule; the operator UI's
  Coverage surface) -- with known gaps reading as the work queue. Two
  faces, one source: report exports carry the ATT&CK Navigator layer
  proving *what was done* (the engagement's dispatched tasks through the
  same resolver), and the matrix shows operators *what can be done*.
  Coverage advances module by module, ordered by real engagement need --
  the matrix is a dashboard, not a completion deadline.
- **Built-in observability** (ADR-008; shipped). No Prometheus. A diagnostics
  endpoint and a UI stats page over PG and in-process counters: beacon
  latency distribution, task queue depth, SSE connection count, build
  durations, module load state. Export, if an engagement ever demands it,
  arrives as a module -- never as a standing component. The endpoint is the
  deployment admin's aggregate read (no engagement dimension anywhere in
  the payload), mapped from the composition root because its dimensions
  span layers transport cannot reference, and outside the versioned OpenAPI
  contract like the capability catalog.
- **Resumable transfers** (ADR-010; shipped, both arms). The chunked
  staged pull carries byte-offset resume and both-side hash verification: a
  demand names the bytes an interrupted run left held and proves them by
  SHA-256, the answer serves only the unserved remainder, and the completing
  result carries the payload hash the server verifies against the artifact it
  served. The DNS degraded path carries the same capability over its `s.`/
  `d.` grammar -- one resume rule on every wire. The upload arm gives the
  exfil channel the same semantics in reverse: offset-bearing chunks with a
  declared whole-artifact hash place idempotently into one bounded
  cross-connection store, the seam reports (`ExfilProgress` on the frame
  carriers, the `x.` probe over DNS) chain contacts so an interrupted run
  resumes from the bytes the server already holds, and the DNS upstream is
  sealed-only under the `rod-dns-exfil-v1` tag with a 1 MiB per-stream
  ceiling -- the spoofing decision the item carried (a task id rides the
  DNS query name in the clear, and a plaintext MB-scale upload would forge
  evidence onto real tasks).

### 15.4 Product disciplines (ADR-011 through ADR-015)

- **Benchmark-first** (ADR-012). Every major functional domain starts with
  a benchmark note at `docs/benchmarks/<domain>.md`: which tools are
  mainstream here, what to adopt, what to skip, why -- conclusions at the
  product and interaction layer only, never code. First batch: C2 tasking
  and implant management (Sliver, Mythic, Cobalt Strike, Havoc), recon
  (nmap, masscan, Amass, Maltego), phishing campaigns (GoPhish), and
  browser hook (BeEF). "Because X has it" is not an argument; the kernel
  test of Sec 15.1 still gates every adoption.
- **UI information architecture** (ADR-013) _(shipped)_. Navigation
  organizes by engagement and lifecycle stage -- overview / recon /
  delivery / action / assets / report / admin, seven slots treated as a
  scarce resource: a new domain answers *which slot it enters* before it
  exists. The timeline is the main screen -- the audited event stream,
  filterable by entity, operator, and stage. Master-detail covers every
  entity listing (the implant, campaign, and recon-asset pages landed;
  the remaining listings follow as they gain detail reads); a command
  palette (reusing the search index), keyboard-first tasking, and a
  table density toggle keep the console fast; every entity detail page
  carries a related-entities sidebar (source campaign, parent implant,
  produced credentials -- lineage, the campaign leg, and the recon-asset
  link draw today); a Maltego-style topology view ships as an optional
  render module _(future)_. Tables, details, timelines, and matrices
  are **generic components** driven by Sec 15.2's schema and output
  taxonomy -- the UI, like the framework, knows no specific capability,
  so a new domain lands without touching navigation.
- **Unified entity model.** Integration runs through one entity model, one
  timeline, and references -- never point-to-point feature APIs. The
  first-class entities: Engagement, Operator, ReconAsset, Campaign and
  Recipient, Implant (parentage and the browser/web-shell classes
  included), Task, Artifact, Credential, Listener/Front -- linked by
  explicit foreign keys (never implicit strings), every entity carrying
  `engagement_id` and `operator_id` (Sec 2's rule). The foreign keys are
  composite with the engagement id on both sides, so a reference cannot
  cross engagements at the database -- the isolation the query layer
  always kept, now a constraint too. The load-bearing links: recon
  assets select directly as campaign targets (shipped); recipient
  events chain to implants through deploy tokens (shipped); implant
  parentage draws the lateral-movement tree (shipped, and an implant's
  detail reads the whole chain -- ancestors, children, and the campaign
  leg); task products land
  as credentials and artifacts, reusable through task references
  (ADR-005); a browser hook session *is* a browser-class implant -- form
  capture lands in the same credential store, command history in the same
  timeline.
- **Domain granularity** (ADR-014). Function ships at three granularities:
  **domain** (a navigation entry, first-class entities, its own workflow),
  **module** (a capability package behind the contract), **verb** (the
  atomic command, the ATT&CK mount point). A new domain passes the **four
  tests** -- *entity* (it introduces a first-class entity other domains
  reference) and *stage* (a distinct lifecycle stage with its own working
  mode) mandatory together, *authorization* (distinct ROE gating
  semantics) and *benchmark* (a tool category to benchmark against)
  weighted. What fails lands as an in-domain provider (a new data source
  is not a domain), a channel extension inside a domain (SMS phishing is a
  campaign channel, not a domain), a verb or module (a new operation on an
  existing entity), or a transport provider (a new carriage, ADR-004).
  Anti-patterns, each a documented death: a domain per tool, a domain per
  ATT&CK tactic (the matrix is a lens, not an org chart), and the god
  domain. Every major version re-reviews the domain list in both
  directions: a module that never produces cross-domain entities demotes;
  a provider that grows them promotes.
- **Documentation discipline** (ADR-015). `docs/` is a **closed set**:
  README (one page), architecture.md (this file, the single architecture
  truth), glossary.md, todo.md, one guide per extension seam under
  `extending/` (implants, tradecraft, transports), one runbook per
  operations concern, and
  `benchmarks/<domain>.md`. A new document must first answer which
  existing one cannot hold it, and why. One fact is defined in one place
  and linked everywhere else. Docs carry what / why / how to deploy;
  usage detail lives in the tool's own help. Stale content is deleted or
  merged, never archived beside its replacement. Doc changes ride the
  code PR they belong to.
- **Repository organization** (ADR-011). The GitHub organization is
  created early (the name checked against existing products), and the main
  repository moves in with history intact. The platform -- teamserver,
  UI, protocol, reference implant, loader, redirector, plugin SDK, docs --
  stays a **monorepo**; the bus-factor answer is the ecosystem, not
  repository sprawl. Splits happen only along contract seams -- both sides
  talking solely through versioned contracts, each independently
  releasable -- in order: `rod-registry` (naturally independent), then
  community module repositories, then third-party build units, then
  `rod-implant-rust` (once `Rod.Protocol` freezes 1.0), then redirector
  and UI (later, or never). No split happens before `Rod.Protocol` and
  the module contracts ship as semver-versioned releases.

### 15.5 Decision index

| ADR | Decision | Folded into |
|-----|----------|-------------|
| 001 | Capability modules fully in-tree; `Rod.Capabilities` | Sec 15.1 |
| 002 | Ecosystem: git index registry + signed manifests + `rod mod` CLI | Sec 15.2 |
| 003 | Ecosystem from zero; capability contract first-class (schema, output taxonomy, versions) | Sec 15.2 |
| 004 | Transport provider abstraction (shipped); optional WireGuard, default off (shipped); mTLS reopening rescinded | Sec 8, Sec 15.3 |
| 005 | Collaboration metadata modeled apart from the audit chain | Sec 15.3 |
| 006 | Versioned `/api/v1`, OpenAPI, Python/Go SDKs, scoped tokens, MCP read-write | Sec 15.3 |
| 007 | ATT&CK coverage matrix as the capability north star | Sec 15.3 |
| 008 | Built-in observability, no external dependencies | Sec 15.3 |
| 009 | Module package format and trust chain (`rod-module.toml`) | Sec 15.2 |
| 010 | Resumable file transfer (byte offset + both-side hashes) | Sec 15.3 |
| 011 | GitHub org, platform monorepo, splits only along contract seams | Sec 15.4 |
| 012 | Benchmark note before every functional domain | Sec 15.4 |
| 013 | UI: lifecycle navigation, timeline main screen, contract-driven rendering | Sec 15.4 |
| 014 | Domain open/close discipline: three granularities, four tests | Sec 15.4 |
| 015 | Closed documentation set, one topic per document | Sec 15.4 |
