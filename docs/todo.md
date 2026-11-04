# Rod -- Todo

Open work only. An item leaves this file the moment it ships -- its record
is the commit history, and the design it followed lives in
[architecture.md](architecture.md); the designed-but-deferred items stay
where they are designed (the sections carry their own _(future)_ /
_(shipped)_ markers). Nothing here is an archive of the done.

Each item names the architecture section it serves and carries a one-line
acceptance criterion (_AC:_), so "done" stays testable. Follow the
[repository conventions](../AGENTS.md).

Lean is the standing default for the kernel: an addition there must say
what an engagement cannot do without it. The module layer carries the
breadth mandate ([architecture.md Sec 15.1](architecture.md)): it
advances on a standing cadence, ordered by the coverage matrix's gaps,
and a real engagement's needs reorder that queue rather than gate it.
Refactors, deletions, and answering with docs instead of code stay
first-class items here, equal to features.

Four zones. The queue is ordered platform work: an item takes its
place by precedence and leaves the moment its acceptance criterion
lands. The standing line is the module conveyor: it never empties and
carries no order to work in -- the batches order themselves (low-risk
ground first, the sensitive families behind their default-off gates),
and inside a batch the right module to take is still the one an
engagement or the matrix names. On hold is parking, not rejection:
each item there names the fact or decision that reopens it, and a
cleared condition prompts the move back -- it does not make the move
on its own. Backlog is the candidate pool: platform and product
candidates wait there for a real user to name the need; capability-module
candidates are the standing line's future batches, and an engagement
naming one promotes it ahead of the standing order.

## The queue

Sequential platform work, precedence-ordered; an item leaves the
moment its acceptance criterion lands. The compatibility window
orders the first two: the seal's key schedule and the contact chain's
framing both touch what a deployed artifact carries baked in -- cheap
to change while no artifact is fielded, messy to migrate after -- so
they order ahead of the standing line below until they land:

- **Session key agreement over the baked seal** (serves Sec 8's
  envelope crypto, Sec 9). The seal today is AES-256-GCM under the
  key baked into the artifact, so a seized artifact decrypts its own
  recorded traffic, past and future -- the classical seized-config
  PCAP class, no quantum needed. Ephemeral X25519 at the handshake,
  HKDF into the session's sealing keys, the baked key remaining the
  enrollment identity and root; curves are cheap on every side (.NET
  ECDH, Go crypto/ecdh, x25519-dalek), so the wire contract's barrier
  does not move. ML-KEM stays out: the hybrid guards decade-horizon
  secrets engagement traffic does not carry, and the negotiated-arm
  pattern (the replay-nonce arm's shape) can add it later without a
  break.
  _AC:_ a captured artifact's baked key can no longer open its
  pre-capture recorded traffic; both pinned trees complete the agreed
  handshake and the Tier 0 rig pins the exchange
  (extending/implants.md), the lock bumping the two trees together.

- **Chained contacts through a parent** (serves Sec 5.2's pivot
  model, Sec 8). The pivot model's implant-side half: a planted host
  with no egress of its own enrolls and keeps its contact by riding a
  parent implant, the chain composing level over level toward the one
  host that can reach the edge. Riding the tunnel set (a parent-side
  bind fronting its carriage) is the in-design route; a standalone
  peer-listener transport family reopens the retired SMB/mTLS/QUIC
  line (Sec 15.3) and must argue it anew, not restate it.
  _AC:_ an implant on an egress-less segment maintains its session
  through a parent to the teamserver in the implant e2e matrix, with
  every hop's records attributed.

- **Implant-carried transports -- the exec-v1 provider seam** (serves
  Sec 8, Sec 15.1). Open the carrier seam to authors who will never
  write C#: a `transport-provider/exec-v1` contract (length-delimited
  protobuf over stdio, the exec-v1 module idiom mirrored server-side)
  lets a community package carry its carrier's listener half as a
  supervised process in any language -- two author functions (fetch a
  sealed body, deliver one) on an SDK skeleton, the generic adapter
  registering the declared carriers on its behalf so the operator API,
  carrier table, and audit treat the transport as native. Alongside it
  the implant-side half: the extension tier reaches the dial dispatch
  (an extension contributes a contact client), and the build pairs a
  listener's transport name with the package carrying it, refusing a
  build it cannot resolve. The frame paths never change -- the provider
  sees sealed bytes, not frames (extending/transports.md) -- and a
  carrier passes rod-conform's provider lane before it may name itself.
  _AC:_ a community carrier (a Discord or Telegram dead-drop is the
  shape) ships end to end -- install, listener create, build,
  enrollment -- with zero C# and zero forks; the conformance lane runs
  its provider leg, and a crashed provider marks its listener
  unhealthy without touching the teamserver.

- **The CLR assembly host -- execute-assembly** (serves Sec 5.4's
  loader seam, Sec 13). Windows engagements arrive with a C# toolchain
  in hand, and hosting it is what they cannot do without: the classic
  CLR (.NET Framework 4.x) first -- console redirection and
  AssemblyResolve for the multi-DLL tools, inline mode -- with the
  sacrificial-process mode and hostfxr (.NET 5+) as the follow-on
  stages. Native AOT is no substitute (the COM-interop and
  reflection-heavy tools do not survive it), and the AMSI/ETW posture
  composes with the shipped avoid and unload modules.
  _AC:_ a Rubeus/Seatbelt-class .NET Framework tool runs inline with
  its output captured into the engagement trail; ships disabled,
  enabled per build profile (Sec 7).

- **Fuzz the coff-v1 parser** (serves Sec 5.4). The parser is
  host-blind, so a cargo-fuzz campaign over malformed object files
  runs on today's lanes; the corpus regression matrix rides the
  conformance clause below.
  _AC:_ the parser survives a sustained fuzzing run without panic, and
  the campaign rides the implant tree's CI.

- **The coff-v1 conformance clause** (serves Sec 5.4). Unparked: the
  implant e2e matrix's windows cells now bake and run the reference
  implant live, the lane this item waited on. The clause compiles a
  mingw fixture BOF (the toolchain already rides the CI lane) and
  drives `plugin.load-coff-v1` against the running implant; a
  community-corpus regression matrix -- a standing set of mainstream
  BOFs loaded and executed each run -- rides the same leg.
  _AC:_ the clause passes on a windows cell of the implant e2e matrix,
  the corpus matrix with it, and the loader's host-blind tests keep
  their tier (extending/implants.md, Tier 2).

## The standing line

The module layer's conveyor: capability modules advancing the ATT&CK
coverage matrix (architecture.md Sec 15.1, Sec 5.4), in family batches
ordered by matrix gap. It never empties -- a family item ships
entries, folds them into its shipped list, and keeps going; the pace
is whatever the matrix gaps and real engagements set, not a schedule.

First batch, the Windows long tail (the domain-discovery family and
the persistence family both shipped -- the module line's second worked
pair covers both halves of domain recon, the credential-free sweep in
v1.0 and the authenticated directory read in v1.1, and the third
through sixth pairs carry the persist long tail: the registry run-key
seat as runkeys, the service seat as services, the WMI subscription
seat as wmi, and the DLL search-order seat as hijack):

- **Credential collection family** (serves Sec 15.2, Sec 5.4; the
  collect long tail -- the account hive dump shipped as hives, the
  unsealing primitive as dpapi, the Chromium login stores as browser,
  the LSA secret store read as lsasecrets, and the logon session's
  credential manager store as credman, the family's first five
  entries): further dump paths -- Windows-gated, opsec notes
  naming the on-target footprint.
  _AC:_ the standing module contract (manifest, paired halves, coverage
  declaration, CI lane), plus sensitive rows ship disabled and enable
  per build profile (Sec 7).

- **Defense-evasion family** (serves Sec 15.2; the evasion long tail
  -- the AMSI and ETW patch module shipped as avoid, and the ntdll
  unhooking module as unload with its v1.1 breadth: per-DLL,
  per-function, and the KnownDlls section-object freshness source):
  whatever verb the matrix and a real engagement name next.
  _AC:_ the standing module contract, plus ships disabled, enabled per
  build profile (Sec 7).

## On hold

- **Live-engagement feedback loop.** _AC:_ at least one real-engagement
  gap list lands in this file. Parked on the engagement itself: the
  loop's only input is one. Range mode stands in for rehearsal pressure
  until then ([operations/range.md](operations/range.md)).

- **iOS shell for the Rust implant** (serves architecture.md Sec 12.2).
  Parked on a real device to run the enrollment leg: the implant e2e
  matrix already carries macOS build hosts with Xcode's SDK (the old
  blocker, cleared), but the acceptance needs a carrier app linking the
  static library on a device or simulator, and none is at hand. Shape
  unchanged: the same library-plus-shell pattern as the Android item
  against aarch64-apple-ios; delivery is inherently sideloading
  territory (a signed carrier app or a jailbroken device), an
  operational constraint the runbook documents rather than something
  the build can remove.
  _AC:_ cross-compiling from a macOS host produces a static library a
  carrier app links, and the enrollment leg runs.

## Backlog

Second wave -- take up once real users exist:

- **Purple-team mode** -- verb to technique to expected-detection
  mapping riding the evidence package: each audited action carries the
  defender-side telemetry it should have produced (the Sysmon/EDR event
  ids), and the report gains the blue-team checklist a client's SIEM
  answers against (Sec 11, reporting domain) -- the assessment asset a
  procurement cycle can name, not only the operator's weapon.

- **Go SDK** -- the versioned operator API's Go face (Sec 15.3, ADR-006):
  a thin client cut against the committed OpenAPI contract. Split out of
  the MCP item: nothing in-tree or queued consumes it, so it waits for a
  real user to name the need.

- **Rule-based alerting** -- an SSE rule engine: new credential seen,
  beacon lost then returning, lure link clicked (management domain).

- **Shift-handoff briefing** -- one-click digest since the operator's last
  handoff, widening the shipped digest (Sec 11.1; collaboration layer).

Platform and product candidates -- a candidate starts when a real user or
engagement names the need:

- **Engagement-as-code** -- a declarative engagement manifest, git
  reviewed, one-click infrastructure rebuild (management domain).

- **Replay room** -- an audit-chain timeline replay view for client
  debriefs (reporting domain).

- **Credential lifecycle** -- use success and failure records drive
  "likely rotated" marks that prevent lockouts (assets domain).

- **LLM copilot** -- next-step suggestions from entity state and the
  coverage matrix; suggests only, never executes (MCP/LLM layer).

- **Approval-gated MCP writes** -- the shipped write tools gain their
  policy engine: engagement scope burned into the teamserver (a target
  allowlist the tools cannot widen), every side-effecting call held
  for an operator's approval, the audit chain unchanged. The
  autonomous-chain non-goal below stands: every write stays a single
  human-approved action, never a chained one (MCP/LLM layer).

- **Full malleable profiles** -- the shipped transport knobs (enroll
  path, User-Agent, headers, fallback endpoints) deepen into per-verb
  request and response shape templates, one malleable profile per
  listener (Sec 8, transports domain).

Explicit non-goals, standing: a cross-engagement organizational knowledge
base (violates engagement isolation at its root) and autonomous LLM task
chains (violates the unattended-sensitive-verb red line, Sec 10.4).
