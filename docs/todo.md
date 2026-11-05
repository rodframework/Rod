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
moment its acceptance criterion lands.

- **Delete the in-tree transports** (serves Sec 8, ADR-025). Remove
  `Rod.Transport`'s listener families (Dns, Streams, WireGuard,
  ShellCatch) and `ITransportProvider` once the official packages serve
  the e2e legs; the web-specific profile fields (enroll path,
  User-Agent, headers, TLS posture) move into the https package's
  config schema; shellcatch returns as a listener package; WireGuard
  moves to the community slot or retires.
  _AC:_ the teamserver process opens no implant-ingress socket, an
  architecture test holds that line, and the raw-TCP family's reach is
  documented as the pivot chain's.

- **Implant manifests and the metadata-driven UI** (serves Sec 6/10,
  ADR-027). The manifest schema riding the registry; build-record
  binding (source ref + manifest); field-vocabulary rendering for the
  build and tasking forms; the strict/open enrollment tiers;
  server-side descriptors demoted to optional enrichment.
  _AC:_ a build form renders entirely from a manifest, and a minimal
  manifest -- one target, poll, one carrier, id-only -- builds and runs
  as a first-class citizen.

- **The capability digest on the wire** (serves Sec 9/10, ADR-027).
  rod.proto grows the version/identity fields and the fixed 32-byte
  capability digest; the handshake's full verb advertisement deprecates
  along the evolution rules.
  _AC:_ conformance and both reference implants carry the digest, and a
  manifest/implant drift surfaces as a roster flag.

- **The baked config block and the patch build unit** (serves
  Sec 5.1/6, ADR-026). The `RODCFG01` block format over the profile's
  deterministic bytes; placeholder embedding in both implant trees; the
  template build unit type and patcher, with registry provenance.
  _AC:_ one source version produces a compiled artifact and a patched
  template artifact whose runtime behavior is indistinguishable, and
  every build states its path.

- **The language kits and the dial tier** (serves Sec 5.3/6, ADR-025).
  Extract the Rust and Go kits (proto codegen, seal, framing) from the
  reference implants; put each family's dial behind the kit's dial
  interface; open the `rod-kit-<lang>` community slot.
  _AC:_ a from-scratch implant built from a kit plus a few dozen lines
  of medium glue passes the Tier 0 rig.

- **The edge host** (serves Sec 8, ADR-025). The redirector's
  replacement: an enrolled remote node that pulls listener packages and
  runs listeners under kernel control, the bridge over TLS, inheriting
  the fleet's enrollment and credential model. The bridge dials in
  either direction: edge dials home by default; kernel dials out for a
  teamserver sited with no inbound reach, the edge then listening on
  both its faces.
  _AC:_ a reference implant serves a full e2e leg through a remote
  edge-hosted listener, in both dial directions.

- **Close the docs on the externalized-listener shape** (serves
  ADR-015, ADR-025). Rewrite Sec 8 (and the Sec 4/5/6/9/10/12/13
  passages the migration touches) for the listener model; retire
  extending/transports.md; rewrite operations/redirectors.md as the
  edge runbook; drop listeners.md's transition note.
  _AC:_ no document describes the in-process provider seam or the
  redirector as a current shape.

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
  coverage matrix, built on the shipped triage seam (Sec 11.3's
  summarize route and the MCP read tools are the foundation, not the
  feature); suggests only, never executes (MCP/LLM layer).

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
