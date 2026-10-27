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

Active is advisory order, not a queue: the batches order themselves
(low-risk ground first, the sensitive families behind their default-off
gates), and inside a batch the right module to take is still the one an
engagement or the matrix names. On hold is parking, not rejection: each
item there names the fact or decision that reopens it, and a cleared
condition prompts the move back into Active -- it does not make the move
on its own. Backlog is the candidate pool: platform and product
candidates wait there for a real user to name the need; capability-module
candidates are this line's future batches, and an engagement naming one
promotes it ahead of the standing order.

## Active

The module layer's standing line: capability modules advancing the
ATT&CK coverage matrix (architecture.md Sec 15.1, Sec 5.4), in family
batches ordered by matrix gap.

First batch, the Windows long tail (the domain-discovery family and
the persistence family both shipped -- the module line's second worked
pair covers both halves of domain recon, the credential-free sweep in
v1.0 and the authenticated directory read in v1.1, and the third
through sixth pairs carry the persist long tail: the registry run-key
seat as runkeys, the service seat as services, the WMI subscription
seat as wmi, and the DLL search-order seat as hijack):

- **Credential collection family** (serves Sec 15.2, Sec 5.4; the
  collect long tail -- the account hive dump shipped as hives, the
  unsealing primitive as dpapi, and the Chromium login stores as
  browser, the family's first three entries): further dump paths --
  Windows-gated, opsec notes naming the on-target footprint.
  _AC:_ the standing module contract (manifest, paired halves, coverage
  declaration, CI lane), plus sensitive rows ship disabled and enable
  per build profile (Sec 7).

- **ntdll unhooking** (serves Sec 15.2; the defense-evasion family's
  second module): `evasion.unload`, the module-layer implementation
  behind the placeholder verb -- the mapped ntdll's `.text` compared
  against the disk copy's own bytes (the portable-executable headers
  and section table parsed by hand out of both images, a build
  fingerprint refusing a disk copy the mapped image does not match),
  the bare task the read (the differing-byte count) and `restore`
  the write the operator names (page flipped writable, clean bytes
  copied, protection restored, instruction cache flushed),
  idempotent under a second run. v1.0 restores the whole `.text`
  alone -- per-DLL, per-function, and KnownDlls section-object paths
  are the later widening -- and both Windows architectures carry it:
  the compare and the copy are byte arithmetic no architecture owns.
  The registration rides the gate the family's first entry set: the
  `modifies-defenses` attribute and the Evasion category hold the
  verb behind the sensitive policy.
  _AC:_ the standing module contract, plus the verb stays behind the
  sensitive policy (unattended firing refuses) and the plugin rides
  the per-engagement module load, never a default profile.

- **Defense-evasion family** (serves Sec 15.2; the evasion long tail
  -- the AMSI and ETW patch module shipped as avoid, and the
  unhooking module is the entry above): the module-layer
  implementations behind the evasion verbs.
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

- **Go SDK** -- the versioned operator API's Go face (Sec 15.3, ADR-006):
  a thin client cut against the committed OpenAPI contract. Split out of
  the MCP item: nothing in-tree or queued consumes it, so it waits for a
  real user to name the need.

- **Purple-team mode** -- verb to technique to expected-detection mapping;
  the report gains a blue-team checklist (reporting domain).

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

Explicit non-goals, standing: a cross-engagement organizational knowledge
base (violates engagement isolation at its root) and autonomous LLM task
chains (violates the unattended-sensitive-verb red line, Sec 10.4).
