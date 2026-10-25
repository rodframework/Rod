# Rod -- Todo

Open work only. An item leaves this file the moment it ships -- its record
is the commit history, and the design it followed lives in
[architecture.md](architecture.md); the designed-but-deferred items stay
where they are designed (the sections carry their own _(future)_ /
_(shipped)_ markers). Nothing here is an archive of the done.

Each item names the architecture section it serves and carries a one-line
acceptance criterion (_AC:_), so "done" stays testable. Follow the
[repository conventions](../AGENTS.md).

Lean is the standing default: an addition must say what an engagement
cannot do without it; refactors, deletions, and answering with docs
instead of code are first-class items here, equal to features. The program
queue below (architecture.md Sec 15) is the standing source of new work;
new work outside that queue still starts from a gap an actual engagement
surfaces.

Active is advisory order, not a queue: the phases order themselves (P0,
the replacement threshold, ahead of P1 and P2), and inside a phase the
right item to take is still the one an engagement actually needs. On
hold is parking, not rejection: each item there names the fact or decision
that reopens it, and a cleared condition prompts the move back into
Active -- it does not make the move on its own. Backlog is the candidate
pool: nothing there is scheduled, and a candidate starts only when an
engagement names the need.

## Active

Nothing queued. The P2 ecosystem wave shipped (the record is the commit
history): the public docs site, the module lifecycle guide, the
on-demand module CI lane, the ATT&CK coverage advancement mechanism, and
range mode. What remains parked waits on facts only a real engagement or
new hardware can name -- Active is advisory order, not a queue, and an
empty queue is the honest state between needs.

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

Engagement-driven candidates -- a candidate starts only when an engagement
names the need:

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
