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

Nothing queued. Phase P1 -- long-board parity (architecture.md Sec 15)
shipped with the UI information-architecture rework (ADR-013; the
record is the commit history), which also cleared P2's parking
condition: the items below left the hold and enter Active one at a
time, when an engagement names the need -- Active is advisory order,
not a queue, and an empty queue is the honest state between needs.

## On hold

Phase P2 -- ecosystem and trust (architecture.md Sec 15). Unparked:
the parking condition was P1 shipped, and it did; each item below now
waits only for an engagement to name it.

- **Public docs site + runbooks.** _AC:_ architecture.md published as the
  site.
- **Module development end-to-end docs** (init through publish). _AC:_ an
  outside contributor ships a first module following the docs alone.
- **On-demand module build/test paths.** _AC:_ main-repository CI time
  does not grow linearly with the module set.
- **Live-engagement feedback loop.** _AC:_ at least one real-engagement
  gap list lands in this file.
- **ATT&CK coverage advancement mechanism** (Sec 15.3, ADR-007). _AC:_
  module PRs declare technique coverage; the matrix and the release notes
  update from it automatically.
- **Range mode** -- scripted fake implants as the action domain's
  provider. _AC:_ fake implants run the real protocol end to end; 500+
  concurrent beacons simulate under load.

- **iOS shell for the Rust implant** (serves architecture.md Sec 12.2).
  Parked on a macOS build host: the Apple link needs Xcode's SDK, which
  the Linux host cannot carry. Shape: the same library-plus-shell pattern
  as the Android item against aarch64-apple-ios; delivery is inherently
  sideloading territory (a signed carrier app or a jailbroken device), an
  operational constraint the runbook documents rather than something the
  build can remove.
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
