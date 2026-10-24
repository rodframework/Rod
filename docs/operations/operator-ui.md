# Operator UI -- the panels and their fields

The operator UI keeps its panels to a headline row with a question mark
beside it: the standfirst -- the sentence or two of orientation each panel
opens with -- is folded behind that mark and rides out on hover or keyboard
focus, and everything else lives in hover text on the field it describes.
Every page -- top-level or engagement surface -- opens on the same single
page title naming its surface; page content sits in cards, one concern per
card (a flow's form and the roster it feeds may share one). A card opens on
a header of its own: either a heading naming the concern in the console's
vocabulary -- Roster, Fleet, New campaign, Invite an operator, never the
page title repeated -- or the control row (toolbar, toggle, filter line)
that drives it; nothing sits bare on the page. A heading that pairs with
the card's own actions (refresh, a form toggle) is a header row: heading
left, actions right, one aligned line. This page is the long form:
what each panel shows, and what every build and listener field does, in
one place. Screenshots-age; this text is the reference.

## Navigation -- the seven slots

Engagement navigation is fixed at seven lifecycle slots
(architecture.md Sec 15.4, ADR-013): **overview / recon / delivery /
action / assets / report / admin**, in the order an engagement lives
them. The slots are a scarce resource -- a new domain answers *which
slot it enters* before it exists, never an eighth sidebar entry; its
screens land inside the slot as sub-surfaces, which are cheap. The
sidebar carries the slots; the content area opens each slot with its
own sub-nav strip (Delivery's listeners, launchers, campaigns, shells,
web shells, build; Action's implants, task log, automation; and so on),
so the sidebar promises a working mode and never a screen list.

The hash route names slot and sub, with entity drill-ins for the
master-detail surfaces: `#/engagements/{id}/{slot}/{sub}`, a detail
page at `.../{sub}/{entityId}`, and the session console at
`.../implants/{implantId}/interact`. Pre-slot deep links keep
resolving -- the retired tab ids map onto their surfaces (Intel to the
target picture, Audit to the ledger, and so on), so an old bookmark
lands on the work, not on a fallback. `g` then the slot's number
(1-7, the sidebar's order) jumps while an engagement is open; the
chord dies on a pause, any other key, or focus in a field.

Every entity listing is a master list whose rows open a **detail
page**, and every detail page carries a **related-entities sidebar**:
the explicit links of the unified entity model (an implant's lineage
and the campaign that delivered it, a campaign's recon assets and the
implants its recipients enrolled, a recon asset's referencing
campaigns) drawn as navigation, not strings to eyeball. The **density
toggle** on the topbar switches every table and feed row between the
comfortable reading posture and the compact scanning one --
browser-local, like every console preference.

The overview slot is the timeline and nothing else: entering an
engagement lands on the audited event stream, the surface everything
else writes into.

## Timeline -- the overview main screen

The timeline is the console's main screen: the audited event stream
itself -- every recorded fact plus the comments and chat that ride
beside the chain (marked *unchained*) -- newest first, one row per
event with its stage chip, kind, actor, implant link, and payload
line; a row unfolds its full payload and output. The stream lands from
the audit endpoint's newest window and refreshes on the live beat;
older history walks the keyset with **Load older**.

Three filters narrow the loaded window, all client-side because a
filter must feel instant, not round-trip: **stage** (the lifecycle
stage each kind reads into -- setup, recon, delivery, action, assets,
collab -- classified from the kind alone, an unknown future kind
reading as *other*), **operator** (derived from the window, system
included), and free text across kind, verb, payload, outcome, and the
entity ids -- which is the entity filter: paste an implant id and the
stream narrows to it. The implant reference on a row links into that
implant's detail page.

The same trail has two other reads, and each keeps its own surface:
the **Audit ledger** under Report is the dense forensic table (paged,
kind-filtered), and the report exports render the narrative
projections. The timeline is the watch's live read.

## Operating surfaces

Three words describe every conversation an implant has with the teamserver,
and the UI uses them precisely:

- **Enroll** -- the one-time registration. A dropped artifact redeems its
  baked credential exactly once, receives its identity and certificate, and
  reports its host facts and its baked contact cadence (sleep/jitter). It
  never happens again for that implant.
- **Contact** -- every later contact, on the sleep cadence the build baked.
  The implant calls home, picks up queued tasking, and returns results on
  the next cycle. All ordinary operations (shell commands, file transfers,
  process listings, screenshots) ride contacts. Every contact's handshake
  re-advertises the implant's *current* cadence, so the fleet's detail
  strip shows the live sleep/jitter pair -- a `beacon.sleep` retune lands
  on the record at the next contact.
- **Interactive** -- not "everything else": it is the on-demand live channel
  (`shell.interact`, tunnels) for real-time typing -- held open over the
  stream on a stream-mode build (the WebSocket beacon on a web front, the
  held socket on a TCP front), or carried store-and-forward on a poll build's
  contacts (operator input arrives on the next response, at the contact
  cadence). An implant that never opens one still fully operates through
  contacts.

Two builds of that contact cadence: **poll** mode makes each contact a
short request-response cycle (call home, drain tasking, sleep), while
**stream** mode holds one long-lived connection open instead -- not "one
contact", but one connection that never ends: tasking is pushed down it in
real time and the session's last-seen advances by touches on the same
stream. Either way every ordinary task rides the same verb grammar; the
difference is only how the bytes travel.

The interactive shell (`shell.interact`) is a real terminal where the
platform allows it: on Linux/macOS the reference implant runs the shell
under a pseudo-terminal, so prompts and line editing appear and the pane's
^C button sends the interrupt byte that becomes SIGINT for the foreground
program. Where no pseudo-terminal wrapper exists (a stripped container,
Windows before a ConPTY handler lands), the channel falls back to
byte-transparent pipes: fully usable, but without echo or signal
semantics. It opens as a **dialog** (the menu's "Interactive shell", the
console's `interact`, or the fleet menu): every shell session the implant
ever ran stays visible as a folded history block -- the transcript is the
task's own record -- with a separator line above the live session marking
each break. A shell does not survive its channel: when the operator closes
stdin, the shell exits, or the idle window closes an abandoned session
(default 10 minutes without operator input; `ROD_SHELL_IDLE_SECONDS`
overrides for lab runs), the next shell starts fresh -- a new process in
its home directory -- under the separator. Closing the dialog keeps a
running session alive server-side; reopening continues it.

## Interaction ownership

One operator at a time types into a surface (architecture.md Sec 4.5). The
typing halves -- a live channel pane (shell or tunnel, relay binds
included) and a caught shell's console -- are exclusively claimed: the
first thing this console sends takes the claim, the pane's header and input
placeholder name the holder (`held by alice`) while another operator holds
it, and dismissing the pane releases it. A disconnect releases it too --
the claim lives exactly as long as its holder's live stream -- and the
server refuses a second operator's input outright (a 409 naming the holder)
rather than interleaving two keyboards into one shell. Teardown never needs
the claim: closing a caught shell or unbinding a relay stays open to every
acting operator, so a runaway surface is always killable.

Beside the exclusive claims, the fleet table carries **driving** badges --
the operator whose tasking each implant last saw, a soft signal refreshed
on every hand-off. What an operator may do on an engagement is their
membership tier (see [Members](#members)): a reader watches while the
server refuses her acting routes with 403 -- the landing roster's *You*
column names each engagement's tier for you.

## Naming -- the fixed vocabulary

The three connection behaviors above are the whole vocabulary, and the two
nouns are **listener** (the server-side object, created on the Listeners
page) and its **public endpoint** (the address implants dial). Every
address-carrying field names the noun it picks and, where it matters, the
behaviors it carries in parentheses. These names are **locked**: they
appear here, in the Build form, the Payloads library, and the listener
form, and they do not drift per panel. Changing any of them is a
deliberate act that updates this section first.

- **Listener (enroll + contact)** -- the Build form's first field: the
  listener whose public endpoint gets baked. The implant registers on it
  once and contacts on it for the rest of its life, interactive riding
  the same front (the WebSocket beacon on a web front's stream build, the
  contacts themselves on a poll build). The
  Payloads library's **Listener** column names the same thing
  per artifact.
- **Public endpoint (enroll + contact, manual)** -- the typed-address
  twin of the pick, under Advanced, for an address this teamserver does
  not serve (a redirector you control elsewhere).
- **Fallback public endpoints** -- backup enroll + contact addresses
  baked behind the primary and walked in order when it burns.
- **Public endpoint** -- the listener form's own field of the same name:
  what the listener will be to implants. "Callback" appears nowhere; it
  was retired as a synonym that meant three things.

Transport labels in the listener form follow the same rule -- they name
what each transport carries, not how a build makes it ride: every
transport -- HTTPS, cleartext HTTP, raw TCP, and the DNS family (TXT over
UDP, the same grammar over HTTPS on DoH) -- carries **enroll + contact +
interactive** (the socket enrolls on its opening exchange and holds the
live session on a stream build; the DNS family enrolls through a chunked
TXT exchange and opens the session itself -- a DNS-only target's whole
lifecycle rides the one carrier). Interactive rides the stream fronts
live or the poll cycles store-and-forward -- over DNS, the input arrives
on the TXT answers and the output chunks up as queries, at the query-rate
cadence: the slowest wire that carries it, carried anyway. How each
behavior rides is the build's pick -- the mode -- and the Build
form's summary spells that out per build.

Three identity layers fold into the UI, and it pays to keep them straight:
a **device** is the host an implant reported at enroll (hostname, OS/arch,
account -- recorded on the implant, grouped in the fleet), an **implant** is
one enrolled identity (class, kill date, lineage, lifecycle), and a
**session** is the live connection (at most one per implant; its state is
the status dot and the last-seen column). A session whose last contact
rode the DNS carrier wears a **degraded · dns** note beside its status dot
-- the degraded-mode contract (architecture.md Sec 8): presence, short
tasking, and chunked results only, channel tasks queued until a stream
carrier returns.

- **Implants** -- the fleet in one table, one row per implant, grouped by
  device with collapsible group headers (an OS mark -- Windows, Apple, Linux,
  or the neutral chip -- and the hostname flush-left with the column content,
  the full OS description the implant reported at enroll beside it, the
  collapse caret at the far right).
  A toolbar rides the table: free-text search across the identity fields
  (applied on Enter or its Search button), a state filter (online / offline /
  retired), a class filter, and column
  sorting (implant id, last seen, kill date -- first click the natural
  direction, second flips, third returns to the default fleet order);
  past ten device groups the table paginates. The header row is always
  laid down, so an empty fleet (or a filter that matches nothing) reads as
  a table with a message, not an empty card. The row's dot is the session
  (green while it lives, gray after), the **User** column is the account the
  implant process runs under, and the last-seen column reads the
  freshest stamp -- the presence roster while online, the implant row's
  durable heartbeat after the beacon goes dark -- re-rendered on a quiet
  30 s clock so relative stamps keep moving between live events. The kill
  date column shows the artifact's own fuse as reported at enroll, "none"
  for open-ended builds. A stream
  that closes cleanly drops Online immediately; a stream that dies
  silently holds Online until the staleness sweep closes its session
  (default 15 minutes of silence, swept every minute -- adjustable at
  runtime on the **Settings** page, boot-defaulted from
  `Sessions:Staleness:Threshold` / `SweepInterval`) -- the standfirst and
  the dot's hover text say so, and Last seen always tells the truth in the
  meantime. Devices group by the hostname reported at enroll, so two hosts
  reporting the same hostname (cloned machines) share a group; the group
  header's hover says so, and the rows underneath stay per-identity. Notes and
  retire live on the row; **Details** opens the implant's detail page
  (the record, the recent tasks, and the related-entities sidebar --
  lineage, the delivering campaign, the recon asset), **Interact** the
  session console; and everything else opens from its context menu
  (right-click or the three-dot button): shell commands, the file browser,
  the process browser, recon, persistence, collection, modules -- each
  entry gated on the implant's class, argument-bearing verbs opening a
  labeled dialog
  (marked with a right-edge ellipsis, the native "asks for more" menu
  convention), zero-argument verbs issuing directly. The argument dialogs
  are schema-driven: each verb's fields come from its declared parameter
  schema in the capability catalog (architecture.md Sec 15.2), so a
  module's verb renders a labeled form the moment it registers -- the UI
  holds no per-verb table, and a verb nobody described falls back to the
  raw-arguments form.
- **Session console** (`#/engagements/{id}/action/implants/{implantId}/interact`,
  the Interact link on a row; its title bar carries a Details link to
  the implant's detail page) -- one implant, rendered as a terminal: a title
  bar naming the device, identity, and live state; a scrolling transcript of
  that implant's task history (each task a line with time, status tag, verb,
  and arguments; short output unfolds under the line, long output folds
  behind a line count; a channel task's pane opens in the
  same flow above the prompt); and a prompt at the bottom -- a plain line
  runs as a shell command, `help` lists the shortcuts (`interact`, `sleep`,
  `ps`, `kill`, `screenshot`, `hostenum`, `portscan`, `services`,
  `download`, `upload`, `files`, `raw`); `upload` opens the picker dialog,
  because its argument is a local file. `sleep <interval> [jitter]` retunes
  the live contact cadence without a rebuild (Go durations or bare seconds;
  `sleep 0 0` polls back-to-back -- the near-interactive posture over a poll
  build), and the same verb rides the row menu's **Beacon → Contact
  interval** entry as a labeled dialog. The transcript follows the newest line while
  the operator is parked at the bottom and pins when they scroll up. The
  Advanced disclosure is the raw verb+arguments escape hatch, pinned to
  this implant. The module family rides the row menu's **Modules** group:
  **Load module** opens a labeled dialog whose file picker carries the
  module binary as the task's staged content (the server binds its sha256
  into the signed tasking), **List modules** issues directly, and
  **Unload module** asks for the name. Once a module is loaded, its verbs
  answer here exactly like built-ins. A live tunnel pane carries its relay
  control in the header: **Start relay** (tunnel.forward) or
  **Start SOCKS** (tunnel.socks) binds a teamserver-side listener onto the
  channel -- an ephemeral loopback port the answer names, so
  proxychains-and-alike ride the tunnel without typing bytes into the
  transcript -- and **Unbind** tears it down (open to any task-scoped
  operator, the safety valve). Closing the pane releases the typing claim
  but leaves a bound relay listening; the pane that reopens re-detects it
  by the refusal a second bind gets.
- **Task log** (beside Implants, in the Action slot) -- the engagement's
  task history as a filterable, live log: by implant (switches to that
  implant's own feed), verb, status, issuing operator, or free text. Each
  row carries a chevron that unfolds the full output (and a one-line
  preview of the answer while collapsed); channels open their pane, and
  the unfolded row lists the task's artifacts with downloads and the
  operator-side attach that binds an evidence file to the task's record.
  A completed row with output also offers **Summarize with LLM**
  ([llm.md](llm.md)): the captured output goes to the configured
  OpenAI-compatible endpoint and the answer renders under the output --
  an explicit button, not a passive label, because the request egresses
  content and every attempt is audited against the clicking operator; an
  unconfigured integration answers 503 naming the configuration section,
  shown verbatim.
  The log's tasking is read-only -- canceling a queued task happens in
  that implant's session console. Issuing happens in the implant menu and
  the console; this surface is for reading.

Two browsing panes open from the menu (and the console): the **process
browser** (`recon.ps` as a filterable table with a confirmed per-row
`proc.kill`) and the **file browser** (`fs.list` walks the tree; upload
rides `file.push`, download rides `file.pull` -- small files inline, larger
ones through the artifact store). Both are snapshots with a refresh, and
their results ride a browse cache: reopening shows the last listing with
its age, a listing in flight when the pane closed is attached to instead
of re-issued (its answer lands in the cache either way -- the cache polls
on its own), walking back up the tree is instant, and the file browser
reopens on the last visited directory. Refresh cancels the queued listing
it replaces and issues a fresh one, so one browse never stacks a second
identical command behind it. An implant binary fielded before a browse
verb existed answers "unknown verb" (verbs are baked into the artifact at
build time); the panes translate that answer into the fix -- rebuild the
payload and redeploy.

## Command palette

**Ctrl+K** opens the palette anywhere in the console; **Esc** closes it. The
palette is the keyboard's reach over what the mouse already reaches: one
fuzzy field whose entries are navigation (every sub-surface, Settings,
System, the engagements list), entities (implants by hostname, user, or
id -- Enter opens the session console; campaigns and recon assets --
Enter opens the detail page), verbs (the capability registry; Enter
opens the verb's dialog), and task snippets (Enter runs). Slot jumps
(`g` 1-7) and the density toggle round out the keyboard leg; see
[Navigation](#navigation--the-seven-slots). Matching scores a
subsequence -- a prefix beats a word start beats a substring beats
scattered letters -- and implant entries tie-break online-first, so the
shortest reach lands on the live box.

A verb or a snippet picked outside a session console needs a target, and
the palette asks rather than guesses: the same field re-queries the fleet
and the second Enter issues against the pick. Inside a session console the
implant is the context and one Enter issues against it. The palette is a
dispatcher, not a surface of its own -- every entry routes to the handler
the mouse would reach, and no verb, gate, or panel exists only inside it.

Inside an engagement the same field is also the **global search**: from
three characters on, the query asks the teamserver's full-text index
(Postgres `tsvector` under the covers; no external engine) and the
answers ride above the local entries -- hits across task output,
comments, artifact metadata, credentials, and chat, each routing to the
surface that shows its corpus. The search is engagement-scoped by
construction, and a credential's secret is never matchable text: the
index covers its metadata only.

## Task snippets

A **task snippet** is a named sequence of issue commands,
engagement-scoped and shareable: saved once by any operator, it lists in
every operator's palette and survives a restart like every engagement
fact. The shape is a name plus ordered steps, each step a verb and its
arguments verbatim -- and no target: a snippet runs against whichever
implant the operator picks (the console's implant, or the palette's
target step), so one triage sequence serves the whole fleet.

Saving starts from the session console's menu: a dialog lists the
implant's recent transcript as a checklist, the operator picks the lines
in order, names the sequence, saves. Validation at save is structural
only -- steps present, in order, and bounded (a refusal names the
bound) -- because the issuance gates at run time are the authority,
exactly as if the steps were typed. A snippet is keyboard shorthand an
operator fires while present: it never fires on a schedule and never
chains on results -- unattended tasking is the Automation panel's
domain.

Running issues every step at once through the ordinary tasking path: each
task is attributed to the running operator, gated exactly like a typed
one (a step a gate refuses refuses alone; the rest still issue), and the
console shows the sequence landing line by line. Saving and deleting are
audited engagement facts attributed to the operator; running writes no
separate record -- the tasks themselves are the trail. Management lives
in the palette: a snippet entry shows its steps and deletes from there.

## Automation

The Automation panel manages the engagement's declarative rules
(architecture.md Sec 10.4): what fires while no operator watches -- the
overnight command every 30 minutes, the triage batch on first contact, the
chain that reads a completed result and tasks the follow-up. Every firing
issues through the ordinary tasking gates, attributes to the synthetic
**automation** operator (the handle the audit listing shows), and lands in
the trail as its own `AutomationRuleFired` fact beside the task's arc.

**New rule** is the three-part form:

- **Trigger** -- *Every interval* (seconds; the schedule is durable: it
  survives a teamserver restart, and fires missed while the server was down
  are skipped, not made up) or *On event* -- one of the engagement's
  operational beats (session opened/closed, task issued/completed/
  cancelled, implant retired), optionally narrowed by *Only this implant*
  and, on task-completed triggers, by *Completed verb*. Event triggers are
  best-effort like the bus they ride; the engine's own firings never
  re-trigger (chains terminate).
- **Action** -- the target implant and the verb (with its OPSEC badges
  inline) plus arguments, issued verbatim on every firing. Channel verbs
  and sensitive verbs never fire unattended; the server refuses them at
  creation with the reason.
- **Cooldown / firing cap** (optional) -- the minimum spacing between
  firings (default: the interval, or one minute for event rules; a burst of
  matching events yields one firing) and the cap after which the rule
  disables itself and says so in the trail. Defaults: 100 firings.

**Rules** reads each rule's own guard state back: status (enabled /
disabled), the trigger and action, the fire count against its cap, the next
firing (or the last one), and the consecutive-refusal streak -- three
refusals in a row (an ROE violation, a closed door) disable the rule
automatically. The list rides the live event tick, so counts move as
firings land. Row actions: **Disable** (the cancel; **Enable** re-arms from
now) and the two-click **Delete**.

## Notifications

The Notifications panel manages the engagement's out-of-band channels
(architecture.md Sec 4.4): the webhook URLs that receive the live events no
operator sat up for -- the implant that returns overnight, the shell that
gets caught at 3 a.m. Each push is the frame a connected console sees
(kind, engagement, implant/task ids, payload, timestamp); delivery is
single-attempt and best-effort like the bus it rides, every attempt lands
in the trail as a `WebhookDelivered` fact, and the URL is the channel's
bearer secret -- the trail and this console show only its host.

**New channel** is the name, the URL (absolute https; plain http on
loopback only), and the event kinds to push. The notifiable set is the
engagement's operational beats -- sessions, shell caught/lost, task
issued/completed/cancelled, implant retired, payload fetched; presence and
channel output are excluded (console chatter and a per-chunk firehose).
Note the split from automation's trigger list: a caught shell is exactly
what an off-console operator wants to hear about, so the shell kinds push
here though they never trigger a rule.

**Channels** reads each channel's own bookkeeping back: status, the target
host, the kinds it pushes, the delivery count with the last delivery, and
the consecutive-failure streak -- three in a row park the channel with the
cause in the trail (fix the receiver, then **Enable** starts the watch
fresh). Row actions: **Test** (one synthetic frame down the same delivery
path -- the verification to run before relying on a channel overnight; the
outcome is the answer either way), **Disable**/**Enable**, and the
two-click **Delete**.

Where a channel points is an OPSEC decision: the push body is what the
console sees, task output included, so pointing it at a third-party IM
bridge is a decision about engagement data leaving the box
([teamserver.md](teamserver.md), the `Webhooks` row).

## Handoff digest

The Handoff digest is the Audit ledger's window mode (architecture.md
Sec 11.1): the resuming operator's read of what happened on the watch
while nobody sat at this console. The live stream has no replay -- events
that fired while disconnected never happened, console-side -- so the
digest answers the resume question from the one place that holds it: the
engagement's audit trail, windowed and curated into a single ordered
account. It earned its own tab once and retired it again: the resume
question is a query over the ledger, and the ledger is where it is asked.

**The window** anchors where you pick it: the quick picks (last 12h, 24h,
48h) set both bounds at click time, the custom fields set explicit
inclusive bounds (an empty end reads as now), and the server's default,
with nothing picked, is the last twelve hours. The span is capped at
thirty-one days -- longer horizons are the Audit ledger's job, which
pages. Refresh re-reads the same bounds, so late-landing facts inside the
window appear while the window itself never slides.

**The watch in numbers** sizes the shift first: the non-zero counts of
sessions opened and closed, implants enrolled and retired, tasking
issued with its outcomes, ROE refusals, implant notes, and shell
sessions. **The watch in order** is the account itself, oldest first,
each entry enriched the way the report timeline enriches it -- the acting
operator's handle, the implant's class, the task's verb and outcome --
with the window's integrity line above it (the content hash and the
chain-verification state, the timeline's discipline). One reading note:
a `SessionClosed` line is written by the staleness sweep, so it marks a
stream that went silent; a session closed by a re-enroll leaves the
successor's `SessionOpened` as its trace and no close event of its own.

**Copy handoff note** renders the same account as Markdown onto the
clipboard -- the note to paste to the next watch or the channel of your
choosing.

## Recon

The Recon panel is the external workbench's acting surface
(architecture.md Sec 11.4; the egress decisions, configuration keys, and
caps live in [recon.md](recon.md)): the scoping an operator runs before
the first foothold. One form, four runs -- the **RDAP** registration
lookup (whois behind it for zones without RDAP), the **Subdomains**
census over certificate transparency, **Resolve** over DNS-over-HTTPS
(one name per line; the first line alone is a single lookup, a full box
is a bulk run), and the **Port scan** with the optional ports grammar
(`22,80,443`, `1-1024`; blank scans the curated default set).

A run is synchronous: the egress, the artifact, and the audit event all
happen inside the request, so the button holds at "Running…" -- a scan
at the port cap can take half a minute -- and the answer is the landed
finding itself, rendered in the pane below the form. Each artifact shape
reads as its own table (the census as a name list, resolution as
host/addresses/CNAME, the scan as open ports ordered by port), the
registration record as indented JSON and the whois fallback verbatim;
long findings cap at five hundred rows inline -- the download is the
exhaustive read, and opening one records the trail's `ArtifactViewed`
event like any other loot.

The panel carries no egress decisions of its own. Which RDAP mirror,
which CT mirror, whose resolver, and where a scan dials from are
teamserver configuration (recon.md again); a half that is not configured
answers `503` naming the setting it wants, and the form's error line
shows that sentence verbatim rather than paraphrasing the decision into
a dead end. The scan alone carries the ROE target gate: the form shows
the engagement's `permittedTargets` beside it, and a target outside the
scope is refused before any connection opens (`422` with the violated
rule, the refusal its own audit event). The panel opens the engagement's
**ROE editor** -- a scope line above the form ("Engagement scope: 2
verbs, any implant, 16 targets", or "unrestricted") with an **Edit
scope** button (writers and the owner; the workbench is the ROE-gated
surface, but the profile gates tasking everywhere). The dialog edits all
three allow-lists as one-entry-per-line text areas -- permitted verbs
(exact or `namespace.*` wildcards), permitted implants (exact ids), and
permitted targets (hostnames, IPs, CIDR blocks) -- each empty meaning
unrestricted on that dimension, and the dialog says so when all three
would go unrestricted. Applying is audited (`RoeUpdated`); a malformed
target entry is refused by name rather than silently matching nothing.

The **Findings** list under the form is the workbench's own history --
the engagement's `recon.*` artifacts paged out of the loot board,
task-less and attributed to the running operator -- reopening in the
same pane. The findings join the reads beside this panel: the loot
board's rows and the topology projection's dashed recon-seen hosts
both read the same artifacts this panel produces.

The slot's third surface is the **recon-assets roster**: the named
targeting vocabulary -- emails, domains, hosts, addresses -- recorded
as campaign-worthy, with a kind filter and a record form. An asset's
whole point is selection: campaign creation picks recipients straight
from the roster, and every recipient and enrolled implant carries the
asset link back. Each row opens the asset's detail page (the record,
deletion, and the sidebar walking forward to the referencing campaigns
and the implants they enrolled); deleting an asset refuses while any
campaign still references it.

## Target picture

The target picture is what the engagement learned about the target
(architecture.md Sec 11.2) -- the read the operator consults instead of
re-reading transcripts, the recon slot's read half (the workbench
fills it). Two sections share the card.

**Hosts** is the device dimension: implants grouped under the hostname
they reported at enroll (case-insensitive; an implant that reported
none stands alone under the fleet), each row showing fleet
occupancy, the OS and account the enrollment reported, the crew's
labels, and the note count. "Notes & labels" opens the attributed-facts
panel: notes append (immutable, like implant notes), labels set and
clear -- each action an audit event, and the live set is the last-wins
reduction over them. A host only a note or label names still appears:
recon can see what nothing occupies.

**Loot** is the typed board over the artifact store: each row is an
artifact the engagement captured or attached, classified by what
gathered it (screenshot, credential, file, other -- the producing verb's
declared output kind decides, any module verb included) and carrying its
capture attribution -- the task and its verb, the implant, the credited
operator; a pre-foothold workbench finding carries the running operator
alone, there being no task to join. Screenshots open as an inline
preview; other kinds download.
Opening a piece of loot records an `ArtifactViewed` event attributed to
you: reading a projection of the evidence is not an act on the
engagement, but bytes leaving the platform are. "Load older" walks the
pages.

**Credentials** is the harvest board: one row per credential any
completed task produced, parsed at read time from the output of every
verb that declared credential output (the reference `collect.cred` and
any module's harvest -- architecture.md Sec 15.2's second contract).
Secrets stay masked until the row's reveal; each row carries its capture
attribution (task, verb, implant). Nothing is stored -- the projection
re-reads the task history, the same posture the topology holds, and the
persisted credential entity (reuse, rotation marks) stays the entity
model's work.

**Topology** is the assembled network picture: hosts grouped from
enrollments (accented) beside the ones only recon observed (dashed) or
a note named, pivot links drawn outward along recorded parentage, and
the recon observations listed underneath. Nothing is stored -- the
projection re-reads the fleet, the trail, and the enumeration-typed task
outputs (task outputs and the workbench's task-less findings artifacts
alike) every time -- and a broken audit chain refuses to render over it.

## Assets -- the engagement's holdings

The assets slot holds what the engagement gathered and built: the
harvest, the exfil board, and the durable payload library
([Payloads](#payloads) below). Two of the three were the old Intel
panel's sections; the slots rework drew the line -- loot and
credentials are holdings, not target knowledge.

**Loot** (the typed board over the artifact store) and
**Credentials** (the harvest board) render exactly as they did inside
Intel, each now owning its surface: loot rows classified by what
gathered them (screenshots preview inline, other kinds download,
opening records the `ArtifactViewed` pull), credential rows masked
until revealed with their capture attribution. The classification is
the producing verb's declared output kind, any module verb included,
and the projection re-reads at render time -- nothing is stored.

The transcript surfaces ride the same taxonomy: a completed task's
output block in the session console and the task log renders as the
panel its verb declared (a process table, a file table, a credential
table, a findings table, or the artifact with an inline preview for
file and screenshot outputs) and falls back to plain text when the
output does not parse -- the UI keeps working, the module just earns no
panel (architecture.md Sec 15.2).

## Listeners

An engagement's C2 ingress. Each listener owns two addresses:

- **Bind** -- the socket *this server* opens. Picked from the host's
  interfaces (the dropdown is built from `GET /network/interfaces`): one NIC,
  the all-interfaces wildcard (`0.0.0.0`), or a custom address; the port is
  its own field, defaulted per transport (https 443, http 8080,
  DNS 53, TCP 443).
- **Public endpoint** -- the address *implants dial* (enroll + contact,
  and interactive), baked into payloads. The create form's
  field of the same name takes a bare host, host:port, or full URL and
  completes it (scheme from the transport, port from the bind); empty
  derives it from the bind. In production this is typically your
  redirector ([redirectors.md](redirectors.md)); in dev it is usually the
  bind itself.
- **Certificate** (http/https transports) -- whose certificate the front
  presents, the fact every build against it inherits as its TLS roots.
  `engagement CA` (the default) works for any domain you point at the
  listener: the CA mints the front's leaf with a SAN naming the public
  host, and artifacts pin the CA. `public` marks a real-domain front
  whose publicly-trusted certificate an operator-run edge terminates in
  front of this listener (the public endpoint must be that edge's https
  address) -- the shape that survives TLS inspection. The roster marks a
  public front beside its transport.

Endpoint completion (HTTP-shaped transports only): an empty endpoint derives
from the bind (`bind 10.1.2.3:8443` on https becomes
`https://10.1.2.3:8443`); a bare hostname (`redirect.example`) takes the
transport's scheme and the listener's own port; a `host:port` pair takes the
transport's scheme; a complete URL passes through. The stored form is always a
full URL, so the roster and every build read one uniform shape. A wildcard
bind (`0.0.0.0`) names no dialable address, so it cannot derive -- give it a
hostname. DNS and TCP cannot derive at all; their endpoint (zone /
  host:port) is required.

The transport dropdown is grouped by role -- payload ingress (https,
http, TCP), the DNS family for DNS-only egress (DNS, DoH), catchers
(shellcatch) -- and the form opens on https: the one-port posture that
carries every behavior, so the untouched default is already the recommended
shape.

Every listener is engagement-scoped and persisted -- a restart rebinds it with
the same id -- and enrollment through its socket accepts only that
engagement's tokens. **Repoint** swaps the public endpoint at runtime without
touching the socket (a burned redirector is severed). **Delete** is guarded
twice over: the button itself arms (first click turns it into a "Confirm
delete" that reverts on its own after a few seconds), and the teamserver
records which listener's socket carried each enrollment, refusing with the
count when live implants enrolled through it (retired implants do not count)
-- the operator UI turns that refusal into a final confirmation naming the
dependents, and only its explicit accept (or `?force=true` on the API)
unbinds and forgets the listener. A listener nothing depends on dies in two
clicks and no dialogs.

**Fronts** are the enrolled-fleet half (architecture.md Sec 8): attached
redirectors render as indented sub-rows under their listener -- the
primary badge first, the redirector's name, the endpoint it binds, and the
address implants dial through it. The create form and the attach form
share one card slot as a two-entry tab strip (the settings page's strip
shape; both keep their drafts across a switch), with the attach tab
disabled until a frontable listener exists. Attaching a front (the
*Attach a front* tab) names the listener (every payload-ingress family -- the web pair
and the raw socket ride the TCP splice, the DNS family the redirector's
datagram relay), a redirector from the fleet roster, the endpoint that
redirector binds, and the public
endpoint implants dial (completed like the listener's own; a dns or doh
front names the **resolver** -- host or host:port -- because the zone is
the listener record's own, and the DNS family's record never follows its
primary front). Picking the listener drafts the form: the bind pre-fills
with the transport's standard public port, and Primary pre-checks when
the listener has no fronts yet -- the drafts are there to correct, and a
hand-typed endpoint survives a re-pick. **Primary** inserts the front at
the head and repoints the
listener to it; *Promote* does the same later -- the rotation op that
replaces repointing for enrolled fleets, since the node receives and serves
its rule the moment the attach lands. *Detach* (two clicks) removes the
front's rule on the next
push; detaching the primary promotes the next front. Every front change
lands in the engagement's audit trail. Fronts and the manual repoint compose
freely: a listener with no fronts is the manual fleet of old, and its
endpoint edits work exactly as before.

The panel's transport shapes, one per family:

- **`HTTPS` is the one-port shape** (the mainstream C2 listener): TLS with
  no client certificate requested anywhere -- the handshake is
  indistinguishable from an ordinary website's. Enrollment rides the socket
  on the deploy token and contacts ride the sealed envelope under the
  per-artifact key, both authenticated at the application layer. One
  listener, one port: enroll + contact, and the WebSocket beacon hangs off
  the same front when the build runs stream mode.
- **`HTTP` (cleartext, loopback) carries enroll + contact over the envelope
  POST cycle** (poll mode): every contact body and its response seal as
  AES-256-GCM under the per-artifact key -- the authentication cleartext
  http lacks a TLS layer for. The WebSocket beacon rides it the same way
  for a lab stream build.
- **`TCP`** carries the socket family: enrollment on the opening exchange,
  one connection per contact on a poll build, the held live session on a
  stream build.
- **`DNS`/`DoH`** carries the datagram family: the chunked TXT enroll
  exchange, poll contacts under the zone, the store-and-forward
  interactive discipline at the query-rate cadence.

Every payload build pins the teamserver CA into the artifact, so the
implant's first contact (enroll) validates the server it dials against the
C2's own CA -- no system-trust assumptions.

## Launchers

The engagement's one-liner home: every command an operator copies out, in
one place. **Catch a shell**, **Deliver a beacon**, and **Hook a browser**
share one card slot as a tab strip (the settings page's strip shape; all
keep their drafts and picks across a switch) -- each card carries its own
growing roster, so no list pushes another card off-screen. The catch tab
rides only while a shellcatch listener exists.

**Catch a shell** renders the paste-ready reverse-shell one-liners for a
shellcatch listener's public endpoint -- the classic shapes across the
interpreter families a target is likely to have (`bash -i >& /dev/tcp/...`,
`nc`, a Python/Perl/PHP/socat one-liner, a PowerShell client). A listener
picker renders the chosen endpoint's set in one fixed place when several
catchers exist. No credential is involved: the address is the listener's
own endpoint, and the caught shell lands in the Shells roster. The
python pty shape leads because it is the full-interactive catch: a real
pty (via python's pty module -- the dependency most targets have) echoes
typing, colors the prompt, turns ^C into SIGINT, and runs full-screen
programs; the socat shape serves the same posture where socat exists.
Every shape wears its posture as a chip -- *interactive* (green, a pty)
or *dumb* (amber, a pipe) -- so the choice reads at a glance instead of
from experience.
The plain shapes run without a terminal -- their output is faithfully
rendered, colorless and line-at-a-time (the console converts their
bare-LF line endings so the transcript does not staircase), but typing
has no echo and ^C is just a byte; the console's Local echo switch makes
that typing visible.

**Deliver a beacon** cuts the payload fetch command, so a target with any
shell access beacons without a file landing first. The shell console's
Upgrade render produces the same commands for a shell it already caught;
this panel is where an operator cuts them ahead of any catch. The form and
the **Kept launchers** list below it share one card -- cutting a launcher
and coming back to it is one surface, the same layout the Build surface gives
its form and job strip. The one pick
that matters is the **payload** -- the build the fetch delivers
(the engagement's newest stands in). The rest live behind the "fetch front
& credential" fold because the defaults are almost always right: the
hardened HTTP(S) front for the fetch URL, a single-use credential (one
paste, one download) living 30 minutes. Unfold to name a specific front, to
widen the credential for a many-host deployment (unlimited or a fixed
count, up to a day), or both.

The answer carries the fetch URL, the credential, and one command per
downloader family *for the payload's own target OS*: `curl`, `wget`, and the
python3 memfd family that runs the fetched bytes without landing a file for
Linux builds; PowerShell's `iwr` for Windows builds. A command for another OS
would spend the fetch credential on bytes that cannot run, so it never
renders (a payload with no recorded target keeps every family -- the shell
being pasted into is then the only clue). Copy the one the target's shell
has; the beacon lands in the fleet table on its enrollment, already
reporting its cadence. Over an https front every family's command disables
transport verification -- the front's certificate comes from the engagement
CA, which no stock target toolchain trusts (the implant itself pins that CA);
the fetch credential is the gate.

Why the fetch carries its own credential when the payload bakes one: the
baked credential lives inside the artifact and enrolls the implant after it
runs. The fetch -- downloading those bytes -- presents a freshly minted,
scoped token instead, so a long-lived enrollment secret never rides a
command line or shell history. Each served fetch spends one use of that
token; a refused fetch (wrong front, unknown payload) spends nothing, and
the credential dies by budget, expiry, or revocation.

**Kept launchers** is the list every render lands in: when it was cut, for
which payload (named by the payload library's fingerprint -- the same
identifier the Payloads library's Fingerprint column shows, so a row matches
its artifact without an id detour; a deleted payload falls back to the
bare artifact id), over which front, and the credential's standing as one
plain line -- `usable · 1 of 1 downloads left · until 19:00`, or `no
downloads left`, `expired 19:00`, `revoked 18:35` when it is done (a
bounded credential whose token has left the store is out of downloads
whichever end it met). **Commands** expands the row's one-liners directly
beneath it (re-rendered from the row's URL and credential, so an old row
always copies in the current shape). **Commands** appears only while the credential still
serves fetches -- a dead credential's one-liner would download nothing
(the route refuses the fetch; the artifact itself stays downloadable to
the operator from the Payloads library). **Delete** closes the row's whole
lifecycle: the credential dies wherever a copy of the command carries it,
the row goes, and the mint's history stays on the audit trail -- for a
surgical revoke that keeps the row, the API's `:revoke` endpoint remains.
The rows survive a teamserver restart when the durable store is
configured, like every other engagement fact.

**Hook a browser** is the XSS foothold's delivery, the third surface:
the mint renders the in-tree hook script with its bake (enrollment
credential, seal key, cadence, verbs) and answers the paste-ready
`<script src>` tag to inject on the vulnerable page, plus a test page
URL that enrolls the first browser pointed at it. The pick that matters
is the **front** -- an http(s) listener whose public endpoint every
victim's browser dials; the cadence, enrollment budget, and seal posture
sit behind the fold (the budget is enrollments, one per hooked browser
and one per reload where the page's storage is blocked -- serving the
script itself is unbudgeted; the cleartext posture exists for hooking
plain-http pages where the browser offers no `crypto.subtle`). Every
mint lands in the roster below with **Revoke**: the serving URL 404s,
the baked credential stops enrolling, and browsers already holding the
script go quiet at their next contact. The hooked browsers themselves
need no surface of their own -- they are Browser-class rows in the
fleet table, taskable from the same menu (fingerprint, cookies, DOM
read, screenshot, redirect, prompt), their results in the same task log
and audit trail as any implant's.

## Campaigns

The tracked-lure delivery surface (architecture.md Sec 11.5,
[campaigns.md](campaigns.md) for the egress decisions): the email-shaped
half of delivery, beside the builds each recipient gets and the listeners
that front every lure.

**New campaign** posts the campaign whole: the name, the **front** (the
engagement's http/https listener whose public endpoint composes every
lure URL), the **relay** (host, port, TLS posture, optional credentials,
and the from address -- whose address sends this mail is the egress
decision the runbook records), the **message** (subject and body merging
`{{link}}` -- required -- `{{pixel}}`, `{{email}}`, `{{name}}`; an HTML
body without `{{pixel}}` gets the tracking pixel injected), the
**recipients** (one per line, email and optional display name), and the
**per-recipient build** essentials. Creation validates to refusal: the
server parses the build profile with the build pipeline's own parser and
refuses an unknown merge field or a body without the link at the seam,
not at delivery. The relay password never returns on read-back.

A created campaign sits in **draft** -- nothing leaves. **Launch** arms
it: the engine mints one single-use enrollment credential per recipient,
drives one build per recipient through the job queue (the price of
enrollment attribution -- a shared build could attribute the click, never
the enrollment), and sends each message once on the build's completion.
Single-attempt, no retry: a failure lands on the row with its reason, and
a retry is a new campaign.

Each roster row opens the campaign's **detail page**, where launch and
revoke sit beside what they arm or burn. The list's evidence columns
are the point: **o/c/x** counts opens, clicks, and executions. An open
is the pixel firing (best-effort -- mail clients that block remote
images never fire it), a click is the lure fetch, and an **executed**
recipient is an enrollment fact -- the implant that redeemed the baked
credential. The detail page's recipients table carries the
per-recipient arc -- status and failure, the lure link to copy, the
four stamps -- with the entity links drawn as navigation: a recipient
selected from the recon vocabulary links to its asset, and an executed
row links to the implant it enrolled. The related-entities sidebar
folds the same links into groups (the campaign's recon assets, its
implants). **Revoke** burns the campaign from any live state: no
further sends, and every lure in it 404s from that moment.

Recipients come from two vocabularies: the typed lines above, or the
**recon-asset picker** -- the roster's email-kind assets as checkboxes,
each riding the create body as a `reconAssetId` reference. A campaign
built that way is linked from its targets back: the asset's detail
page lists the campaigns that selected it and the implants they
enrolled.

## Build

The engagement's build home:
The main path is the mainstream shape: pick the **Listener (enroll +
contact)** and the **target** (OS/arch -- the Rust build unit's supported
set: Linux amd64/arm64/arm/x86, Windows amd64/x86),
leave the rest at the defaults, and build. The artifact is a
self-contained native executable with its enrollment credential
baked in -- drop it on the target and run, zero arguments. A summary
above the **Build payload** button composes from the picks live, labeled
with the fixed vocabulary: the front it enrolls on (name, transport,
public endpoint), how it contacts (envelope POSTs at the picked cadence,
a held WebSocket beacon, a held or per-contact socket connection, or the
DNS TXT carrier), and how
interactive rides (the live channel's stream, or store-and-forward over
the contacts -- the same discipline whichever wire the poll runs on).

The form's pick is the vocabulary's core role: the **enroll + contact
listener** is where the implant calls home (it registers there once and
contacts there for the rest of its life), interactive riding the same
front -- the WebSocket beacon on a web front, the held socket on a
TCP front, sealed frames under the per-artifact key, or the contacts themselves on
a poll build. Everything else -- "enroll",
"contact" in the hover texts -- names the moments inside that one
relationship.

The card's toggle switches to the tab's second artifact kind:
**Webshell script** renders a placement script with its credential baked
in, composed from two picks -- the **language** (PHP, JSP, ASPX, and
classic ASP today; the wire protocol is the same shape in every language
the list grows) and the **encryption**: the Rod family's AES-256-GCM seal
under a 256-bit key baked at generation (the default, PHP and JSP), or
the universal one-liner (the classic eval shape every manager drives,
base64 on the wire, password-gated; PHP, ASPX, and classic ASP -- whose
line is the statement-running `execute` variant, the working shape of
the family on IIS legacy). Generation is instant (no job queue): the
answer shows the credential and the script with Copy and Download, the
artifact lands in the payload store like any build, and the reachable
URL is registered under Web shells once the script is placed. The
payload library's detail row reads the credential back out of the stored
script, so "what was the key" stays answerable long after the generate
panel closed.

**Class**: there is no class pick -- the form builds the full implant
alone. The stager class is retired with the .NET trees: staged delivery
rides the Launchers surface's one-liners, which fetch the artifact over the
token-gated route and (on Linux, via the memfd family) can run it without
landing a file.

**Beacon profile**:

- **Mode** -- `stream` holds the connection open (interactive; server-push
  tasking); `poll` contacts, drains queued tasking, closes, and sleeps --
  the low-and-slow shape. Both modes carry interactive: live over the
  held stream, or store-and-forward over the contacts at the cadence
  below.
- **Contact every / Randomize ±** -- the call-home cadence and the random
  slack added to every interval so contacts are not clockwork. Defaults
  30 s / 10 s.
- **Max uses** -- how many hosts the baked credential may enroll: one spend
  per host, so one executable can seed several machines until the budget runs
  out. `0` = unlimited. Default 1.

**TLS trust is not a build knob**: which roots the artifact's TLS dials
trust is the picked front's fact, set as the listener's **Certificate**
(the engagement CA terminates a `pinned` front -- the default, and it
works for any domain you point at the listener, since the CA mints the
front's leaf for that host; `public` marks a real-domain front whose
certificate an operator-run edge terminates -- the shape that survives
TLS inspection). The build inherits the posture, the pre-build summary's
`tls` line names it, and the fallback offer stays inside it:
the artifact bakes one root set, so a TLS front presenting the other
certificate is a dial the walk cannot verify.

**Advanced** (all defaulted server side; open only to change them):

- **Public endpoint (enroll + contact, manual)** -- the dial address
  when you deliberately build without naming a listener.
- **Fallback public endpoints** -- backup enroll + contact addresses
  baked in behind the primary and dialed in order when it burns; they
  share the enroll path and the fixed contact route.
- **Enroll path** -- the URI path of the one-time registration POST. The
  only path knob: contacts ride the fixed `/implants/beacon` route and the
  held beacon its own fixed stream route, so no other path exists to set.
  Change it only when a redirector rewrites to the real route. Default
  `/implants/enroll`.
- **User agent** -- the `User-Agent` the implant presents, to blend with a
  known-good client. Empty leaves the HTTP client's default.
- **Request timeout (s)** -- per-request HTTP timeout. Default 30.
- **Enroll body** -- shapes the ENROLL request body only (the "envelope"
  word elsewhere -- the POST contact shape -- is a different thing).
  `AES-GCM` (the default) encrypts it under a
  per-artifact key minted at build, so the body stays opaque even where
  TLS terminates early (a redirector, a fronting CDN) or on cleartext
  `http` -- the same default posture contacts already carry. On direct
  `https` it is redundant -- TLS already encrypts the channel.
  `None` sends the raw JSON body, the lab-debug shape; `Base64` wraps it
  as one string so the body does not read as structured C2.
- **Kill date** -- the artifact's optional fuse. Past it the executable stops
  being usable: a leftover copy refuses to run, and a live implant terminates
  at its next contact. Empty = no fuse: the implant runs until retired -- the
  long-haul default. A pinned date also bounds the baked credential's window
  unless *Valid for* overrides it. The implant reports its baked date at
  enroll, so the fleet's Kill date column shows the artifact's own fuse
  (a dash for open-ended builds).
- **Valid for (h)** -- how long the baked credential can enroll **new**
  implants. Pairs with *Max uses*: that caps how many enrolls, this caps for
  how long. Empty = until the kill date, or a 30-day drop window when there
  is none (an open-ended implant is no reason to leave a dropped credential
  redeemable for years). Enrollment is permanent: an implant that enrolled
  keeps contacting for the rest of its life whatever this window does --
  the window (and the use budget) gate only copies of the binary that have
  not enrolled yet.

**Recent builds** is the job queue's status strip: builds run as background
jobs, the strip polls while anything runs, and it shows the last five -- enough
to watch the running build and grab the artifact you just made. Each finished
row carries its artifact, its baked token (revoke it there), the front it dials
(the listener name when the endpoint matches one), and the download -- or a
"deleted" note once the artifact is removed from the library, because a job row
outlives the payload it produced. The queue itself is bounded (50 finished jobs
per engagement) and lives for the process lifetime; the record of every
artifact that ever finished is the Payloads library, so the two do not try to be
each other.

## Payloads

The durable library and the record of every build: every payload the
engagement ever built, straight from the payload store -- restart-safe,
unbounded by the build queue. Filter by class, language, target, listener,
or fingerprint. Each row names the **Listener** it dials (the engagement
listener's name, transport, and address when the baked endpoint matches
one; the bare address with a "manual" tag when it was typed for a
redirector this server does not serve) and shows the **Credential**
column -- the baked token's use budget read live off the token store at
list time: how many enrolls were spent out of the minted maximum, how many
are left (a zero budget reads "unlimited"), and the window (an expired or revoked credential reads "no
enrolls left"; on the in-memory dev store a fully spent token reads the
same, because the store drops it at zero).
The row's chevron unfolds the **build parameters** snapshotted at bake
time: mode, contact cadence and jitter, kill date, the credential's
minted shape, enroll path, user agent, request timeout, enroll-body
envelope, contact protection, and fallback fronts -- so "what did I build" never depends on
remembering the form.
**Download** the bytes again, **Revoke** to kill the baked credential (a
deployed artifact that has not yet enrolled will not be able to), or
**Delete** the payload -- the bytes and the row are gone, a launcher
fetching it 404s from then on, and the deletion is an audited fact.
Beside the filter, **Mint credential** mints a standalone delivery
credential -- the same token shape a build bakes, without a payload
attached, for hand delivery: the launcher one-liners aimed at an
operator-run edge, a drop, a scripted enrollment. The dialog's knobs are
the route's bounds in operator units (uses 1-10000, lifetime up to 30
days; the defaults are the single-use one-hour shape), the mint is
audited without the secret, and the secret reads out exactly once in the
dialog that minted it -- copy it before closing. A standalone token has
no payload row, so its revoke rides the same dialog.

## Shells

The engagement's caught reverse shells: every no-protocol connection a
shellcatch listener accepted, with its status, remote address, and
last-output stamp. Selecting a row opens the console -- scrolled into view
with the row that opened it, so a long roster never hides the panel below
the fold -- a real terminal
emulator (xterm) wired straight to the held connection: keystrokes ride
the input route as typed (Enter, ^C, and paste are the shell's line
discipline's to interpret -- there is no form), output renders with its
colors and cursor addressing, and full-screen programs (vim, top) work
when the caught shell runs under a pty -- the python-pty and socat catch
shapes size one
and name its type before the shell runs (stty 120x30, TERM
xterm-256color; the console starts at that fixed geometry, since the catch
socket carries no resize channel), the plain shapes have none. **Sync
size** re-points that geometry after the window moves: it fits the
emulator to the card and hands the target the same rows/cols over the
input route, so full-screen programs redraw at the width the operator
sees (a pty-less shell answers it with a harmless stty error). The typing half is
claim-aware (see
[Interaction ownership](#interaction-ownership)). Typing lands where the
surface's inset frame sits: click the surface to focus, and the clipboard
rides Ctrl+Shift+C / Ctrl+Shift+V (the Insert pair works too; native
Ctrl+V pastes) while Ctrl+C stays the interrupt a terminal expects.
Two header controls answer the plain shapes and the odd code page:
**Local echo** writes the operator's own strikes to the emulator (caret
notation for control bytes) for a pty-less shell that never echoes -- off
by default, since a pty shell echoes itself and a second echo doubles
every character -- and the encoding selector repoints the session's codec
(UTF-8 default; GBK for a cmd.exe box on a legacy Chinese code page), both
directions at once.
**Disconnect** ends a
live shell from the row or the console (two clicks from the row): the
socket closes, the target-side one-liner exits with it, and the row's
status settles -- an ended row keeps its readable transcript until
dismissed.

**Upgrade** renders the same paste-ready launchers the Launchers surface cuts
(the fetch one-liners that grow the shell into an enrolled implant), with
the same picks: which build the fetch delivers -- a payload whose baked
enrollment credential is dead cannot enroll the beacon it downloads, so
those entries refuse, and with no deliverable build at all the button
says so instead of letting the paste discover it -- and which front
serves the fetch.

## Web shells

The operating side of the web-shell builds: the roster of scripts placed
in targets' web roots, bound to the engagement by registration. A
web-shell never enrolls; execution is synchronous and every line lands
on the task log like any other tasking. The scripts themselves generate
under Build (that tab's Webshell script half).

Registering takes the reachable URL plus the family and credential,
either way: **claim a generated script** -- picked from the engagement's
WebShell-class payloads, the family and baked key coming from the stored
script so the key never travels through the operator's clipboard -- or
enter the family and credential by hand: the sealed Rod shapes (PHP,
JSP) or the universal eval one-liners (PHP, ASPX, classic ASP), an empty
credential minting a fresh one. When the register call mints a script it
answers with the paste-ready one-liner and its credential. Each row
shows the URL, adapter, credential, last probe (ok or failed, with its
stamp), and status. **Test** probes the endpoint, **Remove** unregisters
it, and **Console** opens the line-oriented runner: each submitted line
is one synchronous execution whose output appends to a local transcript
-- a web-shell has no live stream, and the task log carries the durable
history.

## Home

The dashboard at `#/` -- the console's landing route, reached by the bare
hash, the topbar's Home entry, and the sidebar's brand mark. One orienting
page composed over every engagement the operator can reach (the roster plus
the same per-engagement implant, task, and loot reads the engagement views
make; there is no cross-engagement aggregate endpoint, and the composition
keeps the dashboard inside the engagement-scoped surface the server
enforces).

An attention strip opens the page when anything outranks the numbers:
active implants past their baked kill date (danger) or hitting one within
7 days (warn, linking to the affected engagement's fleet), open engagements
with no implants (no foothold yet), and open engagements idle 7 days or
longer. It renders nothing when there is nothing to flag.

Five posture cards follow: the engagement mix (open, frozen, retired), the
fleet's live posture (sessions over active implants, with the host count),
tasking volume over the last 14 days with its failure count and a daily
mini-trend, loot captured across engagements (count and bytes), and the
fleet's newest check-in. Below them: a stacked daily activity chart over
the same 14-day window (completed, open, cancelled, failed), fleet growth
(cumulative enrolled implants with the per-day enrollment bars), the
operating rhythm (weekday x hour task density, local timezone), the active
fleet split by OS family, the window's top task verbs, a per-engagement
fleet table (fleet bar, online/active, windowed task count, last tasking
age; every row links into its engagement, sealed records read from the
roster's own summary), and the newest tasking across engagements -- each
row linking into that engagement's task log.

Every windowed read takes the listing's newest page (200 items, the page
cap), so an engagement with more history than the cap undercounts its
oldest days -- the dashboard is an operating overview, not a ledger.
Retired records are sealed: they count toward the engagement-mix card
only. Roster changes (create, close-out) re-read the page on the spot.

## Engagements

The full roster: every engagement the operator can reach, created and
edited here, with the close-out arc on the row. The count chips above the
table size the close-out pipeline at a glance (open, frozen, retired) and
the deployment's live posture beside it (online/active implants across
every engagement); the table's **Fleet** column sizes each engagement the
same way -- live sessions over active (non-retired) implants, the green
dot marking one that still has implants breathing. Outside an engagement
the sidebar carries a recent-engagements quick-jump
(newest first, sealed records excluded; the roster is the full account).
Create takes a name and
an optional description; **Edit** reworks the working record (name and
description -- a retired record is sealed, its editing refused). The
status chip reads open, frozen, or retired, and drilling in hands off to
the engagement's detail view with the full capability surface. The row
actions drive the close-out: **Freeze** stops new tasking, enrollments,
and token mints (in-flight results still land; a mistaken freeze
reverses with **Unfreeze**), **Export evidence** downloads the close-out
ZIP (audit trail, artifacts, report, manifest), and **Retire** is the
terminal step, refused until frozen -- a close-out, not an erasure: the
evidence stays readable while the record stops serving.

## Settings

`#/settings`, from the topbar's settings entry -- the page opens straight
on **Account**, so the personal surface stays one click from anywhere.
The page is a tab strip (the same toggle
shape the engagement build page's implant/webshell pick uses), so a long
member roster can never push the other sections off-screen. The
**Account** and **Console** tabs are every operator's own surface, while
the **Members** and **Runtime** tabs render for the deployment admin
alone -- a member's settings page is purely personal, and the server
draws the same line (a member's roster read refuses with 403).

The admin's **Members** tab is the account
roster and its management sheet (the management path the
`Operators:Initial` seed stood in for; see [teamserver.md](teamserver.md)).
The table lists
every account: handle (yours marked *you*; admins marked *admin*; a
switched-off account reads *disabled*; a revoked credential reads *no
password*) and creation date. Reach arrives per engagement, from each
engagement's Members panel, and every account comes up a deployment
member: the admin provisions with *New operator* (handle and an initial
password of at least 8 characters, handed over out of band) and holds
the *Disable* / *Enable* pair -- the account off switch (two clicks):
every authentication path -- login, live cookie session, API token --
refuses at its next use, while the memberships wait as they were, so
*Enable* restores exactly the reach the account had; the last enabled
account, or the last enabled admin, cannot be disabled (the 409 names
the rule), and disabling yourself ends your own session with no way back
alone. *Reset password* takes just the new password on another
operator's row; on the admin's own row it asks for the current password
first, because a change on your own account is self-service and proves
possession. *Manage* opens the row's **API tokens** shelf (mint with the
one-time secret beside a copy button, list, revoke).

Next comes the admin's **Runtime** tab -- server-wide, live on save, remembered
across restarts. Session presence explains the fleet's offline behavior
and adjusts it live: *Offline after* is how long a silent session holds
its Online dot before the staleness sweep closes it (1 minute..24 hours;
keep it above your implants' contact interval or every quiet gap flaps
offline), *Sweep every* is how often the check runs (10 seconds..1
hour). Saving applies on the next sweep pass -- no restart -- and the
server persists the pair (`RuntimeSettings:FilePath`, default
`runtime-settings.json` beside the server) so a restart remembers them;
the `Sessions:Staleness` config section remains the boot default. Bounds
violations refuse with the reason rather than clamping. The build cache
is the shared cargo target dir payload builds compile against: a
persistent directory turns a cold cross-compile into a one-time cost
(dependency artifacts are reused; concurrent builds queue on cargo's own
lock), empty keeps builds hermetic, and the boot default is the
`ROD_RUST_TARGET_DIR` variable. Applies to the next build, remembered
across restarts.

**Account** is the signed-in operator's own surface, the page's default
tab and the same card for
admin and member: identity at a glance (avatar, handle, role, creation
date), *Change password* (current password, new, confirm -- the current
one is verified server-side, and the change ends this session at its
next request, so the console walks back to the login view), and this
account's **API tokens** shelf -- password and tokens are self-service;
the admin never needs to stand in. The **Console** tab is this
browser's own preferences, kept in localStorage and never sent to the
server. One knob is the refresh cadence -- how often presence-style
surfaces (the redirector roster, the engagement view's fallback refresh,
the shell roster) re-read while their tab is visible; build progress
keeps its own faster cadence because it is task progress, not
presence. The other is the table density (comfortable or compact) --
its toggle rides the topbar where it is used; the Console tab records
the standing choice. Saves re-arm running timers on the spot.

## Members

Each engagement's `#/engagements/{id}/admin/members` surface -- the crew roster
that decides reach (architecture.md Sec 3). The table lists the owner
first (access by creation: writes plus grant management) beside every
member with their tier and grant date: a **writer** acts (tasking,
listeners, closeout, deploy-token minting), a **reader** watches (every
read and the live stream; the server refuses writes with 403). Grant
management is the owner's alone: *Invite an operator* takes a handle and
the tier being granted, and member rows offer *Make reader/writer*
re-tiering (effective on the member's next request) and *Remove* (from
its next request on, the engagement is invisible to that operator
again). The owner cannot be removed or re-tiered. Every grant, re-tier,
and removal lands in the engagement's own audit trail, and the landing
roster's *You* column names your tier on each engagement you can see --
a row there always means you hold one.

## Redirectors

`#/redirectors`, from the topbar -- the deployment's forwarding fleet
(architecture.md Sec 8), deployment-scoped like the System page: no
engagement in the route, because a node is machine capacity and scope
arrives per front at the listener it attaches to. **Fleet** is the roster:
each enrolled node with its live status (the control connection itself --
*online* while connected, *offline* with the last-contact age when not),
its self-reported build (the same version/commit pair the binary prints,
so fleet provenance reads off the node), its address and enrollment age.
*Retire* (two clicks) takes a node out of the deployment: the live control
session closes and the next reconnect is refused by name. The roster and
the ledger read for every operator; the writes -- retire, mint, revoke --
are the deployment admin's, and a member sees the read-only note instead
of the forms. **Enrollment
credentials** pre-provision new nodes: *Mint* takes the node's roster name
and an optional lifetime (default a day) and shows the secret exactly
once, rendered inside the complete node invocation -- the control URL
derived from this console's own address and TLS posture (wss behind
HTTPS, ws otherwise) plus the runbook's state path -- with copy buttons
for the whole command and the bare secret. Only its digest is stored, the
credential is single-use, and pasting the command on the machine is the
whole enrollment. The ledger names each credential's state (unused, enrolled --
with the node it minted, expired, revoked); *Revoke* (two clicks) makes an
unused credential permanently unusable. The attach/detach/promote half --
where nodes meet engagements -- lives in each engagement's
[Listeners](#listeners) surface (a membership question, not a deployment
one); the runbook walks the whole flow
([redirectors.md](redirectors.md), Sec 0).

## System

`#/system`, from the topbar's system entry -- the deployment's preflight.
**Server** names the host facts (machine, OS, .NET runtime, uptime);
**Persistence** names the adapter each store runs on and where the data
lives -- the configured data directory, or the Postgres target with its
credentials masked (a composition choice made at startup through
`ConnectionStrings:Postgres`, not a runtime knob).
**Build units** is each unit's self-reported environment: the findings
list covers cargo and rustc (versioned when found, with the install fix
when not), the Rust source tree and the teamserver proto tree the build
copies, and the cargo target cache (a `ROD_RUST_TARGET_DIR` warning names
the hermetic cold-build cost); the target table reads one row per
buildable triple -- Rust std installed (`rustup target add <triple>` is
the fix shown inline) and the cross linker its platform pieces need on
PATH. A unit reports *ready*, *partial* (some targets unbuildable), or
*unavailable* (a missing prerequisite: toolchain, source, or proto) --
the same failures a build job would surface minutes later, read here in
one glance before the first build is ever queued.

## Evidence panels

- **Audit ledger** (under the Report slot) -- the append-only, hash-chained
  ledger; tampering with a stored event breaks the chain at the next link.
  Paged and filterable; the raw feed the report renders from. Its second
  reading mode is the handoff digest (see
  [Handoff digest](#handoff-digest)) -- the windowed watch-resume read
  of the same trail. The watch's live read of it is the
  [timeline](#timeline--the-overview-main-screen) on the overview slot;
  the narrative rendering lives as the Report's timeline section, and
  the standalone `/timeline` endpoint stays a scripting deliverable.
- **Report** -- the whole engagement as a reproducible JSON/Markdown export,
  timeline included. (The Artifacts tab retired: evidence objects -- file
  pulls, exfil chunks, the operator-side attach -- surface in the task
  log's expanded rows, where the task they document already lives.)

## Deferred work

Design decisions recorded for later rounds; nothing here is built yet.

### The split-socket contact front (removed)

A build once could name a second front for its steady-state contacts
(enroll on one listener, the beacon on another). It was removed: every
front serves its own contact cycle, the fallback walk already covers the
burned-front case inside one protocol family, and the pairing rules the
split required (scheme families, certificate postures) were the most
complicated corner of the build form for a shape no deployment needed. A
build dials one protocol -- its front's -- and the contact derives from
it. Reintroducing a split would need the whole chain again: request
fields, parser gates, a baked second dial, and walk semantics for
entries the baked carriage cannot serve.

### Runtime kill-date changes

The kill date is build-time only today: an optional fuse baked into the
artifact, reported at enroll, enforced on both sides. Retire covers the
"stop this implant now" need for a reachable implant, and the open-ended
default (empty = no fuse) already covers long-haul control -- so the case
for changing the fuse on a fielded implant is narrow: tightening it as a
scheduled fail-safe, or extending one whose window is closing. The honest
shape, if ever needed, is operator-controlled like retire: a row action
sets the new date, the server records it (so its handshake gate agrees),
and the change rides the next contact as tasking the implant applies to
its own fuse -- beacon.sleep's cadence control is the template.

## Comments, chat, and task references

**Comments** are the engagement's mutable process knowledge: free text an
operator attaches to a task (the task log's expanded row), an implant
(the session console), an artifact (the loot board's rows), the
engagement itself (the Members surface), or an operator (the member rows).
The author may edit or delete within the deployment's edit window
(`Collaboration:CommentEditWindowMinutes`, default one day); after that
the comment is read-only until the engagement ends. Comments ride the
timeline and the live stream as ordinary, explicitly mutable events and
never enter the hash-chained audit trail -- process knowledge and
evidence are different things, and the console keeps them apart.

**Chat** is the watch's room: the Chat toggle in the engagement's lower
right opens a docked panel with the engagement's channels -- `general`
exists from the first read -- where messages are append-only (a
correction is a new message). Chat rides the timeline beside comments,
never the chain.

**Task references** work wherever operators type: `@task-<id>` links a
task, `$cred-<id>` addresses a harvested credential row (the credentials
board carries each row's id). In comments and chat the server validates
every well-formed token at publish -- a dangling reference is refused
with the offender named -- and the placeholder stays a placeholder. In
task input the validation runs at issuance and the substitution runs on
the dispatch wire alone: the task row, the live stream, and the audit
trail carry the placeholder form, the implant alone receives the secret,
so the plaintext never lands in a store.
