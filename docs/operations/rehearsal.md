# Rehearsal engagement -- the pre-deployment walk

Operational runbook for the rehearsal every deployment gets before it faces
a client network: one full engagement lifecycle on production-shaped
infrastructure -- an externally provisioned CA, Postgres persistence,
redirector fronts with a burn and repoint, a mid-engagement crash with
audit-chain recovery, a mid-engagement CA rotation, a teardown to
report, and the dated surface refresh legs of Sec 7
([architecture.md](../architecture.md) Sec 8, Sec 9, Sec 12.1).

This record was executed 2026-10-09 against the settled four-family
surface (architecture.md Sec 8): the Https one-port listener carrying the
envelope poll and the WebSocket beacon, the raw-TCP front, the DNS/DoH
fronts, engagement-scoped listeners, and pipeline-built Rust payloads.
Every command below is real and ran on one Linux host (WSL); the acceptance
evidence quoted is what that run produced. The multi-host Windows leg
(Sec 5) is the dated record of its own execution, folded in here like
every other leg. Scale the addresses to the engagement's real
infrastructure; the lifecycle steps do not change.

The walk exists because composed-system defects are invisible to slices.
This run caught two (fixed in the commits that record this walk):

- Every DoH listener with a bind host different from its zone name baked
  an artifact that could never enroll: the listener's TLS leaf named the
  zone in its SAN while the bake dials the bind as the resolver, so the
  implant's rustls client failed name validation at the first handshake.
  The leaf now names what the dial actually addresses.
- A restart restored the socket-owning listeners (TCP, DNS) but silently
  skipped every Kestrel-riding one (Https, DoH) -- the restore probed the
  published endpoints before the web host existed, timed out, and
  withdrew endpoints that were about to bind ("Restored 2 of 4", the web
  pair down after every restart). The restore now runs once the host's
  own listeners are bound.

## 1. Provision the infrastructure

### The engagement CA (out of band)

The teamserver never generates the production CA
([architecture.md](../architecture.md) Sec 9); provision one with the
operator PKI tooling and hand the teamserver the PEM files:

```
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout ca.key -out ca.crt -days 3650 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -subj "/O=Rod Rehearsal/CN=Rod Rehearsal Engagement CA"
```

RSA is the only supported CA key type; keep the key off the teamserver
host if the signing posture demands it (only the signing path needs it --
rotation is file replacement plus restart, Sec 6).

### Postgres

Stand up a PostgreSQL instance and apply the schema once per deployment:

```
createdb rod_rehearsal
dotnet ef database update \
  -p src/teamserver/Rod.Persistence -s src/teamserver/Rod.TeamServer \
  --connection "Host=<host>;Port=<port>;Username=<user>;Database=rod_rehearsal"
```

### The redirectors

Build and deploy the reference L4 forwarder per
[redirectors.md](redirectors.md) -- one process per front. The forwarder
splices TCP, so it fronts every TCP-carried front: the Https one-port
listener, the raw-TCP listener, and DoH. A plain UDP DNS front cannot
ride it -- serve the DNS listener direct from the teamserver host or put
datagram fronting in front of it deliberately; the reference redirector
has no UDP story by design.

```
dotnet publish src/redirector/Rod.Redirector.csproj -r linux-x64 -c Release
rod-redirector -listen <front-a>:443 -upstream <teamserver-https-bind>
rod-redirector -listen <front-b>:443 -upstream <teamserver-https-bind>
```

## 2. Start the teamserver

Startup configuration names the operator front only -- the shared tier
carrying the UI and API with no implant ingress. Implant-facing listeners
are engagement-scoped, created through the operator API in Sec 3, and
persist across restarts (a restart rebinds them with the same ids).

```
export Pki__CaCertificatePath=/path/ca.crt
export Pki__CaPrivateKeyPath=/path/ca.key
export ConnectionStrings__Postgres='Host=<host>;Port=<port>;Username=<user>;Password=<pass>;Database=rod'
export Audit__DataDirectory=/path/engagement-data
export Operators__Initial__Handle=lead Operators__Initial__Password=...
dotnet run --project src/teamserver/Rod.TeamServer
```

Startup fails loudly on a missing CA file, an unreachable database, or a
misconfigured listener -- that is the acceptance for step zero.

## 3. Walk the lifecycle

Every step below runs over the operator API (`/operators/login` first;
the session cookie rides every later call).

1. **Open the engagement**: `POST /engagements`.

2. **Create the engagement's listeners**
   (`POST /engagements/{id}/listeners`), one per family the engagement
   needs. The rehearsal shape, all four:

   | Name | Transport | Bind | Public endpoint |
   |------|-----------|------|-----------------|
   | `https-front` | `https` | `127.0.0.1:9443` | `https://<front-a>` (the redirector; blank derives the bind itself) |
   | `tcp-front` | `tcp` | `127.0.0.1:9543` | `<tcp-front-host>:<port>` |
   | `dns-front` | `dns` | `127.0.0.1:5300` (UDP) | the zone, e.g. `c2.rehearsal.test` |
   | `doh-front` | `doh` | `127.0.0.1:8484` | the zone |

   The bind is the socket this server opens; the public endpoint is what
   implants dial. The web family derives a complete endpoint from the
   bind; the zone and host:port shapes must be spelled out. A wildcard
   bind names no dialable address and is refused with a blank endpoint.

3. **Build the payloads** (`POST /engagements/{id}/payloads`), each
   naming the engagement's listener (the baked endpoint comes from the
   listener's record) and minting-baking its enrollment credential --
   the artifact deploys with zero run-time arguments. One build per
   shape the engagement flies; the rehearsal built five, `mode: poll`
   and `mode: stream` against the Https front (the envelope POST cycle
   and the WebSocket beacon), `stream` against the raw-TCP front, `poll`
   against the DNS and DoH fronts:

   ```json
   {"language":"Rust","class":"Implant","targetOs":"linux","targetArch":"amd64",
    "listenerId":"<id>","mode":"poll","sleepSeconds":5,"jitterSeconds":2,
    "killDate":"2026-10-15T00:00:00Z",
    "fallbackEndpoints":["https://<front-b>"]}
   ```

   A DNS-family bake dials the listener's own bind as the resolver, so
   on DoH the bind host is the name the implant verifies the leaf
   against -- an IP bind bakes an IP dial and the leaf covers it.

4. **Render the launchers** (`POST /engagements/{id}/launchers` with the
   payload id): the paste-ready one-liner per shell family -- the disk
   pair (curl, wget) and the Linux in-memory memfd family -- each
   fetching the payload over the engagement's web front under a freshly
   minted download credential whose budget (max uses, lifetime) the
   render sets. Every render is kept as a row: re-copy it while the
   credential lives, watch its budget spend, revoke or delete it from
   the same list.

5. **Deploy**: paste the family that fits the target. The one-liner
   fetch carries its own verification bypass (no stock downloader trusts
   the engagement CA; the credential gates the fetch, and the
   enrollment that follows does the pinning), and the fetched artifact's
   first contact pins the CA. Verify the fetch against the build's
   fingerprint before it runs:

   ```
   sha256sum /tmp/.rod-payload   # == the payload row's fingerprint
   ```

   The artifact enrolls through the front it was built against and
   appears on the roster (`GET /engagements/{id}/implants`). The
   rehearsal deployed all five: the Https poll implant through the
   in-memory memfd one-liner (no disk file), the rest through curl. The
   DNS implant enrolled on its first poll cycle; the DoH implant's
   chunked enroll exchange rode its poll cadence (~80 s at sleep 5).

6. **Task and collect**: issue verbs over
   `POST /engagements/{id}/tasks`; results land on the task and in the
   audit trail. The rehearsal round-tripped `shell.exec` over the
   envelope, DNS, and DoH carriers, `fs.list` over the WebSocket beacon,
   and bulk collection over the raw-TCP stream: a 2 MiB `file.pull`
   streamed as 4 chunks into the artifact store, and the downloaded
   artifact's sha256 matched the source exactly. Interactive shells ride
   the live streams: `shell.interact` opens the channel, operator input
   posts to `POST /tasks/{id}/input` (base64 bytes, `eof` closes), and
   the task completes with the whole transcript -- verified over both
   the WebSocket beacon and the raw-TCP carriage.

7. **Crash and recover**: kill the teamserver mid-engagement (the fronts
   keep listening; the implants' contact loops retry), restart it.
   Accept: the listeners rebind from their persisted definitions with
   the same ids; the implants return to the roster unattended (the
   stream implants after their reconnect backoff); the audit trail
   reloads with the pre-crash hash chain byte-identical (the report's
   integrity digest is unchanged); artifacts remain retrievable
   byte-exact; the operator cookie survives (the data-protection keys
   and the credential store are durable).

8. **Burn a front**: stop the primary redirector. The implant's contacts
   fail and the baked egress walk advances to the fallback front -- it
   returns to the roster with no operator action. Then repoint the
   listener
   (`POST /engagements/{engagementId}/listeners/{id}:repoint` with the
   fallback front) so the server-side record names the live front and
   the burned one is severed. No backend restart, no bind change. Verify
   the burn before assuming it: probe the front's port, not the wrapper
   process's pid -- a `nohup` wrapper can die while the forwarder lives.

9. **Tear down to report**: retire each implant
   (`POST /engagements/{id}/implants/{implantId}:retire` -- its session
   closes), stop the fronts, export the report
   (`GET /engagements/{id}/report?format=markdown`), and decommission
   the infrastructure. The data directory and the report are the
   evidence that outlives the teardown.

## Acceptance evidence from the walk (2026-10-09)

- Five pipeline builds (Rust, linux amd64), 2,392,816 bytes each with
  distinct fingerprints and baked credentials; four curl fetches whose
  sha256 matched the build fingerprints exactly, one memfd deployment
  with no disk artifact.
- Enrollment on every family: the envelope POST cycle and the WebSocket
  beacon on the Https front, the raw-TCP opening exchange, the DNS
  chunked enroll, and the DoH enroll (after the leaf-SAN fix below).
- Tasking on every carrier: `shell.exec` over envelope, DNS, and DoH;
  `fs.list` over the beacon; a 2 MiB `file.pull` over raw-TCP stream as
  4 chunks, artifact sha256 `18e5344e…` byte-exact on download;
  interactive `shell.interact` transcripts over both live streams.
- `kill -9` mid-engagement followed by restart: 4 of 4 listeners
  rebind; 5 of 5 implants return unattended; the pre-crash 60-event
  hash-chain prefix reloads byte-identical (report integrity digest
  `265159A9…` unchanged); the exfil artifact returns its exact bytes;
  the operator session stays valid; a post-crash task completes.
- Burning the primary front (kill, port probed dead) moved the fronted
  implant to its baked fallback with no operator action; the repoint
  swapped the listener's public endpoint at runtime (`repointedAt`
  stamped, bind untouched); the next task round-tripped through the new
  front.

## 4. The composed shape

The single-host walk stands the fronts in on loopback; the composed
deployment differs by address substitution and two TLS rules
([redirectors.md](redirectors.md) Sec 6):

- The Https one-port front presents the engagement-CA leaf (its SAN
  names the host implants dial -- the public endpoint's host for the web
  family, the bind's host for DoH). An edge in front of it either
  switches at L4 (SNI, no termination) or terminates with a real-domain
  certificate on a listener whose trust posture is `public`; the implant
  then validates the real chain instead of the engagement CA.
- The raw-TCP and UDP DNS fronts carry no TLS anywhere -- the
  per-artifact key sealing the bodies is the identity, so an L4 front
  is transparent by construction and a terminating hop buys nothing.

## 5. The Windows leg (dated 2026-09-23)

The Rust reference implant verified on a real Windows host (Windows 11
24H2, x64, on the lab's VMware guest) against a teamserver on the Linux
build host, both artifacts pipeline-built through the operator API --
the leg that cannot run from Linux. Two builds: an http-front poll
implant and a tcp-front stream implant, minted credentials baked, zero
run-time arguments. What ran, and what it produced:

- **Enrollment both ways.** The poll implant enrolled over the envelope
  POST cycle (http front) and the stream implant over the raw-TCP
  carriage's opening exchange -- the socket family's enroll arm on real
  Windows, not the Linux e2e's subprocess shape.
- **The core surface.** `shell.exec` (whoami), `fs.list` (full NTFS home
  listing), `file.push` + `file.pull` (a 25-byte file round-tripped
  byte-exact), `proc.kill` (a spawned notepad terminated by pid).
- **The sensitive four.** `inject.shellcode` injected a 3-byte `ret`
  stub into a live notepad and reported the remote thread completing --
  the VirtualAllocEx/WriteProcessMemory/CreateRemoteThread path end to
  end. `collect.keylog` started, drained, and stopped (an SSH
  session-0 implant captures nothing, correctly: no interactive desktop
  feeds it). `collect.minidump` ran its full argument and
  process-resolution path and was refused at the privilege boundary --
  an unelevated implant cannot OpenProcess lsass -- which is the
  designed refusal, not a defect.
- **The channel verbs over the raw-TCP carriage.** `shell.interact`
  opened the pipes-backed cmd, answered `whoami` through the
  ChannelInput/ChannelOutput frames on the live stream. `tunnel.forward`
  relayed through the implant back to the build host: a relay-bound
  local port fetched a probe file through the Windows socket pump, both
  hops verified.

The plugin seam's Windows leg (`module.load`'s manual PE map,
architecture.md Sec 5.4) ran 2026-10-11 on the same guest against the dev
teamserver shape the browser leg below uses: a fresh engagement, one http
listener direct, its public endpoint repointed through an SSH reverse
tunnel (the lab's WSL host is not routable from the VMware segment, so the
guest dials a loopback forward back into the build host). The reference
hostenum module built for `x86_64-pc-windows-gnu` (1,210,712 bytes,
sha256 `4d4355ed…`) rode the load task's staged content, and the
round-trip the criterion names completed: `module.load` answered
"module hostenum loaded: recon.hostenum; advertised at the next
contact", `module.list` reported `hostenum: recon.hostenum`, the tasked
verb answered the full finding (host `PENETRATION`, os windows, arch
x86_64, user, path), `module.unload` retracted it, and a second
`recon.hostenum` completed with outcome `Failed` and the refusal "this
build carries no handler for the verb" -- the grammar named afterward,
the same acceptance the Linux module drill verified. Every task's audit
arc read `TaskIssued → TaskDispatched → TaskCompleted`, the load task's
with `ArtifactAttached` carrying the module's sha256 beside them. The
teardown followed the standing shape: implant retired, report exported,
engagement frozen and retired.

Two mapper defects, exactly the ones this leg exists to catch: the PE
mapper's code paths are `cfg(windows)`-gated, so the Linux suite compiles
them but never executes them, and both sat in code no unit test ran.

- The relocation walker read each block's first dword -- the page RVA --
  as the block's size, so every real image (whose page RVAs dwarf the
  directory) read as `malformed relocation table`, and the entry offsets
  resolved against the block itself instead of the covered page. Fixed
  to the documented block layout (page RVA at +0, size at +4, entries
  page-relative), with a unit test pinning the walk under
  `cfg(windows)`.
- The TLS setup reduced the directory's address fields against the
  preferred image base and rebased them again -- a double translation
  that walked off the image whenever the allocation did not land on the
  preferred base (always, under ASLR), and the crash landed in the CRT's
  copy. Fixed to dereference the fields as the live pointers relocation
  left them. The isolation harness that pinned the fix -- a ctypes
  reproduction of the mapper's stages run on the guest, against the same
  dll bytes -- walks allocate, copy, relocate, imports, TLS, DllMain,
  and the export family green, and the module round-trip above is the
  fixed artifact's evidence.

Two adversarial observations from that run, now operator guidance:

- A pipeline win-x64 build defect the Linux legs cannot see: the unit
  picked the `.exe` suffix by `triple.StartsWith("windows")`, and the
  Windows cargo triples begin with the arch (`x86_64-pc-windows-gnu`),
  so a successful compile read as a missing artifact. Fixed with the
  OS-segment test; the regression test drives a real win-x64 build.
- A `start /b` shell.exec blocks the poll queue head on Windows (the
  child inherits the pipe, the task never completes, later tasks queue
  behind it) -- the Windows twin of the pipe semantics the Linux legs
  already know. Spawn through `powershell Start-Process` instead.
- Platform facts to plan around: an onlogon-trigger schtasks install
  and `schtasks /s` remote execution require an elevated implant;
  runkey, the recon set, and the file/shell surface work per-user; the
  service mechanism fails cleanly with access denied when unelevated.
- An SSH-spawned process on the guest dies with the session: Windows
  OpenSSH kills its whole job object when a session closes, so an
  implant launched through `Start-Process` vanished silently seconds
  after the deploying channel exited -- enrolled, then gone, with no
  refusal, no task, and no audit fact. Hold the launching channel open
  for the leg's duration (a foreground `cmd /c` on one long-lived SSH
  session) or schedule the artifact outside the session; the module leg
  above used the held-channel shape.

Cleanup verified on the guest: implant processes killed, artifacts and
the pushed file removed.

## 6. Rotate the engagement CA mid-engagement

Rotation is file replacement plus restart (Sec 1) -- what that does to a
live engagement only shows when executed against one. The drill runs on
the installed shape with tasking current: implants contacting, then the
swap, then the re-entry ([architecture.md](../architecture.md) Sec 9).

1. Mint the successor CA with the Sec 1 command, with a fresh subject so
   logs distinguish the two CAs.
2. Swap and restart -- the successor lands under the installed paths
   `appsettings.Production.json` already names, and the restart is the
   cut point:

   ```
   sudo cp ca2.crt /etc/rod/pki/ca.crt
   sudo cp ca2.key /etc/rod/pki/ca.key
   sudo systemctl restart rod-teamserver
   ```

3. Re-enter the fleet: build a fresh payload (the build bakes the
   successor CA as the pin the artifact's first contact validates
   against -- pre-rotation artifacts pin the incumbent and cannot come
   back), render a launcher for it, and paste the one-liner where
   presence is needed. The render's download credential is fresh by
   construction, so the spent originals cost nothing.

Blast radius, measured on the executed drill (2026-10-09, five live
implants across all four families, tasking current):

- Every TLS-fronted implant died at its next contact and never
  recovered: the pinned incumbent CA rejects the server's successor
  chain, and the egress walk cycles its baked endpoints forever --
  rotation is not a front burn, and no fallback survives it.
- The UDP DNS carrier split in half: the implant's polls kept
  refreshing its presence (no TLS handshake exists to fail), so the
  roster kept showing it online -- but every task came back
  client-refused (`signature verification failed; not executed`),
  because the signed tasking verifies against the pinned incumbent
  signer. A DNS-carried implant after rotation looks alive and cannot
  execute; treat roster presence on that carrier as dead until re-entered.
- Untouched: operator cookies (the DataProtection key ring is not CA
  state), engagements, tasks, artifacts (byte-exact), the audit chain
  (extended, not broken -- every pre-rotation event hash identical),
  and the listener set (4 of 4 rebind on the rotation restart).
- Re-entry verified end to end: a fresh build against the rotated CA,
  fetched through the standing redirector front, enrolled, and answered
  tasking (`reentry-ok`) through the same front.

Plan the cut accordingly: rotation is scheduled downtime for implant
presence. Budget one fresh build-and-render per implant that must come
back, and treat every pre-rotation leaf as dead the moment the service
restarts -- including the DNS-carried ones the roster has not given up
on yet.

## 7. The surface refresh legs (dated 2026-10-10)

The base walk settles the carrier and lifecycle surface; the operator
surface has since grown four families it never exercised -- the recon
workbench ([recon.md](recon.md)), the MCP endpoint ([mcp.md](mcp.md)),
the LLM summarize client ([llm.md](llm.md)), and the Linux module load
(extending/modules.md). These legs ran all four against a live
engagement on the same single-host shape: a fresh engagement in the
standing rehearsal database, one Https listener direct on loopback (no
redirectors -- fronting was the base walk's question, not this one's),
and a freshly provisioned operator, so every route ran under the
membership model's owner role rather than any global scope. One
pipeline-built Linux poll implant enrolled through the front (fetch
sha256 equal to the build fingerprint) and carried the module leg.

What ran, and what it produced:

- **The recon workbench, passive and active.** A `recon:resolve` on
  `www.example.com` through the configured DoH resolver answered four
  addresses and landed `recon.resolve:www.example.com` as a task-less
  artifact under the running operator's attribution
  (`ReconLookupCompleted`). With the ROE target scope narrowed to
  `127.0.0.1`, a port scan of the loopback passed the gate
  (`ReconScanCompleted`, the three open ports as findings), and the same
  scan aimed at `203.0.113.10` was refused before any connection opened:
  `422` on the route, `ReconScanRefused` in the trail naming the violated
  rule.
- **An MCP read through an operator API token.** A minted token
  authenticated the endpoint as its principal (Streamable HTTP,
  stateless): `initialize` answered the server's toolset, `tools/call
  list_implants` read the live roster -- the enrolled implant, its host
  and liveness -- and `list_engagements` rendered exactly the engagements
  the token's operator holds membership on. A read naming a foreign
  engagement answered not-found: the scope rule holds through the agent
  surface. Reads are unaudited by design (the digest's posture); the
  token's mint is the trail's record of the surface's use.
- **A summarize against a local OpenAI-compatible endpoint.** llama.cpp's
  server (build b11541, CPU) serving Qwen2.5-0.5B-Instruct (q4_k_m) on
  the teamserver host -- the local-runtime posture [llm.md](llm.md)
  names, engagement content staying on the engagement's own
  infrastructure. A completed `shell.exec` (uname/id/uptime, 267 chars
  captured) summarized to a faithful paragraph; the route answered
  `{taskId, model, summary}` and the trail carries
  `LlmSummaryGenerated` with outcome `succeeded:qwen2.5-0.5b-instruct`,
  the endpoint and key absent from the event as designed.
- **The Linux module round-trip.** The reference hostenum module built
  for `x86_64-unknown-linux-musl` (589,272 bytes, sha256 `3a1887a9…`,
  bound into the load task's signed arguments and verified by the
  implant) loaded through `module.load hostenum` with the bytes as the
  task's staged content: staged in a memfd -- the live implant's fd table
  shows `/memfd:rod-module (deleted)`, and nothing matching the module
  ever touched disk. `module.list` reported `hostenum: recon.hostenum`;
  the tasked verb answered host enumeration in the JSON-lines grammar
  (arch, host, os, path, user); `module.unload` retracted it; and a
  second `recon.hostenum` task completed with outcome `Failed` and the
  refusal "this build carries no handler for the verb" -- the grammar
  named afterward, the same acceptance the Windows module drill
  specifies.

The teardown followed the base walk's shape: implant retired, report
exported (integrity digest `A0D1C113…`), engagement frozen, evidence
package taken, engagement retired.

One composed-system defect, caught the way this document exists to catch
them: the report export 500'd on the first attempt. The Postgres
membership store's roster listing ordered its rows by reaching into the
typed id (`.OrderBy(m => m.OperatorId.Value)`), which EF Core cannot
translate, so every report over a live Postgres died in the crew section
-- while the in-memory adapter the test suite runs translates any
ordering and never met it. Fixed to order by the converted column, with
a regression test over the real-Postgres durability fixture that fails
on the old line and passes on the new one.

## 8. The browser-hook leg (dated 2026-10-10)

The Browser class shipped (architecture.md Sec 5.2, Sec 8); this leg ran
its acceptance criterion live: a real browser, a real teamserver, and the
two verbs the criterion names. The lab shape: the dev teamserver
(`dotnet run`, in-memory core state), a fresh engagement, one http
listener direct on loopback (public endpoint equals bind -- fronting was
not this leg's question), and a minted sealed hook (5s poll, 10-use
enrollment budget, fingerprint `636c1642…`). The browser is the host's
headless Chromium (`--headless=new`), loading the mint's own test page --
the stand-in for a script-injection foothold, the exact artifact a victim
fetches.

What ran, and what it produced:

- **The mint and the serve.** `POST /engagements/{id}/hooks` answered
  `hookId 66277163…` with the serving URL and the paste-ready
  `<script src>` snippet; the roster lists the hook with its posture and
  cadence. Loading the test page wrote the first-touch trail exactly as
  designed: three `HookFetched` facts (script, test page) naming each
  fetcher's address and user agent before any identity existed, then the
  identity-bearing half followed.
- **The enrollment.** The hook enrolled over the sealed envelope carrier
  in the real browser's JavaScript -- the hand-rolled protobuf codec, the
  WebCrypto AES-256-GCM R1 body, the strictly increasing counter, and the
  sealed JSON enroll all executed as served, unmodified: the roster row
  is class `Browser`, online, reporting `os=Linux x86_64
  arch=browser`, carrier `envelope`, and the trail carries
  `ImplantEnrolled` with the class beside a single `SessionOpened` (the
  poll cadence's session-reuse guard holding).
- **The criterion's task pair.** `browser.fingerprint` and
  `browser.cookies` issued at 16:17:37, both dispatched on one poll
  contact at 16:17:40, both completed `Succeeded` at 16:17:41 -- about
  four seconds end to end. The fingerprint answered the full navigator
  facts of the headless browser (HeadlessChrome/150 UA, en-US, 800x600,
  Asia/Shanghai timezone, the hooked page's own URL); the cookie read
  answered `(no readable cookies)`, the honest empty set of the origin's
  non-HttpOnly jar. Both tasks' audit arcs read
  `TaskIssued → TaskDispatched → TaskCompleted` attributed to the
  Browser-class implant.

The teardown followed the standing shape: implant retired, engagement
frozen and retired.

One composed-system defect, again caught exactly the way this document
exists to catch them: the first live run stranded every dispatched task.
The hook's seal decode resolved the raw ArrayBuffer WebCrypto returns,
and the script's readers speak Uint8Array -- so the hook never parsed a
response at all, polled on happily, and silently ignored its tasking
while every CI pin stayed green (the fake hook in the e2e suite decodes
with .NET's own primitives and never met the shape). The node
golden-vector smoke shared the blind spot: it round-tripped frames
through the codec but never through a decrypt. Fixed with the wrap the
encrypt side always had, hardened the failed-contact re-queue beside it,
and re-run green end to end -- the leg below is the fixed artifact's
evidence, not the first attempt's.
