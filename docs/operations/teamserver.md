# Teamserver -- stand up, configure, run

The operational runbook for the Rod teamserver: build, first login, the
configuration reference, and the durability options. The design rationale lives
in [architecture.md](../architecture.md); this file is about running the thing.

## Prerequisites

- .NET SDK 10, pinned by `global.json` at the repo root.
- Node.js 22.12+ only for the operator UI (a backend-only checkout runs
  without it; the host explains at request time how to build the bundle).
- PostgreSQL, only when you opt into durable state (below).

## Build and run

```
dotnet build Rod.slnx     # builds the teamserver; bundles the UI when wwwroot is missing
dotnet run --project src/teamserver/Rod.TeamServer
```

With no `Listeners` configuration the host binds one loopback HTTP listener on
`127.0.0.1:59443` so `dotnet run` works out of the box. That configuration
names the **operator front only** -- it carries no implant ingress, and
enrollment is refused on it outright. Implant-facing listeners are
**engagement-scoped**: created through the engagement's Listeners panel (or
`POST /engagements/{id}/listeners`) against exactly one engagement, persisted
so a restart rebinds them, unique across ports, and enforced at enrollment --
anything but that engagement's own token is refused whole on the socket
(architecture.md Sec 8). A payload build names its engagement's listener and
the baked endpoint comes from the listener's record; every contact rides
that same front -- the envelope POST cycle for a poll build, the
WebSocket beacon hanging off the same schemed front for a stream build
(architecture.md Sec 8). The build also mints and
bakes the artifact's enrollment credential, so the artifact deploys with zero
run-time arguments. The manual mint endpoint stays server-side for the
rotation and re-entry drills, but it is no operator surface. The operator UI
is served same-origin at `/`; its panels and every build/listener field are
documented in [operator-ui.md](operator-ui.md). The same front also carries
the read-only MCP endpoint (`/mcp`) that an operator's agent tooling drives
on an operator API token -- same principal, same scopes
([mcp.md](mcp.md)) -- so whoever can reach the console can reach it, and
nobody else should be able to reach either. During UI development,
`npm run dev` in
`src/teamserver/Rod.TeamServer/Client` proxies the API to :59443.

## First login

The initial admin is provisioned at startup from the `Operators:Initial`
section and is idempotent (an existing account with a password is never
touched):

```json
{
  "Operators": {
    "Initial": {
      "Handle": "lead",
      "Password": "set-via-environment-in-production"
    }
  }
}
```

A deployment sets a handle and a password, nothing else -- the two
fields resolve independently (a configured password with a blank handle seeds the
default handle `admin`). Unset, both environments seed `admin`: in
Development with password `admin`, in Production with a generated
password that is logged exactly once, at the moment its hash is stored
-- later boots find the hash standing and log nothing. There is no
lockout: an unconfigured server boots with a loginable account. Bind a
real password via environment (`Operators__Initial__Password`) or a
secret store, never inline.

The seeded account is the deployment admin: the one role that provisions
accounts, holds the disable switch, and writes the redirector fleet and
the runtime settings (architecture.md Sec 4.5). Every account it
provisions through `POST /operators` comes up a **member** --
permanently, since there is no promote or demote path; the bootstrap at
boot is the only way a deployment grows an admin. Members keep
self-service over their own password and API tokens; reach inside
engagements arrives per engagement, as memberships engagement owners
grant (`POST /engagements/{id}/members`). `GET /operators` lists the
roster with each account's role -- the deployment admin's read; a
member's account surface is `GET /operators/me`.
`PUT /operators/{id}/credentials`
re-provisions a password (the previous generation's sessions end at
their next request; the caller's own account -- proving the current
password, so a stolen session cannot quietly own the account -- or the
admin's), and
`POST /operators/{id}:disable` / `:enable` are the account's off and
back on -- a disabled account authenticates nowhere (login, cookie
session, API token) but keeps its memberships, so enabling restores
exactly what it had. Disabling the last enabled account, or the last
enabled admin, is refused (409) so a deployment never strands itself.

## The dev loop

1. Log in at the UI (or `POST /operators/login`).
2. Create an engagement; create its listener (the engagement's own implant
   ingress -- the operator front refuses enrollments): `POST
   /engagements/{id}/listeners` with `{"name": "dev", "transport": "Http",
   "bindAddress": "127.0.0.1:8080"}` (the public endpoint derives from the
   bind on the web-shaped transports); mint a deploy token. The UI path is
   the engagement's Listeners panel.
3. Build a payload for it (class, target OS/arch, beacon profile, malleable
   transport) and download the artifact from the payload store.
4. Run the reference implant for a quick end-to-end check:
   `ROD_ENROLL_URL=http://127.0.0.1:8080/implants/enroll
   ROD_DEPLOY_TOKEN=<secret> cargo run --manifest-path
   src/implant/rust/Cargo.toml` -- the address is
   the listener from step 2, not the operator front; `ROD_MODE=stream`
   selects the interactive shape (poll is the default). It appears in the
   implants list (grouped under the host it reported at enroll), takes
   tasking, and its results land in the audit trail.
5. For a live shell, open the implant's session console (its Interact link in
   the fleet) and type `interact` -- or issue `shell.interact` from the
   implant's context menu, or `POST /engagements/{id}/tasks` -- and the
   Interact pane opens: type into the
   input line and watch the transcript stream. Over the API the same loop is
   `POST /engagements/{id}/tasks/{taskId}/input` with `{"data": "<base64>"}`
   per line and `{"eof": true}` to close stdin -- the task completes with the
   whole session as its output (architecture.md Sec 10.3). Interactive
   channels need a stream-mode contact; a poll-mode implant reports the task
   Failed with the reason.
6. To reach a host only the implant can see, issue `tunnel.forward` with
   arguments `<host> <port>`: the same Interact pane carries the tunnel --
   input posts are relayed to the peer and its answers land on the transcript,
   `eof` half-closes the send side, and the task ends when the peer closes,
   with the relay summary as its final output (architecture.md Sec 10.1).
7. To let an unmodified tool ride that tunnel, bind a relay port onto the
   dispatched task: `POST /engagements/{id}/tasks/{taskId}/relay` (body
   `{"bindAddress": "loopback", "port": 0}` -- loopback and an ephemeral port
   are the defaults) and point the tool at the returned endpoint. Its bytes
   cross the channel without a single API call per byte, the answers come
   back raw, and the bind and its close (with byte tallies) land in the
   engagement trail. On `tunnel.forward` the relay bridges one connection to
   the task's fixed destination; `DELETE /engagements/{id}/tasks/{taskId}/relay`
   ends it early (architecture.md Sec 10.1). Binding off-loopback (`any` or an
   IP literal) exposes the tunnel to every host that can reach the port --
   name the address only when the operator path needs it.
8. For arbitrary destinations through one task, issue `tunnel.socks` (no
   arguments) and bind the same relay route: the endpoint speaks SOCKS5
   (no auth, CONNECT only), so a browser pointed at it as its proxy -- or
   proxychains, or any SOCKS-configured client -- reaches whatever the
   implant can reach, each connection under its own id on the one channel.
   The task's final output is the proxy's record: the destinations dialed
   and the bytes moved (architecture.md Sec 10.1). Close it with an eof
   input post; the bind dies with the task.
9. To represent a host that cannot run an implant at all, derive a Pivot
   child from a full-implant parent (`lateral.move` with arguments
   `<token> Pivot`) and task the child directly: its tasking executes on the
   parent's beacon stream, marked with the child's id and attributed to the
   child end to end (architecture.md Sec 5.2). The child never appears in
   presence -- it has no process -- so its liveness is the parent's.

Staged delivery rides the launcher one-liners, not a loader build (the
stager class is retired): render them per payload in the operator UI's
Launchers tab, or straight from a caught shell's Upgrade panel. The
one-liner fetches the artifact over the engagement's web front
(`GET /implants/payloads/{id}`), presenting the freshly minted fetch
credential -- each served fetch spends one use of it -- and the fetched
artifact then enrols with the credential baked into it at build time and
appears on the roster. On Linux the memfd family stages the bytes in
memory and runs them without landing a file. The artifact prints nothing
to the terminal it was launched from (exit codes alone tell the bare
story); run it with `ROD_VERBOSE=1` while testing to see enrollment and
contact diagnostics.

## The engagement ROE profile

Each engagement carries a rules-of-engagement profile the server enforces
(architecture.md Sec 9): `permittedVerbs` (exact verbs or `namespace.*`
wildcards) and `permittedImplants` (exact implant ids) gate task issuance
-- a task outside the profile is refused with `422` and a `TaskRoeRefused`
audit event naming the violated rule -- and `permittedTargets` (exact
hostnames, exact IPs, or CIDR blocks) gates the recon workbench's port
scan before any connection opens. Every dimension is empty meaning
unrestricted; the scope change itself lands in the trail as `RoeUpdated`.
Operators apply the profile over the API (`PUT /engagements/{id}/roe`;
there is no UI editor today); applying an empty profile reopens the
engagement. The target-scope entry shapes and their matching rules are
spelled out in [recon.md](recon.md).

## Configuration reference

Opt-in sections of `appsettings.json` (environment variables work through the
standard `Section__Key` mapping):

| Section | What it selects | Default when absent |
|---------|-----------------|---------------------|
| `Operators:Initial` | The initial admin account, provisioned idempotently at startup (`Handle`, `Password` -- each field falls back on its own). Bind the password through the environment (`Operators__Initial__Password`), never inline. | Handle `admin`; password `admin` in Development, or in Production a generated password logged exactly once at first boot. |
| `Listeners` | The **shared tier** only: the operator front, plus any deliberately shared ingress (e.g. the certificate-less enroll edge). One entry per socket -- `Name`, `Transport` (`Http`, `Https`, `Dns`, `Doh`, or `Tcp`; `Https` is the one-port shape -- TLS with no client certificate requested anywhere, enrollment on the token and contacts on the sealed envelope under the per-artifact key, both halves on one socket; `Doh` carries the DNS grammar over RFC 8484 HTTPS bodies and, like `Dns`, takes the zone as its public endpoint), `BindAddress` (what the host opens), `PublicEndpoint` (what implants dial; typically a redirector; for a `Dns` entry it is the zone the TXT contacts live under). Https entries terminate TLS against the implant CA; DNS entries bind a UDP socket; `Tcp` entries bind a raw socket under the certificate-less identity posture. Implant-facing listeners are engagement-scoped and created through the operator API, not configuration (architecture.md Sec 8). Keep `Http` entries on loopback: the operator API and the certificate-less beacon ride them in the clear, and a non-loopback bind logs a startup warning (architecture.md Sec 8). | One loopback HTTP listener on `127.0.0.1:59443`. |
| `Audit:DataDirectory` | File-backed audit trail, artifacts, and built payloads that survive a restart. Each append writes and flushes one hash-chained record; recovery verifies each engagement's chain and refuses a tampered trail. | In-memory (lost on restart). |
| `ConnectionStrings:Postgres` | The durable PostgreSQL pair replaces the in-memory core-state and audit adapters (EF Core over Npgsql). Apply the schema with `dotnet ef database update -p src/teamserver/Rod.Persistence -s src/teamserver/Rod.TeamServer`. | In-memory. |
| `Pki` | An externally provisioned engagement CA as PEM files (`CaCertificatePath`, `CaPrivateKeyPath`, optional `CaPrivateKeyPassphrase`) -- production leaf issuance. Unparseable or mismatched material fails at startup, not at the first enrollment. RSA only. | The self-signed dev CA (key lives in process -- not for production). |
| `Sessions:Staleness` | `Threshold` and `SweepInterval` for the session sweeper -- the close path for streams that die silently and for poll-mode contact cadences. | 15-minute threshold, 1-minute sweep. |
| `Webhooks` | The notification forwarder's timing: `EngineTickSeconds` (how soon a registration starts hearing events) and `DeliveryTimeoutSeconds` (one push's budget; delivery is single-attempt, no retry). Channels are registered per engagement from the operator API (architecture.md Sec 4.4), not configured here. OPSEC notes the operator owns: the push body is what a connected console sees, task output included, so where a channel points -- a self-hosted receiver or a third-party IM bridge -- is a decision about engagement data leaving the box; the URL is the channel's bearer secret (the audit trail never records it), and plain http is loopback-only. | 5 s tick, 10 s delivery timeout. |
| `Capabilities:Modules` | Capability modules, each a `Namespace.Type, AssemblyName` entry. The in-tree reference modules under `modules/` ship listed and load through this same list, exactly like an operator's external modules; see [extending/modules.md](../extending/modules.md). | The shipped list carries the in-tree reference module set; absent the section entirely, the built-in placeholders alone. |
| `Build:Transforms` | Out-of-tree post-build payload transforms, each a `Namespace.Type, AssemblyName` entry, applied in listed order; the fingerprint and `PayloadBuilt` audit event cover the transformed bytes. | The empty chain (no transform runs; bytes stored as built). |
| `Build:RustSourceDirectory` | An installed teamserver (a publish with no repo above it) names the Rust crate the build unit compiles at request time. | The repo walk-up a checkout uses (`src/implant/rust`). |
| `Build:GoSourceDirectory` | The Go build unit's twin: names the Go module the unit compiles at request time. | The repo walk-up a checkout uses (`src/implant/go`). |
| `Llm` | The opt-in LLM triage client (architecture.md Sec 11): `Enabled`, `BaseUrl` (any OpenAI-compatible chat-completions endpoint, cloud or local), `ApiKey` (bind through the environment, `Llm__ApiKey`), `Model`, plus `RequestTimeoutSeconds`/`MaxInputChars`/`MaxOutputTokens` budgets. Every summarize request is engagement-scoped and audited; the egress decision is the operator's -- see [llm.md](llm.md) before enabling. | Disabled (the summarize route answers 503). |
| `Recon` | The external recon workbench's halves (architecture.md Sec 11.4): `RdapBaseUrl`, `CtBaseUrl`, `DohBaseUrl`, and `WhoisServer` arm the passive lookups; `ScanOrigin` (`Teamserver` is the only shipped origin) arms the port scan; `RequestTimeoutSeconds` and the `Max*`/`Scan*` caps bound each run. Naming an endpoint is the egress decision -- see [recon.md](recon.md) before arming any half; the scan additionally gates on the engagement's ROE target scope. | Every half closed (each route answers 503 naming this section). |
| `RuntimeSettings` | Where the operator-facing runtime settings persist: `FilePath` for the session-staleness pair, `BuildFilePath` for the build section (the shared cargo target dir). Best-effort persistence of operator preferences, not engagement data. | `runtime-settings.json` / `runtime-build-settings.json` beside the working directory. |

## Production install and recovery

The installed shape: a self-contained publish under `/opt/rod`, a dedicated
service user, secrets in a root-only environment file, and a systemd unit
supervising the process. Everything below is the executed install path --
each step was walked on a clean tree, then crash-restarted, upgraded, and
restored from backup before being written down.

### Install

The build host needs the pinned SDK; the deploy host needs neither SDK nor
runtime, only PostgreSQL reachability:

```
dotnet publish src/teamserver/Rod.TeamServer/Rod.TeamServer.csproj \
  -c Release -r linux-x64 --self-contained true -o /tmp/rod-publish
```

Lay the host out (the service user's home is where the DataProtection key
ring lands -- see the backup trio):

```
sudo useradd -r -d /var/lib/rod -M -s /usr/sbin/nologin rod
sudo mkdir -p /var/lib/rod/data /etc/rod/pki /opt/rod
sudo chown rod:rod /var/lib/rod /var/lib/rod/data
sudo cp -a /tmp/rod-publish /opt/rod/teamserver          # + appsettings.Production.json below
sudo cp ca.crt ca.key /etc/rod/pki/ && sudo chown root:rod /etc/rod/pki/* \
  && sudo chmod 640 /etc/rod/pki/ca.crt /etc/rod/pki/ca.key
```

Non-secret configuration rides `appsettings.Production.json` next to the
binary (the Pki paths, `Audit:DataDirectory`, and the listener shape);
apply the schema once per deployment from a checkout, not the install
tree:

```
dotnet ef database update -p src/teamserver/Rod.Persistence \
  -s src/teamserver/Rod.TeamServer --connection "<rod connection string>"
```

The unit (`/etc/systemd/system/rod-teamserver.service`):

```ini
[Unit]
Description=Rod teamserver (C2 kernel)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=rod
Group=rod
Environment=ASPNETCORE_ENVIRONMENT=Production
EnvironmentFile=/etc/rod/teamserver.env
ExecStart=/opt/rod/teamserver/Rod.TeamServer
WorkingDirectory=/opt/rod/teamserver
StateDirectory=rod
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/rod

[Install]
WantedBy=multi-user.target
```

`sudo systemctl daemon-reload && sudo systemctl enable --now
rod-teamserver`, then accept: `systemctl is-active` reports active and
`POST /operators/login` on the operator listener answers 200. After
debugging a crash-looping start, clear the rate limit with `systemctl
reset-failed rod-teamserver` before starting again.

### One-command install

The install path above, executed by a script: a release carries the
self-contained teamserver tarball, the payload build source (implant crate,
Go module, wire protos, dependencies vendored beside them), and
`scripts/install.sh`. CI builds the assets on a clean runner
(`.github/workflows/release.yml`), so no developer host's paths or state
ever touch what ships, and the release tag is verified against RodVersion
before the build -- the binary's BuildStamp names the same tag the assets
were cut from. The repository is public, so the deploy host needs no
authentication:

```
curl -fsSL https://github.com/rodframework/Rod/releases/latest/download/install.sh \
  | sudo bash
```

Pin a version with `sudo bash -s v1.0.0` in place of the trailing `bash`.
The script lays out `/opt/rod`, generates `appsettings.Production.json`
(non-secret shape only), the commented secret env template, and the unit,
then starts the service in the ephemeral posture; rerunning with a newer
version upgrades in place, carrying every operator-written file across.
What it cannot invent stays manual and unchanged from above: the database
and its schema, the engagement CA, and the Rust toolchain (the next
section). The script's rehearsal knobs (`ROD_REHEARSAL`, `ROD_ASSET_BASE`,
`ROD_PREFIX`) exercise the install path without root or systemd against a
local asset directory.

### Build sources and the operator UI

Two more install-shape facts, both walked end to end on the supervised
install:

**Payload builds compile from source at request time**, and the install
tree has no repo above it, so the deployment names its build source trees
with `Build:RustSourceDirectory` and `Build:GoSourceDirectory`
(a configured-but-missing directory fails the build loudly). The minimal
deployed tree the keys can point at:

```
/opt/rod/src/
  src/implant/rust/                                 # the build source, no target/
  src/implant/go/                                   # the Go module, vendor/ included
  src/teamserver/Rod.Protocol/protos/               # the wire contract the implants compile against
```

The service user also needs the Rust toolchain (`cargo`, `rustc`, and the
cross linkers) on PATH and a warm cargo cache
(`/var/lib/rod/.cargo`) -- the build spawns `cargo build` and pulls crates
into that cache. On a host without registry egress, copy the cache from
the build host at install time. The Go unit needs only the Go toolchain
on PATH: its module vendors its dependencies, so `go build` never touches
the network.

Acceptance from the executed walk: an implant built through the
supervised install returned its fingerprint, and the downloaded
artifact's sha256 matched it exactly.

**The operator UI is a build-time bundle**: with Node 22.12+ on the
build host, `npm ci && npm run build` in
`src/teamserver/Rod.TeamServer/Client` emits `wwwroot/`, and the
publish carries it -- without Node the install runs API-only. The
executed walk logged into the installed UI, listed the engagements,
opened one, and saw the live presence channel mark its own operator
session online.

### Build provenance

The publish stamps its provenance into the binaries: the product version
(`RodVersion` in `Directory.Build.props`) and the exact source commit the
binary was built from, resolved from git HEAD at build time. A release is a
git tag `v<RodVersion>` cut from the tree it was built from; the stamp is
what ties an installed binary back to that tag -- not a hand-declared source
path in configuration.

The installed teamserver reports the pair two ways:

- at startup, as the first log line -- `Rod teamserver 1.0.0
  (commit <sha>)` in `journalctl -u rod-teamserver`;
- on request, over the operator API, behind a session:

```
curl -s -c jar.txt -H 'Content-Type: application/json' \
  -d '{"handle":"lead","password":"<from the secret store>"}' \
  http://<operator listener>/operators/login > /dev/null
curl -s -b jar.txt http://<operator listener>/build
# -> {"version":"1.0.0","sourceCommit":"<sha>"}
```

Accept an install only when the stamp matches the tag it was cut from. The
deployed redirector reports the same pair via `rod-redirector -version`
([redirectors.md](redirectors.md)). The implant source tree is deliberately
unstamped: a captured artifact must not carry the teamserver's source
provenance.

### Cutting a release

RodVersion carries the `-dev` suffix for as long as work continues toward
the release; a release is claimed the moment the suffix drops (the
convention `Directory.Build.props` documents). The procedure, end to end:

1. Drop the suffix in `Directory.Build.props` and commit -- the same
   change the tag is cut from. A suffixed version (`-rc1`, or `-dev`
   itself) works identically for rehearsal: the release workflow accepts
   any `v<RodVersion>` tag and marks a suffixed one a prerelease, so
   `latest` (and install.sh's `latest/download` redirect) only ever
   names a bare-version release.
2. Push `main`, then cut the tag from that change and push it. Pushed
   commits are signed; the workflow's tag guard fails any tag that does
   not match RodVersion, so a mismatched or stale tag cannot ship.
3. The tag triggers `.github/workflows/release.yml`: it builds the
   assets on a clean runner (no developer host touches what ships) and
   publishes the release with the teamserver tarball, the vendored
   payload build source, and install.sh.
4. Accept: the release page lists the three assets, the startup stamp
   names the tag's version and commit, and the one-command install
   against `latest` resolves to the new tag.

### Secrets

`Operators__Initial__Password` and `Pki__CaPrivateKeyPassphrase`
([architecture.md](../architecture.md) Sec 9) never live in the
world-readable appsettings. They ride the root-only environment file the
unit injects (`/etc/rod/teamserver.env`, mode 0600):

```
Operators__Initial__Handle=lead
Operators__Initial__Password=<from the secret store>
ConnectionStrings__Postgres=<rod connection string>
```

The fields resolve independently: an unset handle seeds `admin`, and an
unset password -- outside Development -- is generated and logged exactly
once at first boot, so an incomplete section still leaves a loginable
account rather than a 401. The section is read once at first boot and
never re-read; rotate credentials through the operator API, not by
editing the file.

### Upgrade

Stop, replace, start:

```
sudo systemctl stop rod-teamserver
sudo rm -rf /opt/rod/teamserver && sudo cp -a /tmp/rod-publish /opt/rod/teamserver
sudo cp appsettings.Production.json /opt/rod/teamserver/
sudo systemctl start rod-teamserver
```

Sessions survive: the operator cookie is sealed by the DataProtection
key ring and stamp-checked against the credential store, and both are
durable state outside the process. The same is true of a crash --
`Restart=on-failure` brings the process back (verified with `kill -9`:
new pid, cookie still accepted) while the fronts keep splicing and
implants retry.

### Backup and restore: the trio that moves together

Three pieces of durable state must move as a set. Restoring any one
alone yields broken logins or lost evidence:

1. **The Postgres dump** -- operators, engagements, tasks: everything
   the durable core-state pair owns (`ConnectionStrings:Postgres`).
2. **The evidence data directory** (`Audit:DataDirectory`) -- the
   hash-chained audit trail, artifacts, and the payload store.
3. **The DataProtection key ring** --
   `/var/lib/rod/.aspnet/DataProtection-Keys` under the service user's
   home (the teamserver pins no path, so the ASP.NET Core default
   applies). It seals operator cookies and API tokens; a fresh ring
   silently invalidates every issued cookie.

Take the set with the service stopped, so the three members agree:

```
sudo systemctl stop rod-teamserver
pg_dump -h <host> -U rod rod > rod.sql
sudo tar -C /var/lib/rod -czf data.tgz data
sudo cp -a /var/lib/rod/.aspnet aspnet-keys
```

Restore onto the wiped host (drop and recreate the empty database
first; the dump carries the schema):

```
sudo systemctl stop rod-teamserver
sudo -u postgres psql -c "DROP DATABASE rod;" -c "CREATE DATABASE rod OWNER rod;"
psql -h <host> -U rod -d rod -f rod.sql
sudo rm -rf /var/lib/rod/data /var/lib/rod/.aspnet
sudo tar -C /var/lib/rod -xzf data.tgz
sudo cp -a aspnet-keys /var/lib/rod/.aspnet
sudo chown -R rod:rod /var/lib/rod/data /var/lib/rod/.aspnet
sudo systemctl start rod-teamserver
```

Accept: a pre-backup operator cookie authenticates the first request
after the restore, and the engagement roster reads back. The failure
modes are structural, not flaky: the dump without the key ring leaves
the old cookie unreadable (401), the key ring without the dump fails the
per-request stamp check against the credential store (401), and the
data directory without the database orphans the audit chain the report
reads.

The restore has its own health check: at startup the teamserver verifies
the database against the persistence model -- every mapped table present
and carrying its primary key -- and aborts the boot naming the offending
tables otherwise. This closes a failure class the win-x64 surface walk
caught live: a database carrying every table and row but none of its
constraints boots apparently healthy and dies at the first task
dispatch, where the replay-nonce reservation's ON CONFLICT meets its
missing arbiter. Verify a restore the same way the install verifies a
first boot: `systemctl is-active` plus one login, and the schema guard
has already vouched for the store underneath.

## Resuming the watch

An operator returning to the console after an absence reads the shift
handoff digest instead of the raw trail (architecture.md Sec 11.1):

```
curl -s -b jar.txt \
  "http://<operator listener>/engagements/<id>/handoff-digest?from=<ISO>&to=<ISO>"
# ?format=markdown renders the human handoff note for the next watch.
```

The digest is one ordered account of the watch's beats -- sessions opened
and closed, implants enrolled and retired, tasking with its outcomes, ROE
refusals, implant notes, shell sessions -- under a count summary, with the
timeline's enrichment and integrity stamp. Bounds are inclusive; `to`
defaults to now and `from` to twelve hours before it, and the span is
capped at thirty-one days (longer horizons are the timeline's job). One
semantic to know when reading the session lines: the `SessionClosed` fact
is written by the staleness sweep, so it marks a stream that went silent;
a session closed by a re-enroll leaves the successor's `SessionOpened` as
its trace and no close event of its own.

## Closing out an engagement

A finished engagement leaves through the close-out (architecture.md Sec 2
step 10, Sec 11): freeze, export the evidence package, verify it, retire.
All three are operator API actions over the operator listener, logged in the
session cookie:

```
# 1. Freeze: the engagement stops accepting new tasking, enrollments, and
#    token mints, so its trail is final. In-flight results still land.
#    A mistaken freeze is reversible before retirement:
#    POST .../engagements/<id>:unfreeze reopens the engagement.
curl -s -b jar.txt -X POST http://<operator listener>/engagements/<id>:freeze

# 2. Export: one ZIP with audit.jsonl (the full hash-chained trail),
#    artifacts.jsonl, report.json + report.md, and the manifest that pins
#    every file's bytes.
curl -s -b jar.txt -X POST \
  http://<operator listener>/engagements/<id>:evidence-package \
  -o rod-evidence-<id>.zip

# 3. Verify offline -- on any host, with nothing Rod running on it. The
#    binary recomputes every digest, re-runs the chain check, and validates
#    the artifact records; exit 0 is a verified package.
dotnet Rod.TeamServer.dll --verify-evidence rod-evidence-<id>.zip

# 4. Retire: terminal, and refused until the engagement is frozen.
curl -s -b jar.txt -X POST http://<operator listener>/engagements/<id>:retire
```

Acceptance from the walk above: the exported package re-verifies byte-exact
on a host with no Rod infrastructure running, and every step of the close-out
(`EngagementFrozen`, `EvidenceExported`, `EngagementRetired`) is itself an
audited, attributed event in the trail the package carries. The exported
trail ends one event before the export's own record -- a later re-export
(before retire) carries it, so late-landing results are not lost.

## Production posture

- Terminate the beacon on an **https listener** and front it with a redirector;
  the listener's public endpoint is repointable at runtime so burned
  infrastructure swaps without touching the backend
  ([redirectors.md](redirectors.md)).
- Configure the **external CA**, **Postgres**, and an **operator account from
  a secret store**; run with no Development fallback.
- Every privileged action lands in the engagement-scoped, hash-chained audit
  trail regardless of configuration -- keep `Audit:DataDirectory` (or
  Postgres) on durable storage, since the trail is the report source and
  outlives the operation (architecture.md Sec 11).
- Pin the install to its source: accept a deployment only after the build
  stamp matches the release tag it was cut from (see "Build provenance"
  above) -- the binaries name their commit, so provenance is read off the
  running system, not off deployment notes.
- The teamserver **originates egress, not just ingress**, where an operator
  arms it: the recon workbench's lookups and scan (RDAP, CT, DoH, whois to
  the configured endpoints; scan connections from the teamserver process
  when `Recon:ScanOrigin` names it -- [recon.md](recon.md)) and the LLM
  triage client's summarize requests to its endpoint
  ([llm.md](llm.md)). Each half stays closed until its endpoint is named,
  and the egress posture of each is a deliberate per-engagement decision --
  a hardened deployment leaves every one of them disabled unless the
  engagement calls for it.
- Before pointing the stack at a client network, walk the full lifecycle on
  the production shape once -- the procedure and its acceptance evidence
  live in [rehearsal.md](rehearsal.md).
