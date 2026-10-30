<p align="center"><img src="docs/assets/rod-logo.png" alt="Rod" width="200"></p>

<h1 align="center">Rod</h1>

<p align="center">
  An <b>authorized-use red-team operations platform</b> for penetration
  tests and security research.<br>
  Pre-foothold recon, one teamserver, a fleet of disposable implants
  reaching hosts behind NAT and firewalls over implant-initiated
  connections --<br>
  and an audit trail that becomes the report.
</p>

<p align="center">
  <a href="https://github.com/rodframework/Rod/actions/workflows/ci.yml"><img src="https://github.com/rodframework/Rod/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/rodframework/Rod/actions/workflows/implant-matrix.yml"><img src="https://github.com/rodframework/Rod/actions/workflows/implant-matrix.yml/badge.svg" alt="Implant e2e matrix"></a>
  <img src="https://img.shields.io/badge/.NET_10-512BD4?logo=dotnet&logoColor=white" alt=".NET 10">
  <img src="https://img.shields.io/badge/Rust-DEA584?logo=rust&logoColor=black" alt="Rust">
  <img src="https://img.shields.io/badge/React_19-61DAFB?logo=react&logoColor=black" alt="React 19">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License: Apache-2.0"></a>
</p>

> **Authorized use only.** Rod gives its operators remote code execution
> wherever its artifacts run. It must **only** be used against systems
> and networks you own or are **expressly authorized** to test.
> Unauthorized use is illegal in most jurisdictions.

> **Status: implemented; sensitive capabilities arrive as modules and stay
> off by default.** The
> teamserver, reference implant, build pipeline, operator UI, and durable
> state are in place. The reference implant runs the compiled core (shell
> execution one-shot and interactive, file transfer both ways, directory
> listing, process termination, beacon retiming, tunneling, the module
> family -- load/list/unload, memfd-exec on Linux -- and the Windows-gated
> sensitive trio: shellcode injection, LSASS minidump, input capture), while
> the long tail (recon sweeps, lateral movement, persistence, credential
> and screen collection) and the exploit/evasion categories arrive through
> the extension seams as opt-in modules -- in-tree reference modules and
> external ones load through the same path
> ([architecture.md Sec 13, Sec 15](docs/architecture.md)). Operator-side,
> the
> external recon workbench ships pre-foothold scoping -- passive
> RDAP/CT/DoH/whois lookups and an ROE-gated port scan whose findings land
> as engagement artifacts
> ([docs/operations/recon.md](docs/operations/recon.md)).

## What you get

- **Five transports, one task grammar.** `http`, `https`, `dns`, `tcp`,
  and `doh` listeners ship in-tree; every verb works
  over every carrier, with live channels on the stream transports and
  store-and-forward channels on the poll transports.
- **Disposable implants with baked profiles.** Each implant generates its
  own keypair at first run (no key material ships in the artifact), carries
  a build-time profile -- contact mode, beacon cadence and jitter, kill
  date, transport shape -- and enrolls on a one-time credential baked at
  build, so a dropped artifact needs zero run-time arguments.
- **Web shells and caught reverse shells.** The build panel renders
  placement scripts in PHP, JSP, ASPX, or classic ASP -- sealed under a
  baked AES-256-GCM key, or in the universal eval shape -- and a placed
  script registers as an implant driven through the same tasking and audit
  surface. A `shellcatch` listener catches raw reverse-shell one-liners
  (`nc`, bash `/dev/tcp`, ...), fingerprints the OS, and hands back
  paste-ready lines that upgrade the catch into a full implant.
- **One-liner delivery, plus a sealed loader tier.** Delivery rides
  paste-ready launcher one-liners (curl/wget/PowerShell fetch-and-run, and a
  Linux in-memory memfd family that never lands a file); each fetch spends a
  use of the build's baked credential. For the tightest footprint a ~25 KB
  `no_std` loader fetches its implant as an AES-GCM-sealed body, verifies it,
  and execs it straight from memory
  ([architecture.md Sec 6](docs/architecture.md)).
- **Polyglot by contract.** The wire protocol is the product: the Rust
  reference implant is one implementation, and Go, C/C++, or Nim implants
  build against the same language-neutral contract without coupling the
  teamserver to their toolchains.
- **A plugin seam for the long tail.** Capability modules written against
  the in-tree `rod-plugin-sdk` crate load into an already-deployed artifact
  over the sealed task channel (`module.load`), join the dispatch table,
  and read in the console exactly like built-in verbs; Linux stages them in
  a memfd and execs them -- nothing on disk. The `hostenum` pair
  (server package at rod-plugin-hostenum, implant half in the
  rod-implant-rust repository) is the worked example to copy
  ([docs/extending/modules.md](docs/extending/modules.md)).
- **Pre-foothold recon on the teamserver.** An engagement-scoped workbench
  runs passive RDAP registration lookups, certificate-transparency
  subdomain censuses, and DoH resolution (whois as the fallback behind the
  RDAP flag) -- each half armed only when its egress endpoint is named,
  never by silent default -- plus a port scan gated on the engagement's ROE
  target scope. Findings land as task-less engagement artifacts and join
  the intel layer's topology projection
  ([docs/operations/recon.md](docs/operations/recon.md)).
- **Tracked delivery campaigns.** The email-shaped delivery step on the
  teamserver (architecture.md Sec 2, Sec 11.5): a per-recipient lure
  message sent through a named SMTP relay, each link bound to a
  per-recipient build whose baked credential attributes the enrollment
  that follows -- opened, clicked, and executed tracked to tasking, the
  whole causal chain in one trail
  ([docs/operations/campaigns.md](docs/operations/campaigns.md)).
- **Agent-friendly read surfaces.** The operator front exposes a read-only
  MCP server (`/mcp`, six tools over the engagement's read side, driven on
  operator API tokens) and an opt-in OpenAI-compatible LLM triage client
  that summarizes a completed task's captured output -- both under the
  console's scoping and audit posture
  ([docs/operations/mcp.md](docs/operations/mcp.md),
  [docs/operations/llm.md](docs/operations/llm.md)).
- **A multiplayer operator console.** A React web UI -- fleet view, tasking,
  interactive shells, file and process browsers, listeners, payload and
  webshell builds, evidence panels -- with server-sent-event updates and
  every action attributed to the operator who took it.
- **Evidence as a first-class output.** A hash-chained audit trail,
  generated reports (JSON + Markdown), and a close-out evidence package:
  what happened, who did it, and what it proved.
- **Swappable infrastructure.** Redirectors are near-stateless .NET Native
  AOT single binaries fronting the listeners; a burned one is replaced, not
  mourned.

## The shape of an operation

Everything is scoped to an **Engagement** -- the unit of tenancy,
isolation, authorization, and evidence. Implants enrol into exactly one
engagement; data, tasking, artifacts, and audit records never cross that
boundary, by construction. An engagement runs the red-team lifecycle:
stand up listeners, build payloads, operate the fleet (shell, transfer,
recon, lateral movement, persistence, collection, exfiltration,
tunneling), then close out -- freeze, export the evidence package, retire.

```mermaid
flowchart LR
    subgraph T [In-scope targets]
        I[Implant fleet]
        W[Web shells]
    end
    R[Redirectors - disposable]
    subgraph S [Teamserver]
        E[Engagement listeners]
        K[Kernel - state, tasking, builds]
        F[Operator front - console, /mcp]
    end
    subgraph O [Operator side]
        B[Browser console]
        M[MCP agents]
    end
    D[(Postgres + audit trail)]
    I -->|implant-initiated contacts| R
    W -->|placement-script callbacks| R
    R --> E --> K
    B --> F
    M --> F
    F --> K
    K --> D
```

## Components

| Component | Stack | Notes |
|-----------|-------|-------|
| Teamserver | .NET 10 (LTS), ASP.NET Core | Monolithic kernel, six internal layers. |
| Operator UI | React 19, Vite | Lives in the teamserver project; served same-origin. |
| Implants | Rust reference (static musl / mingw; Android carrier cdylib); Go/C/C++/Nim out-of-tree | Short-lived, disposable; implant-generated keys. |
| Web shells | PHP, JSP, ASPX, classic ASP scripts | Placement scripts with baked credentials; synchronous tasking. |
| Loader | Rust (`no_std`, no libc) | Sealed fetch-and-exec from memory; Linux amd64/arm64. |
| Build units | Rust in-tree; others out-of-tree | Language-neutral build contract ([architecture.md Sec 12.2](docs/architecture.md)). |
| Capability modules | Rust against `rod-plugin-sdk`; the official set in the ecosystem registry | `module.load` into a deployed artifact; memfd-exec on Linux. |
| Redirectors | .NET Native AOT, single static binary | Tiny VPS footprint; no runtime install. |
| Data store | In-memory and file-backed by default; PostgreSQL opt-in | `ConnectionStrings:Postgres` switches in durable state and audit. |

## Quick start

### Development

Prerequisites: .NET SDK 10 (pinned by `global.json`) and Node.js 22.12+
for the operator UI.

```
dotnet build Rod.slnx     # builds the teamserver and the operator UI
dotnet run --project src/teamserver/Rod.TeamServer
```

1. Open `http://127.0.0.1:5080` and sign in as `operator` / `operator` --
   the built-in Development account that applies whenever the `Operators`
   configuration section supplies no initial operator.
2. Create an engagement, then its listener in the engagement's Listeners
   panel, and mint a deploy token (`POST /engagements/{id}/deploy-tokens`)
   for the source-tree dev implant. A listener is the engagement's private
   implant ingress -- persisted and rebound on restart; the operator front
   refuses implant traffic.
3. Build a payload naming that listener. The build mints the enrollment
   credential and bakes it in; deploy the artifact anywhere in scope and it
   enrolls on run.
4. To try the fleet without a build, run the source-tree dev implant with
   the listener and the deploy token from step 2 --
   `ROD_ENROLL_URL=http://127.0.0.1:8080/implants/enroll
   ROD_DEPLOY_TOKEN=<secret> cargo run`
   from the rod-implant-rust checkout (`ROD_MODE=stream` for the interactive
   shape; `ROD_VERBOSE=1` narrates to stderr).

The full lifecycle walk -- single-host and multi-host runs, the win-x64
adversarial surface walk, the CA rotation drill, with acceptance evidence
at every step -- is [docs/operations/rehearsal.md](docs/operations/rehearsal.md).

### Production

The installed shape (the executed path, walked end to end in
[docs/operations/teamserver.md](docs/operations/teamserver.md) -- install,
upgrade, backup/restore, posture):

```
dotnet publish src/teamserver/Rod.TeamServer/Rod.TeamServer.csproj \
  -c Release -r linux-x64 --self-contained true -o /tmp/rod-publish
```

- Self-contained publish under `/opt/rod`, a dedicated `rod` service user,
  and a systemd unit with the hardening flags; secrets ride a root-only
  environment file (`Operators__Initial__*`, the CA key passphrase, the
  PostgreSQL connection string).
- **Outside Development there is no fallback login.** The first operator
  comes from the `Operators:Initial` section -- the whole section, read
  once at first boot; rotate credentials through the operator API.
- Durable state: PostgreSQL for authoritative state and audit
  (`ConnectionStrings:Postgres`, schema applied once via
  `dotnet ef database update`), a data directory for artifacts and built
  payloads, and the engagement CA (PEM cert + key) under `/etc/rod/pki`.
- Payload builds compile from source at request time: the deployment names
  the Rust crate the build unit compiles (`Build:RustSourceDirectory`) and
  keeps the service user's cargo registry cache warm.
- Binaries stamp their version and source commit (startup log line and
  `GET /build`); accept an install only when the stamp matches the tag it
  was cut from.

Configuration is opt-in sections of `appsettings.json`; the authoritative
reference -- every section, key, and default -- is the configuration table
in [docs/operations/teamserver.md](docs/operations/teamserver.md). The
headline sections:

| Section | Effect |
|---------|--------|
| `ConnectionStrings:Postgres` | Durable teamserver state in PostgreSQL, including listener definitions. |
| `Audit:DataDirectory` | File-backed audit trail, artifacts, and built payloads that survive a restart. |
| `Pki` | An externally provisioned engagement CA (PEM cert + key); omit for the dev self-signed CA. |
| `Listeners` | The shared tier only (the operator front). Implant-facing listeners are engagement-scoped, created through the API. |
| `Operators` | Production operator provisioning (`Operators:Initial`); no Development fallback outside Development. |
| `Build` | Deployed build-source trees for request-time payload compilation. |

The rest live only in the reference table: `Sessions:Staleness` and
`Webhooks` (engine timing and notification forwarding),
`Capabilities:Modules` and `Build:Transforms` (the module and transform
extension points -- a deployment lists its installed set, from the
registry or its own trees), `Llm` (the opt-in triage client), and `Recon`
(the workbench's egress endpoints and scan origin) -- each an OPSEC
decision the runbook next to it documents.

## Documentation

The doc tree, by what you came for:

| What you came for | Start here |
|-------------------|------------|
| The design -- lifecycle, engagement model, kernel layers, implants and profiles, build pipeline, OPSEC, transports, the sensitive-capability boundary | [docs/architecture.md](docs/architecture.md) |
| A from-scratch implant against the wire contract | [docs/extending/implants.md](docs/extending/implants.md) |
| A new C2 carrier, in-tree or out | [docs/extending/transports.md](docs/extending/transports.md) |
| A capability module against the seams -- official or community, one loading path | [docs/extending/modules.md](docs/extending/modules.md) |
| Stand-up, configuration, and the production runbook | [docs/operations/teamserver.md](docs/operations/teamserver.md) |
| The operator console's panels and fields | [docs/operations/operator-ui.md](docs/operations/operator-ui.md) |
| Redirector build, deploy, and rotation | [docs/operations/redirectors.md](docs/operations/redirectors.md) |
| The Android carrier leg -- build, emulator lab, devices | [docs/operations/android.md](docs/operations/android.md) |
| The pre-deployment rehearsal walk | [docs/operations/rehearsal.md](docs/operations/rehearsal.md) |
| Pre-foothold recon -- egress decisions and the scan's ROE gate | [docs/operations/recon.md](docs/operations/recon.md) |
| Delivery campaigns -- the egress decisions and the tracked lure | [docs/operations/campaigns.md](docs/operations/campaigns.md) |
| Agent tooling over the read side (MCP) | [docs/operations/mcp.md](docs/operations/mcp.md) |
| The opt-in LLM triage client | [docs/operations/llm.md](docs/operations/llm.md) |
| Open work, terminology, vulnerability reporting | [docs/todo.md](docs/todo.md), [docs/glossary.md](docs/glossary.md), [SECURITY.md](SECURITY.md) |

## Sensitive capabilities stay off by default

Exploit behavior, detection evasion, LSASS dumping, and input capture are
**pluggable capability contracts**: the core defines their interfaces and
dispatch and ships no concrete techniques or in-the-wild PoCs. Concrete
behavior arrives as modules -- official or community, both through the
same registry and loading path -- and every sensitive one stays
disabled until a build profile enables it
([architecture.md Sec 7, Sec 13, Sec 15](docs/architecture.md)).

Delivery (phishing, host interaction) is likewise out of scope: Rod
ingests the first callback and correlates it to the engagement. Rod
commands authorized targets; it is not a general-purpose platform.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
