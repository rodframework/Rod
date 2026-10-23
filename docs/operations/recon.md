# External recon workbench (pre-foothold scoping)

The teamserver carries an operator-layer workbench for the scoping that
precedes the first foothold (architecture.md Sec 11.4): RDAP registration
lookups, certificate-transparency subdomain enumeration, and a port scan --
run on the teamserver, engagement-scoped, their findings landed as
engagement artifacts that join the intel layer's topology projection. This
runbook covers the egress decisions an operator makes before arming each
half, the configuration, the ROE target scope that gates the scan, and what
lands in the audit trail.

Four routes, all task scope, all refused on a closed engagement:

```
POST /engagements/{engagementId}/recon:rdap        {"target": "example.com"}
POST /engagements/{engagementId}/recon:subdomains  {"target": "example.com"}
POST /engagements/{engagementId}/recon:resolve     {"target": "www.example.com"}
POST /engagements/{engagementId}/recon:resolve     {"targets": ["a.example.com", "b.example.com"]}
POST /engagements/{engagementId}/recon:portscan    {"target": "10.0.0.5", "ports": "22,80,443"}
```

## The egress decisions come first

Even a passive lookup leaves the teamserver under its own address carrying
the target's name. Which services the workbench rides is the operator's
call, never a silent default: each half stays closed (its route answers
`503` naming the configuration section) until its service is named.

- **RDAP** (`Recon:RdapBaseUrl`) -- the registration-data egress. A public
  redirector (for example `https://rdap.org`) resolves the right registry
  per query and sees every lookup; a registry-direct endpoint (for example
  `https://rdap.verisign.com/com/v1`) narrows what any one party observes
  but only serves its own zone; a fronted mirror (an operator-run proxy in
  front of either) keeps the teamserver's address off the service's logs
  entirely. Pick per engagement, per OPSEC posture.
- **Certificate transparency** (`Recon:CtBaseUrl`) -- the subdomain census
  rides the crt.sh JSON shape (`{base}/?q=%.{domain}&output=json`); crt.sh
  itself or any mirror answering that shape serves it. The same
  direct-or-fronted tradeoff applies, plus volume: a CT mirror is a public
  service under no engagement's control, so front it when the census
  itself should not read as reconnaissance from your address.
- **The resolver** (`Recon:DohBaseUrl`) -- resolution rides
  DNS-over-HTTPS, not the host's resolver: the JSON answer shape Google's
  and Cloudflare's endpoints both serve
  (`GET {base}?name={name}&type={type}`), so `https://dns.google/resolve`
  or `https://cloudflare-dns.com/dns-query` work as-is, and a fronted
  mirror keeps the teamserver's questions off the public resolver's logs.
  Whose resolver answers is part of the engagement's OPSEC story -- a
  target-adjacent resolver sees your census's follow-up.
- **Whois** (`Recon:WhoisServer`, port 43) -- the fallback behind the
  RDAP flag for registries that never built RDAP (much of the ccTLD
  world). One query per lookup, the answer captured verbatim, no
  referral chasing: a server that hands back a referral names it in the
  captured text, and an operator chasing one re-runs against that
  server. Plain TCP, no TLS -- whois is a 1980s protocol and its egress
  is readable on the wire, which is one more reason it is the fallback
  and not the primary.
- **The scan's origin** (`Recon:ScanOrigin`) -- where the scan's
  connections egress from is its own decision, separate from the lookups.
  The only origin this teamserver ships is `Teamserver`: the scan dials the
  target directly from the teamserver process. That is the honest default
  shape for a lab or a controlled engagement network, and the wrong shape
  the moment the target's edge should not see the teamserver's address --
  in that posture, scope with the passive halves and scan through an
  implant already inside (`recon.portscan` tasking) instead. Any other
  origin value is refused with a `503` naming this runbook: a
  redirector-originated scan is a future choice with its own decision, not
  a fallback.

The scan is additionally gated on the engagement's ROE target scope
(architecture.md Sec 9, below); the passive lookups are deliberately not --
the target scope is often what the lookup is building, so gating the lookup
on the scope it informs would deadlock the scoping flow.

## Configuration

| Key | Default | Meaning |
|-----|---------|---------|
| `Recon:RdapBaseUrl` | -- | The RDAP service (`{base}/domain/{name}`). Unset: the route answers `503`. |
| `Recon:CtBaseUrl` | -- | The CT mirror answering the crt.sh JSON shape. Unset: `503`. |
| `Recon:DohBaseUrl` | -- | The DoH resolver (`GET {base}?name=&type=`, JSON answers). Unset: `503`. |
| `Recon:WhoisServer` | -- | The whois fallback server, `host` or `host:port` (43 when unnamed). Unset: RDAP registry-misses stay failed runs. |
| `Recon:ScanOrigin` | -- | `Teamserver` arms the scan; unset or any other value keeps it at `503`. |
| `Recon:RequestTimeoutSeconds` | `30` | Per-request budget for the passive lookups. |
| `Recon:MaxSubdomainNames` | `5000` | How many distinct names one enumeration records. |
| `Recon:MaxResolveTargets` | `256` | How many names one resolution request may carry. |
| `Recon:ResolveConcurrency` | `32` | How many names a bulk resolution queries at once. |
| `Recon:ScanConnectTimeoutMilliseconds` | `1500` | Per-port connect budget. |
| `Recon:ScanConcurrency` | `128` | How many ports one scan probes at once. |
| `Recon:ScanMaxPorts` | `4096` | How many ports one request may name; a full-range sweep is several requests. |

Example (environment):

```
Recon__RdapBaseUrl=https://rdap.org
Recon__CtBaseUrl=https://crt.sh
Recon__DohBaseUrl=https://cloudflare-dns.com/dns-query
Recon__WhoisServer=whois.iana.org
Recon__ScanOrigin=Teamserver
```

## The scan's ROE target scope

The port scan is the workbench's active half, so it carries the gate the
passive lookups skip: the engagement's ROE profile
(`PUT /engagements/{id}/roe`) gains `permittedTargets`, and a scan naming
a target outside it is refused with `422` before any connection opens,
the refusal recorded in the trail as a `ReconScanRefused` event naming the
violated rule.

Entry shapes, each matching only its own kind of target:

- **Exact hostname**, case-folded (`web01.example.com`).
- **Exact IP** (`203.0.113.10`).
- **CIDR block** (`10.0.0.0/24`, IPv4 or IPv6); an entry with a `/` that
  does not parse as a network is refused at the apply route -- a mistyped
  CIDR that silently matched nothing would narrow the scope to zero.

An empty list means unrestricted. A hostname matches by name only, never by
resolution: a DNS answer is not an authorization fact, and the scope must
not depend on what the target's own nameservers say. Symmetrically, a CIDR
entry never matches a hostname target -- resolve first and name the
address, or list the name.

## Findings and audit

Every run lands its findings as a task-less engagement artifact under the
acting operator's attribution -- pre-foothold there is no task to join --
and every attempt in the trail:

- `recon:rdap` -- a JSON registration record (registrar, status, dates,
  nameservers, secureDNS), artifact `recon.rdap:{domain}`, event
  `ReconLookupCompleted`. When the registry has no record and
  `Recon:WhoisServer` is set, the whois answer is captured verbatim
  instead (artifact `recon.whois:{domain}`, text/plain) and the event's
  lookup name reads `rdap>whois`.
- `recon:subdomains` -- JSON lines, one `{"host": name}` per name, the
  documented recon grammar (extending/modules.md), artifact
  `recon.subdomains:{domain}`, event `ReconLookupCompleted`. The names join
  the topology projection as observed hosts; wildcard certificate literals
  name no concrete host and are not findings.
- `recon:resolve` -- JSON lines, one `{"host": name,
  "addresses": [...]}` (the hostenum shape, a `cname` field along for
  alias chains) per name that answered; an IP target records its PTR
  name. A single negative (NXDOMAIN, no PTR) is a failed run naming the
  negative; a bulk run counts its misses in the summary and records only
  the names that live. The addresses join the topology projection beside
  the hosts they name. Event `ReconLookupCompleted`, artifact
  `recon.resolve:{name}` / `recon.resolve:{n}-names`.
- `recon:portscan` -- JSON lines, one `{"host": h, "port": p,
  "state":"open"}` per open port (closed and filtered ports are not
  findings), artifact `recon.portscan:{host}:{ports}`, event
  `ReconScanCompleted`. The default port set (no `ports` named) is a
  curated stable list; name `ports` as a comma list with hyphen ranges
  (`22,80,443`, `1-1024`) for anything else.

The audit payload names the lookup and the target but never the egress
endpoint -- configuration names the endpoint, this runbook the decision.
The outcome is the findings artifact id on success, `failed:{reason}` on
failure; the refusal the ROE gate causes is its own `ReconScanRefused`
event. The findings appear in the operator UI's Recon tab (the run form beside
its findings list, each artifact rendered by its shape), in the loot
view (task-less, attributed to the running operator), and in the
topology projection beside implant-side recon.

## The target list

Findings are evidence; a **recon asset** is a target the engagement chose
to track (architecture.md Sec 15.4). Three routes keep the list:

- `GET /engagements/{id}/recon-assets` -- the list, the picker a campaign
  create selects from.
- `POST /engagements/{id}/recon-assets` -- record a target: `kind`
  (`email`, `domain`, `host`, `address`), `value` (cased to the list's
  own rule), optional `displayName` (the merge name a campaign selection
  defaults to), and optional `sourceArtifactId` -- the findings artifact
  the target was lifted from, its provenance on the row. Identity is
  `(engagement, kind, value)`: the same address twice is one target, and
  the second recording is a 409 naming the row that already carries it.
- `DELETE /engagements/{id}/recon-assets/{assetId}` -- remove a target.
  Refused (409) while a campaign recipient still references it: the
  recipient row's reference is the record of the engagement aiming at
  the target, and the composite foreign key behind it is what refuses.

An `email` asset selects directly as a campaign target -- the create's
recipient entry names `reconAssetId` instead of typing the address, the
address and display name resolve onto the recipient row at creation, and
the row keeps them even if the asset later goes (see
[campaigns.md](campaigns.md)). The network kinds serve the recon picture
and future consumers; they are not mail targets and a campaign create
refuses them (422). Recording and deletion are `ReconAssetRecorded` /
`ReconAssetDeleted` facts on the engagement trail; both are refused while
the engagement is closed.

## Evolution notes

- **Redirector- or implant-originated scans** arrive as new `ScanOrigin`
  choices with their own decisions recorded here, not as changes to the
  route. An implant-originated scan already exists as ordinary
  `recon.portscan` tasking from inside; a redirector-originated one has a
  real design bill -- the reference redirector is an opaque L4 splice
  with no control channel, so originating dials from it means a control
  contract between teamserver and redirector.
- **Reverse-whois** (registrant-driven discovery) would be a fifth
  passive half, but no public reverse-whois service rides a stable open
  contract; it reopens when one does.
