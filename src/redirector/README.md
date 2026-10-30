# Rod.Redirector -- reference .NET Native AOT redirector

The in-tree **reference redirector** for Rod
([architecture.md Sec 8](../../../docs/architecture.md)). It is a
near-stateless, **opaque L4 TCP forwarder**: an implant dials this redirector's
public endpoint, and the redirector splices the byte stream to the teamserver
listener's bind address without inspecting or altering it.

Because it forwards at L4, the **mTLS beacon channel** (HTTP/2 + client cert)
and the **HTTPS enroll request** both pass through end to end -- the redirector
never terminates transport, so it cannot break the client-certificate
authentication the beacon depends on. This is benign plumbing (socat/rinetd
semantics; mainstream under the architecture.md Sec 13 tradecraft boundary),
with no evasion and no payload awareness.

A burned redirector is swapped by deploying a fresh one and **repointing the
listener** (`POST /listeners/{id}:repoint`); this binary is the missing half of
that rotation, the teamserver-side repoint being the other. The
end-to-end runbook lives in
[docs/operations/redirectors.md](../../../docs/operations/redirectors.md).

This project is a **standalone deployable** with no in-house references -- it is
coupled to the teamserver only by the TCP stream it forwards. It ships in
`Rod.slnx` (unlike the reference implant, which is external because the
teamserver build unit compiles it per payload-build request) so it gets central
build, test, and format coverage.

## Build

Normal build and unit tests run with the rest of the solution:

```
dotnet build Rod.slnx --configuration Release
dotnet test Rod.slnx --configuration Release --no-build
```

The redirector targets a single static native binary with no runtime install
(architecture.md Sec 12.2).
Publish the Native AOT binary for a target:

```
dotnet publish src/redirector/dotnet/Rod.Redirector.csproj \
  -r linux-x64 -c Release
# -> bin/Release/net10.0/linux-x64/publish/rod-redirector
```

`PublishAot` is set in the csproj, so `publish` with a RID produces the native
binary. CI publishes it on every change to prove the AOT property holds.

## Run

Manual mode (one hand-configured rule):

```
rod-redirector -listen 0.0.0.0:443 -upstream teamserver.internal:8443
rod-redirector -listen *:443 -upstream teamserver.internal:8443 -allow 10.0.0.0/8,192.168.0.0/16
```

Enrolled mode (rules arrive from the teamserver's control plane,
architecture.md Sec 8; the runbook's Sec 0 walks the whole flow):

```
rod-redirector -control wss://teamserver:59443/redirectors/control \
               -credential <enrollment secret> \
               -state /var/lib/rod/redirector.state.json
```

| Flag           | Env              | Meaning                                                                  |
| -------------- | ---------------- | ----------------------------------------------------------------------- |
| `-listen`      | `ROD_LISTEN`     | bind endpoint `host:port`; host may be `*` / `0.0.0.0` / `::` or an IP. |
| `-upstream`    | `ROD_UPSTREAM`   | teamserver listener endpoint `host:port`; host may be a DNS name.       |
| `-allow`       | `ROD_ALLOW`      | optional comma-separated source CIDR allow-list. Empty allows all.      |
| `-control`     | `ROD_CONTROL`    | control channel URL (`ws://`/`wss://`) on the teamserver's shared tier -- selects enrolled mode. |
| `-credential`  | `ROD_CREDENTIAL` | enrollment credential, presented once; the minted identity persists in the state file. |
| `-state`       | `ROD_STATE`      | where the node identity lives (default `rod-redirector.state.json`; the file carries the node secret). |

The two modes are exclusive: enrolled mode takes no manual flags. Flags win
over env. `Ctrl-C` / `SIGTERM` stop the accept loop and drain; in enrolled
mode a dropped control link reconnects with capped backoff while the
forwarders keep serving the last applied rules, and a terminal refusal
(spent, revoked, retired) exits the process.

## What it does and does not do

- **Does:** forward opaque TCP bytes in both directions with correct half-close,
  so request/response (enroll) and bidirectional (beacon) traffic carry through
  unchanged; optionally restrict sources by CIDR.
- **Does not:** terminate TLS, read or alter payloads, route by URI or
  User-Agent, or enforce engagement tenancy (those are teamserver/edge concerns;
  the malleable `User-Agent`/URI routing of Sec 7 is a TLS-terminating-edge
  deployment concern; see architecture.md Sec 8).
