# Redirectors -- build, deploy, rotate

Operational runbook for the in-tree reference redirector, the **opaque L4 TCP
forwarder** that fronts a teamserver listener ([architecture.md](../architecture.md)
Sec 7 and Sec 8). The
forwarder source is at
[the redirector source](https://github.com/rodframework/Rod/tree/main/src/redirector/dotnet).

The reference redirector does one thing: accept a TCP connection on its public
endpoint and splice the byte stream to the listener's bind address, in both
directions, with correct half-close. It never terminates TLS, never inspects or
alters the payload, and never enforces engagement tenancy. That is the whole
point -- it carries the beacon channel and the HTTPS enroll request
through end to end, so the application-layer seal the security model
depends on is preserved intact.

This is the deploy/rotate half of the "Redirector deployment story." The
teamserver-side half -- repointing a listener's public endpoint without touching
the backend bind -- already ships. Together they let an operator swap
a burned redirector **end to end**: deploy a fresh forwarder, repoint the
listener, decommission the old host. No backend restart, no bind change, no
service interruption to live implants.

## 0. Enrolled mode (the control plane)

Everything below (Secs 1-6) is the **manual fleet**: a hand-deployed binary
with command-line rules, rotated by repointing the listener. The enrolled
mode (architecture.md Sec 8) is the same opaque forwarder driven by the
teamserver instead: the node dials home, receives its forwarding rules as
fronts attach to listeners, and rotation is a promote -- no manual binary
reconfiguration anywhere.

The flow:

1. **Mint a credential** on the console's Redirectors page (or
   `POST /redirectors/credentials` with a name). The secret is shown exactly
   once, rendered inside the complete `rod-redirector` invocation -- control
   URL and state path filled in, the scheme matching the console's own TLS
   posture -- so enrollment is a copy and a paste. Its name becomes the
   node's roster name.

2. **Run the node** pointed at the teamserver's shared tier:

   ```
   rod-redirector -control wss://teamserver.example:59443/redirectors/control \
                  -credential <secret> \
                  -state /var/lib/rod/redirector.state.json
   ```

   The credential enrolls exactly once; the minted node identity persists in
   the state file (chmod 600) and every later start omits `-credential`. The
   control channel must ride the shared tier (the operator front or a
   deliberate shared ingress) -- it is refused outright on any engagement's
   implant listener, so the engagement sockets never name a control surface.

3. **Attach a front** to a listener (the engagement's Listeners tab, or
   `POST /engagements/{id}/listeners/{listenerId}/fronts`): name the node,
   the endpoint it binds (e.g. `0.0.0.0:443`), and the public endpoint
   implants dial through it. The rule -- bind that endpoint, splice to the
   listener's bind -- reaches the node on its open control connection and
   the forwarder starts serving immediately. Attaching **primary** (or
   promoting later) makes the front the public endpoint new builds bake:
   that is the rotation op, the enrolled form of repointing.

4. **Rotate a burned node**: bring its replacement up the same way, attach
   its front, promote it. Detach (or retire) the burned one. No repoint, no
   binary restart on the survivor, no backend change.

5. **Retire a node** from the Redirectors page (or `POST /redirectors/{id}:retire`)
   when the machine leaves the deployment: its live control session closes
   and its next reconnect is refused by name. The machine's fronts detach
   like any other.

The node's data plane outlives the control link: a dropped connection
reconnects with capped backoff while the forwarders keep splicing the last
applied rules. A terminal refusal (a spent, revoked, or retired identity)
exits the process -- the operator intervenes, the node does not flap.

One DNS note: fronting a dns or doh listener rides the node's datagram
relay -- the front's public endpoint names the **resolver** implants dial
(a bare host or host:port; the zone stays the listener's own), and builds
against the fronted listener bake `dns://<resolver>/<zone>` from the
primary front. `ws://` instead of `wss://` is the lab posture --
production nodes dial the same TLS front the console rides.

## 1. Build the forwarder binary

The redirector targets a single static native binary with no runtime install
(architecture.md Sec 12.2). Publish it for the redirector host's RID:

```
dotnet publish src/redirector/dotnet/Rod.Redirector.csproj -r linux-x64 -c Release
# -> src/redirector/dotnet/bin/Release/net10.0/linux-x64/publish/rod-redirector
```

`PublishAot` is set in the csproj, so a `publish` with a RID is all it takes.
CI publishes the binary on every change to prove the AOT property holds. For a
non-`linux-x64` target, pass the matching RID (`linux-arm64`, etc.).

The published `rod-redirector` is a single ~2 MB stripped ELF with no runtime
dependency beyond libc -- copy just that one file to the host.

## 2. Deploy a redirector

Each redirector fronts exactly one listener on one port (v1 is single-rule per
process; multi-port fronting is one process per port). You need:

- The **public endpoint** implants should dial, e.g. `203.0.113.10:443` (the
  redirector host's address and the port you will listen on).
- The **upstream** -- the teamserver listener's bind address, e.g.
  `10.0.0.5:8443`. This is the address the forwarder splices to, and it must be
  reachable from the redirector host. It is *not* the public endpoint.

Copy the binary and run it:

```
rod-redirector -listen 0.0.0.0:443 -upstream 10.0.0.5:8443
```

Flags (each has an `ROD_*` env fallback; flags win over env):

| Flag        | Env           | Meaning                                                                  |
| ----------- | ------------- | ----------------------------------------------------------------------- |
| `-listen`   | `ROD_LISTEN`  | bind endpoint `host:port`; host may be `*` / `0.0.0.0` / `::` or an IP. |
| `-upstream` | `ROD_UPSTREAM`| teamserver listener endpoint `host:port`; host may be a DNS name.       |
| `-allow`    | `ROD_ALLOW`   | optional comma-separated source CIDR allow-list. Empty allows all.      |

`Ctrl-C` / `SIGTERM` stop the accept loop and let in-flight copies drain.

### Running under systemd

A minimal unit (`/etc/systemd/system/rod-redirector.service`) so the forwarder
restarts on crash and starts at boot:

```ini
[Unit]
Description=Rod redirector (L4 TCP forwarder)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/rod-redirector -listen 0.0.0.0:443 -upstream 10.0.0.5:8443
Environment=ROD_ALLOW=198.51.100.0/24
Restart=on-failure
# Run as an unprivileged user; the binary needs no special privileges for port
# 443 only if the host allows it (e.g. `sysctl net.ipv4.ip_unprivileged_port_start=443`
# or CAP_NET_BIND_SERVICE on the binary). Otherwise listen on a high port and
# NAT 443 to it at the firewall.
User=rod
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Firewall and allow-list

The redirector's `-allow` CIDR list is the only routing an L4 forwarder can do,
and it is a deployment-time tightening -- **not the security boundary**. The
real identity gate is the teamserver's per-artifact key (Sec 9): a contact
that does not verify under the artifact's seal is dropped regardless of
what the redirector forwarded. Use the host firewall and
`-allow` together to keep the redirector off public port-scans and to limit the
connection surface; treat engagement identity as the teamserver's job.

## 3. Wire the listener to the redirector

The listener's **public endpoint** is the address implants dial -- the
redirector. Its **bind address** is the socket the teamserver owns and the
redirector splices to. These are decoupled (Sec 8): set the listener's public
endpoint to the redirector host (`203.0.113.10:443` in the example above) and
leave the bind address as the upstream you passed to `-upstream`.

If the listener already exists, repoint it (see the rotation flow below). If you
are standing up a new listener, set its public endpoint to the redirector at
creation.

## 4. Verify the forwarder

Before pointing live traffic at a freshly deployed redirector, confirm it splices
both directions. First, confirm which tree the binary came from -- the build
stamps the version and exact source commit into the binary, so provenance is
read off the deployed artifact, not off deployment notes:

```
./rod-redirector -version
# -> rod-redirector 1.0.0 (commit <sha>)   -- must match the release tag the
#                                             binary was built from
```

The same pair is the first line the forwarder logs at startup. From a host that
can reach the redirector's public endpoint:

```
# The enroll route is HTTPS-protected, so a plain TCP connect is enough
# to prove the forwarder reached the teamserver's TLS listener:
openssl s_client -connect 203.0.113.10:443 -servername <expected-host>
# Expect a TLS handshake response from the teamserver listener (the redirector
# is transparent at L4).
```

From the teamserver side, `GET /engagements/{engagementId}/listeners` shows
the listener's `publicEndpoint`
pointing at the redirector and `state` healthy. New implants enrolled against the
redirector's endpoint should open sessions.

## 5. Rotate a burned redirector (the end-to-end swap)

This is the acceptance criterion for the "Redirector deployment story": a burned
redirector is swapped **end to end**, not just in the registry. The flow:

1. **Deploy the replacement** (redirector B) following Sec 2, pointed at the same
   upstream listener bind address. B is now serving on its own public endpoint
   (e.g. `198.51.100.20:443`) but nothing is dialed against it yet.

2. **Repoint the listener** to B. The teamserver-side half:

   ```
   POST /engagements/{engagementId}/listeners/{id}:repoint
   Content-Type: application/json

   { "publicEndpoint": "198.51.100.20:443" }
   ```

   The endpoint requires an authenticated operator session. The Kestrel bind is
   untouched; the registry's public-endpoint lookup now resolves B and no longer
   resolves A. New enrollments and new-beacon dials use B immediately.

3. **Verify** through B (Sec 4) and confirm live implants continue to beacon.
   Implants already connected through A keep their in-flight TCP connections
   until those connections close; the next dial goes to B because the listener's
   public endpoint has moved.

4. **Decommission the burned host (A):** stop the forwarder, tear down the host,
   revoke any credentials that lived on it. A no longer resolves to any
   listener, so even if an implant redials it, the connection goes nowhere -- the
   burned endpoint is severed, not just hidden.

No teamserver restart, no backend bind change, no service interruption: the only
thing that moved is the public endpoint implants dial.

## 6. Share 443 with a cover domain (external-proxy fronting)

One public address, one port that matters -- 443 -- and the engagement wants it
to serve a real site for a cover domain while the beacon channel rides the same
port under its own name. That is standard frontline proxy work -- SNI routing
with mismatch refusal -- and it belongs to a proxy in front of the forwarder,
not to the forwarder: the in-tree redirector stays a minimal mover and gains no
routing code for it (architecture.md Sec 8). Any L4 SNI switcher works; nginx's
`stream` module with `ssl_preread` is the worked example here.

One constraint shapes the whole setup: the front must not terminate TLS
for the beacon path. The per-artifact key sealing every contact body is
the identity (Sec 7), and a terminating hop the engagement does not
control sits between that key's endpoints for no gain -- the bodies are
ciphertext either way, so pass-through keeps the trust path short.
`ssl_preread` peeks at the ClientHello's SNI
extension and switches at L4 -- the TLS records, the ALPN h2 negotiation,
and the sealed bodies all carry through untouched, exactly as they do
through the redirector. The cover name is the one that terminates: it lands on
an ordinary HTTPS server holding the cover certificate, the only termination in
the picture.

With the front and the forwarder on the same host, the chain is:

```
implant (SNI c2.example.com)    --> front :443 --> rod-redirector 127.0.0.1:8443 --> teamserver listener
visitor (SNI cover.example.com) --> front :443 --> cover site 127.0.0.1:8080 (terminates, serves)
anything else (no/unknown SNI)  --> refused
```

Deploy the forwarder on a loopback port instead of 443 -- nothing about the
binary changes, only the `-listen` value (the systemd unit's `ExecStart` line
follows it):

```
rod-redirector -listen 127.0.0.1:8443 -upstream 10.0.0.5:8443
```

The front, nginx `stream` tier (`/etc/nginx/nginx.conf`; Fedora/RHEL ship the
module as `nginx-mod-stream` -- put `load_module modules/ngx_stream_module.so;`
at the top of the file -- Debian bundles it):

```nginx
stream {
    map $ssl_preread_server_name $backend {
        cover.example.com   127.0.0.1:8080;   # cover site's HTTPS server
        c2.example.com      127.0.0.1:8443;   # rod-redirector
        default             127.0.0.1:9;      # nothing listens there: mismatch refused
    }

    server {
        listen 443;
        ssl_preread on;        # peek SNI, never terminate
        proxy_pass $backend;   # IP:port values only, so no runtime resolver is needed
    }
}
```

And the cover site itself, the same nginx `http` tier:

```nginx
http {
    server {
        listen 127.0.0.1:8080 ssl;
        server_name cover.example.com;
        ssl_certificate     /etc/nginx/certs/cover.crt;
        ssl_certificate_key /etc/nginx/certs/cover.key;
        root /var/www/cover;
    }
}
```

Pointing `default` at a dead port is the refusal: nginx cannot connect
upstream and drops the client, so a probe with no SNI, a wrong name, or a
domain-fronting-shaped guess gets nothing. (Sending `default` to the cover
backend instead is the other stance -- an unnamed probe then sees the site,
not a reset; pick one deliberately.)

Because the front now owns the public port, three consequences:

- **The listener's public endpoint must be the C2 hostname on 443**
  (`c2.example.com:443`), not a bare IP: the implant's TLS stack sends SNI
  from the host it dials, and that is what the front routes on. The reference
  implant does this by construction -- both the enroll client and the beacon
  channel derive SNI from the URL host -- so no profile or build change is
  needed.
- **Source filtering moves to the front.** The forwarder's `-allow` now sees
  the front's address (loopback here), not the implant's real source; leave it
  empty and filter at the front (nginx `allow`/`deny` on the stream `server`)
  or the host firewall, as before.
- **Rotation is untouched.** The front is just another hop in front of the
  forwarder: swap the whole front by repointing the listener to the new host's
  endpoint (Sec 5), or swap only the forwarder by editing the front's map
  entry. A burned *name* is severed by repointing exactly the way a burned
  host is.

Verification is Sec 4's probe with the SNI spelled out:

```
openssl s_client -connect 203.0.113.10:443 -servername c2.example.com
# Expect the teamserver listener's handshake (front -> forwarder -> listener);
# -servername cover.example.com returns the cover site's certificate, and a
# bogus or absent SNI drops the connection.
```

HAProxy's `tcp` mode with SNI content rules or an edge CDN's TCP pass-through
tier are drop-in equivalents. A front that terminates TLS for the C2 name
sees only the sealed contact bodies -- ciphertext either way -- but adds
a hop the engagement does not control; keep termination at the teamserver
unless the deployment knowingly chooses an edge (Sec 7, architecture.md
Sec 9).

### Two C2 domains on one listener

A second engagement domain that should ride the *same* teamserver bind port is
the same fronting picture with a second C2 name instead of a cover name -- and
the one-listener model makes the constraint worth spelling out:

- **A listener is one bind with one public endpoint.** Creating a second
  listener on a port already bound is refused (bind conflict), and pointing a
  second domain's DNS at the same bind does not work for the pinned-trust
  shape: the teamserver's leaf names the listener's *stored* public host in
  its SAN, so an implant dialing the other domain fails name verification.
- **Same DNS story, cleartext http:** there is no certificate constraint, so
  both domains may point at the one listener; repoint it to choose which name
  new builds bake (implants already deployed keep dialing the name they
  baked).
- **The multi-domain answer is the fronting tier.** Both domains terminate at
  an edge that holds their certificates -- the same `ssl_preread` map with a
  second C2 entry forwarding to the forwarder (pinned trust: the edge must
  *not* terminate, so the two names need two teamserver listeners, each
  naming its own host) -- or the edge terminates per domain and forwards to
  the one teamserver listener, whose **Certificate** posture is set to
  `public` so builds against it validate the real chain
  (architecture.md Sec 9). The rotation story is unchanged: a burned name is
  severed by repointing its listener, a burned front by swapping the map
  entry.

## 7. Security notes

- **The redirector is an untrusted edge.** It has no teamserver credentials, no
  engagement keys, and no access to the payload beyond the opaque bytes it
  forwards -- which are TLS-protected in transit. Treat it as disposable: a
  compromised redirector should yield nothing but a TCP splice. (The future
  Sealing layer, Sec 9, will make this explicit end to end.)
- **Identity is the teamserver's job.** The per-artifact key authenticates
  the implant at the application layer; the redirector cannot and does not
  participate. A hop that cannot see the key cannot forge it -- which is
  exactly why the seal, not the transport, carries the trust.
- **Allow-list hygiene.** Keep `-allow` as tight as the engagement permits and
  revisit it when the source ranges change. An empty allow-list (allow all) is
  acceptable when a host firewall already restricts the source; do not run both
  open.
- **One process per port.** Each fronted port is its own process (Sec 8). A
  burned port takes down only that process; the others keep serving.
- **No payload awareness, by design.** This forwarder cannot do malleable
  `User-Agent`/URI routing or serve a cover site, because all of that lives
  inside TLS and is invisible at L4. A deployment that needs L7 routing
  terminates TLS at its own edge, in front of (or instead of) this forwarder --
  an operator deployment concern, not an in-tree capability (architecture.md
  Sec 8). Sharing 443 with a cover domain stays within the L4 discipline: the
  SNI fronting pattern (Sec 6) switches on the ClientHello's name and
  terminates nothing on the beacon path.

## See also

- [architecture.md Sec 8](../architecture.md) -- the redirector design
  decision (L4 opaque forwarder, Native AOT, alternatives considered).
- [architecture.md](../architecture.md) Sec 7 and Sec 8 -- transports,
  listeners, and the redirector abstraction.
- [The redirector's own README](https://github.com/rodframework/Rod/blob/main/src/redirector/dotnet/README.md)
  -- flags, env, and build for the forwarder binary.
