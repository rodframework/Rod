# Range mode -- the simulated engagement

Operational runbook for range mode: standing a simulated engagement whose
implant fleet is the teamserver's own scripted beacons -- training crews,
shaking out operator workflows, and load-shaping a deployment before it
faces a client network -- against the real platform surface
([architecture.md](../architecture.md) Sec 15.3).

The beacons are protocol-real clients: they enroll through a listener's
real ingress, run the envelope POST cycle with canonical tasking
verification, and answer tasking whose results land in the same task log
and audit arcs any implant's do. Only the payload behind each verb is
simulated -- every answer says so. The roster, the task log, and the
timeline need no range-specific view; the fleet is a first-class citizen
of the action domain, which is the point.

## The evidence rule

A range engagement is marked at creation (`range: true`, immutable). The
mark rides the engagement everywhere its identity travels: the create
response, the roster listing, the report -- whose header carries the
range banner and whose integrity hash seals the mark -- and the audit
chain's genesis link. Simulated evidence can never read as a real
engagement's; nothing converts a range into a real engagement after the
fact.

## Standing one up

Range mode is default-off. Enable it in the deployment's configuration
and restart:

```json
{
  "Range": {
    "Enabled": true
  }
}
```

With the switch off, the range surface does not mount at all. With it
on, an operator session on the console (or the API token holding the
operate scope) drives the fleet:

1. **Create the range engagement** -- `POST /engagements` with
   `{"name": "Training Greenfield", "range": true}`. Spawning on an
   engagement that is not a range refuses with guidance; so does
   creating a fleet against a closed engagement.

2. **Create the listener** -- `POST /engagements/{id}/listeners` with
   transport `http`:

   ```json
   {"name": "range-front", "transport": "http",
    "bindAddress": "127.0.0.1:9543", "publicEndpoint": ""}
   ```

   A range fleet contacts over the cleartext lab posture -- plaintext
   framed bodies under the listener's own bind, identity by enrollment
   -- which is the http family's documented lab shape; a non-http
   listener refuses the spawn naming the reason. The fleet dials the
   bind, not the public endpoint: the range exercises the platform's
   full ingress path, and the one leg it cannot exercise from inside
   the process is the redirector hop in front of the bind.

3. **Spawn the fleet** -- `POST /engagements/{id}/range:spawn`:

   ```json
   {"listenerId": "<id>", "count": 500, "sleepSeconds": 5,
    "jitterSeconds": 2, "goDarkCount": 40, "prefix": "greenfield"}
   ```

   One multi-use deploy token is minted for the fleet (the audit
   `range-spawn` fact names the token; every simulated enrollment
   resolves back to it, attributing the whole fleet to the spawning
   operator). The beacons enroll in bounded waves -- a large fleet
   never lands as one spike -- then poll at their cadence.

4. **Read the posture** -- `GET /engagements/{id}/range`: enrolled,
   contacting, dark, and failed counts, contact and result totals, and
   the first few beacon errors if any. `POST .../range:stop` retires
   the loops; the trail stays exactly as it ran.

## What the fleet answers

The script answers the verbs a training engagement tasks most, in the
structured grammar the generic panels parse: `shell.exec` (clearly
labeled simulated output), `fs.list` (a file table), `proc.list` (a
process table), `recon.hostenum` (an enumeration finding that lands in
the topology view), and `beacon.sleep` -- a real retune, the beacon's
own cadence moves. Anything else refuses with the same grammar the real
implant's refusal uses (`no handler for the verb`).

`GoDarkCount` beacons (the last N of the fleet) go dark once and come
back as the same identities -- the beacon-lost-then-returning leg. The
default timings scatter across a minute so a standing fleet churns
naturally; `darkAfterSeconds` / `darkForSeconds` pin them exactly when
a trainer scripts the moment a beacon drops.

## Shaping load

A 500-beacon fleet at `sleepSeconds: 2` sustains on the order of two
hundred contacts a second against one teamserver on loopback hardware
(the acceptance test holds exactly this shape). Sleep and jitter are
the dials: cadence scales as `count / (sleep + jitter / 2)` contacts
per second. Enrollments arrive in waves of 48; a spawn of 500 lands
inside a few seconds on dev hardware.

The scale ceiling per spawn is 2000 beacons (the enrollment token's
budget); a bigger range is multiple listeners and multiple spawns --
though one engagement fields one fleet, and a respawn replaces it.

## The teardown

Stop the fleet, then the engagement's own close-out: freeze, export the
report (it carries the range banner and the simulated arcs), retire.
The report is the evidence that outlives the range -- and it says, in
its first breath, what it is.
