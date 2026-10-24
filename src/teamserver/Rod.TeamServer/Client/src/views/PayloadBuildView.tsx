import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  type BuildJob,
  type ListenerSummary,
  type PayloadSummary,
  enqueueBuildJob,
  listBuildJobs,
  listListeners,
  listPayloads,
  revokeDeployToken,
} from '../api'
import { frontFor, hostPortOf } from '../fronts'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'
import { fmtBytes } from '../format'
import { StatusBadge } from '../components/StatusBadge'
import { WebShellGenerateForm } from '../components/WebShellGenerateForm'

// The payload-build panel -- the artifact factory's operator face. The main
// path is the mainstream shape (Cobalt Strike's package dialog, Sliver's
// generate): name the listener the implant dials and the target it runs on,
// leave everything else at its default, and build -- the artifact is a
// self-contained executable with its enrollment credential baked in, so
// "drop it on the target and run" needs no arguments. Everything an
// operator sets rarely -- the malleable wire knobs (fallbacks, paths,
// headers-adjacent fields, envelope) and the credential window -- folds
// into the Advanced disclosure, defaulted server side, so the form never
// makes an operator read a knob they will not touch. The tab's second
// artifact kind is the web-shell script: the same
// prepare-then-place flow as the classic managers, rendered by the
// WebShellGenerateForm beside the implant form under one toggle.
//
// The form offers only what the pipeline actually delivers: the in-tree Rust
// unit (no language picker for units that are not registered), the full
// implant alone (the stager class retired with the .NET trees, delivery
// rides the launcher one-liners, so no class picker either), this
// engagement's family listeners (http/https/tcp/dns/doh all serve
// enrollment; only the shell catcher greys out), and the target set the
// Rust unit compiles (linux amd64/arm64/arm/x86, windows amd64/x86,
// android arm64/amd64 -- the carrier legs; macOS needs the Apple SDK and
// Windows ARM has no triple, so neither is offered).
// Interactive needs no second listener: every front carries its own
// contacts -- the envelope POST cycle for poll, the WebSocket beacon for
// stream, the socket family's held session.
//
// The build runs as a server-side job: submitting queues it and returns
// immediately; the recent-builds list below is the in-process view of the
// queue (fetched on mount, polled while anything runs), so leaving the page
// or refreshing never loses a running build. The strip shows the last few
// jobs as the queue's status -- for the artifact record (fronts, credential
// budgets, every build that ever finished) the durable home is the Payloads
// tab, which is also why a deleted payload reads "deleted" here instead of
// offering a download the store can no longer serve.

// How many jobs the queue strip shows; the rest is history the Payloads tab
// owns better.
const RECENT_BUILDS_SHOWN = 5

// The transports an implant can enroll through -- the HTTP-shaped fronts,
// the socket family (enrollment over the stream contact), and the DNS
// family (enrollment over DNS: the chunked TXT exchange a DNS-only target
// runs); the listener select offers these and greys everything else out.
const ENROLL_TRANSPORTS = new Set(['http', 'https', 'tcp', 'dns', 'doh'])

// The arch set per OS the Rust build unit maps onto a cargo triple (musl
// for Linux, GNU for Windows, the NDK bionic cross for Android). macOS
// needs the Apple SDK to link and Windows ARM has no GNU target, so
// neither is offered; Android pairs arm64 devices with amd64 -- the
// emulator the lab proves the leg on. The form lists exactly what
// compiles, the same rule the class and listener picks follow.
const ARCHS: Record<string, string[]> = {
  linux: ['amd64', 'arm64', 'arm', 'x86'],
  windows: ['amd64', 'x86'],
  android: ['arm64', 'amd64'],
}

// Whether a listener's dial is TLS (an https-family transport, or an
// absolute https public endpoint on an edge-fronted cleartext listener) --
// the dial that must present the front's own certificate posture.
function dialHttps(l: ListenerSummary): boolean {
  return (
    l.transport === 'https'
    || l.transport === 'mtls'
    || /^https:\/\//i.test(l.publicEndpoint.trim())
  )
}

function elapsed(job: BuildJob): string {
  const start = new Date(job.startedAt ?? job.requestedAt).getTime()
  const end = job.completedAt ? new Date(job.completedAt).getTime() : Date.now()
  const seconds = Math.max(0, Math.round((end - start) / 1000))
  return seconds >= 60 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${seconds}s`
}

export function PayloadBuildView({
  engagementId,
}: {
  engagementId: string
}) {
  // The tab's two artifact kinds share the card: the implant build form
  // (the pipeline's jobs) and the web-shell script generator (instant
  // render, no job). One toggle, one mental model -- this is where
  // artifacts are made.
  const [artifact, setArtifact] = useState<'implant' | 'webshell'>('implant')
  // The implant pipeline's own tier pick: the full implant, or the loader
  // that fetches and runs a stored implant from memory (the sealed
  // payload rides the loader's per-build key; the Launchers tab delivers
  // the loader with the same one-liner families).
  const [tier, setTier] = useState<'implant' | 'loader'>('implant')
  const [deliversPayloadId, setDeliversPayloadId] = useState('')
  const [targetOs, setTargetOs] = useState('linux')
  const [targetArch, setTargetArch] = useState('amd64')
  // The android carrier's deployment shape: the installable package by
  // default, the bare library when an engagement's own carrier loads it.
  // Every other target leaves format empty -- the exe spellings are
  // synonyms over the same binary, and the disk-or-memory choice is the
  // launcher step's.
  const [apkFormat, setApkFormat] = useState<'apk' | 'so'>('apk')
  const [listenerId, setListenerId] = useState('')
  const [listeners, setListeners] = useState<ListenerSummary[]>([])
  // Poll is the default posture: every front family carries it, and a held
  // connection is a standing detection signal an operator opts into, not
  // out of.
  const [mode, setMode] = useState('poll')
  const [sleepSeconds, setSleepSeconds] = useState('30')
  const [jitterSeconds, setJitterSeconds] = useState('10')
  const [killDate, setKillDate] = useState('')
  const [tokenMaxUses, setTokenMaxUses] = useState('1')
  const [revoking, setRevoking] = useState<string | null>(null)
  const [jobs, setJobs] = useState<BuildJob[]>([])
  // The payload library, fetched beside the jobs so the strip knows which
  // finished artifacts still exist (a deleted payload reads "deleted"
  // instead of offering a download that would 404) and reads each baked
  // token's live state -- the budget a revoke or an enrollment moves.
  const [library, setLibrary] = useState<PayloadSummary[]>([])
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  // The Advanced disclosure's fields; every one defaults server side, so they
  // ride empty unless the operator opens the section and fills them.
  // Fallbacks come from the inventory, not free text: the ordered ids of the
  // engagement's same-family listeners picked as walked fallbacks.
  const [fallbackIds, setFallbackIds] = useState<string[]>([])
  const [enrollPath, setEnrollPath] = useState('')
  const [userAgent, setUserAgent] = useState('')
  const [requestTimeoutSeconds, setRequestTimeoutSeconds] = useState('')
  const [envelope, setEnvelope] = useState('AesGcm')
  const [contactProtection, setContactProtection] = useState(true)
  const [tokenHours, setTokenHours] = useState('')


  // Every web front carries its own contacts -- the envelope POST cycle
  // for poll, the WebSocket beacon for stream -- so one listener is always
  // the whole story.
  const selectedListener = listeners.find((l) => l.id === listenerId)

  // The poll-only family: DNS/DoH carry no live stream to hold -- one
  // answer per poll -- so stream mode is incoherent on them and the form
  // keeps the mode honest (the server refuses the pairing with the same
  // fix). The socket family (TCP) bakes either mode: stream holds the
  // live session, poll cycles one connection per contact.
  const pollOnly =
    selectedListener?.transport === 'dns' || selectedListener?.transport === 'doh'

  useEffect(() => {
    if (pollOnly && mode === 'stream') setMode('poll')
  }, [pollOnly, mode])

  // The loader tier's client-side shape of the server's gates: a Linux
  // memfd artifact on the two arches its crate compiles, dialing a
  // cleartext http front (no TLS in the tier; any host shape dials).
  // The server refuses anything else with the same rules; these
  // keep the form from offering a build it would reject.
  const loaderTier = tier === 'loader'
  useEffect(() => {
    if (loaderTier && targetOs !== 'linux') setTargetOs('linux')
  }, [loaderTier, targetOs])
  useEffect(() => {
    if (loaderTier && !['amd64', 'arm64'].includes(targetArch)) setTargetArch('amd64')
  }, [loaderTier, targetArch])
  // The loader's dial test: the picked front must be an http listener --
  // any host shape dials (literal v4/v6 or a name the loader resolves).
  const loaderFrontOk = !loaderTier || selectedListener?.transport === 'http'
  // The delivery picker's offer: this engagement's stored implants (a
  // loader delivers the implant tier, never another loader).
  const deliverable = library.filter((p) => !p.deliversPayloadId && p.kind !== 'loader')

  const num = (value: string): number | null => {
    const trimmed = value.trim()
    if (trimmed === '') return null
    const parsed = Number(trimmed)
    return Number.isFinite(parsed) ? parsed : null
  }

  // The scheme families the egress walk serves -- the server's own rule:
  // the web pair, the DNS pair, and the raw socket. Fallbacks dial the
  // front's family only, so both the picker and the chips stay inside it.
  const familyOf = (transport: string): string =>
    transport === 'http' || transport === 'https' ? 'web'
      : transport === 'dns' || transport === 'doh' ? 'dns'
        : transport === 'tcp' ? 'tcp' : ''

  // The front's family: the picked listener's transport.
  const frontFamily = selectedListener ? familyOf(selectedListener.transport) : ''

  // The certificate posture a build against the picked front bakes (the
  // listener owns the fact; the build inherits it) and the TLS-dial test
  // that decides whether a candidate front's posture must agree: cleartext
  // dials need no roots, TLS dials must present the front's own posture or
  // the walk cannot verify them.
  const frontPosture = selectedListener?.trustPosture || 'pinned'

  // The dial a picked fallback bakes -- the same normalization the server
  // applies when the listener itself is named: an absolute public endpoint
  // stands as typed, a bare one completes under the transport's scheme, and
  // the DNS family's dial names the listener's own bind as the resolver
  // with its public endpoint as the zone.
  const dialOf = (l: ListenerSummary): string => {
    const pub = l.publicEndpoint.trim()
    if (l.transport === 'dns' || l.transport === 'doh') {
      const zone = pub.replace(/\.+$/, '').toLowerCase()
      return `${l.transport}://${l.bindAddress.trim()}/${zone}`
    }
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(pub)) return pub
    return `${l.transport}://${pub}`
  }

  // A wildcard-bound DNS listener names no resolver an implant can dial --
  // the same refusal the named-listener path applies -- so it stays off the
  // fallback offer.
  const wildcardBound = (l: ListenerSummary): boolean =>
    (l.transport === 'dns' || l.transport === 'doh')
    && /^(0\.0\.0\.0:|\[::\]:|:::)/.test(l.bindAddress.trim())

  // The picker's offer and the picked chips, both held to the front's own
  // family; a changed front filters the picks for free (an id its family no
  // longer serves resolves to no chip and bakes nothing).
  const eligible = useMemo(
    () => listeners.filter((l) =>
      l.id !== listenerId
      && familyOf(l.transport) === frontFamily
      && !wildcardBound(l)
      && (!dialHttps(l) || (l.trustPosture || 'pinned') === frontPosture)),
    [listeners, listenerId, frontFamily, frontPosture],
  )
  const picked = useMemo(
    () => fallbackIds
      .map((id) => eligible.find((l) => l.id === id))
      .filter((l): l is ListenerSummary => l !== undefined),
    [fallbackIds, eligible],
  )

  const movePick = (id: string, delta: number) => {
    setFallbackIds((prev) => {
      const from = prev.indexOf(id)
      const to = from + delta
      if (from < 0 || to < 0 || to >= prev.length) return prev
      const next = [...prev]
      ;[next[from], next[to]] = [next[to], next[from]]
      return next
    })
  }

  const refreshJobs = useCallback(async () => {
    try {
      const [list, library] = await Promise.all([
        listBuildJobs(engagementId),
        // A completed job's artifact can be deleted from the library at any
        // time; the strip re-reads the ids with every refresh so the
        // deleted/readable split stays current. The library load failing
        // degrades to "download" -- the click itself reports the 404.
        listPayloads(engagementId).catch(() => []),
      ])
      setJobs(list)
      setLibrary(library)
    } catch {
      // Keep the last known list; the next poll retries.
    }
  }, [engagementId])

  useEffect(() => {
    void refreshJobs()
  }, [refreshJobs])

  const libraryIds = useMemo(() => new Set(library.map((p) => p.artifactId)), [library])

  const active = jobs.some((j) => j.state === 'queued' || j.state === 'running')

  // This engagement's own listeners, the ingress a build can name. Loaded on
  // mount; the engagement's listeners panel is where they are created.
  useEffect(() => {
    void (async () => {
      try {
        setListeners(await listListeners(engagementId))
      } catch {
        // Without the inventory the form has nothing to offer: the empty
        // select says so, and the next mount retries.
      }
    })()
  }, [engagementId])

  // One pickable listener preselects itself on first load: with exactly one
  // front there is nothing to choose between. Only once -- after the user
  // has chosen (or deliberately chosen none), the preselect never fights
  // them again by snapping a deselected listener back into place.
  const preselected = useRef(false)
  const pickable = useMemo(
    () => listeners.filter((l) => ENROLL_TRANSPORTS.has(l.transport)),
    [listeners],
  )
  useEffect(() => {
    if (preselected.current || listeners.length === 0 || listenerId) return
    if (pickable.length === 1) setListenerId(pickable[0].id)
    preselected.current = true
  }, [pickable, listenerId, listeners.length])

  // Poll only while a job is in flight -- the list is otherwise quiet, and a
  // completed build changes nothing until the next submit.
  const timer = useRef<number | null>(null)
  useEffect(() => {
    if (!active) {
      if (timer.current !== null) {
        window.clearInterval(timer.current)
        timer.current = null
      }
      return
    }
    timer.current = window.setInterval(() => void refreshJobs(), 2000)
    return () => {
      if (timer.current !== null) {
        window.clearInterval(timer.current)
        timer.current = null
      }
    }
  }, [active, refreshJobs])

  const onRevokeToken = async (tokenId: string) => {
    if (!window.confirm(`Revoke baked token ${tokenId.slice(0, 8)}? The credential stops working immediately; a deployed artifact that has not enrolled yet will not be able to.`))
      return
    setRevoking(tokenId)
    try {
      await revokeDeployToken(engagementId, tokenId)
      setError(null)
      await refreshJobs()
    } catch (e) {
      setError(String(e))
    } finally {
      setRevoking(null)
    }
  }

  const onBuild = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!listenerId) {
      setError('Pick a listener (create one in the listeners panel first).')
      return
    }
    if (loaderTier && !loaderFrontOk) {
      setError('The loader dials a cleartext http front -- pick an http listener.')
      return
    }
    if (loaderTier && !deliversPayloadId) {
      setError('Pick the stored implant the loader delivers.')
      return
    }
    setSubmitting(true)
    try {
      await enqueueBuildJob(engagementId, {
        // Language rides empty: the server defaults to the in-tree Rust unit,
        // and no other unit is registered to pick.
        language: null,
        // Class rides empty the same way: the server defaults to the full
        // implant, and the stager class is retired.
        class: null,
        targetOs,
        targetArch,
        listenerId,
        endpoint: null,
        // The walked fallback list: the picked fronts' dials in walk order,
        // family-checked server side.
        fallbackEndpoints: picked.length > 0 ? picked.map(dialOf) : null,
        enrollPath: enrollPath || null,
        userAgent: userAgent || null,
        headers: null,
        requestTimeoutSeconds: num(requestTimeoutSeconds),
        envelope: envelope !== 'None' ? envelope : null,
        contactProtection: contactProtection ? null : false,
        // Poll is the server's default mode; an explicit stream pick rides,
        // the deliberate interactive shape.
        mode: mode !== 'poll' ? mode : null,
        sleepSeconds: num(sleepSeconds),
        jitterSeconds: num(jitterSeconds),
        killDate: killDate ? new Date(killDate).toISOString() : null,
        tokenMaxUses: num(tokenMaxUses),
        tokenLifetimeSeconds: num(tokenHours) !== null ? num(tokenHours)! * 3600 : null,
        // The tier pick: the loader names its stage; the implant rides the
        // default.
        kind: loaderTier ? 'loader' : null,
        deliversPayloadId: loaderTier ? deliversPayloadId : null,
        // Format rides empty on the desktop legs: every spelling is the
        // same native binary over the Rust unit, and the disk-or-memory
        // choice is the launcher step's (the Launchers tab offers both
        // families for every payload). Android deploys through the
        // carrier -- the picked shape rides.
        format: targetOs === 'android' && !loaderTier ? apkFormat : null,
        // Trust rides empty by design: the picked front's listener owns the
        // certificate posture, and the build inherits it server side.
        trust: null,
      })
      setError(null)
      await refreshJobs()
    } catch (e) {
      setError(String(e))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <section className="view">
      <h2>
        Build
        <HelpHint>
          The engagement's build home: self-contained implants from the job queue, web-shell
          scripts rendered instantly -- every drop-on-target artifact cut here, its knobs baked
          at generation.
        </HelpHint>
      </h2>
      <div className="card">
        {/* The artifact-kind toggle: the implant pipeline and the web-shell
            generator share this card -- one place that makes drop-on-target
            artifacts. */}
        <div className="inline-form">
          <button
            className={artifact === 'implant' ? 'primary sm' : 'ghost sm'}
            onClick={() => setArtifact('implant')}
            title="A self-contained executable with its enrollment credential baked in, built by the server-side pipeline."
          >
            Implant
          </button>
          <button
            className={artifact === 'webshell' ? 'primary sm' : 'ghost sm'}
            onClick={() => setArtifact('webshell')}
            title="A placement script with its credential baked in, rendered instantly for a target's web root."
          >
            Webshell script
          </button>
        </div>
        {artifact === 'webshell' ? (
          <>
            <h3>
              Generate web-shell script
              <HelpHint>
                A placement script with its credential baked in — generate here, drop it in the
                target's web root, register the reachable URL under Web shells.
              </HelpHint>
            </h3>
            <WebShellGenerateForm engagementId={engagementId} />
          </>
        ) : (
          <>
            <h3>
              Build payload
              <HelpHint>
                Pick a listener and a target, leave the rest at the defaults. The artifact is a
                self-contained executable with its enrollment credential baked in — drop it and
                run. Every knob is baked at generation.
              </HelpHint>
            </h3>
            <form className="build-form" onSubmit={onBuild}>
          <fieldset>
            <legend>Target</legend>
            <label>
              Tier
              <select
                value={tier}
                onChange={(e) => setTier(e.target.value as 'implant' | 'loader')}
                title="Which tier of the delivery stack this build produces. Implant: the full product -- every baked contact, the verb set, the sealed envelope. Loader: a ~25 KB no-libc dialer that fetches the payload you pick over cleartext http, authenticates it under the build's per-artifact AES-GCM key (nothing executes that does not open under that key), and runs it from a memfd -- it never lands on disk. The loader's baked credential spends one use per execution (each run fetches the payload once), so budget the token accordingly."
              >
                <option value="implant">Implant (full product)</option>
                <option value="loader">Loader (sealed payload, memfd)</option>
              </select>
            </label>
            {loaderTier && (
              <label>
                Delivered implant
                <select
                  value={deliversPayloadId}
                  onChange={(e) => setDeliversPayloadId(e.target.value)}
                  title="The stored implant this loader fetches and runs. The fetch serves the payload sealed under the loader's own baked key; deleting either artifact ends the delivery."
                >
                  <option value="" disabled>-- pick the delivered implant --</option>
                  {deliverable.map((p) => (
                    <option key={p.artifactId} value={p.artifactId}>
                      {p.fingerprint.slice(0, 12)} · {p.target ?? 'unknown-target'} ·{' '}
                      {p.builtAt.slice(0, 10)}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label>
              Listener (enroll + contact)
              <select
                value={listenerId}
                onChange={(e) => setListenerId(e.target.value)}
                title="The listener whose public endpoint gets baked: the implant registers on it once (enroll) and contacts on it for the rest of its life -- interactive rides the same front, and the summary under the form spells out how. The fallbacks under Advanced extend both exchanges, in walk order. Every family serves enrollment (web, raw socket, DNS/DoH); only the shell catcher serves none."
              >
                <option value="" disabled>-- pick a listener --</option>
                {listeners.map((l) =>
                  ENROLL_TRANSPORTS.has(l.transport) ? (
                    <option
                      key={l.id}
                      value={l.id}
                      disabled={loaderTier && l.transport !== 'http'}
                    >
                      {l.name} ({l.transport} → {l.publicEndpoint})
                      {loaderTier && l.transport !== 'http' ? ' — http only for the loader' : ''}
                    </option>
                  ) : (
                    <option key={l.id} disabled>
                      {l.name} ({l.transport} — not enroll ingress)
                    </option>
                  ),
                )}
              </select>
            </label>
            <label>
              OS
              {/* The build unit maps these onto a runtime identifier and refuses
                  anything outside the supported set, so the form offers exactly
                  that set instead of free text a typo can waste a build on. */}
              <select
                value={targetOs}
                onChange={(e) => {
                  setTargetOs(e.target.value)
                  if (!ARCHS[e.target.value].includes(targetArch)) setTargetArch('amd64')
                }}
              >
                <option value="linux">Linux</option>
                <option value="windows" disabled={loaderTier}>
                  Windows
                </option>
                <option value="android" disabled={loaderTier}>
                  Android
                </option>
              </select>
            </label>
            <label>
              Arch
              {/* The arch list follows the OS: Windows pairs with the GNU x86
                  targets alone (no ARM Windows triple), Linux adds the musl
                  ARM and x86 triples, Android carries arm64 devices and amd64
                  (the emulator). */}
              <select value={targetArch} onChange={(e) => setTargetArch(e.target.value)}>
                {ARCHS[targetOs].map((a) => (
                  <option key={a} value={a}>
                    {a === 'amd64' ? 'amd64 / x64' : a}
                  </option>
                ))}
              </select>
            </label>
            {targetOs === 'android' && (
              <label>
                Format
                {/* The android deploys through the carrier: the packaged
                    installable by default, the bare library when an
                    engagement's own app loads it. */}
                <select value={apkFormat} onChange={(e) => setApkFormat(e.target.value as 'apk' | 'so')}>
                  <option value="apk">apk (carrier package)</option>
                  <option value="so">so (carrier library)</option>
                </select>
              </label>
            )}
          </fieldset>
          {loaderTier ? (
            <fieldset>
              <legend>Credential</legend>
              <label>
                Max uses
                <input
                  value={tokenMaxUses}
                  onChange={(e) => setTokenMaxUses(e.target.value)}
                  title="The loader's baked credential spends one use per execution (each run fetches the sealed stage once), not per host -- a loader meant to survive reboots needs a budget or 0 (unlimited) inside its kill window. Default 1: a single-shot delivery."
                />
                <span className="field-help">0 = unlimited</span>
              </label>
              <p className="muted" style={{ gridColumn: '1 / -1', margin: 0 }}>
                The loader bakes no contact profile — its only knobs are the stage it delivers and
                the credential that gates the fetch. The implant it runs carries its own baked
                profile from its build.
              </p>
            </fieldset>
          ) : (
          <fieldset>
            <legend>Beacon profile</legend>
            <label>
              Mode
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                disabled={pollOnly}
                title={pollOnly
                  ? 'This front holds no live stream (one connection or one answer per contact), so poll is the only coherent mode -- the server refuses the stream pairing with the same fix.'
                  : 'How the artifact contacts: stream holds one connection open with live server push; poll exchanges one contact per interval. Either way every verb rides -- the summary below spells out how.'}
              >
                <option value="poll">poll — contact and sleep (default)</option>
                <option value="stream" disabled={pollOnly}>stream — persistent connection</option>
              </select>
            </label>
            <label>
              Contact every (s)
              <input
                value={sleepSeconds}
                onChange={(e) => setSleepSeconds(e.target.value)}
                title="How often the implant calls home. Default 30."
              />
            </label>
            <label>
              Randomize ± (s)
              <input
                value={jitterSeconds}
                onChange={(e) => setJitterSeconds(e.target.value)}
                title="Random slack added to every interval so contacts are not clockwork. Default 10."
              />
            </label>
            <label>
              Max uses
              <input
                value={tokenMaxUses}
                onChange={(e) => setTokenMaxUses(e.target.value)}
                title="How many hosts the baked credential may enroll -- one spend per host, so one artifact can seed several machines until the budget runs out. 0 = unlimited. Default 1. Revoke it in the payload library to kill a leaked artifact's credential."
              />
              <span className="field-help">0 = unlimited</span>
            </label>
            <p className="muted" style={{ gridColumn: '1 / -1', margin: 0 }}>
              Call-home cadence and the baked credential's host cap. The artifact's kill-date fuse
              and the credential's enroll window ride under Advanced — hover each field for
              specifics.
            </p>
          </fieldset>
          )}
          <details className="build-advanced">
            <summary>Advanced — wire shape and credential timing</summary>
            <div className="grid">
              <p className="muted" style={{ gridColumn: '1 / -1', margin: 0 }}>
                Wire shape and credential timing. The fallback fronts are picked from this
                engagement's same-family listeners, in walk order; the one path knob is
                registration's. The artifact's kill-date fuse and the credential's enroll
                window ride here too.
              </p>
              <div className="fallback-fronts">
                <span className="fallback-caption">Fallback fronts (walk order)</span>
                {picked.length === 0 ? (
                  <p className="muted" style={{ margin: 0 }}>
                    None — the primary front is the whole walk.
                  </p>
                ) : (
                  <div className="fallback-chips">
                    {picked.map((l, i) => (
                      <span className="chip" key={l.id}>
                        <strong>{l.name}</strong>
                        {dialOf(l)}
                        <button
                          type="button"
                          className="link"
                          disabled={i === 0}
                          onClick={() => movePick(l.id, -1)}
                          title="Walk this front earlier"
                        >
                          ↑
                        </button>
                        <button
                          type="button"
                          className="link"
                          disabled={i === picked.length - 1}
                          onClick={() => movePick(l.id, 1)}
                          title="Walk this front later"
                        >
                          ↓
                        </button>
                        <button
                          type="button"
                          className="link"
                          onClick={() =>
                            setFallbackIds((prev) => prev.filter((x) => x !== l.id))
                          }
                          title="Drop this fallback"
                        >
                          ✕
                        </button>
                      </span>
                    ))}
                  </div>
                )}
                <select
                  value=""
                  onChange={(e) => {
                    if (e.target.value) setFallbackIds((prev) => [...prev, e.target.value])
                  }}
                  title="Add one of this engagement's same-family listeners as a walked fallback. The baked entry is its public endpoint as of this build (the DNS family: its bind as the resolver plus its zone) — a later repoint does not update already-deployed artifacts, the walk only bridges until a rebuild."
                >
                  <option value="">
                    {eligible.filter((l) => !fallbackIds.includes(l.id)).length === 0
                      ? 'No same-family listeners left to add'
                      : '-- add a fallback front --'}
                  </option>
                  {eligible.filter((l) => !fallbackIds.includes(l.id)).map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name} ({l.transport} → {dialOf(l)})
                    </option>
                  ))}
                </select>
              </div>
              <label>
                Enroll path
                <input
                  value={enrollPath}
                  onChange={(e) => setEnrollPath(e.target.value)}
                  placeholder="/implants/enroll"
                  title="The URI path of the one-time registration POST (default /implants/enroll). The only path knob: contacts ride the fixed /implants/beacon route and the interactive stream rides the mTLS socket's own path. Change it only when a redirector rewrites to the real route."
                />
              </label>
              <label>
                User agent
                <input
                  value={userAgent}
                  onChange={(e) => setUserAgent(e.target.value)}
                  placeholder="HTTP client default"
                  title="The User-Agent header the implant presents, so the traffic blends with a known-good client."
                />
              </label>
              <label>
                Request timeout (s)
                <input
                  value={requestTimeoutSeconds}
                  onChange={(e) => setRequestTimeoutSeconds(e.target.value)}
                  placeholder="30"
                  title="Per-request HTTP timeout. Default 30."
                />
              </label>
              <label>
                Enroll body
                <select
                  value={envelope}
                  onChange={(e) => setEnvelope(e.target.value)}
                  title="Shapes the ENROLL request body only. AES-GCM (the default) encrypts it under a per-artifact key minted at build — the same default posture contacts already carry; redundant on direct https, where TLS already encrypts the channel. None sends the raw JSON body, the lab-debug shape; Base64 wraps it as one string so it no longer reads as structured C2."
                >
                  <option>None</option>
                  <option>Base64</option>
                  <option value="AesGcm">AES-GCM</option>
                </select>
              </label>
              <label
                className="checkbox-label"
                title="Seals every contact POST and its response as AES-256-GCM under a per-artifact key minted at build, covering a fresh counter — the authentication the web contacts use instead of a TLS client certificate, and the confidentiality that makes cleartext http carry encrypted content. Off is the lab-debug plaintext frame."
              >
                Protect contacts
                <span className="checkbox-row">
                  <input
                    type="checkbox"
                    checked={contactProtection}
                    onChange={(e) => setContactProtection(e.target.checked)}
                  />
                  {/* The algorithm rides beside the box, not in the caption:
                      the caption stays the field's name like its siblings,
                      and the seal's identity reads as the box's annotation. */}
                  <span className="field-help">AES-256-GCM</span>
                </span>
              </label>
              <label>
                Kill date
                <input
                  type="date"
                  value={killDate}
                  onChange={(e) => setKillDate(e.target.value)}
                  title="Past this date the executable stops being usable: a leftover copy refuses to run, and a live implant terminates at its next contact. Empty = no fuse -- the implant runs until retired (the long-haul default). A date also caps the baked credential's window unless 'Valid for' overrides it."
                />
              </label>
              <label>
                Valid for (h)
                <input
                  value={tokenHours}
                  onChange={(e) => setTokenHours(e.target.value)}
                  placeholder="hours"
                  title="How long the baked credential can enroll NEW implants. Pairs with Max uses: that caps how many enrolls, this caps for how long. Empty = until the kill date, or a 30-day drop window when there is none. Enrollment is permanent — an implant that already enrolled contacts for life; this only gates copies that have not enrolled yet."
                />
                <span className="field-help">empty = until the kill date, else 30 days</span>
              </label>
            </div>
          </details>
          <BuildSummary
            listener={selectedListener}
            mode={mode}
            sleep={sleepSeconds}
            jitter={jitterSeconds}
          />
          <button className="primary" type="submit" disabled={submitting}>
            Build payload
          </button>
        </form>
        {error && <p className="error">{error}</p>}

        <h3 className="jobs-head">Recent builds</h3>
        {jobs.length === 0 ? (
          <div className="empty">
            <Icon name="package" />
            No builds yet -- the queue is empty.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Requested</th>
                  <th>Target</th>
                  <th>Listener</th>
                  <th>State</th>
                  <th>Artifact</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {jobs.slice(0, RECENT_BUILDS_SHOWN).map((job) => {
                  const front = frontFor(job.endpoint, listeners)
                  const inLibrary =
                    !job.artifact || libraryIds.has(job.artifact.artifactId)
                  return (
                    <tr key={job.jobId}>
                      <td title={job.jobId}>{new Date(job.requestedAt).toLocaleString()}</td>
                      <td>
                        <code>
                          {job.language} {job.target}
                        </code>
                      </td>
                      <td>
                        <span
                          title={
                            front
                              ? `The engagement's ${front.transport} listener: ${job.endpoint} (enroll + contact)`
                              : `No listener serves this address (typed for a redirector): ${job.endpoint}`
                          }
                        >
                          {front ? (
                            <>
                              {front.name} <span className="muted">({front.transport})</span> ·{' '}
                              <code>{hostPortOf(job.endpoint)}</code>
                            </>
                          ) : (
                            <>
                              <code>{hostPortOf(job.endpoint)}</code>{' '}
                              <span className="muted">manual</span>
                            </>
                          )}
                        </span>
                      </td>
                      <td>
                        {(job.state === 'queued' || job.state === 'running') && (
                          <span className="spinner inline-spinner" />
                        )}
                        <StatusBadge status={job.state} />
                        <span className="muted"> {elapsed(job)}</span>
                        {job.error && <div className="error">{job.error}</div>}
                      </td>
                      <td>
                        {job.artifact ? (
                          <span>
                            <code>{job.artifact.fingerprint.slice(0, 16)}</code>
                            <span className="muted"> ({fmtBytes(job.artifact.size)})</span>
                          </span>
                        ) : (
                          <span className="muted">—</span>
                        )}
                        {job.artifact?.tokenId && (() => {
                          // The library row for this artifact carries the
                          // credential's live state; a payload deleted from
                          // the library leaves the line as plain provenance.
                          const state = library.find(
                            (p) => p.tokenId === job.artifact!.tokenId,
                          )
                          const dead =
                            state != null
                            && state.tokenMaxUses !== 0
                            && (state.tokenRemainingUses == null
                              || state.tokenRemainingUses <= 0)
                          return (
                            <div className="muted" title={job.artifact.tokenId}>
                              baked token {job.artifact.tokenId.slice(0, 8)}
                              {dead
                                ? ' — no enrolls left'
                                : state && state.tokenMaxUses === 0
                                  ? ' · unlimited enrolls'
                                  : state
                                    ? ` · ${state.tokenRemainingUses} of ${state.tokenMaxUses} enrolls left`
                                    : ''}
                              {revoking === job.artifact.tokenId ? (
                                ' (revoking…)'
                              ) : (
                                <>
                                  {' '}
                                  <button
                                    className="sm danger"
                                    onClick={() => void onRevokeToken(job.artifact!.tokenId!)}
                                    title="The leak answer: the baked credential stops working at the next enrollment attempt"
                                  >
                                    Revoke token
                                  </button>
                                </>
                              )}
                            </div>
                          )
                        })()}
                      </td>
                      <td>
                        {job.artifact &&
                          (inLibrary ? (
                            <a
                              className="download-link"
                              href={`engagements/${engagementId}/payloads/${job.artifact.artifactId}`}
                              download
                            >
                              Download
                            </a>
                          ) : (
                            <span
                              className="muted"
                              title="The artifact was deleted from the payload library -- the bytes are gone and its fetch URL 404s. The credential can still be revoked above."
                            >
                              deleted
                            </span>
                          ))}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {jobs.length > RECENT_BUILDS_SHOWN && (
              <p className="muted" style={{ padding: '6px 10px', margin: 0 }}>
                {jobs.length - RECENT_BUILDS_SHOWN} older job
                {jobs.length - RECENT_BUILDS_SHOWN === 1 ? '' : 's'} hidden -- every finished
                artifact stays in the{' '}
                <a href={`#/engagements/${engagementId}/assets/payloads`}>Payloads</a> library.
              </p>
            )}
          </div>
        )}
        </>
        )}

        <p className="muted">
          Finished payloads live on in the <a href={`#/engagements/${engagementId}/assets/payloads`}>Payloads</a> library.
        </p>
      </div>
    </section>
  )
}

// The baked shape, composed live from the picks above: what the artifact
// enrolls on, how it contacts, and how interactive rides -- read before the
// build commits, not discovered on target. The three keys are the fixed
// vocabulary's three behaviors; the values follow the front's transport and
// the mode.
function BuildSummary({
  listener,
  mode,
  sleep,
  jitter,
}: {
  listener?: ListenerSummary
  mode: string
  sleep: string
  jitter: string
}) {
  const front = listener?.publicEndpoint ?? '— pick a listener —'
  const via = listener ? `${listener.name} (${listener.transport})` : 'unpicked'
  const cadence = `every ${sleep.trim() || '30'}s ± ${jitter.trim() || '10'}s`
  // The socket family's dial shape.
  const socket = listener?.transport === 'tcp'
  // The DNS family as the enroll front itself (the DNS-only target's shape).
  const dnsFront = !socket && (listener?.transport === 'dns' || listener?.transport === 'doh')
  // The trust posture rides the summary on the TLS-shaped fronts -- the one
  // knob whose fact (whose certificate the front presents) lives on the
  // listener while the choice lives here, so it reads at commit time
  // instead of living forgotten under Advanced.
  const tlsFront = listener?.transport === 'https' || listener?.transport === 'mtls'

  const contact = socket
    ? `one socket connection per contact, ${cadence}, on ${front}`
    : dnsFront
      ? `DNS TXT polls, ${cadence}, on ${front} — the whole lifecycle on one front`
      : mode === 'poll'
        ? `sealed envelope POSTs ${cadence} on ${front}`
        : `WebSocket beacon held open on ${front}`

  const interactive = dnsFront
    ? 'store-and-forward over the DNS polls — input on the TXT answers, output as chunked queries (query-rate cadence; the slowest wire that carries it)'
    : mode === 'poll'
      ? 'store-and-forward over those contacts — input rides the next cycle (sleep 0 approaches live)'
      : 'live channel over the WebSocket beacon'

  return (
    <div className="build-summary" title="What this build bakes, composed from the picks above">
      <div>
        <span className="summary-key">enroll</span> once on <code>{front}</code> via {via}
      </div>
      <div>
        <span className="summary-key">contact</span> {contact}
      </div>
      <div>
        <span className="summary-key">interactive</span> {interactive}
      </div>
      {tlsFront && (
        <div
          title="The front's certificate posture -- set on the listener, inherited here as the roots the dials trust"
        >
          <span className="summary-key">tls</span>{' '}
          {(listener.trustPosture || 'pinned') === 'public'
            ? 'public roots — a real-domain certificate an operator-run edge terminates'
            : 'engagement CA pinned — the front presents the CA’s own leaf'}
        </div>
      )}
    </div>
  )
}
