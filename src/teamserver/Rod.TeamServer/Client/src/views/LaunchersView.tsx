import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import {
  type HookRow,
  type LauncherRow,
  type ListenerSummary,
  type MintedHook,
  type PayloadSummary,
  deleteLauncher,
  listHooks,
  listLaunchers,
  listListeners,
  listPayloads,
  mintHook,
  renderLaunchers,
  revokeHook,
} from '../api'
import { catchLaunchers } from '../catchOneLiners'
import { launcherHint } from '../launcherFamilies'
import { CopyButton } from '../components/CopyButton'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'
import { osIconFor } from '../osKind'
import { deliverable, payloadLabel } from '../payloads'
import { useNow } from '../when'

// The engagement's one-liner home: every command an operator copies out,
// in one place. Three surfaces live here. "Catch a shell" renders the
// paste-ready reverse-shell one-liners per shellcatch listener -- no
// credential is involved, the address is the listener's public endpoint,
// and the caught shell lands in the Shells roster. "Deliver a beacon"
// cuts a payload-fetch render: pick the payload, the server mints the
// download credential and answers with the downloader one-liner per shell
// family. "Kept launchers" is the list those renders land in -- every cut
// is kept, so the operator can come back to it: re-copy the command any
// time, watch the credential's budget, revoke it the moment it leaks, and
// delete the row when it is spent.

// The redeem budgets an operator realistically picks. Single-use is the
// default posture (one paste, one download); the wider budgets serve a
// many-host deployment from one render.
const USE_OPTIONS: { value: number; label: string }[] = [
  { value: 1, label: 'Single use' },
  { value: 0, label: 'Unlimited (until expiry)' },
  { value: 5, label: '5 uses' },
  { value: 25, label: '25 uses' },
]

const LIFETIME_OPTIONS: { value: number; label: string }[] = [
  { value: 30, label: '30 minutes' },
  { value: 120, label: '2 hours' },
  { value: 720, label: '12 hours' },
  { value: 1440, label: '24 hours' },
]

export function LaunchersView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick?: number
}) {
  const [payloads, setPayloads] = useState<PayloadSummary[]>([])
  const [listeners, setListeners] = useState<ListenerSummary[]>([])
  const [rows, setRows] = useState<LauncherRow[]>([])
  const [payloadId, setPayloadId] = useState('')
  const [listenerId, setListenerId] = useState('')
  const [maxUses, setMaxUses] = useState(1)
  const [lifetimeMinutes, setLifetimeMinutes] = useState(30)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [commandsFor, setCommandsFor] = useState<string | null>(null)

  // The browser-hook surface's own state: the mint form's choices and the
  // roster of minted hooks (every one is a kept served artifact).
  const [hooks, setHooks] = useState<HookRow[]>([])
  const [hookListenerId, setHookListenerId] = useState('')
  const [hookSleep, setHookSleep] = useState(30)
  const [hookUses, setHookUses] = useState(50)
  const [hookEnvelope, setHookEnvelope] = useState<'aesgcm' | 'none'>('aesgcm')
  const [hookBusy, setHookBusy] = useState(false)
  const [lastMinted, setLastMinted] = useState<MintedHook | null>(null)

  // The catch, delivery, and hook cards share one slot as tabs (the settings
  // page's strip shape): each card carries its own growing roster -- the
  // catch one-liners, the kept launchers, the minted hooks -- and stacking
  // them meant one list pushed the other cards off-screen. All drafts live
  // in this view's state, so a tab switch keeps what was picked.
  const [formTab, setFormTab] = useState<'deliver' | 'hook' | 'catch'>('deliver')
  // The catch tab's listener pick; empty means the first shellcatch listener.
  const [catchListenerId, setCatchListenerId] = useState('')

  // The quiet clock keeps expiry counts moving between interactions.
  const now = useNow(30_000)

  const refreshRows = useCallback(async () => {
    try {
      const [launcherRows, hookRows] = await Promise.all([
        listLaunchers(engagementId),
        listHooks(engagementId),
      ])
      setRows(launcherRows)
      setHooks(hookRows)
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }, [engagementId])

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const [allPayloads, allListeners] = await Promise.all([
          listPayloads(engagementId),
          listListeners(engagementId),
        ])
        if (cancelled) return
        setPayloads(allPayloads)
        setListeners(allListeners)
        setError(null)
      } catch (e) {
        if (!cancelled) setError(String(e))
      }
    })()
    return () => {
      cancelled = true
    }
  }, [engagementId])

  // The live tick rides the SSE PayloadFetched frame: a target pulling a
  // credential spends it on the server, and the row's remaining budget
  // moves here without an operator pressing refresh.
  useEffect(() => {
    void refreshRows()
  }, [refreshRows, onlineTick])

  // A selection must not survive the engagement switch.
  useEffect(() => {
    setCommandsFor(null)
  }, [engagementId])

  const webListeners = useMemo(
    () => listeners.filter((l) => ['http', 'https', 'mtls'].includes(l.transport)),
    [listeners],
  )
  // The hook rides the web family proper (fetch + the envelope POST), so the
  // mTLS shape is out: only plain http/https fronts answer it.
  const hookFronts = useMemo(
    () => listeners.filter((l) => ['http', 'https'].includes(l.transport)),
    [listeners],
  )
  const catchers = useMemo(
    () => listeners.filter((l) => l.transport === 'shellcatch'),
    [listeners],
  )

  const onRender = useCallback(async () => {
    setBusy(true)
    try {
      await renderLaunchers(engagementId, {
        payloadId: payloadId || undefined,
        listenerId: listenerId || undefined,
        maxUses,
        lifetimeMinutes,
      })
      await refreshRows()
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }, [engagementId, payloadId, listenerId, maxUses, lifetimeMinutes, refreshRows])

  const onDelete = async (row: LauncherRow) => {
    if (!window.confirm('Delete this launcher? Its credential stops working at the next fetch (every pasted copy dies with it), and the row goes -- the mint\'s history stays on the audit trail.'))
      return
    try {
      await deleteLauncher(engagementId, row.launcherId)
      await refreshRows()
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }

  const onMintHook = useCallback(async () => {
    if (!hookListenerId) return
    setHookBusy(true)
    try {
      const minted = await mintHook(engagementId, {
        listenerId: hookListenerId,
        sleepSeconds: hookSleep,
        envelope: hookEnvelope,
        tokenMaxUses: hookUses,
      })
      setLastMinted(minted)
      await refreshRows()
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setHookBusy(false)
    }
  }, [engagementId, hookListenerId, hookSleep, hookEnvelope, hookUses, refreshRows])

  const onRevokeHook = async (row: HookRow) => {
    if (!window.confirm('Revoke this hook? The serving URL 404s from now on, its baked credential stops enrolling, and every browser already holding the script goes quiet at its next contact.'))
      return
    try {
      await revokeHook(engagementId, row.hookId)
      if (lastMinted?.hookId === row.hookId) setLastMinted(null)
      await refreshRows()
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }

  const usesLabel = useMemo(
    () => USE_OPTIONS.find((o) => o.value === maxUses)?.label ?? `${maxUses} uses`,
    [maxUses],
  )
  const lifetimeLabel = useMemo(
    () => LIFETIME_OPTIONS.find((o) => o.value === lifetimeMinutes)?.label ?? `${lifetimeMinutes} min`,
    [lifetimeMinutes],
  )
  const frontLabel = useMemo(() => {
    if (!listenerId) return 'auto front'
    const named = webListeners.find((l) => l.id === listenerId)
    return named ? named.name : 'named front'
  }, [listenerId, webListeners])

  // The catcher whose one-liners render; the tab strip falls back to the
  // delivery form if the last shellcatch listener goes away while the catch
  // tab is open.
  const catchCatcher = catchers.find((l) => l.id === catchListenerId) ?? catchers[0]
  const shownTab = formTab === 'catch' && catchers.length === 0 ? 'deliver' : formTab

  return (
    <section className="view">
      <h2>
        Launchers
        <HelpHint>
          Every paste-ready one-liner this engagement can cut, in one place: reverse shells that
          land in the Shells roster, payload fetches that grow a beacon in the Implants table,
          and the browser hook that enrolls a victim's browser as a Browser-class implant. The
          three surfaces ride one tab strip, each keeping its own roster or one-liners below it;
          every fetch render is kept — re-copy it any time; Delete closes its lifecycle (the
          credential dies with the row, and the mint's history is the audit trail's to keep).
        </HelpHint>
      </h2>
      {error && <p className="error">{error}</p>}

      {/* The catch, delivery, and hook cards share one slot as tabs: each
          carries its own growing roster, so stacking them let one list push
          the other cards off-screen. The strip shape is the settings
          page's; the catch tab rides only when a shellcatch listener
          exists. */}
      <div className="inline-form">
        <button
          className={shownTab === 'deliver' ? 'primary sm' : 'ghost sm'}
          onClick={() => setFormTab('deliver')}
          title="Cut a paste-ready one-liner that fetches a built payload over the engagement's web front and runs it."
        >
          Deliver a beacon
        </button>
        <button
          className={shownTab === 'hook' ? 'primary sm' : 'ghost sm'}
          onClick={() => setFormTab('hook')}
          title="Mint a served hook script and inject the answer as a script tag on the vulnerable page."
        >
          Hook a browser
        </button>
        {catchers.length > 0 && (
          <button
            className={shownTab === 'catch' ? 'primary sm' : 'ghost sm'}
            onClick={() => setFormTab('catch')}
            title="The paste-ready reverse-shell one-liners for a shellcatch listener's public endpoint."
          >
            Catch a shell
          </button>
        )}
      </div>

      {/* The catch surface: no credential, no mint -- the pure rendering of
          a shellcatch listener's (host, port) into the classic reverse-shell
          shapes. The listener picker renders one set of one-liners in one
          fixed place, instead of a fold per listener when several exist. */}
      {shownTab === 'catch' && (
        <div className="card">
          <h3>
            Catch a shell
            <HelpHint>
              Reverse-shell one-liners for a shellcatch listener's public endpoint. No credential
              is involved — the address is the listener's own endpoint; paste one on the target
              and the shell lands in the Shells roster.
            </HelpHint>
          </h3>
          {catchers.length > 1 ? (
            <div className="inline-form">
              <select
                value={catchCatcher?.id ?? ''}
                onChange={(e) => setCatchListenerId(e.target.value)}
                title="Which shellcatch listener's public endpoint the one-liners dial"
              >
                {catchers.map((l) => (
                  <option key={l.id} value={l.id}>
                    {l.name} · {l.publicEndpoint}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <p className="muted">
              Catching on <code>{catchCatcher?.name}</code> ·{' '}
              <code>{catchCatcher?.publicEndpoint}</code>
            </p>
          )}
          {catchCatcher && catchLaunchers(catchCatcher.publicEndpoint).length > 0 ? (
            <div className="upgrade-panel">
              {catchLaunchers(catchCatcher.publicEndpoint).map((launcher) => (
                <div key={launcher.id} className="upgrade-launcher">
                  <span title={`For ${launcher.os} targets`}>
                    <Icon name={osIconFor(launcher.os)} className="wire-icon" />
                  </span>
                  <code>{launcher.id}</code>
                  {/* The shape's posture up front: which one-liners land a
                      full-interactive pty shell and which land a dumb pipe
                      decides which the operator pastes at all. */}
                  <span
                    className={`status shape-${launcher.kind}`}
                    title={launcher.note}
                  >
                    {launcher.kind === 'pty' ? 'interactive' : 'dumb'}
                  </span>
                  <code className="upgrade-command">{launcher.command}</code>
                  <CopyButton text={launcher.command} />
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">
              This listener's public endpoint is not a dialable host:port — repoint it and the
              one-liners render.
            </p>
          )}
        </div>
      )}

      {/* The browser-hook mint: the XSS foothold's delivery. A hook is not a
          one-liner but a served script -- the mint renders it with its bake
          and answers the `<script src>` tag to inject; the hooked browsers
          then appear in the Implants table as Browser-class rows, taskable
          from the same menu as any implant. */}
      {shownTab === 'hook' && (
      <div className="card">
          <h3>
            Hook a browser
            <HelpHint>
              Mint a served hook script and inject the answer as a{' '}
              <code>{'<script src>'}</code> tag on the vulnerable page. Each hooked browser
              enrolls as a Browser-class implant over the sealed envelope carrier — the fetch
              URL's unguessable id is the only credential a victim's browser ever presents.
            </HelpHint>
          </h3>
        {hookFronts.length === 0 ? (
          <div className="empty">
            <Icon name="globe" />
            No HTTP(S) listener in this engagement yet — the hook rides the web family;
            create one under Listeners first.
          </div>
        ) : (
          <>
            <div className="inline-form">
              <select
                value={hookListenerId}
                onChange={(e) => setHookListenerId(e.target.value)}
                title="The front the hook is served from and contacts through -- its public endpoint is what every victim's browser dials"
              >
                <option value="">Choose a front…</option>
                {hookFronts.map((l) => (
                  <option key={l.id} value={l.id}>
                    {l.name} · {l.transport} · {l.publicEndpoint}
                  </option>
                ))}
              </select>
              <button
                className="primary"
                onClick={() => void onMintHook()}
                disabled={hookBusy || !hookListenerId}
              >
                {hookBusy ? 'Minting…' : 'Mint hook'}
              </button>
            </div>
            {/* Cadence, budget, and posture: the knobs an operator sizes per
                campaign. The budget is enrollments (one per hooked browser,
                and one per reload where storage is blocked), not fetches --
                serving the script is unbudgeted. */}
            <details className="build-advanced">
              <summary title="Poll cadence, enrollment budget, and seal posture">
                Cadence &amp; budget — {hookSleep}s poll ·{' '}
                {hookUses === 0 ? 'unlimited enrollments' : `${hookUses} enrollments`} ·{' '}
                {hookEnvelope === 'aesgcm' ? 'sealed' : 'cleartext (plain-http pages)'}
              </summary>
              <div className="inline-form">
                <select
                  value={hookSleep}
                  onChange={(e) => setHookSleep(Number(e.target.value))}
                  title="The base interval between poll contacts; jitter of a fifth rides beside it"
                >
                  {[10, 30, 60, 300].map((s) => (
                    <option key={s} value={s}>
                      {s}s poll
                    </option>
                  ))}
                </select>
                <select
                  value={hookUses}
                  onChange={(e) => setHookUses(Number(e.target.value))}
                  title="Every hooked browser's enrollment spends one use of the baked token"
                >
                  <option value={0}>Unlimited enrollments</option>
                  {[10, 50, 200].map((n) => (
                    <option key={n} value={n}>
                      {n} enrollments
                    </option>
                  ))}
                </select>
                <select
                  value={hookEnvelope}
                  onChange={(e) => setHookEnvelope(e.target.value as 'aesgcm' | 'none')}
                  title="Sealed is the mainstream posture (enroll and contacts are AES-GCM under the baked key); cleartext serves plain-http pages where crypto.subtle is unavailable"
                >
                  <option value="aesgcm">Sealed (aesgcm)</option>
                  <option value="none">Cleartext (plain-http pages)</option>
                </select>
              </div>
            </details>
            {lastMinted && (
              <div className="upgrade-panel">
                <p>
                  Inject on the vulnerable page:{' '}
                  <code className="upgrade-command">{lastMinted.snippet}</code>{' '}
                  <CopyButton text={lastMinted.snippet} />
                </p>
                <p className="muted">
                  Test page <code>{lastMinted.testPageUrl}</code> — load it in a browser
                  and the hook enrolls into this engagement.
                </p>
              </div>
            )}
            {hooks.length > 0 && (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Minted</th>
                      <th>Serving URL</th>
                      <th>Front</th>
                      <th>Posture</th>
                      <th>Cadence</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {hooks.map((row) => (
                      <tr key={row.hookId}>
                        <td>{new Date(row.builtAt).toLocaleString()}</td>
                        <td title={`Fingerprint ${row.fingerprint}`}>
                          <code>{row.url}</code> <CopyButton text={row.url} />
                        </td>
                        <td title={row.url}>{row.endpoint}</td>
                        <td>{row.envelope === 'none' ? 'cleartext' : 'sealed'}</td>
                        <td>{row.sleepSeconds != null ? `${row.sleepSeconds}s` : '—'}</td>
                        <td>
                          <div className="row-actions">
                            <button className="ghost sm" onClick={() => void onRevokeHook(row)}>
                              Revoke
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
      )}

      {/* One card, one flow: the render form above, the kept rows below --
          the same single surface the Build tab gives its form and job strip,
          so cutting a launcher and coming back to it reads as one place
          instead of two boxed steps. */}
      {shownTab === 'deliver' && (
      <div className="card">
        <h3>
          Deliver a beacon
          <HelpHint>
            A one-liner that fetches the payload over the engagement's web front and runs it.
            Each served fetch spends one use of a freshly minted credential; the enrollment that
            follows rides the credential baked into the fetched artifact.
          </HelpHint>
        </h3>
        {payloads.length === 0 || webListeners.length === 0 ? (
          <div className="empty">
            <Icon name="copy" />
            {payloads.length === 0 && webListeners.length === 0
              ? 'Delivery needs a payload (Build) and an HTTP(S) listener (Listeners) — create both first.'
              : payloads.length === 0
                ? 'No payload in this engagement yet — build one under Build first.'
                : 'No HTTP(S) listener in this engagement yet — create one under Listeners first.'}
          </div>
        ) : (
          <>
            <div className="inline-form">
              <select
                value={payloadId}
                onChange={(e) => setPayloadId(e.target.value)}
                title="The payload the fetch delivers; the newest build stands in when unnamed"
              >
                <option value="">Newest build</option>
                {payloads.map((p) => {
                  const dead = !deliverable(p)
                  return (
                    <option key={p.artifactId} value={p.artifactId} disabled={dead}>
                      {payloadLabel(p)}
                      {dead ? ' — credential dead' : ''}
                    </option>
                  )
                })}
              </select>
              <button className="primary" onClick={() => void onRender()} disabled={busy}>
                {busy ? 'Rendering…' : 'Render'}
              </button>
            </div>
            {/* The choices almost every render leaves alone. The payload bakes
                its own endpoints and enrollment credential; the fetch still
                needs a front to ride and a download credential to present, and
                the defaults -- the hardened front, single use, half an hour --
                are the right posture for the one-paste-one-download shape. */}
            <details className="build-advanced">
              <summary title="The fetch front and the minted credential's policy — the defaults fit the one-paste-one-download shape">
                Fetch front &amp; credential — {frontLabel} · {usesLabel.toLowerCase()} ·{' '}
                {lifetimeLabel.toLowerCase()}
              </summary>
              <div className="inline-form">
                <select
                  value={listenerId}
                  onChange={(e) => setListenerId(e.target.value)}
                  title="Every HTTP(S)/mTLS listener serves the payload fetch on its own public endpoint -- there is no separate file host, and the teamserver's own address never appears in a command. Name a listener when the fetch must cross a specific front (a redirector, say); unnamed prefers https, then mTLS, then the newest."
                >
                  <option value="">Auto — hardened front first</option>
                  {webListeners.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name} · {l.transport} · {l.publicEndpoint}
                    </option>
                  ))}
                </select>
                <select
                  value={maxUses}
                  onChange={(e) => setMaxUses(Number(e.target.value))}
                  title="How many served fetches the minted credential allows"
                >
                  {USE_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
                <select
                  value={lifetimeMinutes}
                  onChange={(e) => setLifetimeMinutes(Number(e.target.value))}
                  title="How long the minted credential lives"
                >
                  {LIFETIME_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>
            </details>
          </>
        )}

        <h3 className="jobs-head">
          Kept launchers
          <HelpHint>
            Every fetch render lands in this list. Commands re-render from each row's URL and
            credential, so an old row always copies in the current shape. Delete closes a row's
            whole lifecycle: the credential dies wherever a copy of the command carries it, the
            row goes, and the mint's history is the audit trail's to keep.
          </HelpHint>
        </h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th></th>
                <th>Cut</th>
                <th>Payload</th>
                <th>Front</th>
                <th>Credential</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6}>
                    <div className="empty">
                      <Icon name="copy" />
                      No launchers kept yet — every render above lands here, re-copyable until its
                      credential expires.
                    </div>
                  </td>
                </tr>
              )}
              {rows.map((row) => {
                const expired = new Date(row.expiresAt).getTime() <= now
                const revoked = row.revokedAt != null
                // A bounded credential whose token is no longer stored is out
                // of downloads no matter which end it met -- spent to zero,
                // revoked, or expired and swept; reading null as "alive" was
                // exactly the contradiction the old two-column display showed.
                const spent =
                  row.maxUses !== 0 &&
                  (row.tokenRemainingUses == null || row.tokenRemainingUses <= 0)
                const live = !revoked && !expired && !spent
                const status = revoked
                  ? `revoked ${new Date(row.revokedAt!).toLocaleTimeString()}`
                  : expired
                    ? `expired ${new Date(row.expiresAt).toLocaleTimeString()}`
                    : spent
                      ? 'no downloads left'
                      : row.maxUses === 0
                        ? `usable · unlimited downloads · until ${new Date(row.expiresAt).toLocaleTimeString()}`
                        : `usable · ${row.tokenRemainingUses} of ${row.maxUses} downloads left · until ${new Date(row.expiresAt).toLocaleTimeString()}`
                // The commands expand under their own row -- the shared
                // chevron-and-row-click affordance every detail table uses,
                // so the one-liners belong beside the row they were cut for,
                // not pooled below the table. Only while the credential
                // still serves fetches: a dead credential's command would
                // download nothing.
                const commandsOpen = commandsFor === row.launcherId
                return (
                  <Fragment key={row.launcherId}>
                    <tr
                      className={live ? 'console-row' : 'row-dim'}
                      onClick={
                        live
                          ? () =>
                              setCommandsFor((current) =>
                                current === row.launcherId ? null : row.launcherId,
                              )
                          : undefined
                      }
                    >
                      <td onClick={(e) => e.stopPropagation()}>
                        {live && (
                          <button
                            className={`ghost sm row-expand${commandsOpen ? ' open' : ''}`}
                            aria-label={commandsOpen ? 'Hide the commands' : 'Show the commands'}
                            title={
                              commandsOpen
                                ? 'Hide the one-liners'
                                : 'The one-liners this row was cut with'
                            }
                            onClick={() =>
                              setCommandsFor((current) =>
                                current === row.launcherId ? null : row.launcherId,
                              )
                            }
                          >
                            <Icon name={commandsOpen ? 'chevronDown' : 'chevronRight'} />
                          </button>
                        )}
                      </td>
                      <td title={`Cut by ${row.createdByHandle}`}>
                        {new Date(row.createdAt).toLocaleString()}
                      </td>
                      <td>
                        {/* The library's identifier for the delivered
                            payload, at the Payloads tab's own column width,
                            so a row matches its payload without the id
                            detour; a deleted payload falls back to the bare
                            artifact id. */}
                        {row.payloadFingerprint ? (
                          <code
                            title={`Fingerprint ${row.payloadFingerprint} · artifact ${row.payloadId} — match it on the Payloads tab`}
                          >
                            {row.payloadFingerprint.slice(0, 16)}
                          </code>
                        ) : (
                          <code
                            className="muted"
                            title={`Artifact ${row.payloadId} — no longer in the payload library`}
                          >
                            {row.payloadId.slice(0, 8)}
                          </code>
                        )}
                      </td>
                      <td title={row.frontEndpoint}>{row.frontName}</td>
                      <td
                        title={
                          live
                            ? 'The credential still serves fetches: copies of the command download until the budget or the window closes'
                            : 'This credential no longer serves fetches; the row stays until deleted (Delete also kills a live credential)'
                        }
                      >
                        {status}
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <div className="row-actions">
                          <button className="ghost sm" onClick={() => void onDelete(row)}>
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                    {commandsOpen && (
                      <tr className="payload-detail-row">
                        <td colSpan={6}>
                          <div className="upgrade-panel">
                            <p>
                              Fetch URL <code>{row.url}</code> · credential{' '}
                              <code className="upgrade-command">{row.tokenSecret}</code>{' '}
                              <CopyButton text={row.tokenSecret} />
                            </p>
                            {row.launchers.map((launcher) => (
                              <div key={launcher.id} className="upgrade-launcher" title={launcherHint(launcher.id)}>
                                <span title={`For ${launcher.os} targets`}>
                                  <Icon name={osIconFor(launcher.os)} className="wire-icon" />
                                </span>
                                <code>{launcher.id}</code>
                                <code className="upgrade-command">{launcher.command}</code>
                                <CopyButton text={launcher.command} />
                              </div>
                            ))}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
      )}
    </section>
  )
}
