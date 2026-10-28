import { Fragment, useCallback, useEffect, useState } from 'react'
import {
  type ListenerSummary,
  type MintedDeployToken,
  type PayloadSummary,
  deletePayload,
  listListeners,
  listPayloads,
  mintDeployToken,
  revokeDeployToken,
} from '../api'
import { frontFor, hostPortOf } from '../fronts'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'
import { CopyButton } from '../components/CopyButton'
import { fmtBytes } from '../format'

// The engagement's payload library: the payload store's durable listing, the
// view that outlives the Build page's bounded, process-local job queue. A
// payload built weeks ago is still here -- downloadable again, its baked
// credential's use budget readable (how many enrolls it has left, read live
// off the token store), its credential revocable, and deletable (which also
// stops the fetch URL serving) -- whatever happened to the build queue or
// the teamserver process. This is the record; the Build page's recent-builds
// strip is only the queue's status.
//
// Each row expands into the build's own parameters -- the beacon profile,
// the wire knobs, the credential's minted shape -- snapshotted at bake time,
// so "what did I build" never depends on remembering the form. Rows are
// single-line; the detail carries what does not fit.
// The long-form explanation lives in docs/operations/operator-ui.md; the
// filter field and actions carry their own hover text.

// The taxonomy's wire class names read as noise for the only implant class
// there is, so the library shows the operator-facing kind; the raw value
// stays filterable.
function kindLabel(klass: string): string {
  if (klass === 'Implant') return 'implant'
  if (klass === 'WebShell') return 'web shell'
  return klass
}

export function PayloadsView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [payloads, setPayloads] = useState<PayloadSummary[]>([])
  const [listeners, setListeners] = useState<ListenerSummary[]>([])
  // The filter commits on Enter or the Search button, like every text search
  // in the operator UI.
  const [filterDraft, setFilterDraft] = useState('')
  const [filter, setFilter] = useState('')
  const [revoking, setRevoking] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [mintOpen, setMintOpen] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [list, fronts] = await Promise.all([
        listPayloads(engagementId),
        listListeners(engagementId).catch(() => [] as ListenerSummary[]),
      ])
      setPayloads(list)
      setListeners(fronts)
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }, [engagementId])

  // The live tick rides along: a credential's remaining uses and liveness
  // move server-side (a paste spends it, a revoke kills it), and the roster
  // needs to re-read them without a manual refresh -- the same cadence every
  // other live tab follows.
  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  const onRevokeToken = async (tokenId: string) => {
    if (
      !window.confirm(
        `Revoke baked token ${tokenId.slice(0, 8)}? The credential stops working immediately; a deployed artifact that has not enrolled yet will not be able to.`,
      )
    )
      return
    setRevoking(tokenId)
    try {
      await revokeDeployToken(engagementId, tokenId)
      setError(null)
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setRevoking(null)
    }
  }

  const onDelete = async (p: PayloadSummary) => {
    if (
      !window.confirm(
        `Delete payload ${p.fingerprint.slice(0, 12)} (${kindLabel(p.class)}${p.target ? ' ' + p.target : ''})? ` +
        'The stored bytes are gone and the fetch URL stops serving. The deletion is audited.',
      )
    )
      return
    try {
      await deletePayload(engagementId, p.artifactId)
      setError(null)
      await refresh()
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <section className="view">
      <h2>
        Payloads
        <HelpHint>
          Every payload this engagement built — durable, restart-safe, filterable. The credential
          column reads the baked token's use budget live; the chevron unfolds the build's
          parameters. Mint credential, beside the filter, mints a standalone delivery credential
          for hand delivery — no payload attached.
        </HelpHint>
      </h2>
      <div className="card">
        <div className="inline-form">
          <input
            className="filter-text"
            placeholder="Filter (linux, aot, listener, fingerprint…)"
            value={filterDraft}
            onChange={(e) => setFilterDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') setFilter(filterDraft)
            }}
            title="Free text across class, language, target, listener, and fingerprint. Enter or the Search button applies."
          />
          <button
            className="ghost"
            onClick={() => setFilter(filterDraft)}
            title="Apply the filter (Enter works too)"
          >
            Search
          </button>
          <button className="ghost" onClick={() => void refresh()}>
            <Icon name="refresh" />
            Refresh
          </button>
          <button
            className="ghost"
            onClick={() => setMintOpen(true)}
            title="Mint a standalone deployment credential -- the same token shape a build bakes, for hand delivery; single-use and one hour by default, the secret shows once"
          >
            Mint credential
          </button>
        </div>
        {mintOpen && (
          <MintTokenDialog engagementId={engagementId} onClose={() => setMintOpen(false)} />
        )}
        {error && <p className="error">{error}</p>}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th></th>
                <th>Built</th>
                <th>Kind</th>
                <th>Target</th>
                <th>Listener</th>
                <th>Credential</th>
                <th>Size</th>
                <th>Fingerprint</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {payloads.length === 0 && (
                <tr>
                  <td colSpan={9}>
                    <div className="empty">
                      <Icon name="package" />
                      No payloads stored yet -- build one on the Build tab.
                    </div>
                  </td>
                </tr>
              )}
              {payloads
                  .filter((p) => {
                    const q = filter.trim().toLowerCase()
                    if (!q) return true
                    const front = frontFor(p.endpoint, listeners)
                    return [p.class, p.unitId, p.kind, p.target, p.build?.format, p.endpoint, front?.name, p.fingerprint].some(
                      (v) => v?.toLowerCase().includes(q),
                    )
                  })
                  .map((p) => {
                    const front = frontFor(p.endpoint, listeners)
                    const expired =
                      p.tokenExpiresAt !== null && new Date(p.tokenExpiresAt).getTime() < Date.now()
                    const used =
                      p.tokenMaxUses !== null && p.tokenRemainingUses !== null
                        ? p.tokenMaxUses - p.tokenRemainingUses
                        : null
                    const open = expanded === p.artifactId
                    return (
                      <Fragment key={p.artifactId}>
                        <tr
                          className="console-row"
                          onClick={() => setExpanded(open ? null : p.artifactId)}
                        >
                          <td onClick={(e) => e.stopPropagation()}>
                            <button
                              className={`ghost sm row-expand${open ? ' open' : ''}`}
                              aria-label={open ? 'Collapse build parameters' : 'Expand build parameters'}
                              title={open ? 'Hide the build parameters' : 'The parameters this payload was built with'}
                              onClick={() => setExpanded(open ? null : p.artifactId)}
                            >
                              <Icon name={open ? 'chevronDown' : 'chevronRight'} />
                            </button>
                          </td>
                          <td>{new Date(p.builtAt).toLocaleString()}</td>
                          <td>
                            <code>
                              {p.unitId} · {kindLabel(p.class)}
                              {p.kind === 'loader' && (
                                <span
                                  className="muted"
                                  title={`Loader: fetches ${p.deliversPayloadId ?? 'its payload'} sealed and runs it from a memfd -- nothing lands on disk. Deleting the delivered artifact ends the delivery.`}
                                >
                                  {' '}· loader
                                </span>
                              )}
                            </code>
                          </td>
                          <td>
                            {p.target ?? '—'}
                            {p.build?.format && p.build.format !== 'exe' && (
                              <span className="muted"> · {p.build.format}</span>
                            )}
                          </td>
                          <td>
                            <span
                              title={
                                front
                                  ? `The engagement's ${front.transport} listener: ${p.endpoint} (enroll + contact)`
                                  : `No listener serves this address (typed for a redirector): ${p.endpoint}`
                              }
                            >
                              {front ? (
                                <>
                                  {front.name} <span className="muted">({front.transport})</span> ·{' '}
                                  <code>{hostPortOf(p.endpoint ?? '')}</code>
                                </>
                              ) : (
                                <>
                                  <code>{hostPortOf(p.endpoint ?? '')}</code>{' '}
                                  <span className="muted">manual</span>
                                </>
                              )}
                            </span>
                          </td>
                          <td onClick={(e) => e.stopPropagation()}>
                            {p.tokenId ? (
                              used !== null && p.tokenMaxUses !== null && p.tokenRemainingUses !== null ? (
                                <span
                                  title={`Baked token ${p.tokenId}${
                                    p.tokenExpiresAt
                                      ? ` · expires ${new Date(p.tokenExpiresAt).toLocaleString()}`
                                      : ''
                                  } -- one spend per enrolled host; a zero budget is unlimited`}
                                >
                                  {p.tokenMaxUses === 0 ? (
                                    <>
                                      unlimited{used > 0 ? ` · ${used} spent` : ''}
                                    </>
                                  ) : (
                                    <>
                                      {used}/{p.tokenMaxUses} spent · {p.tokenRemainingUses} left
                                    </>
                                  )}
                                  {expired ? ' · expired' : ''}
                                  {revoking === p.tokenId ? (
                                    ' (revoking…)'
                                  ) : (
                                    <>
                                      {' '}
                                      <button
                                        className="sm danger"
                                        onClick={() => void onRevokeToken(p.tokenId!)}
                                        title="The baked credential stops working at the next enrollment attempt"
                                      >
                                        Revoke
                                      </button>
                                    </>
                                  )}
                                </span>
                              ) : (
                                // A state this row cannot read means the store no
                                // longer holds the token: revoked (which reads as
                                // gone by contract), or hard-deleted with its
                                // launcher. The revoke endpoint is
                                // idempotent-refusing -- a click here could only
                                // ever answer 404 -- so no button is offered.
                                <span
                                  className="muted"
                                  title={`Baked token ${p.tokenId} is no longer held -- revoked, or deleted with its launcher. No more enrollments, and nothing left to revoke.`}
                                >
                                  no enrolls left
                                </span>
                              )
                            ) : (
                              <span className="muted">—</span>
                            )}
                          </td>
                          <td title={`${p.size} bytes`}>{fmtBytes(p.size)}</td>
                          <td>
                            <code title={p.fingerprint}>{p.fingerprint.slice(0, 16)}</code>
                          </td>
                          <td onClick={(e) => e.stopPropagation()}>
                            <a
                              className="download-link"
                              href={`engagements/${engagementId}/payloads/${p.artifactId}`}
                              download
                            >
                              Download
                            </a>{' '}
                            <button className="sm danger" onClick={() => void onDelete(p)}>
                              Delete
                            </button>
                          </td>
                        </tr>
                        {open && (
                          <tr className="payload-detail-row">
                            <td colSpan={9}>
                              <PayloadDetail payload={p} />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}

// The build's own parameters, snapshotted at bake time and read back from the
// library row: what the form carried when this artifact was generated. Null
// fields mean the build's default -- the snapshot records what was set, and
// the defaults live in the Build form's help text.
function PayloadDetail({ payload }: { payload: PayloadSummary }) {
  const b = payload.build
  const line = (label: string, value: React.ReactNode): [string, React.ReactNode] => [label, value]
  const lines: [string, React.ReactNode][] = [
    line('Fingerprint', <code>{payload.fingerprint}</code>),
    line('Built', new Date(payload.builtAt).toLocaleString()),
    line(
      'Credential',
      payload.tokenId ? (
        <>
          token <code>{payload.tokenId.slice(0, 8)}</code>
          {b?.tokenMaxUses != null
            ? b.tokenMaxUses === 0
              ? ' · unlimited uses'
              : ` · max ${b.tokenMaxUses} enroll${b.tokenMaxUses === 1 ? '' : 's'}`
            : ''}
          {payload.tokenExpiresAt
            ? ` · expires ${new Date(payload.tokenExpiresAt).toLocaleString()}`
            : ''}
          {payload.tokenMaxUses === 0
            ? ''
            : payload.tokenMaxUses != null && payload.tokenRemainingUses != null
              ? ` · ${payload.tokenRemainingUses} left`
              : ' · no enrolls left (revoked or deleted with its launcher)'}
        </>
      ) : payload.class === 'WebShell' && payload.credential ? (
        <>
          {payload.target?.startsWith('rod-') ? 'connection key' : 'connection password'}{' '}
          <code>{payload.credential}</code>
        </>
      ) : (
        'none baked'
      ),
    ),
  ]
  if (b) {
    lines.push(
      line('Mode', b.mode ?? 'poll (default)'),
      line('Format', b.format ?? 'exe (default)'),
      line('TLS trust', b.trust === 'public' ? 'public — real-domain front' : 'pinned (default)'),
      line(
        'Contact',
        b.sleepSeconds != null
          ? `every ${b.sleepSeconds}s ± ${b.jitterSeconds ?? 0}s jitter`
          : 'defaults',
      ),
      line('Kill date', b.killDate ? new Date(b.killDate).toLocaleString() : 'none (open-ended)'),
    )
    if (b.enrollPath) lines.push(line('Enroll path', <code>{b.enrollPath}</code>))
    if (b.userAgent) lines.push(line('User agent', <code>{b.userAgent}</code>))
    if (b.requestTimeoutSeconds != null)
      lines.push(line('Request timeout', `${b.requestTimeoutSeconds}s`))
    if (b.envelope) lines.push(line('Enroll body', b.envelope))
    lines.push(
      line(
        'Contact protection',
        b.contactProtection == null ? 'on (default)' : b.contactProtection ? 'on' : 'off',
      ),
    )
  }
  if (b?.fallbackEndpoints?.length)
    lines.push(
      line('Fallback fronts', b.fallbackEndpoints.map((f) => hostPortOf(f)).join(' · ')),
    )
  lines.push(line('Content type', <code>{payload.contentType}</code>))
  lines.push(line('Size', `${payload.size} bytes`))

  return (
    <div className="payload-detail">
      {lines.map(([label, value]) => (
        <div className="payload-detail-line" key={label}>
          <span className="muted">{label}</span>
          <span>{value}</span>
        </div>
      ))}
    </div>
  )
}

// A standalone credential mint: the same token shape a build bakes, minted
// for hand delivery without a payload attached -- the launcher one-liners
// aimed at an operator-run edge, a drop, a scripted enrollment. The knobs
// match the route's bounds (uses 1..10000, lifetime 60s..30d) but read in
// the units an operator thinks in; the defaults are the single-use,
// one-hour shape a body-less mint would give. The secret returns once and
// only once, so the dialog holds the result open until dismissed -- closing
// without copying it is losing it -- and offers the revoke right beside it
// for the minted-by-mistake case (a standalone token has no payload row to
// revoke from).
function MintTokenDialog({ engagementId, onClose }: { engagementId: string; onClose: () => void }) {
  const [uses, setUses] = useState('1')
  const [minutes, setMinutes] = useState('60')
  const [busy, setBusy] = useState(false)
  const [minted, setMinted] = useState<MintedDeployToken | null>(null)
  const [revoked, setRevoked] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (busy || minted) return
    setBusy(true)
    try {
      const maxUses = Math.min(10_000, Math.max(1, Math.round(Number(uses) || 1)))
      const lifetimeSeconds = Math.min(
        2_592_000,
        Math.max(60, Math.round((Number(minutes) || 60) * 60)),
      )
      setMinted(await mintDeployToken(engagementId, { maxUses, lifetimeSeconds }))
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const onRevoke = async () => {
    if (!minted || busy) return
    if (!window.confirm('Revoke this token now? Its remaining uses stop working immediately.'))
      return
    setBusy(true)
    try {
      await revokeDeployToken(engagementId, minted.tokenId)
      setRevoked(true)
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <form className="card modal" onSubmit={onSubmit}>
        <h3>
          Mint delivery credential <code>deploy token</code>
        </h3>
        {minted ? (
          <>
            <p className="muted">
              Token <code>{minted.tokenId.slice(0, 8)}</code> · {minted.maxUses} use
              {minted.maxUses === 1 ? '' : 's'} · expires{' '}
              {new Date(minted.expiresAt).toLocaleString()}
            </p>
            <div className="task-detail-line">
              <span className="muted">secret</span> <code>{minted.secret}</code>{' '}
              <CopyButton text={minted.secret} />
            </div>
            <p className={revoked ? 'muted' : 'error'}>
              {revoked
                ? 'Revoked -- the secret above is dead; close and mint again if needed.'
                : 'The secret returns only once. Copy it before closing -- this dialog is the last place it reads out.'}
            </p>
            <div className="inline-form">
              {!revoked && (
                <button className="ghost" type="button" onClick={() => void onRevoke()} disabled={busy}>
                  Revoke now
                </button>
              )}
              <span className="spacer" />
              <button className="primary" type="button" onClick={onClose}>
                Done
              </button>
            </div>
          </>
        ) : (
          <>
            <label>
              Max uses
              <input
                type="number"
                min={1}
                max={10000}
                value={uses}
                onChange={(e) => setUses(e.target.value)}
              />
              <span className="field-help">How many implants may enroll on this token (1-10000).</span>
            </label>
            <label>
              Lifetime (minutes)
              <input
                type="number"
                min={1}
                max={43200}
                value={minutes}
                onChange={(e) => setMinutes(e.target.value)}
              />
              <span className="field-help">
                How long the window stays open (60 seconds to 30 days).
              </span>
            </label>
            <p className="muted">
              The mint is audited; the secret never enters the trail. A frozen or retired
              engagement mints nothing.
            </p>
            {error && <p className="error">{error}</p>}
            <div className="inline-form">
              <button className="ghost" type="button" onClick={onClose}>
                Cancel
              </button>
              <button className="primary" type="submit" disabled={busy}>
                {busy ? 'Minting…' : 'Mint'}
              </button>
            </div>
          </>
        )}
      </form>
    </div>
  )
}
