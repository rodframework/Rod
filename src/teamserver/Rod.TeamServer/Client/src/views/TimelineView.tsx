import { useCallback, useEffect, useMemo, useState } from 'react'
import { type AuditEventEntry, listAudit } from '../api'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'
import { engagementPath } from '../slots'
import { TIMELINE_STAGES, stageOfKind } from '../timelineStage'
import { ago, useNow } from '../when'

// The engagement's main screen (architecture.md Sec 15.4, ADR-013): the
// timeline -- the audited event stream itself, every recorded fact and
// the mutable collaboration rows that ride beside it, newest first. The
// same trail the ledger reads forensically and the report exports read
// narratively; this is the watch's live read of it. The stream lands
// from the audit endpoint's newest window (the live SSE tick refreshes
// it -- the stream is the fan-out, the trail is the truth), older
// history walks the keyset on demand, and the filters -- stage,
// operator, and free text across the entity ids and fields -- run
// client-side over what is loaded, because a filter must feel instant,
// not round-trip.

// Events without an operator or implant carry the empty GUID on the
// wire (a non-nullable server field), not null -- render it as no link,
// not as "00000000-...".
const EMPTY_GUID = '00000000-0000-0000-0000-000000000000'

function kindLabel(kind: string): string {
  return kind.replace(/([a-z])([A-Z])/g, '$1 $2')
}

export function TimelineView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [events, setEvents] = useState<AuditEventEntry[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [stage, setStage] = useState('')
  const [operator, setOperator] = useState('')
  // The text search commits on Enter or the Search button; the dropdowns
  // stay live.
  const [queryDraft, setQueryDraft] = useState('')
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  // The clock for relative stamps; a per-second tick keeps "2m ago"
  // moving without a live event to bump it.
  const now = useNow(1_000)

  const refresh = useCallback(async () => {
    setBusy(true)
    try {
      const page = await listAudit(engagementId)
      setEvents(page.items)
      setCursor(page.nextCursor)
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
      setLoading(false)
    }
  }, [engagementId])

  const loadOlder = useCallback(async () => {
    if (!cursor) return
    setBusy(true)
    try {
      const page = await listAudit(engagementId, cursor)
      setEvents((current) => [...current, ...page.items])
      setCursor(page.nextCursor)
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }, [engagementId, cursor])

  useEffect(() => {
    void refresh()
    // A stale filter must never survive an engagement switch.
    setExpanded(new Set())
    setStage('')
    setOperator('')
    setQueryDraft('')
    setQuery('')
  }, [refresh])

  // The live beat: any tasking, campaign, or collaboration movement
  // re-reads the newest window. The trail stays authoritative -- the
  // stream only says "something moved".
  useEffect(() => {
    if (onlineTick === 0) return
    void refresh()
  }, [onlineTick, refresh])

  const operators = useMemo(
    () => [...new Set(events.map((e) => e.operatorHandle))].sort(),
    [events],
  )

  const filtered = useMemo(() => {
    const byStage = stage === '' ? events : events.filter((e) => stageOfKind(e.kind) === stage)
    const byOperator =
      operator === '' ? byStage : byStage.filter((e) => e.operatorHandle === operator)
    const needle = query.trim().toLowerCase()
    if (needle === '') return byOperator
    return byOperator.filter((e) =>
      [
        e.kind,
        e.verb,
        e.payload,
        e.output ?? '',
        e.outcome,
        e.operatorHandle,
        e.operatorId,
        e.implantId,
        e.taskId,
      ]
        .join(' ')
        .toLowerCase()
        .includes(needle),
    )
  }, [events, stage, operator, query])

  const toggle = (eventId: string) => {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(eventId)) next.delete(eventId)
      else next.add(eventId)
      return next
    })
  }

  const oldest = events.length > 0 ? events[0].at : null

  return (
    <section className="view">
      <h2>
        Timeline
        <HelpHint>
          The audited event stream -- every recorded fact plus the comments and chat that ride
          beside the chain, newest first. The stage, operator, and text filters run over what is
          loaded; Load older walks back through history. The dense forensic read of the same
          trail is the Audit ledger under Report.
        </HelpHint>
      </h2>
      <div className="card">
        <div className="table-toolbar">
          <select
            value={stage}
            onChange={(e) => setStage(e.target.value)}
            aria-label="Stage filter"
            title="The lifecycle stage an event belongs to (client-side over the loaded window)"
          >
            <option value="">All stages</option>
            {TIMELINE_STAGES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            value={operator}
            onChange={(e) => setOperator(e.target.value)}
            aria-label="Operator filter"
            title="The acting operator (system included); derived from the loaded window"
          >
            <option value="">All operators</option>
            {operators.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </select>
          <input
            className="toolbar-search"
            placeholder="Search kind, verb, entity id, payload…"
            value={queryDraft}
            onChange={(e) => setQueryDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') setQuery(queryDraft)
            }}
            title="Free text across kind, verb, payload, outcome, operator, and the entity ids. Enter or the Search button applies."
          />
          <button
            className="ghost"
            onClick={() => setQuery(queryDraft)}
            title="Apply the text search (Enter works too)"
          >
            Search
          </button>
          <button className="ghost" onClick={() => void refresh()} disabled={busy}>
            <Icon name="refresh" />
            Refresh
          </button>
        </div>
        <p className="muted timeline-standfirst">
          {filtered.length} of {events.length} loaded
          {oldest && ` · since ${new Date(oldest).toLocaleString()}`}
          {cursor && ' · history continues below'}
        </p>
        {error && <p className="error">{error}</p>}
        {loading ? (
          <div className="empty">
            <span className="spinner" />
            Reading the trail…
          </div>
        ) : (
          <ol className="timeline-feed">
            {filtered.length === 0 && (
              <li className="empty">
                <Icon name="activity" />
                {events.length === 0
                  ? 'Nothing recorded yet.'
                  : 'Nothing in the window matches the filters.'}
              </li>
            )}
            {[...filtered].reverse().map((e) => {
              const open = expanded.has(e.eventId)
              const stageOfEvent = stageOfKind(e.kind)
              const implantLink =
                e.implantId !== EMPTY_GUID && e.implantId !== ''
                  ? engagementPath(engagementId, 'implants', e.implantId, 'interact')
                  : null
              return (
                <li key={e.eventId} className={`timeline-row${open ? ' open' : ''}`}>
                  <button
                    className="timeline-body"
                    onClick={() => toggle(e.eventId)}
                    title={open ? 'Collapse the event detail' : 'Expand payload and output'}
                  >
                    <span className="timeline-time" title={new Date(e.at).toLocaleString()}>
                      {ago(e.at, now)}
                    </span>
                    <span className={`stage-chip stage-${stageOfEvent}`}>{stageOfEvent}</span>
                    <span className="timeline-kind">{kindLabel(e.kind)}</span>
                    <span className="timeline-actor">
                      <code title={e.operatorId}>{e.operatorHandle}</code>
                    </span>
                    {implantLink && (
                      <a
                        className="timeline-entity"
                        href={implantLink}
                        onClick={(ev) => ev.stopPropagation()}
                        title={`Implant ${e.implantId}`}
                      >
                        {e.implantId.slice(0, 8)}
                      </a>
                    )}
                    <span className="timeline-payload">
                      {e.payload ? e.payload.split('\n')[0] : ''}
                    </span>
                    {e.mutable && (
                      <span
                        className="timeline-mutable"
                        title="A mutable collaboration row riding the stream outside the hash chain"
                      >
                        unchained
                      </span>
                    )}
                  </button>
                  {open && (
                    <div className="timeline-detail">
                      <div>
                        <span className="muted">verb</span> <code>{e.verb}</code>
                        {e.taskId !== EMPTY_GUID && e.taskId !== '' && (
                          <>
                            {' '}
                            <span className="muted">task</span>{' '}
                            <code>{e.taskId.slice(0, 8)}</code>
                          </>
                        )}
                        {e.outcome && (
                          <>
                            {' '}
                            <span className="muted">outcome</span> {e.outcome}
                          </>
                        )}
                      </div>
                      {e.payload && <pre className="output">{e.payload}</pre>}
                      {e.output && <pre className="output">{e.output}</pre>}
                    </div>
                  )}
                </li>
              )
            })}
          </ol>
        )}
        {cursor && (
          <div className="load-more">
            <button className="ghost" onClick={() => void loadOlder()} disabled={busy}>
              {busy ? 'Loading…' : 'Load older'}
            </button>
          </div>
        )}
      </div>
    </section>
  )
}
