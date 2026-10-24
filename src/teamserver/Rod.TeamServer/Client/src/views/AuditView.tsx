import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  type AuditEventEntry,
  type DigestEntry,
  type DigestWindow,
  type HandoffDigest,
  getHandoffDigest,
  getHandoffDigestMarkdown,
  listAudit,
} from '../api'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'

// The operational event log: the per-engagement, append-only,
// hash-chained audit trail, oldest-first in causal order. Every action that
// changes engagement state or binds an identity produces an immutable,
// attributed event. Two reads over the one trail:
//
// - the ledger -- the dense, paged, filterable table a forensic read wants:
//   kind filter, free-text search across verb/payload/outcome, and "load
//   older" walking back through history;
// - the handoff window (architecture.md Sec 11.1) -- the resuming
//   operator's read: the trail windowed and curated into one ordered
//   account of the watch's beats, with the counts that size the shift, the
//   chain-verification line, and the markdown handoff note. It is a query
//   over this ledger, so it lives here as a reading mode -- the resume
//   question is asked where the trail is read, not on a tab of its own.
//
// The narrative rendering of the same facts is the report export's timeline
// section (and the standalone /timeline endpoint stays a scripting
// deliverable); the report exports consume this same trail.

const ALL_KINDS = '(all)'

// Events without an operator or implant carry the empty GUID on the wire (a
// non-nullable server field), not null -- render it as a dash, not as
// "00000000-...". Implant ids arrive normalized to the compact form, so
// the absent marker also reads as the empty string.
const EMPTY_GUID = '00000000-0000-0000-0000-000000000000'

function shortId(id: string): string {
  return id === EMPTY_GUID || id === '' ? '\u2014' : id.slice(0, 8)
}

export function AuditView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [mode, setMode] = useState<'ledger' | 'window'>('ledger')

  return (
    <section className="view">
      <h2>
        Audit
        <HelpHint>
          The engagement's append-only, hash-chained ledger — tampering with a stored event breaks
          the chain at the next link — every recorded fact paged and filterable, with the windowed
          watch-resume read beside it.
        </HelpHint>
      </h2>
      <div className="card">
        <div className="table-toolbar">
          <button
            className={mode === 'ledger' ? 'sm' : 'ghost sm'}
            onClick={() => setMode('ledger')}
            title="The dense, paged, filterable table a forensic read wants."
          >
            Ledger
          </button>
          <button
            className={mode === 'window' ? 'sm' : 'ghost sm'}
            onClick={() => setMode('window')}
            title="The handoff digest: the window you pick, the watch as one ordered account (architecture.md Sec 11.1)."
          >
            Handoff window
          </button>
        </div>
        {mode === 'ledger' ? (
          <LedgerSection engagementId={engagementId} onlineTick={onlineTick} />
        ) : (
          <HandoffWindowSection engagementId={engagementId} onlineTick={onlineTick} />
        )}
      </div>
    </section>
  )
}

function LedgerSection({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [events, setEvents] = useState<AuditEventEntry[]>([])
  const [eventsCursor, setEventsCursor] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [kind, setKind] = useState(ALL_KINDS)
  // The text search commits on Enter or the Search button; the kind dropdown
  // stays live.
  const [queryDraft, setQueryDraft] = useState('')
  const [query, setQuery] = useState('')

  const refresh = useCallback(async () => {
    setBusy(true)
    try {
      // The newest window of the trail; older pages load on demand.
      const page = await listAudit(engagementId)
      setEvents(page.items)
      setEventsCursor(page.nextCursor)
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
      setLoading(false)
    }
  }, [engagementId])

  const loadOlder = useCallback(async () => {
    if (!eventsCursor) return
    setBusy(true)
    try {
      const page = await listAudit(engagementId, eventsCursor)
      setEvents((current) => [...current, ...page.items])
      setEventsCursor(page.nextCursor)
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }, [engagementId, eventsCursor])

  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  const kinds = useMemo(() => {
    const set = new Set(events.map((e) => e.kind))
    return [ALL_KINDS, ...[...set].sort()]
  }, [events])

  const filtered = useMemo(() => {
    const byKind = kind === ALL_KINDS ? events : events.filter((e) => e.kind === kind)
    const needle = query.trim().toLowerCase()
    if (needle === '') return byKind
    return byKind.filter(
      (e) =>
        e.verb.toLowerCase().includes(needle) ||
        e.payload.toLowerCase().includes(needle) ||
        (e.output ?? '').toLowerCase().includes(needle) ||
        e.outcome.toLowerCase().includes(needle) ||
        e.operatorHandle.toLowerCase().includes(needle),
    )
  }, [events, kind, query])

  return (
    <>
      <div className="inline-form">
        <select
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          title="Event kind filter"
          aria-label="Event kind filter"
        >
          {kinds.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
        <input
          className="filter-text"
          placeholder="Search verb, payload, outcome, operator…"
          value={queryDraft}
          onChange={(e) => setQueryDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') setQuery(queryDraft)
          }}
          title="Free text across verb, payload, output, outcome, and operator. Enter or the Search button applies; the kind filter above is live."
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
      {error && <p className="error">{error}</p>}
      {loading ? (
        <div className="empty">
          <span className="spinner" />
          Loading audit trail…
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>At</th>
                <th>Kind</th>
                <th>Verb</th>
                <th>Operator</th>
                <th>Implant</th>
                <th>Payload</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <div className="empty">
                      <Icon name="list" />
                      No events recorded yet.
                    </div>
                  </td>
                </tr>
              )}
              {[...filtered].reverse().map((e) => (
                <tr key={e.eventId}>
                  <td>{new Date(e.at).toLocaleString()}</td>
                  <td>
                    <span className="status">{e.kind}</span>
                  </td>
                  <td>
                    <code>{e.verb}</code>
                  </td>
                  <td>
                    {/* The resolved handle, with the guid on hover for the rare
                        event whose operator record no longer resolves. */}
                    <code title={e.operatorId}>{e.operatorHandle}</code>
                  </td>
                  <td>
                    <code>{shortId(e.implantId)}</code>
                  </td>
                  <td>
                    <pre className="output">{e.payload || '\u2014'}</pre>
                  </td>
                  <td>{e.outcome || '\u2014'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {eventsCursor && (
        <div className="load-more">
          <button className="ghost" onClick={() => void loadOlder()} disabled={busy}>
            {busy ? 'Loading…' : 'Load older'}
          </button>
        </div>
      )}
    </>
  )
}

const QUICK_WINDOWS: readonly { label: string; hours: number }[] = [
  { label: 'Last 12h', hours: 12 },
  { label: 'Last 24h', hours: 24 },
  { label: 'Last 48h', hours: 48 },
]

function when(iso: string): string {
  return new Date(iso).toLocaleString()
}

function entryActor(e: DigestEntry): string {
  return e.operator?.handle ?? 'system'
}

function entrySubject(e: DigestEntry): string {
  return e.implant?.class ?? '\u2014'
}

// The non-zero counts, in watch reading order, so the row sizes the watch
// before the table tells it.
function countChips(d: HandoffDigest): { n: number; label: string }[] {
  const s = d.summary
  return [
    { n: s.sessionsOpened, label: 'sessions opened' },
    { n: s.sessionsClosed, label: 'sessions closed' },
    { n: s.implantsEnrolled, label: 'implants enrolled' },
    { n: s.implantsRetired, label: 'implants retired' },
    { n: s.tasksIssued, label: 'tasks issued' },
    { n: s.tasksCompleted, label: 'completed' },
    { n: s.tasksCancelled, label: 'cancelled' },
    { n: s.roeRefusals, label: 'ROE refusals' },
    { n: s.notesAdded, label: 'notes added' },
    { n: s.shellSessionsOpened, label: 'shells opened' },
    { n: s.shellSessionsEnded, label: 'shells ended' },
  ].filter((c) => c.n > 0)
}

function HandoffWindowSection({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  // undefined from/to asks the server for its default: to = now, from =
  // twelve hours before it. Picking anchors the window where it was picked;
  // refresh re-reads the same bounds, so late-landing facts inside the window
  // appear while the window itself never slides.
  const [bounds, setBounds] = useState<DigestWindow>({})
  const [digest, setDigest] = useState<HandoffDigest | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [copying, setCopying] = useState(false)
  // Custom-bound drafts; they commit on Apply, not per keystroke.
  const [fromDraft, setFromDraft] = useState('')
  const [toDraft, setToDraft] = useState('')

  const refresh = useCallback(async () => {
    setBusy(true)
    try {
      setDigest(await getHandoffDigest(engagementId, bounds))
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
      setLoading(false)
    }
  }, [engagementId, bounds])

  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  const pickQuick = (hours: number) => {
    const to = new Date()
    const from = new Date(to.getTime() - hours * 3_600_000)
    setBounds({ from: from.toISOString(), to: to.toISOString() })
    setFromDraft('')
    setToDraft('')
  }

  const applyCustom = () => {
    const from = fromDraft ? new Date(fromDraft).toISOString() : undefined
    const to = toDraft ? new Date(toDraft).toISOString() : undefined
    setBounds({ from, to })
  }

  const copyHandoffNote = async () => {
    setCopying(true)
    try {
      const markdown = await getHandoffDigestMarkdown(engagementId, bounds)
      await navigator.clipboard.writeText(markdown)
      setNotice('Handoff note copied -- paste it to the next watch.')
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setCopying(false)
    }
  }

  return (
    <>
      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      <div className="inline-form">
        {QUICK_WINDOWS.map((q) => (
          <button
            key={q.hours}
            className="ghost"
            onClick={() => pickQuick(q.hours)}
            title={`Anchor the window to the ${q.label.toLowerCase()}`}
          >
            {q.label}
          </button>
        ))}
        <input
          className="filter-text"
          type="datetime-local"
          value={fromDraft}
          onChange={(e) => setFromDraft(e.target.value)}
          title="Custom window start (inclusive)"
          aria-label="Window start"
        />
        <input
          className="filter-text"
          type="datetime-local"
          value={toDraft}
          onChange={(e) => setToDraft(e.target.value)}
          title="Custom window end (inclusive; empty = now)"
          aria-label="Window end"
        />
        <button className="ghost" onClick={applyCustom} title="Apply the custom bounds">
          Apply
        </button>
        <button className="ghost" onClick={() => void refresh()} disabled={busy}>
          <Icon name="refresh" />
          Refresh
        </button>
        <button
          className="ghost"
          onClick={() => void copyHandoffNote()}
          disabled={copying}
          title="Copy the same account as a markdown handoff note"
        >
          {copying ? 'Copying…' : 'Copy handoff note'}
        </button>
      </div>
      {digest && (
        <p className="muted" title={`Integrity ${digest.contentHash}`}>
          Window {when(digest.from)} — {when(digest.to)}, generated {when(digest.generatedAt)}.{' '}
          {digest.chainVerified
            ? 'Audit chain verified.'
            : `Audit chain verification FAILED: ${digest.chainBreak}`}
        </p>
      )}

      {digest && countChips(digest).length > 0 && (
        <div className="count-row">
          {countChips(digest).map((c) => (
            <span key={c.label} className="chip">
              <strong>{c.n}</strong> {c.label}
            </span>
          ))}
        </div>
      )}

      {loading ? (
        <div className="empty">
          <span className="spinner" />
          Reading the trail…
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>At</th>
                <th>Kind</th>
                <th>Verb</th>
                <th>Operator</th>
                <th>Implant</th>
                <th>Payload</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {(!digest || digest.entries.length === 0) && (
                <tr>
                  <td colSpan={7}>
                    <div className="empty">
                      <Icon name="activity" />
                      No watch events in the window.
                    </div>
                  </td>
                </tr>
              )}
              {digest?.entries.map((e) => (
                <tr key={e.eventId}>
                  <td title={when(e.at)}>{when(e.at)}</td>
                  <td>
                    <span className="status">{e.kind}</span>
                  </td>
                  <td>
                    <code>{e.task?.verb ?? e.verb}</code>
                  </td>
                  <td>
                    <code title={e.operator?.operatorId ?? undefined}>{entryActor(e)}</code>
                  </td>
                  <td>
                    <code title={e.implant?.implantId}>{entrySubject(e)}</code>
                  </td>
                  <td>
                    <pre className="output">{e.payload || '\u2014'}</pre>
                  </td>
                  <td>{e.task?.outcome ?? (e.outcome || '\u2014')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
