import { useEffect, useState } from 'react'
import {
  type LootEntry,
  fetchArtifactBlob,
  listLoot,
} from '../api'
import { CommentsPanel } from '../components/CommentsPanel'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'
import { saveBlob } from '../download'

// The loot board: the artifact store typed by what gathered each piece
// (screenshots, harvested credentials riding exfil, pushed and pulled
// files), classified server-side off the verb's declared output kind --
// the board knows no verb, only the kinds. An assets-slot surface since
// the slots rework: loot is what the engagement holds. Opening a piece
// records the pull; a working note on a captured file is process
// knowledge on that artifact, folded behind its row.

const LOOT_KINDS = ['screenshot', 'credential', 'file', 'other'] as const

function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`
  return `${(size / (1024 * 1024)).toFixed(1)} MiB`
}

export function LootBoardView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [kind, setKind] = useState<string>('')
  const [items, setItems] = useState<LootEntry[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [preview, setPreview] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const page = await listLoot(engagementId, kind || undefined)
        if (cancelled) return
        setItems(page.items)
        setCursor(page.nextCursor)
        setError(null)
      } catch (e) {
        if (!cancelled) setError(String(e))
      }
    })()
    return () => {
      cancelled = true
    }
  }, [engagementId, kind, onlineTick])

  const loadOlder = async () => {
    if (!cursor) return
    try {
      const page = await listLoot(engagementId, kind || undefined, cursor)
      setItems((current) => [...current, ...page.items])
      setCursor(page.nextCursor)
    } catch (e) {
      setError(String(e))
    }
  }

  const open = async (entry: LootEntry) => {
    try {
      const blob = await fetchArtifactBlob(engagementId, entry.artifactId)
      if (entry.kind === 'screenshot') {
        setPreview((current) => {
          if (current) URL.revokeObjectURL(current)
          return URL.createObjectURL(blob)
        })
        return
      }
      saveBlob(blob, entry.name)
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <section className="view">
      <h2>
        Loot
        <HelpHint>
          The typed board over the artifact store: screenshots, harvested files, and exfil,
          classified by what gathered each piece. Opening a piece records the pull in the
          trail; comments fold behind a row as process knowledge on that artifact.
        </HelpHint>
      </h2>
      <div className="card">
        <div className="table-toolbar">
          <button className={kind === '' ? 'sm' : 'ghost sm'} onClick={() => setKind('')}>
            All
          </button>
          {LOOT_KINDS.map((k) => (
            <button
              key={k}
              className={kind === k ? 'sm' : 'ghost sm'}
              onClick={() => setKind(k)}
            >
              {k.charAt(0).toUpperCase() + k.slice(1)}
            </button>
          ))}
        </div>
        {preview && (
          <div className="loot-preview">
            <img src={preview} alt="captured screenshot" />
            <button
              className="ghost sm"
              onClick={() => {
                URL.revokeObjectURL(preview)
                setPreview(null)
              }}
            >
              Close preview
            </button>
          </div>
        )}
        <table>
          <thead>
            <tr>
              <th>Captured</th>
              <th>Kind</th>
              <th>Name</th>
              <th>Gathered by</th>
              <th>Size</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.map((entry) => (
              <LootRow
                key={entry.artifactId}
                engagementId={engagementId}
                entry={entry}
                onOpen={() => void open(entry)}
              />
            ))}
          </tbody>
        </table>
        {items.length === 0 && <p className="muted">No loot captured yet.</p>}
        {cursor && (
          <button className="ghost sm" onClick={() => void loadOlder()}>
            Load older
          </button>
        )}
        {error && <p className="error">{error}</p>}
      </div>
    </section>
  )
}

// One loot row with the artifact's comments folded behind a chevron: a
// working note on a captured file is process knowledge on that artifact.
function LootRow({
  engagementId,
  entry,
  onOpen,
}: {
  engagementId: string
  entry: LootEntry
  onOpen: () => void
}) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <tr>
        <td>
          <button
            className={`ghost sm row-expand${open ? ' open' : ''}`}
            title={open ? 'Hide comments' : 'Comments on this artifact'}
            onClick={() => setOpen((v) => !v)}
          >
            <Icon name={open ? 'chevronDown' : 'chevronRight'} />
          </button>{' '}
          {new Date(entry.storedAt).toLocaleString()}
        </td>
        <td>
          <span className="chip">{entry.kind}</span>
        </td>
        <td title={entry.contentType}>{entry.name}</td>
        <td title={entry.taskId ? `task ${entry.taskId}` : 'pre-foothold finding'}>
          {entry.verb ?? '—'}
          {entry.implantId ? ` (implant ${entry.implantId.slice(0, 8)})` : ''}
        </td>
        <td>{formatBytes(entry.size)}</td>
        <td>
          <button className="ghost sm" onClick={onOpen}>
            {entry.kind === 'screenshot' ? 'Open' : 'Download'}
          </button>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6}>
            <CommentsPanel
              engagementId={engagementId}
              subjectKind="artifact"
              subjectId={entry.artifactId}
            />
          </td>
        </tr>
      )}
    </>
  )
}
