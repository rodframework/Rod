import { useCallback, useEffect, useState } from 'react'
import {
  type HostEntry,
  type HostNote,
  type Topology,
  addHostNote,
  clearHostLabel,
  getTopology,
  listHostNotes,
  listHosts,
  setHostLabel,
} from '../api'
import { HelpHint } from '../components/HelpHint'

// The target picture (architecture.md Sec 11.2): what the engagement
// learned about the target, organized as a picture instead of
// transcripts -- the recon slot's read half (the workbench fills it).
// Two sections share one card: the host roster (the enrollment-hostname
// grouping with the crew's attributed labels and notes) and the
// topology graph (hosts, pivot links, and recon observations assembled
// at read time). Everything is a read of stores that already hold the
// data; the only writes are the label and note facts, which land in the
// audit trail like their implant-side twins. The loot and credential
// boards moved to the assets slot with the slots rework -- they are
// what the engagement holds, not what it learned about the target.

type Section = 'hosts' | 'topology'

export function TargetPictureView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [section, setSection] = useState<Section>('hosts')
  return (
    <section className="view">
      <h2>
        Target picture
        <HelpHint>
          What the engagement learned about the target: hosts grouped by the name they reported
          at enroll, and the network picture with its pivot links and recon observations.
          Labels and notes are attributed trail facts. The recon workbench fills the picture;
          the assets slot holds what the engagement gathered from it.
        </HelpHint>
      </h2>
      <div className="card">
        <div className="table-toolbar">
          {(['hosts', 'topology'] as const).map((s) => (
            <button
              key={s}
              className={section === s ? 'sm' : 'ghost sm'}
              onClick={() => setSection(s)}
            >
              {s === 'hosts' ? 'Hosts' : 'Topology'}
            </button>
          ))}
        </div>
        {section === 'hosts' && <HostsSection engagementId={engagementId} onlineTick={onlineTick} />}
        {section === 'topology' && <TopologySection engagementId={engagementId} onlineTick={onlineTick} />}
      </div>
    </section>
  )
}

// --- Hosts: the grouped picture, with labels and notes --------------------

function HostsSection({ engagementId, onlineTick }: { engagementId: string; onlineTick: number }) {
  const [hosts, setHosts] = useState<HostEntry[]>([])
  const [ungrouped, setUngrouped] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const body = await listHosts(engagementId)
      setHosts(body.hosts)
      setUngrouped(body.ungroupedImplantIds)
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }, [engagementId])

  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  return (
    <div>
      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>Fleet</th>
            <th>OS</th>
            <th>Account</th>
            <th>Labels</th>
            <th>Notes</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((host) => (
            <HostRow
              key={host.host}
              engagementId={engagementId}
              host={host}
              expanded={expanded === host.host}
              onToggle={() => setExpanded(expanded === host.host ? null : host.host)}
              onChanged={() => void refresh()}
            />
          ))}
        </tbody>
      </table>
      {ungrouped.length > 0 && (
        <p className="muted">
          {ungrouped.length} implant{ungrouped.length === 1 ? '' : 's'} reported no hostname and
          stands alone (see the fleet under Action).
        </p>
      )}
      {hosts.length === 0 && <p className="muted">No hosts in the picture yet.</p>}
      {error && <p className="error">{error}</p>}
    </div>
  )
}

function HostRow({
  engagementId,
  host,
  expanded,
  onToggle,
  onChanged,
}: {
  engagementId: string
  host: HostEntry
  expanded: boolean
  onToggle: () => void
  onChanged: () => void
}) {
  return (
    <>
      <tr>
        <td>
          <strong>{host.host}</strong>
        </td>
        <td>
          {host.onlineCount}/{host.implantIds.length} online
        </td>
        <td>
          {[host.os, host.arch].filter(Boolean).join(' ') || <span className="muted">—</span>}
        </td>
        <td>{host.username ?? <span className="muted">—</span>}</td>
        <td>
          {host.labels.length === 0 ? (
            <span className="muted">—</span>
          ) : (
            host.labels.map((label) => (
              <span key={label} className="chip" title="A marker the crew set; clearing it appends to the trail.">
                {label}
              </span>
            ))
          )}
        </td>
        <td>{host.noteCount > 0 ? host.noteCount : <span className="muted">—</span>}</td>
        <td>
          <button className="ghost sm" onClick={onToggle}>
            {expanded ? 'Hide' : 'Notes & labels'}
          </button>
        </td>
      </tr>
      {expanded && (
        <tr className="notes-row">
          <td colSpan={7}>
            <HostFacts engagementId={engagementId} host={host} onChanged={onChanged} />
          </td>
        </tr>
      )}
    </>
  )
}

function HostFacts({
  engagementId,
  host,
  onChanged,
}: {
  engagementId: string
  host: HostEntry
  onChanged: () => void
}) {
  const [notes, setNotes] = useState<HostNote[]>([])
  const [noteDraft, setNoteDraft] = useState('')
  const [labelDraft, setLabelDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    void (async () => {
      try {
        setNotes(await listHostNotes(engagementId, host.host))
      } catch (e) {
        setError(String(e))
      }
    })()
  }, [engagementId, host.host])

  const run = async (action: () => Promise<unknown>) => {
    if (busy) return
    setBusy(true)
    try {
      await action()
      setError(null)
      onChanged()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="notes-panel">
      <ul className="notes-list">
        {notes.length === 0 ? (
          <li className="muted">No notes on this host yet.</li>
        ) : (
          notes.map((n) => (
            <li key={n.noteId}>
              <span className="notes-meta">
                <code>{n.author.slice(0, 8)}</code> {new Date(n.at).toLocaleString()}
              </span>
              {n.text}
            </li>
          ))
        )}
      </ul>
      <form
        className="task-form"
        onSubmit={(e) => {
          e.preventDefault()
          const text = noteDraft.trim()
          if (!text) return
          void run(async () => {
            await addHostNote(engagementId, host.host, text)
            setNoteDraft('')
            setNotes(await listHostNotes(engagementId, host.host))
          })
        }}
      >
        <input
          className="wide"
          placeholder="what is this box?"
          value={noteDraft}
          onChange={(e) => setNoteDraft(e.target.value)}
        />
        <button className="sm" type="submit" disabled={busy || !noteDraft.trim()}>
          Add note
        </button>
      </form>
      <div className="label-chips">
        {host.labels.map((label) => (
          <span key={label} className="chip">
            {label}
            <button
              className="chip-x"
              title="Clear this label (an attributed trail fact)"
              onClick={() => void run(() => clearHostLabel(engagementId, host.host, label))}
            >
              ×
            </button>
          </span>
        ))}
        <form
          className="task-form"
          onSubmit={(e) => {
            e.preventDefault()
            const label = labelDraft.trim()
            if (!label) return
            void run(async () => {
              await setHostLabel(engagementId, host.host, label)
              setLabelDraft('')
            })
          }}
        >
          <input
            placeholder="label"
            value={labelDraft}
            onChange={(e) => setLabelDraft(e.target.value)}
          />
          <button className="sm" type="submit" disabled={busy || !labelDraft.trim()}>
            Label
          </button>
        </form>
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  )
}

// --- Topology: the assembled network picture --------------------------------

function TopologySection({ engagementId, onlineTick }: { engagementId: string; onlineTick: number }) {
  const [topology, setTopology] = useState<Topology | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    void (async () => {
      try {
        setTopology(await getTopology(engagementId))
        setError(null)
      } catch (e) {
        setError(String(e))
      }
    })()
  }, [engagementId, onlineTick])

  if (error) return <p className="error">{error}</p>
  if (!topology) return <p className="muted">Assembling the picture…</p>
  if (topology.hosts.length === 0) return <p className="muted">Nothing in the picture yet.</p>
  if (!topology.chainVerified) {
    return (
      <p className="error">
        The engagement's audit chain does not verify ({topology.chainBreak}); the picture refuses to
        render over a broken trail.
      </p>
    )
  }

  return <TopologyGraph topology={topology} />
}

// Layered layout: hosts with no incoming pivot edge sit at depth 0, each
// pivot target one layer deeper than its source. Fixed node metrics keep the
// SVG edges and the positioned boxes in agreement without measuring the DOM.
const NODE_W = 168
const NODE_H = 64
const LAYER_GAP = 110
const SLOT_GAP = 24

function TopologyGraph({ topology }: { topology: Topology }) {
  const depthByHost = new Map<string, number>()
  const byHost = new Map(topology.hosts.map((h) => [h.host, h]))
  const pivotTargets = new Set(topology.links.map((l) => l.toHost))

  // Deepest path from any pivot source, breadth-limited by host count (the
  // graph is a forest in practice; the cap keeps a malformed cycle finite).
  const maxDepth = topology.hosts.length
  const depthOf = (host: string, seen: Set<string>): number => {
    if (depthByHost.has(host)) return depthByHost.get(host)!
    if (seen.has(host) || seen.size > maxDepth) return 0
    seen.add(host)
    let depth = 0
    for (const link of topology.links) {
      if (link.toHost === host && byHost.has(link.fromHost)) {
        depth = Math.max(depth, depthOf(link.fromHost, seen) + 1)
      }
    }
    depthByHost.set(host, depth)
    return depth
  }
  for (const host of topology.hosts) depthOf(host.host, new Set())

  // Observed and noted hosts ride the base layer beside the entry beacons.
  for (const host of topology.hosts) {
    if (!pivotTargets.has(host.host) && !depthByHost.has(host.host)) {
      depthByHost.set(host.host, 0)
    }
  }

  const layers = new Map<number, string[]>()
  for (const host of topology.hosts) {
    const depth = Math.min(depthByHost.get(host.host) ?? 0, maxDepth)
    if (!layers.has(depth)) layers.set(depth, [])
    layers.get(depth)!.push(host.host)
  }
  const orderedLayers = [...layers.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([depth, hosts]) => [depth, hosts.sort()] as const)

  const slotsPerLayer = Math.max(...orderedLayers.map(([, hosts]) => hosts.length))
  const width = slotsPerLayer * (NODE_W + SLOT_GAP)
  const position = new Map<string, { x: number; y: number }>()
  for (const [depth, hosts] of orderedLayers) {
    hosts.forEach((host, index) => {
      position.set(host, {
        x: (width - hosts.length * (NODE_W + SLOT_GAP)) / 2 + index * (NODE_W + SLOT_GAP),
        y: depth * (NODE_H + LAYER_GAP),
      })
    })
  }
  const height = (orderedLayers.length - 1) * (NODE_H + LAYER_GAP) + NODE_H

  const center = (host: string) => {
    const p = position.get(host)!
    return { cx: p.x + NODE_W / 2, cy: p.y + NODE_H / 2 }
  }

  return (
    <div>
      <div className="topo-canvas" style={{ width, height: height + 8 }}>
        <svg width={width} height={height + 8}>
          {topology.links.map((link, index) => {
            if (!position.has(link.fromHost) || !position.has(link.toHost)) return null
            const from = center(link.fromHost)
            const to = center(link.toHost)
            return (
              <line
                key={index}
                x1={from.cx}
                y1={from.cy}
                x2={to.cx}
                y2={to.cy}
                className="topo-edge"
                markerEnd="url(#topo-arrow)"
              />
            )
          })}
          <defs>
            <marker id="topo-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L8,4 L0,8 z" />
            </marker>
          </defs>
        </svg>
        {topology.hosts.map((host) => {
          const p = position.get(host.host)!
          return (
            <div
              key={host.host}
              className={`topo-node topo-${host.kind}`}
              style={{ left: p.x, top: p.y, width: NODE_W }}
              title={`${host.kind} host${host.os ? ` · ${host.os}` : ''}${
                host.implantIds.length > 0
                  ? ` · ${host.online}/${host.implantIds.length} online`
                  : ''
              }`}
            >
              <strong>{host.host}</strong>
              <span className="muted">
                {host.kind === 'enrolled'
                  ? `${host.online}/${host.implantIds.length} online`
                  : host.kind === 'observed'
                    ? host.os ?? 'recon-seen'
                    : 'noted'}
              </span>
              {host.labels.length > 0 && (
                <span className="topo-labels">{host.labels.join(' · ')}</span>
              )}
            </div>
          )
        })}
      </div>
      {topology.observations.length > 0 && (
        <details className="topo-observations">
          <summary>Recon observations ({topology.observations.length})</summary>
          <ul className="notes-list">
            {topology.observations.map((o, index) => (
              <li key={index}>
                <span className="notes-meta">
                  <code>{o.verb}</code> {new Date(o.at).toLocaleString()}
                </span>
                <strong>{o.host}</strong>
                {o.port !== null && ` :${o.port}${o.state ? `/${o.state}` : ''}${o.service ? ` (${o.service})` : ''}`}
                {o.address && ` — ${o.address}`}
                {o.os && ` · ${o.os}`}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}
