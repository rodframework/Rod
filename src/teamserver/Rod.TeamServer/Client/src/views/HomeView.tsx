import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  type Engagement,
  type EngagementTask,
  type Implant,
  type LootEntry,
  listEngagements,
  listEngagementTasks,
  listImplants,
  listLoot,
} from '../api'
import { HelpHint } from '../components/HelpHint'
import { type IconName, Icon } from '../components/Icons'
import { StatusBadge } from '../components/StatusBadge'
import { fmtBytes } from '../format'
import { osFamilyOf, type OsFamily } from '../osKind'
import { ago, useNow } from '../when'

// The home dashboard (`#/`; the bare hash and the brand mark both land here):
// one orienting page over every engagement the operator can reach, composed
// client-side from the roster plus the same per-engagement reads the
// engagement views make (implants, tasks, loot). No dedicated
// cross-engagement aggregate endpoint exists -- and the composition keeps the
// dashboard inside the engagement-scoped surface the server already enforces.
// Retired records are sealed: they count toward the roster card only, and
// their per-engagement reads are skipped.

// The activity window the charts and cards answer over. Every paged read
// takes the newest page (200 is the listing's hard page cap), so an
// engagement with more history than the cap undercounts its oldest days --
// the dashboard is an operating overview, not a ledger.
const TASK_WINDOW_DAYS = 14
const PAGE_LIMIT = 200

// When the dashboard should start shouting about an implant's time fuse: a
// kill date inside the horizon is a foothold about to vanish on its own.
const KILL_DATE_HORIZON_DAYS = 7
// An open engagement with no tasking this long is either forgotten or stuck;
// either way it belongs on the attention strip, not in the noise floor.
const STALE_ENGAGEMENT_DAYS = 7

// Task statuses collapse into the classes the activity chart stacks. The
// in-flight pair (queued, dispatched) reads as one "open" series; anything
// unrecognized joins it rather than inventing a legend entry.
type TaskClass = 'completed' | 'open' | 'cancelled' | 'failed'

function taskClass(status: string): TaskClass {
  switch (status.toLowerCase()) {
    case 'completed':
      return 'completed'
    case 'failed':
      return 'failed'
    case 'cancelled':
    case 'canceled':
      return 'cancelled'
    default:
      return 'open'
  }
}

const TASK_CLASSES: readonly TaskClass[] = ['completed', 'open', 'cancelled', 'failed']
const TASK_CLASS_LABEL: Record<TaskClass, string> = {
  completed: 'completed',
  open: 'open (queued or dispatched)',
  cancelled: 'cancelled',
  failed: 'failed',
}

function engagementStatus(e: Engagement): { label: string; tone: string } {
  if (e.retiredAt) return { label: 'retired', tone: 'status retired' }
  if (e.frozenAt) return { label: 'frozen', tone: 'status' }
  return { label: 'open', tone: 'status completed' }
}

// Local-day key: the operator reads the chart in their own timezone. Keys are
// only compared for equality (bucket lookup), never ordering.
function dayKey(date: Date): string {
  return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`
}

interface DayBucket {
  key: string
  label: string
  counts: Record<TaskClass, number>
  total: number
}

// One engagements-list row's posture, precomputed so the render stays a map.
interface FleetRow {
  engagement: Engagement
  status: { label: string; tone: string }
  active: number
  online: number
  tasksInWindow: number
  lastTaskAt: string | null
  lootCount: number
  lootBytes: number
}

// A condition worth drawing the eye before the numbers do: each links to the
// surface that acts on it.
interface Alert {
  key: string
  tone: 'danger' | 'warn' | 'info'
  text: string
  href: string
  title: string
}

interface HomeData {
  engagements: Engagement[]
  // Per-engagement reads for non-retired engagements only; an entry is absent
  // when that read failed, so the row falls back to the roster's summary.
  implants: Partial<Record<string, Implant[]>>
  tasks: Partial<Record<string, EngagementTask[]>>
  loot: Partial<Record<string, LootEntry[]>>
}

function StatCard({
  icon,
  label,
  value,
  sub,
  title,
  spark,
}: {
  icon: IconName
  label: string
  value: string
  sub?: string
  title?: string
  spark?: number[]
}) {
  const sparkMax = spark ? Math.max(1, ...spark) : 1
  return (
    <div className="stat-card" title={title}>
      <div className="stat-head">
        <Icon name={icon} />
        <span className="stat-label">{label}</span>
      </div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
      {spark && spark.length > 0 && (
        <div className="sparkline" aria-hidden="true">
          {spark.map((v, i) => (
            <div
              key={i}
              className={`spark-bar${i === spark.length - 1 ? ' last' : v > 0 ? '' : ' flat'}`}
              style={{ height: `${Math.max(6, (v / sparkMax) * 100)}%` }}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// Stacked daily bars over the task window, in pure CSS: one flex column per
// local day, segments proportioned against the busiest day. The native title
// on each column carries the exact breakdown.
function ActivityChart({ buckets }: { buckets: DayBucket[] }) {
  const max = Math.max(1, ...buckets.map((b) => b.total))
  return (
    <div className="activity-chart" role="img" aria-label="Tasks per day over the window">
      {buckets.map((bucket, i) => (
        <div
          key={bucket.key}
          className="activity-col"
          title={`${bucket.label} -- ${bucket.total} task${bucket.total === 1 ? '' : 's'}${TASK_CLASSES.filter(
            (cls) => bucket.counts[cls] > 0,
          )
            .map((cls) => `, ${bucket.counts[cls]} ${TASK_CLASS_LABEL[cls]}`)
            .join('')}`}
        >
          <div className="activity-stack">
            {TASK_CLASSES.map((cls) =>
              bucket.counts[cls] > 0 ? (
                <div
                  key={cls}
                  className={`activity-seg ${cls}`}
                  style={{ height: `${(bucket.counts[cls] / max) * 100}%` }}
                />
              ) : null,
            )}
          </div>
          {(i % 2 === 0 || i === buckets.length - 1) && (
            <span className="activity-label">{bucket.label}</span>
          )}
        </div>
      ))}
    </div>
  )
}

// Cumulative enrolled implants over the window as a line with a soft area,
// with the per-day enrollment count as faint bars underneath -- growth and
// its daily contribution in one read. Fixed-viewBox SVG like the donut.
function GrowthChart({ cumulative, daily, labels }: { cumulative: number[]; daily: number[]; labels: string[] }) {
  const W = 560
  const H = 190
  const PAD_L = 36
  const PAD_R = 16
  const PAD_T = 14
  const PAD_B = 26
  const plotW = W - PAD_L - PAD_R
  const plotH = H - PAD_T - PAD_B
  const n = cumulative.length
  const maxCum = cumulative[n - 1] ?? 0
  const maxDaily = Math.max(1, ...daily)
  // A 1/2/5 ceiling keeps the top gridline a number worth reading.
  const niceCeil = (v: number): number => {
    const exp = Math.max(0, Math.floor(Math.log10(Math.max(1, v))))
    const base = 10 ** exp
    for (const m of [1, 2, 5, 10]) if (m * base >= v) return m * base
    return 10 * base
  }
  const yMax = niceCeil(Math.max(1, maxCum))
  const x = (i: number) => PAD_L + (n <= 1 ? plotW / 2 : (i / (n - 1)) * plotW)
  const y = (v: number) => PAD_T + (1 - v / yMax) * plotH
  const line = cumulative.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ')
  const area = `${PAD_L},${(PAD_T + plotH).toFixed(1)} ${line} ${(PAD_L + plotW).toFixed(1)},${(PAD_T + plotH).toFixed(1)}`
  const barW = Math.min(10, (plotW / Math.max(1, n)) * 0.34)
  const gridValues = [0, yMax / 2, yMax]
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="growth-chart"
      role="img"
      aria-label="Cumulative enrolled implants over the window"
    >
      {gridValues.map((v) => (
        <g key={v}>
          <line className="chart-grid" x1={PAD_L} x2={W - PAD_R} y1={y(v)} y2={y(v)} />
          <text className="chart-axis-text" x={PAD_L - 6} y={y(v)} dominantBaseline="central" textAnchor="end">
            {v}
          </text>
        </g>
      ))}
      {daily.map((v, i) =>
        v > 0 ? (
          <rect
            key={i}
            className="growth-bar"
            x={x(i) - barW / 2}
            y={PAD_T + plotH - (v / maxDaily) * plotH * 0.55}
            width={barW}
            height={(v / maxDaily) * plotH * 0.55}
            rx={1.5}
          />
        ) : null,
      )}
      <polygon className="growth-area" points={area} />
      <polyline className="growth-line" points={line} />
      {labels.map((label, i) =>
        label ? (
          <text
            key={i}
            className="chart-axis-text"
            x={x(i)}
            y={H - 8}
            textAnchor={i === 0 ? 'start' : i === labels.length - 1 ? 'end' : 'middle'}
          >
            {label}
          </text>
        ) : null,
      )}
      <text className="chart-last-value" x={x(n - 1)} y={Math.max(12, y(maxCum) - 8)} textAnchor="end">
        {maxCum}
      </text>
    </svg>
  )
}

// Weekday x hour task density: when the work actually happens. Monday-first,
// the operator's local timezone, intensity on the accent.
const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

// A donut on 42x42 viewBox geometry where the track circle's circumference is
// ~100, so segment lengths are percentages directly.
function Donut({
  segments,
  center,
}: {
  segments: { label: string; value: number; color: string }[]
  center: string
}) {
  const total = segments.reduce((n, s) => n + s.value, 0)
  let cumulative = 0
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 42 42" className="donut" role="img" aria-label="Implants by OS family">
        <circle className="donut-track" cx="21" cy="21" r="15.9155" />
        {total > 0 &&
          segments
            .filter((s) => s.value > 0)
            .map((s) => {
              const pct = (s.value / total) * 100
              const offset = 25 - cumulative
              cumulative += pct
              return (
                <circle
                  key={s.label}
                  className="donut-seg"
                  cx="21"
                  cy="21"
                  r="15.9155"
                  style={{ stroke: s.color }}
                  strokeDasharray={`${pct} ${100 - pct}`}
                  strokeDashoffset={offset}
                />
              )
            })}
        <text className="donut-center" x="21" y="21" dominantBaseline="central" textAnchor="middle">
          {center}
        </text>
      </svg>
      <div className="donut-legend">
        {segments.map((s) => (
          <div key={s.label} className="donut-legend-row">
            <span className="donut-swatch" style={{ background: s.color }} />
            <span className="donut-legend-label">{s.label}</span>
            <span className="donut-legend-value">{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// A labeled share bar (the fleet and verb cards): a track plus filled
// segments, widths in percent of the row's own scale.
function ShareBar({ parts, scale }: { parts: { value: number; className: string }[]; scale: number }) {
  const total = parts.reduce((n, p) => n + p.value, 0)
  if (total === 0) return <div className="share-bar empty" title="No active implants" />
  return (
    <div className="share-bar">
      {parts.map((part, i) =>
        part.value > 0 ? (
          <div
            key={i}
            className={`share-fill ${part.className}`}
            style={{ width: `${(part.value / Math.max(scale, 1)) * 100}%` }}
          />
        ) : null,
      )}
    </div>
  )
}

// The weekday x hour density grid: 7 rows of 24 cells, tinted by the cell's
// share of the busiest cell, each carrying its count on the native title.
function RhythmChart({ cells }: { cells: number[][] }) {
  const max = Math.max(1, ...cells.flat())
  return (
    <div className="rhythm-chart" role="img" aria-label="Task density by weekday and hour">
      {cells.map((row, weekday) => (
        <div key={weekday} className="rhythm-row">
          <span className="rhythm-row-label">{WEEKDAYS[weekday]}</span>
          {row.map((count, hour) => (
            <span
              key={hour}
              className={`rhythm-cell${count === 0 ? ' empty' : ''}`}
              style={count > 0 ? { opacity: 0.15 + (0.85 * count) / max } : undefined}
              title={`${WEEKDAYS[weekday]} ${String(hour).padStart(2, '0')}:00 -- ${count} task${count === 1 ? '' : 's'}`}
            />
          ))}
        </div>
      ))}
      <div className="rhythm-axis">
        <span className="rhythm-row-label" />
        {[0, 3, 6, 9, 12, 15, 18, 21].map((hour) => (
          <span key={hour} className="rhythm-hour-label">
            {hour}
          </span>
        ))}
      </div>
    </div>
  )
}

export function HomeView() {
  const [data, setData] = useState<HomeData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const now = useNow(30_000)

  const load = useCallback(async () => {
    setBusy(true)
    try {
      const engagements = await listEngagements()
      const live = engagements.filter((e) => !e.retiredAt)
      // A failed per-engagement read leaves that engagement's entry absent,
      // so its panels degrade to the roster's own summary counts rather than
      // failing the page (or reading as an empty fleet).
      const [implantLists, taskLists, lootLists] = await Promise.all([
        Promise.all(live.map((e) => listImplants(e.engagementId).then((v) => v, () => null))),
        Promise.all(
          live.map((e) =>
            listEngagementTasks(e.engagementId, undefined, PAGE_LIMIT)
              .then((page) => page.items)
              .catch(() => null),
          ),
        ),
        Promise.all(
          live.map((e) => listLoot(e.engagementId, undefined, undefined, PAGE_LIMIT).then((p) => p.items).catch(() => null)),
        ),
      ])
      const implants: HomeData['implants'] = {}
      const tasks: HomeData['tasks'] = {}
      const loot: HomeData['loot'] = {}
      live.forEach((e, i) => {
        if (implantLists[i]) implants[e.engagementId] = implantLists[i]
        if (taskLists[i]) tasks[e.engagementId] = taskLists[i]
        if (lootLists[i]) loot[e.engagementId] = lootLists[i]
      })
      setData({ engagements, implants, tasks, loot })
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
    // Roster changes (create, close-out, membership) re-shape the dashboard's
    // whole basis, so they re-read it on the spot.
    window.addEventListener('rod-engagements-changed', load)
    return () => window.removeEventListener('rod-engagements-changed', load)
  }, [load])

  const derived = useMemo(() => {
    if (!data) return null
    const { engagements, implants, tasks, loot } = data
    const live = engagements.filter((e) => !e.retiredAt)

    // ---- Fleet posture, kill dates, loot ---------------------------------
    let fleetActive = 0
    let fleetOnline = 0
    let lastSeen: string | null = null
    const hosts = new Set<string>()
    const osCounts = new Map<OsFamily, number>([
      ['windows', 0],
      ['linux', 0],
      ['apple', 0],
      ['other', 0],
    ])
    let lootCount = 0
    let lootBytes = 0
    let lootCapped = false
    // Kill-date posture over active implants: the soonest future date drives
    // the alert (and its link); an already-passed date on an active row is a
    // beacon the fleet should have heard from and hasn't.
    let killSoonest: { at: string; engagementId: string } | null = null
    let killSoonCount = 0
    let killExpiredCount = 0
    const killHorizonMs = KILL_DATE_HORIZON_DAYS * 86_400_000

    // The aggregations run in flat loops (not per-row closures) so the
    // accumulators' control flow stays visible where they are read.
    for (const e of live) {
      const rows = implants[e.engagementId]
      const lootRows = loot[e.engagementId] ?? []
      lootCount += lootRows.length
      lootBytes += lootRows.reduce((n, l) => n + l.size, 0)
      if (lootRows.length >= PAGE_LIMIT) lootCapped = true
      if (rows) {
        fleetActive += rows.filter((i) => !i.retiredAt).length
        fleetOnline += rows.filter((i) => i.isOnline && !i.retiredAt).length
      } else {
        // A failed implant read degrades the totals to the roster's own
        // summary counts, same as the per-engagement row.
        fleetActive += e.summary?.implantCount ?? 0
        fleetOnline += e.summary?.onlineCount ?? 0
        continue
      }
      for (const i of rows) {
        if (i.retiredAt) continue
        hosts.add(i.hostname ?? '')
        osCounts.set(osFamilyOf(i.os), (osCounts.get(osFamilyOf(i.os)) ?? 0) + 1)
        if (i.lastSeenAt && (!lastSeen || i.lastSeenAt > lastSeen)) lastSeen = i.lastSeenAt
        if (i.killDate) {
          const remaining = new Date(i.killDate).getTime() - Date.now()
          if (remaining <= 0) {
            killExpiredCount++
          } else if (remaining <= killHorizonMs) {
            killSoonCount++
            if (!killSoonest || i.killDate < killSoonest.at) {
              killSoonest = { at: i.killDate, engagementId: e.engagementId }
            }
          }
        }
      }
    }

    const fleetRows: FleetRow[] = engagements.map((e) => {
      const rows = implants[e.engagementId]
      const active = rows
        ? rows.filter((i) => !i.retiredAt).length
        : (e.summary?.implantCount ?? 0)
      const online = rows
        ? rows.filter((i) => i.isOnline && !i.retiredAt).length
        : (e.summary?.onlineCount ?? 0)
      const lootRows = loot[e.engagementId] ?? []
      return {
        engagement: e,
        status: engagementStatus(e),
        active,
        online,
        tasksInWindow: 0,
        lastTaskAt: null,
        lootCount: lootRows.length,
        lootBytes: lootRows.reduce((n, l) => n + l.size, 0),
      }
    })
    const fleetScale = Math.max(1, ...fleetRows.map((r) => r.active))
    const totalEnrolled = live.reduce(
      (n, e) => n + (implants[e.engagementId]?.length ?? 0),
      0,
    )

    // ---- Windowed tasking -------------------------------------------------
    const buckets: DayBucket[] = []
    const bucketByKey = new Map<string, DayBucket>()
    const today = new Date()
    for (let back = TASK_WINDOW_DAYS - 1; back >= 0; back--) {
      const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - back)
      const bucket: DayBucket = {
        key: dayKey(d),
        label: d.toLocaleDateString(undefined, { month: 'numeric', day: 'numeric' }),
        counts: { completed: 0, open: 0, cancelled: 0, failed: 0 },
        total: 0,
      }
      buckets.push(bucket)
      bucketByKey.set(bucket.key, bucket)
    }
    const windowStart = new Date(
      today.getFullYear(),
      today.getMonth(),
      today.getDate() - (TASK_WINDOW_DAYS - 1),
    ).getTime()

    const rhythm = Array.from({ length: 7 }, () => Array.from({ length: 24 }, () => 0))
    const verbCounts = new Map<string, number>()
    const recent: { task: EngagementTask; engagement: Engagement }[] = []
    let windowTotal = 0
    let windowFailed = 0
    // Enrollments per day (every row the listing holds, retired included --
    // growth counts what arrived, not what survived) over the window, plus
    // the baseline of older rows the cumulative line starts from.
    const enrolledPerDay = new Array<number>(TASK_WINDOW_DAYS).fill(0)
    let enrolledBeforeWindow = 0
    for (const e of live) {
      const rows = implants[e.engagementId] ?? []
      for (const i of rows) {
        const created = new Date(i.createdAt).getTime()
        if (created < windowStart) {
          enrolledBeforeWindow++
        } else {
          const bucket = bucketByKey.get(dayKey(new Date(i.createdAt)))
          if (bucket) enrolledPerDay[buckets.indexOf(bucket)]++
        }
      }
      let lastTaskAt: string | null = null
      let tasksInWindow = 0
      for (const t of tasks[e.engagementId] ?? []) {
        recent.push({ task: t, engagement: e })
        if (!lastTaskAt || t.createdAt > lastTaskAt) lastTaskAt = t.createdAt
        const created = new Date(t.createdAt)
        if (created.getTime() >= windowStart) {
          tasksInWindow++
          windowTotal++
          const cls = taskClass(t.status)
          if (cls === 'failed') windowFailed++
          const bucket = bucketByKey.get(dayKey(created))
          if (bucket) {
            bucket.counts[cls]++
            bucket.total++
          }
          rhythm[(created.getDay() + 6) % 7][created.getHours()]++
          verbCounts.set(t.verb, (verbCounts.get(t.verb) ?? 0) + 1)
        }
      }
      const row = fleetRows.find((r) => r.engagement.engagementId === e.engagementId)
      if (row) {
        row.tasksInWindow = tasksInWindow
        row.lastTaskAt = lastTaskAt
      }
    }
    recent.sort((a, b) => b.task.createdAt.localeCompare(a.task.createdAt))
    const verbs = [...verbCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)
    const cumulative: number[] = []
    let running = enrolledBeforeWindow
    for (const n of enrolledPerDay) {
      running += n
      cumulative.push(running)
    }
    const enrolledInWindow = enrolledPerDay.reduce((n, v) => n + v, 0)

    // ---- Attention strip --------------------------------------------------
    const alerts: Alert[] = []
    if (killExpiredCount > 0) {
      alerts.push({
        key: 'kill-expired',
        tone: 'danger',
        text: `${killExpiredCount} active implant${killExpiredCount === 1 ? '' : 's'} past kill date`,
        href: killSoonest ? `#/engagements/${killSoonest.engagementId}/action/implants` : '#/engagements',
        title: 'Active (non-retired) rows whose baked kill date has passed -- the artifact refuses to run past it',
      })
    }
    if (killSoonCount > 0 && killSoonest) {
      const inDays = Math.max(1, Math.ceil((new Date(killSoonest.at).getTime() - Date.now()) / 86_400_000))
      alerts.push({
        key: 'kill-soon',
        tone: 'warn',
        text: `${killSoonCount} implant${killSoonCount === 1 ? '' : 's'} hit kill date within ${KILL_DATE_HORIZON_DAYS}d -- next in ${inDays}d`,
        href: `#/engagements/${killSoonest.engagementId}/action/implants`,
        title: `Soonest kill date: ${new Date(killSoonest.at).toLocaleString()}`,
      })
    }
    const openNoFoothold = live.filter((e) => {
      if (e.frozenAt) return false
      const row = fleetRows.find((r) => r.engagement.engagementId === e.engagementId)
      return (row?.active ?? 0) === 0
    })
    if (openNoFoothold.length > 0) {
      alerts.push({
        key: 'no-foothold',
        tone: 'info',
        text: `${openNoFoothold.length} open engagement${openNoFoothold.length === 1 ? '' : 's'} without implants`,
        href: '#/engagements',
        title: openNoFoothold.map((e) => e.name).join(', '),
      })
    }
    const staleMs = STALE_ENGAGEMENT_DAYS * 86_400_000
    const openStale = live.filter((e) => {
      if (e.frozenAt) return false
      const row = fleetRows.find((r) => r.engagement.engagementId === e.engagementId)
      const lastMotion = row?.lastTaskAt ?? e.createdAt
      return Date.now() - new Date(lastMotion).getTime() > staleMs
    })
    if (openStale.length > 0) {
      alerts.push({
        key: 'stale',
        tone: 'warn',
        text: `${openStale.length} open engagement${openStale.length === 1 ? '' : 's'} idle ${STALE_ENGAGEMENT_DAYS}d+`,
        href: '#/engagements',
        title: openStale.map((e) => e.name).join(', '),
      })
    }

    return {
      open: live.filter((e) => !e.frozenAt).length,
      frozen: live.filter((e) => e.frozenAt).length,
      retired: engagements.length - live.length,
      fleetActive,
      fleetOnline,
      fleetScale,
      hostCount: hosts.size,
      lastSeen,
      osCounts,
      fleetRows,
      buckets,
      rhythm,
      windowTotal,
      windowFailed,
      verbs,
      recent: recent.slice(0, 12),
      lootCount,
      lootBytes,
      lootCapped,
      cumulative,
      enrolledPerDay,
      enrolledInWindow,
      totalEnrolled,
      alerts,
    }
  }, [data])

  if (loading) {
    return (
      <section className="view">
        <h2>Home</h2>
        <div className="empty">
          <span className="spinner" />
          Loading the dashboard…
        </div>
      </section>
    )
  }

  const engagements = data?.engagements ?? []

  return (
    <section className="view">
      <h2>
        Home
        <HelpHint>
          Posture and activity across every engagement you can reach -- attention items first, then
          fleet health, tasking volume, loot, and the newest operator work, over open and frozen
          engagements. Retired records count toward the roster card only; the engagements list stays
          the full account.
        </HelpHint>
        <button className="sm ghost" onClick={() => void load()} disabled={busy} title="Re-read the dashboard">
          <Icon name="refresh" />
        </button>
      </h2>
      {error && <p className="error">{error}</p>}

      {engagements.length === 0 ? (
        <div className="card empty">
          <Icon name="globe" />
          No engagements yet -- the dashboard lights up once you create one.
          <a href="#/engagements">Open the engagements list</a>
        </div>
      ) : (
        derived && (
          <>
            {derived.alerts.length > 0 && (
              <div className="alert-strip">
                {derived.alerts.map((a) => (
                  <a key={a.key} className={`alert-chip ${a.tone}`} href={a.href} title={a.title}>
                    <span className="alert-dot" />
                    {a.text}
                  </a>
                ))}
              </div>
            )}

            <div className="stat-grid">
              <StatCard
                icon="globe"
                label="Engagements"
                value={String(derived.open + derived.frozen)}
                sub={`${derived.open} open · ${derived.frozen} frozen · ${derived.retired} retired`}
                title="Non-retired engagements you can reach, split by close-out state"
              />
              <StatCard
                icon="cpu"
                label="Fleet"
                value={`${derived.fleetOnline} / ${derived.fleetActive}`}
                sub={`implants online${derived.hostCount > 0 ? ` · ${derived.hostCount} host${derived.hostCount === 1 ? '' : 's'}` : ''}`}
                title="Live sessions over active (non-retired) implants across non-retired engagements"
              />
              <StatCard
                icon="inbox"
                label={`Tasking (${TASK_WINDOW_DAYS}d)`}
                value={String(derived.windowTotal)}
                sub={
                  derived.windowFailed > 0
                    ? `${derived.windowFailed} failed`
                    : 'no failures in the window'
                }
                title="Tasks issued inside the window, read from each engagement's newest 200"
                spark={derived.buckets.map((b) => b.total)}
              />
              <StatCard
                icon="archive"
                label="Loot"
                value={`${derived.lootCapped ? '~' : ''}${derived.lootCount}`}
                sub={derived.lootCount > 0 ? `${fmtBytes(derived.lootBytes)} captured` : 'nothing captured yet'}
                title="Artifacts across non-retired engagements (newest 200 each)"
              />
              <StatCard
                icon="clock"
                label="Last heard"
                value={derived.lastSeen ? ago(derived.lastSeen, now) : '--'}
                sub="newest implant check-in"
                title={derived.lastSeen ? new Date(derived.lastSeen).toLocaleString() : undefined}
              />
            </div>

            <div className="dash-grid">
              <div className="card dash-wide">
                <h3>Task activity -- last {TASK_WINDOW_DAYS} days</h3>
                {derived.windowTotal > 0 ? (
                  <ActivityChart buckets={derived.buckets} />
                ) : (
                  <p className="muted">No tasking inside the window.</p>
                )}
                <div className="legend-row">
                  {TASK_CLASSES.map((cls) => (
                    <span key={cls} className="legend-item">
                      <span className={`swatch ${cls}`} />
                      {cls === 'open' ? 'open (queued/dispatched)' : cls}
                    </span>
                  ))}
                </div>
              </div>

              <div className="card">
                <h3>
                  Fleet growth
                  <span className="muted card-sub">
                    {derived.enrolledInWindow > 0
                      ? `+${derived.enrolledInWindow} enrolled in ${TASK_WINDOW_DAYS}d`
                      : 'no new enrollments in the window'}
                  </span>
                </h3>
                {derived.totalEnrolled > 0 ? (
                  <GrowthChart
                    cumulative={derived.cumulative}
                    daily={derived.enrolledPerDay}
                    labels={derived.buckets.map((b, i) =>
                      i === 0 || i === derived.buckets.length - 1 ? b.label : '',
                    )}
                  />
                ) : (
                  <p className="muted">No implants enrolled yet.</p>
                )}
                <div className="legend-row">
                  <span className="legend-item"><span className="swatch line" />cumulative enrolled</span>
                  <span className="legend-item"><span className="swatch bar-soft" />new per day</span>
                </div>
              </div>

              <div className="card">
                <h3>Operating rhythm</h3>
                {derived.windowTotal > 0 ? (
                  <RhythmChart cells={derived.rhythm} />
                ) : (
                  <p className="muted">No tasking inside the window.</p>
                )}
                <p className="muted rhythm-note">
                  Task density by weekday and hour, this machine's timezone, last {TASK_WINDOW_DAYS} days.
                </p>
              </div>

              <div className="card">
                <h3>Fleet by OS</h3>
                {derived.fleetActive > 0 ? (
                  <Donut
                    center={String(derived.fleetActive)}
                    segments={[
                      { label: 'Windows', value: derived.osCounts.get('windows') ?? 0, color: 'var(--info)' },
                      { label: 'Linux', value: derived.osCounts.get('linux') ?? 0, color: 'var(--success)' },
                      { label: 'macOS', value: derived.osCounts.get('apple') ?? 0, color: 'var(--warn)' },
                      { label: 'Other', value: derived.osCounts.get('other') ?? 0, color: 'var(--muted)' },
                    ]}
                  />
                ) : (
                  <p className="muted">No active implants.</p>
                )}
              </div>

              <div className="card">
                <h3>Top task verbs</h3>
                {derived.verbs.length > 0 ? (
                  <div className="verb-list">
                    {derived.verbs.map(([verb, count]) => (
                      <div key={verb} className="verb-row">
                        <code>{verb}</code>
                        <ShareBar scale={derived.verbs[0][1]} parts={[{ value: count, className: 'verb' }]} />
                        <span className="muted">{count}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="muted">No tasking inside the window.</p>
                )}
              </div>

              <div className="card dash-wide">
                <h3>Engagements</h3>
                <div className="fleet-list">
                  {derived.fleetRows.map((row) => (
                    <a
                      key={row.engagement.engagementId}
                      className="fleet-row"
                      href={`#/engagements/${row.engagement.engagementId}`}
                      title={`${row.engagement.name} (${row.engagement.engagementId}) -- created ${new Date(row.engagement.createdAt).toLocaleDateString()}${row.lootCount > 0 ? `; ${row.lootCount} loot (${fmtBytes(row.lootBytes)})` : ''}`}
                    >
                      <span className="fleet-name" title={`${row.engagement.name} (${row.engagement.engagementId})`}>
                        {row.engagement.name}
                      </span>
                      <span className={row.status.tone}>{row.status.label}</span>
                      <ShareBar
                        scale={derived.fleetScale}
                        parts={
                          row.engagement.retiredAt
                            ? [{ value: row.active, className: 'retired' }]
                            : [
                                { value: row.online, className: 'online' },
                                { value: row.active - row.online, className: 'offline' },
                              ]
                        }
                      />
                      <code className="fleet-counts">
                        {row.online}/{row.active}
                      </code>
                      <span className="fleet-tasks" title={`Tasks in the last ${TASK_WINDOW_DAYS} days`}>
                        {row.tasksInWindow} tasks
                      </span>
                      <span
                        className="fleet-last muted"
                        title={row.lastTaskAt ? new Date(row.lastTaskAt).toLocaleString() : 'No tasking recorded'}
                      >
                        {row.lastTaskAt ? ago(row.lastTaskAt, now) : 'never'}
                      </span>
                    </a>
                  ))}
                </div>
              </div>
            </div>

            <div className="card">
              <h3>Recent tasking</h3>
              {derived.recent.length > 0 ? (
                <div className="recent-list">
                  {derived.recent.map(({ task, engagement }) => (
                    <a
                      key={task.taskId}
                      className="recent-row"
                      href={`#/engagements/${engagement.engagementId}/action/tasking`}
                      title={`${engagement.name} -- ${task.verb} ${task.arguments}`}
                    >
                      <span className="recent-time" title={new Date(task.createdAt).toLocaleString()}>
                        {ago(task.createdAt, now)}
                      </span>
                      <StatusBadge status={task.status} />
                      <code>{task.verb}</code>
                      <span className="recent-args">{task.arguments || '\u00a0'}</span>
                      <span className="recent-engagement" title={engagement.engagementId}>
                        {engagement.name}
                      </span>
                      <span className="muted" title={task.issuedBy}>
                        {task.issuedByHandle}
                      </span>
                    </a>
                  ))}
                </div>
              ) : (
                <p className="muted">Nothing issued yet.</p>
              )}
            </div>
          </>
        )
      )}
    </section>
  )
}
