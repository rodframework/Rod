import { useCallback, useEffect, useRef, useState } from 'react'
import { type DiagnosticsReport, getDiagnostics } from '../api'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'

// The diagnostics page (architecture.md Sec 15.3, ADR-008): the deployment's
// own health at a glance -- beacon turnaround, queue depth, connected
// operator streams, build durations, and the loaded module set. Everything
// is a deployment-wide aggregate; nothing here names an engagement, an
// implant, or an operator. The page polls while it is open (the numbers are
// live counters, not stored facts) and stops polling the moment it unmounts.

// Refresh cadence: often enough that the numbers read live, rarely enough
// that an open tab costs the server nothing.
const REFRESH_MS = 10_000

function ms(value: number | null): string {
  if (value === null) return '—'
  if (value >= 60_000) return `${(value / 60_000).toFixed(1)}m`
  if (value >= 1000) return `${(value / 1000).toFixed(1)}s`
  return `${Math.round(value)}ms`
}

export function DiagnosticsView() {
  const [report, setReport] = useState<DiagnosticsReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const alive = useRef(true)

  const refresh = useCallback(async () => {
    setBusy(true)
    try {
      const next = await getDiagnostics()
      if (alive.current) {
        setReport(next)
        setError(null)
      }
    } catch (e) {
      if (alive.current) setError(String(e))
    } finally {
      if (alive.current) setBusy(false)
    }
  }, [])

  useEffect(() => {
    alive.current = true
    void refresh()
    const timer = window.setInterval(() => void refresh(), REFRESH_MS)
    return () => {
      alive.current = false
      window.clearInterval(timer)
    }
  }, [refresh])

  return (
    <section className="view">
      <h2>
        Diagnostics
        <HelpHint>
          The deployment's own health: beacon turnaround, task queue depth, connected operator
          streams, recent build durations, and the loaded module set -- in-process counters and
          aggregate reads, nothing standing beside the teamserver. Every number spans the whole
          deployment; nothing names an engagement.
        </HelpHint>
      </h2>
      {error && <p className="error">{error}</p>}

      {!report && !error && (
        <div className="empty">
          <span className="spinner" /> Reading the counters…
        </div>
      )}

      {report && (
        <>
          <div className="card">
            <div className="card-head">
              <h3>Beacon turnaround</h3>
              <button className="ghost" onClick={() => void refresh()} disabled={busy}>
                <Icon name="refresh" />
                Refresh
              </button>
            </div>
            <p className="muted">
              How long the server takes to turn one upstream beacon frame around, cumulative since
              process start across every carriage.
            </p>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Latency</th>
                    <th>Frames</th>
                  </tr>
                </thead>
                <tbody>
                  {report.beacons.latencyBuckets.map((bucket) => {
                    const max = Math.max(
                      1,
                      ...report.beacons.latencyBuckets.map((b) => b.count),
                    )
                    return (
                      <tr key={bucket.label}>
                        <td>
                          <code>{bucket.label}</code>
                        </td>
                        <td>
                          {bucket.count.toLocaleString()}
                          {bucket.count > 0 && (
                            <span
                              className="latency-bar"
                              style={{ width: `${Math.max(2, (bucket.count / max) * 60)}%` }}
                            />
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card">
            <h3>Task queue</h3>
            <p className="muted">Every task the deployment holds, by lifecycle status.</p>
            <dl className="kv">
              <dt>Queued</dt>
              <dd>{report.taskQueue.queued.toLocaleString()}</dd>
              <dt>Dispatched</dt>
              <dd>{report.taskQueue.dispatched.toLocaleString()}</dd>
              <dt>Completed</dt>
              <dd>{report.taskQueue.completed.toLocaleString()}</dd>
              <dt>Cancelled</dt>
              <dd>{report.taskQueue.cancelled.toLocaleString()}</dd>
            </dl>
          </div>

          <div className="card">
            <h3>Operator streams</h3>
            <dl className="kv">
              <dt>Connected SSE streams</dt>
              <dd>{report.operatorStreams.connectedStreams.toLocaleString()}</dd>
            </dl>
          </div>

          <div className="card">
            <h3>Builds</h3>
            <p className="muted">
              The last {report.builds.total.toLocaleString()} builds (window of 100): duration
              stats over successes; failures count but do not skew them. In-flight includes builds
              waiting on the concurrency gate.
            </p>
            <dl className="kv">
              <dt>In flight</dt>
              <dd>{report.builds.inFlight.toLocaleString()}</dd>
              <dt>Succeeded / failed</dt>
              <dd>
                {report.builds.succeeded.toLocaleString()} / {report.builds.failed.toLocaleString()}
              </dd>
              <dt>Duration min / mean / p95 / max</dt>
              <dd>
                {ms(report.builds.minMs)} / {ms(report.builds.meanMs)} / {ms(report.builds.p95Ms)} /{' '}
                {ms(report.builds.maxMs)}
              </dd>
            </dl>
          </div>

          <div className="card">
            <h3>Modules</h3>
            <p className="muted">
              The modules that loaded through the config list, and the verbs they carry. A module
              that failed to load never appears -- the server refuses to start with it.
            </p>
            {report.modules.loaded.length === 0 ? (
              <p className="muted">
                No modules configured: every registered verb rides its built-in placeholder.
              </p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Module</th>
                      <th>Verbs</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.modules.loaded.map((module) => (
                      <tr key={module.name}>
                        <td>{module.name}</td>
                        <td>
                          {module.verbs.map((verb) => (
                            <code key={verb}>{verb}</code>
                          ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="muted">
              {report.modules.verbsRegistered.toLocaleString()} verbs registered,{' '}
              {report.modules.verbsPlaceholder.toLocaleString()} on placeholders.
            </p>
          </div>
        </>
      )}
    </section>
  )
}
