import { useCallback, useEffect, useState } from 'react'
import { type SystemInfo, getSystemInfo } from '../api'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'

// The system page: the deployment's preflight, read at a glance. The host
// section names the machine the operator is actually driving; the build
// section is every build unit's self-reported environment -- toolchains
// found or missing, the source trees located, and per-target readiness
// (Rust std installed, the cross linker present). The point is honesty
// before failure: a deployment missing a mingw cross-compiler learns it
// here, not minutes later inside a build job.

// The badge vocabulary maps the report's levels onto the task-status pill
// colors: green for a found fact, the queued amber for a working-but-slow
// posture, red for a missing prerequisite.
function levelClass(level: string): string {
  if (level === 'ok') return 'status completed'
  if (level === 'warn') return 'status dispatched'
  return 'status failed'
}

function unitStatusClass(status: string): string {
  if (status === 'ready') return 'status completed'
  if (status === 'partial') return 'status dispatched'
  return 'status failed'
}

function elapsed(iso: string): string {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

export function SystemView() {
  const [info, setInfo] = useState<SystemInfo | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    setBusy(true)
    try {
      setInfo(await getSystemInfo())
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  return (
    <section className="view">
      <h2>
        System
        <HelpHint>
          The host this teamserver runs on, and the environment its build pipeline found —
          toolchains, source trees, per-target readiness — so a missing prerequisite is a glance
          here, not a failed build.
        </HelpHint>
      </h2>
      {error && <p className="error">{error}</p>}

      <div className="card">
        <div className="card-head">
          <h3>Server</h3>
          <button className="ghost" onClick={() => void refresh()} disabled={busy}>
            <Icon name="refresh" />
            Refresh
          </button>
        </div>
        {info ? (
          <dl className="kv">
            <dt>Host</dt>
            <dd>{info.server.host}</dd>
            <dt>Operating system</dt>
            <dd>{info.server.operatingSystem}</dd>
            <dt>Runtime</dt>
            <dd>{info.server.runtime}</dd>
            <dt>Uptime</dt>
            <dd title={`Started ${new Date(info.server.startedAt).toLocaleString()}`}>
              {elapsed(info.server.startedAt)}
            </dd>
          </dl>
        ) : (
          !error && (
            <div className="empty">
              <span className="spinner" />
              Probing the environment…
            </div>
          )
        )}
      </div>

      {info && (
        <>
          <div className="card">
            <h3>Persistence</h3>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Store</th>
                    <th>Adapter</th>
                  </tr>
                </thead>
                <tbody>
                  {info.persistence.stores.map((store) => (
                    <tr key={store.concern}>
                      <td>{store.concern}</td>
                      <td>
                        <code>{store.adapter}</code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="muted">
              {info.persistence.postgresTarget
                ? `Core state persists to PostgreSQL at ${info.persistence.postgresTarget} (set by ConnectionStrings:Postgres at startup -- a composition choice, not a runtime knob).`
                : 'No database configured: core state (engagements, implants, tasks, tokens, listeners, launchers) lives in memory and dies with the process; the audit trail, artifacts, and payloads persist to ' +
                  (info.persistence.dataDirectory || '(no data directory configured)') +
                  '. Set ConnectionStrings:Postgres before startup for durable core state.'}
            </p>
          </div>

          <div className="card">
            <h3>Build units</h3>
            {info.buildUnits.map((unit) => (
              <div key={unit.unitId} className="system-unit">
                <h4>
                  <span className={unitStatusClass(unit.status)}>{unit.status}</span>{' '}
                  {unit.unitId} build unit
                </h4>
                <ul className="system-findings">
                  {unit.findings.map((f) => (
                    <li key={f.area}>
                      <span className={levelClass(f.level)}>{f.level}</span>{' '}
                      <strong>{f.area}</strong>
                      <span className="muted"> — {f.detail}</span>
                    </li>
                  ))}
                </ul>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Target</th>
                        <th>Triple</th>
                        <th>Rust std</th>
                        <th>Linker</th>
                      </tr>
                    </thead>
                    <tbody>
                      {unit.targets.map((t) => (
                        <tr key={t.triple} className={t.stdInstalled && t.linkerFound ? '' : 'row-dim'}>
                          <td>{t.target}</td>
                          <td>
                            <code>{t.triple}</code>
                          </td>
                          <td>
                            <span className={t.stdInstalled ? 'status completed' : 'status failed'}>
                              {t.stdInstalled ? 'installed' : 'missing'}
                            </span>{' '}
                            {!t.stdInstalled && (
                              <span className="muted">rustup target add {t.triple}</span>
                            )}
                          </td>
                          <td>
                            <span className={t.linkerFound ? 'status completed' : 'status failed'}>
                              {t.linkerFound ? 'present' : 'missing'}
                            </span>{' '}
                            <span className="muted">{t.linker}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </section>
  )
}
