import { useEffect, useState } from 'react'
import { type CredentialRow, listCredentials } from '../api'
import { HelpHint } from '../components/HelpHint'

// The credentials board (architecture.md Sec 15.2's second contract):
// the read-time projection over every completed task whose verb declared
// credential output -- any module's harvest lands here through its
// declaration alone, so the board knows no verb. An assets-slot surface
// since the slots rework: credentials are what the engagement holds.
// Secrets stay masked until revealed; the rows carry their capture
// attribution.

export function CredentialsBoardView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [rows, setRows] = useState<CredentialRow[] | null>(null)
  const [revealed, setRevealed] = useState<Set<number>>(new Set())
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const list = await listCredentials(engagementId)
        if (!cancelled) {
          setRows(list)
          setError(null)
        }
      } catch (e) {
        if (!cancelled) setError(String(e))
      }
    })()
    return () => {
      cancelled = true
    }
  }, [engagementId, onlineTick])

  return (
    <section className="view">
      <h2>
        Credentials
        <HelpHint>
          The harvest board: every credential any verb that declared credential output
          captured -- any module's harvest lands here through its declaration alone. Secrets
          stay masked until revealed; each row carries its capture attribution.
        </HelpHint>
      </h2>
      <div className="card">
        {error && <p className="error">{error}</p>}
        {!rows && !error && <p className="muted">Assembling the harvest…</p>}
        {rows && (
          <>
            <table>
              <thead>
                <tr>
                  <th>Captured</th>
                  <th>Kind</th>
                  <th>Principal</th>
                  <th>Secret</th>
                  <th>Source</th>
                  <th>Host</th>
                  <th>Harvested by</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, index) => (
                  <tr key={`${row.verb}-${row.principal}-${index}`}>
                    <td>{new Date(row.capturedAt).toLocaleString()}</td>
                    <td>
                      <span className="chip">{row.kind}</span>
                    </td>
                    <td>
                      <code>{row.principal}</code>
                    </td>
                    <td>
                      {row.secret === null ? (
                        <span className="muted">—</span>
                      ) : revealed.has(index) ? (
                        <code>{row.secret}</code>
                      ) : (
                        <button
                          className="ghost sm"
                          onClick={() => setRevealed((current) => new Set(current).add(index))}
                        >
                          Reveal
                        </button>
                      )}
                    </td>
                    <td>{row.source ?? <span className="muted">—</span>}</td>
                    <td>{row.host ?? <span className="muted">—</span>}</td>
                    <td title={row.taskId ? `task ${row.taskId}` : undefined}>
                      {row.verb}
                      {row.implantId ? ` (implant ${row.implantId.slice(0, 8)})` : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length === 0 && (
              <p className="muted">
                No credentials harvested yet -- any verb that declares credential output lands
                its rows here.
              </p>
            )}
          </>
        )}
      </div>
    </section>
  )
}
