import { useCallback, useEffect, useState } from 'react'
import {
  type EngagementTask,
  type ImplantDetail,
  type ReconAsset,
  getImplantDetail,
  listImplantTasks,
  listReconAssets,
} from '../api'
import { RelatedEntities } from '../components/RelatedEntities'
import { StatusBadge } from '../components/StatusBadge'
import { engagementPath } from '../slots'
import { relatedForImplant } from '../related'
import { ago, formatSeconds } from '../when'

// The implant detail page (architecture.md Sec 15.4, ADR-013): the
// master-detail drill-in the fleet table's rows open -- the whole
// record on the left, the related-entities sidebar on the right. The
// sidebar is the point: lineage (the lateral-movement tree the
// provenance chain draws), the campaign whose lure delivered this
// implant, and the recon asset the target was selected from -- the
// unified entity model's explicit links, not strings to eyeball. The
// session console stays the working surface; this page is the read.

function fact(label: string, node: React.ReactNode): React.ReactNode {
  return (
    <div className="detail-fact" key={label}>
      <span className="detail-fact-label">{label}</span>
      <span className="detail-fact-value">{node}</span>
    </div>
  )
}

const dash = <span className="muted">&mdash;</span>

export function ImplantDetailView({
  engagementId,
  implantId,
  onlineTick,
}: {
  engagementId: string
  implantId: string
  onlineTick: number
}) {
  const [detail, setDetail] = useState<ImplantDetail | null>(null)
  const [tasks, setTasks] = useState<EngagementTask[]>([])
  const [assets, setAssets] = useState<ReconAsset[]>([])
  const [missing, setMissing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [read, taskPage, roster] = await Promise.all([
        getImplantDetail(engagementId, implantId),
        listImplantTasks(engagementId, implantId),
        listReconAssets(engagementId).catch(() => [] as ReconAsset[]),
      ])
      setDetail(read)
      setTasks(taskPage.items)
      setAssets(roster)
      setMissing(false)
      setError(null)
    } catch (e) {
      // A retired-and-pruned id or a stale link: say it plainly.
      setMissing(true)
      setError(String(e))
    }
  }, [engagementId, implantId])

  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  if (missing) {
    return (
      <section className="view">
        <h2>Implant</h2>
        <p className="muted">
          No implant reads as {implantId.slice(0, 8)}.{' '}
          <a href={engagementPath(engagementId, 'implants')}>Back to the fleet</a>. {error}
        </p>
      </section>
    )
  }

  if (!detail) {
    return (
      <section className="view">
        <h2>Implant</h2>
        <div className="empty">
          <span className="spinner" /> Reading the record…
        </div>
      </section>
    )
  }

  const { implant, provenance } = detail
  const retired = !!implant.retiredAt
  const host = [implant.hostname, implant.os, implant.arch, implant.username].filter(Boolean).join(' · ')
  const campaign = provenance.campaign

  return (
    <section className="view">
      <a className="back-link" href={engagementPath(engagementId, 'implants')}>
        &larr; Implants
      </a>
      <div className="entity-detail">
        <div className="entity-detail-main">
          <h2>
            <code>{implant.implantId.slice(0, 8)}</code>{' '}
            <span className="muted">{implant.class}</span>{' '}
            <StatusBadge status={retired ? 'retired' : implant.isOnline ? 'online' : 'offline'} />
          </h2>
          <div className="entity-actions">
            <a
              className="button-link sm"
              href={engagementPath(engagementId, 'implants', implant.implantId, 'interact')}
              title="Open the session console -- the working surface"
            >
              Interact
            </a>
          </div>
          <div className="detail-facts">
            {fact('implant', <code>{implant.implantId}</code>)}
            {fact('host', host || dash)}
            {fact(
              'cadence',
              implant.sleepSeconds != null ? (
                <>
                  every {formatSeconds(implant.sleepSeconds)} ±{' '}
                  {implant.jitterSeconds != null ? formatSeconds(implant.jitterSeconds) : '?'}
                </>
              ) : (
                <span className="muted">not reported</span>
              ),
            )}
            {fact(
              'lifecycle',
              <>
                created {new Date(implant.createdAt).toLocaleString()}
                {implant.killDate ? <> · kill {new Date(implant.killDate).toLocaleDateString()}</> : null}
                {retired ? <> · retired {new Date(implant.retiredAt!).toLocaleString()}</> : null}
                {implant.lastSeenAt ? <> · last seen {ago(implant.lastSeenAt)}</> : null}
              </>,
            )}
            {fact(
              'deployed by',
              implant.deployedBy ? (
                <code title={implant.deployedBy}>{implant.deployedByHandle}</code>
              ) : (
                dash
              ),
            )}
            {fact(
              'ingress',
              implant.enrolledViaListenerId ? <code>{implant.enrolledViaListenerId}</code> : dash,
            )}
            {fact(
              'carriers',
              implant.carriers && implant.carriers.length > 0 ? (
                implant.carriers.join(', ')
              ) : (
                <span className="muted">undeclared</span>
              ),
            )}
            {campaign &&
              fact(
                'delivered by',
                <>
                  campaign{' '}
                  <a href={engagementPath(engagementId, 'campaigns', campaign.campaignId)}>
                    {campaign.campaignName}
                  </a>{' '}
                  to {campaign.email}
                  {campaign.executedAt ? <> · executed {ago(campaign.executedAt)}</> : null}
                </>,
              )}
          </div>

          <h3>Tasks</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Verb</th>
                  <th>Status</th>
                  <th>Issued</th>
                  <th>Outcome</th>
                </tr>
              </thead>
              <tbody>
                {tasks.length === 0 && (
                  <tr>
                    <td colSpan={4} className="muted">
                      No tasks issued yet.
                    </td>
                  </tr>
                )}
                {[...tasks].reverse().map((t) => (
                  <tr key={t.taskId}>
                    <td>
                      <code>{t.verb}</code>
                    </td>
                    <td>{t.status}</td>
                    <td title={new Date(t.createdAt).toLocaleString()}>{ago(t.createdAt)}</td>
                    <td>{t.outcome || <span className="muted">&mdash;</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <aside className="entity-detail-aside">
          <h3>Related</h3>
          <RelatedEntities groups={relatedForImplant(engagementId, detail, assets)} />
        </aside>
      </div>
    </section>
  )
}
