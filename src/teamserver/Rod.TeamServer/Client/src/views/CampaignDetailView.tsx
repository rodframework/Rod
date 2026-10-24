import { useCallback, useEffect, useState } from 'react'
import {
  type Campaign,
  type Implant,
  type ReconAsset,
  getCampaign,
  launchCampaign,
  listImplants,
  listReconAssets,
  revokeCampaign,
} from '../api'
import { CopyButton } from '../components/CopyButton'
import { RelatedEntities } from '../components/RelatedEntities'
import { engagementPath } from '../slots'
import { relatedForCampaign } from '../related'
import { ago } from '../when'

// The campaign detail page (architecture.md Sec 15.4, ADR-013): the
// master-detail drill-in the campaigns roster's rows open. The
// recipients table is the evidence -- opened and clicked are fetch
// facts, executed is the enrollment itself -- and now carries the
// entity links the unified model ships: each recipient selected from
// the recon vocabulary reads as a link to its asset, and each execution
// as a link to the implant it enrolled. The sidebar folds the same
// links into groups (the assets the campaign targeted, the implants it
// produced); launch and revoke stay here, beside what they arm or burn.

const STATE_HELP: Record<string, string> = {
  draft: 'Created; nothing has been sent and no builds were driven. Launch arms it.',
  launched: 'Armed: the engine drives per-recipient builds and sends.',
  completed: 'Every recipient is terminal (sent or failed). The lures stay live until revoked.',
  revoked: 'Burned: sends stopped and every lure in the campaign 404s.',
}

const STATUS_LABEL: Record<string, string> = {
  pending: 'pending',
  building: 'building',
  sent: 'sent',
  failed: 'failed',
}

function stampCell(iso: string | null): React.ReactNode {
  return iso ? (
    <td title={new Date(iso).toLocaleString()}>{ago(iso)}</td>
  ) : (
    <td className="muted">--</td>
  )
}

function fact(label: string, node: React.ReactNode): React.ReactNode {
  return (
    <div className="detail-fact" key={label}>
      <span className="detail-fact-label">{label}</span>
      <span className="detail-fact-value">{node}</span>
    </div>
  )
}

export function CampaignDetailView({
  engagementId,
  campaignId,
  onlineTick,
}: {
  engagementId: string
  campaignId: string
  onlineTick: number
}) {
  const [campaign, setCampaign] = useState<Campaign | null>(null)
  const [implants, setImplants] = useState<Implant[]>([])
  const [assets, setAssets] = useState<ReconAsset[]>([])
  const [missing, setMissing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const [read, fleet, roster] = await Promise.all([
        getCampaign(engagementId, campaignId),
        listImplants(engagementId).catch(() => [] as Implant[]),
        listReconAssets(engagementId).catch(() => [] as ReconAsset[]),
      ])
      setCampaign(read)
      setImplants(fleet)
      setAssets(roster)
      setMissing(false)
      setError(null)
    } catch (e) {
      setMissing(true)
      setError(String(e))
    }
  }, [engagementId, campaignId])

  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  const act = async (what: 'launch' | 'revoke') => {
    setBusy(true)
    try {
      if (what === 'launch') await launchCampaign(engagementId, campaignId)
      else await revokeCampaign(engagementId, campaignId)
      await refresh()
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  if (missing) {
    return (
      <section className="view">
        <h2>Campaign</h2>
        <p className="muted">
          No campaign reads as {campaignId.slice(0, 8)}.{' '}
          <a href={engagementPath(engagementId, 'campaigns')}>Back to the roster</a>. {error}
        </p>
      </section>
    )
  }

  if (!campaign) {
    return (
      <section className="view">
        <h2>Campaign</h2>
        <div className="empty">
          <span className="spinner" /> Reading the campaign…
        </div>
      </section>
    )
  }

  const recipients = campaign.recipients ?? []
  const assetById = new Map(assets.map((a) => [a.assetId, a]))

  return (
    <section className="view">
      <a className="back-link" href={engagementPath(engagementId, 'campaigns')}>
        &larr; Campaigns
      </a>
      <div className="entity-detail">
        <div className="entity-detail-main">
          <h2>
            {campaign.name}{' '}
            <span className="muted" title={STATE_HELP[campaign.state]}>
              ({campaign.state})
            </span>
          </h2>
          <div className="entity-actions">
            {campaign.state === 'draft' && (
              <button className="primary sm" disabled={busy} onClick={() => void act('launch')}>
                Launch
              </button>
            )}
            {campaign.state !== 'revoked' && campaign.state !== 'draft' && (
              <button className="ghost sm" disabled={busy} onClick={() => void act('revoke')}>
                Revoke
              </button>
            )}
          </div>
          <div className="detail-facts">
            {fact(
              'relay',
              <>
                {campaign.from} via {campaign.relayHost}:{campaign.relayPort} ({campaign.relayTls}
                {campaign.relayUsername ? `, auth as ${campaign.relayUsername}` : ''})
              </>,
            )}
            {fact('front', campaign.listenerName ?? campaign.listenerId)}
            {fact(
              'evidence',
              <>
                {campaign.sent}/{campaign.total} sent{campaign.failed > 0 ? `, ${campaign.failed} failed` : ''}{' '}
                · {campaign.opened} opened · {campaign.clicked} clicked · {campaign.executed} executed
              </>,
            )}
            {fact(
              'lifecycle',
              <>
                created {new Date(campaign.createdAt).toLocaleString()}
                {campaign.launchedAt ? <> · launched {ago(campaign.launchedAt)}</> : null}
                {campaign.completedAt ? <> · completed {ago(campaign.completedAt)}</> : null}
                {campaign.revokedAt ? <> · revoked {ago(campaign.revokedAt)}</> : null}
              </>,
            )}
          </div>

          <h3>Recipients</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Recipient</th>
                  <th>Status</th>
                  <th>Recon asset</th>
                  <th>Lure</th>
                  <th>Sent</th>
                  <th>Opened</th>
                  <th>Clicked</th>
                  <th>Executed</th>
                </tr>
              </thead>
              <tbody>
                {recipients.length === 0 && (
                  <tr>
                    <td colSpan={8} className="muted">
                      No recipients.
                    </td>
                  </tr>
                )}
                {recipients.map((r) => {
                  const asset = r.reconAssetId ? assetById.get(r.reconAssetId) : undefined
                  return (
                    <tr key={r.recipientId}>
                      <td>
                        {asset ? (
                          <a
                            href={engagementPath(engagementId, 'assets', r.reconAssetId!)}
                            title={`Selected from the recon vocabulary: ${asset.value} (${asset.kind})`}
                          >
                            {r.email}
                          </a>
                        ) : (
                          r.email
                        )}
                        {r.name ? <span className="muted"> ({r.name})</span> : null}
                      </td>
                      <td>
                        {STATUS_LABEL[r.status]}
                        {r.failure ? <span className="muted"> -- {r.failure}</span> : null}
                      </td>
                      <td>
                        {r.reconAssetId ? (
                          <a
                            href={engagementPath(engagementId, 'assets', r.reconAssetId)}
                            title={asset?.value ?? r.reconAssetId}
                          >
                            {(asset?.displayName ?? asset?.value ?? r.reconAssetId.slice(0, 8))}
                          </a>
                        ) : (
                          <span className="muted">typed</span>
                        )}
                      </td>
                      <td>
                        {r.lureUrl ? (
                          <CopyButton text={r.lureUrl} label="Copy link" />
                        ) : (
                          <span className="muted">{r.lureId.slice(0, 8)}</span>
                        )}
                      </td>
                      {stampCell(r.sentAt)}
                      {stampCell(r.openedAt)}
                      {stampCell(r.clickedAt)}
                      {r.enrolledImplantId ? (
                        <td title={r.executedAt ? new Date(r.executedAt).toLocaleString() : undefined}>
                          <a href={engagementPath(engagementId, 'implants', r.enrolledImplantId)}>
                            {r.enrolledImplantId.slice(0, 8)}
                          </a>
                        </td>
                      ) : (
                        <td className="muted">--</td>
                      )}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          {error && <p className="error">{error}</p>}
        </div>
        <aside className="entity-detail-aside">
          <h3>Related</h3>
          <RelatedEntities groups={relatedForCampaign(engagementId, campaign, implants, assets)} />
        </aside>
      </div>
    </section>
  )
}
