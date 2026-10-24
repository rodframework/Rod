import { useCallback, useEffect, useState } from 'react'
import {
  type Campaign,
  type Implant,
  type ReconAsset,
  deleteReconAsset,
  getCampaign,
  listCampaigns,
  listImplants,
  listReconAssets,
} from '../api'
import { RelatedEntities } from '../components/RelatedEntities'
import { engagementPath } from '../slots'
import { relatedForAsset } from '../related'
import { useArmedDelete } from '../useArmedDelete'
import { ago } from '../when'

// The recon-asset detail page (architecture.md Sec 15.4, ADR-013): the
// targeting vocabulary's own read. The sidebar walks the links forward
// -- the campaigns whose recipients selected this asset and the implants
// those recipients enrolled -- assembled client-side over the campaign
// details (the list read omits recipients) and the fleet list, because
// the reference counts are engagement-sized, not page-sized. Deletion
// lives here too: it refuses while any campaign still references the
// asset, and the server's 409 sentence is the error line.

function fact(label: string, node: React.ReactNode): React.ReactNode {
  return (
    <div className="detail-fact" key={label}>
      <span className="detail-fact-label">{label}</span>
      <span className="detail-fact-value">{node}</span>
    </div>
  )
}

export function ReconAssetDetailView({
  engagementId,
  assetId,
  onlineTick,
}: {
  engagementId: string
  assetId: string
  onlineTick: number
}) {
  const [asset, setAsset] = useState<ReconAsset | null>(null)
  const [campaignDetails, setCampaignDetails] = useState<Campaign[]>([])
  const [implants, setImplants] = useState<Implant[]>([])
  const [missing, setMissing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [armed, arm] = useArmedDelete()

  const refresh = useCallback(async () => {
    try {
      // Recipients ride the detail reads only, so the reference walk
      // fetches each campaign's detail; campaign counts stay small
      // enough that this is one burst, not a pagination problem.
      const [roster, campaignList, fleet] = await Promise.all([
        listReconAssets(engagementId),
        listCampaigns(engagementId),
        listImplants(engagementId).catch(() => [] as Implant[]),
      ])
      const found = roster.find((a) => a.assetId === assetId)
      if (!found) {
        setMissing(true)
        return
      }
      const details = await Promise.all(
        campaignList.map((c) => getCampaign(engagementId, c.campaignId).catch(() => null)),
      )
      setAsset(found)
      setCampaignDetails(details.filter((c): c is Campaign => c !== null))
      setImplants(fleet)
      setMissing(false)
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }, [engagementId, assetId])

  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  const onDelete = () => {
    arm(assetId, () => {
      void (async () => {
        try {
          await deleteReconAsset(engagementId, assetId)
          window.location.hash = engagementPath(engagementId, 'assets')
        } catch (e) {
          setError(String(e))
        }
      })()
    })
  }

  if (missing) {
    return (
      <section className="view">
        <h2>Recon asset</h2>
        <p className="muted">
          No recon asset reads as {assetId.slice(0, 8)}.{' '}
          <a href={engagementPath(engagementId, 'assets')}>Back to the roster</a>.
        </p>
      </section>
    )
  }

  if (!asset) {
    return (
      <section className="view">
        <h2>Recon asset</h2>
        <div className="empty">
          <span className="spinner" /> Reading the asset… {error}
        </div>
      </section>
    )
  }

  return (
    <section className="view">
      <a className="back-link" href={engagementPath(engagementId, 'assets')}>
        &larr; Recon assets
      </a>
      <div className="entity-detail">
        <div className="entity-detail-main">
          <h2>
            <code>{asset.value}</code> <span className="muted">{asset.kind}</span>
          </h2>
          <div className="entity-actions">
            <button
              className={armed ? 'danger sm' : 'ghost sm'}
              onClick={onDelete}
              title="Delete the asset (refuses while a campaign references it)"
            >
              {armed ? 'Confirm' : 'Delete'}
            </button>
          </div>
          <div className="detail-facts">
            {fact('value', <code>{asset.value}</code>)}
            {fact('kind', asset.kind)}
            {fact('display name', asset.displayName ?? <span className="muted">&mdash;</span>)}
            {fact(
              'recorded',
              <>
                {' '}
                {ago(asset.createdAt)} by <code title={asset.createdBy}>{asset.createdByHandle}</code>
              </>,
            )}
          </div>
          {error && <p className="error">{error}</p>}
        </div>
        <aside className="entity-detail-aside">
          <h3>Related</h3>
          <RelatedEntities groups={relatedForAsset(engagementId, asset, campaignDetails, implants)} />
        </aside>
      </div>
    </section>
  )
}
