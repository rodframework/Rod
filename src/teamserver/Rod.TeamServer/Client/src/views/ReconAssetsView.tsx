import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  type ReconAsset,
  type ReconAssetKind,
  createReconAsset,
  deleteReconAsset,
  listReconAssets,
} from '../api'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'
import { useArmedDelete } from '../useArmedDelete'
import { ago } from '../when'

// The recon-assets roster (architecture.md Sec 15.4, the unified entity
// model): the named targeting vocabulary -- emails, domains, hosts,
// addresses -- recorded as campaign-worthy before any foothold exists.
// An asset's whole point is selection: campaign recipients take a
// reconAssetId in place of a hand-typed address, and recipients and the
// implants they enroll carry the id back, so the roster is where the
// delivery stage reaches in for its targets. Recording and deletion are
// trail facts; deletion refuses while a campaign still references the
// asset (the server's 409, shown verbatim).

const KINDS: readonly ReconAssetKind[] = ['email', 'domain', 'host', 'address']

const KIND_HINT: Record<ReconAssetKind, string> = {
  email: 'a delivery target address',
  domain: 'a scope or infrastructure name',
  host: 'a named machine',
  address: 'a network address',
}

export function ReconAssetsView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [assets, setAssets] = useState<ReconAsset[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [kind, setKind] = useState<ReconAssetKind>('email')
  const [value, setValue] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [armed, arm] = useArmedDelete()
  // The client-side kind filter; live like the fleet's dropdowns.
  const [kindFilter, setKindFilter] = useState('')

  const refresh = useCallback(async () => {
    try {
      setAssets(await listReconAssets(engagementId))
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }, [engagementId])

  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  const filtered = useMemo(
    () => (kindFilter === '' ? assets : assets.filter((a) => a.kind === kindFilter)),
    [assets, kindFilter],
  )

  const onAdd = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!value.trim() || busy) return
    setBusy(true)
    try {
      await createReconAsset(engagementId, {
        kind,
        value: value.trim(),
        displayName: displayName.trim() || undefined,
      })
      setValue('')
      setDisplayName('')
      await refresh()
      setError(null)
    } catch (e) {
      // A duplicate value answers 409; the server's sentence is the
      // form's error line.
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const onDelete = (assetId: string) => {
    arm(assetId, () => {
      void (async () => {
        try {
          await deleteReconAsset(engagementId, assetId)
          await refresh()
          setError(null)
        } catch (e) {
          setError(String(e))
        }
      })()
    })
  }

  return (
    <section className="view">
      <h2>
        Recon assets
        <HelpHint>
          The named targeting vocabulary: what the recon stage recorded as
          campaign-worthy. Campaign recipients select an asset instead of a
          hand-typed address, and recipients and the implants they enroll carry
          the asset link back -- the related-entities sidebar draws it. Deleting
          an asset refuses while any campaign recipient still references it.
        </HelpHint>
      </h2>
      <div className="card">
        <p className="muted">
          {assets.length} asset{assets.length === 1 ? '' : 's'}
          {kindFilter !== '' && assets.length !== filtered.length && (
            <span title="Clear the kind filter to see every asset"> (of {assets.length})</span>
          )}
        </p>
        <div className="table-toolbar">
          <select
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value)}
            aria-label="Kind filter"
            title="The asset kind: email, domain, host, or address"
          >
            <option value="">All kinds</option>
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Value</th>
                <th>Kind</th>
                <th>Display name</th>
                <th>Recorded</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={5}>
                    <div className="empty">
                      <Icon name="target" />
                      {assets.length === 0
                        ? 'No recon assets recorded yet.'
                        : 'No assets match the kind filter.'}
                    </div>
                  </td>
                </tr>
              )}
              {filtered.map((asset) => (
                <tr key={asset.assetId}>
                  <td>
                    <a
                      href={`#/engagements/${engagementId}/recon/assets/${asset.assetId}`}
                      title="Open the asset's detail page -- its campaigns and implants"
                    >
                      <code>{asset.value}</code>
                    </a>
                  </td>
                  <td title={KIND_HINT[asset.kind]}>{asset.kind}</td>
                  <td>
                    {asset.displayName ?? <span className="muted">&mdash;</span>}
                  </td>
                  <td title={`${new Date(asset.createdAt).toLocaleString()} by ${asset.createdBy.slice(0, 8)}`}>
                    {ago(asset.createdAt)}
                  </td>
                  <td>
                    <button
                      className={armed === asset.assetId ? 'danger sm' : 'ghost sm'}
                      onClick={() => onDelete(asset.assetId)}
                      title="Delete the asset (refuses while a campaign references it)"
                    >
                      {armed === asset.assetId ? 'Confirm' : 'Delete'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {error && <p className="error">{error}</p>}
        <form className="task-form" onSubmit={onAdd}>
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as ReconAssetKind)}
            aria-label="Asset kind"
            title={KIND_HINT[kind]}
          >
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
          <input
            placeholder="value (an address, a domain, a host)"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            required
          />
          <input
            className="wide"
            placeholder="display name (optional)"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
          <button type="submit" disabled={busy || !value.trim()}>
            Record
          </button>
        </form>
      </div>
    </section>
  )
}
