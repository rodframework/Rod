import type React from 'react'
import { useCallback, useEffect, useState } from 'react'
import {
  type Campaign,
  type ReconAsset,
  createCampaign,
  listCampaigns,
  listListeners,
  listReconAssets,
} from '../api'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'
import { engagementPath } from '../slots'
import { ago } from '../when'

// The tracked-lure delivery surface (docs/operations/campaigns.md,
// architecture.md Sec 11.5): the email-shaped half of delivery. A campaign
// is created whole -- relay, template, recipients, build profile -- and
// nothing leaves until launch. The roster is the master list: each row
// opens the campaign's detail page (the evidence columns, the recipients,
// launch and revoke, the related-entities sidebar); the counts here size
// the campaign at a glance. Recipients come from two vocabularies: a
// hand-typed address, or a recon asset selected straight from the
// targeting roster -- the unified entity model's link (Sec 15.4), spent
// at creation.

const STATE_HELP: Record<string, string> = {
  draft: 'Created; nothing has been sent and no builds were driven. Launch arms it.',
  launched: 'Armed: the engine drives per-recipient builds and sends.',
  completed: 'Every recipient is terminal (sent or failed). The lures stay live until revoked.',
  revoked: 'Burned: sends stopped and every lure in the campaign 404s.',
}

export function CampaignsView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [error, setError] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setCampaigns(await listCampaigns(engagementId))
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }, [engagementId])

  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  const onCreated = async (created: Campaign) => {
    setShowCreate(false)
    await refresh()
    // Land on the new campaign's detail page, where launch waits.
    window.location.hash = engagementPath(engagementId, 'campaigns', created.campaignId)
  }

  return (
    <section className="view">
      <h2>
        Campaigns
        <HelpHint>
          The tracked lure into tasking: per-recipient messages whose links bind to per-recipient
          builds, followed from send to open, click, and the enrollment itself. One build per
          recipient is the price of enrollment attribution; delivery is single-attempt; the relay
          and its TLS posture are per-campaign decisions, never server defaults. Each row opens the
          campaign's detail page -- the evidence and the actions live there.
        </HelpHint>
      </h2>
      {error && <p className="error">{error}</p>}

      {showCreate && (
        <div className="card">
          <h3>New campaign</h3>
          <CreateForm engagementId={engagementId} onCreated={(c) => void onCreated(c)} />
        </div>
      )}

      <div className="card">
        <div className="card-head">
          <h3>Roster</h3>
          <div className="inline-form">
            <button className="ghost" onClick={() => void refresh()}>
              <Icon name="refresh" />
              Refresh
            </button>
            <button className="primary" onClick={() => setShowCreate((v) => !v)}>
              {showCreate ? 'Close the form' : 'New campaign'}
            </button>
          </div>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>State</th>
                <th>Recipients</th>
                <th>Evidence (o/c/x)</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c) => (
                <tr key={c.campaignId}>
                  <td>
                    <a
                      href={engagementPath(engagementId, 'campaigns', c.campaignId)}
                      title="Open the campaign's detail page"
                    >
                      {c.name}
                    </a>
                  </td>
                  <td title={STATE_HELP[c.state]}>{c.state}</td>
                  <td>
                    {c.sent}/{c.total} sent{c.failed > 0 ? `, ${c.failed} failed` : ''}
                  </td>
                  <td>
                    {c.opened}/{c.clicked}/{c.executed}
                  </td>
                  <td title={new Date(c.createdAt).toLocaleString()}>{ago(c.createdAt)}</td>
                </tr>
              ))}
              {campaigns.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    No campaigns yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}

// The create form posts the campaign whole. The build profile carries the
// essentials the per-recipient artifact needs (language, class, target,
// cadence, fuse); the server parses it with the build pipeline's own
// parser, so anything invalid refuses at the seam with its own words.
// Recipients arrive from two vocabularies: typed lines (email [name])
// and selected recon assets -- an asset carries its own address and
// becomes the link the sidebar later draws.
function CreateForm({
  engagementId,
  onCreated,
}: {
  engagementId: string
  onCreated: (created: Campaign) => void
}) {
  const [listeners, setListeners] = useState<{ id: string; name: string; transport: string }[]>([])
  const [assets, setAssets] = useState<ReconAsset[]>([])
  const [error, setError] = useState<string | null>(null)

  const [name, setName] = useState('')
  const [listenerId, setListenerId] = useState('')
  const [relayHost, setRelayHost] = useState('')
  const [relayPort, setRelayPort] = useState('587')
  const [relayTls, setRelayTls] = useState<'starttls' | 'implicit' | 'none'>('starttls')
  const [relayUsername, setRelayUsername] = useState('')
  const [relayPassword, setRelayPassword] = useState('')
  const [from, setFrom] = useState('')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [bodyIsHtml, setBodyIsHtml] = useState(false)
  const [recipients, setRecipients] = useState('')
  // The selected recon-asset ids; they ride the create body as
  // reconAssetId recipients beside the typed lines.
  const [selectedAssets, setSelectedAssets] = useState<Set<string>>(new Set())
  const [language, setLanguage] = useState('rust')
  const [targetOs, setTargetOs] = useState('linux')
  const [targetArch, setTargetArch] = useState('amd64')
  const [sleepSeconds, setSleepSeconds] = useState('30')

  const emailAssets = assets.filter((a) => a.kind === 'email')

  useEffect(() => {
    void (async () => {
      try {
        const [all, roster] = await Promise.all([
          listListeners(engagementId),
          listReconAssets(engagementId).catch(() => [] as ReconAsset[]),
        ])
        // The lure rides the web family only; the server refuses the rest,
        // the select simply does not offer them.
        const web = all.filter((l) => l.transport === 'http' || l.transport === 'https')
        setListeners(web)
        setListenerId((current) => current || web[0]?.id || '')
        setAssets(roster)
      } catch (e) {
        setError(String(e))
      }
    })()
  }, [engagementId])

  const toggleAsset = (assetId: string) => {
    setSelectedAssets((current) => {
      const next = new Set(current)
      if (next.has(assetId)) next.delete(assetId)
      else next.add(assetId)
      return next
    })
  }

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    const typed = recipients
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line) => {
        const [email, ...rest] = line.split(/\s+/)
        return { email, name: rest.join(' ') || undefined }
      })
    const fromAssets = [...selectedAssets].map((reconAssetId) => ({ reconAssetId }))
    try {
      const created = await createCampaign(engagementId, {
        name,
        listenerId,
        relayHost,
        relayPort: Number(relayPort),
        relayTls,
        relayUsername: relayUsername || undefined,
        relayPassword: relayPassword || undefined,
        from,
        subject,
        body,
        bodyIsHtml,
        recipients: [...typed, ...fromAssets],
        build: {
          language,
          class: 'Implant',
          targetOs,
          targetArch,
          sleepSeconds: Number(sleepSeconds),
          listenerId,
        },
      })
      setError(null)
      onCreated(created)
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <form className="build-form" onSubmit={(e) => void onSubmit(e)}>
      <fieldset>
        <legend>New campaign</legend>
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="q3-renewal-push" required />
        </label>
        <label>
          Front (the listener whose public endpoint carries every lure)
          <select value={listenerId} onChange={(e) => setListenerId(e.target.value)} required>
            {listeners.length === 0 && <option value="">no http/https listener</option>}
            {listeners.map((l) => (
              <option key={l.id} value={l.id}>
                {l.name} ({l.transport})
              </option>
            ))}
          </select>
        </label>
      </fieldset>
      <fieldset>
        <legend>Relay (the egress decision -- whose address sends this mail)</legend>
        <label>
          Host
          <input value={relayHost} onChange={(e) => setRelayHost(e.target.value)} placeholder="smtp.relay.example" required />
        </label>
        <label>
          Port
          <input value={relayPort} onChange={(e) => setRelayPort(e.target.value)} inputMode="numeric" required />
        </label>
        <label>
          TLS
          <select value={relayTls} onChange={(e) => setRelayTls(e.target.value as 'starttls' | 'implicit' | 'none')}>
            <option value="starttls">startTls (upgrade in the clear)</option>
            <option value="implicit">implicit (TLS from the first byte)</option>
            <option value="none">none (lab relays only)</option>
          </select>
        </label>
        <label>
          Username (optional)
          <input value={relayUsername} onChange={(e) => setRelayUsername(e.target.value)} autoComplete="off" />
        </label>
        <label>
          Password (optional)
          <input
            type="password"
            value={relayPassword}
            onChange={(e) => setRelayPassword(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        <label>
          From
          <input value={from} onChange={(e) => setFrom(e.target.value)} placeholder="billing@lure.example" required />
        </label>
      </fieldset>
      <fieldset>
        <legend>Message (merge fields: {'{{link}}'} required; {'{{pixel}}'}, {'{{email}}'}, {'{{name}}'})</legend>
        <label>
          Subject
          <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Your {{name}} renewal" required />
        </label>
        <label>
          Body
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder={'Dear {{name}}, review your renewal at {{link}}.'}
            rows={4}
            required
          />
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={bodyIsHtml} onChange={(e) => setBodyIsHtml(e.target.checked)} />
          HTML body (auto-injects the tracking pixel when {'{{pixel}}'} is absent)
        </label>
      </fieldset>
      <fieldset>
        <legend>Recipients (typed: one per line, email [display name])</legend>
        <textarea
          value={recipients}
          onChange={(e) => setRecipients(e.target.value)}
          placeholder={'alice@target.example Alice\ntarget.bob@example.com'}
          rows={3}
        />
      </fieldset>
      {emailAssets.length > 0 && (
        <fieldset>
          <legend>Recipients from recon assets (the targeting vocabulary, selected straight)</legend>
          <div className="asset-picker">
            {emailAssets.map((a) => (
              <label key={a.assetId} className="checkbox asset-picker-item">
                <input
                  type="checkbox"
                  checked={selectedAssets.has(a.assetId)}
                  onChange={() => toggleAsset(a.assetId)}
                />
                <code>{a.value}</code>
                {a.displayName ? <span className="muted"> {a.displayName}</span> : null}
              </label>
            ))}
          </div>
          {selectedAssets.size > 0 && (
            <p className="muted">{selectedAssets.size} recon asset(s) selected as recipients.</p>
          )}
        </fieldset>
      )}
      <fieldset>
        <legend>Per-recipient build (one build per recipient -- the attribution price)</legend>
        <label>
          Language
          <input value={language} onChange={(e) => setLanguage(e.target.value)} required />
        </label>
        <label>
          Target OS
          <input value={targetOs} onChange={(e) => setTargetOs(e.target.value)} required />
        </label>
        <label>
          Target arch
          <input value={targetArch} onChange={(e) => setTargetArch(e.target.value)} required />
        </label>
        <label>
          Sleep (s)
          <input value={sleepSeconds} onChange={(e) => setSleepSeconds(e.target.value)} inputMode="numeric" />
        </label>
      </fieldset>
      {error && <p className="error">{error}</p>}
      <button className="primary" type="submit">
        Create (draft -- nothing sends until launch)
      </button>
    </form>
  )
}
