import type React from 'react'
import { useCallback, useEffect, useState } from 'react'
import {
  type Campaign,
  type CampaignRecipient,
  createCampaign,
  getCampaign,
  launchCampaign,
  listCampaigns,
  listListeners,
  revokeCampaign,
} from '../api'
import { CopyButton } from '../components/CopyButton'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'
import { ago } from '../when'

// The tracked-lure delivery surface (docs/operations/campaigns.md,
// architecture.md Sec 11.5): the email-shaped half of delivery. A campaign
// is created whole -- relay, template, recipients, build profile -- and
// nothing leaves until launch; the engine then drives one build per
// recipient (the price of enrollment attribution) and sends each message
// once. The evidence columns are the point: opened and clicked are fetch
// facts, executed is the enrollment itself -- the only proof the artifact
// ran. The egress decisions (which relay, whose address, TLS posture) are
// made here per campaign and recorded in the runbook, never defaulted by
// the server.

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
  return iso ? <td title={new Date(iso).toLocaleString()}>{ago(iso)}</td> : <td className="muted">--</td>
}

export function CampaignsView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [selected, setSelected] = useState<Campaign | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
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

  const open = async (campaignId: string) => {
    try {
      setSelected(await getCampaign(engagementId, campaignId))
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }

  const act = async (campaignId: string, what: 'launch' | 'revoke') => {
    setBusy(true)
    try {
      if (what === 'launch') await launchCampaign(engagementId, campaignId)
      else await revokeCampaign(engagementId, campaignId)
      await open(campaignId)
      await refresh()
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const onCreated = async (created: Campaign) => {
    setShowCreate(false)
    await refresh()
    await open(created.campaignId)
  }

  return (
    <section className="view">
      <h2>
        Campaigns
        <HelpHint>
          The tracked lure into tasking: per-recipient messages whose links bind to per-recipient
          builds, followed from send to open, click, and the enrollment itself. One build per
          recipient is the price of enrollment attribution; delivery is single-attempt; the relay
          and its TLS posture are per-campaign decisions, never server defaults.
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
                <th></th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c) => (
                <tr key={c.campaignId}>
                  <td>
                    <a
                      href={`#/engagements/${engagementId}/delivery/campaigns`}
                      onClick={(e) => {
                        e.preventDefault()
                        void open(c.campaignId)
                      }}
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
                  <td>
                    {c.state === 'draft' && (
                      <button disabled={busy} onClick={() => void act(c.campaignId, 'launch')}>
                        Launch
                      </button>
                    )}
                    {c.state !== 'revoked' && c.state !== 'draft' && (
                      <button className="ghost" disabled={busy} onClick={() => void act(c.campaignId, 'revoke')}>
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {campaigns.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    No campaigns yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {selected && <Detail campaign={selected} onAct={act} busy={busy} />}
      </div>
    </section>
  )
}

function Detail({
  campaign,
  onAct,
  busy,
}: {
  campaign: Campaign
  onAct: (id: string, what: 'launch' | 'revoke') => Promise<void>
  busy: boolean
}) {
  const rows = campaign.recipients ?? []
  return (
    <>
      <h4>
        {campaign.name}{' '}
        <span className="muted" title={STATE_HELP[campaign.state]}>
          ({campaign.state})
        </span>
      </h4>
      <p className="muted">
        From {campaign.from} via {campaign.relayHost}:{campaign.relayPort} ({campaign.relayTls}
        {campaign.relayUsername ? `, auth as ${campaign.relayUsername}` : ''}) -- front{' '}
        {campaign.listenerName ?? campaign.listenerId}.
        {campaign.state === 'draft' && (
          <>
            {' '}
            <button className="primary" disabled={busy} onClick={() => void onAct(campaign.campaignId, 'launch')}>
              Launch
            </button>
          </>
        )}
        {campaign.state !== 'revoked' && campaign.state !== 'draft' && (
          <>
            {' '}
            <button className="ghost" disabled={busy} onClick={() => void onAct(campaign.campaignId, 'revoke')}>
              Revoke
            </button>
          </>
        )}
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Recipient</th>
              <th>Status</th>
              <th>Lure</th>
              <th>Sent</th>
              <th>Opened</th>
              <th>Clicked</th>
              <th>Executed</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r: CampaignRecipient) => (
              <tr key={r.recipientId}>
                <td>
                  {r.email}
                  {r.name ? <span className="muted"> ({r.name})</span> : null}
                </td>
                <td>
                  {STATUS_LABEL[r.status]}
                  {r.failure ? <span className="muted"> -- {r.failure}</span> : null}
                </td>
                <td>{r.lureUrl ? <CopyButton text={r.lureUrl} label="Copy link" /> : <span className="muted">{r.lureId}</span>}</td>
                {stampCell(r.sentAt)}
                {stampCell(r.openedAt)}
                {stampCell(r.clickedAt)}
                {r.executedAt ? (
                  <td title={new Date(r.executedAt).toLocaleString()}>
                    {ago(r.executedAt)} <span className="muted">implant {r.enrolledImplantId}</span>
                  </td>
                ) : (
                  <td className="muted">--</td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

// The create form posts the campaign whole. The build profile carries the
// essentials the per-recipient artifact needs (language, class, target,
// cadence, fuse); the server parses it with the build pipeline's own
// parser, so anything invalid refuses at the seam with its own words.
function CreateForm({
  engagementId,
  onCreated,
}: {
  engagementId: string
  onCreated: (created: Campaign) => void
}) {
  const [listeners, setListeners] = useState<{ id: string; name: string; transport: string }[]>([])
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
  const [language, setLanguage] = useState('rust')
  const [targetOs, setTargetOs] = useState('linux')
  const [targetArch, setTargetArch] = useState('amd64')
  const [sleepSeconds, setSleepSeconds] = useState('30')

  useEffect(() => {
    void (async () => {
      try {
        const all = await listListeners(engagementId)
        // The lure rides the web family only; the server refuses the rest,
        // the select simply does not offer them.
        const web = all.filter((l) => l.transport === 'http' || l.transport === 'https')
        setListeners(web)
        setListenerId((current) => current || web[0]?.id || '')
      } catch (e) {
        setError(String(e))
      }
    })()
  }, [engagementId])

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    const parsed = recipients
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line) => {
        const [email, ...rest] = line.split(/\s+/)
        return { email, name: rest.join(' ') || undefined }
      })
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
        recipients: parsed,
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
        <legend>Recipients (one per line: email [display name])</legend>
        <textarea
          value={recipients}
          onChange={(e) => setRecipients(e.target.value)}
          placeholder={'alice@target.example Alice\ntarget.bob@example.com'}
          rows={3}
          required
        />
      </fieldset>
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
