import { useCallback, useEffect, useMemo, useState } from 'react'
import { ChatPanel } from '../components/ChatPanel'
import {
  type ClaimSummary,
  type DrivingEntry,
  type LiveOperator,
  type PresenceRecord,
  type SessionOperator,
  listImplants,
  listOnline,
  subscribeToEngagement,
} from '../api'
import type { SubId } from '../slots'
import { SLOTS, engagementPath } from '../slots'
import { LiveContext } from '../shell'
import { usePollIntervalMs } from '../clientPrefs'
import { AuditView } from './AuditView'
import { TimelineView } from './TimelineView'
import { ImplantsView } from './ImplantsView'
import { ImplantDetailView } from './ImplantDetailView'
import { InteractView } from './InteractView'
import { LaunchersView } from './LaunchersView'
import { ListenersView } from './ListenersView'
import { PayloadBuildView } from './PayloadBuildView'
import { PayloadsView } from './PayloadsView'
import { ReportView } from './ReportView'
import { ShellsView } from './ShellsView'
import { WebShellsView } from './WebShellsView'
import { TaskLogView } from './TaskLogView'
import { AutomationView } from './AutomationView'
import { NotificationsView } from './NotificationsView'
import { TargetPictureView } from './TargetPictureView'
import { CredentialsBoardView } from './CredentialsBoardView'
import { LootBoardView } from './LootBoardView'
import { MembersView } from './MembersView'
import { ReconView } from './ReconView'
import { ReconAssetsView } from './ReconAssetsView'
import { ReconAssetDetailView } from './ReconAssetDetailView'
import { CampaignsView } from './CampaignsView'
import { CampaignDetailView } from './CampaignDetailView'

// The engagement detail body: the sub-surface named by the route only --
// navigation lives in the shell's sidebar (the seven slots) and the sub
// tab strip this view lays down -- and the live summary (connection
// state, fleet counts, operator presence) is published to the topbar
// through LiveContext. One SSE stream stays open so every connected
// operator sees tasking, results, and presence live; the stream's
// hello/leave events also drive the operator roster, and a monotonically
// increasing tick lets child views refresh without polling of their own.
// The online-implant roster (the presence query's projection: an implant
// is online exactly while its session is active) is fetched here and
// handed to the Implants view, on the live tick and a short
// reconciliation poll -- quiet heartbeats produce no SSE event, so the
// poll is what keeps a beaconing implant's last-seen moving.

export function EngagementView({
  engagementId,
  operator,
  sub,
  entityId,
  interact,
}: {
  engagementId: string
  operator: SessionOperator
  // The active sub-surface (slots.ts's vocabulary); the slot is implied
  // by it, so the view dispatch needs no slot prop.
  sub: SubId
  // An entity drill-in under the sub -- the implant id on the session
  // console and detail routes, the campaign and asset ids on their
  // detail pages.
  entityId?: string
  // True on the session console (`.../implants/{id}/interact`); false or
  // absent is the detail page.
  interact?: boolean
}) {
  const [online, setOnline] = useState<LiveOperator[]>([])
  const [connected, setConnected] = useState(false)
  // A monotonically increasing tick the SSE handlers bump on any tasking or
  // presence change; child views read it to refresh without polling.
  const [tick, setTick] = useState(0)
  const [chatOpen, setChatOpen] = useState(false)
  const [implantCount, setImplantCount] = useState(0)
  const [onlineImplants, setOnlineImplants] = useState<PresenceRecord[]>([])
  // Interaction ownership (architecture.md Sec 4.5): the engagement's held
  // claims and driving map, seeded by the hello frame and kept current by
  // the claim/activity events. The interact panes read them through the live
  // context to lock a surface another operator holds.
  const [claims, setClaims] = useState<ClaimSummary[]>([])
  const [driving, setDriving] = useState<DrivingEntry[]>([])
  const [error, setError] = useState<string | null>(null)
  // The fallback poll's cadence, set per browser in Settings.
  const pollMs = usePollIntervalMs()

  const refreshCount = useCallback(async () => {
    try {
      setImplantCount((await listImplants(engagementId)).length)
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }, [engagementId])

  useEffect(() => {
    void refreshCount()
  }, [refreshCount, tick])

  useEffect(() => {
    const close = subscribeToEngagement(engagementId, {
      onHello: (operators, heldClaims, drivingMap) => {
        setConnected(true)
        setOnline(operators)
        setClaims(heldClaims)
        setDriving(drivingMap)
      },
      onOperatorJoined: (id, handle) =>
        setOnline((current) =>
          current.some((o) => o.id === id) ? current : [...current, { id, handle }],
        ),
      onOperatorLeft: (id) => setOnline((current) => current.filter((o) => o.id !== id)),
      onClaimAcquired: (claim) =>
        setClaims((current) =>
          current.some((c) => c.kind === claim.kind && c.surfaceId === claim.surfaceId)
            ? current.map((c) => (c.kind === claim.kind && c.surfaceId === claim.surfaceId ? claim : c))
            : [...current, claim],
        ),
      onClaimReleased: (claim) =>
        setClaims((current) =>
          current.filter((c) => !(c.kind === claim.kind && c.surfaceId === claim.surfaceId)),
        ),
      onImplantActivity: (implantId, operatorId) =>
        setDriving((current) => {
          const at = new Date().toISOString()
          return current.some((d) => d.implantId === implantId)
            ? current.map((d) => (d.implantId === implantId ? { ...d, operatorId, at } : d))
            : [...current, { implantId, operatorId, at }]
        }),
      onError: () => setConnected(false),
      onTaskIssued: () => setTick((t) => t + 1),
      onTaskCompleted: () => setTick((t) => t + 1),
      onTaskCancelled: () => setTick((t) => t + 1),
      onSessionOpened: () => setTick((t) => t + 1),
      onSessionClosed: () => setTick((t) => t + 1),
      onShellSessionOpened: () => setTick((t) => t + 1),
      onShellSessionEnded: () => setTick((t) => t + 1),
      // A launcher credential was spent by an actual download: the kept
      // rows' budgets and the audit trail both move on it.
      onPayloadFetched: () => setTick((t) => t + 1),
      onCampaignActivity: () => setTick((t) => t + 1),
      // A comment or chat row moved: the mutable surfaces refetch on the
      // same beat everything else does.
      onCollaborationChange: () => setTick((t) => t + 1),
    })
    return close
  }, [engagementId])

  // A stale roster must never survive an engagement switch: clear it now and
  // let the fetch below repopulate for the new engagement.
  useEffect(() => {
    setOnlineImplants([])
  }, [engagementId])

  // The online-implant roster is refreshed on the live tick (SessionOpened
  // when an implant contacts, SessionClosed when its stream dies or is
  // swept) so the fleet counts move the moment the roster changes. A quiet
  // heartbeat -- an online implant simply beaconing on its cadence --
  // produces no SSE event, so the short poll below is also what keeps the
  // fleet's last-seen stamps moving between events, and it re-anchors the
  // roster to the server's view after a dropped SSE connection. One small
  // JSON read per operator every few seconds is nothing next to the SSE
  // stream already held open.
  useEffect(() => {
    let cancelled = false
    const refresh = async () => {
      try {
        const roster = await listOnline(engagementId)
        if (!cancelled) setOnlineImplants(roster)
      } catch {
        // Keep the last known roster; the next tick or poll retries.
      }
    }
    void refresh()
    const timer = window.setInterval(() => void refresh(), pollMs)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [engagementId, tick, pollMs])

  const live = useMemo(
    () => ({
      connected,
      operators: online,
      implantCount,
      onlineCount: onlineImplants.length,
      operatorId: operator.operatorId,
      claims,
      driving,
    }),
    [connected, online, implantCount, onlineImplants.length, operator.operatorId, claims, driving],
  )

  // The slot the active sub belongs to, and its sibling subs: the tab
  // strip this view lays down above the content.
  const slot = SLOTS.find((s) => s.subs.some((x) => x.id === sub)) ?? SLOTS[0]

  return (
    <LiveContext.Provider value={live}>
      {error && <p className="error">{error}</p>}
      {slot.subs.length > 1 && (
        <nav className="subnav" aria-label={`${slot.label} surfaces`}>
          {slot.subs.map((item) => (
            <a
              key={item.id}
              className={`subnav-item${item.id === sub ? ' active' : ''}`}
              href={engagementPath(engagementId, item.id)}
            >
              {item.label}
            </a>
          ))}
        </nav>
      )}
      {sub === 'timeline' && <TimelineView engagementId={engagementId} onlineTick={tick} />}
      {sub === 'picture' && <TargetPictureView engagementId={engagementId} onlineTick={tick} />}
      {sub === 'workbench' && <ReconView engagementId={engagementId} onlineTick={tick} />}
      {sub === 'assets' && entityId && (
        <ReconAssetDetailView engagementId={engagementId} assetId={entityId} onlineTick={tick} />
      )}
      {sub === 'assets' && !entityId && (
        <ReconAssetsView engagementId={engagementId} onlineTick={tick} />
      )}
      {sub === 'tasking' && <TaskLogView engagementId={engagementId} onlineTick={tick} />}
      {sub === 'automation' && <AutomationView engagementId={engagementId} onlineTick={tick} />}
      {sub === 'notifications' && (
        <NotificationsView engagementId={engagementId} onlineTick={tick} />
      )}
      {sub === 'members' && <MembersView engagementId={engagementId} operator={operator} />}
      {sub === 'implants' && entityId && interact && (
        <InteractView
          engagementId={engagementId}
          implantId={entityId}
          operator={operator}
          onlineTick={tick}
          onlineImplants={onlineImplants}
        />
      )}
      {sub === 'implants' && entityId && !interact && (
        <ImplantDetailView engagementId={engagementId} implantId={entityId} onlineTick={tick} />
      )}
      {sub === 'implants' && !entityId && (
        <ImplantsView engagementId={engagementId} onlineTick={tick} onlineImplants={onlineImplants} />
      )}
      {sub === 'campaigns' && entityId && (
        <CampaignDetailView engagementId={engagementId} campaignId={entityId} onlineTick={tick} />
      )}
      {sub === 'campaigns' && !entityId && (
        <CampaignsView engagementId={engagementId} onlineTick={tick} />
      )}
      {sub === 'shells' && <ShellsView engagementId={engagementId} onlineTick={tick} />}
      {sub === 'webshells' && <WebShellsView engagementId={engagementId} onlineTick={tick} />}
      {sub === 'audit' && <AuditView engagementId={engagementId} onlineTick={tick} />}
      {sub === 'evidence' && <ReportView engagementId={engagementId} />}
      {sub === 'listeners' && <ListenersView engagementId={engagementId} />}
      {sub === 'launchers' && <LaunchersView engagementId={engagementId} onlineTick={tick} />}
      {sub === 'build' && <PayloadBuildView engagementId={engagementId} />}
      {sub === 'payloads' && <PayloadsView engagementId={engagementId} onlineTick={tick} />}
      {sub === 'credentials' && (
        <CredentialsBoardView engagementId={engagementId} onlineTick={tick} />
      )}
      {sub === 'loot' && <LootBoardView engagementId={engagementId} onlineTick={tick} />}
      <button
        className={chatOpen ? 'ghost sm chat-toggle active' : 'ghost sm chat-toggle'}
        title={chatOpen ? 'Close the watch channel' : 'Open the watch channel'}
        onClick={() => setChatOpen((v) => !v)}
      >
        Chat
      </button>
      {chatOpen && (
        <ChatPanel engagementId={engagementId} tick={tick} onClose={() => setChatOpen(false)} />
      )}
    </LiveContext.Provider>
  )
}
