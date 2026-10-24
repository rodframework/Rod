// Engagement navigation: the seven lifecycle slots (architecture.md
// Sec 15.4, ADR-013) and the sub-surfaces each slot holds. Lives in a
// plain module (not the Nav component file) so the component file holds
// only components and stays fast-refresh clean.
//
// The slots are a scarce resource, fixed at seven: overview / recon /
// delivery / action / assets / report / admin. A new domain answers
// *which slot it enters* before it exists -- it never adds an eighth
// entry here. Inside a slot, sub-surfaces are cheap: the slot is the
// navigation promise (one working mode), the subs are how that mode's
// screens are arranged. Sub ids are stable route segments (deep links
// keep working); labels and order are presentation.

import type { IconName } from './components/Icons'

export type SlotId = 'overview' | 'recon' | 'delivery' | 'action' | 'assets' | 'report' | 'admin'

export type SubId =
  | 'timeline'
  | 'workbench'
  | 'assets'
  | 'picture'
  | 'listeners'
  | 'launchers'
  | 'campaigns'
  | 'shells'
  | 'webshells'
  | 'build'
  | 'implants'
  | 'tasking'
  | 'automation'
  | 'credentials'
  | 'loot'
  | 'payloads'
  | 'audit'
  | 'evidence'
  | 'members'
  | 'notifications'

export interface SubDef {
  id: SubId
  label: string
  icon: IconName
}

export interface SlotDef {
  id: SlotId
  label: string
  icon: IconName
  // The first sub is the slot's landing surface when the hash names the
  // slot alone.
  subs: readonly SubDef[]
}

// The engagement in the order it is lived. Overview leads: the timeline
// is the main screen -- the audited event stream everything else writes
// into, where an operator lands to see what moved. Recon holds the
// pre-foothold working mode: the workbench that extends the picture, the
// recon assets selected as campaign targets, and the target picture
// itself. Delivery is the initial-access working set -- the listeners
// that front it, the one-liners, the tracked-lure campaigns, the caught
// and placed shells, and the build factory that arms each. Action is
// post-foothold: the implant fleet with its consoles, the task log, and
// the rule engine that fires the same verbs unattended. Assets is what
// the engagement holds -- the harvest (credentials), the exfil board
// (loot), and the durable payload library. Report closes the record:
// the audit ledger and the evidence bundle. Admin tends the engagement
// itself: the crew roster and the out-of-band channels.
export const SLOTS: readonly SlotDef[] = [
  { id: 'overview', label: 'Overview', icon: 'activity', subs: [{ id: 'timeline', label: 'Timeline', icon: 'activity' }] },
  {
    id: 'recon',
    label: 'Recon',
    icon: 'search',
    subs: [
      { id: 'picture', label: 'Target picture', icon: 'globe' },
      { id: 'workbench', label: 'Workbench', icon: 'search' },
      { id: 'assets', label: 'Recon assets', icon: 'target' },
    ],
  },
  {
    id: 'delivery',
    label: 'Delivery',
    icon: 'send',
    subs: [
      { id: 'listeners', label: 'Listeners', icon: 'radio' },
      { id: 'launchers', label: 'Launchers', icon: 'copy' },
      { id: 'campaigns', label: 'Campaigns', icon: 'send' },
      { id: 'shells', label: 'Shells', icon: 'terminal' },
      { id: 'webshells', label: 'Web shells', icon: 'globe' },
      { id: 'build', label: 'Build', icon: 'package' },
    ],
  },
  {
    id: 'action',
    label: 'Action',
    icon: 'terminal',
    subs: [
      { id: 'implants', label: 'Implants', icon: 'cpu' },
      { id: 'tasking', label: 'Task log', icon: 'inbox' },
      { id: 'automation', label: 'Automation', icon: 'clock' },
    ],
  },
  {
    id: 'assets',
    label: 'Assets',
    icon: 'archive',
    subs: [
      { id: 'credentials', label: 'Credentials', icon: 'file' },
      { id: 'loot', label: 'Loot', icon: 'folder' },
      { id: 'payloads', label: 'Payloads', icon: 'package' },
    ],
  },
  {
    id: 'report',
    label: 'Report',
    icon: 'file',
    subs: [
      { id: 'audit', label: 'Audit ledger', icon: 'list' },
      { id: 'evidence', label: 'Report', icon: 'file' },
    ],
  },
  {
    id: 'admin',
    label: 'Admin',
    icon: 'users',
    subs: [
      { id: 'members', label: 'Members', icon: 'users' },
      { id: 'notifications', label: 'Notifications', icon: 'bell' },
    ],
  },
]

export function slotOf(slot: string): SlotDef | null {
  return SLOTS.find((s) => s.id === slot) ?? null
}

export function subOf(slot: SlotDef, sub: string): SubDef | null {
  return slot.subs.find((s) => s.id === sub) ?? null
}

// Every sub id names its slot (sub ids are unique across slots), so a
// sub alone is enough to build a link -- callers never repeat the slot.
const SUB_SLOT: ReadonlyMap<SubId, SlotDef> = new Map(
  SLOTS.flatMap((slot) => slot.subs.map((sub) => [sub.id, slot])),
)

// The engagement hash for a sub-surface, with optional drill-ins: an
// entity detail page, and the session console behind an implant detail
// (`.../implants/{id}/interact`).
export function engagementPath(engagementId: string, sub: SubId, entityId?: string, tail?: 'interact'): string {
  const slot = SUB_SLOT.get(sub)
  if (!slot) return `#/engagements/${engagementId}`
  let path = `#/engagements/${engagementId}/${slot.id}/${sub}`
  if (entityId) path += `/${entityId}`
  if (entityId && tail) path += `/${tail}`
  return path
}

// The pre-slot tab vocabulary, retired when the slots landed. Stale deep
// links resolve through this map instead of the fallback, so a bookmark
// lands on the work, not on the overview. Two feed-shaped tabs retired
// earlier ride the same map: the handoff digest is the Audit ledger's
// window mode, and task artifacts surface in the task log's expanded
// rows. Two old tabs (`recon`, `report`) have no entry: their ids became
// slot ids, so those hashes resolve as the slot itself and land on its
// first sub -- one sub away from the old surface, inside the right slot.
export const LEGACY_TAB_ROUTES: Readonly<Record<string, { sub: SubId }>> = {
  intel: { sub: 'picture' },
  implants: { sub: 'implants' },
  shells: { sub: 'shells' },
  webshells: { sub: 'webshells' },
  tasking: { sub: 'tasking' },
  automation: { sub: 'automation' },
  listeners: { sub: 'listeners' },
  launchers: { sub: 'launchers' },
  campaigns: { sub: 'campaigns' },
  build: { sub: 'build' },
  payloads: { sub: 'payloads' },
  members: { sub: 'members' },
  notifications: { sub: 'notifications' },
  audit: { sub: 'audit' },
  // Retired before the slots: surfaces that folded into their neighbors.
  artifacts: { sub: 'tasking' },
  digest: { sub: 'audit' },
}

// Where a route's segments land once every legacy shape is resolved:
// the slot, the sub (the slot's landing sub when the hash stopped at
// the slot), and any entity drill-in. Unknown slots and subs fall back
// to the timeline -- the orienting surface -- rather than guessing.
export interface EngagementLocation {
  slot: SlotDef
  sub: SubDef
  entityId?: string
  interact?: boolean
}

export function resolveEngagementLocation(segments: {
  slot: string
  sub?: string
  entityId?: string
  interact?: boolean
}): EngagementLocation {
  const slot = slotOf(segments.slot)
  const legacy = slot ? null : LEGACY_TAB_ROUTES[segments.slot]
  // Where the segments land: a valid slot keeps its named sub (or its
  // landing sub); a legacy tab lands on its mapped sub; anything else
  // falls to the timeline.
  const target = legacy ? (SUB_SLOT.get(legacy.sub) ?? SLOTS[0]) : (slot ?? SLOTS[0])
  const named = slot && segments.sub ? subOf(slot, segments.sub) : null
  const sub = named ?? (legacy ? subOf(target, legacy.sub) : null) ?? target.subs[0]
  return {
    slot: target,
    sub,
    // A stale sub under a resolved slot drops the drill-in: an entity id
    // that names no surface here belongs to no page.
    entityId: named ? segments.entityId : undefined,
    interact: named ? segments.interact : undefined,
  }
}
