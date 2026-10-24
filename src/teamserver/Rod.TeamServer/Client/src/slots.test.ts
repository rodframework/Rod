// The seven-slot navigation's acceptance (architecture.md Sec 15.4,
// ADR-013): the slot list is exactly the seven lifecycle slots, every
// sub id names one slot (links build from a sub alone), and every
// pre-slot tab id -- plus the two feed tabs retired before the slots --
// resolves to a live surface, so stale deep links land on the work.

import { describe, expect, it } from 'vitest'
import {
  LEGACY_TAB_ROUTES,
  SLOTS,
  engagementPath,
  resolveEngagementLocation,
  slotOf,
  subOf,
} from './slots'

describe('slot vocabulary', () => {
  it('holds exactly the seven lifecycle slots, in lived order', () => {
    expect(SLOTS.map((s) => s.id)).toEqual([
      'overview',
      'recon',
      'delivery',
      'action',
      'assets',
      'report',
      'admin',
    ])
  })

  it('gives every slot at least one sub and lands the slot on its first', () => {
    for (const slot of SLOTS) {
      expect(slot.subs.length).toBeGreaterThan(0)
      expect(resolveEngagementLocation({ slot: slot.id }).sub.id).toBe(slot.subs[0].id)
    }
  })

  it('never repeats a sub id across slots, so a sub alone names its path', () => {
    const ids = SLOTS.flatMap((s) => s.subs.map((x) => x.id))
    expect(new Set(ids).size).toBe(ids.length)
  })
})

describe('engagementPath', () => {
  it('builds slot/sub paths, entity drill-ins, and the interact console', () => {
    expect(engagementPath('e', 'implants')).toBe('#/engagements/e/action/implants')
    expect(engagementPath('e', 'timeline')).toBe('#/engagements/e/overview/timeline')
    expect(engagementPath('e', 'campaigns', 'c1')).toBe('#/engagements/e/delivery/campaigns/c1')
    expect(engagementPath('e', 'implants', 'i1', 'interact')).toBe(
      '#/engagements/e/action/implants/i1/interact',
    )
  })
})

describe('route resolution', () => {
  it('resolves a slot to its landing sub', () => {
    const loc = resolveEngagementLocation({ slot: 'delivery' })
    expect(loc.slot.id).toBe('delivery')
    expect(loc.sub.id).toBe('listeners')
  })

  it('resolves a sub under its slot', () => {
    const loc = resolveEngagementLocation({ slot: 'recon', sub: 'assets' })
    expect(loc.sub.id).toBe('assets')
  })

  it('resolves an entity drill-in and drops it under an unknown sub', () => {
    expect(resolveEngagementLocation({ slot: 'action', sub: 'implants', entityId: 'i' }).entityId).toBe('i')
    expect(resolveEngagementLocation({ slot: 'action', sub: 'nope', entityId: 'i' }).entityId).toBeUndefined()
    expect(resolveEngagementLocation({ slot: 'action', sub: 'nope' }).sub.id).toBe('implants')
  })

  it('falls unknown slots to the timeline', () => {
    const loc = resolveEngagementLocation({ slot: 'gibberish' })
    expect(loc.slot.id).toBe('overview')
    expect(loc.sub.id).toBe('timeline')
  })

  it('lands every legacy tab on a live sub', () => {
    for (const [tab, target] of Object.entries(LEGACY_TAB_ROUTES)) {
      const loc = resolveEngagementLocation({ slot: tab })
      expect(loc.sub.id, `legacy tab ${tab}`).toBe(target.sub)
      // The destination must be a real sub of a real slot.
      expect(slotOf(loc.slot.id)).not.toBeNull()
      expect(subOf(loc.slot, target.sub)).not.toBeNull()
    }
  })

  it('maps the fourteen non-colliding pre-slot tabs onto the slots', () => {
    // `recon` and `report` are absent by design: those ids became slot
    // ids, so their hashes resolve as the slot and land on its first sub.
    expect(LEGACY_TAB_ROUTES).toMatchObject({
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
    })
  })
})
