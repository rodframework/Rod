// Sidebar navigation for an engagement: the seven lifecycle slots
// (architecture.md Sec 15.4, ADR-013). Slot ids are hash route segments,
// so items are plain anchors: deep links, keyboard navigation, and
// middle-click all work through the shell's hashchange listener with no
// extra handler here. A slot's sub-surfaces are the content area's own
// tab strip, not the sidebar's -- the sidebar promises a working mode,
// never a screen list. Definitions live in slots.ts.

import { Icon } from './Icons'
import { SLOTS, engagementPath, type SlotId } from '../slots'

export function EngagementNav({
  engagementId,
  active,
}: {
  engagementId: string
  active: SlotId
}) {
  return (
    <div className="nav-group">
      {SLOTS.map((slot) => (
        <a
          key={slot.id}
          className={`nav-item${slot.id === active ? ' active' : ''}`}
          href={engagementPath(engagementId, slot.subs[0].id)}
          title={slot.label}
        >
          <Icon name={slot.icon} />
          <span className="label">{slot.label}</span>
        </a>
      ))}
    </div>
  )
}
