import { Icon } from './Icons'
import type { RelatedGroup } from '../related'

// The related-entities sidebar (architecture.md Sec 15.4, ADR-013):
// every entity detail page carries one. Pure presentation over the
// link groups the builders in related.ts fold from the entity model's
// explicit foreign keys -- the panel knows nothing about which entity it
// hangs beside, so a new domain's links render the day its detail page
// does. Groups with no links are the caller's call: builders omit them,
// and an empty group list reads as the honest "nothing links here yet".

export function RelatedEntities({ groups }: { groups: RelatedGroup[] }) {
  if (groups.length === 0) {
    return <p className="muted related-empty">No related entities yet.</p>
  }
  return (
    <div className="related">
      {groups.map((group) => (
        <div className="related-group" key={group.label}>
          <div className="related-group-label">{group.label}</div>
          {group.links.map((link) => (
            <a className="related-link" key={link.key} href={link.hash} title={link.subtitle}>
              <Icon name="chevronRight" className="wire-icon" />
              <span className="related-link-body">
                <span className="related-link-title">{link.title}</span>
                {link.subtitle && <span className="related-link-subtitle">{link.subtitle}</span>}
              </span>
            </a>
          ))}
        </div>
      ))}
    </div>
  )
}
