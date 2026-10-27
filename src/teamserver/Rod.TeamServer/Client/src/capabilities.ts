// Capability-catalog helpers. The operator UI groups verbs by
// category and surfaces each verb's OPSEC attributes as risk badges. The catalog
// is data-driven from GET /capabilities (the registry), so this module only
// knows the category/attribute *labels* -- the verbs themselves arrive from the
// server, never hardcoded here.

import { type CapabilityDescriptor, listCapabilities } from './api'

// Canonical category order for display: core baseline first, then the offensive
// lifecycle (recon -> lateral -> persist -> collect -> exfil), then tunneling,
// then the browser hook set, then the two sensitive contract categories last.
// Categories returned by the server but not listed here fall through to the
// end in their natural order.
const CATEGORY_ORDER: readonly string[] = [
  'Core',
  'Recon',
  'Lateral',
  'Persist',
  'Collect',
  'Exfil',
  'Tunnel',
  'Browser',
  'Evasion',
  'Exploit',
]

function categoryRank(category: string): number {
  const index = CATEGORY_ORDER.indexOf(category)
  return index === -1 ? CATEGORY_ORDER.length : index
}

// A short human label for each category, shown as the group heading in the
// capability picker. Falls back to the raw enum name for anything unexpected.
const CATEGORY_LABELS: Record<string, string> = {
  Core: 'Core',
  Recon: 'Reconnaissance',
  Lateral: 'Lateral movement',
  Persist: 'Persistence',
  Collect: 'Collection',
  Exfil: 'Exfiltration',
  Tunnel: 'Tunneling',
  Browser: 'Browser hook',
  Evasion: 'Evasion (contract)',
  Exploit: 'Exploit (contract)',
}

function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category] ?? category
}

export interface CapabilityGroup {
  category: string
  label: string
  descriptors: CapabilityDescriptor[]
}

// Groups the catalog into ordered categories for the picker. Stable within a
// group by verb (alphabetical) so the list does not reshuffle on re-fetch.
function groupByCategory(descriptors: CapabilityDescriptor[]): CapabilityGroup[] {
  const buckets = new Map<string, CapabilityDescriptor[]>()
  for (const d of descriptors) {
    const list = buckets.get(d.category) ?? []
    list.push(d)
    buckets.set(d.category, list)
  }
  for (const list of buckets.values()) {
    list.sort((a, b) => a.verb.localeCompare(b.verb))
  }
  return [...buckets.entries()]
    .sort((a, b) => categoryRank(a[0]) - categoryRank(b[0]))
    .map(([category, items]) => ({ category, label: categoryLabel(category), descriptors: items }))
}

// OPSEC attribute metadata. The server sets free-form key/value flags on each
// descriptor (architecture.md Sec 7); this maps the known flags to a short label
// and a severity, so the picker can badge risky actions consistently. Unknown
// attributes still render, using the raw key.
export interface OpsecAttributeMeta {
  key: string
  label: string
  risk: 'low' | 'medium' | 'high'
}

const KNOWN_ATTRIBUTES: Record<string, OpsecAttributeMeta> = {
  'touches-network': { key: 'touches-network', label: 'network', risk: 'medium' },
  'derives-child': { key: 'derives-child', label: 'child implant', risk: 'high' },
  'touches-credential': { key: 'touches-credential', label: 'credential', risk: 'high' },
  'writes-to-disk': { key: 'writes-to-disk', label: 'writes disk', risk: 'medium' },
  'persists': { key: 'persists', label: 'persists', risk: 'high' },
  'reads-filesystem': { key: 'reads-filesystem', label: 'reads fs', risk: 'low' },
  'reads-credential': { key: 'reads-credential', label: 'reads cred', risk: 'high' },
  'reads-input': { key: 'reads-input', label: 'reads input', risk: 'high' },
  'modifies-defenses': { key: 'modifies-defenses', label: 'modifies defenses', risk: 'high' },
  'exploits-target': { key: 'exploits-target', label: 'exploits target', risk: 'high' },
}

export function attributeMeta(key: string): OpsecAttributeMeta {
  return KNOWN_ATTRIBUTES[key] ?? { key, label: key, risk: 'low' }
}

// Loads and groups the catalog in one call; the views consume the grouped shape.
export async function loadCapabilityGroups(): Promise<CapabilityGroup[]> {
  return groupByCategory(await listCapabilities())
}

// Folds the grouped catalog into a verb -> attributes map, the lookup the
// task dialogs and automation panel share to badge a picked verb.
export function verbAttributes(groups: readonly CapabilityGroup[]): Map<string, Record<string, string>> {
  const map = new Map<string, Record<string, string>>()
  for (const group of groups) {
    for (const descriptor of group.descriptors) {
      map.set(descriptor.verb, descriptor.attributes)
    }
  }
  return map
}

// The wire-capability coverage mirror (ADR-017's runtime half): each tier's
// task-path face is the verb whose reference handler carries its frames, so
// advertising the verb claims the capability. The server's WireCapabilities
// (Rod.CoreState) is the authority this mirrors -- the server still refuses
// anything this table gets wrong, exactly like the class-verb mirror above.
const COVERING_VERB: Record<string, string> = {
  'plugin-loader': 'module.load',
  'exfil-chunks': 'file.pull',
  'staged-uploads': 'file.push',
}

export function coversRequirement(advertised: readonly string[], name: string): boolean {
  const verb = COVERING_VERB[name]
  return !!verb && advertised.some((held) => held.toLowerCase() === verb)
}

// A session's loadable plugin set: the catalog's named modules whose
// requirement rows the session's handshake advertisement covers. A module
// that declares nothing loads anywhere; an unnamed catalog entry is a
// placeholder, not a plugin, and never lists.
export interface LoadableModule {
  module: string
  verb: string
  requires: string[]
  covered: boolean
  missing: string[]
}

export function loadableModules(
  descriptors: readonly CapabilityDescriptor[],
  advertised: readonly string[],
): LoadableModule[] {
  const modules: LoadableModule[] = []
  for (const descriptor of descriptors) {
    if (!descriptor.module) continue
    const requires = descriptor.requires ?? []
    const missing = requires.filter((name) => !coversRequirement(advertised, name))
    modules.push({ module: descriptor.module, verb: descriptor.verb, requires, covered: missing.length === 0, missing })
  }
  return modules.sort((a, b) => a.module.localeCompare(b.module))
}
