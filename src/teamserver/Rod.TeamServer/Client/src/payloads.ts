// Payload-library reads shared by the surfaces that pick one to deliver:
// whether a build's baked enrollment credential still lives, and the label a
// picker entry reads by. Extracted from the Launchers view when the shell
// console's upgrade grew the same picker.

import type { PayloadSummary } from './api'

// Whether a payload's baked enrollment credential still lives: the render
// refuses a dead one (revoked, spent, or expired -- the fetched artifact
// could never enroll), so the picker says so instead of letting the submit
// discover it. A credential-free build rides: it is the manual-mint shape
// with its own delivery story.
export function deliverable(p: PayloadSummary): boolean {
  if (!p.tokenId) return true
  if (p.tokenMaxUses === 0) {
    return p.tokenExpiresAt == null
      || new Date(p.tokenExpiresAt).getTime() > Date.now()
  }
  return (
    p.tokenRemainingUses != null
    && p.tokenRemainingUses > 0
    && (p.tokenExpiresAt == null || new Date(p.tokenExpiresAt).getTime() > Date.now())
  )
}

export function payloadLabel(p: PayloadSummary): string {
  const target = p.target ?? p.unitId
  return [
    // The wire class reads as noise for the only implant class there is;
    // the other kinds (a web-shell script) still stand out.
    p.class === 'Implant' ? null : p.class,
    target,
    // The library's own identifier, at the same width the Payloads tab's
    // Fingerprint column shows, so a picker entry matches its row there.
    p.fingerprint ? p.fingerprint.slice(0, 16) : null,
    new Date(p.builtAt).toLocaleString(),
  ]
    .filter(Boolean)
    .join(' · ')
}
