// Thin typed wrappers over the teamserver operator HTTP API
// (Rod.Transport/Endpoints). The browser UI talks to the same JSON endpoints
// the implant and operator layers do; the host serves this bundle from wwwroot
// so the calls are same-origin in production and proxied to :59443 in dev.

export interface RoeProfile {
  permittedVerbs: string[]
  permittedImplants: string[]
  // Exact hostnames (case-folded), exact IPs, or CIDR blocks; empty = unrestricted.
  // Gates the recon workbench's scan, never tasking.
  permittedTargets: string[]
}

// The close-out state rides on timestamps: null while the engagement is open,
// frozenAt set once the close-out starts (no new tasking or deployments),
// retiredAt set when it completes -- terminal, the record sealed.
export interface Engagement {
  engagementId: string
  name: string
  description: string | null
  ownerId: string
  ownerHandle: string
  // The caller's standing on this engagement (owner / writer / reader); null
  // on responses that do not carry it.
  yourRole: string | null
  createdAt: string
  roe: RoeProfile
  frozenAt: string | null
  retiredAt: string | null
  // The landing roster's fleet posture, carried by the list response: active
  // (non-retired) implants and how many hold a live session. Null on the
  // create and edit responses, which do not size the fleet.
  summary: { implantCount: number; onlineCount: number } | null
}

export interface Implant {
  implantId: string
  engagementId: string
  class: string
  // The artifact's time fuse as reported at enroll; null = open-ended (no
  // fuse -- the implant runs until retired).
  killDate: string | null
  createdAt: string
  isOnline: boolean
  retiredAt: string | null
  parentImplantId: string | null
  // The device identity the implant reported at enroll -- what the fleet
  // groups rows by. Null when the enrolling client predated the field.
  hostname: string | null
  os: string | null
  arch: string | null
  username: string | null
  // The contact cadence the implant last advertised, in seconds: the base
  // sleep and the jitter half-width. Set at enroll (the baked profile) and
  // refreshed by every changed handshake advertisement, so a beacon.sleep
  // retune lands here at the next contact. Null on either half = not
  // reported.
  sleepSeconds: number | null
  jitterSeconds: number | null
  // The operator the implant's events attribute to (the token issuer) --
  // who deployed this beacon.
  deployedBy: string | null
  // The listener whose socket carried the enrollment, when the transport
  // could attribute one -- what a listener-deletion warning counts against.
  enrolledViaListenerId: string | null
  // The durable heartbeat: when the teamserver last heard from this implant,
  // kept after the session is gone. Null when it never contacted past enroll.
  lastSeenAt: string | null
  // The carrier the live session's last contact rode (the degraded-mode
  // vocabulary: web, dns, pipe); 'dns' is the constrained
  // carrier. Null while offline or when no contact recorded one.
  lastCarrier: string | null
  // The baked carrier set the artifact's endpoints dial; null when the
  // enroll derived none.
  carriers: string[] | null
  // The delivery campaign whose lure this implant followed (Sec 11.5):
  // the campaign and the recipient row, null pair on every ordinary
  // enrollment.
  campaignId: string | null
  campaignRecipientId: string | null
}

export interface Task {
  taskId: string
  engagementId: string
  implantId: string
  issuedBy: string
  verb: string
  arguments: string
  // Absent on the issue response -- a freshly issued task is queued by
  // construction, so the server does not say it -- and present on task
  // detail reads. Callers that need the state read getTask or track the
  // task themselves.
  status?: string
  output?: string | null
  outcome?: string | null
  createdAt: string
  dispatchedAt: string | null
  completedAt: string | null
}

export interface Problem {
  error: string
}

// The session cookie expired or was revoked mid-use. The shell listens for the
// unauthorized event and returns to the login view; a view's inline error text
// is not enough when every subsequent call will 401.
class SessionExpiredError extends Error {}

function notifySessionExpired(): void {
  window.dispatchEvent(new Event('rod-unauthorized'))
}

// A refused request with its status attached, so callers can branch on the
// server's verdict (the listener-delete guard's 409) instead of parsing the
// message text.
export class ApiError extends Error {
  readonly status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

async function jsonOrThrow<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const body = (await response.json()) as Problem
      if (body?.error) detail = body.error
    } catch {
      // Non-JSON error body; keep the status text.
    }
    if (response.status === 401) {
      notifySessionExpired()
      throw new SessionExpiredError(detail)
    }
    throw new ApiError(detail, response.status)
  }
  // A 204 (and any empty body) carries nothing to parse -- the delete routes
  // answer that way, and json() on an empty body would turn success into a
  // parse error. Callers expecting void read undefined.
  if (response.status === 204) {
    return undefined as T
  }
  const text = await response.text()
  return (text === '' ? undefined : JSON.parse(text)) as T
}

// --- Operator session (architecture.md Sec 4) --------------------------------
//
// The browser session is established by verified credentials, not a client-
// generated id: POST /operators/login sets the auth cookie, GET /operators/me
// reads the server-recorded operator back, and POST /operators/logout clears it.
// Every other call in this module relies on that cookie; an unauthenticated
// browser gets 401 and the UI shows the login view. This replaces the walking
// skeleton's self-assigned identity.

export interface SessionOperator {
  operatorId: string
  handle: string
  // When the account was provisioned -- the account card's "member since".
  createdAt: string
  // The deployment role the account holds: 'admin' (the bootstrap seed --
  // deployment management) or 'member' (console-created -- self-service
  // over its own password and tokens). The console gates its management
  // surfaces on it; what the operator may reach inside an engagement is
  // decided there by memberships, not here.
  role: 'admin' | 'member'
}

export interface LoginInput {
  handle: string
  password: string
}

export async function login(input: LoginInput): Promise<void> {
  const response = await fetch('operators/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  })
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`)
  }
}

export async function logout(): Promise<void> {
  await fetch('operators/logout', { method: 'POST' })
}

// Resolves the authenticated operator off the session cookie. Throws on 401 so
// the route guard can fall back to the login view.
export async function getSessionOperator(): Promise<SessionOperator> {
  const response = await fetch('operators/me')
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`)
  }
  const body = (await response.json()) as {
    id: string
    handle: string
    createdAt: string
    role: 'admin' | 'member'
  }
  return {
    operatorId: body.id,
    handle: body.handle,
    createdAt: body.createdAt,
    role: body.role,
  }
}

// --- Operator roster (the account machinery) ---------------------------------
//
// The provisioned accounts beside the session's own: GET /operators lists the
// roster (every account, whether a password stands behind it -- the
// deployment admin's read; a member's account surface is /operators/me),
// POST /operators provisions a new one with its initial password (the
// deployment admin's alone; the account comes up as a member), and
// PUT /operators/{id}/credentials re-provisions a password (self-service on
// the caller's own account, admin-only on anyone else's -- the server
// enforces both, drawing 403 where the session's role does not reach).

export interface OperatorAccount {
  id: string
  handle: string
  createdAt: string
  // 'admin' (the bootstrap seed) or 'member' (console-created): the one
  // deployment-level privilege the account holds.
  role: 'admin' | 'member'
  // False after credential revocation: the account exists but no password
  // verifies, so it cannot log in until re-provisioned.
  hasCredential: boolean
  // True while the account is switched off: no authentication path accepts
  // it (login, cookie session, API token), and its memberships wait as they
  // were, so an enable restores exactly the reach it had.
  disabled: boolean
}

export interface CreateOperatorInput {
  handle: string
  password: string
}

export async function listOperators(): Promise<OperatorAccount[]> {
  return jsonOrThrow(await fetch('operators'))
}

export async function createOperator(input: CreateOperatorInput): Promise<OperatorAccount> {
  const response = await fetch('operators', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  })
  return jsonOrThrow<OperatorAccount>(response)
}

// A reset is a new credential generation: the target's live sessions end at
// their next request. Resetting your own password signs this session out too.
// Self-service proves possession: the current password is required when the
// caller acts on its own account; an admin resetting another account omits it.
export async function setOperatorPassword(
  operatorId: string,
  password: string,
  currentPassword?: string,
): Promise<void> {
  jsonOrThrow(
    await fetch(`operators/${operatorId}/credentials`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password, ...(currentPassword !== undefined && { currentPassword }) }),
    }),
  )
}

export interface OperatorTokenRow {
  tokenId: string
  scope: string
  createdAt: string
}

// The one-time bearer secret. It is shown exactly once, at mint; only the
// digest is stored afterwards, so a closed panel cannot bring it back. The
// scope names the capability floor the credential is capped at (read /
// operate / admin); absent a choice the mint is read-scoped.
export interface MintedOperatorToken {
  tokenId: string
  scope: string
  token: string
  createdAt: string
}

// The account off switch and its restore (the deployment admin's alone).
// Disabling ends every authentication path for the account at its next use;
// enabling reopens them with the memberships the account kept. Disabling
// the last enabled account -- or the last enabled admin -- refuses with a
// 409.
export async function disableOperator(operatorId: string): Promise<void> {
  jsonOrThrow(await fetch(`operators/${operatorId}:disable`, { method: 'POST' }))
}

export async function enableOperator(operatorId: string): Promise<void> {
  jsonOrThrow(await fetch(`operators/${operatorId}:enable`, { method: 'POST' }))
}

// API-token management, per account: mint returns the bearer secret exactly
// once, list reads identity-and-lifetime rows (never the secret), and
// revocation takes effect at the token's next use. A disabled account's
// tokens refuse until it is enabled again.
export async function listOperatorTokens(operatorId: string): Promise<OperatorTokenRow[]> {
  return jsonOrThrow(await fetch(`operators/${operatorId}/tokens`))
}

export async function mintOperatorToken(operatorId: string, scope: string): Promise<MintedOperatorToken> {
  const response = await fetch(`operators/${operatorId}/tokens`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scope }),
  })
  return jsonOrThrow<MintedOperatorToken>(response)
}

export async function revokeOperatorToken(operatorId: string, tokenId: string): Promise<void> {
  jsonOrThrow(await fetch(`operators/${operatorId}/tokens/${tokenId}:revoke`, { method: 'POST' }))
}

// --- Engagement members (the membership model, architecture.md Sec 3) ------
//
// An engagement's reach is its member roster: the owner grants, re-tiers,
// and removes. Every console holding a membership reads the roster; the
// mutations are the owner's alone (the server refuses with 403 otherwise).

export interface EngagementMember {
  operatorId: string
  handle: string
  // owner / writer / reader -- the owner row renders beside the members.
  role: string
  addedAt: string
}

export async function listMembers(engagementId: string): Promise<EngagementMember[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/members`))
}

// The invite names a handle (the shared vocabulary) and the granted tier.
export async function addMember(
  engagementId: string,
  handle: string,
  role: 'reader' | 'writer',
): Promise<EngagementMember> {
  const response = await fetch(`engagements/${engagementId}/members`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ handle, role }),
  })
  return jsonOrThrow<EngagementMember>(response)
}

export async function setMemberRole(
  engagementId: string,
  operatorId: string,
  role: 'reader' | 'writer',
): Promise<EngagementMember> {
  const response = await fetch(`engagements/${engagementId}/members/${operatorId}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ role }),
  })
  return jsonOrThrow<EngagementMember>(response)
}

export async function removeMember(engagementId: string, operatorId: string): Promise<void> {
  jsonOrThrow(await fetch(`engagements/${engagementId}/members/${operatorId}`, { method: 'DELETE' }))
}

export interface CreateEngagementInput {
  name: string
  description?: string
}

export async function listEngagements(): Promise<Engagement[]> {
  return jsonOrThrow(await fetch('engagements'))
}

// Roster mutations announce themselves (the same window-event pattern as
// rod-unauthorized) so the shell's engagement surfaces -- the sidebar's
// recent quick-jump and the breadcrumb's name cache -- re-read on the spot
// instead of waiting for a full reload.
function announceEngagementRosterChange(): void {
  window.dispatchEvent(new Event('rod-engagements-changed'))
}

export async function createEngagement(input: CreateEngagementInput): Promise<Engagement> {
  const response = await fetch('engagements', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  })
  const created = jsonOrThrow<Engagement>(response)
  announceEngagementRosterChange()
  return created
}

// The leak answer, above all for a credential baked into a deployed artifact:
// the id stops working at the next redeem or verify. Idempotent-refusing -- a
// second attempt 404s rather than reading as success.
export async function revokeDeployToken(engagementId: string, tokenId: string): Promise<void> {
  const response = await fetch(`engagements/${engagementId}/deploy-tokens/${tokenId}:revoke`, {
    method: 'POST',
  })
  await jsonOrThrow<unknown>(response)
}

// A hand-minted deployment credential: the same token shape a build bakes,
// minted standalone for hand delivery -- a launcher one-liner aimed at an
// operator-run edge, a drop, a scripted enrollment. A body-less post keeps
// the single-use, one-hour default; the two knobs bound a batch window
// (maxUses 1..10000, lifetimeSeconds 60..2592000). The secret returns once
// and only once -- the trail records the mint, never the secret.
export interface MintedDeployToken {
  tokenId: string
  engagementId: string
  secret: string
  issuedBy: string
  issuedAt: string
  expiresAt: string
  maxUses: number
}

export async function mintDeployToken(
  engagementId: string,
  input?: { maxUses?: number; lifetimeSeconds?: number },
): Promise<MintedDeployToken> {
  const body = input ? JSON.stringify(input) : undefined
  const response = await fetch(`engagements/${engagementId}/deploy-tokens`, {
    method: 'POST',
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body,
  })
  return jsonOrThrow(response)
}

export async function listImplants(engagementId: string): Promise<Implant[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/implants`))
}

// --- Implant provenance (architecture.md Sec 15.4, the unified entity
// model) -----------------------------------------------------------
//
// The detail read's second half: the chain around one implant -- the
// ancestors back to the first foothold, the children it derived (the
// lateral-movement tree this detail roots), and the campaign leg (null
// on every ordinary, campaign-free enrollment). The campaign leg carries
// the recipient row whose baked credential the implant redeemed and, when
// the target was selected from the recon vocabulary, the recon asset --
// Sec 15.4's link, read back. This is the related-entities sidebar's
// data source.

export interface ProvenanceAncestor {
  implantId: string
  hostname: string | null
  os: string | null
  class: string
  createdAt: string
  retiredAt: string | null
}

export interface ProvenanceChild {
  implantId: string
  hostname: string | null
  class: string
  createdAt: string
}

export interface ImplantCampaignProvenance {
  campaignId: string
  campaignName: string
  campaignState: string
  recipientId: string
  email: string
  name: string | null
  sentAt: string | null
  openedAt: string | null
  clickedAt: string | null
  executedAt: string | null
  payloadId: string | null
  reconAssetId: string | null
}

export interface ImplantProvenance {
  ancestors: ProvenanceAncestor[]
  children: ProvenanceChild[]
  campaign: ImplantCampaignProvenance | null
}

export interface ImplantDetail {
  implant: Implant
  provenance: ImplantProvenance
}

export async function getImplantDetail(
  engagementId: string,
  implantId: string,
): Promise<ImplantDetail> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/implants/${implantId}`))
}

export interface IssueTaskInput {
  implantId: string
  verb: string
  arguments: string
  // The staged arm (file.push of a larger upload): base64 bytes the server
  // stores as a task-bound artifact and the implant pulls by hash. Absent for
  // every verb whose arguments carry everything.
  content?: string
}

export async function issueTask(
  engagementId: string,
  input: IssueTaskInput,
): Promise<Task> {
  const response = await fetch(`engagements/${engagementId}/tasks`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  })
  return jsonOrThrow(response)
}

// --- Engagement record management ------------------------------
//
// The working record (name + free-text description) is editable while the
// engagement operates and while it is frozen; retirement seals it. The
// close-out path (freeze -> export -> retire) is the engagement's exit from
// service -- the trail stays as the durable account, so "delete" here means
// retiring, not erasing. A mistaken freeze is walked back with unfreeze until
// retirement completes.

export async function editEngagement(
  engagementId: string,
  input: { name: string; description: string | null },
): Promise<Engagement> {
  const response = await fetch(`engagements/${engagementId}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  })
  const edited = jsonOrThrow<Engagement>(response)
  announceEngagementRosterChange()
  return edited
}

// The engagement's rules-of-engagement profile (architecture.md Sec 9's
// guardrails): three allow-lists, each empty meaning unrestricted on that
// dimension. Applying is a scope change the audit trail records as RoeUpdated;
// the answer is the profile now in force. Verb entries match exactly or by
// namespace wildcard (recon.*); implant entries are exact ids; target
// entries are hostnames, IP literals, or CIDR blocks -- a malformed target
// entry is refused by name rather than silently matching nothing.
export async function applyRoe(
  engagementId: string,
  profile: { permittedVerbs: string[]; permittedImplants: string[]; permittedTargets: string[] },
): Promise<RoeProfile> {
  const response = await fetch(`engagements/${engagementId}/roe`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      permittedVerbs: profile.permittedVerbs,
      permittedImplants: profile.permittedImplants,
      permittedTargets: profile.permittedTargets,
    }),
  })
  const scoped = await jsonOrThrow<{ engagementId: string; roe: RoeProfile }>(response)
  return scoped.roe
}

export interface EngagementClosedResult {
  engagementId: string
  at: string
}

export async function freezeEngagement(engagementId: string): Promise<EngagementClosedResult> {
  const response = await fetch(`engagements/${engagementId}:freeze`, { method: 'POST' })
  const frozen = jsonOrThrow<EngagementClosedResult>(response)
  announceEngagementRosterChange()
  return frozen
}

export interface EngagementReopenedResult {
  engagementId: string
  unfrozenAt: string
}

// Reverses a mistaken freeze; refused once the engagement is retired. The
// freeze and the unfreeze both stay in the audit trail.
export async function unfreezeEngagement(engagementId: string): Promise<EngagementReopenedResult> {
  const response = await fetch(`engagements/${engagementId}:unfreeze`, { method: 'POST' })
  const reopened = jsonOrThrow<EngagementReopenedResult>(response)
  announceEngagementRosterChange()
  return reopened
}

export async function retireEngagement(engagementId: string): Promise<EngagementClosedResult> {
  const response = await fetch(`engagements/${engagementId}:retire`, { method: 'POST' })
  const retired = jsonOrThrow<EngagementClosedResult>(response)
  announceEngagementRosterChange()
  return retired
}

// The evidence package is a POST-only close-out action -- the export is an
// audited operator act, not a fetchable resource -- so the download posts and
// takes the returned ZIP as a blob.
export async function fetchEvidencePackageBlob(engagementId: string): Promise<Blob> {
  const response = await fetch(`engagements/${engagementId}:evidence-package`, { method: 'POST' })
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const body = (await response.json()) as Problem
      if (body?.error) detail = body.error
    } catch {
      // Non-JSON error body; keep the status text.
    }
    throw new Error(detail)
  }
  return response.blob()
}

// --- Cancel queued tasking ------------------------------------
//
// Takes a queued task back before the implant wakes: the operator's own
// tasking, retracted. Only a queued task can be cancelled -- one already
// claimed by a beacon stream belongs to the implant and answers with 409.

export interface CancelledTask {
  taskId: string
  engagementId: string
  cancelledBy: string
  cancelledAt: string
}

export async function cancelTask(
  engagementId: string,
  taskId: string,
): Promise<CancelledTask> {
  const response = await fetch(`engagements/${engagementId}/tasks/${taskId}:cancel`, {
    method: 'POST',
  })
  return jsonOrThrow(response)
}

// --- Streaming task input (architecture.md Sec 10.3) ------------------------
//
// A live channel task (shell.interact, tunnel.forward, tunnel.socks) takes
// operator input through its own route: one post is one line of typing or one
// chunk of tunnel traffic, and eof closes the channel's stdin (the shell exits
// and the task completes with the transcript as its record; the tunnel
// half-closes its send side). The transcript itself is the task's own output
// -- read it back with getTask while the channel runs.

export interface TaskDetail {
  taskId: string
  verb: string
  arguments: string
  status: string
  output: string | null
  outcome: string | null
}

export async function getTask(engagementId: string, taskId: string): Promise<TaskDetail> {
  const response = await fetch(`engagements/${engagementId}/tasks/${taskId}`)
  return jsonOrThrow(response)
}

export async function sendTaskInput(
  engagementId: string,
  taskId: string,
  text: string,
  eof = false,
): Promise<void> {
  const data = text.length > 0 ? toBase64Utf8(text) : undefined
  const response = await fetch(`engagements/${engagementId}/tasks/${taskId}/input`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ data, eof }),
  })
  await jsonOrThrow<unknown>(response)
}

// The tunnel pair's relay bind (architecture.md Sec 10.1 tunnel, Sec 10.3):
// a teamserver-side listener bridged onto the live channel, so unmodified
// tooling rides the tunnel without per-byte input posts. Binding takes the
// channel's exclusive claim; the server picks the shape from the task's verb
// (a one-connection bridge for tunnel.forward, a SOCKS5 listener for
// tunnel.socks). No bind query exists server-side -- the endpoint answers
// once at bind time, so the caller keeps the returned endpoint itself.
export interface RelayBind {
  taskId: string
  host: string
  port: number
}

export async function bindTaskRelay(
  engagementId: string,
  taskId: string,
  bindAddress?: string,
  port?: number,
): Promise<RelayBind> {
  const body =
    bindAddress || port
      ? JSON.stringify({ bindAddress: bindAddress || undefined, port: port || 0 })
      : undefined
  const response = await fetch(`engagements/${engagementId}/tasks/${taskId}/relay`, {
    method: 'POST',
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body,
  })
  return jsonOrThrow(response)
}

export async function unbindTaskRelay(engagementId: string, taskId: string): Promise<void> {
  const response = await fetch(`engagements/${engagementId}/tasks/${taskId}/relay`, {
    method: 'DELETE',
  })
  await jsonOrThrow<unknown>(response)
}

// --- LLM attention compression (architecture.md Sec 11) ---------------------
//
// One completed task's captured output sent to the configured
// OpenAI-compatible endpoint for a summary. The request egresses content --
// every attempt, succeeded or failed, is audited as LlmSummaryGenerated
// against the operator who asked. An unconfigured integration answers 503
// naming the configuration section; an upstream failure answers 502.

export interface SummarizedTask {
  taskId: string
  model: string
  summary: string
}

export async function summarizeTask(
  engagementId: string,
  taskId: string,
): Promise<SummarizedTask> {
  const response = await fetch(`engagements/${engagementId}/tasks/${taskId}:summarize`, {
    method: 'POST',
  })
  return jsonOrThrow(response)
}

// Base64 of the UTF-8 encoding: the route binds byte[] from base64, so the
// round-trip preserves arbitrary text exactly.
function toBase64Utf8(text: string): string {
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}

// --- Interaction claims (architecture.md Sec 4.5)  ---------------------------
//
// The exclusive ownership of a typing half: one operator holds the claim on a
// live channel task (its input posts and relay binds) or a caught shell's
// input. The first input takes an unclaimed surface; while another operator
// holds it, the input routes refuse. Claims are visible on the live stream
// (ClaimAcquired / ClaimReleased, and the hello frame's seed) and released on
// the holder's disconnect -- the pane that holds one releases it on dismiss.
// The console needs only the release half: taking is implicit in typing, and
// the views read the claim state from the live stream, not a listing.

export interface ClaimSummary {
  kind: 'channel' | 'shell'
  surfaceId: string
  operatorId: string
  acquiredAt: string
}

// Releases a claim this operator holds; the surface is claimable again.
export async function releaseClaim(
  engagementId: string,
  kind: 'channel' | 'shell',
  surfaceId: string,
): Promise<void> {
  const response = await fetch(`engagements/${engagementId}/claims/${kind}/${surfaceId}`, {
    method: 'DELETE',
  })
  if (!response.ok && response.status !== 404) {
    throw new ApiError(`${response.status} ${response.statusText}`, response.status)
  }
}

// --- Live event stream  ---------------------------------------
//
// Server-Sent Events keep each connected operator session live on an engagement.
// The bus fans task-issued / task-completed / operator-joined / operator-left
// events out to every subscriber, so two operators see each other's actions in
// real time without polling. The operator's identity is read off the session
// cookie server-side, so this stream carries no identity of its own.

export interface LiveOperator {
  id: string
  handle: string
}

// Who is driving which implant (architecture.md Sec 4.5 activity presence):
// the operator whose tasking the implant last saw.
export interface DrivingEntry {
  implantId: string
  operatorId: string
  at: string
}

// One parsed SSE frame. The hello frame seeds the full ownership picture --
// roster, held claims, driving map -- and the claim events keep it current.
export interface LiveEventPayload {
  kind?: string
  engagementId?: string
  operatorId?: string
  implantId?: string | null
  taskId?: string | null
  payload?: string
  at?: string
  operators?: LiveOperator[]
  claims?: ClaimSummary[]
  driving?: DrivingEntry[]
}

export interface EngagementStreamHandlers {
  onHello?: (operators: LiveOperator[], claims: ClaimSummary[], driving: DrivingEntry[]) => void
  onOperatorJoined?: (operatorId: string, handle: string) => void
  onOperatorLeft?: (operatorId: string, handle: string) => void
  onClaimAcquired?: (claim: ClaimSummary) => void
  onClaimReleased?: (claim: ClaimSummary) => void
  onImplantActivity?: (implantId: string, operatorId: string) => void
  onTaskIssued?: (taskId: string, payload: string) => void
  onTaskCompleted?: (taskId: string, payload: string) => void
  onTaskCancelled?: (taskId: string, payload: string) => void
  onChannelOutput?: (taskId: string, chunk: string) => void
  onSessionOpened?: (implantId: string, payload: string) => void
  onSessionClosed?: (implantId: string, payload: string) => void
  onShellSessionOpened?: (payload: string) => void
  onShellSessionEnded?: (payload: string) => void
  onPayloadFetched?: (payload: string) => void
  onCampaignActivity?: (payload: string) => void
  // A comment or chat row moved (added, edited, deleted, a channel created,
  // a message sent): collaboration surfaces refetch on it.
  onCollaborationChange?: (kind: string) => void
  onError?: (event: Event) => void
}

// Parses the claim events' surface payload ("channel/{id}" / "shell/{id}").
function parseClaimPayload(operatorId: string, payload: string, at?: string): ClaimSummary | null {
  const match = /^(channel|shell)\/([\da-fA-F-]+)$/.exec(payload)
  if (!match) return null
  return { kind: match[1] as ClaimSummary['kind'], surfaceId: match[2], operatorId, acquiredAt: at ?? '' }
}

// Opens an SSE stream for an engagement. The auth cookie identifies the operator
// server-side, so no identity travels in the URL. Returns a close that tears
// the stream down; the caller invokes it on unmount. The EventSource reconnects
// automatically on a dropped connection.
export function subscribeToEngagement(
  engagementId: string,
  handlers: EngagementStreamHandlers,
): () => void {
  const source = new EventSource(`engagements/${engagementId}/events`)

  const parse = (data: string): LiveEventPayload | null => {
    try {
      return JSON.parse(data) as LiveEventPayload
    } catch {
      return null
    }
  }

  source.addEventListener('hello', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onHello?.(payload?.operators ?? [], payload?.claims ?? [], payload?.driving ?? [])
  })
  source.addEventListener('OperatorJoined', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onOperatorJoined?.(payload?.operatorId ?? '', payload?.payload ?? '')
  })
  source.addEventListener('OperatorLeft', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onOperatorLeft?.(payload?.operatorId ?? '', payload?.payload ?? '')
  })
  source.addEventListener('ClaimAcquired', (e) => {
    const payload = parse((e as MessageEvent).data)
    const claim = payload && parseClaimPayload(payload.operatorId ?? '', payload.payload ?? '', payload.at)
    if (claim) handlers.onClaimAcquired?.(claim)
  })
  source.addEventListener('ClaimReleased', (e) => {
    const payload = parse((e as MessageEvent).data)
    const claim = payload && parseClaimPayload(payload.operatorId ?? '', payload.payload ?? '', payload.at)
    if (claim) handlers.onClaimReleased?.(claim)
  })
  source.addEventListener('ImplantActivity', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onImplantActivity?.(payload?.implantId ?? '', payload?.operatorId ?? '')
  })
  source.addEventListener('TaskIssued', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onTaskIssued?.(payload?.taskId ?? '', payload?.payload ?? '')
  })
  source.addEventListener('TaskCompleted', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onTaskCompleted?.(payload?.taskId ?? '', payload?.payload ?? '')
  })
  source.addEventListener('TaskCancelled', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onTaskCancelled?.(payload?.taskId ?? '', payload?.payload ?? '')
  })
  source.addEventListener('ChannelOutput', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onChannelOutput?.(payload?.taskId ?? '', payload?.payload ?? '')
  })
  source.addEventListener('SessionOpened', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onSessionOpened?.(payload?.implantId ?? '', payload?.payload ?? '')
  })
  source.addEventListener('SessionClosed', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onSessionClosed?.(payload?.implantId ?? '', payload?.payload ?? '')
  })
  source.addEventListener('ShellSessionOpened', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onShellSessionOpened?.(payload?.payload ?? '')
  })
  source.addEventListener('ShellSessionEnded', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onShellSessionEnded?.(payload?.payload ?? '')
  })
  source.addEventListener('PayloadFetched', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onPayloadFetched?.(payload?.payload ?? '')
  })
  source.addEventListener('CampaignActivity', (e) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onCampaignActivity?.(payload?.payload ?? '')
  })
  const onCollaboration = (e: Event) => {
    const payload = parse((e as MessageEvent).data)
    handlers.onCollaborationChange?.(payload?.kind ?? '')
  }
  source.addEventListener('CommentAdded', onCollaboration)
  source.addEventListener('CommentEdited', onCollaboration)
  source.addEventListener('CommentDeleted', onCollaboration)
  source.addEventListener('ChatChannelCreated', onCollaboration)
  source.addEventListener('ChatMessageSent', onCollaboration)
  source.onerror = (e) => handlers.onError?.(e)

  return () => source.close()
}

// --- Capability catalog  -------------------------------------
//
// The verb table is data-driven from the registry (GET /capabilities) so the UI
// surfaces every capability category as tasking without hardcoding the verbs.
// Each descriptor carries its category (for grouping) and OPSEC attributes (for
// risk badges). Sensitive categories -- evasion and exploit -- are listed too;
// this surface holds only the contract, never concrete tradecraft.

// The parameter schema and output taxonomy (the contract trilogy,
// architecture.md Sec 15.2): everything the UI needs to task a verb it has
// never met. The schema renders the form; the output kind routes the result
// to the right panel; neither reaches the wire, where task arguments stay
// the verb's own opaque string.

export type VerbParameterKind =
  | 'String'
  | 'Text'
  | 'Number'
  | 'Boolean'
  | 'Enum'
  | 'File'
  | 'Array'

export interface VerbParameter {
  name: string
  label: string
  kind: VerbParameterKind
  required: boolean
  help: string | null
  placeholder: string | null
  choices: string[] | null
  trailing: boolean
  inline: boolean
}

export type VerbOutputKind =
  | 'Text'
  | 'Enumeration'
  | 'ProcessList'
  | 'FileList'
  | 'Credential'
  | 'File'
  | 'Screenshot'

export interface VerbOutput {
  kind: VerbOutputKind
  help: string | null
}

export interface CapabilityDescriptor {
  verb: string
  category: string
  version: string
  attributes: Record<string, string>
  parameters: VerbParameter[] | null
  output: VerbOutput | null
  techniques: string[]
}

export async function listCapabilities(): Promise<CapabilityDescriptor[]> {
  return jsonOrThrow(await fetch('capabilities'))
}

// The ATT&CK coverage matrix (ADR-007): one row per technique the running
// deployment can task, naming the verb, module, and implant classes that
// carry it. The status vocabulary is the server's computed implementation
// status -- core (an in-tree reference implementation), module (a loaded
// capability module), gap (declared only: the work queue).
export interface CoverageCarrier {
  verb: string
  status: 'core' | 'module' | 'gap'
  module: string | null
  implantClasses: string[]
}

export interface CoverageTechnique {
  techniqueId: string
  name: string
  tactics: string[]
  carriers: CoverageCarrier[]
  platforms: string[]
}

export interface CapabilityCoverage {
  attackVersion: string
  tactics: string[]
  platforms: string[]
  techniques: CoverageTechnique[]
}

export async function getCapabilityCoverage(): Promise<CapabilityCoverage> {
  return jsonOrThrow(await fetch('capabilities/coverage'))
}

// --- Paged lists --------------------------------------------------
//
// Task, audit, and artifact listings are paged: each call returns one page --
// the newest window on the first call, one page older per cursor -- plus the
// cursor for the next older page (null at the beginning of history). A long
// engagement no longer grows any listing response without bound; the views walk
// pages with their "load older" controls.

export interface ListPage<T> {
  items: T[]
  nextCursor: string | null
}

// --- Engagement-wide task list  ------------------------------
//
// The task history for an engagement across every implant, one page per call,
// oldest first within the page. Reuses the per-implant task shape so both list
// views read identically to a client.

export interface EngagementTask {
  taskId: string
  implantId: string
  issuedBy: string
  verb: string
  arguments: string
  status: string
  output: string | null
  outcome: string | null
  createdAt: string
  completedAt: string | null
}

// The limit rides along for windowed reads (the home dashboard's activity
// chart): the server caps a page at 200 items, and the default is 50.
export async function listEngagementTasks(
  engagementId: string,
  cursor?: string,
  limit?: number,
): Promise<ListPage<EngagementTask>> {
  const params = new URLSearchParams()
  if (cursor) params.set('cursor', cursor)
  if (limit !== undefined) params.set('limit', String(limit))
  const query = params.size > 0 ? `?${params.toString()}` : ''
  return jsonOrThrow(await fetch(`engagements/${engagementId}/tasks${query}`))
}

// --- Per-implant task list  ---------------------------------
//
// The same history scoped to one implant (the session console's feed), same
// paging envelope as the engagement-wide list.

export async function listImplantTasks(
  engagementId: string,
  implantId: string,
  cursor?: string,
): Promise<ListPage<EngagementTask>> {
  const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/implants/${implantId}/tasks${query}`),
  )
}

// --- Audit trail  ---------------------------------------------
//
// The per-engagement, append-only, hash-chained event stream. Every action that
// changes engagement state or binds an identity produces an immutable, attributed
// event; this reads that trail oldest-first so the engagement timeline reads in
// causal order. Distinct from the live SSE stream (transient fan-out).

export interface AuditEventEntry {
  eventId: string
  kind: string
  verb: string
  operatorId: string
  // The resolved handle of the acting operator ("system" for unattributed
  // events), so the trail reads as who acted rather than a guid.
  operatorHandle: string
  implantId: string
  taskId: string
  payload: string
  output: string | null
  outcome: string
  at: string
  // True for the collaboration rows (comments, chat) that ride the timeline
  // as ordinary events without entering the hash chain -- mutable process
  // knowledge beside the chain's immutable facts.
  mutable?: boolean
}

export async function listAudit(
  engagementId: string,
  cursor?: string,
): Promise<ListPage<AuditEventEntry>> {
  const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
  return jsonOrThrow(await fetch(`engagements/${engagementId}/audit${query}`))
}

// --- Artifacts  -----------------------------------------------
//
// First-class evidence objects attached to tasks. Attach (base64 body), list per
// task (metadata only), and retrieve a single artifact's bytes as a file
// download. Scoped by engagement so cross-engagement access is impossible.

export interface ArtifactSummary {
  artifactId: string
  // Null for pre-foothold findings (the recon workbench) -- no task gathered them.
  taskId: string | null
  name: string
  contentType: string
  operatorId: string | null
  size: number
  storedAt: string
}

export async function listArtifacts(
  engagementId: string,
  taskId: string,
  cursor?: string,
): Promise<ListPage<ArtifactSummary>> {
  const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
  return jsonOrThrow(await fetch(`engagements/${engagementId}/tasks/${taskId}/artifacts${query}`))
}

export async function attachArtifact(
  engagementId: string,
  taskId: string,
  input: { name: string; contentType: string | null; content: string },
): Promise<ArtifactSummary> {
  const response = await fetch(`engagements/${engagementId}/tasks/${taskId}/artifacts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  })
  return jsonOrThrow(response)
}

// Returns the artifact's bytes as a blob the caller can download or preview.
export async function fetchArtifactBlob(engagementId: string, artifactId: string): Promise<Blob> {
  const response = await fetch(`engagements/${engagementId}/artifacts/${artifactId}`)
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const body = (await response.json()) as Problem
      if (body?.error) detail = body.error
    } catch {
      // Non-JSON error body; keep the status text.
    }
    throw new Error(detail)
  }
  return response.blob()
}

// --- Report export  ------------------------------------------
//
// Built-in consumer of the event + task + artifact store: the engagement's
// full evidence bundle, JSON by default or Markdown when format='markdown'
// (returned as text), carrying a content hash so two exports of identical
// state match. The timeline's standalone endpoint stays a scripting
// deliverable; this report is the UI's narrative home.

export interface ReportTask {
  taskId: string
  verb: string
  arguments: string
  status: string
  outcome: string | null
  issuedBy: string
  issuedByHandle: string
  implantId: string
  createdAt: string
  dispatchedAt: string | null
  completedAt: string | null
  output: string | null
  artifacts: string[]
}
export interface EngagementReport {
  engagement: {
    engagementId: string
    name: string
    ownerId: string
    ownerHandle: string
    createdAt: string
  }
  generatedAt: string
  contentHash: string
  operators: { operatorId: string; handle: string }[]
  implants: { implantId: string; class: string; parentImplantId: string | null; retiredAt: string | null }[]
  tasks: ReportTask[]
  artifacts: { artifactId: string; taskId: string; name: string; contentType: string; size: number }[]
}

export async function getReport(engagementId: string): Promise<EngagementReport> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/report`))
}

export async function getReportMarkdown(engagementId: string): Promise<string> {
  const response = await fetch(`engagements/${engagementId}/report?format=markdown`)
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
  return response.text()
}

// --- Handoff digest  -----------------------------------------------
//
// The shift-resume read (architecture.md Sec 11.1): a time-windowed,
// kind-whitelisted, ordered account of the watch's beats, projected from the
// same reporting context as the report. Bounds are inclusive ISO-8601
// timestamps; omitting both asks for the last watch window (to = now, from =
// twelve hours before it).

export interface DigestActor {
  operatorId: string
  handle: string
}

export interface DigestSubject {
  implantId: string
  class: string
}

export interface DigestTaskRef {
  taskId: string
  verb: string | null
  outcome: string | null
}

export interface DigestEntry {
  eventId: string
  at: string
  kind: string
  verb: string
  operator: DigestActor | null
  implant: DigestSubject | null
  task: DigestTaskRef | null
  payload: string
  output: string | null
  outcome: string
  hash: string
}

export interface HandoffDigestSummary {
  sessionsOpened: number
  sessionsClosed: number
  implantsEnrolled: number
  implantsRetired: number
  tasksIssued: number
  tasksCompleted: number
  tasksCancelled: number
  roeRefusals: number
  notesAdded: number
  shellSessionsOpened: number
  shellSessionsEnded: number
}

export interface HandoffDigest {
  engagementId: string
  engagementName: string
  from: string
  to: string
  generatedAt: string
  contentHash: string
  chainVerified: boolean
  chainBreak: string | null
  summary: HandoffDigestSummary
  entries: DigestEntry[]
}

export interface DigestWindow {
  from?: string
  to?: string
}

function digestQuery(window: DigestWindow, markdown: boolean): string {
  const params = new URLSearchParams()
  if (window.from) params.set('from', window.from)
  if (window.to) params.set('to', window.to)
  if (markdown) params.set('format', 'markdown')
  const query = params.toString()
  return query ? `?${query}` : ''
}

export async function getHandoffDigest(
  engagementId: string,
  window: DigestWindow = {},
): Promise<HandoffDigest> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/handoff-digest${digestQuery(window, false)}`))
}

// The same account as the human handoff note -- what an operator pastes to
// the next watch.
export async function getHandoffDigestMarkdown(
  engagementId: string,
  window: DigestWindow = {},
): Promise<string> {
  const response = await fetch(
    `engagements/${engagementId}/handoff-digest${digestQuery(window, true)}`,
  )
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
  return response.text()
}

// --- Implant retire / burn  -----------------------------------
//
// Takes an implant out of operation: a retired implant is refused at handshake
// and untaskable. Idempotent; reflects retirement in the listing. The retiring
// operator is the authenticated operator, so no body is sent.

export interface RetireImplantResult {
  implantId: string
  engagementId: string
  retiredBy: string
  retiredAt: string
  justRetired: boolean
  closedSession: string | null
}

export async function retireImplant(
  engagementId: string,
  implantId: string,
): Promise<RetireImplantResult> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/implants/${implantId}:retire`, {
      method: 'POST',
    }),
  )
}

// --- Implant notes --------------------------------------------
//
// The "whose beacon is this" memory: free-text, attributed notes on an
// implant. A note's only storage is the audit trail (ImplantNoteAdded events),
// so it survives a teamserver restart with the trail itself and reads back
// here on the implant view, oldest first.

export interface ImplantNote {
  noteId: string
  implantId: string
  author: string
  text: string
  at: string
}

export async function listImplantNotes(
  engagementId: string,
  implantId: string,
): Promise<ImplantNote[]> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/implants/${implantId}/notes`),
  )
}

export async function addImplantNote(
  engagementId: string,
  implantId: string,
  text: string,
): Promise<ImplantNote> {
  const response = await fetch(`engagements/${engagementId}/implants/${implantId}/notes`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text }),
  })
  return jsonOrThrow(response)
}

// --- Target intel ---------------------------------------------
//
// The layer that holds what the engagement learned (architecture.md Sec
// 11.2): labels on implants and hosts (the marker vocabulary -- attributed
// set/clear trail facts reduced last-wins), notes on hosts, the typed loot
// view over the artifact store, and the assembled topology projection.
// Everything reads back from stores that already hold the data; the trail
// is the only storage anything here writes.

export interface ImplantLabel {
  label: string
  setBy: string
  setAt: string
}

export async function listImplantLabels(
  engagementId: string,
  implantId: string,
): Promise<ImplantLabel[]> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/implants/${implantId}/labels`),
  )
}

export async function setImplantLabel(
  engagementId: string,
  implantId: string,
  label: string,
): Promise<ImplantLabel> {
  const response = await fetch(`engagements/${engagementId}/implants/${implantId}/labels`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ label }),
  })
  return jsonOrThrow(response)
}

export async function clearImplantLabel(
  engagementId: string,
  implantId: string,
  label: string,
): Promise<void> {
  const response = await fetch(
    `engagements/${engagementId}/implants/${implantId}/labels/${encodeURIComponent(label)}`,
    { method: 'DELETE' },
  )
  return jsonOrThrow(response)
}

export interface HostNote {
  noteId: string
  host: string
  author: string
  text: string
  at: string
}

export interface HostLabel {
  label: string
  setBy: string
  setAt: string
}

export interface HostEntry {
  host: string
  labels: string[]
  noteCount: number
  implantIds: string[]
  onlineCount: number
  os: string | null
  arch: string | null
  username: string | null
  firstSeenAt: string | null
}

export interface HostsResponse {
  hosts: HostEntry[]
  ungroupedImplantIds: string[]
}

// Hosts key on the normalized hostname; the caller passes the spelling it
// has and the route folds the case.
export async function listHosts(engagementId: string): Promise<HostsResponse> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/hosts`))
}

export async function listHostNotes(engagementId: string, host: string): Promise<HostNote[]> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/hosts/${encodeURIComponent(host)}/notes`),
  )
}

export async function addHostNote(
  engagementId: string,
  host: string,
  text: string,
): Promise<HostNote> {
  const response = await fetch(`engagements/${engagementId}/hosts/${encodeURIComponent(host)}/notes`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text }),
  })
  return jsonOrThrow(response)
}

export async function listHostLabels(engagementId: string, host: string): Promise<HostLabel[]> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/hosts/${encodeURIComponent(host)}/labels`),
  )
}

export async function setHostLabel(
  engagementId: string,
  host: string,
  label: string,
): Promise<HostLabel> {
  const response = await fetch(`engagements/${engagementId}/hosts/${encodeURIComponent(host)}/labels`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ label }),
  })
  return jsonOrThrow(response)
}

export async function clearHostLabel(
  engagementId: string,
  host: string,
  label: string,
): Promise<void> {
  const response = await fetch(
    `engagements/${engagementId}/hosts/${encodeURIComponent(host)}/labels/${encodeURIComponent(label)}`,
    { method: 'DELETE' },
  )
  return jsonOrThrow(response)
}

// One piece of loot: an artifact the engagement captured or attached, with
// the kind the view classifies it into and the capture attribution.
export interface LootEntry {
  artifactId: string
  kind: string
  // Null for pre-foothold findings (the recon workbench) -- no task gathered them.
  taskId: string | null
  implantId: string | null
  verb: string | null
  capturedBy: string | null
  name: string
  contentType: string
  size: number
  storedAt: string
}

export async function listLoot(
  engagementId: string,
  kind?: string,
  cursor?: string,
  limit?: number,
): Promise<ListPage<LootEntry>> {
  const params = new URLSearchParams()
  if (kind) params.set('kind', kind)
  if (cursor) params.set('cursor', cursor)
  if (limit !== undefined) params.set('limit', String(limit))
  const query = params.size > 0 ? `?${params.toString()}` : ''
  return jsonOrThrow(await fetch(`engagements/${engagementId}/loot${query}`))
}

// --- Credentials (the taxonomy's read-time projection) ---------
//
// The engagement's harvested credential rows, assembled at read time from
// every completed task whose verb declared credential output -- any module's
// harvest, the same projection posture the topology holds. Secrets render
// masked in the UI; nothing here enters the audit chain.

export interface CredentialRow {
  // The row's stable id -- the value a $cred-<id> task-reference placeholder
  // addresses in comments and task input.
  id: string
  kind: string
  principal: string
  secret: string | null
  source: string | null
  host: string | null
  note: string | null
  taskId: string | null
  implantId: string | null
  verb: string
  capturedAt: string
}

export async function listCredentials(engagementId: string): Promise<CredentialRow[]> {
  const page = await jsonOrThrow<{ items: CredentialRow[] }>(
    await fetch(`engagements/${engagementId}/credentials`),
  )
  return page.items
}

export interface TopologyHost {
  host: string
  kind: string
  os: string | null
  arch: string | null
  implantIds: string[]
  online: number
  labels: string[]
}

export interface TopologyLink {
  fromImplantId: string
  toImplantId: string
  fromHost: string
  toHost: string
  kind: string
}

export interface TopologyObservation {
  host: string
  port: number | null
  state: string | null
  service: string | null
  address: string | null
  os: string | null
  arch: string | null
  // Null for pre-foothold findings: the workbench artifact below is the
  // whole attribution (no task, no implant existed yet).
  taskId: string | null
  implantId: string | null
  verb: string
  at: string
  artifactId: string | null
}

export interface Topology {
  engagementId: string
  hosts: TopologyHost[]
  links: TopologyLink[]
  observations: TopologyObservation[]
  chainVerified: boolean
  chainBreak: string | null
}

export async function getTopology(engagementId: string): Promise<Topology> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/topology`))
}

// --- Recon workbench ------------------------------------------
//
// The pre-foothold scoping surface (docs/operations/recon.md): registration
// lookups, certificate-transparency subdomain enumeration, resolution, and
// the ROE-gated port scan. Each route runs synchronously -- the egress, the
// artifact, and the audit event all happen inside the request, so the answer
// carries the landed artifact's metadata rather than a run id. An
// unconfigured half answers 503 naming the setting it wants; that sentence
// is the UI's error line, verbatim.

export interface ReconWorkbenchResult {
  artifactId: string
  name: string
  contentType: string
  findings: number
  size: number
  summary: string
}

async function runRecon(
  engagementId: string,
  route: string,
  body: unknown,
): Promise<ReconWorkbenchResult> {
  const response = await fetch(`engagements/${engagementId}/recon:${route}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  return jsonOrThrow(response)
}

// RDAP registration data (with the whois fallback behind it) and the
// certificate-transparency subdomain census share the one-target shape.
export function runReconLookup(
  engagementId: string,
  kind: 'rdap' | 'subdomains',
  target: string,
): Promise<ReconWorkbenchResult> {
  return runRecon(engagementId, kind, { target })
}

export function runReconResolve(
  engagementId: string,
  targets: string[],
): Promise<ReconWorkbenchResult> {
  return runRecon(engagementId, 'resolve', { targets })
}

// Ports omitted = the curated default set; the grammar (comma list with
// hyphen ranges) is the server's to enforce -- a bad list answers 400 with
// the reason.
export function runReconPortScan(
  engagementId: string,
  target: string,
  ports?: string,
): Promise<ReconWorkbenchResult> {
  return runRecon(engagementId, 'portscan', ports ? { target, ports } : { target })
}

// --- Recon assets (architecture.md Sec 15.4, the unified entity model) ------
//
// The named targeting vocabulary: emails, domains, hosts, and addresses the
// recon stage recorded as campaign-worthy. An asset selects directly as a
// campaign recipient (the create body takes reconAssetId in place of a
// hand-typed address), and every campaign recipient and enrolled implant
// carries its reconAssetId back -- the link the related-entities sidebar
// draws. Deletion refuses (409) while any campaign recipient still
// references the asset.

export type ReconAssetKind = 'email' | 'domain' | 'host' | 'address'

export interface ReconAsset {
  assetId: string
  kind: ReconAssetKind
  value: string
  displayName: string | null
  // The workbench artifact the asset was recorded from, when it was.
  sourceArtifactId: string | null
  createdBy: string
  createdAt: string
}

export async function listReconAssets(engagementId: string): Promise<ReconAsset[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/recon-assets`))
}

export async function createReconAsset(
  engagementId: string,
  input: { kind: ReconAssetKind; value: string; displayName?: string; sourceArtifactId?: string },
): Promise<ReconAsset> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/recon-assets`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        kind: input.kind,
        value: input.value,
        displayName: input.displayName ?? null,
        sourceArtifactId: input.sourceArtifactId ?? null,
      }),
    }),
  )
}

export async function deleteReconAsset(engagementId: string, assetId: string): Promise<void> {
  await jsonOrThrow(await fetch(`engagements/${engagementId}/recon-assets/${assetId}`, {
    method: 'DELETE',
  }))
}

// --- Task snippets --------------------------------------------
//
// The console's saved command sequences (docs/operations/operator-ui.md):
// a named, engagement-scoped, shareable list of issue commands. Plain CRUD
// -- replay happens here in the console, which issues each step through
// the ordinary tasking route, so there is no run endpoint to call.

export interface TaskSnippetStep {
  verb: string
  arguments: string
}

export interface TaskSnippet {
  id: string
  engagementId: string
  name: string
  steps: TaskSnippetStep[]
  createdAt: string
  createdBy: string
}

export async function listTaskSnippets(engagementId: string): Promise<TaskSnippet[]> {
  const page = (await jsonOrThrow(
    await fetch(`engagements/${engagementId}/task-snippets`),
  )) as { snippets: TaskSnippet[] }
  return page.snippets
}

export async function createTaskSnippet(
  engagementId: string,
  name: string,
  steps: TaskSnippetStep[],
): Promise<TaskSnippet> {
  const response = await fetch(`engagements/${engagementId}/task-snippets`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name, steps }),
  })
  return jsonOrThrow(response)
}

export async function deleteTaskSnippet(
  engagementId: string,
  snippetId: string,
): Promise<void> {
  const response = await fetch(`engagements/${engagementId}/task-snippets/${snippetId}`, {
    method: 'DELETE',
  })
  if (!response.ok && response.status !== 404) {
    throw new Error(`delete task snippet: ${response.status}`)
  }
}

// --- Collaboration: comments, chat, global search  -------------
//
// The engagement's mutable process knowledge (architecture.md Sec 15.3):
// comments on entities (editable by their author within a window), chat
// channels, and the one-query global search over task output, comments,
// artifact metadata, credentials, and chat. None of it enters the audit
// chain; the timeline carries it as explicitly mutable rows.

export type CommentSubjectKind =
  | 'task'
  | 'implant'
  | 'artifact'
  | 'file'
  | 'engagement'
  | 'operator'

export interface CommentRow {
  id: string
  subjectKind: CommentSubjectKind
  subjectId: string
  authorId: string
  body: string
  createdAt: string
  editedAt: string | null
  editable: boolean
}

export async function listComments(
  engagementId: string,
  subjectKind: CommentSubjectKind,
  subjectId: string,
): Promise<CommentRow[]> {
  const query = `?subjectKind=${subjectKind}&subjectId=${encodeURIComponent(subjectId)}`
  const page = await jsonOrThrow<{ items: CommentRow[] }>(
    await fetch(`engagements/${engagementId}/comments${query}`),
  )
  return page.items
}

export async function createComment(
  engagementId: string,
  subjectKind: CommentSubjectKind,
  subjectId: string,
  body: string,
): Promise<CommentRow> {
  const response = await fetch(`engagements/${engagementId}/comments`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ subjectKind, subjectId, body }),
  })
  return jsonOrThrow(response)
}

export async function editComment(
  engagementId: string,
  commentId: string,
  body: string,
): Promise<CommentRow> {
  const response = await fetch(`engagements/${engagementId}/comments/${commentId}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ body }),
  })
  return jsonOrThrow(response)
}

export async function deleteComment(engagementId: string, commentId: string): Promise<void> {
  const response = await fetch(`engagements/${engagementId}/comments/${commentId}`, {
    method: 'DELETE',
  })
  if (!response.ok && response.status !== 404) {
    throw new ApiError(`${response.status} ${response.statusText}`, response.status)
  }
}

export interface ChatChannelRow {
  id: string
  name: string
  createdBy: string
  createdAt: string
}

export interface ChatMessageRow {
  id: string
  channelId: string
  authorId: string
  body: string
  sentAt: string
}

export async function listChatChannels(engagementId: string): Promise<ChatChannelRow[]> {
  const page = await jsonOrThrow<{ items: ChatChannelRow[] }>(
    await fetch(`engagements/${engagementId}/chat/channels`),
  )
  return page.items
}

export async function createChatChannel(
  engagementId: string,
  name: string,
): Promise<ChatChannelRow> {
  const response = await fetch(`engagements/${engagementId}/chat/channels`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name }),
  })
  return jsonOrThrow(response)
}

export async function listChatMessages(
  engagementId: string,
  channelId: string,
  cursor?: string,
): Promise<ListPage<ChatMessageRow>> {
  const query = cursor ? `?cursor=${encodeURIComponent(cursor)}&limit=50` : '?limit=50'
  return jsonOrThrow(await fetch(`engagements/${engagementId}/chat/channels/${channelId}/messages${query}`))
}

export async function sendChatMessage(
  engagementId: string,
  channelId: string,
  body: string,
): Promise<ChatMessageRow> {
  const response = await fetch(`engagements/${engagementId}/chat/channels/${channelId}/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ body }),
  })
  return jsonOrThrow(response)
}

export type SearchCorpus =
  | 'task_output'
  | 'comment'
  | 'artifact'
  | 'credential'
  | 'chat_message'

export interface SearchHitRow {
  corpus: SearchCorpus
  refId: string
  title: string
  excerpt: string
  at: string
}

export async function searchEngagement(
  engagementId: string,
  query: string,
  corpora?: SearchCorpus[],
): Promise<SearchHitRow[]> {
  const params = new URLSearchParams({ q: query })
  if (corpora && corpora.length > 0) params.set('corpora', corpora.join(','))
  const page = await jsonOrThrow<{ items: SearchHitRow[] }>(
    await fetch(`engagements/${engagementId}/search?${params.toString()}`),
  )
  return page.items
}

// --- Listeners and redirector repoint  -----------------------
//
// Listeners are the engagement's own C2 ingress: created here against the
// engagement in the path, persisted so a restart rebinds them, and enforced at
// enrollment (a foreign engagement's token is refused whole on the socket).
// The bind address is the socket; the public endpoint is the redirector
// implants dial, decoupled so a repoint swaps a burned front without backend
// change. The operator front the UI rides is startup configuration, carries no
// implant ingress, and never appears here.

export interface ListenerSummary {
  id: string
  name: string
  transport: string
  bindAddress: string
  publicEndpoint: string
  // Whose certificate the front presents -- 'pinned' (the engagement CA)
  // or 'public' (a real-domain chain an operator-run edge terminates). The
  // listener owns the fact; builds inherit it as their TLS roots.
  trustPosture: string
  state: string
  createdAt: string
  repointedAt: string | null
  // The ordered enrolled-front list (architecture.md Sec 8): attachments to
  // redirector nodes the control plane provisions with forwarding rules.
  // Index zero is the primary -- the public endpoint above reports it.
  fronts: ListenerFrontSummary[]
}

export interface ListenerFrontSummary {
  frontId: string
  nodeId: string
  nodeName: string
  listenEndpoint: string
  publicEndpoint: string
  allowList: string | null
  isPrimary: boolean
  attachedAt: string
}

// The host's bindable interfaces (GET /network/interfaces): the read view the
// listener form's bind dropdown is built from. The wildcard all-interfaces
// entry is a client-side constant, not a reported interface.
export interface NetworkInterfaceSummary {
  name: string
  address: string
}

export async function listNetworkInterfaces(): Promise<NetworkInterfaceSummary[]> {
  return jsonOrThrow(await fetch('network/interfaces'))
}

export async function listListeners(engagementId: string): Promise<ListenerSummary[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/listeners`))
}

export interface CreateListenerInput {
  name: string
  transport: string
  bindAddress: string
  publicEndpoint: string
  // Whose certificate the front presents: 'pinned' (the default -- the
  // engagement CA) or 'public' (a real-domain front an operator-run edge
  // terminates; needs an https dial). The listener owns the fact; builds
  // inherit it as their TLS roots.
  trust?: string
}

export async function createListener(
  engagementId: string,
  input: CreateListenerInput,
): Promise<ListenerSummary> {
  const response = await fetch(`engagements/${engagementId}/listeners`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  })
  return jsonOrThrow(response)
}

export async function repointListener(
  engagementId: string,
  listenerId: string,
  publicEndpoint: string,
): Promise<ListenerSummary> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/listeners/${listenerId}:repoint`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ publicEndpoint }),
    }),
  )
}

// Deletes the listener. A listener live implants enrolled through refuses
// with a 409 naming them; `force` is the explicit second confirmation that
// deletes anyway.
export async function deleteListener(
  engagementId: string,
  listenerId: string,
  force = false,
): Promise<void> {
  await jsonOrThrow<unknown>(
    await fetch(
      `engagements/${engagementId}/listeners/${listenerId}${force ? '?force=true' : ''}`,
      { method: 'DELETE' },
    ),
  )
}

// --- Listener fronts (the enrolled redirector fleet) ---------
//
// A front attaches an enrolled node to a listener (architecture.md Sec 8):
// the control plane provisions the node with the forwarding rule (bind the
// listen endpoint, splice to the listener's bind), and implants dial the
// front's public endpoint. The primary front is the endpoint builds bake;
// promoting one is the rotation op for enrolled fleets.

export interface AttachFrontInput {
  nodeId: string
  listenEndpoint: string
  publicEndpoint?: string
  allowList?: string
  primary?: boolean
}

export async function attachListenerFront(
  engagementId: string,
  listenerId: string,
  input: AttachFrontInput,
): Promise<ListenerFrontSummary> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/listeners/${listenerId}/fronts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
    }),
  )
}

export async function detachListenerFront(
  engagementId: string,
  listenerId: string,
  frontId: string,
): Promise<void> {
  await jsonOrThrow<unknown>(
    await fetch(`engagements/${engagementId}/listeners/${listenerId}/fronts/${frontId}`, {
      method: 'DELETE',
    }),
  )
}

export async function promoteListenerFront(
  engagementId: string,
  listenerId: string,
  frontId: string,
): Promise<ListenerFrontSummary> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/listeners/${listenerId}/fronts/${frontId}:primary`, {
      method: 'POST',
    }),
  )
}

// --- The redirector fleet (deployment-scoped) -----------------
//
// The enrolled fleet (architecture.md Sec 8): nodes dial home over the
// control channel, the roster reads their presence, and enrollment
// credentials pre-provision new ones. Deployment-scoped like the routes it
// rides -- no engagement context.

export interface RedirectorNodeSummary {
  id: string
  name: string
  online: boolean
  enrolledAt: string
  retiredAt: string | null
  lastSeenAt: string
  lastAddress: string | null
  reportedVersion: string | null
  reportedCommit: string | null
}

export interface RedirectorCredentialSummary {
  id: string
  name: string
  issuedAt: string
  expiresAt: string
  enrolledNodeId: string | null
  revokedAt: string | null
}

// The mint result: the secret exists exactly once, here -- the ledger keeps
// hashes and stamps only.
export interface MintedRedirectorCredential {
  id: string
  name: string
  secret: string
  issuedAt: string
  expiresAt: string
}

export async function listRedirectorNodes(): Promise<RedirectorNodeSummary[]> {
  return jsonOrThrow(await fetch('redirectors'))
}

export async function listRedirectorCredentials(): Promise<RedirectorCredentialSummary[]> {
  return jsonOrThrow(await fetch('redirectors/credentials'))
}

export async function mintRedirectorCredential(
  name: string,
  ttlHours?: number,
): Promise<MintedRedirectorCredential> {
  return jsonOrThrow(
    await fetch('redirectors/credentials', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name, ttlHours }),
    }),
  )
}

export async function revokeRedirectorCredential(id: string): Promise<void> {
  await jsonOrThrow<unknown>(
    await fetch(`redirectors/credentials/${id}:revoke`, { method: 'POST' }),
  )
}

export async function retireRedirectorNode(id: string): Promise<void> {
  await jsonOrThrow<unknown>(await fetch(`redirectors/${id}:retire`, { method: 'POST' }))
}

// --- Caught reverse shells (shellcatch) -----------------------
//
// The engagement's caught shells: connections a shellcatch listener holds
// that speak no Rod protocol. The roster reads the session registry; the
// console reads output by cursor (a long poll parks server-side until the
// next chunk), and input/close/upgrade are the operator actions over the
// held socket.

export interface ShellSession {
  sessionId: string
  status: 'live' | 'lost' | 'closed'
  os: 'unknown' | 'windowscmd' | 'windowspowershell' | 'unixshell'
  remoteAddress: string
  openedAt: string
  lastInputAt: string | null
  lastOutputAt: string | null
  endedAt: string | null
  // The codec both directions speak; null when the session has ended (the
  // codec was the live connection's, and died with it) -- the console then
  // shows the default.
  encoding: string | null
}

export async function listShells(engagementId: string): Promise<ShellSession[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/shells`))
}

export interface ShellOutputChunk {
  sequence: number
  at: string
  text: string
}

export interface ShellOutput {
  latestSequence: number
  chunks: ShellOutputChunk[]
}

// Reads the shell's output after a cursor. The server parks the request
// until new output exists (bounded ~20s), so a console keeps one request in
// flight instead of a spinning poll.
export async function readShellOutput(
  engagementId: string,
  sessionId: string,
  after: number,
): Promise<ShellOutput> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/shells/${sessionId}/output?after=${after}`),
  )
}

export async function sendShellInput(
  engagementId: string,
  sessionId: string,
  text: string,
): Promise<void> {
  await jsonOrThrow<unknown>(
    await fetch(`engagements/${engagementId}/shells/${sessionId}:input`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text }),
    }),
  )
}

// Repoints the session's codec: output decodes and input encodes with the
// named encoding from the offered set. The answer is the server's canonical
// name for what was set.
export async function setShellEncoding(
  engagementId: string,
  sessionId: string,
  encoding: string,
): Promise<string> {
  const answer = await jsonOrThrow<{ encoding: string }>(
    await fetch(`engagements/${engagementId}/shells/${sessionId}:encoding`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ encoding }),
    }),
  )
  return answer.encoding
}

export async function closeShell(engagementId: string, sessionId: string): Promise<void> {
  await jsonOrThrow<unknown>(
    await fetch(`engagements/${engagementId}/shells/${sessionId}:close`, { method: 'POST' }),
  )
}

export interface ShellLauncher {
  id: string
  os: string
  command: string
}

export interface ShellUpgrade {
  payloadId: string
  url: string
  tokenSecret: string
  tokenExpiresAt: string
  launchers: ShellLauncher[]
}

// Renders the paste-ready launchers that grow the shell into a real implant
// (a single-use deploy token is minted server-side; the paste itself is the
// operator's action through the input route).
export async function upgradeShell(
  engagementId: string,
  sessionId: string,
  payloadId?: string,
  listenerId?: string,
): Promise<ShellUpgrade> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/shells/${sessionId}:upgrade`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        payloadId: payloadId ?? null,
        listenerId: listenerId ?? null,
      }),
    }),
  )
}

// --- Standalone launchers --------------------------------------
//
// The one-liner delivery surface: the same paste-ready payload fetch renders
// the shell console's upgrade produces, without a caught shell to grow from.
// The operator names the payload and the web front (or takes the engagement's
// own preference), sets the download credential's policy (uses and lifetime),
// and copies the downloader command for the target's shell family. Every
// render is kept as a row the operator can return to: re-copy the command,
// watch the credential's budget, revoke it the moment it leaks, and delete
// the row when it is spent.

export interface LauncherRow {
  launcherId: string
  payloadId: string
  // The delivered payload's library identifier -- the same fingerprint the
  // Payloads tab shows -- joined at read time; null once the payload is
  // deleted from the library.
  payloadFingerprint: string | null
  url: string
  frontName: string
  frontEndpoint: string
  tokenSecret: string
  maxUses: number
  expiresAt: string
  createdAt: string
  createdBy: string
  revokedAt: string | null
  // The live credential state, joined from the token store; null when the
  // token is no longer stored (revoked, or spent to zero).
  tokenRemainingUses: number | null
  tokenExpiresAt: string | null
  // Re-rendered on read, so the row always copies in the current shape.
  launchers: ShellLauncher[]
}

export interface RenderLauncherInput {
  payloadId?: string
  listenerId?: string
  // How many served fetches the minted credential allows: 1 = one download
  // (default), 0 = unlimited until expiry.
  maxUses?: number
  // The credential's lifetime in minutes; 30 by default.
  lifetimeMinutes?: number
}

export async function renderLaunchers(
  engagementId: string,
  input: RenderLauncherInput = {},
): Promise<LauncherRow> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/launchers`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        payloadId: input.payloadId ?? null,
        listenerId: input.listenerId ?? null,
        maxUses: input.maxUses ?? null,
        lifetimeMinutes: input.lifetimeMinutes ?? null,
      }),
    }),
  )
}

export async function listLaunchers(engagementId: string): Promise<LauncherRow[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/launchers`))
}

// Removes the row -- tidying, not disabling: the credential dies by its own
// revocation or expiry, and the trail keeps the mint.
export async function deleteLauncher(
  engagementId: string,
  launcherId: string,
): Promise<void> {
  await jsonOrThrow(
    await fetch(`engagements/${engagementId}/launchers/${launcherId}`, {
      method: 'DELETE',
    }),
  )
}

// --- Web-shell endpoints --------------------------------------
//
// The engagement's web-shell endpoints: scripts placed in targets' web
// roots, bound to the engagement by registration and driven by their
// protocol adapter. Execution is synchronous -- the request itself plays
// the beacon -- and lands as a normal task on the anchor implant row.

export interface WebShell {
  implantId: string
  url: string
  adapterId: string
  password: string
  scriptLanguage: string
  retired: boolean
  registeredAt: string
  lastProbeAt: string | null
  lastProbeOk: boolean | null
}

export interface RegisteredWebShell extends WebShell {
  script: string
}

export interface RegisterWebShellInput {
  url: string
  adapterId?: string
  password?: string
  payloadId?: string
}

export async function listWebShells(engagementId: string): Promise<WebShell[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/webshells`))
}

export interface GeneratedWebShellScript {
  payloadId: string
  adapterId: string
  scriptLanguage: string
  password: string
  script: string
  fingerprint: string
}

// Generates a web-shell script with its credential baked in, decoupled from
// any endpoint: prepare the artifact first, place it, register the URL later.
// The script lands in the payload store like any build. The credential is
// the family's own -- the baked key for the sealed Rod family, the
// connection password for the classic managers.
export async function generateWebShellScript(
  engagementId: string,
  adapterId?: string,
  password?: string,
): Promise<GeneratedWebShellScript> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/webshells/scripts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ adapterId: adapterId ?? null, password: password ?? null }),
    }),
  )
}

export async function registerWebShell(
  engagementId: string,
  input: RegisterWebShellInput,
): Promise<RegisteredWebShell> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/webshells`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        url: input.url,
        adapterId: input.adapterId ?? null,
        password: input.password ?? null,
      }),
    }),
  )
}

export async function removeWebShell(engagementId: string, implantId: string): Promise<void> {
  await jsonOrThrow<unknown>(
    await fetch(`engagements/${engagementId}/webshells/${implantId}`, { method: 'DELETE' }),
  )
}

export interface WebShellProbe {
  ok: boolean
  latencyMs: number
  detail?: string | null
}

export async function probeWebShell(
  engagementId: string,
  implantId: string,
): Promise<WebShellProbe> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/webshells/${implantId}:test`, { method: 'POST' }),
  )
}

export interface WebShellExecution {
  taskId: string
  output: string
  outcome: string
  elapsedMs: number
}

export async function executeWebShell(
  engagementId: string,
  implantId: string,
  command: string,
): Promise<WebShellExecution> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/webshells/${implantId}:exec`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ command }),
    }),
  )
}


// --- Online implant roster (presence) -------------------------
//
// The per-engagement online roster: an implant is online exactly while it
// holds an active session, so this is the live-channel projection -- session,
// capabilities, last seen -- beside the enrolled-implant record the implants
// tab holds. This is the crew's live situational-awareness view.

export interface PresenceRecord {
  sessionId: string
  implantId: string
  engagementId: string
  capabilities: string[]
  onlineAt: string
  lastSeenAt: string
}

export async function listOnline(engagementId: string): Promise<PresenceRecord[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/presence`))
}

// --- Payload build with OPSEC profile (//) --------------
//
// Builds an implant artifact, baking in the beacon profile (mode, sleep,
// jitter), the kill date, and the malleable transport profile (endpoint,
// fallbacks, URIs, headers, timing, envelope). These are baked at generation;
// a live implant's profile is read-only after enrollment, so OPSEC changes go
// through a rebuild + redeploy.

export interface BuildPayloadInput {
  language: string | null
  class: string | null
  targetOs: string | null
  targetArch: string | null
  // Naming the engagement's listener supplies the endpoint from its record;
  // the manual endpoint covers shapes with no listener yet. Mutually
  // exclusive on the wire. The contact rides the front the listener names --
  // there is no second endpoint to pick.
  listenerId: string | null
  endpoint: string | null
  fallbackEndpoints: string[] | null
  enrollPath: string | null
  userAgent: string | null
  headers: Record<string, string> | null
  requestTimeoutSeconds: number | null
  // The enroll-body shape only. Contact protection is its own knob below --
  // the two phases are independent.
  envelope: string | null
  // Whether the artifact's contact bodies seal under the per-artifact key
  // minted at build. Null (the default) leaves it on; false is the explicit
  // lab-debug opt-out -- the plaintext frame body, unauthenticated over
  // cleartext and unencrypted over TLS.
  contactProtection: boolean | null
  mode: string | null
  sleepSeconds: number | null
  jitterSeconds: number | null
  killDate: string | null
  // The baked enrollment credential's scope: how many implants the artifact's
  // token may enroll, and how long the mint stays redeemable. Absent values
  // default server-side to single use inside the artifact's kill window.
  tokenMaxUses: number | null
  tokenLifetimeSeconds: number | null
  // The delivery tier: 'implant' (the default, the full product) or
  // 'loader' -- the small dialer that fetches and runs a stored payload
  // from memory. A loader build must name the payload it delivers.
  kind: string | null
  // The payload a loader delivers: this engagement's stored implant. Null
  // on implant builds; required on loader builds.
  deliversPayloadId: string | null
  // The artifact's form factor: 'exe' (the default), 'exe-trimmed', or
  // 'aot'. Compatibility spellings over one native binary -- the Rust unit
  // emits the same artifact for each; 'dll' is retired with the .NET
  // implant and refused server side. Null leaves the 'exe' default.
  format: string | null
  // Retired as a pick: the front's listener owns the certificate posture
  // and the build inherits it. Null always; a non-null value may only
  // agree with the named front (the server refuses a contradiction).
  trust: string | null
}

export interface BuildPayloadResult {
  artifactId: string
  engagementId: string
  class: string
  language: string
  contentType: string
  fingerprint: string
  size: number
  builtAt: string
  // The id of the enrollment credential baked into the artifact, when the
  // build minted one -- enough to revoke it, never the secret itself.
  tokenId: string | null
}

// --- Background payload builds ---------------------------------
//
// A build invokes a real toolchain, so it runs as a server-side job: POST
// returns 202 with the queued job immediately, and the build finishes into
// the payload store and the audit trail whatever happens to the page that
// asked. The job list is the durable view -- a browser refresh reloads it and
// keeps showing progress, so a build is never lost to navigation.

export type BuildJobState = 'queued' | 'running' | 'completed' | 'failed'

export interface BuildJob {
  jobId: string
  engagementId: string
  state: BuildJobState
  requestedBy: string
  requestedAt: string
  startedAt: string | null
  completedAt: string | null
  class: string
  language: string
  target: string
  endpoint: string
  mode: string
  error: string | null
  artifact: BuildPayloadResult | null
}

export async function enqueueBuildJob(
  engagementId: string,
  input: BuildPayloadInput,
): Promise<BuildJob> {
  const response = await fetch(`engagements/${engagementId}/payload-jobs`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  })
  return jsonOrThrow(response)
}

export async function listBuildJobs(engagementId: string): Promise<BuildJob[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/payload-jobs`))
}

// --- Payload library -----------------------------------------
//
// The payload store's own listing: the durable answer to the bounded,
// process-local build-job list. A payload built weeks ago stays here --
// downloadable, its baked credential revocable, and deletable (which also
// stops any fetch of it) -- whatever happened to the Recent builds
// queue or the teamserver process in between.

export interface PayloadSummary {
  artifactId: string
  class: string
  language: string
  target: string | null
  endpoint: string | null
  contentType: string
  size: number
  fingerprint: string
  builtAt: string
  tokenId: string | null
  // The baked credential's live state, joined from the token store at list
  // time. Null fields with a tokenId present mean the token is no longer
  // stored -- spent-and-removed, revoked, or expired and swept -- which reads
  // as "no enrollments left."
  tokenMaxUses: number | null
  tokenRemainingUses: number | null
  tokenExpiresAt: string | null
  // A generated web-shell script's connection credential, read back out of
  // the stored script by its family's adapter; null for every other
  // artifact class.
  credential: string | null
  // The bake-time build parameters; null on payloads built before the
  // snapshot existed, null fields inside mean "the build's default".
  build: PayloadBuildProfile | null
  // The delivery tier: 'implant', or 'loader' with the delivery reference
  // naming the artifact it delivers. Null on records that predate the kind
  // axis.
  kind: string | null
  deliversPayloadId: string | null
}

export interface PayloadBuildProfile {
  mode: string | null
  sleepSeconds: number | null
  jitterSeconds: number | null
  killDate: string | null
  tokenMaxUses: number | null
  enrollPath: string | null
  userAgent: string | null
  requestTimeoutSeconds: number | null
  envelope: string | null
  contactProtection: boolean | null
  fallbackEndpoints: string[] | null
  // The artifact's form-factor spelling, null meaning the 'exe' default (or
  // a record that predates the axis). Informational over the in-tree Rust
  // unit: every spelling is the same native binary, and delivery posture is
  // the launcher step's choice.
  format: string | null
  // The TLS trust posture, null meaning the pinned default: which roots the
  // artifact's TLS dials trust -- the baked engagement CA, or the public
  // set for a real-domain front.
  trust: string | null
}

export async function listPayloads(engagementId: string): Promise<PayloadSummary[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/payloads`))
}

// Removes the stored payload: the bytes and the library row are gone, and a
// fetch of it 404s from now on. The deletion is audited server-side.
export async function deletePayload(engagementId: string, artifactId: string): Promise<void> {
  await jsonOrThrow<unknown>(
    await fetch(`engagements/${engagementId}/payloads/${artifactId}`, { method: 'DELETE' }),
  )
}

// --- System info ------------------------------------------------
//
// The system page's read: the host's own facts (OS, runtime, uptime) and
// every build unit's self-reported environment -- toolchains found or
// missing, source trees located, per-target std and cross-linker
// readiness. The preflight a deployment checks itself against.

export interface SystemInfo {
  server: {
    host: string
    operatingSystem: string
    runtime: string
    startedAt: string
    now: string
  }
  // Which adapter each store runs on (the startup composition's choice),
  // and where the data lives -- the data directory, or the Postgres target
  // with its credentials masked.
  persistence: {
    dataDirectory: string
    postgresTarget: string | null
    stores: { concern: string; adapter: string }[]
  }
  buildUnits: BuildUnitEnvironment[]
}

export interface BuildUnitEnvironment {
  language: string
  // ready | partial | unavailable
  status: string
  findings: { level: string; area: string; detail: string }[]
  targets: {
    triple: string
    target: string
    stdInstalled: boolean
    linkerFound: boolean
    linker: string
  }[]
}

export async function getSystemInfo(): Promise<SystemInfo> {
  return jsonOrThrow(await fetch('system'))
}

// --- Diagnostics ------------------------------------------------
//
// The deployment's own health read (architecture.md Sec 15.3, ADR-008): the
// five dimensions over in-process counters and aggregate store reads -- no
// Prometheus, no exporter. The deployment admin's alone; every number is a
// deployment-wide aggregate with no engagement dimension.

export interface DiagnosticsReport {
  beacons: {
    // Cumulative since process start: one row per latency bound, in order.
    latencyBuckets: { label: string; count: number }[]
  }
  taskQueue: {
    queued: number
    dispatched: number
    completed: number
    cancelled: number
  }
  operatorStreams: {
    connectedStreams: number
  }
  builds: {
    inFlight: number
    total: number
    succeeded: number
    failed: number
    minMs: number | null
    meanMs: number | null
    maxMs: number | null
    p95Ms: number | null
  }
  modules: {
    loaded: { name: string; verbs: string[] }[]
    verbsRegistered: number
    verbsPlaceholder: number
  }
}

export async function getDiagnostics(): Promise<DiagnosticsReport> {
  return jsonOrThrow(await fetch('diagnostics'))
}

// --- Runtime settings -----------------------------------------
//
// Operator-adjustable server settings. The session-presence pair (the
// staleness sweep's threshold and interval) applies live -- the sweeper reads
// the current values on every pass -- and the server persists changes so a
// restart keeps them.

export interface SessionSettings {
  thresholdMinutes: number
  sweepIntervalMinutes: number
}

export async function getSessionSettings(): Promise<SessionSettings> {
  return jsonOrThrow(await fetch('settings/sessions'))
}

// The build section: the shared cargo target dir -- the warm compile cache.
// Null keeps builds hermetic (a fresh target dir per build).
export interface BuildSettings {
  rustTargetDir: string | null
}

export async function getBuildSettings(): Promise<BuildSettings> {
  return jsonOrThrow(await fetch('settings/build'))
}

export async function putBuildSettings(input: BuildSettings): Promise<BuildSettings> {
  return jsonOrThrow(
    await fetch('settings/build', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ rustTargetDir: input.rustTargetDir ?? '' }),
    }),
  )
}

export async function putSessionSettings(input: SessionSettings): Promise<SessionSettings> {
  return jsonOrThrow(
    await fetch('settings/sessions', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
    }),
  )
}

// --- Automation rules (architecture.md Sec 10.4) ------------------------------
//
// The declarative rules the engine fires while no operator watches: a trigger
// (a fixed interval, or one of the triggerable live events with optional
// condition), one action (a task issuance), and guard state the row carries
// back -- the fire count, the next-fire stamp a time trigger survives a
// restart through, and the refusal streak that ends in the engine parking the
// rule. Firing attributes to the synthetic "automation" operator; the audit
// trail is the record.

export interface AutomationRule {
  id: string
  engagementId: string
  name: string
  triggerKind: 'interval' | 'event'
  intervalSeconds: number | null
  eventKind: string | null
  onlyImplantId: string | null
  completedVerb: string | null
  targetImplantId: string
  verb: string
  arguments: string
  cooldownSeconds: number
  maxFirings: number
  enabled: boolean
  fireCount: number
  lastFiredAt: string | null
  nextFireAt: string | null
  consecutiveRefusals: number
  createdAt: string
  createdBy: string
  disabledAt: string | null
}

export type AutomationTriggerInput =
  | { kind: 'interval'; intervalSeconds: number }
  | { kind: 'event'; eventKind: string }

export interface CreateAutomationRuleInput {
  name: string
  trigger: AutomationTriggerInput
  // Event-trigger conditions: fire only for this implant's events, or (on
  // task-completed triggers) only when this verb completed. Null matches all.
  onlyImplantId?: string | null
  completedVerb?: string | null
  targetImplantId: string
  verb: string
  arguments: string
  // Optional guard overrides; the server defaults cooldown to the interval
  // (event rules: one minute) and the cap to 100.
  cooldownSeconds?: number | null
  maxFirings?: number | null
}

export async function listAutomationRules(engagementId: string): Promise<AutomationRule[]> {
  const page = await jsonOrThrow<{ rules: AutomationRule[] }>(
    await fetch(`engagements/${engagementId}/automation-rules`),
  )
  return page.rules
}

export async function createAutomationRule(
  engagementId: string,
  input: CreateAutomationRuleInput,
): Promise<AutomationRule> {
  const response = await fetch(`engagements/${engagementId}/automation-rules`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  })
  return jsonOrThrow(response)
}

export async function enableAutomationRule(
  engagementId: string,
  ruleId: string,
): Promise<AutomationRule> {
  const response = await fetch(`engagements/${engagementId}/automation-rules/${ruleId}:enable`, {
    method: 'POST',
  })
  return jsonOrThrow(response)
}

// The cancel: a disabled rule fires nothing until re-enabled from now.
export async function disableAutomationRule(
  engagementId: string,
  ruleId: string,
): Promise<AutomationRule> {
  const response = await fetch(`engagements/${engagementId}/automation-rules/${ruleId}:disable`, {
    method: 'POST',
  })
  return jsonOrThrow(response)
}

export async function deleteAutomationRule(engagementId: string, ruleId: string): Promise<void> {
  const response = await fetch(`engagements/${engagementId}/automation-rules/${ruleId}`, {
    method: 'DELETE',
  })
  await jsonOrThrow<unknown>(response)
}

// --- Webhook notifications (architecture.md Sec 4.4) ----------------------------
//
// The engagement's out-of-band channels: each subscription pushes the live
// events it names to one webhook URL -- the SSE frame shape verbatim, so a
// channel receives exactly what a connected console receives. The URL is the
// channel's bearer secret (the audit trail never records it; plain http is
// loopback-only), delivery is single-attempt and best-effort like the bus it
// rides, and three failures in a row park the channel with the cause in the
// trail.

export interface WebhookSubscription {
  id: string
  engagementId: string
  name: string
  url: string
  eventKinds: string[]
  enabled: boolean
  deliveryCount: number
  lastDeliveredAt: string | null
  consecutiveFailures: number
  lastFailureReason: string | null
  createdAt: string
  createdBy: string
  disabledAt: string | null
}

// The event kinds the server's notifiable whitelist admits. Duplicated here
// because the server exposes no "notifiable kinds" read; the server stays the
// authority -- anything else it refuses at registration with a readable 422.
// Unlike automation's trigger list this includes the shell kinds: a caught
// shell is exactly what an off-console operator wants to hear about.
export const NOTIFIABLE_EVENT_KINDS: readonly { value: string; label: string }[] = [
  { value: 'SessionOpened', label: 'Session opened' },
  { value: 'SessionClosed', label: 'Session closed' },
  { value: 'ShellSessionOpened', label: 'Shell caught' },
  { value: 'ShellSessionEnded', label: 'Shell lost' },
  { value: 'TaskIssued', label: 'Task issued' },
  { value: 'TaskCompleted', label: 'Task completed' },
  { value: 'TaskCancelled', label: 'Task cancelled' },
  { value: 'ImplantRetired', label: 'Implant retired' },
  { value: 'PayloadFetched', label: 'Payload fetched' },
]

export interface RegisterWebhookInput {
  name: string
  url: string
  eventKinds: string[]
}

export async function listWebhookSubscriptions(
  engagementId: string,
): Promise<WebhookSubscription[]> {
  const page = await jsonOrThrow<{ subscriptions: WebhookSubscription[] }>(
    await fetch(`engagements/${engagementId}/webhook-subscriptions`),
  )
  return page.subscriptions
}

export async function registerWebhookSubscription(
  engagementId: string,
  input: RegisterWebhookInput,
): Promise<WebhookSubscription> {
  const response = await fetch(`engagements/${engagementId}/webhook-subscriptions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  })
  return jsonOrThrow(response)
}

export async function enableWebhookSubscription(
  engagementId: string,
  subscriptionId: string,
): Promise<WebhookSubscription> {
  const response = await fetch(
    `engagements/${engagementId}/webhook-subscriptions/${subscriptionId}:enable`,
    { method: 'POST' },
  )
  return jsonOrThrow(response)
}

// The cancel: a disabled channel pushes nothing until re-enabled, which also
// clears the failure run.
export async function disableWebhookSubscription(
  engagementId: string,
  subscriptionId: string,
): Promise<WebhookSubscription> {
  const response = await fetch(
    `engagements/${engagementId}/webhook-subscriptions/${subscriptionId}:disable`,
    { method: 'POST' },
  )
  return jsonOrThrow(response)
}

// Pushes one test frame through the same delivery path -- the verification an
// operator runs before relying on a channel overnight. The outcome is the
// answer either way; a failed test is a successful verification of a dead
// channel.
export async function testWebhookSubscription(
  engagementId: string,
  subscriptionId: string,
): Promise<{ delivered: boolean; outcome: string }> {
  const response = await fetch(
    `engagements/${engagementId}/webhook-subscriptions/${subscriptionId}:test`,
    { method: 'POST' },
  )
  return jsonOrThrow(response)
}

export async function deleteWebhookSubscription(
  engagementId: string,
  subscriptionId: string,
): Promise<void> {
  const response = await fetch(
    `engagements/${engagementId}/webhook-subscriptions/${subscriptionId}`,
    { method: 'DELETE' },
  )
  await jsonOrThrow<unknown>(response)
}

// The engagement's browser hooks (architecture.md Sec 5.2, Sec 8): the
// served `<script src>` artifacts a script-injection foothold loads. Each
// mint renders the in-tree hook with its bake (credential, seal, cadence,
// verbs) and stores it as a served payload record; the answer's URL is
// what lands in the injected page tag.

export interface MintHookInput {
  // The engagement's http(s) listener whose public endpoint fronts the hook.
  listenerId: string
  // The poll cadence's base interval, seconds.
  sleepSeconds?: number
  // The jitter half-width, seconds.
  jitterSeconds?: number
  // 'aesgcm' (the default -- the mainstream sealed posture) or 'none' (the
  // cleartext posture for hooking plain-http pages where crypto.subtle is
  // unavailable).
  envelope?: 'aesgcm' | 'none'
  // The enrollment budget: every hooked browser's enroll spends one use.
  // Zero is unlimited.
  tokenMaxUses?: number
  killDate?: string | null
}

export interface MintedHook {
  hookId: string
  url: string
  snippet: string
  testPageUrl: string
  listenerName: string
  envelope: string
  sleepSeconds: number
  jitterSeconds: number
  tokenMaxUses: number
  fingerprint: string
}

export interface HookRow {
  hookId: string
  url: string
  endpoint: string | null
  envelope: string | null
  sleepSeconds: number | null
  jitterSeconds: number | null
  builtAt: string
  fingerprint: string
}

export async function mintHook(
  engagementId: string,
  input: MintHookInput,
): Promise<MintedHook> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/hooks`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        listenerId: input.listenerId,
        sleepSeconds: input.sleepSeconds ?? null,
        jitterSeconds: input.jitterSeconds ?? null,
        envelope: input.envelope ?? null,
        tokenMaxUses: input.tokenMaxUses ?? null,
        killDate: input.killDate ?? null,
      }),
    }),
  )
}

export async function listHooks(engagementId: string): Promise<HookRow[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/hooks`))
}

export async function revokeHook(engagementId: string, hookId: string): Promise<void> {
  const response = await fetch(`engagements/${engagementId}/hooks/${hookId}`, {
    method: 'DELETE',
  })
  await jsonOrThrow<unknown>(response)
}

// --- Delivery campaigns (architecture.md Sec 11.5) ----------------------------

// One recipient row of a campaign: the delivery status, the evidence
// timestamps, and the lure link whose unguessable id is the credential. The
// executed binding names the implant that redeemed the baked credential --
// the only proof the artifact ran.
export interface CampaignRecipient {
  recipientId: string
  email: string
  name: string | null
  status: 'pending' | 'building' | 'sent' | 'failed'
  failure: string | null
  lureId: string
  lureUrl: string | null
  tokenId: string | null
  payloadId: string | null
  sentAt: string | null
  openedAt: string | null
  clickedAt: string | null
  executedAt: string | null
  enrolledImplantId: string | null
  // The recon asset this recipient was selected from, when it was -- the
  // targeting vocabulary's link back (Sec 15.4).
  reconAssetId: string | null
}

// A campaign row. The relay password never appears on read-back -- the
// server holds it to present it again, and neither the trail nor this API
// carries it.
export interface Campaign {
  campaignId: string
  name: string
  state: 'draft' | 'launched' | 'completed' | 'revoked'
  listenerId: string
  listenerName: string | null
  from: string
  relayHost: string
  relayPort: number
  relayTls: 'starttls' | 'implicit' | 'none'
  relayUsername: string | null
  bodyIsHtml: boolean
  total: number
  sent: number
  failed: number
  opened: number
  clicked: number
  executed: number
  createdAt: string
  launchedAt: string | null
  completedAt: string | null
  revokedAt: string | null
  recipients: CampaignRecipient[] | null
}

// The create body. The build profile rides as the same shape the Build
// panel posts; the server parses it with the build pipeline's own parser
// and refuses the token knobs (the campaign mints per recipient itself).
// A recipient names exactly one of a hand-typed address or a recon asset
// -- the targeting vocabulary selects directly.
export type CampaignRecipientInput =
  | { email: string; name?: string }
  | { reconAssetId: string; name?: string }

export interface CreateCampaignInput {
  name: string
  listenerId: string
  relayHost: string
  relayPort: number
  relayTls: 'starttls' | 'implicit' | 'none'
  relayUsername?: string
  relayPassword?: string
  from: string
  subject: string
  body: string
  bodyIsHtml: boolean
  recipients: CampaignRecipientInput[]
  build: Record<string, unknown>
}

export async function listCampaigns(engagementId: string): Promise<Campaign[]> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/campaigns`))
}

export async function getCampaign(engagementId: string, campaignId: string): Promise<Campaign> {
  return jsonOrThrow(await fetch(`engagements/${engagementId}/campaigns/${campaignId}`))
}

export async function createCampaign(
  engagementId: string,
  input: CreateCampaignInput,
): Promise<Campaign> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/campaigns`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: input.name,
        listenerId: input.listenerId,
        relay: {
          host: input.relayHost,
          port: input.relayPort,
          tls: input.relayTls,
          username: input.relayUsername ?? null,
          password: input.relayPassword ?? null,
        },
        from: input.from,
        template: {
          subject: input.subject,
          body: input.body,
          bodyIsHtml: input.bodyIsHtml,
        },
        recipients: input.recipients.map((r) =>
          'reconAssetId' in r
            ? { reconAssetId: r.reconAssetId, name: r.name ?? null }
            : { email: r.email, name: r.name ?? null },
        ),
        build: input.build,
      }),
    }),
  )
}

export async function launchCampaign(
  engagementId: string,
  campaignId: string,
): Promise<{ campaignId: string; state: string }> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/campaigns/${campaignId}:launch`, { method: 'POST' }),
  )
}

export async function revokeCampaign(
  engagementId: string,
  campaignId: string,
): Promise<{ campaignId: string; state: string }> {
  return jsonOrThrow(
    await fetch(`engagements/${engagementId}/campaigns/${campaignId}:revoke`, { method: 'POST' }),
  )
}
