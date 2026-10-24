// Timeline stage classification: which lifecycle stage an audit kind
// belongs to (architecture.md Sec 15.4, ADR-013 -- the timeline filters
// by entity, operator, and stage). Pure and client-side on purpose: the
// server records kinds, not stages -- the grouping is a reading of the
// kinds the slots already organize, and an unknown kind (a future
// domain's events) classifies as 'other' rather than guessing.

export type TimelineStage = 'setup' | 'recon' | 'delivery' | 'action' | 'assets' | 'collab' | 'other'

export const TIMELINE_STAGES: readonly TimelineStage[] = [
  'setup',
  'recon',
  'delivery',
  'action',
  'assets',
  'collab',
  'other',
]

// The stage each known kind reads in, pinned against the server's
// AuditEventKind vocabulary. Setup holds the engagement's own
// administration and standing config; recon the pre-foothold scoping
// and the target picture; delivery everything that exists to produce a
// foothold (listeners, payloads, lures, caught and placed shells);
// action the fleet and its tasking; assets what the engagement
// gathered; collab the mutable collaboration rows that ride the stream
// outside the hash chain.
const KIND_STAGES: Readonly<Record<string, TimelineStage>> = {
  // setup
  EngagementCreated: 'setup',
  EngagementUpdated: 'setup',
  EngagementFrozen: 'setup',
  EngagementUnfrozen: 'setup',
  EngagementRetired: 'setup',
  EngagementMemberAdded: 'setup',
  EngagementMemberRoleChanged: 'setup',
  EngagementMemberRemoved: 'setup',
  OperatorAccountChanged: 'setup',
  RoeUpdated: 'setup',
  TaskRoeRefused: 'setup',
  DeployTokenMinted: 'setup',
  DeployTokenRevoked: 'setup',
  AutomationRuleCreated: 'setup',
  AutomationRuleUpdated: 'setup',
  AutomationRuleDeleted: 'setup',
  WebhookSubscriptionCreated: 'setup',
  WebhookSubscriptionUpdated: 'setup',
  WebhookSubscriptionDeleted: 'setup',
  WebhookDelivered: 'setup',
  EvidenceExported: 'setup',

  // recon
  ReconLookupCompleted: 'recon',
  ReconScanCompleted: 'recon',
  ReconScanRefused: 'recon',
  ReconAssetRecorded: 'recon',
  ReconAssetDeleted: 'recon',
  HostNoteAdded: 'recon',
  HostLabeled: 'recon',

  // delivery
  ListenerChanged: 'delivery',
  ListenerFrontChanged: 'delivery',
  PayloadBuilt: 'delivery',
  PayloadDeleted: 'delivery',
  PayloadFetched: 'delivery',
  CampaignStateChanged: 'delivery',
  CampaignMessageSent: 'delivery',
  CampaignLinkServed: 'delivery',
  HookMinted: 'delivery',
  HookFetched: 'delivery',
  ShellSessionOpened: 'delivery',
  ShellSessionEnded: 'delivery',
  ShellSessionClosed: 'delivery',
  ShellSessionInput: 'delivery',
  ShellSessionEncodingChanged: 'delivery',
  WebShellRegistered: 'delivery',
  WebShellRemoved: 'delivery',
  WebShellProbed: 'delivery',

  // action
  ImplantEnrolled: 'action',
  ImplantRetired: 'action',
  ImplantNoteAdded: 'action',
  ImplantLabeled: 'action',
  SessionOpened: 'action',
  SessionClosed: 'action',
  TaskIssued: 'action',
  TaskDispatched: 'action',
  TaskCompleted: 'action',
  TaskCancelled: 'action',
  TaskExpired: 'action',
  ChannelInput: 'action',
  RelayBound: 'action',
  RelayClosed: 'action',
  AutomationRuleFired: 'action',
  // The console's saved command sequences: tasking tooling, kept where
  // the tasking reads.
  TaskSnippetSaved: 'action',
  TaskSnippetDeleted: 'action',

  // assets
  ExfilCaptured: 'assets',
  ArtifactAttached: 'assets',
  ArtifactViewed: 'assets',
  LlmSummaryGenerated: 'assets',

  // collab (mutable rows riding the stream outside the chain)
  Comment: 'collab',
  ChatMessage: 'collab',
}

export function stageOfKind(kind: string): TimelineStage {
  return KIND_STAGES[kind] ?? 'other'
}
