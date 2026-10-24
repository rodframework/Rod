// The timeline's stage filter reads the audit kinds into lifecycle
// stages (ADR-013). These checks pin the mapping against the server's
// full AuditEventKind vocabulary -- every member classifies, nothing
// lands in 'other' by accident -- and the fallback a future domain's
// unknown kind takes.

import { describe, expect, it } from 'vitest'
import { TIMELINE_STAGES, stageOfKind } from './timelineStage'

// The server's AuditEventKind enum, verbatim (Rod.Audit). When a new
// kind ships, it must appear here so the 'other' check below keeps
// meaning "no known kind misclassifies".
const SERVER_KINDS = [
  'EngagementCreated',
  'DeployTokenMinted',
  'ImplantEnrolled',
  'SessionOpened',
  'TaskIssued',
  'TaskDispatched',
  'TaskCompleted',
  'TaskCancelled',
  'PayloadBuilt',
  'PayloadDeleted',
  'ImplantRetired',
  'ImplantNoteAdded',
  'ArtifactAttached',
  'ExfilCaptured',
  'RoeUpdated',
  'EngagementMemberAdded',
  'EngagementMemberRoleChanged',
  'EngagementMemberRemoved',
  'TaskRoeRefused',
  'ChannelInput',
  'RelayBound',
  'RelayClosed',
  'EngagementFrozen',
  'EvidenceExported',
  'EngagementRetired',
  'EngagementUnfrozen',
  'DeployTokenRevoked',
  'EngagementUpdated',
  'ShellSessionOpened',
  'ShellSessionEnded',
  'ShellSessionClosed',
  'ShellSessionInput',
  'ShellSessionEncodingChanged',
  'WebShellRegistered',
  'WebShellRemoved',
  'WebShellProbed',
  'PayloadFetched',
  'AutomationRuleFired',
  'AutomationRuleCreated',
  'AutomationRuleUpdated',
  'AutomationRuleDeleted',
  'WebhookDelivered',
  'WebhookSubscriptionCreated',
  'WebhookSubscriptionUpdated',
  'WebhookSubscriptionDeleted',
  'SessionClosed',
  'TaskSnippetSaved',
  'TaskSnippetDeleted',
  'ImplantLabeled',
  'HostNoteAdded',
  'HostLabeled',
  'ArtifactViewed',
  'LlmSummaryGenerated',
  'ReconLookupCompleted',
  'ReconScanCompleted',
  'ReconScanRefused',
  'HookMinted',
  'HookFetched',
  'CampaignStateChanged',
  'CampaignMessageSent',
  'CampaignLinkServed',
  'ListenerFrontChanged',
  'ListenerChanged',
  'TaskExpired',
  'OperatorAccountChanged',
  'ReconAssetRecorded',
  'ReconAssetDeleted',
  // The mutable projections the merged stream carries beside the chain.
  'Comment',
  'ChatMessage',
]

describe('stageOfKind', () => {
  it('classifies every known server kind out of other', () => {
    for (const kind of SERVER_KINDS) {
      expect(stageOfKind(kind), kind).not.toBe('other')
    }
  })

  it('reads representative kinds into their lifecycle stages', () => {
    expect(stageOfKind('EngagementCreated')).toBe('setup')
    expect(stageOfKind('RoeUpdated')).toBe('setup')
    expect(stageOfKind('ReconLookupCompleted')).toBe('recon')
    expect(stageOfKind('HostLabeled')).toBe('recon')
    expect(stageOfKind('CampaignMessageSent')).toBe('delivery')
    expect(stageOfKind('PayloadBuilt')).toBe('delivery')
    expect(stageOfKind('ShellSessionOpened')).toBe('delivery')
    expect(stageOfKind('TaskCompleted')).toBe('action')
    expect(stageOfKind('ImplantEnrolled')).toBe('action')
    expect(stageOfKind('ExfilCaptured')).toBe('assets')
    expect(stageOfKind('Comment')).toBe('collab')
    expect(stageOfKind('ChatMessage')).toBe('collab')
  })

  it('falls back to other for an unknown kind', () => {
    expect(stageOfKind('SomeFutureDomainThing')).toBe('other')
    expect(stageOfKind('')).toBe('other')
  })

  it('keeps the stage list in display order', () => {
    expect(TIMELINE_STAGES).toEqual([
      'setup',
      'recon',
      'delivery',
      'action',
      'assets',
      'collab',
      'other',
    ])
  })
})
