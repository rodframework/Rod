// The related-entities sidebar's acceptance (architecture.md Sec 15.4,
// ADR-013): entity detail pages draw their sidebar from the unified
// entity model's explicit links. The builders are pure over the
// server's real DTO shapes -- lineage and the campaign leg off the
// implant provenance read, recipient selection off the campaign detail,
// and the recipients-to-implants join off the campaign and fleet lists.

import { describe, expect, it } from 'vitest'
import type {
  Campaign,
  CampaignRecipient,
  Implant,
  ImplantDetail,
  ReconAsset,
} from './api'
import { relatedForAsset, relatedForCampaign, relatedForImplant } from './related'

const guid = (tail: string): string => `1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b${tail}`

const implant = (over: Partial<Implant> = {}): Implant => ({
  implantId: guid('0001'),
  engagementId: 'e',
  class: 'Implant',
  killDate: null,
  createdAt: '2026-01-01T00:00:00Z',
  isOnline: false,
  retiredAt: null,
  parentImplantId: null,
  hostname: 'web01',
  os: 'linux',
  arch: 'amd64',
  username: 'svc',
  sleepSeconds: 30,
  jitterSeconds: 5,
  deployedBy: null,
  enrolledViaListenerId: null,
  lastSeenAt: null,
  lastCarrier: null,
  carriers: null,
  campaignId: null,
  campaignRecipientId: null,
  ...over,
})

const asset = (over: Partial<ReconAsset> = {}): ReconAsset => ({
  assetId: guid('a001'),
  kind: 'email',
  value: 'alice@target.example',
  displayName: null,
  sourceArtifactId: null,
  createdBy: guid('o001'),
  createdAt: '2026-01-01T00:00:00Z',
  ...over,
})

const recipient = (over: Partial<CampaignRecipient> = {}): CampaignRecipient => ({
  recipientId: guid('r001'),
  email: 'alice@target.example',
  name: null,
  status: 'sent',
  failure: null,
  lureId: guid('l001'),
  lureUrl: null,
  tokenId: null,
  payloadId: null,
  sentAt: '2026-01-02T00:00:00Z',
  openedAt: null,
  clickedAt: null,
  executedAt: null,
  enrolledImplantId: null,
  reconAssetId: null,
  ...over,
})

describe('relatedForImplant', () => {
  const detail = (over: Partial<ImplantDetail> = {}): ImplantDetail => ({
    implant: implant(),
    provenance: { ancestors: [], children: [], campaign: null },
    ...over,
  })

  it('draws the lineage from the provenance chain, ancestors first', () => {
    const groups = relatedForImplant(
      'e',
      detail({
        provenance: {
          ancestors: [
            {
              implantId: guid('0002'),
              hostname: null,
              os: 'windows',
              class: 'Implant',
              createdAt: '2025-12-01T00:00:00Z',
              retiredAt: '2025-12-20T00:00:00Z',
            },
          ],
          children: [
            {
              implantId: guid('0003'),
              hostname: 'db01',
              class: 'Implant',
              createdAt: '2026-01-05T00:00:00Z',
            },
          ],
          campaign: null,
        },
      }),
      [],
    )
    const lineage = groups.find((g) => g.label === 'Lineage')
    expect(lineage?.links.map((l) => l.title)).toEqual([guid('0002').slice(0, 8), 'db01'])
    expect(lineage?.links[0].subtitle).toContain('retired')
    expect(lineage?.links[0].hash).toBe(`#/engagements/e/action/implants/${guid('0002')}`)
  })

  it('links the campaign leg and the recon asset it selected from', () => {
    const assetId = guid('a001')
    const groups = relatedForImplant(
      'e',
      detail({
        provenance: {
          ancestors: [],
          children: [],
          campaign: {
            campaignId: guid('c001'),
            campaignName: 'q3-renewal',
            campaignState: 'launched',
            recipientId: guid('r001'),
            email: 'alice@target.example',
            name: null,
            sentAt: '2026-01-02T00:00:00Z',
            openedAt: null,
            clickedAt: null,
            executedAt: '2026-01-03T00:00:00Z',
            payloadId: null,
            reconAssetId: assetId,
          },
        },
      }),
      [asset()],
    )
    expect(groups.find((g) => g.label === 'Campaign')?.links[0].hash).toBe(
      `#/engagements/e/delivery/campaigns/${guid('c001')}`,
    )
    const assetGroup = groups.find((g) => g.label === 'Recon asset')
    expect(assetGroup?.links[0].title).toBe('alice@target.example')
    expect(assetGroup?.links[0].hash).toBe(`#/engagements/e/recon/assets/${assetId}`)
  })

  it('links an unresolvable asset by its id tail rather than dropping it', () => {
    const groups = relatedForImplant(
      'e',
      detail({
        provenance: {
          ancestors: [],
          children: [],
          campaign: {
            campaignId: guid('c001'),
            campaignName: 'n',
            campaignState: 'launched',
            recipientId: guid('r001'),
            email: 'x',
            name: null,
            sentAt: null,
            openedAt: null,
            clickedAt: null,
            executedAt: null,
            payloadId: null,
            reconAssetId: guid('a009'),
          },
        },
      }),
      [],
    )
    expect(groups.find((g) => g.label === 'Recon asset')?.links[0].title).toBe(guid('a009').slice(0, 8))
  })

  it('stays empty for a plain campaign-free enrollment with no lineage', () => {
    expect(relatedForImplant('e', detail(), [])).toEqual([])
  })
})

describe('relatedForCampaign', () => {
  it('collects unique recon assets and the enrolled implants', () => {
    const campaign: Campaign = {
      campaignId: guid('c001'),
      name: 'q3',
      state: 'completed',
      listenerId: guid('l001'),
      listenerName: 'front',
      from: 'billing@lure.example',
      relayHost: 'smtp',
      relayPort: 587,
      relayTls: 'starttls',
      relayUsername: null,
      bodyIsHtml: false,
      total: 2,
      sent: 2,
      failed: 0,
      opened: 1,
      clicked: 1,
      executed: 1,
      createdAt: '2026-01-01T00:00:00Z',
      launchedAt: null,
      completedAt: null,
      revokedAt: null,
      recipients: [
        recipient({ reconAssetId: guid('a001'), enrolledImplantId: guid('0001') }),
        recipient({ recipientId: guid('r002'), reconAssetId: guid('a001') }),
      ],
    }
    const groups = relatedForCampaign('e', campaign, [implant()], [asset()])
    expect(groups.find((g) => g.label === 'Recon assets')?.links).toHaveLength(1)
    const implantsGroup = groups.find((g) => g.label === 'Implants')
    expect(implantsGroup?.links[0].title).toBe('web01')
    expect(implantsGroup?.links[0].hash).toBe(`#/engagements/e/action/implants/${guid('0001')}`)
  })
})

describe('relatedForAsset', () => {
  it('walks recipients to the referencing campaigns and enrolled implants', () => {
    const target = asset()
    const campaign: Campaign = {
      campaignId: guid('c001'),
      name: 'q3',
      state: 'launched',
      listenerId: guid('l001'),
      listenerName: null,
      from: 'a',
      relayHost: 's',
      relayPort: 587,
      relayTls: 'none',
      relayUsername: null,
      bodyIsHtml: false,
      total: 1,
      sent: 1,
      failed: 0,
      opened: 0,
      clicked: 0,
      executed: 1,
      createdAt: '2026-01-01T00:00:00Z',
      launchedAt: null,
      completedAt: null,
      revokedAt: null,
      recipients: [recipient({ reconAssetId: target.assetId, enrolledImplantId: guid('0001') })],
    }
    const enrolled = implant({
      implantId: guid('0001'),
      campaignId: campaign.campaignId,
      campaignRecipientId: campaign.recipients![0].recipientId,
    })
    const bystander = implant({ implantId: guid('0009'), hostname: 'other' })
    const groups = relatedForAsset('e', target, [campaign], [enrolled, bystander])
    expect(groups.find((g) => g.label === 'Campaigns')?.links[0].title).toBe('q3')
    expect(groups.find((g) => g.label === 'Implants')?.links.map((l) => l.title)).toEqual(['web01'])
  })

  it('reads empty for an unreferenced asset', () => {
    expect(relatedForAsset('e', asset(), [], [])).toEqual([])
  })
})
