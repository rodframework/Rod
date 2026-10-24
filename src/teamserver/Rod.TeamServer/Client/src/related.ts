// Related-entities sidebar contract (architecture.md Sec 15.4, ADR-013):
// every entity detail page carries one, drawn from the explicit entity
// links the unified entity model ships -- never point-to-point feature
// APIs. The builders here are pure over resolved DTOs: a view fetches
// the entity's own reads (the provenance detail, the campaign detail,
// the recon-asset roster, the implant list) and hands them in; the
// builder folds them into link groups the panel renders. The hashes are
// the route grammar's -- an entity link is navigation, nothing more.

import type {
  Campaign,
  CampaignRecipient,
  Implant,
  ImplantDetail,
  ReconAsset,
} from './api'
import { engagementPath } from './slots'

export interface RelatedLink {
  key: string
  title: string
  subtitle?: string
  hash: string
}

export interface RelatedGroup {
  label: string
  links: RelatedLink[]
}

const implantLabel = (id: string, hostname: string | null): string =>
  hostname ?? id.slice(0, 8)

// One implant's sidebar: the lineage the provenance chain draws (the
// lateral-movement tree -- ancestors root-first, then the children this
// implant derived), the campaign whose lure it followed, and the recon
// asset the target was selected from when it was.
export function relatedForImplant(
  engagementId: string,
  detail: ImplantDetail,
  assets: readonly ReconAsset[],
): RelatedGroup[] {
  const groups: RelatedGroup[] = []
  const { provenance } = detail
  if (provenance.ancestors.length > 0 || provenance.children.length > 0) {
    groups.push({
      label: 'Lineage',
      links: [
        ...provenance.ancestors.map((a) => ({
          key: `ancestor:${a.implantId}`,
          title: implantLabel(a.implantId, a.hostname),
          subtitle: [
            'ancestor',
            a.class,
            a.retiredAt ? 'retired' : null,
            a.os,
          ]
            .filter(Boolean)
            .join(' · '),
          hash: engagementPath(engagementId, 'implants', a.implantId),
        })),
        ...provenance.children.map((c) => ({
          key: `child:${c.implantId}`,
          title: implantLabel(c.implantId, c.hostname),
          subtitle: ['child', c.class].filter(Boolean).join(' · '),
          hash: engagementPath(engagementId, 'implants', c.implantId),
        })),
      ],
    })
  }
  const campaign = provenance.campaign
  if (campaign) {
    groups.push({
      label: 'Campaign',
      links: [
        {
          key: `campaign:${campaign.campaignId}`,
          title: campaign.campaignName,
          subtitle: `lure followed · ${campaign.campaignState} · ${campaign.email}`,
          hash: engagementPath(engagementId, 'campaigns', campaign.campaignId),
        },
      ],
    })
    const asset = campaign.reconAssetId
      ? assets.find((a) => a.assetId === campaign.reconAssetId)
      : undefined
    if (campaign.reconAssetId) {
      groups.push({
        label: 'Recon asset',
        links: [
          {
            key: `asset:${campaign.reconAssetId}`,
            title: asset ? asset.value : campaign.reconAssetId.slice(0, 8),
            subtitle: asset ? `${asset.kind} · selected as target` : 'recon asset',
            hash: engagementPath(engagementId, 'assets', campaign.reconAssetId),
          },
        ],
      })
    }
  }
  return groups
}

// A campaign's sidebar: the recon assets its recipients were selected
// from, and the implants that redeemed a recipient's baked credential --
// executed is the enrollment itself.
export function relatedForCampaign(
  engagementId: string,
  campaign: Campaign,
  implants: readonly Implant[],
  assets: readonly ReconAsset[],
): RelatedGroup[] {
  const recipients = campaign.recipients ?? []
  const assetLinks = new Map<string, RelatedLink>()
  for (const recipient of recipients) {
    if (!recipient.reconAssetId) continue
    const existing = assetLinks.get(recipient.reconAssetId)
    const asset = assets.find((a) => a.assetId === recipient.reconAssetId)
    assetLinks.set(
      recipient.reconAssetId,
      existing ?? {
        key: `asset:${recipient.reconAssetId}`,
        title: asset ? asset.value : recipient.reconAssetId.slice(0, 8),
        subtitle: asset ? asset.kind : 'recon asset',
        hash: engagementPath(engagementId, 'assets', recipient.reconAssetId),
      },
    )
  }
  const implantLinks: RelatedLink[] = []
  for (const recipient of recipients) {
    if (!recipient.enrolledImplantId) continue
    const implant = implants.find((i) => i.implantId === recipient.enrolledImplantId)
    implantLinks.push({
      key: `implant:${recipient.enrolledImplantId}`,
      title: implant ? implantLabel(implant.implantId, implant.hostname) : recipient.enrolledImplantId.slice(0, 8),
      subtitle: ['enrolled', implant?.class, recipient.email].filter(Boolean).join(' · '),
      hash: engagementPath(engagementId, 'implants', recipient.enrolledImplantId),
    })
  }
  const groups: RelatedGroup[] = []
  if (assetLinks.size > 0) {
    groups.push({ label: 'Recon assets', links: [...assetLinks.values()] })
  }
  if (implantLinks.length > 0) {
    groups.push({ label: 'Implants', links: implantLinks })
  }
  return groups
}

// The recipients of one campaign that were selected from a given asset
// -- the join the asset sidebar walks to reach the implants.
export function recipientsFromAsset(
  campaign: Campaign,
  assetId: string,
): CampaignRecipient[] {
  return (campaign.recipients ?? []).filter((r) => r.reconAssetId === assetId)
}

// A recon asset's sidebar: the campaigns whose recipients selected it,
// and the implants those recipients enrolled -- the targeting
// vocabulary's reach, read back. Campaign details carry recipients (the
// list read omits them), so the view passes the fetched details.
export function relatedForAsset(
  engagementId: string,
  asset: ReconAsset,
  campaignDetails: readonly Campaign[],
  implants: readonly Implant[],
): RelatedGroup[] {
  const referencing = campaignDetails.filter((c) => recipientsFromAsset(c, asset.assetId).length > 0)
  const recipientIds = new Set(
    referencing.flatMap((c) => recipientsFromAsset(c, asset.assetId).map((r) => r.recipientId)),
  )
  const enrolled = implants.filter((i) => i.campaignRecipientId && recipientIds.has(i.campaignRecipientId))
  const groups: RelatedGroup[] = []
  if (referencing.length > 0) {
    groups.push({
      label: 'Campaigns',
      links: referencing.map((c) => ({
        key: `campaign:${c.campaignId}`,
        title: c.name,
        subtitle: `${recipientsFromAsset(c, asset.assetId).length} recipient(s) · ${c.state}`,
        hash: engagementPath(engagementId, 'campaigns', c.campaignId),
      })),
    })
  }
  if (enrolled.length > 0) {
    groups.push({
      label: 'Implants',
      links: enrolled.map((i) => ({
        key: `implant:${i.implantId}`,
        title: implantLabel(i.implantId, i.hostname),
        subtitle: ['enrolled', i.class].filter(Boolean).join(' · '),
        hash: engagementPath(engagementId, 'implants', i.implantId),
      })),
    })
  }
  return groups
}
