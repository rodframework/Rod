import { useEffect, useMemo, useRef, useState } from 'react'
import {
  type Campaign,
  type Engagement,
  type Implant,
  type ReconAsset,
  type SearchHitRow,
  type TaskSnippet,
  deleteTaskSnippet,
  issueTask,
  listCampaigns,
  listEngagements,
  listImplants,
  listReconAssets,
  listTaskSnippets,
  searchEngagement,
} from '../api'
import { loadCapabilityGroups, verbAttributes, type CapabilityGroup } from '../capabilities'
import type { CapabilityDescriptor } from '../api'
import { searchHitHash } from '../collabFormat'
import { fuzzyBest } from '../fuzzy'
import { osIconFor } from '../osKind'
import { SLOTS, engagementPath } from '../slots'
import { formForDescriptor } from '../verbForms'
import { DIRECT_VERBS } from '../views/implantMenu'
import { Icon, type IconName } from './Icons'
import { TaskDialog } from './TaskDialog'

// The command palette: the keyboard's reach over what the mouse already
// reaches (docs/operations/operator-ui.md). One fuzzy field whose entries
// are navigation, implants, verbs, and task snippets -- every entry routes
// to the handler the mouse would reach (a hash navigation, the verb's
// dialog, the ordinary issue route), so the palette is a dispatcher, not a
// surface of its own. A verb or snippet picked with no implant context
// switches the same field to target picking: the second Enter issues
// against the pick, the first against the console's implant when the
// palette opened from one.

type Section = 'find' | 'snippet' | 'verb' | 'implant' | 'navigate'

interface Entry {
  key: string
  section: Section
  label: string
  detail?: string
  keywords: string[]
  // Context bonuses (an online implant outranks an offline twin, snippets
  // outrank single verbs) so equal fuzzy scores order by what the operator
  // is most likely reaching for.
  bonus: number
  icon?: IconName
  run: () => void
}

// A pending action in target-picking mode: what issues once an implant is
// picked. A verb either issues outright (the zero-argument set the menu
// shares) or opens its argument dialog.
type Pending =
  | { kind: 'verb'; verb: string; direct: boolean }
  | { kind: 'snippet'; snippet: TaskSnippet }

const SECTION_LABELS: Record<Section, string> = {
  find: 'find',
  snippet: 'snippet',
  verb: 'verb',
  implant: 'implant',
  navigate: 'go',
}

const MAX_ENTRIES = 14

// Where a search hit lands is collabFormat's routing (checked beside the
// corpus vocabulary it switches on); the palette only renders the entry.

export function CommandPalette({
  engagementId,
  contextImplantId,
  onClose,
}: {
  // The engagement the route sits in; null on the engagements list, where
  // the palette reaches engagements and global pages only.
  engagementId: string | null
  // The session console's implant when the palette opened from one -- the
  // context one-Enter issuance runs against.
  contextImplantId: string | null
  onClose: () => void
}) {
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // Target-picking mode: the pending verb or snippet re-queries the fleet.
  const [pending, setPending] = useState<Pending | null>(null)
  // The verb dialog the palette opens (the same component the console
  // opens), pinned to the resolved target.
  const [dialog, setDialog] = useState<{ verb: string; implantId: string } | null>(null)
  // The snippet inspector: steps listed, delete offered, run resolved like
  // the palette's own run path.
  const [inspect, setInspect] = useState<TaskSnippet | null>(null)

  const [implants, setImplants] = useState<Implant[]>([])
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [assets, setAssets] = useState<ReconAsset[]>([])
  const [snippets, setSnippets] = useState<TaskSnippet[]>([])
  // The engagement-wide server search (architecture.md Sec 15.3): the same
  // query that fuzzy-matches the palette's local entries also asks the
  // tsvector index, so three-plus characters reach task output, comments,
  // artifact metadata, credentials, and chat -- surfaces a local list can
  // never hold.
  const [serverHits, setServerHits] = useState<SearchHitRow[]>([])
  const [groups, setGroups] = useState<CapabilityGroup[]>([])
  const [engagements, setEngagements] = useState<Engagement[]>([])
  const [loaded, setLoaded] = useState(false)

  const listRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // Load what the palette reaches on open: the fleet, the verb registry,
  // and the engagement's snippets (or the engagement list outside an
  // engagement). A failed load keeps the palette usable for what did load.
  useEffect(() => {
    let cancelled = false
    const load = engagementId
      ? Promise.all([
          listImplants(engagementId).catch(() => [] as Implant[]),
          loadCapabilityGroups().catch(() => [] as CapabilityGroup[]),
          listTaskSnippets(engagementId).catch(() => [] as TaskSnippet[]),
          // The entity kinds with detail pages: the palette jumps
          // straight to them, beside the implants it already reached.
          listCampaigns(engagementId).catch(() => [] as Campaign[]),
          listReconAssets(engagementId).catch(() => [] as ReconAsset[]),
        ]).then(([fleet, catalog, saved, campaigns, assets]) => {
          if (cancelled) return
          setImplants(fleet)
          setGroups(catalog)
          setSnippets(saved)
          setCampaigns(campaigns)
          setAssets(assets)
        })
      : listEngagements()
          .catch(() => [] as Engagement[])
          .then((all) => {
            if (cancelled) return
            setEngagements(all)
          })
    void load.finally(() => {
      if (!cancelled) setLoaded(true)
    })
    return () => {
      cancelled = true
    }
  }, [engagementId])

  useEffect(() => {
    inputRef.current?.focus()
  }, [pending])

  useEffect(() => {
    if (!engagementId || pending || query.trim().length < 3) {
      setServerHits([])
      return
    }
    let cancelled = false
    const timer = setTimeout(() => {
      void searchEngagement(engagementId, query.trim())
        .then((hits) => {
          if (!cancelled) setServerHits(hits)
        })
        .catch(() => {
          if (!cancelled) setServerHits([])
        })
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [engagementId, pending, query])

  const navigate = (hash: string) => {
    window.location.hash = hash
    onClose()
  }

  const consoleOf = (implantId: string) =>
    engagementId ? engagementPath(engagementId, 'implants', implantId, 'interact') : '#/engagements'

  // Issues one step of a run. Returns null on success, the refusal text on
  // failure -- the ordinary gates decide, verbatim like a typed task.
  const issueStep = async (implantId: string, verb: string, args: string): Promise<string | null> => {
    if (!engagementId) return 'No engagement is open.'
    try {
      await issueTask(engagementId, { implantId, verb, arguments: args })
      return null
    } catch (e) {
      return e instanceof Error ? e.message : String(e)
    }
  }

  // The snippet run path: every step issued through the ordinary route, a
  // refused step refuses alone and the rest still issue. Success lands the
  // palette on the target's console, where the sequence reads line by
  // line; a partial refusal keeps the palette open with the reason.
  const runSnippet = async (snippet: TaskSnippet, implantId: string) => {
    setBusy(true)
    setError(null)
    const refusals: string[] = []
    for (const step of snippet.steps) {
      const refusal = await issueStep(implantId, step.verb, step.arguments)
      if (refusal) refusals.push(`${step.verb}: ${refusal}`)
    }
    setBusy(false)
    if (refusals.length === 0) {
      navigate(consoleOf(implantId))
      return
    }
    setError(
      `${snippet.steps.length - refusals.length} of ${snippet.steps.length} steps issued — refused: ${refusals[0]}`,
    )
  }

  const dispatch = async (action: Pending, implantId: string) => {
    if (action.kind === 'snippet') {
      await runSnippet(action.snippet, implantId)
      return
    }
    if (!action.direct) {
      // An argument-bearing verb: its dialog asks, pinned to the target.
      setDialog({ verb: action.verb, implantId })
      return
    }
    // A zero-argument verb issues outright, like the menu does.
    setBusy(true)
    const refusal = await issueStep(implantId, action.verb, '')
    setBusy(false)
    if (refusal) {
      setError(refusal)
      return
    }
    navigate(consoleOf(implantId))
  }

  // Resolves the target for a verb or snippet: the console's implant when
  // the palette has that context, else the same field re-queries the fleet.
  const resolveTarget = (action: Pending) => {
    if (contextImplantId) {
      void dispatch(action, contextImplantId)
      return
    }
    setPending(action)
    setQuery('')
    setSelected(0)
    setError(null)
  }

  const descriptors = useMemo(
    () => groups.flatMap((g) => g.descriptors.map((d) => ({ ...d, group: g.label }))),
    [groups],
  )
  const attributesByVerb = useMemo(() => verbAttributes(groups), [groups])
  const descriptorByVerb = useMemo(() => {
    const map = new Map<string, CapabilityDescriptor>()
    for (const group of groups) {
      for (const descriptor of group.descriptors) map.set(descriptor.verb, descriptor)
    }
    return map
  }, [groups])
  const contextImplant = implants.find((i) => i.implantId === contextImplantId) ?? null

  const implantEntry = (implant: Implant, run: () => void): Entry => ({
    key: `implant:${implant.implantId}`,
    section: 'implant',
    label: implant.hostname ?? implant.implantId.slice(0, 8),
    detail: [
      implant.username,
      [implant.os, implant.arch].filter(Boolean).join('/'),
      implant.retiredAt ? 'retired' : implant.isOnline ? 'online' : 'offline',
    ]
      .filter(Boolean)
      .join(' · '),
    keywords: [implant.hostname ?? '', implant.username ?? '', implant.implantId],
    bonus: implant.isOnline && !implant.retiredAt ? 5 : 0,
    run,
  })

  const entries = useMemo<Entry[]>(() => {
    const list: Entry[] = []
    if (!pending && engagementId) {
      // The server's answers outrank the local fuzzy set: an operator who
      // typed a real needle wants the needle, not a similarly-spelled verb.
      for (const hit of serverHits) {
        list.push({
          key: `find:${hit.corpus}:${hit.refId}`,
          section: 'find',
          label: hit.title,
          detail: hit.excerpt,
          keywords: [hit.excerpt],
          bonus: 20,
          run: () => navigate(searchHitHash(engagementId, hit)),
        })
      }
    }
    if (pending) {
      // Target picking: only the fleet is reachable, Enter issues.
      for (const implant of implants) {
        list.push(
          implantEntry(implant, () => {
            const action = pending
            setPending(null)
            setQuery('')
            void dispatch(action, implant.implantId)
          }),
        )
      }
      return list
    }

    if (engagementId) {
      for (const snippet of snippets) {
        list.push({
          key: `snippet:${snippet.id}`,
          section: 'snippet',
          label: snippet.name,
          detail: `${snippet.steps.length} step${snippet.steps.length === 1 ? '' : 's'} · ${snippet.steps
            .map((s) => s.verb)
            .join(', ')}`,
          keywords: [snippet.name, ...snippet.steps.map((s) => s.verb)],
          bonus: 10,
          icon: 'copy',
          run: () => resolveTarget({ kind: 'snippet', snippet }),
        })
      }
      for (const descriptor of descriptors) {
        list.push({
          key: `verb:${descriptor.verb}`,
          section: 'verb',
          label: descriptor.verb,
          detail: descriptor.group,
          keywords: [descriptor.verb, descriptor.group],
          bonus: 0,
          icon: 'terminal',
          run: () =>
            resolveTarget({
              kind: 'verb',
              verb: descriptor.verb,
              // The direct-or-dialog call the implant menu makes: a verb
              // whose declared schema carries no parameters issues outright
              // (the menu's zero-argument mirror covers descriptors without
              // a schema), anything else opens the schema-rendered form.
              direct:
                descriptor.parameters !== null &&
                descriptor.parameters.length === 0 &&
                DIRECT_VERBS.includes(descriptor.verb),
            }),
        })
      }
      for (const implant of implants) {
        list.push(implantEntry(implant, () => navigate(consoleOf(implant.implantId))))
      }
      for (const campaign of campaigns) {
        list.push({
          key: `campaign:${campaign.campaignId}`,
          section: 'navigate',
          label: campaign.name,
          detail: `campaign · ${campaign.state}`,
          keywords: [campaign.name, 'campaign'],
          bonus: 0,
          icon: 'send',
          run: () => navigate(engagementPath(engagementId, 'campaigns', campaign.campaignId)),
        })
      }
      for (const asset of assets) {
        list.push({
          key: `asset:${asset.assetId}`,
          section: 'navigate',
          label: asset.displayName ?? asset.value,
          detail: `recon asset · ${asset.kind}`,
          keywords: [asset.value, asset.displayName ?? '', 'recon asset', asset.kind],
          bonus: 0,
          icon: 'target',
          run: () => navigate(engagementPath(engagementId, 'assets', asset.assetId)),
        })
      }
    } else {
      for (const engagement of engagements) {
        list.push({
          key: `engagement:${engagement.engagementId}`,
          section: 'navigate',
          label: engagement.name,
          detail: engagement.ownerHandle ?? undefined,
          keywords: [engagement.name, engagement.ownerHandle, engagement.engagementId],
          bonus: 0,
          icon: 'globe',
          run: () => navigate(`#/engagements/${engagement.engagementId}`),
        })
      }
    }

    // Navigation entries: the slots' sub-surfaces -- one entry per
    // sub, detailed by its slot, so the palette's go-section mirrors the
    // sidebar's promise at the finer grain the keyboard wants.
    for (const slot of SLOTS) {
      for (const item of slot.subs) {
        list.push({
          key: `sub:${item.id}`,
          section: 'navigate',
          label: item.label,
          detail: slot.label,
          keywords: [item.label, item.id, slot.label],
          bonus: 0,
          icon: item.icon,
          run: () =>
            navigate(engagementId ? engagementPath(engagementId, item.id) : '#/engagements'),
        })
      }
    }
    list.push(
      {
        key: 'page:engagements',
        section: 'navigate',
        label: 'Engagements',
        detail: 'all engagements',
        keywords: ['engagements'],
        bonus: 0,
        icon: 'globe',
        run: () => navigate('#/engagements'),
      },
      {
        key: 'page:settings',
        section: 'navigate',
        label: 'Settings',
        detail: 'teamserver runtime',
        keywords: ['settings'],
        bonus: 0,
        icon: 'settings',
        run: () => navigate('#/settings'),
      },
      {
        key: 'page:system',
        section: 'navigate',
        label: 'System',
        detail: 'host and build environment',
        keywords: ['system'],
        bonus: 0,
        icon: 'activity',
        run: () => navigate('#/system'),
      },
    )
    return list
    // The run handlers close over live state by design; the memo deps are
    // the data the list is built from, and every handler re-reads its
    // action from the loop variable rather than from a cached snapshot.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending, engagementId, implants, snippets, descriptors, engagements, contextImplantId, serverHits, campaigns, assets])

  const matches = useMemo(() => {
    if (query.trim() === '') return entries.slice(0, MAX_ENTRIES)
    const scored: { entry: Entry; score: number }[] = []
    for (const entry of entries) {
      const score = fuzzyBest(query, [
        entry.label,
        ...(entry.detail ? [entry.detail] : []),
        ...entry.keywords,
      ])
      if (score !== null) scored.push({ entry, score: score + entry.bonus })
    }
    scored.sort((a, b) => b.score - a.score || a.entry.label.localeCompare(b.entry.label))
    return scored.slice(0, MAX_ENTRIES).map((s) => s.entry)
  }, [entries, query])

  useEffect(() => {
    setSelected(0)
  }, [query, pending])

  // Keep the keyboard-selected row visible while arrowing through.
  useEffect(() => {
    const row = listRef.current?.querySelector<HTMLElement>(`[data-index='${selected}']`)
    row?.scrollIntoView({ block: 'nearest' })
  }, [selected])

  const onKey = (event: React.KeyboardEvent) => {
    if (event.key === 'Escape') {
      if (pending) {
        setPending(null)
        setQuery('')
        return
      }
      onClose()
      return
    }
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setSelected((s) => Math.min(s + 1, matches.length - 1))
      return
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault()
      setSelected((s) => Math.max(s - 1, 0))
      return
    }
    if (event.key === 'Enter') {
      event.preventDefault()
      if (busy || matches.length === 0) return
      const entry = matches[Math.min(selected, matches.length - 1)]
      entry?.run()
    }
  }

  const pendingLabel =
    pending?.kind === 'snippet'
      ? `Run snippet '${pending.snippet.name}' on…`
      : pending?.kind === 'verb'
        ? `Issue ${pending.verb} on…`
        : null

  return (
    <>
      <div className="palette-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="palette" role="dialog" aria-label="Command palette" onKeyDown={onKey}>
        <div className="palette-input">
            <Icon name={pending ? 'chevronRight' : 'terminal'} className="wire-icon" />
            <input
              ref={inputRef}
              value={query}
              aria-label={pendingLabel ?? 'Command palette search'}
              placeholder={
                pendingLabel ??
                (engagementId
                  ? 'Search snippets, verbs, implants, pages…'
                  : 'Search engagements, pages…')
              }
              onChange={(e) => setQuery(e.target.value)}
              disabled={busy}
              autoFocus
            />
            <kbd>esc</kbd>
          </div>
          {error && <p className="error palette-error">{error}</p>}
          <div className="palette-list" ref={listRef}>
            {!loaded && <div className="palette-empty muted">Loading…</div>}
            {loaded && matches.length === 0 && (
              <div className="palette-empty muted">
                {pending ? 'No implant matches.' : 'Nothing matches.'}
              </div>
            )}
            {matches.map((entry, index) => (
              <button
                key={entry.key}
                data-index={index}
                className={`palette-item${index === selected ? ' selected' : ''}`}
                onMouseEnter={() => setSelected(index)}
                onClick={() => entry.run()}
              >
                {entry.icon ? (
                  <Icon name={entry.icon} className="wire-icon" />
                ) : (
                  <span className="wire-icon" />
                )}
                <span className="palette-item-label">{entry.label}</span>
                {entry.detail && <span className="palette-item-detail muted">{entry.detail}</span>}
                {entry.section === 'snippet' && (
                  <span
                    className="palette-item-manage"
                    title="Show the snippet's steps, run, or delete"
                    onClick={(e) => {
                      e.stopPropagation()
                      const snippet = snippets.find((s) => `snippet:${s.id}` === entry.key)
                      if (snippet) setInspect(snippet)
                    }}
                  >
                    …
                  </span>
                )}
                <span className="palette-item-section">{SECTION_LABELS[entry.section]}</span>
              </button>
            ))}
          </div>
          <div className="palette-foot muted">
            <span>↑↓ move</span>
            <span>↵ run</span>
            <span>esc close</span>
            {contextImplantId && !pending && contextImplant && (
              <span className="palette-context">
                on <Icon name={osIconFor(contextImplant.os)} className="wire-icon" />
                {contextImplant.hostname ?? contextImplantId.slice(0, 8)}
              </span>
            )}
          </div>
        </div>
      </div>

      {dialog && engagementId && (
        <TaskDialog
          engagementId={engagementId}
          implantId={dialog.implantId}
          verb={dialog.verb}
          form={formForDescriptor(descriptorByVerb.get(dialog.verb))}
          attributes={attributesByVerb.get(dialog.verb) ?? {}}
          onClose={() => setDialog(null)}
          onIssued={() => {
            const target = dialog.implantId
            setDialog(null)
            navigate(consoleOf(target))
          }}
        />
      )}

      {inspect && engagementId && (
        <SnippetInspector
          engagementId={engagementId}
          snippet={inspect}
          contextImplantId={contextImplantId}
          onDeleted={() => {
            setInspect(null)
            setSnippets((current) => current.filter((s) => s.id !== inspect.id))
          }}
          onRun={(implantId) => {
            setInspect(null)
            void runSnippet(inspect, implantId)
          }}
          onClose={() => setInspect(null)}
        />
      )}
    </>
  )
}

// The snippet inspector: the saved sequence at a glance -- each step's verb
// and arguments in issue order -- with delete (the armed two-click pattern
// every destructive action in the console uses) and run (the same target
// resolution the palette applies; from a session console the implant is
// the context).
function SnippetInspector({
  engagementId,
  snippet,
  contextImplantId,
  onDeleted,
  onRun,
  onClose,
}: {
  engagementId: string
  snippet: TaskSnippet
  contextImplantId: string | null
  onDeleted: () => void
  onRun: (implantId: string) => void
  onClose: () => void
}) {
  const [error, setError] = useState<string | null>(null)
  const [armed, setArmed] = useState(false)

  const onDelete = async () => {
    if (!armed) {
      setArmed(true)
      return
    }
    try {
      await deleteTaskSnippet(engagementId, snippet.id)
      onDeleted()
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="card modal">
        <div className="inline-form">
          <h3 style={{ marginRight: 'auto' }}>Snippet “{snippet.name}”</h3>
          <button className="ghost" onClick={onClose}>
            Close
          </button>
        </div>
        <p className="muted">
          {snippet.steps.length} step{snippet.steps.length === 1 ? '' : 's'}, saved{' '}
          {new Date(snippet.createdAt).toLocaleString()} — issued verbatim through the ordinary
          tasking gates, each step attributed to the running operator.
        </p>
        <ol className="snippet-steps">
          {snippet.steps.map((step, index) => (
            <li key={index}>
              <code>{step.verb}</code>
              {step.arguments && <span className="muted"> {step.arguments}</span>}
            </li>
          ))}
        </ol>
        {error && <p className="error">{error}</p>}
        <div className="inline-form">
          <button
            className="primary"
            disabled={!contextImplantId}
            title={
              contextImplantId
                ? "Run every step against this console's implant"
                : 'Run from the palette (it asks for the target) or from an implant console'
            }
            onClick={() => contextImplantId && onRun(contextImplantId)}
          >
            Run
          </button>
          <button className={armed ? 'danger' : 'ghost'} onClick={() => void onDelete()}>
            {armed ? 'Confirm' : 'Delete'}
          </button>
        </div>
      </div>
    </div>
  )
}
