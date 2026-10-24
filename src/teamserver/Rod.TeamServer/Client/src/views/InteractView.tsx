import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  type CapabilityDescriptor,
  type EngagementTask,
  type Implant,
  type PresenceRecord,
  type SessionOperator,
  cancelTask,
  issueTask,
  listImplantTasks,
  listImplants,
} from '../api'
import { loadCapabilityGroups, type CapabilityGroup } from '../capabilities'
import { osIconFor } from '../osKind'
import { CommentsPanel } from '../components/CommentsPanel'
import { ContextMenu } from '../components/ContextMenu'
import { useContextMenu } from '../contextMenuState'
import { FileBrowser } from '../components/FileBrowser'
import { Icon } from '../components/Icons'
import { InteractPane } from '../components/InteractPane'
import { ProcessBrowser } from '../components/ProcessBrowser'
import { ShellDialog } from '../components/ShellDialog'
import { SnippetSaveDialog } from '../components/SnippetSaveDialog'
import { StatusBadge } from '../components/StatusBadge'
import { TaskDialog } from '../components/TaskDialog'
import { TaskOutputView } from '../components/TaskOutputView'
import { formForDescriptor, isChannelVerb } from '../verbForms'
import { ellipsize } from '../format'
import { ago, formatSeconds, useNow } from '../when'
import { implantMenuEntries } from './implantMenu'

// The session console: one implant, rendered as the terminal operators expect
// from a C2. A title bar names the device, the identity, and the live state;
// below it the transcript -- this implant's task history in causal order,
// each task a line with its status, output expanding under the line (short
// output shows outright, long output folds); the channel pane for interactive
// tasks opens inside the same flow, above the prompt, so the typing never
// changes windows. The prompt at the bottom is the keyboard path: a plain
// line runs as a shell command, a handful of prefixed words map to the
// common verbs, and 'help' lists them. Everything the prompt cannot express
// (an upload's file picker, the full verb table) stays one menu away in the
// title bar's three-dot menu -- the same menu the implant rows open.

// Short outputs render unfolded; anything longer folds behind the line until
// the operator opens it -- a recon.ps dump should not bury the prompt.
const UNFOLDED_OUTPUT_LIMIT = 400

interface QuickCommand {
  usage: string
  note: string
}

const QUICK_HELP: readonly QuickCommand[] = [
  { usage: '‹command line›', note: 'runs as a shell command on the target' },
  { usage: 'interact', note: 'open the interactive shell dialog (a real terminal: PTY, Ctrl+C works; history survives)' },
  { usage: 'sleep <interval> [jitter]', note: 'retune the contact cadence (10s, 5m, 0 0 = back-to-back, near-interactive)' },
  { usage: 'ps', note: 'list processes (the browser pane is in the menu)' },
  { usage: 'kill <pid>', note: 'terminate a process' },
  { usage: 'screenshot', note: 'capture the display' },
  { usage: 'hostenum', note: 'local host facts' },
  { usage: 'portscan <host> <start-end>', note: 'scan a host' },
  { usage: 'services <host> <ports>', note: 'probe services' },
  { usage: 'download <path>', note: 'pull a file back' },
  { usage: 'upload', note: 'push a file (opens the picker)' },
  { usage: 'files', note: 'open the file browser pane' },
  { usage: 'raw <verb> [args…]', note: 'issue any verb directly' },
]

export function InteractView({
  engagementId,
  implantId,
  operator,
  onlineTick,
  onlineImplants,
}: {
  engagementId: string
  implantId: string
  operator: SessionOperator
  onlineTick: number
  onlineImplants: PresenceRecord[]
}) {
  const [implant, setImplant] = useState<Implant | null>(null)
  const [missing, setMissing] = useState(false)
  const [tasks, setTasks] = useState<EngagementTask[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  // Output blocks the operator flipped against their default fold state.
  const [toggled, setToggled] = useState<Set<string>>(new Set())
  const [interactTask, setInteractTask] = useState<string | null>(null)
  // The interactive-shell dialog: the menu's "Interactive shell" and the
  // `interact` shortcut both open it. It owns the session lifecycle --
  // continuing a live shell or starting a new one under the history.
  const [shellOpen, setShellOpen] = useState(false)
  const [dialogVerb, setDialogVerb] = useState<string | null>(null)
  const [processes, setProcesses] = useState(false)
  const [filesOpen, setFilesOpen] = useState(false)
  // The snippet save flow reads this console's transcript; the palette
  // (Ctrl+K) is where a saved sequence is replayed from.
  const [saveSnippet, setSaveSnippet] = useState(false)
  const [capabilityGroups, setCapabilityGroups] = useState<CapabilityGroup[]>([])
  const [line, setLine] = useState('')
  const [hint, setHint] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const menu = useContextMenu()
  const transcriptRef = useRef<HTMLDivElement>(null)
  const pinnedRef = useRef(true)

  useEffect(() => {
    void loadCapabilityGroups()
      .then(setCapabilityGroups)
      .catch((e) => setError(String(e)))
  }, [])

  const refresh = useCallback(async () => {
    try {
      const [implants, page] = await Promise.all([
        listImplants(engagementId),
        listImplantTasks(engagementId, implantId),
      ])
      setImplant(implants.find((i) => i.implantId === implantId) ?? null)
      setMissing(implants.every((i) => i.implantId !== implantId))
      setTasks(page.items)
      setCursor(page.nextCursor)
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }, [engagementId, implantId])

  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  // A stale toggle set or channel pane must not survive an engagement switch.
  useEffect(() => {
    setToggled(new Set())
    setInteractTask(null)
    setShellOpen(false)
  }, [engagementId, implantId])

  const loadOlder = useCallback(async () => {
    if (!cursor) return
    try {
      const page = await listImplantTasks(engagementId, implantId, cursor)
      setTasks((current) => [...current, ...page.items])
      setCursor(page.nextCursor)
    } catch (e) {
      setError(String(e))
    }
  }, [engagementId, implantId, cursor])

  // The full descriptors by verb: attributes badge the dialogs, parameters
  // render the forms, and the output kind keys the typed panels -- whatever
  // the registry declares, module verbs included.
  const descriptorByVerb = useMemo(() => {
    const map = new Map<string, CapabilityDescriptor>()
    for (const group of capabilityGroups) {
      for (const descriptor of group.descriptors) map.set(descriptor.verb, descriptor)
    }
    return map
  }, [capabilityGroups])

  const presence = onlineImplants.find((p) => p.implantId === implantId)

  // The quiet clock: the offline branch's "last seen 2m ago" is derived from
  // the passage of time, so it re-renders on its own instead of waiting for a
  // live event that (by definition) is not coming.
  const now = useNow(30_000)

  // The transcript follows the newest line only while the operator is parked
  // at the bottom (a terminal, not a jump scroll); scrolling up to read pins
  // the view until they return down.
  useEffect(() => {
    const el = transcriptRef.current
    if (el && pinnedRef.current) el.scrollTop = el.scrollHeight
  }, [tasks, interactTask, toggled])

  const onTranscriptScroll = () => {
    const el = transcriptRef.current
    if (!el) return
    pinnedRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80
  }

  const issue = useCallback(
    async (verb: string, args: string) => {
      setBusy(true)
      pinnedRef.current = true
      try {
        const task = await issueTask(engagementId, { implantId, verb, arguments: args })
        setHint(null)
        await refresh()
        return task
      } catch (e) {
        setError(String(e))
        throw e
      } finally {
        setBusy(false)
      }
    },
    [engagementId, implantId, refresh],
  )

  const onQuick = async (event: React.FormEvent) => {
    event.preventDefault()
    const trimmed = line.trim()
    if (!trimmed || busy) return
    setLine('')
    const space = trimmed.indexOf(' ')
    const head = space === -1 ? trimmed : trimmed.slice(0, space)
    const rest = space === -1 ? '' : trimmed.slice(space + 1).trim()
    try {
      switch (head) {
        case 'help':
          setHint(QUICK_HELP.map((c) => `${c.usage} — ${c.note}`).join('    ·    '))
          return
        case 'interact':
          setShellOpen(true)
          return
        case 'sleep':
          await issue('beacon.sleep', rest)
          return
        case 'shell':
          await issue('shell.exec', rest)
          return
        case 'ps':
          await issue('recon.ps', '')
          return
        case 'kill':
          await issue('proc.kill', rest.split(/\s+/)[0] ?? '')
          return
        case 'screenshot':
          await issue('collect.screenshot', '')
          return
        case 'hostenum':
          await issue('recon.hostenum', '')
          return
        case 'portscan':
          await issue('recon.portscan', rest)
          return
        case 'services':
          await issue('recon.service', rest)
          return
        case 'download':
          await issue('file.pull', rest)
          return
        case 'files':
          setFilesOpen(true)
          return
        case 'upload':
          // The one shortcut that cannot read its argument off a command
          // line: it opens the picker dialog instead of issuing inline.
          setDialogVerb('file.push')
          return
        case 'raw': {
          const verb = rest.split(/\s+/)[0] ?? ''
          if (!verb) {
            setHint('raw <verb> [args…]')
            return
          }
          await issue(verb, rest.slice(verb.length).trim())
          return
        }
        default:
          await issue('shell.exec', trimmed)
      }
    } catch {
      // issue() already surfaced the error.
    }
  }

  const onCancel = async (taskId: string) => {
    if (!window.confirm(`Cancel queued task ${taskId.slice(0, 8)}? It will never be dispatched.`)) {
      return
    }
    try {
      await cancelTask(engagementId, taskId)
      await refresh()
    } catch (e) {
      setError(String(e))
    }
  }

  const toggleToggled = (taskId: string) => {
    setToggled((current) => {
      const next = new Set(current)
      if (next.has(taskId)) next.delete(taskId)
      else next.add(taskId)
      return next
    })
  }

  if (missing) {
    return (
      <div className="card">
        <h3>Session</h3>
        <div className="empty">
          <Icon name="cpu" />
          Implant {implantId.slice(0, 8)} is not enrolled in this engagement.{' '}
          <a href={`#/engagements/${engagementId}/action/implants`}>Back to the implants</a>.
        </div>
      </div>
    )
  }

  const menuEntries = implant
    ? implantMenuEntries(implant, {
        onShell: () => setShellOpen(true),
        onIssue: (verb) => {
          void issue(verb, '')
        },
        onDialog: (verb) => setDialogVerb(verb),
        onProcesses: () => setProcesses(true),
        onFiles: () => setFilesOpen(true),
        onSaveSnippet: () => setSaveSnippet(true),
      })
    : []

  const hostLabel = implant?.hostname ?? 'unknown host'

  return (
    <>
      <div className="terminal console-terminal">
        <div className="console-titlebar">
          <a className="back-link" href={`#/engagements/${engagementId}/action/implants`}>
            ← Implants
          </a>
          <span className="console-host" title={`Implant ${implantId}`}>
            <Icon name={osIconFor(implant?.os)} className="wire-icon" />
            {hostLabel}
            <code>{implantId.slice(0, 8)}</code>
          </span>
          <span className="console-facts">
            {implant ? [implant.class, ...[implant.os, implant.arch].filter(Boolean)].join(' · ') : ''}
            {implant?.username ? ` · as ${implant.username}` : ''}
            {implant?.parentImplantId ? ` · parent ${implant.parentImplantId.slice(0, 8)}` : ''}
            {implant?.sleepSeconds != null
              ? ` · every ${formatSeconds(implant.sleepSeconds)} ± ${
                  implant.jitterSeconds != null ? formatSeconds(implant.jitterSeconds) : '?'
                }`
              : ''}
            {implant
              ? implant.killDate
                ? ` · kill ${new Date(implant.killDate).toLocaleDateString()}`
                : ' · no kill date'
              : ''}
          </span>
          <span className="console-live">
            {implant && (
              <StatusBadge
                status={implant.retiredAt ? 'retired' : implant.isOnline ? 'online' : 'offline'}
              />
            )}
            {presence && !implant?.retiredAt && (
              <span
                className="muted"
                title={`Online since ${new Date(presence.onlineAt).toLocaleString()}`}
              >
                seen {new Date(presence.lastSeenAt).toLocaleTimeString()}
              </span>
            )}
            {!presence && implant?.lastSeenAt && !implant.retiredAt && (
              <span
                className="muted"
                title={`Last heard ${new Date(implant.lastSeenAt).toLocaleString()}`}
              >
                last seen {ago(implant.lastSeenAt, now)}
              </span>
            )}
          </span>
          <span className="spacer">
            <button
              className="ghost sm menu-trigger"
              title="Implant actions"
              onClick={(e) => {
                const rect = (e.currentTarget as HTMLButtonElement).getBoundingClientRect()
                menu.openAt({ x: rect.left, y: rect.bottom + 4 })
              }}
            >
              <Icon name="more" />
            </button>
          </span>
        </div>

        <div className="console-transcript" ref={transcriptRef} onScroll={onTranscriptScroll}>
          {cursor && (
            <button className="ghost sm console-older" onClick={() => void loadOlder()}>
              ↑ load older
            </button>
          )}
          {tasks.length === 0 && (
            <div className="console-empty muted">
              No tasks on this implant yet -- type below, 'help' for the shortcuts, or use the
              menu (top right).
            </div>
          )}
          {tasks.map((task) => (
            <ConsoleBlock
              key={task.taskId}
              task={task}
              engagementId={engagementId}
              operatorId={operator.operatorId}
              outputKind={descriptorByVerb.get(task.verb)?.output?.kind ?? null}
              toggled={toggled.has(task.taskId)}
              onToggle={() => toggleToggled(task.taskId)}
              onCancel={() => void onCancel(task.taskId)}
              onInteract={() =>
                setInteractTask(interactTask === task.taskId ? null : task.taskId)
              }
            />
          ))}
          {interactTask && (
            <InteractPane
              engagementId={engagementId}
              taskId={interactTask}
              verb={tasks.find((t) => t.taskId === interactTask)?.verb ?? 'channel'}
              onClose={() => setInteractTask(null)}
            />
          )}
        </div>

        <form className="console-prompt" onSubmit={onQuick}>
          <span className="prompt" aria-hidden="true">
            {hostLabel.split('.')[0]} ›
          </span>
          <input
            className="wide"
            placeholder={implant?.retiredAt ? 'implant retired' : 'type a command and press Enter -- help lists the shortcuts'}
            value={line}
            onChange={(e) => setLine(e.target.value)}
            disabled={busy || !!implant?.retiredAt}
            autoFocus
          />
          <button className="primary sm" type="submit" disabled={busy || !line.trim()}>
            Run
          </button>
        </form>
        {hint && <div className="console-hint muted">{hint}</div>}
        {error && <p className="error terminal-error">{error}</p>}
      </div>

      <details className="build-advanced">
        <summary>Advanced — raw task against this implant</summary>
        <RawTaskForm
          groups={capabilityGroups}
          disabled={!!implant?.retiredAt}
          onSubmit={(verb, args) => void issue(verb, args)}
        />
      </details>

      {menu.menu && (
        <ContextMenu x={menu.menu.x} y={menu.menu.y} entries={menuEntries} onClose={menu.close} />
      )}
      {shellOpen && implant && (
        <ShellDialog
          engagementId={engagementId}
          implantId={implantId}
          hostLabel={hostLabel}
          onClose={() => setShellOpen(false)}
        />
      )}
      {processes && implant && (
        <ProcessBrowser engagementId={engagementId} implantId={implantId} onClose={() => setProcesses(false)} />
      )}
      {filesOpen && implant && (
        <FileBrowser
          engagementId={engagementId}
          implantId={implantId}
          osHint={implant.os}
          onClose={() => setFilesOpen(false)}
        />
      )}
      {saveSnippet && (
        <SnippetSaveDialog
          engagementId={engagementId}
          tasks={tasks}
          onClose={() => setSaveSnippet(false)}
        />
      )}
      {dialogVerb && implant && (
        <TaskDialog
          engagementId={engagementId}
          implantId={implantId}
          verb={dialogVerb}
          form={formForDescriptor(descriptorByVerb.get(dialogVerb))}
          attributes={descriptorByVerb.get(dialogVerb)?.attributes ?? {}}
          onClose={() => setDialogVerb(null)}
          onIssued={() => void refresh()}
        />
      )}
      {implant && (
        <div className="card">
          <h3>Comments</h3>
          <CommentsPanel
            engagementId={engagementId}
            subjectKind="implant"
            subjectId={implantId}
            tick={onlineTick}
          />
        </div>
      )}
    </>
  )
}

// One task in the transcript: the line (time, status tag, verb, arguments,
// author, row actions) with the output folded under it. Short output renders
// unfolded so the common case -- a command and its answer -- reads like a
// terminal exchange without a click; the toggle set holds blocks the operator
// flipped against their default.
function ConsoleBlock({
  task,
  engagementId,
  operatorId,
  outputKind,
  toggled,
  onToggle,
  onCancel,
  onInteract,
}: {
  task: EngagementTask
  engagementId: string
  operatorId: string
  outputKind: import('../api').VerbOutputKind | null
  toggled: boolean
  onToggle: () => void
  onCancel: () => void
  onInteract: () => void
}) {
  const output = task.output ?? ''
  const hasOutput = output.length > 0
  const unfoldByDefault = hasOutput && output.length <= UNFOLDED_OUTPUT_LIMIT
  const visible = unfoldByDefault ? !toggled : toggled

  const failed = task.outcome === 'Failed'

  return (
    <div className={`console-block${visible && hasOutput ? ' open' : ''}`}>
      <div className="console-line" onClick={hasOutput ? onToggle : undefined}>
        <span className="t">
          {new Date(task.completedAt ?? task.createdAt).toLocaleTimeString()}
        </span>
        <span className={`tag tag-${task.status.toLowerCase()}${failed ? ' tag-failed' : ''}`}>
          {failed ? 'failed' : task.status.toLowerCase()}
        </span>
        <code className="v">{task.verb}</code>
        <span className="args">{task.arguments.length > 0 ? ellipsize(task.arguments) : ''}</span>
        <span className="by">{task.issuedBy === operatorId ? 'you' : task.issuedBy.slice(0, 8)}</span>
        <span className="acts" onClick={(e) => e.stopPropagation()}>
          {task.status === 'Queued' && (
            <button className="danger sm" onClick={onCancel}>
              cancel
            </button>
          )}
          {isChannelVerb(task.verb) && (
            <button className="sm" onClick={onInteract}>
              interact
            </button>
          )}
          {hasOutput && !visible && (
            <button className="ghost sm" onClick={onToggle}>
              {(output.match(/\n/g)?.length ?? 0) + 1} lines
            </button>
          )}
        </span>
      </div>
      {hasOutput && visible && (
        <TaskOutputView
          engagementId={engagementId}
          taskId={task.taskId}
          output={output}
          outputKind={outputKind}
          className="console-output"
        />
      )}
    </div>
  )
}

// The raw-task escape hatch: any verb in the registry, free-form arguments --
// the old tasking form minus the implant picker, pinned to this console's
// implant.
function RawTaskForm({
  groups,
  disabled,
  onSubmit,
}: {
  groups: CapabilityGroup[]
  disabled: boolean
  onSubmit: (verb: string, args: string) => void
}) {
  const [verb, setVerb] = useState('shell.exec')
  const [args, setArgs] = useState('')
  return (
    <form
      className="task-form"
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit(verb, args)
        setArgs('')
      }}
    >
      <select value={verb} onChange={(e) => setVerb(e.target.value)} title="Capability verb">
        {groups.map((group) => (
          <optgroup key={group.category} label={group.label}>
            {group.descriptors.map((d) => (
              <option key={d.verb} value={d.verb}>
                {d.verb}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
      <input
        className="wide"
        placeholder="arguments"
        value={args}
        onChange={(e) => setArgs(e.target.value)}
      />
      <button className="primary" type="submit" disabled={disabled}>
        Issue
      </button>
    </form>
  )
}
