import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  type ArtifactSummary,
  type EngagementTask,
  type Implant,
  type SummarizedTask,
  type VerbOutputKind,
  attachArtifact,
  fetchArtifactBlob,
  listArtifacts,
  listEngagementTasks,
  listImplantTasks,
  listImplants,
  summarizeTask,
} from '../api'
import { loadCapabilityGroups } from '../capabilities'
import { CommentsPanel } from '../components/CommentsPanel'
import { HelpHint } from '../components/HelpHint'
import { Icon } from '../components/Icons'
import { InteractPane } from '../components/InteractPane'
import { StatusBadge } from '../components/StatusBadge'
import { TaskOutputView } from '../components/TaskOutputView'
import { saveBlob } from '../download'
import { ellipsize, fmtBytes } from '../format'
import { isChannelVerb } from '../verbForms'

// The task log: the engagement's working record of issued tasking, live on
// the SSE tick. Issuing moved to the implants menu and the session console;
// what belongs here is reading -- filter by implant (its console feed,
// engagement-wide when unfiltered), by verb, by status, by operator, or
// free text over verb/arguments/output, and watch new rows land as operators
// work. "Show me every shell command this engagement ran" is the shape this
// view exists for. Tasking stays read-only: retracting a queued task is an
// operational action and lives in the session console, next to the implant
// it targets. The two acts beyond reading are evidence -- the expanded row
// attaches an operator-side file to the task's record, the job the retired
// Artifacts tab held -- and the LLM summary, an explicit egressing request.
// Channel transcripts still open from their rows.

export function TaskLogView({
  engagementId,
  onlineTick,
}: {
  engagementId: string
  onlineTick: number
}) {
  const [tasks, setTasks] = useState<EngagementTask[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [implants, setImplants] = useState<Implant[]>([])
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [interactTask, setInteractTask] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // The filters. Implant "" means engagement-wide; the others are
  // client-side predicates over the loaded window.
  const [implantFilter, setImplantFilter] = useState('')
  const [verbFilter, setVerbFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [operatorFilter, setOperatorFilter] = useState('')
  // The text search commits on Enter or the Search button (the dropdown
  // filters above stay live): typing a long output fragment should not
  // re-filter on every keystroke.
  const [textDraft, setTextDraft] = useState('')
  const [textFilter, setTextFilter] = useState('')
  // The verb -> output-kind map the typed output panels key on, from the
  // capability registry -- whatever it declares, module verbs included.
  const [outputKindByVerb, setOutputKindByVerb] = useState<Map<string, VerbOutputKind>>(new Map())

  useEffect(() => {
    void loadCapabilityGroups()
      .then((groups) => {
        const map = new Map<string, VerbOutputKind>()
        for (const group of groups) {
          for (const descriptor of group.descriptors) {
            if (descriptor.output) map.set(descriptor.verb, descriptor.output.kind)
          }
        }
        setOutputKindByVerb(map)
      })
      .catch(() => {
        // The catalog is a render enhancement; a failed load leaves the
        // plain transcript, which is the honest fallback.
      })
  }, [])

  const refresh = useCallback(async () => {
    try {
      const [implantList, page] = await Promise.all([
        listImplants(engagementId),
        implantFilter
          ? listImplantTasks(engagementId, implantFilter)
          : listEngagementTasks(engagementId),
      ])
      setImplants(implantList)
      setTasks(page.items)
      setCursor(page.nextCursor)
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [engagementId, implantFilter])

  useEffect(() => {
    void refresh()
  }, [refresh, onlineTick])

  // A filter switch must not carry an expanded row or an open pane across
  // sources; the rows themselves are different objects.
  useEffect(() => {
    setExpanded(new Set())
    setInteractTask(null)
  }, [implantFilter])

  const loadOlder = useCallback(async () => {
    if (!cursor) return
    setLoadingMore(true)
    try {
      const page = implantFilter
        ? await listImplantTasks(engagementId, implantFilter, cursor)
        : await listEngagementTasks(engagementId, cursor)
      setTasks((current) => [...current, ...page.items])
      setCursor(page.nextCursor)
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoadingMore(false)
    }
  }, [engagementId, implantFilter, cursor])

  // The verb/operator/status options come from the loaded window: the set of
  // things that actually happened, not a catalog of things that could.
  const verbs = useMemo(() => [...new Set(tasks.map((t) => t.verb))].sort(), [tasks])
  const statuses = useMemo(() => [...new Set(tasks.map((t) => t.status))].sort(), [tasks])
  // The operator filter matches by id exactly; the options label with the
  // resolved handle the rows carry, so the dropdown reads like the log.
  const operators = useMemo(
    () => [...new Set(tasks.map((t) => t.issuedBy))].sort(),
    [tasks],
  )
  const handleByOperator = useMemo(
    () => new Map(tasks.map((t) => [t.issuedBy, t.issuedByHandle])),
    [tasks],
  )

  const filtered = useMemo(() => {
    const needle = textFilter.trim().toLowerCase()
    return tasks.filter((t) => {
      if (verbFilter && t.verb !== verbFilter) return false
      if (statusFilter && t.status !== statusFilter) return false
      if (operatorFilter && t.issuedBy !== operatorFilter) return false
      if (implantFilter && t.implantId !== implantFilter) return false
      if (needle !== '') {
        const haystack = `${t.verb} ${t.arguments} ${t.output ?? ''}`.toLowerCase()
        if (!haystack.includes(needle)) return false
      }
      return true
    })
  }, [tasks, verbFilter, statusFilter, operatorFilter, implantFilter, textFilter])

  const toggleExpanded = (taskId: string) => {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(taskId)) next.delete(taskId)
      else next.add(taskId)
      return next
    })
  }

  if (loading) {
    return (
      <section className="view">
        <h2>Task log</h2>
        <div className="card">
          <div className="empty">
            <span className="spinner" />
            Loading the task log…
          </div>
        </div>
      </section>
    )
  }

  return (
    <section className="view">
      <h2>
        Task log
        <HelpHint>
          Every task this engagement issued, newest first, live as operators work -- read-only;
          cancel queued tasking from the implant's session console.
        </HelpHint>
      </h2>
      <div className="card">
        <div className="inline-form">
          <select
            value={implantFilter}
            onChange={(e) => setImplantFilter(e.target.value)}
            title="Filter by implant (switches to that implant's own history)"
          >
            <option value="">All implants</option>
            {implants.map((i) => (
              <option key={i.implantId} value={i.implantId}>
                {i.hostname ? `${i.hostname} · ` : ''}
                {i.implantId.slice(0, 8)} ({i.class})
              </option>
            ))}
          </select>
          <select value={verbFilter} onChange={(e) => setVerbFilter(e.target.value)} title="Filter by verb">
            <option value="">All verbs</option>
            {verbs.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} title="Filter by status">
            <option value="">Any status</option>
            {statuses.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            value={operatorFilter}
            onChange={(e) => setOperatorFilter(e.target.value)}
            title="Filter by the issuing operator"
          >
            <option value="">Any operator</option>
            {operators.map((o) => (
              <option key={o} value={o}>
                {handleByOperator.get(o) ?? o.slice(0, 8)}
              </option>
            ))}
          </select>
          <input
            className="filter-text"
            placeholder="Search verb, arguments, output…"
            value={textDraft}
            onChange={(e) => setTextDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') setTextFilter(textDraft)
            }}
            title="Free text across verb, arguments, and output. Enter or the Search button applies; the dropdown filters above are live."
          />
          <button
            className="ghost"
            onClick={() => setTextFilter(textDraft)}
            title="Apply the text search (Enter works too)"
          >
            Search
          </button>
        </div>

        {interactTask && (
          <InteractPane
            engagementId={engagementId}
            taskId={interactTask}
            verb={tasks.find((t) => t.taskId === interactTask)?.verb ?? 'channel'}
            onClose={() => setInteractTask(null)}
          />
        )}

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th></th>
                <th>Verb</th>
                <th>Implant</th>
                <th>Status</th>
                <th>By</th>
                <th>At</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <div className="empty">
                      <Icon name="inbox" />
                      {tasks.length === 0 ? 'No tasks yet.' : 'No tasks match the filters.'}
                    </div>
                  </td>
                </tr>
              )}
              {[...filtered].reverse().map((t) => (
                <LogRow
                  key={t.taskId}
                  engagementId={engagementId}
                  task={t}
                  tick={onlineTick}
                  outputKind={outputKindByVerb.get(t.verb) ?? null}
                  expanded={expanded.has(t.taskId)}
                  onToggle={() => toggleExpanded(t.taskId)}
                  onInteract={() =>
                    setInteractTask(interactTask === t.taskId ? null : t.taskId)
                  }
                  interactOpen={interactTask === t.taskId}
                />
              ))}
            </tbody>
          </table>
        </div>
        {cursor && (
          <div className="load-more">
            <button className="ghost" onClick={() => void loadOlder()} disabled={loadingMore}>
              {loadingMore ? 'Loading…' : 'Load older'}
            </button>
          </div>
        )}
        {error && <p className="error">{error}</p>}
      </div>
    </section>
  )
}

function LogRow({
  engagementId,
  task,
  tick,
  outputKind,
  expanded,
  onToggle,
  onInteract,
  interactOpen,
}: {
  engagementId: string
  task: EngagementTask
  tick: number
  outputKind: VerbOutputKind | null
  expanded: boolean
  onToggle: () => void
  onInteract: () => void
  interactOpen: boolean
}) {
  return (
    <>
      <tr className="console-row" onClick={onToggle}>
        <td onClick={(e) => e.stopPropagation()}>
          <button
            className={`ghost sm row-expand${expanded ? ' open' : ''}`}
            onClick={onToggle}
            title={expanded ? 'Collapse the output' : 'Expand the full output'}
          >
            <Icon name={expanded ? 'chevronDown' : 'chevronRight'} />
          </button>
        </td>
        <td>
          <div>
            <code>{task.verb}</code>{' '}
            <span className="muted console-args">
              {task.arguments.length > 0 ? ellipsize(task.arguments) : ''}
            </span>
          </div>
          {/* A one-line preview of the answer under the command: the log's
              rows stay scannable while still showing that data came back --
              the chevron unfolds the whole thing. */}
          {!expanded && task.output && (
            <div className="muted console-args output-preview">{ellipsize(task.output, 96)}</div>
          )}
        </td>
        <td>
          <a
            className="button-link sm"
            href={`#/engagements/${engagementId}/action/implants/${task.implantId}/interact`}
            title="Open the session console -- queued tasks cancel there"
            onClick={(e) => e.stopPropagation()}
          >
            {task.implantId.slice(0, 8)}
          </a>
        </td>
        <td>
          <StatusBadge status={task.status} />
          {task.outcome === 'Failed' && <span className="error"> failed</span>}
        </td>
        <td>
          <code title={task.issuedBy}>{task.issuedByHandle}</code>
        </td>
        <td>
          {task.completedAt
            ? new Date(task.completedAt).toLocaleTimeString()
            : new Date(task.createdAt).toLocaleTimeString()}
        </td>
        <td onClick={(e) => e.stopPropagation()}>
          <div className="row-actions">
            {isChannelVerb(task.verb) && (
              <button className="sm" onClick={onInteract}>
                {interactOpen ? 'Hide' : 'Interact'}
              </button>
            )}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7}>
            <div className="task-detail">
              {task.arguments.length > 0 && (
                <div className="task-detail-line">
                  <span className="muted">arguments</span> <code>{task.arguments}</code>
                </div>
              )}
              {task.output ? (
                <TaskOutputView
                  engagementId={engagementId}
                  taskId={task.taskId}
                  output={task.output}
                  outputKind={outputKind}
                  className="output long"
                />
              ) : (
                <pre className="output long">—</pre>
              )}
              <TaskSummary engagementId={engagementId} task={task} />
              <div className="task-detail-line muted">
                created {new Date(task.createdAt).toLocaleString()}
                {task.completedAt && <> · completed {new Date(task.completedAt).toLocaleString()}</>}
                {' '}· by <code title={task.issuedBy}>{task.issuedByHandle}</code>
              </div>
              <TaskArtifacts engagementId={engagementId} taskId={task.taskId} />
              <CommentsPanel
                engagementId={engagementId}
                subjectKind="task"
                subjectId={task.taskId}
                tick={tick}
              />
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// The LLM half of an expanded row (docs/operations/llm.md): one completed
// task's captured output, compressed on demand. The button is deliberately
// not a passive label -- the request egresses the task's content to the
// configured endpoint, and every attempt lands in the audit trail against
// the operator who clicked, so the affordance is an explicit act. A 503
// names the configuration section verbatim rather than paraphrasing the
// opt-in into a dead end.
function TaskSummary({ engagementId, task }: { engagementId: string; task: EngagementTask }) {
  const [busy, setBusy] = useState(false)
  const [summary, setSummary] = useState<SummarizedTask | null>(null)
  const [error, setError] = useState<string | null>(null)

  if (task.status !== 'Completed' || !task.output) return null

  const onSummarize = async () => {
    if (busy) return
    setBusy(true)
    try {
      setSummary(await summarizeTask(engagementId, task.taskId))
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="task-detail-summary">
      {summary ? (
        <>
          <div className="task-detail-line">
            <span className="muted">llm summary</span>{' '}
            <span className="muted">({summary.model})</span>
          </div>
          <pre className="output">{summary.summary}</pre>
        </>
      ) : null}
      <button
        className="ghost sm"
        onClick={() => void onSummarize()}
        disabled={busy}
        title="Send this task's captured output to the configured LLM endpoint for a summary -- the request egresses content and is audited"
      >
        {busy ? 'Summarizing…' : summary ? 'Re-run summary' : 'Summarize with LLM'}
      </button>
      {error && <span className="error"> {error}</span>}
    </div>
  )
}

// The artifacts a task produced or consumed, lazily fetched on expand: a
// staged upload binds its bytes to the task, a large pull streams into the
// store. The same line carries the operator-side attach -- evidence a task
// did not produce itself, bound to the task it documents -- so evidence
// work stays in the row it belongs to.
function TaskArtifacts({ engagementId, taskId }: { engagementId: string; taskId: string }) {
  const [artifacts, setArtifacts] = useState<ArtifactSummary[] | null>(null)
  const [fileName, setFileName] = useState('')
  const [fileBytes, setFileBytes] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      setArtifacts((await listArtifacts(engagementId, taskId)).items)
    } catch {
      setArtifacts([])
    }
  }, [engagementId, taskId])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const onFile = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = () => {
      // reader.result is a data URL; strip the prefix to get the raw base64.
      const result = String(reader.result ?? '')
      const comma = result.indexOf(',')
      setFileBytes(comma >= 0 ? result.slice(comma + 1) : result)
    }
    reader.readAsDataURL(file)
  }

  const onAttach = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!fileName) return
    setBusy(true)
    try {
      await attachArtifact(engagementId, taskId, {
        name: fileName,
        contentType: null,
        content: fileBytes,
      })
      setFileName('')
      setFileBytes('')
      await refresh()
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const onDownload = async (artifact: ArtifactSummary) => {
    try {
      saveBlob(await fetchArtifactBlob(engagementId, artifact.artifactId), artifact.name)
    } catch {
      // The row stays; a failed fetch surfaces on retry.
    }
  }

  return (
    <div className="task-detail-artifacts">
      <span className="muted">artifacts</span>
      {artifacts?.map((a) => (
        <span key={a.artifactId} className="task-detail-artifact">
          <code>{a.name}</code> <span className="muted">({fmtBytes(a.size)})</span>{' '}
          <button className="sm" onClick={() => void onDownload(a)}>
            Download
          </button>
        </span>
      ))}
      <form className="inline-form" onSubmit={onAttach}>
        <input type="file" onChange={onFile} aria-label="Evidence file" />
        <input
          placeholder="name"
          value={fileName}
          onChange={(e) => setFileName(e.target.value)}
          title="The evidence name; defaults to the chosen file's name"
          aria-label="Artifact name"
        />
        <button className="sm" type="submit" disabled={busy || !fileBytes}>
          {busy ? 'Attaching…' : 'Attach'}
        </button>
        {error && <span className="error">{error}</span>}
      </form>
    </div>
  )
}
