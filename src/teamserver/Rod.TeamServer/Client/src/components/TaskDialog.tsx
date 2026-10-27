import { useState } from 'react'
import { issueTask, type Task } from '../api'
import { type LoadableModule } from '../capabilities'
import { readSelectedFile, type SelectedFile, type VerbForm } from '../verbForms'
import { OpsecBadges } from './OpsecBadges'

// The schema-driven task dialog (architecture.md Sec 15.2's first contract):
// labeled fields rendered from the verb's declared parameter schema, not a
// per-verb table. The verb's OPSEC attributes ride along from the registry so
// a risky issuance says so before the button, not after. Submitting builds the
// arguments (and the staged content, for a large upload) and issues the task;
// the caller decides what feedback follows (the task log will show it either
// way -- it is engagement-wide and live).

export function TaskDialog({
  engagementId,
  implantId,
  verb,
  form,
  attributes,
  loadable,
  nameField,
  onIssued,
  onClose,
}: {
  engagementId: string
  implantId: string
  verb: string
  form: VerbForm
  attributes: Record<string, string>
  // The session's loadable plugin set (ADR-017's runtime half, mirrored
  // client-side): when the caller supplies it for a module.load, the dialog
  // offers the covered modules as one-click names and names what an uncovered
  // one is missing. The server's issuance gate stays the authority.
  loadable?: readonly LoadableModule[]
  // The form field the picked module name lands in (module.load's `name`).
  nameField?: string
  onIssued?: (task: Task) => void
  onClose: () => void
}) {
  const [values, setValues] = useState<Record<string, string | boolean>>({})
  const [files, setFiles] = useState<Record<string, SelectedFile>>({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const onFilePicked = async (key: string, file: globalThis.File | undefined) => {
    if (!file) return
    try {
      setFiles((current) => ({ ...current, [key]: { name: file.name, base64: '', bytes: 0 } }))
      const selected = await readSelectedFile(file)
      setFiles((current) => ({ ...current, [key]: selected }))
    } catch (e) {
      setError(String(e))
    }
  }

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    try {
      const built = await form.build(values, files)
      const task = await issueTask(engagementId, {
        implantId,
        verb,
        arguments: built.arguments,
        content: built.content,
      })
      onIssued?.(task)
      onClose()
    } catch (e) {
      setError(String(e))
      setBusy(false)
    }
  }

  // Required means the operator must supply it: a picked file, a checked
  // flag, or a non-empty value.
  const missing = form.fields.some(
    (f) => f.required && f.kind === 'File' && !files[f.key],
  ) || form.fields.some(
    (f) => f.required && f.kind === 'Boolean' && values[f.key] !== true,
  ) || form.fields.some(
    (f) =>
      f.required &&
      f.kind !== 'File' &&
      f.kind !== 'Boolean' &&
      ((values[f.key] as string) ?? '').trim() === '',
  )

  const wide = (field: (typeof form.fields)[number]) =>
    field.kind === 'Text' || field.kind === 'Array'

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <form className="card modal" onSubmit={onSubmit}>
        <h3>
          {form.title} <code>{verb}</code>
        </h3>
        {form.fields.map((field) => (
          <label key={field.key}>
            {field.kind === 'Boolean' ? (
              <span className="inline-form">
                <input
                  type="checkbox"
                  checked={values[field.key] === true}
                  onChange={(e) =>
                    setValues((current) => ({ ...current, [field.key]: e.target.checked }))
                  }
                />
                {field.label}
              </span>
            ) : (
              <>
                {field.label}
                {field.kind === 'File' ? (
                  <input
                    type="file"
                    onChange={(e) => void onFilePicked(field.key, e.target.files?.[0])}
                  />
                ) : field.kind === 'Enum' && field.choices ? (
                  <select
                    value={(values[field.key] as string) ?? ''}
                    onChange={(e) =>
                      setValues((current) => ({ ...current, [field.key]: e.target.value }))
                    }
                  >
                    <option value="">-- pick --</option>
                    {field.choices.map((choice) => (
                      <option key={choice} value={choice}>
                        {choice}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={field.kind === 'Number' ? 'number' : 'text'}
                    className={wide(field) ? 'wide' : undefined}
                    placeholder={field.placeholder}
                    value={(values[field.key] as string) ?? ''}
                    onChange={(e) =>
                      setValues((current) => ({ ...current, [field.key]: e.target.value }))
                    }
                  />
                )}
              </>
            )}
            {field.help && <span className="field-help">{field.help}</span>}
          </label>
        ))}
        {loadable && loadable.length > 0 && nameField && (
          <div className="module-picker">
            <span className="field-help">
              This session's loadable plugins (what its advertisement covers)
            </span>
            <div className="inline-form">
              {loadable.map((entry) => (
                <button
                  key={entry.module}
                  type="button"
                  className="ghost sm"
                  disabled={!entry.covered}
                  title={
                    entry.covered
                      ? `${entry.module} -- requires ${entry.requires.join(', ') || 'nothing'}`
                      : `${entry.module} -- missing ${entry.missing.join(', ')}`
                  }
                  onClick={() =>
                    setValues((current) => ({ ...current, [nameField]: entry.module }))
                  }
                >
                  {entry.module}
                  {entry.covered ? '' : ` (needs ${entry.missing.join(', ')})`}
                </button>
              ))}
            </div>
          </div>
        )}
        <div className="task-meta">
          <OpsecBadges attributes={attributes} />
        </div>
        {error && <p className="error">{error}</p>}
        <div className="inline-form">
          <button className="ghost" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" type="submit" disabled={busy || missing}>
            {busy ? 'Issuing…' : 'Issue task'}
          </button>
        </div>
      </form>
    </div>
  )
}
