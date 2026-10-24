import { useEffect, useRef, useState } from 'react'
import {
  type ChatChannelRow,
  type ChatMessageRow,
  createChatChannel,
  listChatChannels,
  listChatMessages,
  sendChatMessage,
} from '../api'
import { collectChatHistory } from '../collabFormat'

// The engagement's coordination room (architecture.md Sec 15.3, ADR-005):
// channels and messages, append-only, riding the timeline and the live
// stream but never the audit chain. Rendered as a docked panel beside the
// working view -- chat is a surface, not a navigation slot.
export function ChatPanel({
  engagementId,
  tick,
  onClose,
}: {
  engagementId: string
  tick?: number
  onClose: () => void
}) {
  const [channels, setChannels] = useState<ChatChannelRow[]>([])
  const [active, setActive] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessageRow[]>([])
  const [draft, setDraft] = useState('')
  const [newChannel, setNewChannel] = useState('')
  const [creating, setCreating] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const listRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    void (async () => {
      try {
        const loaded = await listChatChannels(engagementId)
        setChannels(loaded)
        setActive((current) => current ?? loaded[0]?.id ?? null)
        setError(null)
      } catch (e) {
        setError(String(e))
      }
    })()
  }, [engagementId, tick])

  useEffect(() => {
    if (!active) return
    void (async () => {
      try {
        // Newest window first, walked to the beginning by the shared
        // collector -- chat history is bounded by the watch, not the
        // engagement.
        setMessages(await collectChatHistory((cursor) => listChatMessages(engagementId, active, cursor)))
        setError(null)
      } catch (e) {
        setError(String(e))
      }
    })()
  }, [engagementId, active, tick])

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight })
  }, [messages])

  const send = async () => {
    const body = draft.trim()
    if (!body || !active || busy) return
    setBusy(true)
    try {
      await sendChatMessage(engagementId, active, body)
      setDraft('')
      setMessages(await collectChatHistory((cursor) => listChatMessages(engagementId, active, cursor)))
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <aside className="chat-dock">
      <header>
        <strong>Chat</strong>
        <button className="chip-x" title="Close chat" onClick={onClose}>
          ×
        </button>
      </header>
      <div className="chat-channels">
        {channels.map((c) => (
          <button
            key={c.id}
            className={c.id === active ? 'chat-channel active' : 'chat-channel'}
            onClick={() => setActive(c.id)}
          >
            {c.name}
          </button>
        ))}
        {creating ? (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              const name = newChannel.trim()
              if (!name) return
              void (async () => {
                try {
                  const created = await createChatChannel(engagementId, name)
                  setChannels(await listChatChannels(engagementId))
                  setActive(created.id)
                  setCreating(false)
                  setNewChannel('')
                  setError(null)
                } catch (e) {
                  setError(String(e))
                }
              })()
            }}
          >
            <input
              autoFocus
              value={newChannel}
              placeholder="channel name"
              onChange={(e) => setNewChannel(e.target.value)}
            />
          </form>
        ) : (
          <button className="chat-channel" title="Add a channel" onClick={() => setCreating(true)}>
            +
          </button>
        )}
      </div>
      <div className="chat-messages" ref={listRef}>
        {messages.length === 0 ? (
          <p className="muted">The room is quiet. Say hello to the watch.</p>
        ) : (
          messages.map((m) => (
            <div key={m.id} className="chat-line">
              <span className="notes-meta">
                <code title={m.authorId}>{m.authorHandle}</code> {new Date(m.sentAt).toLocaleTimeString()}
              </span>
              {m.body}
            </div>
          ))
        )}
      </div>
      <form
        className="task-form chat-input"
        onSubmit={(e) => {
          e.preventDefault()
          void send()
        }}
      >
        <input
          className="wide"
          placeholder="message the watch (@task-… / $cred-… resolve on send)"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
        />
        <button className="sm" type="submit" disabled={busy || !draft.trim() || !active}>
          Send
        </button>
      </form>
      {error && <div className="error">{error}</div>}
    </aside>
  )
}
