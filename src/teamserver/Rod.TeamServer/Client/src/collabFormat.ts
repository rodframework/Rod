// Collaboration-panel helpers (architecture.md Sec 15.3, ADR-005): the pure
// pieces the comments panel, the chat dock, and the palette's global-search
// results render from. Extracted so the rules are checkable -- the token
// grammar is the server's wire grammar, and a rendering regression here is a
// reference an operator misreads.

import type { ChatMessageRow, ListPage, SearchHitRow } from './api'

// --- Comments: reference tokens -------------------------------------------

export type CommentBodyPart =
  | { kind: 'text'; text: string }
  | { kind: 'task'; text: string }
  | { kind: 'cred'; text: string }

// Splits a comment body into text and reference-token parts. The grammar is
// the server's TaskReferences lifter, exactly: a marker followed by a
// guid-shaped run with the trailing boundary tokenizes; anything else stays
// literal text -- the server never resolved it, so the console shows what
// was written, never a chip that misreads as a live reference.
const GUID = '(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'
const REF_TOKEN = new RegExp(`(@task-${GUID}|\\$cred-${GUID})(?![0-9a-fA-F-])`, 'g')

export function splitCommentBody(body: string): CommentBodyPart[] {
  const parts = body.split(REF_TOKEN)
  const out: CommentBodyPart[] = []
  for (const part of parts) {
    if (part.startsWith('@task-')) out.push({ kind: 'task', text: part })
    else if (part.startsWith('$cred-')) out.push({ kind: 'cred', text: part })
    else if (part.length > 0) out.push({ kind: 'text', text: part })
  }
  return out
}

// The chip label a token renders as: kind plus the id's last four, so a
// reference reads as "cred·a1b2" instead of a wall of guid. The full token
// rides the element's title for the hover read.
export function refTokenLabel(token: string): string {
  const kind = token.startsWith('@task-') ? 'task' : 'cred'
  return `${kind}·${token.slice(-4)}`
}

// --- Chat: whole-history page walk -----------------------------------------

// Walks the message listing's cursor chain (newest window first) and returns
// the channel's whole history oldest-first. Chat history is bounded by the
// watch, not the engagement, so walking to the beginning is the honest read.
export async function collectChatHistory(
  fetchPage: (cursor?: string) => Promise<ListPage<ChatMessageRow>>,
): Promise<ChatMessageRow[]> {
  const collected: ChatMessageRow[] = []
  let cursor: string | undefined
  do {
    const page = await fetchPage(cursor)
    collected.unshift(...page.items)
    cursor = page.nextCursor ?? undefined
  } while (cursor)
  return collected
}

// --- Global search: hit routing --------------------------------------------

// Where a search hit lands: the sub-surface that shows the corpus it came
// from. Comments and tasks live in the task log, credentials and loot on
// the assets boards, chat in the overview timeline that merges it beside
// the audit stream.
export function searchHitHash(engagementId: string, hit: SearchHitRow): string {
  const base = `#/engagements/${engagementId}`
  switch (hit.corpus) {
    case 'comment':
    case 'task_output':
      return `${base}/action/tasking`
    case 'credential':
      return `${base}/assets/credentials`
    case 'artifact':
      return `${base}/assets/loot`
    case 'chat_message':
      return `${base}/overview/timeline`
    default:
      return base
  }
}
