// The collaboration panels' UI acceptance (architecture.md Sec 15.3,
// ADR-005): the comments panel's reference-token rendering mirrors the
// server's wire grammar, the chat dock assembles its whole history from the
// newest-window-first pages, and a global-search hit lands on the surface
// that shows the corpus it came from. These checks run against the server's
// real DTO shapes; the panels render straight from the same helpers.

import { describe, expect, it } from 'vitest'
import type { ChatMessageRow, SearchHitRow } from './api'
import { collectChatHistory, refTokenLabel, searchHitHash, splitCommentBody } from './collabFormat'

const guid = '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d'

describe('splitCommentBody', () => {
  it('passes plain text through as one part', () => {
    expect(splitCommentBody('nothing to resolve here')).toEqual([
      { kind: 'text', text: 'nothing to resolve here' },
    ])
    expect(splitCommentBody('')).toEqual([])
  })

  it('tokenizes both marker kinds in both guid forms', () => {
    const hyphenated = `see @task-${guid} and $cred-${guid}`
    expect(splitCommentBody(hyphenated)).toEqual([
      { kind: 'text', text: 'see ' },
      { kind: 'task', text: `@task-${guid}` },
      { kind: 'text', text: ' and ' },
      { kind: 'cred', text: `$cred-${guid}` },
    ])

    const bare = guid.replace(/-/g, '')
    expect(splitCommentBody(`$cred-${bare}`)).toEqual([{ kind: 'cred', text: `$cred-${bare}` }])
  })

  it('keeps adjacent tokens apart', () => {
    const parts = splitCommentBody(`@task-${guid}$cred-${guid}`)
    expect(parts.map((p) => p.kind)).toEqual(['task', 'cred'])
  })

  it('leaves a marker with a non-guid run as literal text', () => {
    // The server never resolved this shape, so the console shows what was
    // written -- a dangling-looking chip would misread worse than the text.
    expect(splitCommentBody('costs $cred-fifty')).toEqual([
      { kind: 'text', text: 'costs $cred-fifty' },
    ])
  })
})

describe('refTokenLabel', () => {
  it('reads as kind plus the id tail', () => {
    expect(refTokenLabel(`@task-${guid}`)).toBe('task·4c5d')
    expect(refTokenLabel(`$cred-${guid}`)).toBe('cred·4c5d')
  })
})

describe('collectChatHistory', () => {
  const message = (id: string): ChatMessageRow => ({
    id,
    channelId: 'channel',
    authorId: '00000000-0000-0000-0000-000000000001',
    body: id,
    sentAt: '2026-10-22T00:00:00Z',
  })

  it('walks the cursor chain and returns the history oldest-first', async () => {
    // The listing serves the newest window first; the walk unshifts each
    // older page, so the assembled transcript reads in causal order.
    const pages = new Map<string | undefined, { items: string[]; nextCursor: string | null }>([
      [undefined, { items: ['m5', 'm6'], nextCursor: 'page2' }],
      ['page2', { items: ['m3', 'm4'], nextCursor: 'page3' }],
      ['page3', { items: ['m1', 'm2'], nextCursor: null }],
    ])
    const walked: (string | undefined)[] = []
    const history = await collectChatHistory(async (cursor) => {
      walked.push(cursor)
      const page = pages.get(cursor)!
      return { items: page.items.map(message), nextCursor: page.nextCursor }
    })

    expect(walked).toEqual([undefined, 'page2', 'page3'])
    expect(history.map((m) => m.id)).toEqual(['m1', 'm2', 'm3', 'm4', 'm5', 'm6'])
  })

  it('returns the single page whole when there is no cursor', async () => {
    const history = await collectChatHistory(async () => ({
      items: [message('only')],
      nextCursor: null,
    }))
    expect(history.map((m) => m.id)).toEqual(['only'])
  })
})

describe('searchHitHash', () => {
  const hit = (corpus: SearchHitRow['corpus']): SearchHitRow => ({
    corpus,
    refId: 'ref',
    title: 'title',
    excerpt: 'excerpt',
    at: '2026-10-22T00:00:00Z',
  })

  it('routes each corpus to the surface that shows it', () => {
    const base = '#/engagements/e-id'
    expect(searchHitHash('e-id', hit('comment'))).toBe(`${base}/action/tasking`)
    expect(searchHitHash('e-id', hit('task_output'))).toBe(`${base}/action/tasking`)
    expect(searchHitHash('e-id', hit('credential'))).toBe(`${base}/assets/credentials`)
    expect(searchHitHash('e-id', hit('artifact'))).toBe(`${base}/assets/loot`)
    expect(searchHitHash('e-id', hit('chat_message'))).toBe(`${base}/overview/timeline`)
  })
})
