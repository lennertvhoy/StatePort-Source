/**
 * Unit tests for the pure conversation model helpers.
 */
import { describe, expect, it } from 'vitest'

import type { ConversationMessage } from '@/client'

import {
  bridgePayloadToChip,
  buildTranscriptItems,
  checkAttachment,
  contextSentence,
  extractContentProposals,
  MAX_ATTACHMENT_BYTES,
} from '../conversationModel'

function msg(id: string, iso: string, role: 'user' | 'assistant' = 'user'): ConversationMessage {
  return {
    id,
    conversationId: 'conv_x',
    role,
    content: `content ${id}`,
    createdAt: iso,
    state: 'complete',
    attachments: [],
    contextChips: [],
    toolEvents: [],
  }
}

describe('buildTranscriptItems', () => {
  const messages = [
    msg('m1', '2026-01-01T09:00:00Z'),
    msg('m2', '2026-01-01T10:00:00Z', 'assistant'),
    msg('m3', '2026-01-02T09:00:00Z'),
  ]

  it('inserts day dividers between calendar days', () => {
    const items = buildTranscriptItems(messages)
    expect(items.map((i) => i.type)).toEqual(['day', 'message', 'message', 'day', 'message'])
  })

  it('places the unread divider before the first message after last-seen', () => {
    const items = buildTranscriptItems(messages, { lastSeenId: 'm1', unreadActive: true })
    const unreadAt = items.findIndex((i) => i.type === 'unread')
    expect(unreadAt).toBeGreaterThan(-1)
    expect(items[unreadAt + 1]).toMatchObject({ type: 'message', message: { id: 'm2' } })
    expect(items[unreadAt]).toMatchObject({ label: expect.stringContaining('New since') })
  })

  it('omits the unread divider when everything is seen', () => {
    const items = buildTranscriptItems(messages, { lastSeenId: 'm3', unreadActive: true })
    expect(items.some((i) => i.type === 'unread')).toBe(false)
  })
})

describe('extractContentProposals', () => {
  it('extracts shell commands and diffs as proposals', () => {
    const content = 'Try this:\n```bash\nnixos-rebuild switch\n```\nand\n```diff\n+++ b/flake.nix\n+  hello\n```'
    const proposals = extractContentProposals(content)
    expect(proposals).toEqual([
      { kind: 'command', command: 'nixos-rebuild switch' },
      { kind: 'patch', path: 'flake.nix', proposed: '+++ b/flake.nix\n+  hello' },
    ])
  })

  it('ignores non-actionable fences', () => {
    expect(extractContentProposals('```json\n{}\n```')).toEqual([])
  })
})

describe('checkAttachment', () => {
  it('accepts allowlisted types within the limit', () => {
    expect(checkAttachment('a.png', 'image/png', 1024).ok).toBe(true)
    expect(checkAttachment('b.md', 'text/markdown', 1024).ok).toBe(true)
    expect(checkAttachment('c.yaml', 'application/x-yaml', 1024).ok).toBe(true)
  })

  it('rejects over-limit and disallowed types with reasons', () => {
    const big = checkAttachment('big.txt', 'text/plain', MAX_ATTACHMENT_BYTES + 1)
    expect(big.ok).toBe(false)
    if (!big.ok) expect(big.reason).toContain('2 MiB')
    const bin = checkAttachment('app.exe', 'application/x-msdownload', 100)
    expect(bin.ok).toBe(false)
    // An unknown/empty media type fails closed — the service validates the
    // declared media type and cannot accept an undeclared one.
    const unknown = checkAttachment('b.nix', '', 1024)
    expect(unknown.ok).toBe(false)
  })
})

describe('context chips', () => {
  it('maps bridge payloads to visible chips', () => {
    const chip = bridgePayloadToChip({ kind: 'receipt', instanceId: 'i', receiptId: 'rcpt_9' })
    expect(chip).toMatchObject({ kind: 'receipt', refId: 'rcpt_9', removable: true })
    // Outbound kinds never become chips.
    expect(bridgePayloadToChip({ kind: 'command-draft', instanceId: 'i', command: 'ls' })).toBeNull()
  })

  it('explains context in one human sentence', () => {
    const sentence = contextSentence(
      [
        { id: 'a', kind: 'application', label: 'App', removable: false },
        { id: 'f', kind: 'file', label: 'flake.nix', removable: true },
      ],
      'App',
    )
    expect(sentence).toContain('this application (App)')
    expect(sentence).toContain('flake.nix')
    expect(sentence).toContain('your message')
    expect(sentence).toContain('Nothing else')
  })
})
