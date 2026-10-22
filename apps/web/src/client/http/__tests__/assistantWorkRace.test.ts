import { describe, expect, it } from 'vitest'

import live from './fixtures/live-conversation-20261022.json'
import { HttpAssistantConversationClient } from '../domainsAssistantConversation'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

// Real service bytes from a dev loop, 2026-10-22: one user message and its (failed) assistant work item.
type Live = { instanceId: string; conversation: { result: Record<string, unknown> }; work: { result: unknown } }
const { instanceId, conversation, work } = live as unknown as Live
const before = { ...conversation.result, messages: [] }

function client(transcripts: unknown[]) {
  let reads = 0
  const fake = makeFakeFetch([
    ['GET', `/v1/instances/${instanceId}/conversation`, () => jsonResponse(transcripts[Math.min(reads++, transcripts.length - 1)])],
    ['GET', `/v1/instances/${instanceId}/conversation/assistant-work`, jsonResponse(work.result)],
  ])
  return { conversations: new HttpAssistantConversationClient(new HttpTransport({ fetchFn: fake.fetchFn })), reads: () => reads }
}

describe('assistant work read between two transcript reads', () => {
  it('a message sent between the two reads is picked up by reading the transcript again', async () => {
    const { conversations, reads } = client([before, conversation.result])
    const loaded = await conversations.get(instanceId)
    expect(reads()).toBe(2)
    expect(loaded.messages.some((message) => message.role === 'user')).toBe(true)
    expect(loaded.messages.some((message) => message.role === 'assistant')).toBe(true)
  })

  it('work for a message the transcript still lacks is left for the next read, the conversation still loads', async () => {
    const { conversations } = client([before])
    const loaded = await conversations.get(instanceId)
    expect(loaded.messages).toHaveLength(0)
  })
})
