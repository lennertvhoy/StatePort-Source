import { describe, expect, it } from 'vitest'

import { HttpClient } from '../adapter'
import { HttpCancellableAssistantConversationClient } from '../domainsCancellableAssistantConversation'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const INSTANCE_ID = 'ins_1'
const APPLICATION_ID = 'pkg_project_state'
const CONVERSATION_ID = 'conv_1'
const USER_ID = 'msg_srv_1'
const REPLY_ID = 'msg_srv_2'
const WORK_ID = `assistant.${'a'.repeat(32)}`
const ATTEMPT_ID = `attempt.${WORK_ID}.1`
const LF = String.fromCharCode(10)

function boundMessage(message: Record<string, unknown>) {
  return {
    ...message,
    conversationId: CONVERSATION_ID,
    applicationId: APPLICATION_ID,
    instanceId: INSTANCE_ID,
  }
}

const USER_MESSAGE = {
  ...boundMessage({ id: USER_ID }),
  kind: 'user_message',
  text: 'hello',
  createdAt: '2026-07-21T09:00:00.000Z',
}

const ASSISTANT_MESSAGE = {
  ...boundMessage({ id: REPLY_ID }),
  kind: 'assistant_message',
  text: 'Durable reply.',
  createdAt: '2026-07-21T09:00:01.000Z',
}

function presentation(messages: Array<Record<string, unknown>>) {
  return {
    formatVersion: 'stateport.conversation-presentation/v1',
    applicationBinding: {
      applicationId: APPLICATION_ID,
      instanceId: INSTANCE_ID,
    },
    thread: {
      conversationId: CONVERSATION_ID,
      applicationId: APPLICATION_ID,
      instanceId: INSTANCE_ID,
      title: 'Project conversation',
      channel: 'web',
      createdAt: '2026-07-21T08:00:00.000Z',
      updatedAt: '2026-07-21T09:00:01.000Z',
    },
    messages,
    channelBindings: [{ channel: 'web', state: 'delivered' }],
    pendingApprovals: [],
    receipts: [],
    retentionStatus: { note: 'Kept on this machine.' },
    authority: { channel: 'web' },
  }
}

function sse(frames: Array<{ id?: string; event: string; data: unknown }>): Response {
  const lines: string[] = []
  for (const frame of frames) {
    if (frame.id) lines.push(`id: ${frame.id}`)
    lines.push(`event: ${frame.event}`)
    lines.push(`data: ${JSON.stringify(frame.data)}`)
    lines.push('')
  }
  lines.push('')
  return new Response(lines.join(LF), {
    status: 200,
    headers: { 'Content-Type': 'text/event-stream; charset=utf-8' },
  })
}

function streamEvent(sequence: number) {
  return {
    formatVersion: 'stateport.assistant-stream-event/v1',
    workId: WORK_ID,
    messageId: USER_ID,
    attemptId: ATTEMPT_ID,
    sequence,
    occurredAt: `2026-07-21T09:00:0${sequence}.000Z`,
  }
}

describe('assistant continuity and production selection', () => {
  it('selects the exact durable cancellable client, not the legacy constructor', () => {
    const client = new HttpClient({
      fetchFn: makeFakeFetch([]).fetchFn,
    })
    expect(client.conversation.constructor).toBe(
      HttpCancellableAssistantConversationClient,
    )
  })

  it('resumes after Last-Event-ID without replay or model reinvocation', async () => {
    let streamConnections = 0
    const eventPath =
      `/v1/instances/${INSTANCE_ID}/conversation/messages/${USER_ID}/events`
    const fake = makeFakeFetch([
      [
        'POST',
        `/v1/instances/${INSTANCE_ID}/conversation/messages`,
        jsonResponse({
          ok: true,
          result: { presentation: presentation([USER_MESSAGE]) },
        }),
      ],
      [
        'GET',
        eventPath,
        () => {
          streamConnections += 1
          if (streamConnections === 1) {
            return sse([
              {
                id: `event.${WORK_ID}.2`,
                event: 'assistant_event',
                data: {
                  ...streamEvent(2),
                  type: 'process.started',
                  payload: {},
                },
              },
            ])
          }
          return sse([
            {
              id: `event.${WORK_ID}.3`,
              event: 'assistant_result',
              data: {
                ...streamEvent(3),
                text: 'Durable reply.',
                runtime: { profileDigest: `sha256:${'b'.repeat(64)}` },
                adapter: { id: 'codex-cli', version: 'fixture' },
                provider: { id: 'codex-local' },
                model: { id: 'fixture' },
                usage: { availability: 'unavailable' },
              },
            },
            {
              id: `event.${WORK_ID}.5`,
              event: 'message_end',
              data: {
                ...streamEvent(5),
                status: 'completed',
                replyMessageId: REPLY_ID,
              },
            },
          ])
        },
      ],
      [
        'GET',
        `/v1/instances/${INSTANCE_ID}/conversation`,
        jsonResponse({
          ok: true,
          result: presentation([USER_MESSAGE, ASSISTANT_MESSAGE]),
        }),
      ],
    ])
    const client = new HttpCancellableAssistantConversationClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    const { stream } = await client.sendMessage(INSTANCE_ID, {
      content: 'hello',
    })
    const chunks = []
    for await (const chunk of stream) chunks.push(chunk)

    expect(chunks).toEqual([
      { type: 'delta', text: 'Durable reply.' },
      {
        type: 'done',
        message: expect.objectContaining({
          id: REPLY_ID,
          role: 'assistant',
          content: 'Durable reply.',
        }),
      },
    ])
    const streamCalls = fake.callsTo(eventPath)
    expect(streamCalls).toHaveLength(2)
    expect(streamCalls[0].headers['last-event-id']).toBeUndefined()
    expect(streamCalls[1].headers['last-event-id']).toBe(
      `event.${WORK_ID}.2`,
    )
    expect(
      fake.calls.filter(
        (call) =>
          call.method === 'POST' &&
          call.url.includes('/conversation/messages'),
      ),
    ).toHaveLength(1)
  })
})
