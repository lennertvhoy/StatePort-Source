import { describe, expect, it } from 'vitest'

import { HttpAssistantConversationClient } from '../domainsAssistantConversation'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const INSTANCE_ID = 'ins_1'
const APPLICATION_ID = 'pkg_project_state'
const CONVERSATION_ID = 'conv_1'
const USER_ID = 'msg_srv_1'
const REPLY_ID = 'msg_srv_2'
const WORK_ID = `assistant.${'a'.repeat(32)}`

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

function activeWork(state: 'queued' | 'invoking' | 'result_ready' | 'delivering' = 'invoking') {
  return {
    formatVersion: 'stateport.assistant-work-list/v1',
    conversationId: CONVERSATION_ID,
    enabled: true,
    runtime: {
      profileDigest: `sha256:${'b'.repeat(64)}`,
    },
    items: [
      {
        formatVersion: 'stateport.assistant-work-projection/v1',
        workId: WORK_ID,
        messageId: USER_ID,
        sourceSequence: 1,
        state,
        attemptId: `attempt.${WORK_ID}.1`,
        lastEventId: `event.${WORK_ID}.2`,
        error: null,
        createdAt: '2026-07-21T09:00:00.000Z',
        updatedAt: '2026-07-21T09:00:00.500Z',
      },
    ],
  }
}

function sseResponse(): Response {
  const result = {
    formatVersion: 'stateport.assistant-stream-event/v1',
    workId: WORK_ID,
    messageId: USER_ID,
    attemptId: `attempt.${WORK_ID}.1`,
    sequence: 3,
    occurredAt: '2026-07-21T09:00:01.000Z',
    text: 'Durable reply.',
    runtime: { profileDigest: `sha256:${'b'.repeat(64)}` },
    adapter: { id: 'codex-cli', version: 'fixture' },
    provider: { id: 'codex-local' },
    model: { id: 'fixture' },
    usage: { availability: 'unavailable' },
  }
  const end = {
    formatVersion: 'stateport.assistant-stream-event/v1',
    workId: WORK_ID,
    messageId: USER_ID,
    attemptId: `attempt.${WORK_ID}.1`,
    sequence: 5,
    occurredAt: '2026-07-21T09:00:02.000Z',
    status: 'completed',
    replyMessageId: REPLY_ID,
  }
  const body = [
    `id: event.${WORK_ID}.3`,
    'event: assistant_result',
    `data: ${JSON.stringify(result)}`,
    '',
    `id: event.${WORK_ID}.5`,
    'event: message_end',
    `data: ${JSON.stringify(end)}`,
    '',
    '',
  ].join(String.fromCharCode(10))
  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'text/event-stream; charset=utf-8' },
  })
}

describe('HttpAssistantConversationClient', () => {
  it('replaces the no-processor fake stream with durable SSE events', async () => {
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
        `/v1/instances/${INSTANCE_ID}/conversation/messages/${USER_ID}/events`,
        sseResponse(),
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
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const client = new HttpAssistantConversationClient(transport)

    const { userMessage, stream } = await client.sendMessage(INSTANCE_ID, {
      content: 'hello',
    })
    const chunks = []
    for await (const chunk of stream) chunks.push(chunk)

    expect(userMessage.id).toBe(USER_ID)
    expect(stream.messageId).toBe(`assistant_pending:${USER_ID}`)
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
    const eventCall = fake.callsTo(`/${USER_ID}/events`)[0]
    expect(eventCall.headers.accept).toBe('text/event-stream')
    expect(eventCall.url).not.toContain('token=')
  })

  it('keeps the user message accepted when assistant processing is disabled', async () => {
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
        `/v1/instances/${INSTANCE_ID}/conversation/messages/${USER_ID}/events`,
        jsonResponse({
          ok: false,
          error: {
            code: 'assistant_processor_unavailable',
            message: 'assistant processing is not enabled',
          },
        }, 503),
      ],
    ])
    const client = new HttpAssistantConversationClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    const { stream } = await client.sendMessage(INSTANCE_ID, { content: 'hello' })
    const chunks = []
    for await (const chunk of stream) chunks.push(chunk)

    expect(chunks).toEqual([
      {
        type: 'accepted',
        message:
          'Message saved. Assistant processing is not enabled or configured for this service.',
      },
    ])
  })

  it('reconstructs and resumes the same durable work after page refresh', async () => {
    let transcriptReads = 0
    const fake = makeFakeFetch([
      [
        'GET',
        `/v1/instances/${INSTANCE_ID}/conversation`,
        () => {
          transcriptReads += 1
          return jsonResponse({
            ok: true,
            result: presentation(
              transcriptReads >= 3
                ? [USER_MESSAGE, ASSISTANT_MESSAGE]
                : [USER_MESSAGE],
            ),
          })
        },
      ],
      [
        'GET',
        `/v1/instances/${INSTANCE_ID}/conversation/assistant-work`,
        jsonResponse({
          ok: true,
          result: activeWork(),
        }),
      ],
      [
        'GET',
        `/v1/instances/${INSTANCE_ID}/conversation/messages/${USER_ID}/events`,
        sseResponse(),
      ],
    ])
    const client = new HttpAssistantConversationClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    const restored = await client.get(INSTANCE_ID)
    const placeholder = restored.messages.find(
      (message) => message.id === `assistant_pending:${USER_ID}`,
    )
    expect(placeholder).toMatchObject({
      role: 'assistant',
      state: 'streaming',
      content: '',
    })

    const { userMessage, stream } = await client.streamMessage(INSTANCE_ID, {
      content: '',
      resumeMessageId: placeholder?.id,
    })
    const chunks = []
    for await (const chunk of stream) chunks.push(chunk)

    expect(userMessage.id).toBe(USER_ID)
    expect(stream.messageId).toBe(placeholder?.id)
    expect(chunks).toEqual([
      { type: 'delta', text: 'Durable reply.' },
      {
        type: 'done',
        message: expect.objectContaining({
          id: REPLY_ID,
          state: 'complete',
        }),
      },
    ])
    expect(transcriptReads).toBe(3)
  })
})
