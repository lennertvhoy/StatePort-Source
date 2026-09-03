/**
 * Conversation contract tests: idempotent clientMessageId (preserved across
 * the feature's retry), attachment validation (2 MiB + media types), and the
 * presentation mapping (stateport.conversation-presentation/v1).
 */
import { describe, expect, it } from 'vitest'

import { ClientError } from '../../types'
import { HttpTransport } from '../transport'
import { HttpConversationClient } from '../domainsConversation'
import { jsonResponse, makeFakeFetch } from './helpers'

const APPLICATION_ID = 'pkg_project_state'
const CONVERSATION_ID = 'conv_1'
const ATTACHMENT_ID = `att-${'1'.repeat(32)}`
const ATTACHMENT_DIGEST = `sha256:${'ab'.repeat(32)}`

function attachmentMutation(
  action: 'upload' | 'delete' = 'upload',
  overrides: {
    attachment?: Record<string, unknown>
    receipt?: Record<string, unknown>
  } = {},
) {
  return {
    attachment: {
      formatVersion: 'stateport.conversation-attachment/v1',
      attachmentId: ATTACHMENT_ID,
      name: 'notes.md',
      mediaType: 'text/markdown',
      sizeBytes: 10,
      digest: ATTACHMENT_DIGEST,
      storageKey: `sha256/${'ab'.repeat(32)}`,
      sensitivityLabel: 'private',
      retentionClass: 'conversation_30_days',
      createdAt: '2026-07-19T09:00:00.000Z',
      contextInclusion: {
        status: 'not_proposed',
        automatic: false,
      },
      ...overrides.attachment,
    },
    receipt: {
      formatVersion: 'stateport.conversation-attachment-receipt/v1',
      receiptId: `attachment-receipt-${'2'.repeat(32)}`,
      attachmentId: ATTACHMENT_ID,
      action,
      createdAt: '2026-07-19T09:00:00.000Z',
      payloadDigest: `sha256:${'cd'.repeat(32)}`,
      rawBytesIncluded: false,
      contextInclusion: 'not_proposed',
      ...overrides.receipt,
    },
  }
}

function boundMessage<T extends Record<string, unknown>>(message: T) {
  return {
    ...message,
    conversationId: CONVERSATION_ID,
    applicationId: APPLICATION_ID,
    instanceId: 'ins_1',
  }
}

const USER_MESSAGE = {
  ...boundMessage({ id: 'msg_srv_1' }),
  kind: 'user_message',
  text: 'hello',
  createdAt: '2026-07-04T09:00:00.000Z',
}

function presentation(messages: Array<Record<string, unknown>>) {
  return {
    formatVersion: 'stateport.conversation-presentation/v1',
    applicationBinding: {
      applicationId: APPLICATION_ID,
      instanceId: 'ins_1',
    },
    thread: {
      conversationId: CONVERSATION_ID,
      applicationId: APPLICATION_ID,
      instanceId: 'ins_1',
      title: 'Photography portfolio',
      channel: 'web',
      createdAt: '2026-07-04T08:00:00.000Z',
      updatedAt: '2026-07-04T09:00:00.000Z',
    },
    messages,
    channelBindings: [{ channel: 'web', state: 'delivered' }],
    pendingApprovals: [],
    receipts: [],
    retentionStatus: { note: 'Kept on this machine.' },
    authority: { channel: 'web' },
  }
}

function conversationClient(handler?: (call: { body?: unknown }) => Response) {
  const fake = makeFakeFetch([
    [
      'POST',
      '/v1/instances/ins_1/conversation/messages',
      handler ??
        (() =>
          jsonResponse({
            ok: true,
            result: { presentation: presentation([USER_MESSAGE]) },
          })),
    ],
  ])
  return { fake, client: new HttpConversationClient(new HttpTransport({ fetchFn: fake.fetchFn })) }
}

describe('HttpConversationClient — idempotent sends', () => {
  it('sends a stable clientMessageId and exact service-issued attachment references', async () => {
    const reference = {
      attachmentId: ATTACHMENT_ID,
      name: 'notes.md',
      mediaType: 'text/markdown',
      sizeBytes: 10,
      digest: ATTACHMENT_DIGEST,
    }
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/instances/ins_1/conversation/attachments',
        jsonResponse({ ok: true, result: attachmentMutation() }),
      ],
      [
        'POST',
        '/v1/instances/ins_1/conversation/messages',
        jsonResponse({
          ok: true,
          result: { presentation: presentation([USER_MESSAGE]) },
        }),
      ],
    ])
    const client = new HttpConversationClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const attachment = await client.uploadAttachment('ins_1', {
      name: 'notes.md',
      mimeType: 'text/markdown',
      sizeBytes: 10,
      contentBase64: 'MDEyMzQ1Njc4OQ==',
    })
    await client.sendMessage('ins_1', {
      content: 'hello',
      attachments: [attachment],
    })
    const call = fake.callsTo('/conversation/messages')[0]
    const body = call.body as { clientMessageId: string; text: string; attachments: typeof reference[] }
    expect(body.clientMessageId).toMatch(/^cmsg_[0-9a-f]{32}$/)
    expect(body.text).toBe('hello')
    expect(body.attachments).toEqual([reference])
  })

  it('preserves a caller-provided clientMessageId', async () => {
    const { fake, client } = conversationClient()
    await client.sendMessage('ins_1', { content: 'hello', clientMessageId: 'cmsg_fixed' })
    const call = fake.callsTo('/conversation/messages')[0]
    expect((call.body as { clientMessageId: string }).clientMessageId).toBe('cmsg_fixed')
  })

  it('reuses the same clientMessageId when the feature retries a failed send', async () => {
    let attempts = 0
    const { fake, client } = conversationClient(() => {
      attempts += 1
      // Fail the first attempt, succeed on the retry.
      return attempts === 1
        ? jsonResponse({ ok: false, error: { code: 'x', message: 'boom' } }, 500)
        : jsonResponse({
            ok: true,
            result: { presentation: presentation([USER_MESSAGE]) },
          })
    })
    await expect(client.sendMessage('ins_1', { content: 'hello' })).rejects.toBeInstanceOf(ClientError)
    await client.sendMessage('ins_1', { content: 'hello' })
    const calls = fake.callsTo('/conversation/messages')
    expect(calls).toHaveLength(2)
    const first = (calls[0].body as { clientMessageId: string }).clientMessageId
    const second = (calls[1].body as { clientMessageId: string }).clientMessageId
    expect(second).toBe(first)
  })

  it('streams a synchronous reply as one delta + done', async () => {
    const { client } = conversationClient(() =>
      jsonResponse({
        ok: true,
        result: {
          presentation: presentation([
            USER_MESSAGE,
            boundMessage({
              id: 'msg_srv_2',
              kind: 'assistant_message',
              text: 'Hi there.',
              createdAt: '2026-07-04T09:00:01.000Z',
            }),
          ]),
        },
      }),
    )
    const { stream } = await client.sendMessage('ins_1', { content: 'hello' })
    const chunks = []
    for await (const chunk of stream) chunks.push(chunk)
    expect(chunks).toEqual([
      { type: 'delta', text: 'Hi there.' },
      { type: 'done', message: expect.objectContaining({ id: 'msg_srv_2', role: 'assistant' }) },
    ])
  })

  it('ends as accepted without fabricating a reply when the service returns no reply', async () => {
    const { client } = conversationClient()
    const { stream } = await client.sendMessage('ins_1', { content: 'hello' })
    expect(stream.messageId).toBe('msg_srv_1')
    const chunks = []
    for await (const chunk of stream) chunks.push(chunk)
    expect(chunks).toEqual([
      {
        type: 'accepted',
        message: 'Message accepted. No assistant processor is connected to this conversation.',
      },
    ])
  })
})

describe('HttpConversationClient — attachments', () => {
  function attachmentClient() {
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/instances/ins_1/conversation/attachments',
        jsonResponse({
          ok: true,
          result: attachmentMutation(),
        }),
      ],
    ])
    return { fake, client: new HttpConversationClient(new HttpTransport({ fetchFn: fake.fetchFn })) }
  }

  it('rejects attachments over 2 MiB client-side (no request is made)', async () => {
    const { fake, client } = attachmentClient()
    const err = await client
      .uploadAttachment('ins_1', { name: 'big.png', mimeType: 'image/png', sizeBytes: 2 * 1024 * 1024 + 1 })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
    expect(fake.callsTo('/conversation/attachments')).toHaveLength(0)
  })

  it('rejects unsupported media types client-side', async () => {
    const { fake, client } = attachmentClient()
    const err = await client
      .uploadAttachment('ins_1', { name: 'run.exe', mimeType: 'application/x-msdownload', sizeBytes: 10 })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
    expect(fake.callsTo('/conversation/attachments')).toHaveLength(0)
  })

  it('uploads a valid attachment and maps the result', async () => {
    const { fake, client } = attachmentClient()
    const attachment = await client.uploadAttachment('ins_1', {
      name: 'notes.md',
      mimeType: 'text/markdown',
      sizeBytes: 10,
      contentBase64: 'MDEyMzQ1Njc4OQ==',
    })
    expect(attachment).toMatchObject({ id: ATTACHMENT_ID, name: 'notes.md', mimeType: 'text/markdown', state: 'ready' })
    const call = fake.callsTo('/conversation/attachments')[0]
    expect(call.body).toEqual({
      name: 'notes.md',
      mediaType: 'text/markdown',
      dataBase64: 'MDEyMzQ1Njc4OQ==',
      sensitivityLabel: 'private',
      retentionClass: 'conversation_30_days',
    })
  })

  it.each([
    [
      'changed upload metadata',
      attachmentMutation('upload', {
        attachment: { name: 'different.md' },
      }),
    ],
    [
      'a receipt for another attachment',
      attachmentMutation('upload', {
        receipt: { attachmentId: `att-${'3'.repeat(32)}` },
      }),
    ],
    [
      'the wrong receipt action',
      attachmentMutation('delete'),
    ],
  ])('fails closed when upload returns %s', async (_label, result) => {
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/instances/ins_1/conversation/attachments',
        jsonResponse({ ok: true, result }),
      ],
    ])
    const client = new HttpConversationClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    await expect(
      client.uploadAttachment('ins_1', {
        name: 'notes.md',
        mimeType: 'text/markdown',
        sizeBytes: 10,
        contentBase64: 'MDEyMzQ1Njc4OQ==',
      }),
    ).rejects.toMatchObject({ kind: 'validation' })
  })

  it('deletes only when metadata and receipt bind the requested attachment', async () => {
    const fake = makeFakeFetch([
      [
        'POST',
        `/v1/instances/ins_1/conversation/attachments/${ATTACHMENT_ID}/delete`,
        jsonResponse({ ok: true, result: attachmentMutation('delete') }),
      ],
    ])
    const client = new HttpConversationClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    await expect(
      client.deleteAttachment('ins_1', ATTACHMENT_ID),
    ).resolves.toBeUndefined()
    expect(
      fake.callsTo(`/conversation/attachments/${ATTACHMENT_ID}/delete`)[0],
    ).toMatchObject({
      method: 'POST',
      body: {},
      headers: { 'x-stateport-csrf': 'test-csrf' },
    })
  })

  it('fails closed when a deletion receipt changes attachment identity', async () => {
    const fake = makeFakeFetch([
      [
        'POST',
        `/v1/instances/ins_1/conversation/attachments/${ATTACHMENT_ID}/delete`,
        jsonResponse({
          ok: true,
          result: attachmentMutation('delete', {
            receipt: { attachmentId: `att-${'3'.repeat(32)}` },
          }),
        }),
      ],
    ])
    const client = new HttpConversationClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    await expect(
      client.deleteAttachment('ins_1', ATTACHMENT_ID),
    ).rejects.toMatchObject({ kind: 'validation' })
  })
})

describe('HttpConversationClient — presentation mapping', () => {
  const PRESENTATION = presentation([
    boundMessage({ id: 'm1', kind: 'user_message', text: 'hi', createdAt: '2026-07-04T08:30:00.000Z' }),
    boundMessage({ id: 'm2', kind: 'assistant_message', text: 'hello', createdAt: '2026-07-04T08:31:00.000Z' }),
    boundMessage({ id: 'm3', kind: 'run_event', summary: 'Run applied', createdAt: '2026-07-04T08:32:00.000Z' }),
    boundMessage({ id: 'm4', kind: 'state_proposal_reference', summary: 'Proposal ready', createdAt: '2026-07-04T08:33:00.000Z' }),
  ])

  it('maps the conversation presentation including all message kinds', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/conversation', jsonResponse({ ok: true, result: PRESENTATION })],
    ])
    const client = new HttpConversationClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const conversation = await client.get('ins_1')
    expect(conversation.id).toBe('conv_1')
    expect(conversation.messages.map((m) => m.role)).toEqual(['user', 'assistant', 'system', 'system'])
    expect(conversation.messages[2].toolEvents).toHaveLength(1)
    expect(conversation.messages[3].proposal?.title).toBe('State proposal')
    expect(conversation.deliveryState).toBe('delivered')
    expect(conversation.retentionNote).toBe('Kept on this machine.')
  })

  it('fails closed on the wrong formatVersion', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/conversation', jsonResponse({ ...PRESENTATION, formatVersion: 'stateport.conversation-presentation/v2' })],
    ])
    const client = new HttpConversationClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const err = await client.get('ins_1').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
  })

  it('fails closed when the presentation is bound to a different application instance', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/conversation',
        jsonResponse({
          ok: true,
          result: {
            ...PRESENTATION,
            applicationBinding: {
              applicationId: APPLICATION_ID,
              instanceId: 'ins_other',
            },
          },
        }),
      ],
    ])
    const client = new HttpConversationClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    const error = await client.get('ins_1').catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('fails closed on unknown message kinds', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/conversation',
        jsonResponse({
          ...PRESENTATION,
          messages: [
            boundMessage({ id: 'mx', kind: 'hologram', text: '?' }),
          ],
        }),
      ],
    ])
    const client = new HttpConversationClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const err = await client.get('ins_1').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
  })

  it.each([
    [
      'missing conversation identity',
      {
        thread: {
          ...PRESENTATION.thread,
          conversationId: undefined,
        },
      },
    ],
    [
      'contradictory thread identity',
      {
        thread: {
          ...PRESENTATION.thread,
          id: 'conv_other',
        },
      },
    ],
    [
      'message from another conversation',
      {
        messages: [
          {
            ...PRESENTATION.messages[0],
            conversationId: 'conv_other',
          },
        ],
      },
    ],
  ])('fails closed on %s', async (_label, override) => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/conversation',
        jsonResponse({ ...PRESENTATION, ...override }),
      ],
    ])
    const client = new HttpConversationClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    await expect(client.get('ins_1')).rejects.toMatchObject({
      kind: 'validation',
    })
  })
})

describe('HttpConversationClient — transcript lifecycle receipts', () => {
  const RETENTION = {
    formatVersion: 'stateport.transcript-retention-status/v1',
    conversationId: CONVERSATION_ID,
    applicationId: APPLICATION_ID,
    instanceId: 'ins_1',
    retention: 'explicit_capture',
    storage: 'durable_local',
    status: 'retained',
    messageCount: 1,
    expiryStatus: 'no_automatic_expiry_scheduled',
    expiresAt: null,
    evaluatedAt: '2026-07-19T09:00:00.000Z',
  } as const

  const EXPORTED_MESSAGE = {
    formatVersion: 'stateport.message-envelope/v1',
    messageId: 'msg_srv_1',
    conversationId: CONVERSATION_ID,
    applicationId: APPLICATION_ID,
    instanceId: 'ins_1',
    senderParticipantId: 'local-user',
    sourceChannel: 'web',
    sourceBindingId: 'binding-web-1',
    sequence: 1,
    createdAt: '2026-07-19T08:59:00.000Z',
    observedAt: '2026-07-19T08:59:00.000Z',
    kind: 'user_message',
    body: 'Export this operational message.',
    replyToMessageId: null,
    attachments: [],
    externalIdentity: null,
    authority: 'operational_noncanonical',
    canonicalStateEffect: 'none',
    proposalReference: null,
    collapsedByDefault: false,
    deduplicationKey: `sha256:${'a'.repeat(64)}`,
  } as const

  function lifecycleReceipt(
    operation: 'export' | 'clear',
    requestId: string,
    overrides: Record<string, unknown> = {},
  ) {
    return {
      formatVersion: 'stateport.transcript-lifecycle-receipt/v1',
      receiptId: `transcript-receipt-${operation}`,
      requestId,
      operation,
      applicationId: APPLICATION_ID,
      instanceId: 'ins_1',
      conversationId: CONVERSATION_ID,
      performedBy: 'local-user',
      occurredAt: '2026-07-19T09:00:00.000Z',
      threadIdentity: 'preserved',
      bindingPolicy: 'preserved',
      removed: {
        messages: operation === 'clear' ? 1 : 0,
        deliveries: 0,
        deduplicationEntries: operation === 'clear' ? 1 : 0,
        proposals: 0,
        echoGuards: 0,
      },
      authority: 'operational_noncanonical',
      canonicalStateEffect: 'none',
      ...overrides,
    }
  }

  function exportPayload(requestId: string, overrides: Record<string, unknown> = {}) {
    return {
      export: {
        formatVersion: 'stateport.transcript-export/v1',
        exportId: 'transcript-export-1',
        generatedAt: '2026-07-19T09:00:00.000Z',
        metadata: {
          conversationId: CONVERSATION_ID,
          applicationId: APPLICATION_ID,
          instanceId: 'ins_1',
          threadStatus: 'active',
          retentionStatus: RETENTION,
        },
        messages: [EXPORTED_MESSAGE],
      },
      receipt: lifecycleReceipt('export', requestId),
      ...overrides,
    }
  }

  it('maps the exact export artifact and lifecycle receipt without a follow-up receipt lookup', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/conversation',
        jsonResponse({ ok: true, result: presentation([USER_MESSAGE]) }),
      ],
      [
        'POST',
        '/v1/instances/ins_1/conversation/export',
        (call) => {
          const requestId = (call.body as { requestId: string }).requestId
          return jsonResponse({ ok: true, result: exportPayload(requestId) })
        },
      ],
    ])
    const client = new HttpConversationClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const exported = await client.exportConversation('ins_1')

    expect(exported.markdown).toContain('## User · 2026-07-19T08:59:00.000Z')
    expect(exported.markdown).toContain('Export this operational message.')
    expect(exported.receipt).toMatchObject({
      id: 'transcript-receipt-export',
      instanceId: 'ins_1',
      packageId: APPLICATION_ID,
      eventKind: 'conversation.export',
      result: 'completed_without_change',
      relatedConversationId: CONVERSATION_ID,
      validation: { state: 'not_required' },
    })
    const call = fake.callsTo('/conversation/export')[0]
    expect(call.body).toMatchObject({
      expectedConversationId: CONVERSATION_ID,
      requestId: expect.stringMatching(/^web-export-[0-9a-f]{24}$/),
    })
    expect(fake.callsTo('/receipts/')).toHaveLength(0)
  })

  it('returns and binds the exact clear receipt while preserving the no-canonical-effect claim', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/conversation',
        jsonResponse({ ok: true, result: presentation([USER_MESSAGE]) }),
      ],
      [
        'POST',
        '/v1/instances/ins_1/conversation/clear',
        (call) => {
          const requestId = (call.body as { requestId: string }).requestId
          return jsonResponse({
            ok: true,
            result: {
              receipt: lifecycleReceipt('clear', requestId),
              canonicalStateEffect: 'none',
            },
          })
        },
      ],
    ])
    const client = new HttpConversationClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const { receipt } = await client.clearConversation('ins_1')

    expect(receipt).toMatchObject({
      id: 'transcript-receipt-clear',
      eventKind: 'conversation.clear',
      result: 'completed_without_change',
      relatedConversationId: CONVERSATION_ID,
    })
    expect(fake.callsTo('/conversation/clear')[0].body).toMatchObject({
      expectedConversationId: CONVERSATION_ID,
      requestId: expect.stringMatching(/^web-clear-[0-9a-f]{24}$/),
      confirmation: 'CLEAR_CONVERSATION',
    })
  })

  type LifecycleMutation = {
    receipt?: Record<string, unknown>
    exportMetadata?: Record<string, unknown>
    message?: Record<string, unknown>
  }

  it.each<[string, LifecycleMutation]>([
    ['receipt conversation identity', { receipt: { conversationId: 'conv_other' } }],
    ['receipt instance identity', { receipt: { instanceId: 'ins_other' } }],
    ['receipt authority', { receipt: { authority: 'canonical' } }],
    ['canonical-state effect', { receipt: { canonicalStateEffect: 'changed' } }],
    ['export artifact instance identity', { exportMetadata: { instanceId: 'ins_other' } }],
    ['export message sequence', { message: { sequence: 2 } }],
  ])('fails closed on mismatched %s', async (_label, mutation) => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/conversation',
        jsonResponse({ ok: true, result: presentation([USER_MESSAGE]) }),
      ],
      [
        'POST',
        '/v1/instances/ins_1/conversation/export',
        (call) => {
          const requestId = (call.body as { requestId: string }).requestId
          const payload = exportPayload(requestId)
          if (mutation.receipt) {
            payload.receipt = { ...payload.receipt, ...mutation.receipt }
          }
          if (mutation.exportMetadata) {
            payload.export.metadata = {
              ...payload.export.metadata,
              ...mutation.exportMetadata,
            }
          }
          if (mutation.message) {
            payload.export.messages = [
              { ...payload.export.messages[0], ...mutation.message },
            ]
          }
          return jsonResponse({ ok: true, result: payload })
        },
      ],
    ])
    const client = new HttpConversationClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(client.exportConversation('ins_1')).rejects.toMatchObject({
      kind: 'validation',
    })
  })
})
