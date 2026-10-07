/**
 * HTTP conversation client (contract §"Conversation").
 *
 * - Presentation: `stateport.conversation-presentation/v1`, fail-closed.
 * - Sends use an idempotent clientMessageId; a failed send keeps the same
 *   identity for the feature's retry (the send key is content-stable).
 * - Attachments are validated client-side (2 MiB, media-type allowlist)
 *   before any bytes leave.
 * - There is no streaming endpoint in the contract (long-running run
 *   streaming is a future capability): a synchronous reply in the send
 *   response is surfaced as a one-chunk stream; when the service accepts a
 *   message without a reply the stream ends as accepted without fabricating
 *   either an assistant message or a failed response.
 */
import { z } from 'zod'

import type { ConversationClient, ConversationSendInput } from '../client'
import type {
  Attachment,
  Conversation,
  ConversationMessage,
  ConversationStreamChunk,
  MessageStream,
  Receipt,
} from '../types'
import { ClientError } from '../types'
import { ALLOWED_ATTACHMENT_TYPES, MAX_ATTACHMENT_BYTES } from '../attachmentPolicy'
import { endpoints, FORMAT } from './endpoints'
import { mapAttachment, mapConversation, mapSendResult } from './mappers'
import { HttpTransport } from './transport'

const unknownPayload = z.unknown()
const sha256Wire = z.string().regex(/^sha256:[0-9a-f]{64}$/)

const attachmentMetadataWire = z.object({
  formatVersion: z.literal('stateport.conversation-attachment/v1'),
  attachmentId: z.string().regex(/^att-[0-9a-f]{32}$/),
  name: z.string().min(1).max(128),
  mediaType: z.string().refine(
    (value) => (ALLOWED_ATTACHMENT_TYPES as readonly string[]).includes(value),
    'unsupported attachment media type',
  ),
  sizeBytes: z.number().int().positive().max(MAX_ATTACHMENT_BYTES),
  digest: sha256Wire,
  storageKey: z.string().regex(/^sha256\/[0-9a-f]{64}$/),
  sensitivityLabel: z.enum(['public', 'internal', 'private']),
  retentionClass: z.enum(['conversation_30_days', 'conversation_90_days']),
  createdAt: z.iso.datetime(),
  contextInclusion: z.object({
    status: z.literal('not_proposed'),
    automatic: z.literal(false),
  }).strict(),
}).strict()

const attachmentReceiptWire = z.object({
  formatVersion: z.literal('stateport.conversation-attachment-receipt/v1'),
  receiptId: z.string().regex(/^attachment-receipt-[0-9a-f]{32}$/),
  attachmentId: z.string().regex(/^att-[0-9a-f]{32}$/),
  action: z.enum(['upload', 'delete', 'export']),
  createdAt: z.iso.datetime(),
  payloadDigest: sha256Wire,
  rawBytesIncluded: z.literal(false),
  contextInclusion: z.literal('not_proposed'),
}).strict()

const attachmentMutationWire = z.object({
  attachment: attachmentMetadataWire,
  receipt: attachmentReceiptWire,
}).strict()

const transcriptRetentionWire = z.object({
  formatVersion: z.literal(FORMAT.transcriptRetentionStatus),
  conversationId: z.string().min(1),
  applicationId: z.string().min(1),
  instanceId: z.string().min(1),
  retention: z.enum(['memory_only', 'explicit_capture']),
  storage: z.enum(['process_memory', 'durable_local']),
  status: z.enum(['empty', 'retained']),
  messageCount: z.number().int().nonnegative(),
  expiryStatus: z.literal('no_automatic_expiry_scheduled'),
  expiresAt: z.null(),
  evaluatedAt: z.iso.datetime(),
}).strict()

const transcriptMessageWire = z.object({
  formatVersion: z.literal('stateport.message-envelope/v1'),
  messageId: z.string().min(1),
  conversationId: z.string().min(1),
  applicationId: z.string().min(1),
  instanceId: z.string().min(1),
  senderParticipantId: z.string().min(1),
  sourceChannel: z.enum(['web', 'telegram']),
  sourceBindingId: z.string().min(1).nullable(),
  sequence: z.number().int().positive(),
  createdAt: z.iso.datetime(),
  observedAt: z.iso.datetime(),
  kind: z.enum([
    'user_message',
    'assistant_message',
    'system_message',
    'run_event',
    'tool_event',
    'state_proposal_reference',
  ]),
  body: z.string(),
  replyToMessageId: z.string().min(1).nullable(),
  attachments: z.array(z.unknown()).max(16),
  externalIdentity: z.record(z.string(), z.unknown()).nullable(),
  authority: z.literal('operational_noncanonical'),
  canonicalStateEffect: z.literal('none'),
  proposalReference: z.string().min(1).nullable(),
  collapsedByDefault: z.boolean(),
  deduplicationKey: z.string().regex(/^sha256:[0-9a-f]{64}$/),
}).strict()

const transcriptExportWire = z.object({
  formatVersion: z.literal(FORMAT.transcriptExport),
  exportId: z.string().min(1),
  generatedAt: z.iso.datetime(),
  metadata: z.object({
    conversationId: z.string().min(1),
    applicationId: z.string().min(1),
    instanceId: z.string().min(1),
    threadStatus: z.enum(['active', 'closed']),
    retentionStatus: transcriptRetentionWire,
  }).strict(),
  messages: z.array(transcriptMessageWire).max(10_000),
}).strict()

const transcriptLifecycleReceiptWire = z.object({
  formatVersion: z.literal(FORMAT.transcriptLifecycleReceipt),
  receiptId: z.string().min(1),
  requestId: z.string().min(1),
  operation: z.enum(['export', 'clear']),
  applicationId: z.string().min(1),
  instanceId: z.string().min(1),
  conversationId: z.string().min(1),
  performedBy: z.string().min(1),
  occurredAt: z.iso.datetime(),
  threadIdentity: z.literal('preserved'),
  bindingPolicy: z.literal('preserved'),
  removed: z.object({
    messages: z.number().int().nonnegative(),
    deliveries: z.number().int().nonnegative(),
    deduplicationEntries: z.number().int().nonnegative(),
    proposals: z.number().int().nonnegative(),
    echoGuards: z.number().int().nonnegative(),
  }).strict(),
  authority: z.literal('operational_noncanonical'),
  canonicalStateEffect: z.literal('none'),
}).strict()

const transcriptExportResponseWire = z.object({
  export: transcriptExportWire,
  receipt: transcriptLifecycleReceiptWire,
}).strict()

const transcriptClearResponseWire = z.object({
  receipt: transcriptLifecycleReceiptWire,
  canonicalStateEffect: z.literal('none'),
}).strict()

type TranscriptLifecycleReceiptWire = z.infer<typeof transcriptLifecycleReceiptWire>

function lifecycleContractError(detail: string): never {
  throw new ClientError('validation', 'The conversation lifecycle response failed closed', {
    detail,
  })
}

function bindTranscriptLifecycleReceipt(
  wire: TranscriptLifecycleReceiptWire,
  expected: {
    operation: 'export' | 'clear'
    instanceId: string
    conversationId: string
    requestId: string
  },
): Receipt {
  if (wire.operation !== expected.operation) {
    lifecycleContractError(
      `Expected ${expected.operation} receipt, received ${wire.operation}.`,
    )
  }
  if (wire.instanceId !== expected.instanceId) {
    lifecycleContractError('The receipt instance identity does not match the selected application.')
  }
  if (wire.conversationId !== expected.conversationId) {
    lifecycleContractError('The receipt conversation identity changed during the request.')
  }
  if (wire.requestId !== expected.requestId) {
    lifecycleContractError('The receipt request identity does not match the submitted lifecycle request.')
  }
  if (
    wire.operation === 'export' &&
    Object.values(wire.removed).some((count) => count !== 0)
  ) {
    lifecycleContractError('A transcript export receipt claims that operational records were removed.')
  }
  const action = wire.operation === 'export' ? 'Conversation exported' : 'Conversation cleared'
  const summary =
    wire.operation === 'export'
      ? 'The operational conversation transcript was exported without changing canonical application state.'
      : `The operational conversation transcript was cleared (${wire.removed.messages} messages removed) without changing canonical application state.`
  return {
    id: wire.receiptId,
    instanceId: wire.instanceId,
    packageId: wire.applicationId,
    actionName: action,
    eventKind: `conversation.${wire.operation}`,
    actor: 'user',
    result: 'completed_without_change',
    createdAt: wire.occurredAt,
    validation: {
      state: 'not_required',
      detail: 'This receipt records an operational transcript lifecycle action; canonical application state is explicitly unchanged.',
    },
    summary,
    relatedConversationId: wire.conversationId,
    rawJson: JSON.stringify(wire, null, 2),
  }
}

export { ALLOWED_ATTACHMENT_TYPES, MAX_ATTACHMENT_BYTES }

export function validateAttachmentInput(input: { name: string; mimeType: string; sizeBytes: number }): void {
  if (input.sizeBytes > MAX_ATTACHMENT_BYTES) {
    throw new ClientError(
      'validation',
      `Attachment "${input.name}" exceeds the 2 MiB limit and was not uploaded`,
      { detail: `${input.sizeBytes} bytes > ${MAX_ATTACHMENT_BYTES} bytes (contract limit).` },
    )
  }
  if (!ALLOWED_ATTACHMENT_TYPES.includes(input.mimeType)) {
    throw new ClientError(
      'validation',
      `Attachment "${input.name}" has an unsupported media type (${input.mimeType}) and was not uploaded`,
      { detail: `Supported types: ${ALLOWED_ATTACHMENT_TYPES.join(', ')}.` },
    )
  }
}

function newClientMessageId(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return `cmsg_${[...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')}`
}

/** A one-shot MessageStream over a synchronous send response. */
class HttpMessageStream implements MessageStream {
  readonly messageId: string
  private chunks: ConversationStreamChunk[]
  private stopped = false

  constructor(
    reply: ConversationMessage | undefined,
    acceptedMessageId: string,
    noReplyReason: string,
  ) {
    if (reply) {
      this.messageId = reply.id
      this.chunks = [
        ...(reply.content ? [{ type: 'delta', text: reply.content } as const] : []),
        { type: 'done', message: reply },
      ]
    } else {
      // Honest end: conversation ingest is a valid backend capability even
      // when no assistant processor is connected to produce a reply.
      this.messageId = acceptedMessageId
      this.chunks = [{ type: 'accepted', message: noReplyReason }]
    }
  }

  stop(): void {
    this.stopped = true
  }

  async *[Symbol.asyncIterator](): AsyncIterator<ConversationStreamChunk> {
    for (const chunk of this.chunks) {
      if (this.stopped) return
      yield chunk
    }
  }
}

export class HttpConversationClient implements ConversationClient {
  /**
   * Send key → clientMessageId, retained while a send is in-flight or failed
   * so the feature's retry preserves the idempotent identity (contract §14).
   */
  private pendingSends = new Map<string, string>()
  private conversations = new Map<string, string>()
  private attachmentReferences = new Map<string, {
    attachmentId: string
    name: string
    mediaType: string
    sizeBytes: number
    digest: string
  }>()
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async get(instanceId: string): Promise<Conversation> {
    const payload = await this.transport.request(endpoints.conversation(instanceId), {
      schema: unknownPayload,
    })
    const conversation = mapConversation(payload, instanceId)
    this.conversations.set(instanceId, conversation.id)
    return conversation
  }

  private sendKey(instanceId: string, input: ConversationSendInput): string {
    const attachmentIds = (input.attachments ?? []).map((a) => a.id).join(',')
    return `${instanceId}␟${input.content}␟${attachmentIds}`
  }

  async sendMessage(
    instanceId: string,
    input: ConversationSendInput,
  ): Promise<{ userMessage: ConversationMessage; stream: MessageStream }> {
    if (input.resumeMessageId) {
      // The contract has no live-stream endpoint to re-attach to; the surface
      // marks the message interrupted and offers retry instead of faking one.
      return Promise.reject(
        new ClientError('unavailable', 'Resuming a live response stream is not available against the connected service', {
          detail: 'The contract has no streaming endpoint; a response interrupted by a reload cannot be re-attached.',
        }),
      )
    }
    const key = this.sendKey(instanceId, input)
    const clientMessageId = input.clientMessageId ?? this.pendingSends.get(key) ?? newClientMessageId()
    this.pendingSends.set(key, clientMessageId)
    // On failure the pending identity stays cached: the feature's retry
    // reuses the same clientMessageId (idempotent per contract §14).
    const attachmentReferences = (input.attachments ?? []).map((attachment) => {
      const reference = this.attachmentReferences.get(`${instanceId}\u001f${attachment.id}`)
      if (!reference) {
        throw new ClientError('validation', `Attachment "${attachment.name}" is not bound to this conversation`, {
          detail: 'Only an exact service-issued attachment reference may be sent.',
        })
      }
      return reference
    })
    const payload = await this.transport.request(endpoints.conversationMessages(instanceId), {
      method: 'POST',
      body: {
        clientMessageId,
        text: input.content,
        replyToExternalMessageId: null,
        attachments: attachmentReferences,
      },
      schema: unknownPayload,
    })
    const record = payload as { presentation?: unknown }
    if (record.presentation !== undefined) {
      const conversation = mapConversation(record.presentation, instanceId)
      this.conversations.set(instanceId, conversation.id)
    }
    const mapped = mapSendResult(payload, instanceId)
    this.pendingSends.delete(key)
    const stream = new HttpMessageStream(
      mapped.reply,
      mapped.userMessage.id,
      'Message accepted. No assistant processor is connected to this conversation.',
    )
    return { userMessage: mapped.userMessage, stream }
  }

  streamMessage(
    instanceId: string,
    input: ConversationSendInput,
  ): Promise<{ userMessage: ConversationMessage; stream: MessageStream }> {
    return this.sendMessage(instanceId, input)
  }

  /**
   * No retry endpoint exists in the contract — the feature's resend path
   * (which preserves clientMessageId) is the honest retry.
   */
  retryLast(): Promise<MessageStream> {
    return Promise.reject(
      new ClientError('unavailable', 'Server-side reply retry is not available against the connected service', {
        detail: 'The contract has no retry endpoint; resending preserves the idempotent clientMessageId.',
      }),
    )
  }

  async uploadAttachment(
    instanceId: string,
    input: { name: string; mimeType: string; sizeBytes: number; contentBase64?: string },
  ): Promise<Attachment> {
    validateAttachmentInput(input)
    if (!input.contentBase64) {
      throw new ClientError('validation', `Attachment "${input.name}" carried no bytes`, {
        detail: 'The connected service validates and stores exact bytes; metadata-only uploads are refused.',
      })
    }
    const payload = await this.transport.request(endpoints.conversationAttachments(instanceId), {
      method: 'POST',
      body: {
        name: input.name,
        mediaType: input.mimeType,
        dataBase64: input.contentBase64,
        sensitivityLabel: 'private',
        retentionClass: 'conversation_30_days',
      },
      schema: attachmentMutationWire,
    })
    const raw = payload.attachment
    if (
      raw.name !== input.name ||
      raw.mediaType !== input.mimeType ||
      raw.sizeBytes !== input.sizeBytes ||
      raw.sensitivityLabel !== 'private' ||
      raw.retentionClass !== 'conversation_30_days' ||
      payload.receipt.action !== 'upload' ||
      payload.receipt.attachmentId !== raw.attachmentId
    ) {
      throw new ClientError(
        'validation',
        'The service attachment response did not match the requested upload',
        {
          detail:
            'Attachment metadata and its receipt must preserve the exact uploaded identity and policy.',
        },
      )
    }
    const attachment = mapAttachment(raw)
    this.attachmentReferences.set(`${instanceId}\u001f${attachment.id}`, {
      attachmentId: raw.attachmentId,
      name: raw.name,
      mediaType: raw.mediaType,
      sizeBytes: raw.sizeBytes,
      digest: raw.digest,
    })
    return attachment
  }

  async deleteAttachment(instanceId: string, attachmentId: string): Promise<void> {
    const payload = await this.transport.request(endpoints.conversationAttachmentDelete(instanceId, attachmentId), {
      method: 'POST',
      body: {},
      schema: attachmentMutationWire,
    })
    if (
      payload.attachment.attachmentId !== attachmentId ||
      payload.receipt.attachmentId !== attachmentId ||
      payload.receipt.action !== 'delete'
    ) {
      throw new ClientError(
        'validation',
        'The service attachment deletion response changed identity',
        {
          detail:
            'A deletion is complete only when its metadata and receipt bind the requested attachment.',
        },
      )
    }
    this.attachmentReferences.delete(`${instanceId}\u001f${attachmentId}`)
  }

  async exportConversation(instanceId: string): Promise<{ markdown: string; receipt: Receipt }> {
    const conversationId = this.conversations.get(instanceId) ?? (await this.get(instanceId)).id
    const requestId = newLifecycleRequestId('export')
    const payload = await this.transport.request(endpoints.conversationExport(instanceId), {
      method: 'POST',
      body: {
        expectedConversationId: conversationId,
        requestId,
      },
      schema: transcriptExportResponseWire,
    })
    const exported = payload.export
    const retention = exported.metadata.retentionStatus
    if (
      exported.metadata.instanceId !== instanceId ||
      retention.instanceId !== instanceId
    ) {
      lifecycleContractError('The transcript export instance identity does not match the selected application.')
    }
    if (
      exported.metadata.conversationId !== conversationId ||
      retention.conversationId !== conversationId
    ) {
      lifecycleContractError('The transcript export conversation identity changed during the request.')
    }
    if (
      exported.metadata.applicationId !== retention.applicationId ||
      retention.status === 'empty' !== (retention.messageCount === 0) ||
      retention.messageCount !== exported.messages.length
    ) {
      lifecycleContractError('The transcript export retention identity or message count is inconsistent.')
    }
    const expectedStorage =
      retention.retention === 'memory_only' ? 'process_memory' : 'durable_local'
    if (retention.storage !== expectedStorage) {
      lifecycleContractError('The transcript export retention storage contradicts its retention policy.')
    }
    exported.messages.forEach((message, index) => {
      if (
        message.sequence !== index + 1 ||
        message.instanceId !== instanceId ||
        message.conversationId !== conversationId ||
        message.applicationId !== exported.metadata.applicationId
      ) {
        lifecycleContractError('A transcript export message has a mismatched scope or sequence.')
      }
    })
    const markdown = exported.messages.map((message) => {
      const role =
        message.kind === 'user_message'
          ? 'User'
          : message.kind === 'assistant_message'
            ? 'Assistant'
            : 'System'
      return `## ${role} · ${message.createdAt}\n\n${message.body}`
    }).join('\n\n')
    const receipt = bindTranscriptLifecycleReceipt(payload.receipt, {
      operation: 'export',
      instanceId,
      conversationId,
      requestId,
    })
    return { markdown, receipt }
  }

  /** Clear requires explicit confirmation; the UI collects it before calling. */
  async clearConversation(instanceId: string): Promise<{ receipt: Receipt }> {
    const conversationId = this.conversations.get(instanceId) ?? (await this.get(instanceId)).id
    const requestId = newLifecycleRequestId('clear')
    const payload = await this.transport.request(endpoints.conversationClear(instanceId), {
      method: 'POST',
      body: {
        expectedConversationId: conversationId,
        requestId,
        confirmation: 'CLEAR_CONVERSATION',
      },
      schema: transcriptClearResponseWire,
    })
    return {
      receipt: bindTranscriptLifecycleReceipt(payload.receipt, {
        operation: 'clear',
        instanceId,
        conversationId,
        requestId,
      }),
    }
  }
}

function newLifecycleRequestId(operation: 'export' | 'clear'): string {
  const bytes = new Uint8Array(12)
  crypto.getRandomValues(bytes)
  return `web-${operation}-${[...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`
}
