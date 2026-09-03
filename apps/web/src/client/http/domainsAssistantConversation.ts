import { z } from 'zod'

import type { ConversationSendInput } from '../client'
import type {
  Conversation,
  ConversationMessage,
  ConversationStreamChunk,
  MessageStream,
} from '../types'
import { ClientError } from '../types'
import { HttpConversationClient } from './domainsConversation'
import { endpoints } from './endpoints'
import { HttpTransport } from './transport'

const LF = String.fromCharCode(10)
const CRLF = String.fromCharCode(13, 10)
const FRAME_BOUNDARY = LF + LF
const PENDING_PREFIX = 'assistant_pending:'

const streamBaseWire = z.object({
  formatVersion: z.literal('stateport.assistant-stream-event/v1'),
  workId: z.string().regex(/^assistant\.[0-9a-f]{32}$/),
  messageId: z.string().min(1),
  attemptId: z.string().nullable().optional(),
  sequence: z.number().int().positive().optional(),
  occurredAt: z.iso.datetime().optional(),
})

const assistantResultWire = streamBaseWire.extend({
  text: z.string().min(1).max(262_144),
  runtime: z.record(z.string(), z.unknown()),
  adapter: z.record(z.string(), z.unknown()),
  provider: z.record(z.string(), z.unknown()),
  model: z.record(z.string(), z.unknown()),
  usage: z.record(z.string(), z.unknown()),
}).strict()

const messageEndWire = streamBaseWire.extend({
  status: z.literal('completed'),
  replyMessageId: z.string().min(1),
}).strict()

const assistantErrorWire = streamBaseWire.extend({
  status: z.string(),
  error: z.record(z.string(), z.unknown()).nullable().optional(),
}).strict()

const assistantWorkItemWire = z.object({
  formatVersion: z.literal('stateport.assistant-work-projection/v1'),
  workId: z.string().regex(/^assistant\.[0-9a-f]{32}$/),
  messageId: z.string().min(1),
  sourceSequence: z.number().int().positive(),
  state: z.enum([
    'queued',
    'invoking',
    'result_ready',
    'delivering',
    'failed',
    'cancelled',
  ]),
  attemptId: z.string().nullable(),
  lastEventId: z.string().nullable(),
  error: z.object({
    code: z.string().min(1),
    message: z.string().min(1).max(2_048),
  }).nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
}).strict()

const assistantWorkListWire = z.object({
  formatVersion: z.literal('stateport.assistant-work-list/v1'),
  conversationId: z.string().min(1),
  enabled: z.boolean(),
  runtime: z.record(z.string(), z.unknown()).optional(),
  items: z.array(assistantWorkItemWire).max(100),
}).strict()

interface SseFrame {
  id?: string
  event: string
  data: unknown
}

function parseFrame(raw: string): SseFrame | null {
  let id: string | undefined
  let event = 'message'
  const data: string[] = []
  for (const line of raw.replaceAll(CRLF, LF).split(LF)) {
    if (!line || line.startsWith(':')) continue
    const separator = line.indexOf(':')
    const field = separator < 0 ? line : line.slice(0, separator)
    const value = separator < 0
      ? ''
      : line.slice(separator + 1).replace(/^ /, '')
    if (field === 'id') id = value
    else if (field === 'event') event = value
    else if (field === 'data') data.push(value)
  }
  if (data.length === 0) return null
  let decoded: unknown
  try {
    decoded = JSON.parse(data.join(LF))
  } catch {
    throw new ClientError(
      'validation',
      'Assistant event stream returned malformed JSON',
    )
  }
  return { id, event, data: decoded }
}

async function* frames(response: Response): AsyncGenerator<SseFrame> {
  const reader = response.body?.getReader()
  if (!reader) {
    throw new ClientError(
      'validation',
      'Assistant event stream has no readable body',
    )
  }
  const decoder = new TextDecoder()
  let buffer = ''
  try {
    while (true) {
      const { value, done } = await reader.read()
      buffer += decoder
        .decode(value, { stream: !done })
        .replaceAll(CRLF, LF)
      let boundary = buffer.indexOf(FRAME_BOUNDARY)
      while (boundary >= 0) {
        const raw = buffer.slice(0, boundary)
        buffer = buffer.slice(boundary + FRAME_BOUNDARY.length)
        const frame = parseFrame(raw)
        if (frame) yield frame
        boundary = buffer.indexOf(FRAME_BOUNDARY)
      }
      if (done) break
    }
    const trailing = parseFrame(buffer)
    if (trailing) yield trailing
  } finally {
    reader.releaseLock()
  }
}

class AssistantEventStream implements MessageStream {
  readonly messageId: string
  private readonly abort = new AbortController()
  private readonly transport: HttpTransport
  private readonly transcriptClient: HttpConversationClient
  private readonly instanceId: string
  private readonly sourceMessageId: string
  private stopped = false
  private lastEventId: string | undefined

  constructor(
    transport: HttpTransport,
    transcriptClient: HttpConversationClient,
    instanceId: string,
    sourceMessageId: string,
  ) {
    this.transport = transport
    this.transcriptClient = transcriptClient
    this.instanceId = instanceId
    this.sourceMessageId = sourceMessageId
    this.messageId = `${PENDING_PREFIX}${sourceMessageId}`
  }

  stop(): void {
    if (this.stopped) return
    this.stopped = true
    this.abort.abort()
  }

  private async finalMessage(
    replyMessageId: string,
  ): Promise<ConversationMessage> {
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const conversation = await this.transcriptClient.get(this.instanceId)
      const reply = conversation.messages.find(
        (message) => message.id === replyMessageId,
      )
      if (reply?.role === 'assistant') return reply
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
    throw new ClientError(
      'validation',
      'The assistant completion event referenced a reply that was not present in the durable conversation',
    )
  }

  async *[Symbol.asyncIterator](): AsyncIterator<ConversationStreamChunk> {
    let reconnects = 0
    while (!this.stopped && reconnects <= 3) {
      try {
        const response = await this.transport.stream(
          endpoints.conversationMessageEvents(
            this.instanceId,
            this.sourceMessageId,
          ),
          {
            signal: this.abort.signal,
            lastEventId: this.lastEventId,
          },
        )
        for await (const frame of frames(response)) {
          if (this.stopped) return
          if (frame.id) {
            if (
              this.lastEventId !== undefined &&
              frame.id === this.lastEventId
            ) {
              continue
            }
            this.lastEventId = frame.id
          }
          if (
            frame.event === 'heartbeat' ||
            frame.event === 'assistant_event'
          ) {
            continue
          }
          if (frame.event === 'assistant_result') {
            const result = assistantResultWire.parse(frame.data)
            if (result.messageId !== this.sourceMessageId) {
              throw new ClientError(
                'validation',
                'Assistant result changed source-message identity',
              )
            }
            yield { type: 'delta', text: result.text }
            continue
          }
          if (frame.event === 'message_end') {
            const end = messageEndWire.parse(frame.data)
            if (end.messageId !== this.sourceMessageId) {
              throw new ClientError(
                'validation',
                'Assistant completion changed source-message identity',
              )
            }
            yield {
              type: 'done',
              message: await this.finalMessage(end.replyMessageId),
            }
            return
          }
          if (frame.event === 'assistant_error') {
            const failure = assistantErrorWire.parse(frame.data)
            if (failure.messageId !== this.sourceMessageId) {
              throw new ClientError(
                'validation',
                'Assistant failure changed source-message identity',
              )
            }
            yield {
              type: 'error',
              message:
                typeof failure.error?.message === 'string'
                  ? failure.error.message
                  : 'The assistant attempt failed. Your message remains durable.',
            }
            return
          }
          if (frame.event === 'stream_timeout') break
        }
        reconnects += 1
      } catch (cause) {
        if (this.stopped || this.abort.signal.aborted) {
          yield {
            type: 'accepted',
            message:
              'Stopped listening. The durable assistant attempt may still finish; reload the conversation to see its final result.',
          }
          return
        }
        if (
          cause instanceof ClientError &&
          (
            cause.kind === 'unavailable' ||
            (cause.kind === 'http' && cause.status === 404)
          )
        ) {
          yield {
            type: 'accepted',
            message:
              'Message saved. Assistant processing is not enabled or configured for this service.',
          }
          return
        }
        if (reconnects >= 3) throw cause
        reconnects += 1
        await new Promise((resolve) =>
          setTimeout(resolve, 250 * reconnects),
        )
      }
    }
    if (!this.stopped) {
      yield {
        type: 'error',
        message:
          'The assistant event stream could not be reattached after repeated interruptions.',
      }
    }
  }
}

export class HttpAssistantConversationClient extends HttpConversationClient {
  private readonly assistantTransport: HttpTransport
  private readonly transcriptClient: HttpConversationClient

  constructor(assistantTransport: HttpTransport) {
    super(assistantTransport)
    this.assistantTransport = assistantTransport
    this.transcriptClient = new HttpConversationClient(assistantTransport)
  }

  override async get(instanceId: string): Promise<Conversation> {
    const conversation = await this.transcriptClient.get(instanceId)
    let projection: z.infer<typeof assistantWorkListWire>
    try {
      projection = await this.assistantTransport.request(
        endpoints.conversationAssistantWork(instanceId),
        { schema: assistantWorkListWire },
      )
    } catch (cause) {
      if (
        cause instanceof ClientError &&
        cause.kind === 'http' &&
        cause.status === 404
      ) {
        return conversation
      }
      throw cause
    }
    if (projection.conversationId !== conversation.id) {
      throw new ClientError(
        'validation',
        'Assistant work projection changed conversation identity',
      )
    }
    if (!projection.enabled || projection.items.length === 0) {
      return conversation
    }

    const placeholders: ConversationMessage[] = []
    for (const item of projection.items) {
      const source = conversation.messages.find(
        (message) => message.id === item.messageId,
      )
      if (!source || source.role !== 'user') {
        throw new ClientError(
          'validation',
          'Assistant work references a missing user message',
          { detail: item.messageId },
        )
      }
      const state =
        item.state === 'failed'
          ? 'failed'
          : item.state === 'cancelled'
            ? 'stopped'
            : 'streaming'
      const content =
        item.state === 'failed'
          ? item.error?.message ?? 'The assistant attempt failed.'
          : item.state === 'cancelled'
            ? 'The assistant attempt was cancelled.'
            : ''
      placeholders.push({
        id: `${PENDING_PREFIX}${item.messageId}`,
        conversationId: conversation.id,
        role: 'assistant',
        content,
        createdAt: item.updatedAt,
        state,
        attachments: [],
        contextChips: [],
        toolEvents: [],
      })
    }
    return {
      ...conversation,
      messages: [...conversation.messages, ...placeholders],
      updatedAt: placeholders.reduce(
        (latest, item) =>
          item.createdAt > latest ? item.createdAt : latest,
        conversation.updatedAt,
      ),
    }
  }

  private async resume(
    instanceId: string,
    resumeMessageId: string,
  ): Promise<{
    userMessage: ConversationMessage
    stream: MessageStream
  }> {
    if (!resumeMessageId.startsWith(PENDING_PREFIX)) {
      throw new ClientError(
        'validation',
        'Assistant resume identity is invalid',
      )
    }
    const sourceMessageId = resumeMessageId.slice(PENDING_PREFIX.length)
    if (!sourceMessageId) {
      throw new ClientError(
        'validation',
        'Assistant resume source identity is missing',
      )
    }
    const conversation = await this.transcriptClient.get(instanceId)
    const source = conversation.messages.find(
      (message) => message.id === sourceMessageId,
    )
    if (!source || source.role !== 'user') {
      throw new ClientError(
        'validation',
        'Assistant resume source message is unavailable',
      )
    }
    return {
      userMessage: source,
      stream: new AssistantEventStream(
        this.assistantTransport,
        this.transcriptClient,
        instanceId,
        sourceMessageId,
      ),
    }
  }

  override async sendMessage(
    instanceId: string,
    input: ConversationSendInput,
  ): Promise<{
    userMessage: ConversationMessage
    stream: MessageStream
  }> {
    if (input.resumeMessageId) {
      return this.resume(instanceId, input.resumeMessageId)
    }
    const accepted = await super.sendMessage(instanceId, input)
    accepted.stream.stop()
    return {
      userMessage: accepted.userMessage,
      stream: new AssistantEventStream(
        this.assistantTransport,
        this.transcriptClient,
        instanceId,
        accepted.userMessage.id,
      ),
    }
  }

  override streamMessage(
    instanceId: string,
    input: ConversationSendInput,
  ): Promise<{
    userMessage: ConversationMessage
    stream: MessageStream
  }> {
    return this.sendMessage(instanceId, input)
  }
}
