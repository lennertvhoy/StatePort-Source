import { z } from 'zod'

import type { ConversationSendInput } from '../client'
import type {
  ConversationMessage,
  ConversationStreamChunk,
  MessageStream,
} from '../types'
import { HttpAssistantConversationClient } from './domainsAssistantConversation'
import { endpoints } from './endpoints'
import { HttpTransport } from './transport'

const CANCEL_CONFIRM_TIMEOUT_MS = 5_000
const CANCEL_CONFIRM_POLL_MS = 100
const NO_PROCESSOR_MESSAGE =
  'Message accepted. No assistant processor is connected to this conversation.'

const assistantAvailabilityWire = z.object({
  formatVersion: z.literal('stateport.assistant-work-list/v1'),
  conversationId: z.string().min(1),
  enabled: z.boolean(),
  items: z.array(z.unknown()),
}).passthrough()

class AcceptedMessageStream implements MessageStream {
  readonly messageId: string
  private stopped = false

  constructor(messageId: string) {
    this.messageId = messageId
  }

  stop(): void {
    this.stopped = true
  }

  async *[Symbol.asyncIterator](): AsyncIterator<ConversationStreamChunk> {
    if (!this.stopped) {
      yield { type: 'accepted', message: NO_PROCESSOR_MESSAGE }
    }
  }
}

class DisconnectCancellableMessageStream implements MessageStream {
  readonly messageId: string
  private readonly inner: MessageStream
  private readonly conversationClient: HttpAssistantConversationClient
  private readonly instanceId: string
  private detachedByUser = false
  private terminalObserved = false

  constructor(
    inner: MessageStream,
    conversationClient: HttpAssistantConversationClient,
    instanceId: string,
  ) {
    this.inner = inner
    this.conversationClient = conversationClient
    this.instanceId = instanceId
    this.messageId = inner.messageId
  }

  /**
   * Detach the browser stream. The server applies a short reconnect grace and
   * cancels the provider only if no replacement stream attaches. This keeps a
   * page refresh distinct from a real user stop without adding browser memory
   * as an authority.
   */
  stop(): void {
    if (this.detachedByUser) return
    this.detachedByUser = true
    this.inner.stop()
  }

  private async confirmedStoppedMessage(): Promise<ConversationMessage | null> {
    const deadline = Date.now() + CANCEL_CONFIRM_TIMEOUT_MS
    while (Date.now() < deadline) {
      const conversation = await this.conversationClient.get(this.instanceId)
      const message = conversation.messages.find(
        (candidate) => candidate.id === this.messageId,
      )
      if (message?.state === 'stopped') return message
      if (message?.state === 'failed' || message?.state === 'complete') {
        return null
      }
      await new Promise((resolve) => setTimeout(resolve, CANCEL_CONFIRM_POLL_MS))
    }
    return null
  }

  async *[Symbol.asyncIterator](): AsyncIterator<ConversationStreamChunk> {
    for await (const chunk of this.inner) {
      if (
        chunk.type === 'done' ||
        chunk.type === 'error' ||
        chunk.type === 'stopped'
      ) {
        this.terminalObserved = true
      }
      if (this.detachedByUser && chunk.type === 'accepted') {
        const stopped = await this.confirmedStoppedMessage()
        if (stopped) {
          this.terminalObserved = true
          yield { type: 'stopped', message: stopped }
          return
        }
      }
      yield chunk
    }
    if (this.detachedByUser && !this.terminalObserved) {
      const stopped = await this.confirmedStoppedMessage()
      if (stopped) {
        yield { type: 'stopped', message: stopped }
      }
    }
  }
}

/**
 * Production conversation client with disconnect-aware per-work cancellation.
 * The inherited client remains the event-journal and refresh authority; this
 * wrapper only converts a final browser detach into a confirmed stopped state.
 */
export class HttpCancellableAssistantConversationClient extends HttpAssistantConversationClient {
  private readonly availabilityTransport: HttpTransport

  constructor(transport: HttpTransport) {
    super(transport)
    this.availabilityTransport = transport
  }

  private async assistantEnabled(instanceId: string): Promise<boolean | null> {
    try {
      const projection = await this.availabilityTransport.request(
        endpoints.conversationAssistantWork(instanceId),
        { schema: assistantAvailabilityWire },
      )
      return projection.enabled
    } catch {
      // The projection is an optimization and compatibility probe. The durable
      // event endpoint remains authoritative if it is absent or temporarily
      // unavailable, so no success is fabricated here.
      return null
    }
  }

  override async sendMessage(
    instanceId: string,
    input: ConversationSendInput,
  ): Promise<{
    userMessage: ConversationMessage
    stream: MessageStream
  }> {
    const accepted = await super.sendMessage(instanceId, input)
    if (!input.resumeMessageId) {
      const enabled = await this.assistantEnabled(instanceId)
      if (enabled === false) {
        accepted.stream.stop()
        return {
          userMessage: accepted.userMessage,
          stream: new AcceptedMessageStream(accepted.userMessage.id),
        }
      }
    }
    return {
      userMessage: accepted.userMessage,
      stream: new DisconnectCancellableMessageStream(
        accepted.stream,
        this,
        instanceId,
      ),
    }
  }
}
