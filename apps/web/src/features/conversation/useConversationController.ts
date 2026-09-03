/**
 * useConversationController — the conversation surface's data brain.
 *
 * Owns: history loading, sending with optimistic user echo, consuming the
 * mock stream (delta/done/stopped/error), stop + retry, export (receipt),
 * clear, conversation settings, and polite aria-live announcements of stream
 * state. All domain traffic goes through `getClient()` — never fetch/storage.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type {
  ApplicationInstance,
  Attachment,
  ContextChip,
  Conversation,
  ConversationMessage,
  ConversationSettings,
  MessageStream,
} from '@/client'
import { getClient } from '@/client'
import { applicationDestinationAvailable } from '@/features/application-experience/registry'
import { useSessionStore } from '@/state'
import { useCurrentInstance } from '@/shell/currentInstance'

export interface SendInput {
  content: string
  attachments: Attachment[]
  contextChips: ContextChip[]
}

export interface ConversationController {
  instanceId: string
  instance: ApplicationInstance | null
  conversation: Conversation | null
  messages: ConversationMessage[]
  settings: ConversationSettings
  loading: boolean
  /** History failed to load; composer stays usable (messages kept local). */
  historyError: unknown
  streaming: boolean
  sending: boolean
  /** Polite live-region text describing stream state changes. */
  announcement: string
  send(input: SendInput): Promise<void>
  stop(): void
  retryLast(): Promise<void>
  /** Re-attempt a locally failed user message (send never reached the client). */
  resendFailed(messageId: string): Promise<void>
  discardFailed(messageId: string): void
  exportConversation(): Promise<void>
  clearHistory(): Promise<void>
  reload: () => void
}

export const DEFAULT_CONVERSATION_SETTINGS: ConversationSettings = {
  enterSends: true,
  draftPersistence: true,
  showMessageTimestamps: true,
  compactMessageLayout: false,
  autoScroll: 'when_at_bottom',
  confirmBeforeClearingHistory: true,
  defaultContext: ['application', 'summary'],
  showDeliveryDetails: true,
  toolEventsExpanded: false,
  soundOnResponseFinished: false,
}

/** Local id for optimistic echo before the client confirms (still honest). */
let localMsgSeq = 0

export function useConversationController(instanceId: string): ConversationController {
  const { instance: currentInstance } = useCurrentInstance()
  const [instance, setInstance] = useState<ApplicationInstance | null>(null)
  const [conversation, setConversation] = useState<Conversation | null>(null)
  const [messages, setMessages] = useState<ConversationMessage[]>([])
  const [settings, setSettings] = useState<ConversationSettings>(DEFAULT_CONVERSATION_SETTINGS)
  const [loading, setLoading] = useState(true)
  const [historyError, setHistoryError] = useState<unknown>(null)
  const [streaming, setStreaming] = useState(false)
  const [sending, setSending] = useState(false)
  const [announcement, setAnnouncement] = useState('')
  const [nonce, setNonce] = useState(0)

  const activeStreamRef = useRef<MessageStream | null>(null)
  // Stop also covers a replacement stream whose adapter request is still
  // pending. Without this generation, Stop can end the resumed stream while a
  // just-submitted response attaches a moment later and starts responding
  // again against the user's explicit instruction.
  const stopGenerationRef = useRef(0)
  const mountedRef = useRef(true)
  // Inputs that never reached the client (send threw) → messageId → input.
  const failedInputsRef = useRef(new Map<string, SendInput>())

  const reload = useCallback(() => setNonce((n) => n + 1), [])

  // ── Stream consumption ─────────────────────────────────────────────────────
  const consumeStream = useCallback(async (stream: MessageStream) => {
    activeStreamRef.current?.stop()
    activeStreamRef.current = stream
    setStreaming(true)
    setAnnouncement('Responding…')
    try {
      for await (const chunk of stream) {
        if (!mountedRef.current) break
        if (chunk.type === 'delta') {
          setMessages((prev) =>
            prev.map((m) => (m.id === stream.messageId ? { ...m, content: m.content + chunk.text } : m)),
          )
        } else if (chunk.type === 'done') {
          setMessages((prev) => prev.map((m) => (m.id === stream.messageId ? { ...chunk.message } : m)))
          setAnnouncement('Response complete.')
        } else if (chunk.type === 'accepted') {
          // In HTTP mode a no-processor acceptance is keyed by the accepted
          // user message id. Remove only a transient assistant placeholder;
          // the durable user message and its attachment evidence must remain
          // visible.
          setMessages((prev) =>
            prev.filter(
              (m) => m.id !== stream.messageId || m.role !== 'assistant',
            ),
          )
          setAnnouncement(chunk.message)
        } else if (chunk.type === 'stopped') {
          setMessages((prev) => prev.map((m) => (m.id === stream.messageId ? { ...chunk.message } : m)))
          setAnnouncement('Stopped by you.')
        } else if (chunk.type === 'error') {
          setMessages((prev) =>
            prev.map((m) => (m.id === stream.messageId ? { ...m, state: 'failed' as const } : m)),
          )
          setAnnouncement('The response failed before completion. Your message is preserved — retry is safe.')
        }
      }
    } catch {
      if (mountedRef.current) {
        setMessages((prev) =>
          prev.map((m) => (m.id === stream.messageId ? { ...m, state: 'failed' as const } : m)),
        )
        setAnnouncement('The response failed before completion. Your message is preserved — retry is safe.')
      }
    } finally {
      // Only the ACTIVE stream may clear the streaming flag — a superseded
      // stream (e.g. a resumed reply stopped by a fresh send) must not hide
      // the streaming chrome of the stream that replaced it.
      if (activeStreamRef.current === stream) {
        activeStreamRef.current = null
        if (mountedRef.current) setStreaming(false)
      }
    }
  }, [])

  /** Begin the assistant stream for a freshly sent user message. */
  const beginStream = useCallback(
    (stream: MessageStream) => {
      const placeholder: ConversationMessage = {
        id: stream.messageId,
        conversationId: conversation?.id ?? '',
        role: 'assistant',
        content: '',
        createdAt: new Date().toISOString(),
        state: 'streaming',
        attachments: [],
        contextChips: [],
        toolEvents: [],
      }
      setMessages((prev) =>
        prev.some((m) => m.id === stream.messageId) ? prev : [...prev, placeholder],
      )
      void consumeStream(stream)
    },
    [consumeStream, conversation?.id],
  )

  // ── Load history + settings + instance ─────────────────────────────────────
  useEffect(() => {
    mountedRef.current = true
    let cancelled = false
    setLoading(true)
    setHistoryError(null)
    setMessages([])
    setConversation(null)

    const client = getClient()
    void client.applications
      .get(instanceId)
      .then((inst) => {
        if (!cancelled) setInstance(inst)
      })
      .catch(() => undefined)
    void client.globalSettings
      .get()
      .then((s) => {
        if (!cancelled && s.conversation) setSettings({ ...DEFAULT_CONVERSATION_SETTINGS, ...s.conversation })
      })
      .catch(() => undefined)

    client.conversation
      .get(instanceId)
      .then((conv) => {
        if (cancelled) return
        setConversation(conv)
        setMessages(conv.messages)
        setLoading(false)
        // A persisted streaming-state reply means a stream was in flight when
        // the page loaded: re-attach to it (stop keeps working). When the
        // adapter has no live stream to resume, mark the reply interrupted
        // honestly — the failed-state Retry affordance takes over.
        const inFlight = [...conv.messages]
          .reverse()
          .find((m) => m.role === 'assistant' && m.state === 'streaming')
        if (!inFlight) return
        client.conversation
          .streamMessage(instanceId, { content: '', resumeMessageId: inFlight.id })
          .then(({ stream }) => {
            if (cancelled || !mountedRef.current) {
              stream.stop()
              return
            }
            if (activeStreamRef.current) {
              // A newer stream (a fresh send) attached while the resume was
              // in flight — keep it and let the old reply stop honestly:
              // draining runs the mock's stopped-state persistence to its end.
              stream.stop()
              setMessages((prev) =>
                prev.map((m) => (m.id === stream.messageId ? { ...m, state: 'stopped' as const } : m)),
              )
              void (async () => {
                for await (const chunk of stream) void chunk
              })()
              return
            }
            void consumeStream(stream)
          })
          .catch(() => {
            if (cancelled || !mountedRef.current) return
            setMessages((prev) =>
              prev.map((m) => (m.id === inFlight.id ? { ...m, state: 'failed' as const } : m)),
            )
            setAnnouncement('The response stream was interrupted before it finished. Retry is safe.')
          })
      })
      .catch((err) => {
        if (cancelled) return
        setHistoryError(err)
        setLoading(false)
      })

    return () => {
      cancelled = true
      mountedRef.current = false
      activeStreamRef.current?.stop()
      activeStreamRef.current = null
    }
  }, [instanceId, nonce, consumeStream])

  // ── Send ───────────────────────────────────────────────────────────────────
  const send = useCallback(
    async (input: SendInput) => {
      const content = input.content.trim()
      const readyAttachments = input.attachments.filter((a) => a.state === 'ready')
      if (!content && readyAttachments.length === 0) return
      const stopGeneration = stopGenerationRef.current
      setSending(true)
      try {
        const { userMessage, stream } = await getClient().conversation.streamMessage(instanceId, {
          content,
          attachments: readyAttachments,
          contextChips: input.contextChips,
        })
        if (!mountedRef.current) {
          stream.stop()
          return
        }
        // userMessage is only null on a resume attach — never on a send.
        if (userMessage) {
          setMessages((prev) => [...prev.filter((m) => m.id !== userMessage.id), userMessage])
        }
        // Stop was pressed while this send was awaiting the adapter. Consume a
        // pre-stopped stream so its assistant row reaches the honest stopped
        // state instead of silently starting after the user stopped.
        if (stopGenerationRef.current !== stopGeneration) stream.stop()
        beginStream(stream)
      } catch (err) {
        // The send never landed — keep an honest local "Not sent" message with
        // Retry / Edit / Delete instead of losing the text (conversation.md).
        if (!mountedRef.current) return
        localMsgSeq += 1
        const failedId = `msg_local_failed_${localMsgSeq}`
        failedInputsRef.current.set(failedId, { content, attachments: readyAttachments, contextChips: input.contextChips })
        setMessages((prev) => [
          ...prev,
          {
            id: failedId,
            conversationId: conversation?.id ?? '',
            role: 'user',
            content,
            createdAt: new Date().toISOString(),
            state: 'failed',
            attachments: readyAttachments,
            contextChips: input.contextChips,
            toolEvents: [],
          },
        ])
        setAnnouncement(err instanceof Error ? `Message not sent. ${err.message}` : 'Message not sent.')
      } finally {
        if (mountedRef.current) setSending(false)
      }
    },
    [beginStream, conversation?.id, instanceId],
  )

  // ── Stop / retry ───────────────────────────────────────────────────────────
  const stop = useCallback(() => {
    stopGenerationRef.current += 1
    activeStreamRef.current?.stop()
  }, [])

  const retryLast = useCallback(async () => {
    try {
      const stream = await getClient().conversation.retryLast(instanceId)
      if (!mountedRef.current) {
        stream.stop()
        return
      }
      setMessages((prev) => prev.map((m) => (m.id === stream.messageId ? { ...m, state: 'streaming' as const, content: '' } : m)))
      void consumeStream(stream)
    } catch {
      setAnnouncement('Nothing to retry yet.')
    }
  }, [consumeStream, instanceId])

  const resendFailed = useCallback(
    async (messageId: string) => {
      const input = failedInputsRef.current.get(messageId)
      if (!input) return
      failedInputsRef.current.delete(messageId)
      setMessages((prev) => prev.filter((m) => m.id !== messageId))
      await send(input)
    },
    [send],
  )

  const discardFailed = useCallback((messageId: string) => {
    failedInputsRef.current.delete(messageId)
    setMessages((prev) => prev.filter((m) => m.id !== messageId))
  }, [])

  const receiptBasePath = currentInstance && currentInstance.id === instanceId && applicationDestinationAvailable(currentInstance, 'receipts')
    ? applicationDestinationAvailable(currentInstance, 'workbench')
      ? `/app/${instanceId}/workbench/receipts`
      : `/app/${instanceId}/receipts`
    : undefined

  // ── Export / clear ─────────────────────────────────────────────────────────
  const exportConversation = useCallback(async () => {
    const { markdown, receipt } = await getClient().conversation.exportConversation(instanceId)
    if (typeof URL !== 'undefined' && typeof URL.createObjectURL === 'function') {
      const blob = new Blob([markdown], { type: 'text/markdown' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `conversation-${instanceId}.md`
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    }
    useSessionStore.getState().pushToast({
      kind: 'success',
      title: 'Conversation exported',
      body: `Markdown download started. Recorded as receipt ${receipt.id}.`,
      route: receiptBasePath ? `${receiptBasePath}/${receipt.id}` : undefined,
    })
    setAnnouncement(`Conversation exported. Recorded as receipt ${receipt.id}.`)
  }, [instanceId, receiptBasePath])

  const clearHistory = useCallback(async () => {
    const { receipt } = await getClient().conversation.clearConversation(instanceId)
    if (!mountedRef.current) return
    setMessages([])
    useSessionStore.getState().pushToast({
      kind: 'info',
      title: 'Conversation cleared',
      body: `The operational history on this machine was removed. Canonical application state was unchanged. Recorded as receipt ${receipt.id}.`,
      route: receiptBasePath ? `${receiptBasePath}/${receipt.id}` : undefined,
    })
    setAnnouncement(`Conversation cleared. Canonical application state was unchanged. Recorded as receipt ${receipt.id}.`)
  }, [instanceId, receiptBasePath])

  return useMemo(
    () => ({
      instanceId,
      instance,
      conversation,
      messages,
      settings,
      loading,
      historyError,
      streaming,
      sending,
      announcement,
      send,
      stop,
      retryLast,
      resendFailed,
      discardFailed,
      exportConversation,
      clearHistory,
      reload,
    }),
    [
      instanceId, instance, conversation, messages, settings, loading, historyError,
      streaming, sending, announcement, send, stop, retryLast, resendFailed,
      discardFailed, exportConversation, clearHistory, reload,
    ],
  )
}
