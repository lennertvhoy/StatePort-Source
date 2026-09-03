/**
 * Transcript — the scrollable conversation log (role="log").
 *
 * Day dividers, "New since …" unread marker, follow-latest behavior with a
 * floating "↓ Latest" chip when scrolled up, search-match scrolling, and
 * virtualization (react-virtual) once the transcript gets long. Auto-scroll
 * honors the autoScroll setting and pauses when the user scrolls up.
 */
import { ArrowDown } from 'lucide-react'
import { forwardRef, useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'

import type { ConversationMessage, ConversationSettings } from '@/client'
import { cn } from '@/lib/utils'

import type { TranscriptItem } from './conversationModel'
import { buildTranscriptItems } from './conversationModel'
import { MessageRow } from './MessageRow'

const VIRTUALIZE_THRESHOLD = 60
const AT_BOTTOM_PX = 80

export interface TranscriptHandle {
  scrollToLatest: () => void
  scrollToMessage: (messageId: string) => void
}

export interface TranscriptProps {
  messages: ConversationMessage[]
  instanceId: string
  pinnedIds: string[]
  /** Unread divider: shown when there are messages after lastSeenId. */
  lastSeenId: string | null
  unreadActive: boolean
  settings: ConversationSettings
  /** Current search match — scrolled into view and ringed. */
  currentMatchId: string | null
  dense?: boolean
  onTogglePin: (messageId: string) => void
  onQuote: (message: ConversationMessage) => void
  onRetryResponse: () => void
  onResend: (messageId: string) => void
  onEdit: (messageId: string) => void
  onDiscard: (messageId: string) => void
  /** Fires when the user reaches the bottom (drives last-seen bookkeeping). */
  onAtBottom: () => void
}

export const Transcript = forwardRef<TranscriptHandle, TranscriptProps>(function Transcript(
  {
    messages,
    instanceId,
    pinnedIds,
    lastSeenId,
    unreadActive,
    settings,
    currentMatchId,
    dense,
    onTogglePin,
    onQuote,
    onRetryResponse,
    onResend,
    onEdit,
    onDiscard,
    onAtBottom,
  },
  ref,
) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const atBottomRef = useRef(true)
  const readerPausedRef = useRef(false)
  const lastTouchYRef = useRef<number | null>(null)
  const [atBottom, setAtBottom] = useState(true)
  const [initialScrolled, setInitialScrolled] = useState(false)

  const items = useMemo(
    () => buildTranscriptItems(messages, { lastSeenId, unreadActive }),
    [messages, lastSeenId, unreadActive],
  )
  const virtualize = items.length > VIRTUALIZE_THRESHOLD

  // TanStack Virtual intentionally owns mutable measurement callbacks; React
  // Compiler safely leaves this component un-memoized.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: virtualize ? items.length : 0,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 110,
    overscan: 10,
    getItemKey: (index) => items[index]?.key ?? index,
  })

  const scrollToLatest = useCallback(() => {
    const el = scrollRef.current
    if (!el) return
    if (virtualize) virtualizer.scrollToIndex(items.length - 1, { align: 'end' })
    else el.scrollTop = el.scrollHeight
    readerPausedRef.current = false
    atBottomRef.current = true
    setAtBottom(true)
    onAtBottom()
  }, [virtualize, virtualizer, items.length, onAtBottom])

  const scrollToMessage = useCallback(
    (messageId: string) => {
      const index = items.findIndex((item) => item.type === 'message' && item.message.id === messageId)
      if (index === -1) return
      if (virtualize) {
        virtualizer.scrollToIndex(index, { align: 'center' })
      } else {
        scrollRef.current
          ?.querySelector(`[data-message-id="${messageId}"]`)
          ?.scrollIntoView({ block: 'center' })
      }
    },
    [items, virtualize, virtualizer],
  )

  useImperativeHandle(ref, () => ({ scrollToLatest, scrollToMessage }), [scrollToLatest, scrollToMessage])

  // Initial position: the unread divider when returning, else the latest.
  // Landing at the latest also records last-seen (via onAtBottom); landing at
  // the unread marker does not — the user hasn't seen the new messages yet.
  useEffect(() => {
    if (initialScrolled || items.length === 0) return
    const frame = requestAnimationFrame(() => {
      const unreadIndex = items.findIndex((i) => i.type === 'unread')
      if (unreadIndex !== -1) {
        if (virtualize) virtualizer.scrollToIndex(unreadIndex, { align: 'center' })
        else {
          const firstNew = items[unreadIndex + 1]
          if (firstNew?.type === 'message') {
            scrollRef.current?.querySelector(`[data-message-id="${firstNew.message.id}"]`)?.scrollIntoView({ block: 'start' })
          }
        }
      } else {
        const el = scrollRef.current
        if (el) el.scrollTop = el.scrollHeight
        readerPausedRef.current = false
        onAtBottom()
      }
      setInitialScrolled(true)
    })
    return () => cancelAnimationFrame(frame)
  }, [initialScrolled, items, virtualize, virtualizer, onAtBottom])

  // Follow latest while at the bottom (or when autoScroll = always).
  const lastMessage = messages[messages.length - 1]
  const lastLength = lastMessage?.content.length ?? 0
  useEffect(() => {
    if (!initialScrolled) return
    const follow =
      settings.autoScroll === 'always' ||
      (settings.autoScroll === 'when_at_bottom' && atBottomRef.current && !readerPausedRef.current)
    if (!follow) return
    const el = scrollRef.current
    if (!el) return
    if (virtualize) virtualizer.scrollToIndex(items.length - 1, { align: 'end' })
    else el.scrollTop = el.scrollHeight
  }, [messages.length, lastLength, initialScrolled, settings.autoScroll, virtualize, virtualizer, items.length])

  // Search match → scroll into view.
  useEffect(() => {
    if (currentMatchId) scrollToMessage(currentMatchId)
  }, [currentMatchId, scrollToMessage])

  const onScroll = () => {
    const el = scrollRef.current
    if (!el) return
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight
    const physicallyAtBottom = distanceFromBottom <= 1
    if (physicallyAtBottom) readerPausedRef.current = false
    else if (distanceFromBottom >= AT_BOTTOM_PX) readerPausedRef.current = true
    const next = distanceFromBottom < AT_BOTTOM_PX && !readerPausedRef.current
    atBottomRef.current = next
    setAtBottom(next)
    if (next) onAtBottom()
  }

  // Browser scroll events are delivered after the wheel input. A stream chunk
  // can render in between and otherwise observe the stale "at bottom" ref,
  // yanking the reader back before onScroll gets a chance to pause following.
  const pauseFollowing = () => {
    readerPausedRef.current = true
    atBottomRef.current = false
    setAtBottom(false)
  }

  const renderItem = (item: TranscriptItem) => {
    if (item.type === 'day') {
      return (
        <div className="flex items-center gap-3 py-2" role="separator" aria-label={item.label}>
          <span className="h-px flex-1 bg-border" />
          <span className="text-xs text-foreground-secondary">{item.label}</span>
          <span className="h-px flex-1 bg-border" />
        </div>
      )
    }
    if (item.type === 'unread') {
      return (
        <div className="flex items-center gap-3 py-1" data-testid="unread-marker">
          <span className="h-px flex-1 bg-accent" />
          <span className="text-xs font-medium text-accent">{item.label}</span>
          <span className="h-px flex-1 bg-accent" />
        </div>
      )
    }
    const message = item.message
    return (
      <MessageRow
        message={message}
        instanceId={instanceId}
        pinned={pinnedIds.includes(message.id)}
        onTogglePin={() => onTogglePin(message.id)}
        onQuote={() => onQuote(message)}
        onRetryResponse={onRetryResponse}
        onResend={() => onResend(message.id)}
        onEdit={() => onEdit(message.id)}
        onDiscard={() => onDiscard(message.id)}
        dense={dense}
        highlighted={currentMatchId === message.id}
        showTimestamp={settings.showMessageTimestamps}
        toolEventsExpandedDefault={settings.toolEventsExpanded}
      />
    )
  }

  return (
    <div className="relative flex min-h-0 flex-1 flex-col">
      <div
        ref={scrollRef}
        role="log"
        aria-label="Conversation transcript"
        className="min-h-0 flex-1 overflow-y-auto px-4 py-3"
        onScroll={onScroll}
        onWheel={(event) => {
          if (event.deltaY < 0) pauseFollowing()
        }}
        onTouchStart={(event) => {
          lastTouchYRef.current = event.touches[0]?.clientY ?? null
        }}
        onTouchMove={(event) => {
          const y = event.touches[0]?.clientY
          if (y === undefined) return
          // Finger moving down scrolls the transcript toward older messages.
          if (lastTouchYRef.current !== null && y > lastTouchYRef.current) pauseFollowing()
          lastTouchYRef.current = y
        }}
        onTouchEnd={() => {
          lastTouchYRef.current = null
        }}
        data-testid="transcript"
      >
        <div className={cn('mx-auto flex flex-col gap-3', dense ? 'max-w-none' : 'max-w-[760px]')}>
          {virtualize ? (
            <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
              {virtualizer.getVirtualItems().map((vItem) => {
                const item = items[vItem.index]
                if (!item) return null
                return (
                  <div
                    key={vItem.key}
                    data-index={vItem.index}
                    ref={virtualizer.measureElement}
                    style={{ position: 'absolute', top: 0, left: 0, width: '100%', transform: `translateY(${vItem.start}px)` }}
                    className="pb-3"
                  >
                    {renderItem(item)}
                  </div>
                )
              })}
            </div>
          ) : (
            items.map((item) => <div key={item.key}>{renderItem(item)}</div>)
          )}
        </div>
      </div>

      {!atBottom ? (
        <button
          type="button"
          onClick={scrollToLatest}
          data-testid="jump-to-latest"
          className="absolute bottom-3 right-4 inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-xs font-medium text-foreground shadow-1 transition-colors duration-instant hover:bg-hover"
        >
          <ArrowDown className="size-3.5" aria-hidden="true" />
          Latest
        </button>
      ) : null}
    </div>
  )
})
