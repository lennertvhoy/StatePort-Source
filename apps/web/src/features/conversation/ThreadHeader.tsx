/**
 * ThreadHeader — the compact 40 px conversation header (conversation.md):
 * title, delivery/channel summary, message count, search, export, details
 * toggle, overflow (clear, focus mode), and the honest streaming pair
 * "Responding…" + Stop.
 */
import {
  ArrowDown,
  ArrowUp,
  Download,
  EllipsisVertical,
  Eraser,
  Maximize2,
  MessageSquare,
  Minimize2,
  PanelRight,
  Search,
  Square,
  X,
} from 'lucide-react'
import { useEffect, useRef } from 'react'

import type { Conversation } from '@/client'
import { StatusDot, Tooltip } from '@/components'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'

import { IconAction } from './MessageRow'

export interface ThreadHeaderProps {
  title: string
  conversation: Conversation | null
  messageCount: number
  streaming: boolean
  onStop: () => void
  searchOpen: boolean
  onToggleSearch: () => void
  onExport: () => void
  detailsOpen: boolean
  onToggleDetails: () => void
  onOpenClear: () => void
  focusMode: boolean
  onToggleFocusMode: () => void
  /** Compress to title + details + overflow on narrow screens. */
  compact?: boolean
}

function deliveryLabel(conversation: Conversation | null): { state: 'success' | 'neutral' | 'attention' | 'danger'; label: string } {
  if (!conversation) return { state: 'neutral', label: 'Not configured' }
  const channel = conversation.channel === 'telegram' ? 'Telegram' : 'Web'
  switch (conversation.deliveryState) {
    case 'delivered':
      return { state: 'success', label: `${channel} · Delivered` }
    case 'pending':
      return { state: 'attention', label: `${channel} · Pending` }
    case 'failed':
      return { state: 'danger', label: `${channel} · Delivery failed` }
    default:
      return { state: 'neutral', label: 'Not configured' }
  }
}

export function ThreadHeader({
  title,
  conversation,
  messageCount,
  streaming,
  onStop,
  searchOpen,
  onToggleSearch,
  onExport,
  detailsOpen,
  onToggleDetails,
  onOpenClear,
  focusMode,
  onToggleFocusMode,
  compact,
}: ThreadHeaderProps) {
  const delivery = deliveryLabel(conversation)
  return (
    <header
      className="flex h-10 shrink-0 items-center gap-2 border-b border-border bg-surface px-3"
      data-testid="thread-header"
    >
      <MessageSquare className="size-4 shrink-0 text-foreground-tertiary" aria-hidden="true" />
      <h1 className="truncate text-sm font-semibold text-foreground" tabIndex={-1}>
        {title}
      </h1>
      {/* Delivery state is always visible; only the count compresses away. */}
      <StatusDot state={delivery.state} label={delivery.label} className="max-w-36" />
      {!compact ? (
        <span className="tnum hidden font-mono text-xs text-foreground-tertiary md:inline">
          {messageCount} {messageCount === 1 ? 'message' : 'messages'}
        </span>
      ) : null}

      {streaming ? (
        <span className="inline-flex items-center gap-2 rounded-sm bg-surface-2 px-2 py-1" data-testid="streaming-indicator">
          <span className="text-xs text-foreground-secondary" role="status">
            Responding…
          </span>
          <button
            type="button"
            onClick={onStop}
            data-testid="stop-stream"
            className="inline-flex h-5 items-center gap-1 rounded-xs border border-border bg-surface px-1.5 text-xs font-medium text-foreground hover:bg-hover"
            aria-label="Stop generating the response"
          >
            <Square className="size-3" aria-hidden="true" />
            Stop
          </button>
        </span>
      ) : null}

      <span className="ml-auto flex items-center gap-0.5">
        <IconAction
          icon={Search}
          label="Search in conversation (Ctrl+F)"
          onClick={onToggleSearch}
          testId="conversation-search-toggle"
          className={cn(searchOpen && 'bg-active text-foreground')}
        />
        {!compact ? (
          <IconAction icon={Download} label="Export conversation" onClick={onExport} testId="export-button" />
        ) : null}
        <IconAction
          icon={PanelRight}
          label={detailsOpen ? 'Hide details' : 'Show details'}
          onClick={onToggleDetails}
          testId="details-toggle"
          className={cn(detailsOpen && 'bg-active text-foreground')}
        />
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              aria-label="More conversation actions"
              data-testid="thread-overflow"
              className="inline-flex size-7 items-center justify-center rounded-sm text-foreground-tertiary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            >
              <EllipsisVertical className="size-3.5" aria-hidden="true" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="bg-surface">
            {compact ? (
              <DropdownMenuItem onSelect={onExport}>
                <Download className="size-4" aria-hidden="true" />
                Export conversation
              </DropdownMenuItem>
            ) : null}
            <DropdownMenuItem onSelect={onToggleFocusMode}>
              {focusMode ? <Minimize2 className="size-4" aria-hidden="true" /> : <Maximize2 className="size-4" aria-hidden="true" />}
              {focusMode ? 'Exit focus mode' : 'Focus mode'}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={onOpenClear} className="text-status-danger focus:text-status-danger">
              <Eraser className="size-4" aria-hidden="true" />
              Clear history…
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </span>
    </header>
  )
}

// ── In-conversation search bar ───────────────────────────────────────────────

export interface ConversationSearchBarProps {
  query: string
  onQueryChange: (query: string) => void
  matchCount: number
  activeIndex: number
  onPrev: () => void
  onNext: () => void
  onClose: () => void
}

export function ConversationSearchBar({
  query,
  onQueryChange,
  matchCount,
  activeIndex,
  onPrev,
  onNext,
  onClose,
}: ConversationSearchBarProps) {
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    inputRef.current?.focus()
    inputRef.current?.select()
  }, [])

  // Derived (no state): the polite count announcement.
  const announcement = !query
    ? ''
    : matchCount === 0
      ? 'No matches'
      : `${matchCount} ${matchCount === 1 ? 'match' : 'matches'}`

  return (
    <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-surface-2 px-3" data-testid="conversation-search-bar">
      <Search className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
      <input
        ref={inputRef}
        value={query}
        onChange={(e) => onQueryChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault()
            if (e.shiftKey) onPrev()
            else onNext()
          } else if (e.key === 'Escape') {
            e.preventDefault()
            onClose()
          }
        }}
        placeholder="Search in conversation"
        aria-label="Search in conversation"
        data-testid="conversation-search-input"
        className="h-7 min-w-0 flex-1 rounded-sm border border-input bg-surface px-2 text-sm text-foreground outline-none placeholder:text-foreground-tertiary focus:border-accent"
      />
      <span className="tnum shrink-0 font-mono text-xs text-foreground-tertiary" aria-live="polite">
        {query ? (matchCount === 0 ? '0/0' : `${activeIndex + 1}/${matchCount}`) : ''}
      </span>
      <span className="sr-only" aria-live="polite">
        {announcement}
      </span>
      <Tooltip content="Previous match (Shift+Enter)">
        <button
          type="button"
          onClick={onPrev}
          disabled={matchCount === 0}
          aria-label="Previous match"
          data-testid="search-prev"
          className="inline-flex size-7 items-center justify-center rounded-sm text-foreground-secondary hover:bg-hover disabled:opacity-40"
        >
          <ArrowUp className="size-3.5" aria-hidden="true" />
        </button>
      </Tooltip>
      <Tooltip content="Next match (Enter)">
        <button
          type="button"
          onClick={onNext}
          disabled={matchCount === 0}
          aria-label="Next match"
          data-testid="search-next"
          className="inline-flex size-7 items-center justify-center rounded-sm text-foreground-secondary hover:bg-hover disabled:opacity-40"
        >
          <ArrowDown className="size-3.5" aria-hidden="true" />
        </button>
      </Tooltip>
      <IconAction icon={X} label="Close search (Esc)" onClick={onClose} testId="search-close" />
    </div>
  )
}
