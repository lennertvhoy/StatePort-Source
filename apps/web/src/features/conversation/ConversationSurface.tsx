/**
 * ConversationSurface — the composed conversation view (header, transcript,
 * composer, details). Used full-page by ConversationPage and densely by the
 * workbench sidecar. Owns search, pins, unread bookkeeping, focus mode,
 * clear/export flows, palette commands, and conversation-scoped keyboard.
 */
import { ArrowDownToLine, Download, Keyboard, MessageSquare, PanelRight, Search, Square } from 'lucide-react'
import { useCallback, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'

import type { ConversationMessage } from '@/client'
import { ConfirmDialog, Drawer, EmptyState, ErrorState, InlineNotice, Skeleton } from '@/components'
import { cn } from '@/lib/utils'
import { useRegisterCommands } from '@/shell/commands'
import { useEscapeLayer } from '@/shell/escape'
import { useMediaQuery } from '@/shell/platform'

import type { ComposerHandle } from './Composer'
import { Composer } from './Composer'
import { useContextChips } from './useContextChips'
import { useConversationController } from './useConversationController'
import { useConversationUiStore } from './conversationUiStore'
import { DetailsPanel } from './DetailsPanel'
import { ThreadHeader, ConversationSearchBar } from './ThreadHeader'
import type { TranscriptHandle } from './Transcript'
import { Transcript } from './Transcript'

const SUGGESTIONS = [
  'Summarize recent receipts',
  'Explain the last terminal error',
  'What should I do next in this application?',
]

/** Stable empty reference — zustand selectors must never allocate per call. */
const NO_PINS: string[] = []

export interface ConversationSurfaceProps {
  instanceId: string
  /** Dense workbench-dock variant: compact header, no palette commands. */
  dense?: boolean
}

export function ConversationSurface({ instanceId, dense }: ConversationSurfaceProps) {
  const controller = useConversationController(instanceId)
  const { instance, conversation, messages, settings, loading, historyError, streaming } = controller

  const instanceName = instance?.name ?? 'This application'
  const chipsState = useContextChips(instanceId, instanceName, settings.defaultContext)

  // ── Presentation stores ────────────────────────────────────────────────────
  const pinnedIds = useConversationUiStore((s) => s.pinned[instanceId]) ?? NO_PINS
  const togglePin = useConversationUiStore((s) => s.togglePin)
  const storedDetailsOpen = useConversationUiStore((s) => s.detailsOpen[instanceId])
  const setDetailsOpen = useConversationUiStore((s) => s.setDetailsOpen)
  const lastSeenId = useConversationUiStore((s) => s.lastSeen[instanceId] ?? null)
  const setLastSeen = useConversationUiStore((s) => s.setLastSeen)

  // Default details visibility: open ≥ 1440 px, closed below (first visit only).
  const wide = useMediaQuery('(min-width: 1280px)')
  const detailsOpen = storedDetailsOpen ?? (typeof window !== 'undefined' && window.innerWidth >= 1440 && !dense)

  // ── Local UI state ─────────────────────────────────────────────────────────
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [activeMatch, setActiveMatch] = useState(0)
  const [clearOpen, setClearOpen] = useState(false)
  const [focusMode, setFocusMode] = useState(false)

  const composerRef = useRef<ComposerHandle>(null)
  const transcriptRef = useRef<TranscriptHandle>(null)

  const focusComposer = useCallback(() => composerRef.current?.focus(), [])

  // ── Unread bookkeeping ─────────────────────────────────────────────────────
  // First visit (or after a clear) has no usable marker: the transcript opens
  // at the latest message and its initial scroll reports at-bottom, which
  // records last-seen through onAtBottom below — no effect needed.
  const latestId = messages.length > 0 ? messages[messages.length - 1].id : null

  const unreadActive = Boolean(
    lastSeenId && latestId && lastSeenId !== latestId && messages.some((m) => m.id === lastSeenId),
  )
  const onAtBottom = useCallback(() => {
    if (latestId) setLastSeen(instanceId, latestId)
  }, [latestId, instanceId, setLastSeen])

  // ── Search ─────────────────────────────────────────────────────────────────
  const matches = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return []
    return messages.filter((m) => m.content.toLowerCase().includes(q)).map((m) => m.id)
  }, [messages, searchQuery])
  const activeMatchId = matches.length > 0 ? matches[Math.min(activeMatch, matches.length - 1)] : null

  const stepMatch = useCallback(
    (dir: 1 | -1) => {
      if (matches.length === 0) return
      setActiveMatch((i) => (i + dir + matches.length) % matches.length)
    },
    [matches.length],
  )

  const openSearch = useCallback(() => setSearchOpen(true), [])
  const closeSearch = useCallback(() => {
    setSearchOpen(false)
    setSearchQuery('')
    setActiveMatch(0)
    focusComposer()
  }, [focusComposer])

  // ── Stream stop (Escape, then refocus composer) ────────────────────────────
  useEscapeLayer(streaming, () => {
    controller.stop()
    focusComposer()
  })

  // ── Message actions ────────────────────────────────────────────────────────
  const onQuote = useCallback(
    (message: ConversationMessage) => {
      const quoted = message.content
        .split('\n')
        .map((line) => `> ${line}`)
        .join('\n')
      composerRef.current?.insertText(`${quoted}\n\n`)
    },
    [],
  )

  const lastFailedUser = useMemo(
    () => [...messages].reverse().find((m) => m.role === 'user' && m.state === 'failed'),
    [messages],
  )

  const onEditFailed = useCallback(
    (messageId: string) => {
      const message = messages.find((m) => m.id === messageId)
      if (!message) return
      composerRef.current?.insertText(message.content)
      controller.discardFailed(messageId)
    },
    [messages, controller],
  )

  const onEditLastFailed = useCallback(() => {
    if (lastFailedUser) onEditFailed(lastFailedUser.id)
  }, [lastFailedUser, onEditFailed])

  // ── Clear / export ─────────────────────────────────────────────────────────
  const onOpenClear = useCallback(() => {
    if (settings.confirmBeforeClearingHistory) setClearOpen(true)
    else void controller.clearHistory()
  }, [settings.confirmBeforeClearingHistory, controller])

  const onSlashAction = useCallback(
    (action: 'clear' | 'export') => {
      if (action === 'clear') onOpenClear()
      else void controller.exportConversation()
    },
    [onOpenClear, controller],
  )

  // ── Palette commands ───────────────────────────────────────────────────────
  const toggleDetails = useCallback(() => {
    setDetailsOpen(instanceId, !detailsOpen)
  }, [instanceId, detailsOpen, setDetailsOpen])

  const exportConversation = controller.exportConversation // stable per instanceId
  const commands = useMemo(
    () =>
      dense
        ? []
        : [
            { id: 'conversation.focus_composer', title: 'Focus composer', group: 'Actions' as const, icon: Keyboard, run: focusComposer },
            { id: 'conversation.search', title: 'Search in conversation', group: 'Actions' as const, icon: Search, run: openSearch },
            {
              id: 'conversation.jump_to_latest',
              title: 'Jump to latest message',
              group: 'Actions' as const,
              icon: ArrowDownToLine,
              run: () => transcriptRef.current?.scrollToLatest(),
            },
            {
              id: 'conversation.export',
              title: 'Export conversation',
              group: 'Actions' as const,
              icon: Download,
              run: () => void exportConversation(),
            },
            {
              id: 'conversation.toggle_details',
              title: 'Toggle details panel',
              group: 'Actions' as const,
              icon: PanelRight,
              run: toggleDetails,
            },
          ],
    [dense, focusComposer, openSearch, exportConversation, toggleDetails],
  )
  useRegisterCommands(commands)

  // ── Scoped keys: Ctrl/Cmd+F search, Ctrl/Cmd+Shift+Enter focus mode ───────
  const ownJumpRef = useRef(0)
  const onSurfaceKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && e.key.toLowerCase() === 'f') {
      e.preventDefault()
      openSearch()
    } else if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'Enter') {
      e.preventDefault()
      setFocusMode((v) => !v)
    } else if (e.altKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
      // Alt+↑/↓ jumps between your own messages (conversation.md keyboard map).
      const own = messages.filter((m) => m.role === 'user')
      if (own.length === 0) return
      e.preventDefault()
      ownJumpRef.current =
        e.key === 'ArrowUp'
          ? Math.min(ownJumpRef.current + 1, own.length - 1)
          : Math.max(ownJumpRef.current - 1, 0)
      const target = own[own.length - 1 - ownJumpRef.current]
      if (target) transcriptRef.current?.scrollToMessage(target.id)
    }
  }

  useEscapeLayer(focusMode, () => setFocusMode(false), { priority: -50 })

  // Announce focus-mode transitions politely (screen readers, §10.3 pattern).
  const [focusAnnouncement, setFocusAnnouncement] = useState('')
  const [prevFocusMode, setPrevFocusMode] = useState(focusMode)
  if (prevFocusMode !== focusMode) {
    setPrevFocusMode(focusMode)
    setFocusAnnouncement(focusMode ? 'Focus mode on. Press Escape to restore.' : 'Focus mode off.')
  }

  const title = conversation?.title ?? 'Conversation'

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    // eslint-disable-next-line jsx-a11y/no-static-element-interactions -- scope container: captures scoped chords from any child.
    <div
      className="flex h-full min-h-0 flex-col bg-app outline-none"
      onKeyDown={onSurfaceKeyDown}
      data-testid={dense ? 'conversation-sidecar' : 'conversation-surface'}
    >
      {/* Polite stream/state announcements. */}
      <div aria-live="polite" className="sr-only" data-testid="conversation-announcer">
        {controller.announcement}
      </div>
      <div aria-live="polite" className="sr-only">
        {focusAnnouncement}
      </div>

      {!dense ? (
        <ThreadHeader
          title={title}
          conversation={conversation}
          messageCount={messages.length}
          streaming={streaming}
          onStop={controller.stop}
          searchOpen={searchOpen}
          onToggleSearch={() => (searchOpen ? closeSearch() : openSearch())}
          onExport={() => void controller.exportConversation()}
          detailsOpen={detailsOpen}
          onToggleDetails={toggleDetails}
          onOpenClear={onOpenClear}
          focusMode={focusMode}
          onToggleFocusMode={() => setFocusMode((v) => !v)}
          compact={!wide}
        />
      ) : (
        <SidecarHeader instanceId={instanceId} streaming={streaming} onStop={controller.stop} />
      )}

      {searchOpen && !dense ? (
        <ConversationSearchBar
          query={searchQuery}
          onQueryChange={(q) => {
            setSearchQuery(q)
            setActiveMatch(0)
          }}
          matchCount={matches.length}
          activeIndex={Math.min(activeMatch, Math.max(0, matches.length - 1))}
          onPrev={() => stepMatch(-1)}
          onNext={() => stepMatch(1)}
          onClose={closeSearch}
        />
      ) : null}

      <div className="flex min-h-0 flex-1">
        <div className="flex min-w-0 flex-1 flex-col">
          {historyError ? (
            <div className="flex min-h-0 flex-1 flex-col">
              <div className="px-3 pt-2">
                <InlineNotice tone="attention">
                  History unavailable — new messages will still be saved locally.
                </InlineNotice>
              </div>
              <ErrorState
                title="Could not load the conversation"
                error={historyError}
                preservedNote="Nothing was changed."
                onRetry={controller.reload}
              />
            </div>
          ) : loading ? (
            <div className="flex flex-1 flex-col gap-3 px-4 py-4" data-testid="conversation-loading" aria-label="Loading conversation">
              {[72, 48, 64, 36].map((width, i) => (
                <div key={i} className={cn('flex flex-col gap-1.5', i % 2 === 1 && 'items-end')}>
                  <Skeleton className="h-3 w-20" />
                  <Skeleton className="h-14" style={{ width: `${width}%` }} />
                </div>
              ))}
            </div>
          ) : messages.length === 0 ? (
            <div className="flex-1 overflow-y-auto">
              <EmptyState
                icon={MessageSquare}
                title="No messages yet"
                description="Ask about this application, or send it a file or terminal output to work with."
              />
              <div className="flex flex-wrap justify-center gap-2 px-6 pb-6">
                {SUGGESTIONS.slice(0, 3).map((suggestion) => (
                  <button
                    key={suggestion}
                    type="button"
                    className="rounded-sm border border-border bg-surface px-2.5 py-1.5 text-xs text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                    onClick={() => composerRef.current?.insertText(suggestion)}
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <Transcript
              ref={transcriptRef}
              messages={messages}
              instanceId={instanceId}
              pinnedIds={pinnedIds}
              lastSeenId={lastSeenId}
              unreadActive={unreadActive}
              settings={settings}
              currentMatchId={searchOpen ? activeMatchId : null}
              dense={dense}
              onTogglePin={(id) => togglePin(instanceId, id)}
              onQuote={onQuote}
              onRetryResponse={() => void controller.retryLast()}
              onResend={(id) => void controller.resendFailed(id)}
              onEdit={onEditFailed}
              onDiscard={controller.discardFailed}
              onAtBottom={onAtBottom}
            />
          )}

          {/* Sticky composer — above the keyboard, safe-area aware. */}
          <div
            className={cn(
              'shrink-0 border-t border-border bg-app px-3 pb-[max(0.5rem,env(safe-area-inset-bottom))] pt-2',
              !dense && 'sm:px-4',
            )}
          >
            <div className={cn(!dense && 'mx-auto max-w-[760px]')}>
              <Composer
                ref={composerRef}
                instanceId={instanceId}
                draftKey={instanceId}
                settings={settings}
                streaming={streaming}
                onSend={(input) => void controller.send(input)}
                chipsState={chipsState}
                instanceName={instanceName}
                dense={dense}
                onSlashAction={onSlashAction}
                onEditLastFailed={onEditLastFailed}
              />
            </div>
          </div>
        </div>

        {/* Details: inline dock on wide screens; drawer below 1280 px.
            Focus mode hides the panel for distraction-free reading. */}
        {!dense && detailsOpen && wide && !focusMode ? (
          <aside
            className="hidden w-80 shrink-0 overflow-y-auto border-l border-border bg-surface p-3 xl:block"
            aria-label="Conversation details"
          >
            <DetailsPanel
              instanceId={instanceId}
              conversation={conversation}
              messages={messages}
              pinnedIds={pinnedIds}
              onJumpToMessage={(id) => transcriptRef.current?.scrollToMessage(id)}
            />
          </aside>
        ) : null}
      </div>

      {!dense ? (
        <Drawer open={detailsOpen && !wide && !focusMode} onOpenChange={(open) => setDetailsOpen(instanceId, open)} title="Conversation details" width={420}>
          <DetailsPanel
            instanceId={instanceId}
            conversation={conversation}
            messages={messages}
            pinnedIds={pinnedIds}
            onJumpToMessage={(id) => transcriptRef.current?.scrollToMessage(id)}
          />
        </Drawer>
      ) : null}

      <ConfirmDialog
        open={clearOpen}
        onOpenChange={setClearOpen}
        title="Clear conversation history"
        description="Every message in this conversation will be removed from this machine."
        target={title}
        effect={`${messages.length} ${messages.length === 1 ? 'message' : 'messages'} will be permanently removed.`}
        reversibility="This cannot be undone. Export first if you need a copy."
        confirmLabel="Clear history"
        destructive
        onConfirm={() => controller.clearHistory()}
      />

      {focusMode ? (
        <button
          type="button"
          onClick={() => setFocusMode(false)}
          className="fixed right-3 top-12 z-overlay inline-flex h-7 items-center gap-1.5 rounded-md border border-border bg-surface px-2 text-xs font-medium text-foreground shadow-1"
          data-testid="focus-mode-restore"
        >
          <PanelRight className="size-3.5" aria-hidden="true" />
          Restore · Esc
        </button>
      ) : null}
    </div>
  )
}

/** Compact sidecar header: identity + streaming pair + open-full-view link. */
function SidecarHeader({ instanceId, streaming, onStop }: { instanceId: string; streaming: boolean; onStop: () => void }) {
  return (
    <header className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-surface px-2.5" data-testid="sidecar-header">
      <MessageSquare className="size-4 shrink-0 text-foreground-tertiary" aria-hidden="true" />
      <span className="truncate text-xs font-semibold text-foreground">Conversation</span>
      {streaming ? (
        <span className="inline-flex items-center gap-1.5" data-testid="streaming-indicator">
          <span className="text-xs text-foreground-secondary" role="status">
            Responding…
          </span>
          <button
            type="button"
            onClick={onStop}
            data-testid="stop-stream"
            aria-label="Stop generating the response"
            className="inline-flex h-5 items-center gap-1 rounded-xs border border-border bg-surface px-1.5 text-xs font-medium text-foreground hover:bg-hover"
          >
            <Square className="size-3" aria-hidden="true" />
            Stop
          </button>
        </span>
      ) : null}
      <Link
        to={`/app/${instanceId}/conversation`}
        className="ml-auto text-xs text-accent hover:underline"
        data-testid="open-full-conversation"
      >
        Open
      </Link>
    </header>
  )
}
