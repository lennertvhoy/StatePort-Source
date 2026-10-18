/**
 * ReceiptsTable — the default Receipts list (receipts.md): virtualized 32 px
 * rows, human-facing columns only (Action · Result · Actor · Time), an
 * indicated Time sort, hover quick actions, and full keyboard navigation
 * (↑/↓ · Enter · Ctrl/Cmd+C). Raw fields never appear here.
 *
 * On mobile (`compact`) rows become compact cards: action + result badge on
 * line one, actor · time on line two — the same data, the same keyboard map.
 *
 * Table semantics: role="table"/"rowgroup"/"row"/"columnheader"/"cell" with
 * aria-rowcount/aria-rowindex; roving tabindex comes from
 * useReceiptListKeyboard.
 */
import { useVirtualizer } from '@tanstack/react-virtual'
import { ArrowDown, ArrowUp, Link2 } from 'lucide-react'
import { useRef } from 'react'
import type { MouseEvent as ReactMouseEvent, ReactNode } from 'react'

import type { Receipt, ReceiptResult } from '@/client'
import { CopyButton, StatusBadgeFrom, TimeAgo, Tooltip } from '@/components'
import { cn } from '@/lib/utils'
import { receiptResultPresentation } from '@/semantic'
import { useWorkspaceStore } from '@/state'

import { actionKindIcon, actorLabel } from './receiptsModel'
import type { ReceiptSort } from './receiptsModel'
import type { ReceiptListKeyboard } from './useReceiptListKeyboard'

const ROW_HEIGHT = 32
const CARD_HEIGHT = 60

const GRID_COLS = 'grid-cols-[minmax(0,1fr)_9.5rem_5.5rem_7rem]'

export interface ReceiptsViewProps {
  receipts: Receipt[]
  keyboard: ReceiptListKeyboard
  onOpen: (receipt: Receipt) => void
  onOpenRelated: (receipt: Receipt) => void
  newIds: ReadonlySet<string>
}

export interface ReceiptsTableProps extends ReceiptsViewProps {
  sort: ReceiptSort
  onToggleSort: () => void
  compact?: boolean
  /** Native receipt routes cannot navigate Workbench-only operation/plan targets. */
  nativeRoute?: boolean
}

function ResultBadge({ result }: { result: ReceiptResult }) {
  return <StatusBadgeFrom presentation={receiptResultPresentation(result)} />
}

function relatedLabel(receipt: Receipt, nativeRoute: boolean): string | null {
  if (receipt.relatedApprovalId) return 'Open related approval'
  if (receipt.relatedOperationId && !nativeRoute) return 'Open related operation'
  if (receipt.relatedPlanId && !nativeRoute) return 'Open related plan'
  if (receipt.relatedConversationId) return 'Open related conversation'
  return null
}

function useRowClass() {
  const reducedMotion = useWorkspaceStore((s) => s.reducedMotion)
  return (receipt: Receipt, focused: boolean, newIds: ReadonlySet<string>) =>
    cn(
      'group cursor-pointer outline-none transition-colors duration-fast hover:bg-hover focus-visible:bg-hover',
      focused && 'bg-hover',
      !reducedMotion && newIds.has(receipt.id) && 'bg-accent-soft',
    )
}

export function ReceiptsTable({
  receipts,
  keyboard,
  onOpen,
  onOpenRelated,
  newIds,
  sort,
  onToggleSort,
  compact = false,
  nativeRoute = false,
}: ReceiptsTableProps) {
  const scrollRef = useRef<HTMLDivElement | null>(null)
  const rowClass = useRowClass()

  // TanStack Virtual intentionally owns mutable measurement callbacks; React
  // Compiler safely leaves this component un-memoized.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: receipts.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => (compact ? CARD_HEIGHT : ROW_HEIGHT),
    overscan: 10,
    // jsdom has no layout; an initial rect keeps rows rendered in tests.
    initialRect: { width: 800, height: 480 },
  })

  const bindScroll = (el: HTMLDivElement | null) => {
    scrollRef.current = el
    keyboard.bindContainer(el)
  }

  const rowProps = (receipt: Receipt, index: number) => ({
    'data-receipt-row': index,
    'data-receipt-id': receipt.id,
    tabIndex: keyboard.rowTabIndex(index),
    onFocus: () => keyboard.setActiveIndex(index),
    onClick: (e: ReactMouseEvent<HTMLElement>) => {
      // Row-level click opens the detail; clicks on quick actions do not.
      if ((e.target as HTMLElement).closest('[data-receipt-quick-actions]')) return
      onOpen(receipt)
    },
  })

  const quickActions = (receipt: Receipt): ReactNode => {
    const related = relatedLabel(receipt, nativeRoute)
    return (
      // Row-level click opens the detail; the row skips clicks from this zone.
      <span
        data-receipt-quick-actions=""
        className="flex items-center gap-0.5 opacity-0 transition-opacity duration-instant group-hover:opacity-100 group-focus-within:opacity-100"
      >
        <CopyButton text={receipt.id} label="Copy receipt ID" className="min-h-5 min-w-5" />
        {related ? (
          <Tooltip content={related}>
            <button
              type="button"
              aria-label={related}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') e.stopPropagation()
              }}
              onClick={(e) => {
                e.stopPropagation()
                onOpenRelated(receipt)
              }}
              className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm p-1 text-foreground-secondary transition-colors duration-instant hover:bg-active hover:text-foreground"
            >
              <Link2 className="size-3.5" aria-hidden="true" />
            </button>
          </Tooltip>
        ) : null}
      </span>
    )
  }

  if (compact) {
    return (
      <div
        ref={bindScroll}
        role="listbox"
        aria-label="Receipts"
        onKeyDown={keyboard.onKeyDown}
        // Roving tabindex puts focus on the options; the listbox itself is
        // programmatically focusable.
        tabIndex={-1}
        className="min-h-0 flex-1 overflow-y-auto"
        data-testid="receipts-cards"
      >
        <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
          {virtualizer.getVirtualItems().map((row) => {
            const receipt = receipts[row.index]
            const Icon = actionKindIcon(receipt.eventKind)
            return (
              <div
                key={receipt.id}
                role="option"
                aria-selected={keyboard.activeIndex === row.index}
                aria-label={`${receipt.actionName} — ${actorLabel(receipt.actor)}`}
                {...rowProps(receipt, row.index)}
                className={cn('absolute left-0 top-0 w-full px-2 py-1', rowClass(receipt, keyboard.activeIndex === row.index, newIds))}
                style={{ transform: `translateY(${row.start}px)`, height: CARD_HEIGHT }}
              >
                <span className="flex h-full flex-col justify-center gap-0.5 border-b border-border px-2">
                  <span className="flex items-center gap-2">
                    <Icon className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-sm text-foreground">{receipt.actionName}</span>
                    <ResultBadge result={receipt.result} />
                  </span>
                  <span className="flex items-center gap-1.5 pl-6 text-xs text-foreground-tertiary">
                    <span>{actorLabel(receipt.actor)}</span>
                    <span aria-hidden="true">·</span>
                    <TimeAgo date={receipt.createdAt} />
                    <span className="flex-1" />
                    {quickActions(receipt)}
                  </span>
                </span>
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  // role=grid: rows are focusable/actionable with arrow-key navigation
  // (ARIA grid pattern), so the keyboard handler lives on the grid itself.
  return (
    <div
      role="grid"
      aria-label="Receipts"
      aria-rowcount={receipts.length + 1}
      onKeyDown={keyboard.onKeyDown}
      // Roving tabindex puts focus on the rows; the grid itself is
      // programmatically focusable.
      tabIndex={-1}
      className="flex min-h-0 flex-1 flex-col"
      data-testid="receipts-table"
    >
      <div role="rowgroup" className="shrink-0">
        <div role="row" className={cn('grid h-7 items-center gap-2 border-b border-border bg-surface px-3', GRID_COLS)}>
          <span role="columnheader" className="text-xs font-medium text-foreground-secondary">
            Action
          </span>
          <span role="columnheader" className="text-xs font-medium text-foreground-secondary">
            Result
          </span>
          <span role="columnheader" className="text-xs font-medium text-foreground-secondary">
            Actor
          </span>
          <span role="columnheader" aria-sort={sort === 'newest' ? 'descending' : 'ascending'} className="flex justify-end">
            <button
              type="button"
              onClick={onToggleSort}
              aria-label={sort === 'newest' ? 'Sorted newest first — sort oldest first' : 'Sorted oldest first — sort newest first'}
              className="flex items-center gap-1 rounded-sm text-xs font-medium text-accent transition-colors duration-instant hover:text-accent-hover"
            >
              Time
              {sort === 'newest' ? (
                <ArrowDown className="size-3" aria-hidden="true" />
              ) : (
                <ArrowUp className="size-3" aria-hidden="true" />
              )}
            </button>
          </span>
        </div>
      </div>

      <div ref={bindScroll} role="rowgroup" className="min-h-0 flex-1 overflow-y-auto">
        <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
          {virtualizer.getVirtualItems().map((row) => {
            const receipt = receipts[row.index]
            const Icon = actionKindIcon(receipt.eventKind)
            return (
              <div
                key={receipt.id}
                role="row"
                aria-rowindex={row.index + 2}
                {...rowProps(receipt, row.index)}
                className={cn(
                  'absolute left-0 top-0 grid w-full items-center gap-2 border-b border-border/60 px-3',
                  GRID_COLS,
                  rowClass(receipt, keyboard.activeIndex === row.index, newIds),
                )}
                style={{ transform: `translateY(${row.start}px)`, height: ROW_HEIGHT }}
              >
                <span role="cell" className="flex min-w-0 items-center gap-2">
                  <Icon className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate text-sm text-foreground">{receipt.actionName}</span>
                  {quickActions(receipt)}
                </span>
                <span role="cell">
                  <ResultBadge result={receipt.result} />
                </span>
                <span role="cell" className="truncate text-sm text-foreground-secondary">
                  {actorLabel(receipt.actor)}
                </span>
                <span role="cell" className="flex justify-end">
                  <TimeAgo date={receipt.createdAt} />
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
