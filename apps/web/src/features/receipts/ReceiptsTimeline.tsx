/**
 * ReceiptsTimeline — the timeline view (receipts.md): receipts grouped by
 * day with sticky day headers, a mono 12 px time gutter, and — when "group
 * related" is on — a left connector line chaining receipts that share an
 * approval/plan/operation/conversation relation (approval → run → validate
 * reads downward).
 *
 * Semantics: one role="list" per day group inside a labelled feed; the same
 * keyboard map as the table (shared useReceiptListKeyboard). Vertical by
 * design — on mobile this is the default view.
 */
import { format, parseISO } from 'date-fns'

import type { ReceiptResult } from '@/client'
import { StatusBadgeFrom, TimeAgo } from '@/components'
import { cn } from '@/lib/utils'
import { receiptResultPresentation } from '@/semantic'
import { useWorkspaceStore } from '@/state'

import { actionKindIcon, actorLabel, connectedReceiptIds } from './receiptsModel'
import type { ReceiptDayGroup } from './receiptsModel'
import type { ReceiptsViewProps } from './ReceiptsTable'

export interface ReceiptsTimelineProps extends ReceiptsViewProps {
  groups: ReceiptDayGroup[]
  groupRelated: boolean
}

function ResultBadge({ result }: { result: ReceiptResult }) {
  return <StatusBadgeFrom presentation={receiptResultPresentation(result)} />
}

export function ReceiptsTimeline({ groups, groupRelated, receipts, keyboard, onOpen, newIds }: ReceiptsTimelineProps) {
  const reducedMotion = useWorkspaceStore((s) => s.reducedMotion)

  // Flat visual order → keyboard row index (headers are not focusable).
  const flatIndex = new Map<string, number>()
  receipts.forEach((receipt, index) => flatIndex.set(receipt.id, index))

  // Callback ref (same pattern as the table): the hook's bind runs inside
  // the callback, keeping ref plumbing out of render.
  const bindScroll = (el: HTMLDivElement | null) => {
    keyboard.bindContainer(el)
  }

  return (
    <div
      ref={bindScroll}
      onKeyDown={keyboard.onKeyDown}
      // Roving tabindex puts focus on the options; the listbox itself is
      // programmatically focusable.
      tabIndex={-1}
      className="min-h-0 flex-1 overflow-y-auto"
      role="listbox"
      aria-label="Receipts timeline"
      data-testid="receipts-timeline"
    >
      {groups.map((group) => {
        const connected = groupRelated ? connectedReceiptIds(group.items) : new Set<string>()
        return (
          <section key={group.dayKey} role="group" aria-label={group.label} className="relative">
            <h3 className="sticky top-0 z-10 flex h-7 items-center border-b border-border bg-app px-3 text-xs font-medium text-foreground-secondary">
              {group.label}
            </h3>
            <ol className="m-0 list-none p-0">
              {group.items.map((receipt) => {
                const index = flatIndex.get(receipt.id) ?? 0
                const isConnected = connected.has(receipt.id)
                const Icon = actionKindIcon(receipt.eventKind)
                const focused = keyboard.activeIndex === index
                return (
                  <li
                    key={receipt.id}
                    role="option"
                    aria-selected={focused}
                    data-receipt-row={index}
                    data-receipt-id={receipt.id}
                    tabIndex={keyboard.rowTabIndex(index)}
                    onFocus={() => keyboard.setActiveIndex(index)}
                    onClick={() => onOpen(receipt)}
                    onKeyDown={(e) => {
                      // The row activates itself; stop before the container's
                      // list handler would open the active row a second time.
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        e.stopPropagation()
                        onOpen(receipt)
                      }
                    }}
                    className={cn(
                      'group flex cursor-pointer items-stretch gap-2 border-b border-border/60 px-3 outline-none transition-colors duration-fast hover:bg-hover focus-visible:bg-hover',
                      focused && 'bg-hover',
                      !reducedMotion && newIds.has(receipt.id) && 'bg-accent-soft',
                    )}
                  >
                    {/* Time gutter (mono 12 px) */}
                    <span className="flex w-11 shrink-0 items-center justify-end">
                      <time dateTime={receipt.createdAt} className="tnum font-mono text-xs text-foreground-tertiary">
                        {format(parseISO(receipt.createdAt), 'HH:mm')}
                      </time>
                    </span>
                    {/* Connector gutter: a continuous line links related receipts */}
                    <span className="relative flex w-3 shrink-0 justify-center" aria-hidden="true">
                      {isConnected ? <span className="absolute inset-y-0 w-0.5 bg-accent/50" /> : null}
                      <span
                        className={cn(
                          'absolute top-1/2 size-1.5 -translate-y-1/2 rounded-full',
                          isConnected ? 'bg-accent' : 'bg-border-strong',
                        )}
                      />
                    </span>
                    <span className="flex min-h-10 min-w-0 flex-1 items-center gap-2 py-1">
                      <Icon className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm text-foreground">{receipt.actionName}</span>
                        <span className="block truncate text-xs text-foreground-tertiary sm:hidden">
                          {actorLabel(receipt.actor)} · <TimeAgo date={receipt.createdAt} />
                        </span>
                      </span>
                      <ResultBadge result={receipt.result} />
                      <span className="hidden w-16 truncate text-right text-xs text-foreground-tertiary sm:block">
                        {actorLabel(receipt.actor)}
                      </span>
                    </span>
                  </li>
                )
              })}
            </ol>
          </section>
        )
      })}
    </div>
  )
}
