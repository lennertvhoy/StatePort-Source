/**
 * InstanceRow — one installed application in the All-applications list or the
 * Recently used list. Two presentations of the SAME content (applications.md):
 * - compact rows (single line, hairline-separated),
 * - comfortable panels (two-column grid, more air — never nested cards).
 *
 * Every row carries ONE honest status (icon + label, never a repeated
 * "Ready"), an attention count when > 0, last activity, a Pin mark when
 * pinned, and the context menu. Rows are roving-tabindex list items:
 * Enter opens · Space menu · P pins · Alt+↑↓ reorders pinned rows.
 */
import { EllipsisVertical, GripVertical, Pin, TriangleAlert } from 'lucide-react'
import { useRef } from 'react'

import type { ApplicationInstance, SemanticState } from '@/client'
import { StatusDot, TimeAgo, Tooltip } from '@/components'
import { cn } from '@/lib/utils'
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { InstanceGlyphTile } from '@/shell/appIcon'

import type { DominantStatus } from '../lib/dominantStatus'
import { dominantStatusTooltip } from '../lib/dominantStatus'
import type { useRovingFocus } from '../lib/useRovingFocus'
import { InstanceMenu } from './InstanceMenu'

const STATE_TEXT: Record<SemanticState, string> = {
  success: 'text-status-success',
  neutral: 'text-status-neutral',
  attention: 'text-status-attention',
  waiting: 'text-status-waiting',
  blocked: 'text-status-blocked',
  danger: 'text-status-danger',
  informational: 'text-status-informational',
}

export interface InstanceRowActions {
  onOpen: (instance: ApplicationInstance) => void
  onTogglePin: (instance: ApplicationInstance) => void
  onRename?: (instance: ApplicationInstance) => void
  onOpenSettings: (instance: ApplicationInstance) => void
  onMove?: (instance: ApplicationInstance, direction: -1 | 1) => void
}

interface RowProps extends InstanceRowActions {
  instance: ApplicationInstance
  status: DominantStatus
  readOnly: boolean
  index: number
  roving: ReturnType<typeof useRovingFocus>
  /** Pinned-group position (1-based) when this row is in the pinned group. */
  pinnedPosition?: { index: number; count: number }
  onDragStartRow?: (instance: ApplicationInstance) => void
  onDropOnRow?: (instance: ApplicationInstance) => void
}

function useRowMenu() {
  const triggerRef = useRef<HTMLButtonElement | null>(null)
  return { triggerRef, openMenu: () => triggerRef.current?.click() }
}

function AttentionCount({ instance }: { instance: ApplicationInstance }) {
  const count = instance.attention.filter((a) => !a.acknowledged).length
  if (count === 0) return null
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-status-attention"
      aria-label={`${count} attention ${count === 1 ? 'item' : 'items'}`}
      data-testid={`attention-count-${instance.id}`}
    >
      <TriangleAlert className="size-3" aria-hidden="true" />
      {count}
    </span>
  )
}

function PinnedMark() {
  return (
    <Tooltip content="Pinned · Alt+↑ / Alt+↓ to reorder">
      <span className="inline-flex min-h-6 min-w-6 items-center justify-center" role="img" aria-label="Pinned">
        <Pin className="size-3.5 text-foreground-tertiary" aria-hidden="true" />
      </span>
    </Tooltip>
  )
}

/** Compact single-line row (default density). */
export function InstanceRow(props: RowProps) {
  const { instance, status, readOnly, index, roving, pinnedPosition } = props
  const { triggerRef, openMenu } = useRowMenu()
  const StatusIcon = status.presentation.icon
  const lastActivity = instance.lastOpenedAt ?? instance.createdAt
  const move = (direction: -1 | 1) => props.onMove?.(instance, direction)

  return (
    <li
      className="group flex items-center gap-1 rounded-sm px-1 transition-colors duration-instant hover:bg-hover max-md:min-h-11"
      aria-label={`${instance.name}, ${status.presentation.label}`}
      aria-posinset={pinnedPosition ? pinnedPosition.index + 1 : undefined}
      aria-setsize={pinnedPosition ? pinnedPosition.count : undefined}
      draggable={Boolean(pinnedPosition) && !readOnly}
      onDragStart={(e) => {
        e.dataTransfer.effectAllowed = 'move'
        props.onDragStartRow?.(instance)
      }}
      onDragOver={(e) => {
        if (pinnedPosition) e.preventDefault()
      }}
      onDrop={(e) => {
        e.preventDefault()
        props.onDropOnRow?.(instance)
      }}
      data-testid={`instance-row-${instance.id}`}
      {...roving.rowProps(index, {
        onOpen: () => props.onOpen(instance),
        onMenu: openMenu,
        onTogglePin: readOnly ? undefined : () => props.onTogglePin(instance),
        onMoveUp: pinnedPosition && !readOnly ? () => move(-1) : undefined,
        onMoveDown: pinnedPosition && !readOnly ? () => move(1) : undefined,
      })}
    >
      {pinnedPosition && !readOnly ? (
        <GripVertical
          className="size-4 shrink-0 cursor-grab text-foreground-tertiary opacity-0 transition-opacity duration-instant group-hover:opacity-100 group-focus-within:opacity-100 max-md:hidden"
          aria-hidden="true"
        />
      ) : null}
      <button
        type="button"
        tabIndex={-1}
        onClick={() => props.onOpen(instance)}
        className="flex min-h-10 min-w-0 flex-1 items-center gap-2.5 rounded-sm px-1 text-left md:min-h-row"
        aria-hidden={false}
      >
        <InstanceGlyphTile instance={instance} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium text-foreground">
            {instance.name}
            <span className="ml-2 text-xs font-normal text-foreground-secondary">· {instance.packageDisplayName}</span>
          </span>
          {/* Mobile second line: status + time (desktop shows them inline). */}
          <span className="mt-0.5 flex items-center gap-2 md:hidden">
            <span className={cn('inline-flex items-center gap-1 text-xs font-medium', STATE_TEXT[status.presentation.state])}>
              <StatusIcon className={cn('size-3', status.presentation.spin && 'icon-spin')} aria-hidden="true" />
              {status.presentation.label}
            </span>
            <TimeAgo date={lastActivity} />
          </span>
        </span>
      </button>
      <span
        className={cn('hidden w-36 shrink-0 items-center gap-1.5 text-xs font-medium md:inline-flex', STATE_TEXT[status.presentation.state])}
        data-testid={`instance-status-${instance.id}`}
        data-state={status.presentation.state}
        title={dominantStatusTooltip(status)}
      >
        <StatusIcon className={cn('size-3.5 shrink-0', status.presentation.spin && 'icon-spin')} aria-hidden="true" />
        <span className="truncate">{status.presentation.label}</span>
      </span>
      <AttentionCount instance={instance} />
      <TimeAgo date={lastActivity} className="hidden w-20 shrink-0 text-right md:block" />
      {instance.pinned ? <PinnedMark /> : null}
      <DropdownMenu>
        <DropdownMenuTrigger
          ref={triggerRef}
          tabIndex={-1}
          aria-label={`Actions for ${instance.name}`}
          className="inline-flex min-h-10 min-w-10 shrink-0 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-active hover:text-foreground md:min-h-8 md:min-w-8"
        >
          <EllipsisVertical className="size-4" aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="bg-surface">
          <InstanceMenu
            instance={instance}
            readOnly={readOnly}
            onOpen={() => props.onOpen(instance)}
            onTogglePin={() => props.onTogglePin(instance)}
            onRename={props.onRename ? () => props.onRename?.(instance) : undefined}
            onOpenSettings={() => props.onOpenSettings(instance)}
            onMoveUp={pinnedPosition && !readOnly ? () => move(-1) : undefined}
            onMoveDown={pinnedPosition && !readOnly ? () => move(1) : undefined}
          />
        </DropdownMenuContent>
      </DropdownMenu>
    </li>
  )
}

/** Comfortable-mode panel (two-column grid cell; same content, more air). */
export function InstanceCard(props: RowProps) {
  const { instance, status, readOnly, index, roving, pinnedPosition } = props
  const { triggerRef, openMenu } = useRowMenu()
  const StatusIcon = status.presentation.icon
  const lastActivity = instance.lastOpenedAt ?? instance.createdAt
  const move = (direction: -1 | 1) => props.onMove?.(instance, direction)

  return (
    <li
      className="group rounded-md border border-border bg-surface p-3 transition-colors duration-instant hover:border-border-strong"
      aria-label={`${instance.name}, ${status.presentation.label}`}
      aria-posinset={pinnedPosition ? pinnedPosition.index + 1 : undefined}
      aria-setsize={pinnedPosition ? pinnedPosition.count : undefined}
      draggable={Boolean(pinnedPosition) && !readOnly}
      onDragStart={(e) => {
        e.dataTransfer.effectAllowed = 'move'
        props.onDragStartRow?.(instance)
      }}
      onDragOver={(e) => {
        if (pinnedPosition) e.preventDefault()
      }}
      onDrop={(e) => {
        e.preventDefault()
        props.onDropOnRow?.(instance)
      }}
      data-testid={`instance-card-${instance.id}`}
      {...roving.rowProps(index, {
        onOpen: () => props.onOpen(instance),
        onMenu: openMenu,
        onTogglePin: readOnly ? undefined : () => props.onTogglePin(instance),
        onMoveUp: pinnedPosition && !readOnly ? () => move(-1) : undefined,
        onMoveDown: pinnedPosition && !readOnly ? () => move(1) : undefined,
      })}
    >
      <div className="flex items-start gap-2">
        <button
          type="button"
          tabIndex={-1}
          onClick={() => props.onOpen(instance)}
          className="flex min-h-10 min-w-0 flex-1 items-center gap-2.5 rounded-sm text-left"
        >
          <InstanceGlyphTile instance={instance} className="size-6" />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-medium text-foreground">{instance.name}</span>
            <span className="block truncate text-xs text-foreground-secondary">{instance.packageDisplayName}</span>
          </span>
        </button>
        {pinnedPosition && !readOnly ? (
          <GripVertical className="mt-1 size-4 shrink-0 cursor-grab text-foreground-tertiary" aria-hidden="true" />
        ) : null}
        {instance.pinned ? <PinnedMark /> : null}
        <DropdownMenu>
          <DropdownMenuTrigger
            ref={triggerRef}
            tabIndex={-1}
            aria-label={`Actions for ${instance.name}`}
            className="inline-flex min-h-10 min-w-10 shrink-0 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground md:min-h-8 md:min-w-8"
          >
            <EllipsisVertical className="size-4" aria-hidden="true" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="bg-surface">
            <InstanceMenu
              instance={instance}
              readOnly={readOnly}
              onOpen={() => props.onOpen(instance)}
              onTogglePin={() => props.onTogglePin(instance)}
              onRename={props.onRename ? () => props.onRename?.(instance) : undefined}
              onOpenSettings={() => props.onOpenSettings(instance)}
              onMoveUp={pinnedPosition && !readOnly ? () => move(-1) : undefined}
              onMoveDown={pinnedPosition && !readOnly ? () => move(1) : undefined}
            />
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1">
        <span
          className={cn('inline-flex items-center gap-1.5 text-xs font-medium', STATE_TEXT[status.presentation.state])}
          data-testid={`instance-status-${instance.id}`}
          data-state={status.presentation.state}
          title={dominantStatusTooltip(status)}
        >
          <StatusIcon className={cn('size-3.5', status.presentation.spin && 'icon-spin')} aria-hidden="true" />
          {status.presentation.label}
        </span>
        <AttentionCount instance={instance} />
        <TimeAgo date={lastActivity} />
      </div>
      <div className="mt-3">
        <button
          type="button"
          tabIndex={-1}
          onClick={() => props.onOpen(instance)}
          className="inline-flex min-h-10 w-full items-center justify-center rounded-sm border border-border text-xs font-medium text-accent transition-colors duration-instant hover:bg-hover md:min-h-8"
        >
          Open
        </button>
      </div>
    </li>
  )
}

/** Recently-used compact row (32 px): glyph, name, dominant StatusDot, time, hover Open. */
export function RecentInstanceRow(props: RowProps) {
  const { instance, status, index, roving } = props
  const { triggerRef, openMenu } = useRowMenu()
  return (
    <li
      className="group flex items-center gap-1 rounded-sm px-1 transition-colors duration-instant hover:bg-hover"
      aria-label={`${instance.name}, ${status.presentation.label}`}
      data-testid={`recent-row-${instance.id}`}
      {...roving.rowProps(index, {
        onOpen: () => props.onOpen(instance),
        onMenu: openMenu,
        onTogglePin: () => props.onTogglePin(instance),
      })}
    >
      <button
        type="button"
        tabIndex={-1}
        onClick={() => props.onOpen(instance)}
        className="flex min-h-10 min-w-0 flex-1 items-center gap-2.5 rounded-sm px-1 text-left md:min-h-row"
      >
        <InstanceGlyphTile instance={instance} className="size-4 rounded-xs" />
        <span className="min-w-0 flex-1 truncate text-sm text-foreground">{instance.name}</span>
      </button>
      <StatusDot
        state={status.presentation.state}
        label={dominantStatusTooltip(status)}
        className="hidden w-40 shrink-0 sm:inline-flex"
      />
      <TimeAgo date={instance.lastOpenedAt ?? instance.createdAt} className="w-20 shrink-0 text-right" />
      <button
        type="button"
        tabIndex={-1}
        onClick={() => props.onOpen(instance)}
        className="inline-flex min-h-10 shrink-0 items-center rounded-sm border border-border px-2 text-xs font-medium text-accent opacity-0 transition-opacity duration-instant hover:bg-surface focus-visible:opacity-100 group-hover:opacity-100 md:min-h-7"
      >
        Open
      </button>
      <DropdownMenu>
        <DropdownMenuTrigger
          ref={triggerRef}
          tabIndex={-1}
          aria-label={`Actions for ${instance.name}`}
          className="inline-flex min-h-10 min-w-10 shrink-0 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-active hover:text-foreground md:min-h-8 md:min-w-8"
        >
          <EllipsisVertical className="size-4" aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="bg-surface">
          <InstanceMenu
            instance={instance}
            readOnly={props.readOnly}
            onOpen={() => props.onOpen(instance)}
            onTogglePin={() => props.onTogglePin(instance)}
            onRename={props.onRename ? () => props.onRename?.(instance) : undefined}
            onOpenSettings={() => props.onOpenSettings(instance)}
          />
        </DropdownMenuContent>
      </DropdownMenu>
    </li>
  )
}
