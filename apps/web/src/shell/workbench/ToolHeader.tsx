/**
 * WorkbenchToolHeader — the per-tool canvas header contract (workbench.md):
 * tool name, state slot, primary action slot, maximize button; double-click
 * on empty header space maximizes the tool. Feature tools render this at the
 * top of their canvas.
 */
import { Maximize2 } from 'lucide-react'
import type { ComponentType, ReactNode } from 'react'

import { Tooltip } from '@/components'
import { cn } from '@/lib/utils'

export interface WorkbenchToolHeaderProps {
  name: string
  icon?: ComponentType<{ className?: string }>
  /** Tool-state slot (e.g. OperationStateLabel, StatusDot). */
  state?: ReactNode
  /** One primary action slot (design.md §14: one per surface). */
  primaryAction?: ReactNode
  onMaximize?: () => void
  className?: string
}

export function WorkbenchToolHeader({ name, icon: Icon, state, primaryAction, onMaximize, className }: WorkbenchToolHeaderProps) {
  return (
    <div
      className={cn('flex h-9 shrink-0 items-center gap-2 border-b border-border bg-surface px-3', className)}
      onDoubleClick={(e) => {
        if ((e.target as HTMLElement).closest('a,button')) return
        onMaximize?.()
      }}
      data-testid="workbench-tool-header"
    >
      {Icon ? <Icon className="size-4 text-foreground-secondary" aria-hidden="true" /> : null}
      <h1 className="truncate text-sm font-semibold text-foreground">{name}</h1>
      {state ? <div className="flex items-center gap-2">{state}</div> : null}
      <div className="flex-1" />
      {primaryAction ? <div className="flex items-center gap-1">{primaryAction}</div> : null}
      {onMaximize ? (
        <Tooltip content="Maximize tool">
          <button
            type="button"
            aria-label="Maximize tool"
            onClick={onMaximize}
            className="inline-flex min-h-7 min-w-7 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          >
            <Maximize2 className="size-4" aria-hidden="true" />
          </button>
        </Tooltip>
      ) : null}
    </div>
  )
}
