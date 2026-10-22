/**
 * StatusDot (design.md §7.3) — 8 px filled circle in status color + adjacent
 * text label. Never rendered alone; the tooltip repeats the label. For compact
 * inline contexts (file-tree decorations, terminal tabs, sidebar app rows).
 */
import type { SemanticState } from '@/client'
import type { SemanticPresentation } from '@/semantic'
import { cn } from '@/lib/utils'

import { Tooltip } from './Tooltip'

const DOT_CLASSES: Record<SemanticState, string> = {
  success: 'bg-status-success',
  neutral: 'bg-status-neutral',
  attention: 'bg-status-attention',
  waiting: 'bg-status-waiting',
  blocked: 'bg-status-blocked',
  danger: 'bg-status-danger',
  informational: 'bg-status-informational',
}

export interface StatusDotProps {
  state: SemanticState
  label: string
  /** When false, renders only the dot (label still announced + tooltip). */
  showLabel?: boolean
  className?: string
}

export function StatusDot({ state, label, showLabel = true, className }: StatusDotProps) {
  return (
    <Tooltip content={label}>
      <span className={cn('inline-flex items-center gap-1.5', className)} data-testid="status-dot" data-state={state}>
        <span
          className={cn('size-2 shrink-0 rounded-full', DOT_CLASSES[state])}
          role="img"
          aria-label={label}
        />
        {showLabel ? <span className="truncate text-xs text-foreground-secondary">{label}</span> : null}
      </span>
    </Tooltip>
  )
}

/** Render from a semantic-layer presentation. */
export function StatusDotFrom({
  presentation,
  showLabel,
  className,
}: {
  presentation: SemanticPresentation
  showLabel?: boolean
  className?: string
}) {
  return <StatusDot state={presentation.state} label={presentation.label} showLabel={showLabel} className={className} />
}
