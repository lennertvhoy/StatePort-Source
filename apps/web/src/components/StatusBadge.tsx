/**
 * StatusBadge (design.md §7.3) — the ONLY pill in the product.
 *
 * Inline-flex, 4 px radius, 12 px/600 label, 12 px icon, padding 2 px 8 px,
 * tinted bg + 1 px tint border + status text color. HC themes switch to an
 * outline style via the `.status-badge` rule in index.css. Max 1–2 per row.
 * Status is icon + text — never color-only (§2.3).
 */
import type { LucideIcon } from 'lucide-react'

import type { SemanticState } from '@/client'
import type { SemanticPresentation } from '@/semantic'
import { cn } from '@/lib/utils'

const STATE_CLASSES: Record<SemanticState, string> = {
  success: 'text-status-success bg-status-success-bg border-status-success-border',
  neutral: 'text-status-neutral bg-status-neutral-bg border-status-neutral-border',
  attention: 'text-status-attention bg-status-attention-bg border-status-attention-border',
  waiting: 'text-status-waiting bg-status-waiting-bg border-status-waiting-border',
  blocked: 'text-status-blocked bg-status-blocked-bg border-status-blocked-border',
  danger: 'text-status-danger bg-status-danger-bg border-status-danger-border',
  informational: 'text-status-informational bg-status-informational-bg border-status-informational-border',
}

export interface StatusBadgeProps {
  state: SemanticState
  label: string
  icon?: LucideIcon
  spin?: boolean
  className?: string
}

export function StatusBadge({ state, label, icon: Icon, spin, className }: StatusBadgeProps) {
  return (
    <span
      className={cn(
        'status-badge inline-flex max-w-full items-center gap-1 rounded-sm border px-2 py-0.5 text-xs font-semibold',
        STATE_CLASSES[state],
        className,
      )}
      data-testid="status-badge"
      data-state={state}
    >
      {Icon ? <Icon className={cn('size-3 shrink-0', spin && 'icon-spin')} aria-hidden="true" /> : null}
      <span className="truncate">{label}</span>
    </span>
  )
}

/** Render directly from a semantic-layer presentation (src/semantic.ts). */
export function StatusBadgeFrom({
  presentation,
  className,
}: {
  presentation: SemanticPresentation
  className?: string
}) {
  return (
    <StatusBadge
      state={presentation.state}
      label={presentation.label}
      icon={presentation.icon}
      spin={presentation.spin}
      className={className}
    />
  )
}
