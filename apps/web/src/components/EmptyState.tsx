/**
 * EmptyState (design.md §14) — 20 px muted icon, --text-lg 600 title, one
 * 13 px secondary sentence (what is absent + whether that is normal), up to
 * two actions. Never a dead empty box; `description` is required so
 * "what's next" stays unskippable.
 */
import type { LucideIcon } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'

export interface EmptyStateAction {
  label: string
  onClick: () => void
  icon?: LucideIcon
}

export interface EmptyStateProps {
  icon: LucideIcon
  title: string
  /** One sentence: what is absent and whether that is normal. Required. */
  description: string
  action?: EmptyStateAction
  secondaryAction?: EmptyStateAction
  className?: string
}

export function EmptyState({ icon: Icon, title, description, action, secondaryAction, className }: EmptyStateProps) {
  return (
    <div
      className={cn('flex h-full min-h-40 flex-col items-center justify-center gap-2 px-6 py-10 text-center', className)}
      data-testid="empty-state"
    >
      <Icon className="size-5 text-foreground-tertiary" aria-hidden="true" />
      <h2 className="text-lg text-foreground">{title}</h2>
      <p className="max-w-md text-sm text-foreground-secondary">{description}</p>
      {action || secondaryAction ? (
        <div className="mt-2 flex items-center gap-2">
          {action ? (
            <Button size="sm" onClick={action.onClick}>
              {action.icon ? <action.icon aria-hidden="true" /> : null}
              {action.label}
            </Button>
          ) : null}
          {secondaryAction ? (
            <Button size="sm" variant="ghost" onClick={secondaryAction.onClick}>
              {secondaryAction.icon ? <secondaryAction.icon aria-hidden="true" /> : null}
              {secondaryAction.label}
            </Button>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
