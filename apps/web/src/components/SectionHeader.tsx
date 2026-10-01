/**
 * SectionHeader — section title within a surface (§4.2: --text-lg 600) with
 * optional secondary description and a right-aligned actions slot.
 */
import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

export interface SectionHeaderProps {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  className?: string
}

export function SectionHeader({ title, description, actions, className }: SectionHeaderProps) {
  return (
    <div className={cn('flex items-start justify-between gap-3', className)} data-testid="section-header">
      <div className="min-w-0">
        <h2 className="truncate text-lg text-foreground">{title}</h2>
        {description ? <p className="mt-0.5 text-xs text-foreground-secondary">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-1">{actions}</div> : null}
    </div>
  )
}
