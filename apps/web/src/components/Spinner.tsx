/**
 * Spinner (design.md §6.2) — Loader2 rotating 1 s linear. Under reduced
 * motion the global rule freezes rotation (§6.3); pair with `label` text so
 * loading is communicated by words, not motion.
 */
import { Loader2 } from 'lucide-react'

import { cn } from '@/lib/utils'

export interface SpinnerProps {
  size?: 12 | 16 | 20
  label?: string
  className?: string
}

export function Spinner({ size = 16, label, className }: SpinnerProps) {
  return (
    <span className={cn('inline-flex items-center gap-1.5', className)} role={label ? 'status' : undefined} data-testid="spinner">
      <Loader2 className="icon-spin shrink-0" style={{ width: size, height: size }} aria-hidden="true" />
      {label ? <span className="text-sm text-foreground-secondary">{label}</span> : <span className="sr-only">Loading…</span>}
    </span>
  )
}
