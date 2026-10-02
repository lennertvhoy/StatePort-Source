/**
 * Skeleton (design.md §14) — layout-faithful placeholders. Shimmer only when
 * motion is allowed; under reduced motion the block is a static two-tone fill
 * (the global [data-motion="reduced"] rule freezes the shimmer animation).
 */
import type { CSSProperties } from 'react'

import { cn } from '@/lib/utils'

export interface SkeletonProps {
  className?: string
  style?: CSSProperties
}

export function Skeleton({ className, style }: SkeletonProps) {
  return (
    <div
      className={cn('relative overflow-hidden rounded-sm bg-active', className)}
      style={style}
      aria-hidden="true"
      data-testid="skeleton"
    >
      <div className="absolute inset-0 -translate-x-full animate-[shimmer_1.6s_infinite] bg-gradient-to-r from-transparent via-hover to-transparent" />
    </div>
  )
}

/** A column of row bones matching final row heights (§14: layout-faithful). */
export function SkeletonRows({ rows = 4, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('flex flex-col gap-2 p-3', className)} aria-label="Loading…" role="status">
      <span className="sr-only">Loading…</span>
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-row w-full" />
      ))}
    </div>
  )
}
