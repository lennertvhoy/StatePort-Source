/**
 * Kbd (design.md §8) — key cap: 2 px radius, 1 px border-strong, mono 12 px.
 */
import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

export function Kbd({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        'inline-flex h-5 min-w-5 items-center justify-center rounded-xs border border-border-strong bg-surface-2 px-1 font-mono text-xs leading-none text-foreground-secondary',
        className,
      )}
    >
      {children}
    </kbd>
  )
}
