/**
 * Tooltip (design.md §14) — hover 200 ms delay / focus instant, Esc-dismissible,
 * never traps focus. Token-styled (shadow-1, surface bg).
 */
import * as TooltipPrimitive from '@radix-ui/react-tooltip'
import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

export interface TooltipProps {
  content: ReactNode
  children: ReactNode
  side?: 'top' | 'right' | 'bottom' | 'left'
  align?: 'start' | 'center' | 'end'
  /** When true the tooltip never renders (e.g. touch-only contexts). */
  disabled?: boolean
  className?: string
}

export function Tooltip({ content, children, side = 'top', align = 'center', disabled, className }: TooltipProps) {
  if (disabled || content === null || content === undefined || content === false || content === '') {
    return <>{children}</>
  }
  return (
    <TooltipPrimitive.Provider delayDuration={200} skipDelayDuration={0} disableHoverableContent>
      <TooltipPrimitive.Root>
        <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
        <TooltipPrimitive.Portal>
          <TooltipPrimitive.Content
            side={side}
            align={align}
            sideOffset={6}
            className={cn(
              'z-overlay max-w-64 rounded-sm border border-border bg-surface px-2 py-1 text-xs text-foreground shadow-1',
              'animate-in fade-in-0 zoom-in-95 duration-fast',
              className,
            )}
          >
            {content}
          </TooltipPrimitive.Content>
        </TooltipPrimitive.Portal>
      </TooltipPrimitive.Root>
    </TooltipPrimitive.Provider>
  )
}
