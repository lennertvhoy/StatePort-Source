/**
 * Disclosure — a calm collapsible section: chevron + title row, content below.
 * Radix Collapsible; fully keyboard accessible.
 */
import * as CollapsiblePrimitive from '@radix-ui/react-collapsible'
import { ChevronRight } from 'lucide-react'
import type { ReactNode } from 'react'
import { useState } from 'react'

import { cn } from '@/lib/utils'

export interface DisclosureProps {
  title: ReactNode
  children: ReactNode
  defaultOpen?: boolean
  open?: boolean
  onOpenChange?: (open: boolean) => void
  /** Right-aligned row extras (e.g. a CopyButton). */
  headerExtra?: ReactNode
  className?: string
}

export function Disclosure({
  title,
  children,
  defaultOpen = false,
  open,
  onOpenChange,
  headerExtra,
  className,
}: DisclosureProps) {
  const [internalOpen, setInternalOpen] = useState(defaultOpen)
  const isOpen = open ?? internalOpen

  return (
    <CollapsiblePrimitive.Root
      open={isOpen}
      onOpenChange={(next) => {
        setInternalOpen(next)
        onOpenChange?.(next)
      }}
      className={className}
      data-testid="disclosure"
    >
      <div className="flex items-center">
        <CollapsiblePrimitive.Trigger className="flex min-h-control-sm flex-1 items-center gap-1.5 rounded-sm px-2 py-1 text-left text-sm font-medium text-foreground transition-colors duration-instant hover:bg-hover">
          <ChevronRight
            className={cn('size-4 shrink-0 text-foreground-secondary transition-transform duration-fast', isOpen && 'rotate-90')}
            aria-hidden="true"
          />
          <span className="truncate">{title}</span>
        </CollapsiblePrimitive.Trigger>
        {headerExtra ? <div className="flex items-center gap-1 pr-1">{headerExtra}</div> : null}
      </div>
      <CollapsiblePrimitive.Content className="overflow-hidden data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down">
        {children}
      </CollapsiblePrimitive.Content>
    </CollapsiblePrimitive.Root>
  )
}
