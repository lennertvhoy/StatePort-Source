/**
 * Drawer (design.md §14) — right detail panel (420–560 px) for receipt /
 * approval / plan / context detail. Radix Dialog: focus trap, Escape closes,
 * focus restored to the invoking control. On mobile (< md) it becomes a
 * bottom sheet so it never covers primary actions.
 */
import * as DialogPrimitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'
import { useRestoreFocus } from '@/lib/useRestoreFocus'

export interface DrawerProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description?: ReactNode
  children: ReactNode
  footer?: ReactNode
  /** Panel width on ≥ md (px). Clamped 420–560. */
  width?: number
  className?: string
}

export function Drawer({ open, onOpenChange, title, description, children, footer, width = 480, className }: DrawerProps) {
  const clamped = Math.min(560, Math.max(420, width))
  // No DialogTrigger: the drawer opens from state, so restore focus to the
  // element focused before opening (design.md §16) via onCloseAutoFocus.
  const restoreFocus = useRestoreFocus(open)
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-drawer bg-scrim data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=closed]:animate-out data-[state=closed]:fade-out-0" />
        <DialogPrimitive.Content
          onCloseAutoFocus={restoreFocus}
          className={cn(
            'fixed z-drawer flex flex-col border-border bg-surface shadow-2 outline-none duration-med ease-enter',
            // ≥ md: right drawer sliding from the edge (§6.2).
            'md:inset-y-0 md:right-0 md:h-full md:w-[var(--drawer-w)] md:border-l md:data-[state=open]:slide-in-from-right md:data-[state=closed]:slide-out-to-right',
            // < md: bottom sheet.
            'max-md:inset-x-0 max-md:bottom-0 max-md:max-h-[85vh] max-md:rounded-t-lg max-md:border-t max-md:data-[state=open]:slide-in-from-bottom max-md:data-[state=closed]:slide-out-to-bottom',
            'data-[state=open]:animate-in data-[state=closed]:animate-out',
            className,
          )}
          style={{ ['--drawer-w' as string]: `${clamped}px` }}
          data-testid="drawer"
        >
          <div className="flex min-h-14 items-start justify-between gap-3 border-b border-border px-4 py-3">
            <div className="min-w-0">
              <DialogPrimitive.Title className="truncate text-xl text-foreground">{title}</DialogPrimitive.Title>
              {description ? (
                <DialogPrimitive.Description className="mt-0.5 text-xs text-foreground-secondary">
                  {description}
                </DialogPrimitive.Description>
              ) : (
                <DialogPrimitive.Description className="sr-only">{typeof title === 'string' ? title : 'Details'}</DialogPrimitive.Description>
              )}
            </div>
            <DialogPrimitive.Close
              className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
              aria-label="Close"
            >
              <X className="size-4" aria-hidden="true" />
            </DialogPrimitive.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">{children}</div>
          {footer ? <div className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">{footer}</div> : null}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
