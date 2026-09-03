/**
 * ConfirmDialog (design.md §14) — exact target, exact effect, reversibility,
 * optional related-plan link. The destructive variant requires typing the
 * target name ONLY for truly high-risk actions (destroy VM, reset mock data,
 * revoke authorization). Cancel is focused first on destructive dialogs.
 */
import { TriangleAlert } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

import { cn } from '@/lib/utils'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'

export interface ConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  /** What will happen, in one plain sentence. */
  description?: string
  /** The exact thing the action applies to (name / id). */
  target?: string
  /** The exact effect of confirming. */
  effect?: string
  /** Whether and how the action can be undone. */
  reversibility?: string
  confirmLabel?: string
  cancelLabel?: string
  destructive?: boolean
  /** High-risk only: the exact name the user must type to enable confirm. */
  requireTypedConfirmation?: string
  onConfirm: () => void | Promise<void>
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  target,
  effect,
  reversibility,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  destructive = false,
  requireTypedConfirmation,
  onConfirm,
}: ConfirmDialogProps) {
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const cancelRef = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    if (open) {
      setTyped('')
      setBusy(false)
      // §14: Cancel is focused first on destructive dialogs (focused here,
      // not via the autoFocus prop). Radix also focuses Cancel by default.
      if (destructive) cancelRef.current?.focus()
    }
  }, [open, destructive])

  const needsTyping = destructive && Boolean(requireTypedConfirmation)
  const confirmed = !needsTyping || typed === requireTypedConfirmation

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent data-testid="confirm-dialog" className="bg-surface">
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2 text-xl">
            {destructive ? <TriangleAlert className="size-5 text-status-danger" aria-hidden="true" /> : null}
            {title}
          </AlertDialogTitle>
          {description ? <AlertDialogDescription>{description}</AlertDialogDescription> : null}
        </AlertDialogHeader>

        <div className="flex flex-col gap-2 text-sm">
          {target ? (
            <dl className="flex items-baseline gap-2">
              <dt className="shrink-0 text-xs font-medium text-foreground-secondary">Target</dt>
              <dd className="tnum min-w-0 truncate font-mono text-xs text-foreground">{target}</dd>
            </dl>
          ) : null}
          {effect ? (
            <dl className="flex items-baseline gap-2">
              <dt className="shrink-0 text-xs font-medium text-foreground-secondary">Effect</dt>
              <dd className="text-sm text-foreground">{effect}</dd>
            </dl>
          ) : null}
          {reversibility ? (
            <dl className="flex items-baseline gap-2">
              <dt className="shrink-0 text-xs font-medium text-foreground-secondary">Reversibility</dt>
              <dd className="text-sm text-foreground">{reversibility}</dd>
            </dl>
          ) : null}
          {needsTyping ? (
            <label className="mt-1 flex flex-col gap-1.5">
              <span className="text-xs text-foreground-secondary">
                Type <span className="tnum font-mono font-medium text-foreground">{requireTypedConfirmation}</span> to
                confirm.
              </span>
              <input
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                className="h-control rounded-sm border border-input bg-surface px-2 font-mono text-sm text-foreground"
                autoComplete="off"
                spellCheck={false}
                data-testid="confirm-typed-input"
              />
            </label>
          ) : null}
        </div>

        <AlertDialogFooter>
          {/* Cancel is focused first on destructive dialogs (§14). */}
          <AlertDialogCancel ref={cancelRef} disabled={busy}>
            {cancelLabel}
          </AlertDialogCancel>
          <Button
            variant={destructive ? 'destructive' : 'default'}
            disabled={!confirmed || busy}
            onClick={async () => {
              setBusy(true)
              try {
                await onConfirm()
                onOpenChange(false)
              } finally {
                setBusy(false)
              }
            }}
            className={cn(!confirmed && 'opacity-50')}
            data-testid="confirm-action"
          >
            {confirmLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
