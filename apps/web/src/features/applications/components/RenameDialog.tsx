/**
 * RenameDialog — rename an installed instance. Names are the primary identity
 * everywhere (design.md §11), so this stays a quiet, single-field dialog.
 */
import { useEffect, useState } from 'react'

import { InlineNotice } from '@/components'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

export interface RenameDialogProps {
  open: boolean
  currentName: string
  onOpenChange: (open: boolean) => void
  onSubmit: (name: string) => void | Promise<void>
}

export function RenameDialog({ open, currentName, onOpenChange, onSubmit }: RenameDialogProps) {
  const [name, setName] = useState(currentName)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (open) {
      setName(currentName)
      setBusy(false)
      setError(null)
    }
  }, [open, currentName])

  const trimmed = name.trim()
  const valid = trimmed.length > 0 && trimmed !== currentName

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-surface" data-testid="rename-dialog">
        <DialogHeader>
          <DialogTitle>Rename application</DialogTitle>
          <DialogDescription>
            The instance name is its primary identity across StatePort. Renaming changes nothing else.
          </DialogDescription>
        </DialogHeader>
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            if (!valid || busy) return
            setBusy(true)
            setError(null)
            try {
              await onSubmit(trimmed)
              onOpenChange(false)
            } catch (cause) {
              setError(cause instanceof Error ? cause.message : 'Rename could not be confirmed. Refresh the application before retrying.')
            } finally {
              setBusy(false)
            }
          }}
        >
          <label className="flex flex-col gap-1.5">
            <span className="text-xs font-medium text-foreground-secondary">Instance name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="h-control rounded-sm border border-input bg-surface px-2 text-sm text-foreground"
              maxLength={120}
              disabled={busy}
              autoComplete="off"
              spellCheck={false}
              data-testid="rename-input"
            />
          </label>
          {error ? <InlineNotice tone="danger" title="Rename could not be confirmed">{error}</InlineNotice> : null}
          <DialogFooter className="mt-4">
            <Button type="button" variant="ghost" size="sm" onClick={() => onOpenChange(false)} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={!valid || busy}>
              Rename
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
