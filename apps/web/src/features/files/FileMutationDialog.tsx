/**
 * Governed regular-file path mutations.
 *
 * Create reviews the exact path and initial content before the adapter
 * prepares/previews/confirms the broker diff. Rename and delete bind the
 * confirmation to an exact revision obtained from a fresh broker read.
 * Directories are deliberately outside this surface.
 */
import { FilePlus2, Pencil, Trash2 } from 'lucide-react'
import { useRef, useState } from 'react'

import { ClientError, getClient } from '@/client'
import type { CreateFileResult, DeleteFileResult, RenameFileResult } from '@/client'
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
import { Input } from '@/components/ui/input'

export type FileMutationIntent =
  | { kind: 'create'; parentPath: string }
  | { kind: 'rename'; path: string; expectedRevision: string }
  | { kind: 'delete'; path: string; expectedRevision: string }

type FileMutationSuccess =
  | Extract<CreateFileResult, { ok: true }>
  | Extract<RenameFileResult, { ok: true }>
  | Extract<DeleteFileResult, { ok: true }>

export interface FileMutationDialogProps {
  instanceId: string
  intent: FileMutationIntent | null
  onOpenChange: (open: boolean) => void
  onCompleted: (intent: FileMutationIntent, result: FileMutationSuccess) => void | Promise<void>
}

export function FileMutationDialog(props: FileMutationDialogProps) {
  if (!props.intent) return null
  const identity =
    props.intent.kind === 'create'
      ? `create:${props.intent.parentPath}`
      : `${props.intent.kind}:${props.intent.path}:${props.intent.expectedRevision}`
  return <ActiveFileMutationDialog key={identity} {...props} intent={props.intent} />
}

function ActiveFileMutationDialog({
  instanceId,
  intent,
  onOpenChange,
  onCompleted,
}: Omit<FileMutationDialogProps, 'intent'> & { intent: FileMutationIntent }) {
  const defaultPath =
    intent.kind === 'create'
      ? `${intent.parentPath ? `${intent.parentPath}/` : ''}untitled.txt`
      : intent.kind === 'rename'
        ? intent.path
        : ''
  const [path, setPath] = useState(defaultPath)
  const [content, setContent] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const cancelRef = useRef<HTMLButtonElement | null>(null)
  const pathRef = useRef<HTMLInputElement | null>(null)

  const title =
    intent.kind === 'create'
      ? 'Review new file'
      : intent.kind === 'rename'
        ? 'Review file rename'
        : 'Delete this file?'
  const Icon = intent.kind === 'create' ? FilePlus2 : intent.kind === 'rename' ? Pencil : Trash2
  const target = intent.kind === 'delete' ? intent.path : path.trim()
  const validTarget =
    target.length > 0 &&
    !target.endsWith('/') &&
    !target.startsWith('/') &&
    !target.startsWith('~') &&
    !target.split('/').includes('..') &&
    (intent.kind !== 'rename' || target !== intent.path)

  const confirm = async () => {
    if (!validTarget || busy) return
    setBusy(true)
    setError(null)
    try {
      const result =
        intent.kind === 'create'
          ? await getClient().files.create(instanceId, target, { content })
          : intent.kind === 'rename'
            ? await getClient().files.rename(instanceId, intent.path, {
                destinationPath: target,
                expectedRevision: intent.expectedRevision,
              })
            : await getClient().files.delete(instanceId, intent.path, {
                expectedRevision: intent.expectedRevision,
              })
      if (!result.ok) {
        setError(result.detail)
        return
      }
      await onCompleted(intent, result)
      onOpenChange(false)
    } catch (caught) {
      setError(
        caught instanceof ClientError
          ? caught.message
          : caught instanceof Error
            ? caught.message
            : 'The file operation could not be completed.',
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        // The broker may already have committed while the response is being
        // validated. Keep the exact operation visible until it settles.
        if (!open && busy) return
        onOpenChange(open)
      }}
    >
      <DialogContent
        className="max-w-lg bg-surface"
        data-testid={`file-${intent.kind}-dialog`}
        onOpenAutoFocus={(event) => {
          event.preventDefault()
          if (intent.kind === 'delete') cancelRef.current?.focus()
          else pathRef.current?.focus()
        }}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-xl">
            <Icon
              className={intent.kind === 'delete' ? 'size-5 text-status-danger' : 'size-5 text-accent'}
              aria-hidden="true"
            />
            {title}
          </DialogTitle>
          <DialogDescription>
            {intent.kind === 'create'
              ? 'StatePort will prepare and review the exact new-file diff, then commit only that reviewed content.'
              : intent.kind === 'rename'
                ? 'The rename applies only if the source still matches the revision you just reviewed.'
                : 'The delete applies only if this regular file still matches the revision you just reviewed.'}
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          {intent.kind !== 'delete' ? (
            <label className="flex flex-col gap-1.5">
              <span className="text-xs font-medium text-foreground-secondary">
                {intent.kind === 'create' ? 'New relative path' : 'New relative path'}
              </span>
              <Input
                ref={pathRef}
                value={path}
                onChange={(event) => setPath(event.target.value)}
                className="font-mono"
                spellCheck={false}
                autoComplete="off"
                aria-invalid={!validTarget}
                data-testid={`file-${intent.kind}-path`}
              />
            </label>
          ) : null}

          {intent.kind === 'create' ? (
            <label className="flex flex-col gap-1.5">
              <span className="text-xs font-medium text-foreground-secondary">Initial content</span>
              <textarea
                value={content}
                onChange={(event) => setContent(event.target.value)}
                rows={6}
                className="min-h-28 resize-y rounded-sm border border-input bg-sunken px-2 py-2 font-mono text-xs text-foreground outline-none focus-visible:outline-2 focus-visible:outline-focus"
                spellCheck={false}
                data-testid="file-create-content"
              />
            </label>
          ) : null}

          <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-1 rounded-sm border border-border bg-sunken p-3 text-xs">
            {intent.kind !== 'create' ? (
              <>
                <dt className="text-foreground-secondary">Current path</dt>
                <dd className="truncate font-mono text-foreground">{intent.path}</dd>
              </>
            ) : null}
            {intent.kind !== 'delete' ? (
              <>
                <dt className="text-foreground-secondary">Resulting path</dt>
                <dd className="truncate font-mono text-foreground">{target || '—'}</dd>
              </>
            ) : null}
            <dt className="text-foreground-secondary">Scope</dt>
            <dd className="text-foreground">This application’s registered project only</dd>
            <dt className="text-foreground-secondary">Receipt</dt>
            <dd className="text-foreground">Recorded after the broker validates the exact mutation</dd>
            <dt className="text-foreground-secondary">Reversibility</dt>
            <dd className="text-foreground">
              {intent.kind === 'delete'
                ? 'No automatic restore is promised; use Git or a verified backup if available.'
                : 'A later governed file operation can change it again.'}
            </dd>
          </dl>

          {error ? (
            <div data-testid="file-mutation-error">
              <InlineNotice tone="blocked" title="The file operation was refused">
                {error} Refresh the tree, inspect the file again, and retry.
              </InlineNotice>
            </div>
          ) : null}
        </div>

        <DialogFooter>
          <Button ref={cancelRef} variant="outline" disabled={busy} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant={intent.kind === 'delete' ? 'destructive' : 'default'}
            disabled={!validTarget || busy}
            onClick={() => void confirm()}
            data-testid={`file-${intent.kind}-confirm`}
          >
            {busy
              ? 'Applying…'
              : intent.kind === 'create'
                ? 'Create reviewed file'
                : intent.kind === 'rename'
                  ? 'Rename reviewed file'
                  : 'Delete reviewed file'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
