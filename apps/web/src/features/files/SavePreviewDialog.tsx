/**
 * SavePreviewDialog — THE governed write flow (files.md §The governed save
 * flow; brief "File-write workflow"). Ctrl/Cmd+S or "Review & save" opens
 * this preview; nothing ever writes silently.
 *
 *   review exact diff → affected paths → warnings → Confirm → typed write
 *   (expectedRevision) → validated write → receipt link | honest conflict /
 *   path-policy / read-only / write-failure outcomes.
 *
 * Discard goes through ConfirmDialog. Editor content is never lost on
 * failure; conflicts offer Reload / Save anyway / Copy-then-reload.
 */
import { FileDiff, Save, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import type { EditorSettings, Receipt } from '@/client'
import { getClient, unifiedDiff } from '@/client'
import { ConfirmDialog, InlineNotice, Spinner } from '@/components'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import { copyText } from '@/components'
import { useIsMobile } from '@/shell/platform'

import { DiffView } from './DiffView'
import type { DiffMode } from './DiffView'
import { FileGlyph } from './fileIcons'
import { docIsDirty, useFilesStore } from './filesStore'
import type { FileDoc } from './filesStore'

export interface SavePreviewDialogProps {
  instanceId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Scope the preview to specific paths; null/undefined = all dirty files. */
  paths?: string[] | null
  /** Provenance note (e.g. a patch draft from Conversation). */
  originNote?: string | null
  settings: EditorSettings
  onSaved?: (path: string, receipt: Receipt) => void
  onAnnounce?: (message: string) => void
}

interface FileFailure {
  reason: 'path_policy' | 'read_only' | 'validation' | 'transport'
  detail: string
}

function ModeToggle({ mode, onChange }: { mode: DiffMode; onChange: (mode: DiffMode) => void }) {
  return (
    <div role="group" aria-label="Diff layout" className="flex items-center rounded-sm border border-border">
      {(['unified', 'split'] as const).map((option) => (
        <button
          key={option}
          type="button"
          aria-pressed={mode === option}
          onClick={() => onChange(option)}
          className={cn(
            'h-6 px-2 text-xs font-medium capitalize transition-colors duration-instant',
            mode === option ? 'bg-active text-foreground' : 'text-foreground-secondary hover:text-foreground',
          )}
          data-testid={`diff-mode-${option}`}
        >
          {option === 'unified' ? 'Unified' : 'Side by side'}
        </button>
      ))}
    </div>
  )
}

export function SavePreviewDialog({
  instanceId,
  open,
  onOpenChange,
  paths,
  originNote,
  settings,
  onSaved,
  onAnnounce,
}: SavePreviewDialogProps) {
  const navigate = useNavigate()
  const docs = useFilesStore((s) => s.docs[instanceId])
  const [mode, setMode] = useState<DiffMode>('unified')
  const [saving, setSaving] = useState(false)
  const [failures, setFailures] = useState<Record<string, FileFailure>>({})
  const [discardOpen, setDiscardOpen] = useState(false)
  const isMobile = useIsMobile()

  const dirtyDocs = useMemo(() => {
    if (!docs) return []
    const all = Object.values(docs).filter(docIsDirty)
    return paths && paths.length > 0 ? all.filter((d) => paths.includes(d.path)) : all
  }, [docs, paths])

  const writable = dirtyDocs.filter((d) => !d.readOnly)
  const blocked = dirtyDocs.filter((d) => d.readOnly)

  const stats = useMemo(
    () =>
      dirtyDocs.map((doc) => ({
        path: doc.path,
        diff: unifiedDiff(doc.path, doc.savedContent, doc.draft),
      })),
    [dirtyDocs],
  )
  const totals = useMemo(
    () => stats.reduce((acc, s) => ({ added: acc.added + s.diff.addedLines, removed: acc.removed + s.diff.removedLines }), { added: 0, removed: 0 }),
    [stats],
  )

  const close = () => onOpenChange(false)

  const saveOne = async (doc: FileDoc): Promise<boolean> => {
    const store = useFilesStore.getState()
    try {
      const result = await getClient().files.write(instanceId, doc.path, {
        content: doc.draft,
        expectedRevision: doc.revision,
      })
      if (result.ok) {
        store.applyEntry(instanceId, doc.path, result.entry, result.receipt.id)
        onSaved?.(doc.path, result.receipt)
        onAnnounce?.(`File change saved for ${doc.path}. Receipt created.`)
        setFailures((f) => {
          const next = { ...f }
          delete next[doc.path]
          return next
        })
        return true
      }
      if (result.reason === 'conflict') {
        store.setConflict(instanceId, doc.path, {
          detail: result.detail,
          currentRevision: result.currentRevision ?? doc.revision,
          currentContent: result.currentContent ?? doc.savedContent,
        })
        onAnnounce?.(`Save did not complete for ${doc.path}: ${result.detail}`)
        return false
      }
      const failure: FileFailure = { reason: result.reason, detail: result.detail }
      setFailures((f) => ({ ...f, [doc.path]: failure }))
      onAnnounce?.(`Save did not complete for ${doc.path}: ${result.detail}`)
      return false
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      setFailures((f) => ({ ...f, [doc.path]: { reason: 'transport', detail } }))
      onAnnounce?.(`Write failed for ${doc.path}. Your editor content is preserved.`)
      return false
    }
  }

  const saveAll = async () => {
    setSaving(true)
    let allOk = true
    // Sequential: receipts arrive in path order and one failure never hides another.
    for (const doc of writable) {
      if (!docIsDirty(useFilesStore.getState().docs[instanceId]?.[doc.path] ?? doc)) continue
      const ok = await saveOne(useFilesStore.getState().docs[instanceId]![doc.path]!)
      if (!ok) allOk = false
    }
    setSaving(false)
    if (allOk) close()
  }

  const saveAnyway = async (doc: FileDoc) => {
    const conflict = doc.conflict
    if (!conflict) return
    setSaving(true)
    const store = useFilesStore.getState()
    try {
      const result = await getClient().files.write(instanceId, doc.path, {
        content: doc.draft,
        expectedRevision: conflict.currentRevision,
      })
      if (result.ok) {
        store.applyEntry(instanceId, doc.path, result.entry, result.receipt.id)
        onSaved?.(doc.path, result.receipt)
        onAnnounce?.(`Your version of ${doc.path} was saved over the disk version. Receipt created.`)
      } else if (result.reason === 'conflict') {
        store.setConflict(instanceId, doc.path, {
          detail: result.detail,
          currentRevision: result.currentRevision ?? conflict.currentRevision,
          currentContent: result.currentContent ?? conflict.currentContent,
        })
      } else {
        const failure: FileFailure = { reason: result.reason, detail: result.detail }
        setFailures((f) => ({ ...f, [doc.path]: failure }))
        store.setConflict(instanceId, doc.path, null)
      }
    } catch (error) {
      setFailures((f) => ({
        ...f,
        [doc.path]: { reason: 'transport', detail: error instanceof Error ? error.message : String(error) },
      }))
      store.setConflict(instanceId, doc.path, null)
    } finally {
      setSaving(false)
    }
  }

  const reloadDisk = (doc: FileDoc) => {
    void useFilesStore.getState().reloadDocument(instanceId, doc.path)
    onAnnounce?.(`Reloaded ${doc.path} from disk. Your edited version was discarded.`)
  }

  const copyThenReload = (doc: FileDoc) => {
    void copyText(doc.draft)
    void useFilesStore.getState().reloadDocument(instanceId, doc.path)
    onAnnounce?.(`Copied your version of ${doc.path}, then reloaded the disk version.`)
  }

  const discardAll = () => {
    const store = useFilesStore.getState()
    for (const doc of dirtyDocs) store.discardDraft(instanceId, doc.path)
    onAnnounce?.(`Discarded unsaved changes in ${dirtyDocs.length} file${dirtyDocs.length === 1 ? '' : 's'}.`)
    setFailures({})
    close()
  }

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent
          className={cn(
            'flex flex-col gap-0 overflow-hidden border-border bg-surface p-0 shadow-2',
            isMobile
              ? 'inset-0 top-0 left-0 h-[100dvh] w-full max-w-none translate-x-0 translate-y-0 rounded-none'
              : 'top-[8vh] max-h-[84vh] w-[min(720px,94vw)] translate-y-0 rounded-lg sm:max-w-[min(720px,94vw)]',
          )}
          data-testid="save-preview"
        >
          <DialogHeader className="shrink-0 border-b border-border px-4 py-3">
            <div className="flex items-center justify-between gap-2 pr-6">
              <DialogTitle className="flex items-center gap-2 text-xl">
                <FileDiff className="size-5 text-foreground-secondary" aria-hidden="true" />
                Review changes — {dirtyDocs.length} file{dirtyDocs.length === 1 ? '' : 's'}
              </DialogTitle>
              <ModeToggle mode={mode} onChange={setMode} />
            </div>
            <DialogDescription className="sr-only">
              Review the exact affected paths and diff before confirming this governed file write.
            </DialogDescription>
          </DialogHeader>

          <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
            {originNote ? (
              <div className="mb-3">
                <InlineNotice tone="informational" title="Proposed change">
                  {originNote} It is staged as an unsaved edit — review the diff before saving.
                </InlineNotice>
              </div>
            ) : null}

            {dirtyDocs.length === 0 ? (
              <p className="py-8 text-center text-sm text-foreground-secondary" data-testid="preview-clean">
                No unsaved changes. Nothing will be written.
              </p>
            ) : null}

            {blocked.length > 0 ? (
              <div className="mb-3">
                <InlineNotice tone="blocked" title="Read-only files are excluded from this save">
                  {blocked.map((d) => d.path).join(', ')} — read-only paths can be reviewed but never written.
                </InlineNotice>
              </div>
            ) : null}

            {dirtyDocs.map((doc) => {
              const failure = failures[doc.path]
              const diff = unifiedDiff(doc.path, doc.savedContent, doc.draft)
              return (
                <section key={doc.path} className="mb-4 rounded-md border border-border" data-testid={`preview-file-${doc.path}`}>
                  <header className="flex h-8 items-center gap-2 border-b border-border bg-surface-2 px-3">
                    <FileGlyph path={doc.path} kind="file" className="size-4 shrink-0 text-foreground-secondary" />
                    <span className="tnum min-w-0 flex-1 truncate font-mono text-xs text-foreground">{doc.path}</span>
                    <span className="tnum shrink-0 font-mono text-xs">
                      <span className="text-status-success">+{diff.addedLines}</span>{' '}
                      <span className="text-status-danger">−{diff.removedLines}</span>
                    </span>
                  </header>

                  {doc.conflict ? (
                    <div className="flex flex-col gap-2 p-3" data-testid={`conflict-${doc.path}`}>
                      <InlineNotice tone="attention" title="This file changed on disk since you opened it">
                        {doc.conflict.detail}
                      </InlineNotice>
                      <p className="text-xs text-foreground-secondary">
                        The diff below compares the current disk version (left/before) with your edited version
                        (right/after). Choose how to proceed — nothing is overwritten silently.
                      </p>
                      <div className="h-56 overflow-hidden rounded-sm border border-border">
                        <DiffView
                          path={doc.path}
                          original={doc.conflict.currentContent}
                          modified={doc.draft}
                          mode={mode}
                          settings={settings}
                          ariaLabel={`Conflict diff for ${doc.path}`}
                        />
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <Button size="sm" onClick={() => void saveAnyway(doc)} disabled={saving} data-testid={`conflict-save-anyway-${doc.path}`}>
                          Save my version anyway
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => reloadDisk(doc)} disabled={saving}>
                          Reload disk version
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => copyThenReload(doc)} disabled={saving}>
                          Copy my version, then reload
                        </Button>
                      </div>
                      <p className="text-xs text-foreground-tertiary">
                        “Save my version anyway” overwrites the disk version (revision{' '}
                        <span className="tnum font-mono">{doc.conflict.currentRevision}</span>) with your editor content.
                      </p>
                    </div>
                  ) : failure?.reason === 'path_policy' ? (
                    <div className="p-3" data-testid={`path-policy-${doc.path}`}>
                      <InlineNotice tone="blocked" title="Outside the permitted folder">
                        {failure.detail} Writes are limited to this application&apos;s permitted project root.
                      </InlineNotice>
                      <div className="mt-2">
                        <Button size="sm" variant="outline" onClick={() => { close(); void navigate(`/app/${instanceId}/settings`) }}>
                          Review permissions
                        </Button>
                      </div>
                    </div>
                  ) : failure?.reason === 'read_only' ? (
                    <div className="p-3" data-testid={`read-only-${doc.path}`}>
                      <InlineNotice tone="blocked" title="Read-only file">
                        {failure.detail} This path is marked read-only; it can be reviewed but never written.
                      </InlineNotice>
                    </div>
                  ) : (
                    <>
                      {failure ? (
                        <div className="p-3 pb-0" data-testid={`write-failed-${doc.path}`}>
                          <InlineNotice
                            tone="danger"
                            title="Write failed — nothing was saved"
                            action={
                              <Button size="sm" variant="outline" onClick={() => void saveOne(doc)} disabled={saving}>
                                Retry
                              </Button>
                            }
                          >
                            {failure.detail} Your editor content is preserved.
                          </InlineNotice>
                        </div>
                      ) : null}
                      <div className="h-64 overflow-hidden">
                        <DiffView
                          path={doc.path}
                          original={doc.savedContent}
                          modified={doc.draft}
                          mode={mode}
                          settings={settings}
                          ariaLabel={`Diff of ${doc.path}`}
                        />
                      </div>
                    </>
                  )}
                </section>
              )
            })}
          </div>

          {dirtyDocs.length > 0 ? (
            <div className="shrink-0 border-t border-border px-4 py-2">
              <p className="tnum font-mono text-xs text-foreground-secondary" data-testid="affected-paths">
                Affected paths: {dirtyDocs.length} file{dirtyDocs.length === 1 ? '' : 's'} ·{' '}
                <span className="text-status-success">+{totals.added}</span>{' '}
                <span className="text-status-danger">−{totals.removed}</span> ·{' '}
                {dirtyDocs.map((d) => d.path).join('  ')}
              </p>
            </div>
          ) : null}

          <DialogFooter className="shrink-0 border-t border-border px-4 py-3 sm:justify-between">
            <Button
              variant="ghost"
              onClick={() => setDiscardOpen(true)}
              disabled={saving || dirtyDocs.length === 0}
              className="text-status-danger hover:text-status-danger"
              data-testid="discard-changes"
            >
              <Trash2 aria-hidden="true" />
              Discard changes
            </Button>
            <Button
              onClick={() => void saveAll()}
              disabled={saving || writable.length === 0}
              data-testid="confirm-save"
            >
              {saving ? <Spinner className="size-4" aria-hidden="true" /> : <Save aria-hidden="true" />}
              {saving ? 'Saving…' : `Save changes${writable.length > 1 ? ` (${writable.length})` : ''}`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={discardOpen}
        onOpenChange={setDiscardOpen}
        title="Discard unsaved changes?"
        description="The listed files return to their last saved content."
        target={dirtyDocs.map((d) => d.path).join(', ')}
        effect={`Discard edits in ${dirtyDocs.length} file${dirtyDocs.length === 1 ? '' : 's'}`}
        reversibility="This cannot be undone — only the last saved version is restored."
        confirmLabel="Discard changes"
        destructive
        onConfirm={discardAll}
      />
    </>
  )
}
