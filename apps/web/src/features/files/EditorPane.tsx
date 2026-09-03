/**
 * EditorPane — one editor pane of the Files canvas (files.md): tab strip,
 * breadcrumbs, the per-document editor stack (every open document stays
 * mounted but hidden so undo history, scroll and selection survive tab
 * switches — state preservation is contractual), large-file fast view,
 * read-only banner, per-pane error/loading states, and the status strip.
 */
import { CircleAlert, Lock } from 'lucide-react'
import type { EditorView } from '@codemirror/view'
import { useState } from 'react'

import type { EditorSettings } from '@/client'
import { ErrorState, InlineNotice, Skeleton } from '@/components'
import { cn } from '@/lib/utils'
import { useWorkspaceStore } from '@/state'

import { Breadcrumbs } from './Breadcrumbs'
import { CodeEditor } from './CodeEditor'
import type { EditorCursor, EditorSelectionInfo } from './CodeEditor'
import { EditorTabs } from './EditorTabs'
import {
  MarkdownModeToggle,
  MarkdownPreview,
} from './MarkdownPreview'
import type { MarkdownEditorMode } from './MarkdownPreview'
import { isMarkdownPath } from './markdownPreviewModel'
import { StatusStrip } from './StatusStrip'
import { docIsDirty, useFilesStore } from './filesStore'

export interface EditorPaneProps {
  instanceId: string
  pane: 'primary' | 'secondary'
  paths: string[]
  active: string | null
  settings: EditorSettings
  wordWrap: boolean
  /** Mobile renders without the tab strip (single full-screen editor). */
  showTabs?: boolean
  cursor: EditorCursor | null
  selection: EditorSelectionInfo | null
  onFocusPane: () => void
  onSelect: (path: string) => void
  onClose: (path: string) => void
  onCloseOthers: (path: string) => void
  onReorder: (from: number, to: number) => void
  onReveal: (path: string) => void
  onCompare: (path: string) => void
  onMoveToOtherPane?: (path: string) => void
  onReviewSave: () => void
  onSendSelection: (path: string, selection: EditorSelectionInfo) => void
  onOpenReceipt: (receiptId: string) => void
  onCursor: (pane: 'primary' | 'secondary', path: string, cursor: EditorCursor) => void
  onSelection: (pane: 'primary' | 'secondary', selection: EditorSelectionInfo | null) => void
  registerView: (pane: 'primary' | 'secondary', path: string, view: EditorView | null) => void
}

export function EditorPane({
  instanceId,
  pane,
  paths,
  active,
  settings,
  wordWrap,
  showTabs = true,
  cursor,
  selection,
  onFocusPane,
  onSelect,
  onClose,
  onCloseOthers,
  onReorder,
  onReveal,
  onCompare,
  onMoveToOtherPane,
  onReviewSave,
  onSendSelection,
  onOpenReceipt,
  onCursor,
  onSelection,
  registerView,
}: EditorPaneProps) {
  const docs = useFilesStore((s) => s.docs[instanceId])
  const activeDoc = active ? docs?.[active] : undefined
  const dirty = activeDoc ? docIsDirty(activeDoc) : false
  const [markdownModes, setMarkdownModes] = useState<
    Record<string, MarkdownEditorMode>
  >({})

  const initialCursorFor = (path: string): EditorCursor | null =>
    settings.restoreCursorPositions
      ? (useWorkspaceStore.getState().cursorPositions[`${instanceId}:${path}`] ?? null)
      : null

  return (
    // Pointer down marks this pane as the tree-open target; keys go to children.
    <div
      className="flex h-full min-w-0 flex-col bg-sunken"
      data-testid={`editor-pane-${pane}`}
      onPointerDown={onFocusPane}
    >
      {showTabs ? (
        <EditorTabs
          instanceId={instanceId}
          pane={pane}
          paths={paths}
          active={active}
          onSelect={onSelect}
          onClose={onClose}
          onCloseOthers={onCloseOthers}
          onReorder={onReorder}
          onReveal={onReveal}
          onCompare={onCompare}
          onMoveToOtherPane={onMoveToOtherPane}
        />
      ) : null}
      {active ? <Breadcrumbs instanceId={instanceId} path={active} onReveal={onReveal} /> : null}

      <div className="relative min-h-0 flex-1">
        {paths.map((path) => {
          const doc = docs?.[path]
          const isActive = path === active
          const markdown = isMarkdownPath(path)
          const markdownMode = markdownModes[path] ?? 'edit'
          const previewing = markdown && markdownMode === 'preview'
          return (
            <div
              key={path}
              className={cn('absolute inset-0 flex flex-col', !isActive && 'invisible')}
              aria-hidden={!isActive}
              data-testid={`editor-host-${pane}-${path}`}
            >
              {!doc || doc.status === 'loading' ? (
                <div className="flex h-full gap-3 p-3" data-testid={`editor-loading-${path}`}>
                  <div className="flex w-10 flex-col gap-2">
                    {Array.from({ length: 12 }, (_, i) => (
                      <Skeleton key={i} className="h-4 w-6" />
                    ))}
                  </div>
                  <div className="flex flex-1 flex-col gap-2">
                    {Array.from({ length: 12 }, (_, i) => (
                      <Skeleton key={i} className="h-4" style={{ width: `${88 - (i % 5) * 14}%` }} />
                    ))}
                  </div>
                </div>
              ) : doc.status === 'error' ? (
                <ErrorState
                  title={`Couldn't load ${path.split('/').pop()}`}
                  error={doc.error}
                  preservedNote="The file tree and other open editors are unaffected."
                  onRetry={() => void useFilesStore.getState().reloadDocument(instanceId, path)}
                />
              ) : doc.large && !doc.loadAnyway ? (
                <div className="flex h-full flex-col" data-testid={`large-file-${path}`}>
                  <div className="p-2">
                    <InlineNotice
                      tone="informational"
                      title="Large file — read-only fast view"
                      action={
                        <button
                          type="button"
                          onClick={() => useFilesStore.getState().setLoadAnyway(instanceId, path)}
                          className="rounded-sm border border-border-strong px-2 py-0.5 text-xs font-medium text-foreground transition-colors duration-instant hover:bg-hover"
                        >
                          Load anyway
                        </button>
                      }
                    >
                      This file is larger than 512 KB, so the full editor stayed off to keep the workspace fast.
                    </InlineNotice>
                  </div>
                  <pre className="tnum min-h-0 flex-1 overflow-auto bg-sunken p-3 font-mono text-code text-foreground">
                    {doc.savedContent}
                  </pre>
                </div>
              ) : (
                <>
                  {doc.readOnly ? (
                    <div className="shrink-0 px-3 pt-2" data-testid={`readonly-banner-${path}`}>
                      <InlineNotice tone="blocked">
                        <span className="flex items-center gap-1">
                          <Lock className="size-3.5" aria-hidden="true" />
                          Read-only — this path is outside the writable scope or marked read-only. Selection and copy
                          still work.
                        </span>
                      </InlineNotice>
                    </div>
                  ) : null}
                  {markdown ? (
                    <MarkdownModeToggle
                      path={path}
                      mode={markdownMode}
                      onChange={(mode) =>
                        setMarkdownModes((current) => ({
                          ...current,
                          [path]: mode,
                        }))
                      }
                    />
                  ) : null}
                  <div className="relative min-h-0 flex-1">
                    <div
                      className={cn(
                        'absolute inset-0',
                        previewing && 'invisible pointer-events-none',
                      )}
                      aria-hidden={previewing}
                      inert={previewing ? true : undefined}
                      data-testid={`markdown-editor-layer-${pane}-${path}`}
                    >
                      <CodeEditor
                        path={path}
                        value={doc.draft}
                        readOnly={doc.readOnly}
                        ariaLabel={`Editor for ${path}${doc.readOnly ? ' (read-only)' : ''}`}
                        settings={settings}
                        wordWrap={wordWrap}
                        initialCursor={initialCursorFor(path)}
                        onChangeValue={(value) => useFilesStore.getState().setDraft(instanceId, path, value)}
                        onCursor={(c) => onCursor(pane, path, c)}
                        onSelectionChange={(sel) => {
                          if (isActive) onSelection(pane, sel)
                        }}
                        onRegisterView={(view) => registerView(pane, path, view)}
                      />
                    </div>
                    {markdown ? (
                      <div
                        className={cn(
                          'absolute inset-0',
                          !previewing && 'invisible pointer-events-none',
                        )}
                        aria-hidden={!previewing}
                        inert={!previewing ? true : undefined}
                      >
                        <MarkdownPreview path={path} content={doc.draft} />
                      </div>
                    ) : null}
                  </div>
                </>
              )}
            </div>
          )
        })}
        {paths.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-foreground-tertiary">
            <span className="flex items-center gap-1.5">
              <CircleAlert className="size-4" aria-hidden="true" />
              No file open in this pane — pick one from the tree.
            </span>
          </div>
        ) : null}
      </div>

      {active && activeDoc?.status === 'ready' ? (
        <StatusStrip
          path={active}
          cursor={cursor}
          selection={selection}
          dirty={dirty}
          readOnly={Boolean(activeDoc?.readOnly)}
          indentWith={settings.indentWith}
          tabSize={settings.tabSize}
          lastReceiptId={activeDoc?.lastReceiptId ?? null}
          onReviewSave={onReviewSave}
          onSendSelection={() => selection && active && onSendSelection(active, selection)}
          onOpenReceipt={onOpenReceipt}
        />
      ) : null}
    </div>
  )
}
