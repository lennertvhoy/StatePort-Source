/**
 * EditorTabs (files.md §Canvas, design.md §14) — the in-canvas tab strip:
 * file icon + name, dirty CircleDot, read-only lock, close X (dirty close is
 * confirmed by the caller), middle-click close, drag to reorder, context
 * menu (Close others · Copy relative path · Reveal in tree · Compare with
 * saved · Move to other pane), overflow via the strip-end list.
 */
import { ChevronDown, CircleDot, Copy, FileDiff, FolderTree, Lock, X } from 'lucide-react'
import { useRef } from 'react'

import { Tooltip, copyText } from '@/components'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'
import { useFilesStore } from './filesStore'
import { FileGlyph } from './fileIcons'

export interface EditorTabsProps {
  instanceId: string
  pane: 'primary' | 'secondary'
  paths: string[]
  active: string | null
  onSelect: (path: string) => void
  onClose: (path: string) => void
  onCloseOthers: (path: string) => void
  onReorder: (from: number, to: number) => void
  onReveal: (path: string) => void
  onCompare?: (path: string) => void
  onMoveToOtherPane?: (path: string) => void
}

function fileName(path: string): string {
  return path.split('/').pop() ?? path
}

export function EditorTabs({
  instanceId,
  pane,
  paths,
  active,
  onSelect,
  onClose,
  onCloseOthers,
  onReorder,
  onReveal,
  onCompare,
  onMoveToOtherPane,
}: EditorTabsProps) {
  const docs = useFilesStore((s) => s.docs[instanceId])
  const dragIndex = useRef<number | null>(null)

  if (paths.length === 0) return null

  return (
    <div className="flex h-[30px] shrink-0 items-stretch border-b border-border bg-surface" data-testid={`editor-tabs-${pane}`}>
      <div role="tablist" aria-label={pane === 'primary' ? 'Open files' : 'Open files (second pane)'} className="flex min-w-0 flex-1 items-stretch overflow-x-auto">
        {paths.map((path, index) => {
          const doc = docs?.[path]
          const dirty = doc ? doc.draft !== doc.savedContent && doc.status === 'ready' : false
          const readOnly = Boolean(doc?.readOnly)
          const isActive = path === active
          const name = fileName(path)
          return (
            <ContextMenu key={path}>
              <ContextMenuTrigger asChild>
                <div
                  role="tab"
                  aria-selected={isActive}
                  tabIndex={0}
                  draggable
                  data-testid={`editor-tab-${pane}-${path}`}
                  title={path}
                  className={cn(
                    'group relative flex h-full min-w-0 max-w-44 cursor-default items-center gap-1.5 border-r border-border px-2.5 text-sm outline-none transition-colors duration-instant',
                    isActive
                      ? 'bg-app text-foreground after:absolute after:inset-x-0 after:bottom-0 after:h-0.5 after:bg-accent'
                      : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
                    'focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-focus',
                  )}
                  onClick={() => onSelect(path)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      onSelect(path)
                    }
                  }}
                  onMouseDown={(e) => {
                    if (e.button === 1) {
                      e.preventDefault()
                      onClose(path)
                    }
                  }}
                  onDragStart={(e) => {
                    dragIndex.current = index
                    e.dataTransfer.effectAllowed = 'move'
                    e.dataTransfer.setData('text/plain', path)
                  }}
                  onDragOver={(e) => {
                    e.preventDefault()
                    e.dataTransfer.dropEffect = 'move'
                  }}
                  onDrop={(e) => {
                    e.preventDefault()
                    const from = dragIndex.current
                    if (from !== null && from !== index) onReorder(from, index)
                    dragIndex.current = null
                  }}
                >
                  <FileGlyph path={path} kind="file" className="size-3.5 shrink-0 text-foreground-secondary" />
                  <span className="min-w-0 truncate">{name}</span>
                  {dirty ? (
                    <Tooltip content="Unsaved changes — not yet saved">
                      <CircleDot className="size-3 shrink-0 text-accent" aria-label="Unsaved changes" />
                    </Tooltip>
                  ) : null}
                  {readOnly ? (
                    <Tooltip content="Read-only">
                      <Lock className="size-3 shrink-0 text-foreground-tertiary" aria-label="Read-only" />
                    </Tooltip>
                  ) : null}
                  <button
                    type="button"
                    aria-label={`Close ${name}`}
                    tabIndex={-1}
                    className={cn(
                      'inline-flex min-h-5 min-w-5 shrink-0 items-center justify-center rounded-sm text-foreground-tertiary transition-colors duration-instant hover:bg-active hover:text-foreground',
                      dirty && 'group-hover:opacity-100',
                    )}
                    onClick={(e) => {
                      e.stopPropagation()
                      onClose(path)
                    }}
                  >
                    <X className="size-3.5" aria-hidden="true" />
                  </button>
                </div>
              </ContextMenuTrigger>
              <ContextMenuContent className="w-56 bg-surface">
                <ContextMenuItem onSelect={() => onClose(path)}>
                  <X className="size-4" aria-hidden="true" />
                  Close
                </ContextMenuItem>
                <ContextMenuItem onSelect={() => onCloseOthers(path)} disabled={paths.length <= 1}>
                  <X className="size-4" aria-hidden="true" />
                  Close others
                </ContextMenuItem>
                <ContextMenuSeparator />
                <ContextMenuItem onSelect={() => void copyText(path)}>
                  <Copy className="size-4" aria-hidden="true" />
                  Copy relative path
                </ContextMenuItem>
                <ContextMenuItem onSelect={() => onReveal(path)}>
                  <FolderTree className="size-4" aria-hidden="true" />
                  Reveal in project tree
                </ContextMenuItem>
                {onCompare && dirty ? (
                  <ContextMenuItem onSelect={() => onCompare(path)}>
                    <FileDiff className="size-4" aria-hidden="true" />
                    Compare with saved
                  </ContextMenuItem>
                ) : null}
                {onMoveToOtherPane ? (
                  <>
                    <ContextMenuSeparator />
                    <ContextMenuItem onSelect={() => onMoveToOtherPane(path)}>
                      <FolderTree className="size-4" aria-hidden="true" />
                      Move to other pane
                    </ContextMenuItem>
                  </>
                ) : null}
              </ContextMenuContent>
            </ContextMenu>
          )
        })}
      </div>
      {paths.length > 2 ? (
        <DropdownMenu>
          <DropdownMenuTrigger
            aria-label="List open files"
            className="inline-flex min-w-7 items-center justify-center text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          >
            <ChevronDown className="size-3.5" aria-hidden="true" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-64 bg-surface">
            {paths.map((path) => (
              <DropdownMenuItem key={path} onSelect={() => onSelect(path)}>
                <FileGlyph path={path} kind="file" className="size-4" aria-hidden="true" />
                <span className="tnum min-w-0 flex-1 truncate font-mono text-xs">{path}</span>
                {docs?.[path] && docs[path].draft !== docs[path].savedContent && docs[path].status === 'ready' ? (
                  <CircleDot className="size-3 text-accent" aria-hidden="true" />
                ) : null}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : null}
    </div>
  )
}
