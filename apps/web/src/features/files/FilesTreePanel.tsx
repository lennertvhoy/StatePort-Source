/**
 * FilesTreePanel — the Files tool nav panel (files.md §Layout): project tree
 * with curated file icons, expand/collapse, active-file highlight, dirty
 * dots, read-only locks, git/state letters, full keyboard navigation
 * (arrows, Home/End, Enter, type-ahead) and a per-row context menu
 * (Open · Open to the side · Copy relative path · Reveal · Send to
 * Conversation · Open in Terminal).
 *
 * Registered with the workbench frame via `useRegisterToolPanel('files', …)`
 * and reused as the mobile file-picker content.
 */
import {
  ChevronsDownUp,
  CircleDot,
  Copy,
  ExternalLink,
  FilePlus2,
  FileSearch,
  FolderTree,
  Lock,
  MessageSquare,
  Pencil,
  RefreshCw,
  SquareTerminal,
  Trash2,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import type { FileNode } from '@/client'
import { ClientError, getClient } from '@/client'
import { EmptyState, ErrorState, SkeletonRows, Tooltip, copyText } from '@/components'
import { sendToBridge } from '@/features/bridge/bridgeStore'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu'
import { cn } from '@/lib/utils'
import type { WorkbenchSlotProps } from '@/shell/workbench/WorkbenchSlots'
import { useWorkspaceStore } from '@/state'
import { useSessionStore } from '@/state'

import { FileGlyph } from './fileIcons'
import { FileMutationDialog } from './FileMutationDialog'
import type { FileMutationIntent } from './FileMutationDialog'
import { dirtyPathsOf, useFilesStore } from './filesStore'

export interface FilesTreePanelProps extends WorkbenchSlotProps {
  /** Called after a file is opened from the tree (e.g. close mobile sheet). */
  onFileOpen?: (path: string) => void
  /** Embedded in a sheet: stretch rows for touch targets. */
  touch?: boolean
}

interface FlatRow {
  node: FileNode
  depth: number
  expandable: boolean
  expanded: boolean
}

function flatten(nodes: FileNode[], expanded: Record<string, boolean>): FlatRow[] {
  const rows: FlatRow[] = []
  const walk = (list: FileNode[], depth: number) => {
    for (const node of list) {
      const expandable = node.kind === 'directory' && (node.children?.length ?? 0) > 0
      const isExpanded = expandable && Boolean(expanded[node.path])
      rows.push({ node, depth, expandable, expanded: isExpanded })
      if (isExpanded && node.children) walk(node.children, depth + 1)
    }
  }
  walk(nodes, 0)
  return rows
}

const TYPEAHEAD_RESET_MS = 600

export function FilesTreePanel({ instanceId, onFileOpen, touch }: FilesTreePanelProps) {
  const navigate = useNavigate()
  const tree = useFilesStore((s) => s.trees[instanceId])
  const docs = useFilesStore((s) => s.docs[instanceId])
  const expandedRaw = useFilesStore((s) => s.expanded[instanceId])
  const revealPath = useFilesStore((s) => s.revealPath)
  const activeFile = useWorkspaceStore((s) => s.activeFile[instanceId] ?? null)
  const secondary = useFilesStore((s) => s.secondary[instanceId])
  const openInPane = useFilesStore((s) => s.openInPane[instanceId] ?? 'primary')

  const dirtySet = useMemo(() => new Set(dirtyPathsOf(docs)), [docs])
  const rows = useMemo(() => flatten(tree?.nodes ?? [], expandedRaw ?? {}), [tree?.nodes, expandedRaw])

  const [focusIndex, setFocusIndex] = useState(0)
  const [mutationIntent, setMutationIntent] = useState<FileMutationIntent | null>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const rowRefs = useRef(new Map<string, HTMLDivElement>())
  const typeahead = useRef({ buffer: '', at: 0 })

  const loadTree = useFilesStore((s) => s.loadTree)
  useEffect(() => {
    void loadTree(instanceId)
  }, [instanceId, loadTree])

  const openFile = useCallback(
    (path: string, pane?: 'primary' | 'secondary') => {
      const target = pane ?? openInPane
      void useFilesStore.getState().openDocument(instanceId, path)
      if (target === 'secondary' && useFilesStore.getState().secondary[instanceId]) {
        useFilesStore.getState().openSecondaryFile(instanceId, path)
      } else {
        useWorkspaceStore.getState().openFile(instanceId, path)
      }
      onFileOpen?.(path)
    },
    [instanceId, onFileOpen, openInPane],
  )

  const activateRow = useCallback(
    (row: FlatRow) => {
      if (row.node.kind === 'directory') {
        useFilesStore.getState().toggleDir(instanceId, row.node.path)
      } else {
        openFile(row.node.path)
      }
    },
    [instanceId, openFile],
  )

  // One-shot reveal: the store already expanded ancestors. Adjust focus state
  // during render (derived from the reveal request), then let the effect do
  // the DOM focus/scroll and consume the request.
  const [handledReveal, setHandledReveal] = useState<typeof revealPath>(null)
  if (revealPath && revealPath !== handledReveal && revealPath.instanceId === instanceId) {
    setHandledReveal(revealPath)
    const index = rows.findIndex((r) => r.node.path === revealPath.path)
    if (index >= 0) setFocusIndex(index)
  }
  useEffect(() => {
    if (!revealPath || revealPath.instanceId !== instanceId) return
    const el = rowRefs.current.get(revealPath.path)
    el?.focus()
    el?.scrollIntoView({ block: 'nearest' })
    useFilesStore.getState().clearReveal()
  }, [revealPath, instanceId, rows])

  const moveFocus = useCallback(
    (next: number) => {
      const clamped = Math.max(0, Math.min(rows.length - 1, next))
      setFocusIndex(clamped)
      const row = rows[clamped]
      if (row) {
        rowRefs.current.get(row.node.path)?.focus()
        rowRefs.current.get(row.node.path)?.scrollIntoView({ block: 'nearest' })
      }
    },
    [rows],
  )

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (rows.length === 0) return
    const row = rows[Math.min(focusIndex, rows.length - 1)]
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        moveFocus(focusIndex + 1)
        return
      case 'ArrowUp':
        e.preventDefault()
        moveFocus(focusIndex - 1)
        return
      case 'Home':
        e.preventDefault()
        moveFocus(0)
        return
      case 'End':
        e.preventDefault()
        moveFocus(rows.length - 1)
        return
      case 'ArrowRight': {
        e.preventDefault()
        if (row.expandable && !row.expanded) useFilesStore.getState().setDirExpanded(instanceId, row.node.path, true)
        else if (row.expandable) moveFocus(focusIndex + 1)
        return
      }
      case 'ArrowLeft': {
        e.preventDefault()
        if (row.expandable && row.expanded) {
          useFilesStore.getState().setDirExpanded(instanceId, row.node.path, false)
        } else if (row.depth > 0) {
          const parent = row.node.path.split('/').slice(0, -1).join('/')
          const parentIndex = rows.findIndex((r) => r.node.path === parent)
          if (parentIndex >= 0) moveFocus(parentIndex)
        }
        return
      }
      case 'Enter':
      case ' ':
        e.preventDefault()
        activateRow(row)
        return
      default:
        break
    }
    // Type-ahead: jump to the next visible row matching the buffer.
    if (e.key.length === 1 && !e.metaKey && !e.ctrlKey && !e.altKey) {
      const now = Date.now()
      if (now - typeahead.current.at > TYPEAHEAD_RESET_MS) typeahead.current.buffer = ''
      typeahead.current.buffer += e.key.toLowerCase()
      typeahead.current.at = now
      const query = typeahead.current.buffer
      const start = focusIndex + 1
      const ordered = [...rows.slice(start), ...rows.slice(0, start)]
      const match = ordered.find((r) => r.node.name.toLowerCase().startsWith(query))
      if (match) moveFocus(rows.indexOf(match))
    }
  }

  const copyPath = (path: string) => void copyText(path)

  const sendFileToConversation = (path: string) => {
    sendToBridge({ kind: 'file', instanceId, path })
    void navigate(`/app/${instanceId}/conversation`)
  }

  const openInTerminal = (path: string) => {
    const dir = path.includes('/') ? path.split('/').slice(0, -1).join('/') : '.'
    sendToBridge({ kind: 'command-draft', instanceId, command: `cd ${dir}` })
    void navigate(`/app/${instanceId}/workbench/terminal`)
  }

  const beginPathMutation = async (kind: 'rename' | 'delete', node: FileNode) => {
    if (dirtySet.has(node.path)) {
      useSessionStore.getState().pushToast({
        kind: 'error',
        title: `${kind === 'rename' ? 'Rename' : 'Delete'} not started`,
        body: `${node.path} has unsaved changes. Review and save or discard them first.`,
      })
      return
    }
    try {
      const entry = await getClient().files.read(instanceId, node.path)
      if (entry.readOnly) {
        useSessionStore.getState().pushToast({
          kind: 'error',
          title: `${kind === 'rename' ? 'Rename' : 'Delete'} not available`,
          body: `${node.path} is read-only under this application's file policy.`,
        })
        return
      }
      setMutationIntent({ kind, path: node.path, expectedRevision: entry.revision })
    } catch (error) {
      useSessionStore.getState().pushToast({
        kind: 'error',
        title: `${kind === 'rename' ? 'Rename' : 'Delete'} not started`,
        body: error instanceof ClientError ? error.message : 'The file could not be inspected.',
      })
    }
  }

  const mutationCompleted = async (
    intent: FileMutationIntent,
    result: Parameters<NonNullable<React.ComponentProps<typeof FileMutationDialog>['onCompleted']>>[1],
  ) => {
    if ('destinationPath' in result) {
      useFilesStore.getState().closeDocument(instanceId, result.sourcePath)
      useWorkspaceStore.getState().closeFile(instanceId, result.sourcePath)
      useFilesStore.getState().applyEntry(instanceId, result.destinationPath, result.entry, result.receipt.id)
      useWorkspaceStore.getState().openFile(instanceId, result.destinationPath)
      void useFilesStore.getState().loadTree(instanceId, { force: true })
    } else if (!('entry' in result)) {
      useFilesStore.getState().closeDocument(instanceId, result.path)
      useWorkspaceStore.getState().closeFile(instanceId, result.path)
      void useFilesStore.getState().loadTree(instanceId, { force: true })
    } else {
      useFilesStore.getState().applyEntry(instanceId, result.path, result.entry, result.receipt.id)
      useWorkspaceStore.getState().openFile(instanceId, result.path)
      void useFilesStore.getState().loadTree(instanceId, { force: true })
    }
    const title =
      intent.kind === 'create' ? 'File created' : intent.kind === 'rename' ? 'File renamed' : 'File deleted'
    const resultPath = 'destinationPath' in result ? result.destinationPath : result.path
    useSessionStore.getState().pushToast({
      kind: 'success',
      title,
      body: `${resultPath} · View receipt`,
      route: `/app/${instanceId}/workbench/receipts/${result.receipt.id}`,
    })
  }

  // ── States ─────────────────────────────────────────────────────────────────
  if (!tree || tree.loading) {
    return (
      <div className="p-1" data-testid="files-tree-loading">
        <SkeletonRows rows={8} />
      </div>
    )
  }
  if (tree.error) {
    return (
      <ErrorState
        title="Couldn't load the file tree"
        error={tree.error}
        preservedNote="Open editors are unaffected."
        onRetry={() => void loadTree(instanceId, { force: true })}
      />
    )
  }
  const nodes = tree.nodes ?? []
  if (nodes.length === 0) {
    return (
      <div className="flex h-full flex-col" data-testid="files-tree-panel">
        <div className="flex h-7 shrink-0 items-center justify-end border-b border-border px-2">
          <Tooltip content="Create regular file">
            <button
              type="button"
              aria-label="Create regular file"
              data-testid="file-create-root"
              onClick={() => setMutationIntent({ kind: 'create', parentPath: '' })}
              className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-secondary hover:bg-hover hover:text-foreground"
            >
              <FilePlus2 className="size-3.5" aria-hidden="true" />
            </button>
          </Tooltip>
        </div>
        <EmptyState
          icon={FolderTree}
          title="No files yet"
          description="This application's project folder is empty. Create a regular file through the governed review."
        />
        <FileMutationDialog
          instanceId={instanceId}
          intent={mutationIntent}
          onOpenChange={(open) => {
            if (!open) setMutationIntent(null)
          }}
          onCompleted={mutationCompleted}
        />
      </div>
    )
  }

  const gitLetter = (node: FileNode) => {
    if (node.gitStatus === 'modified') return { letter: 'M', label: 'Modified', className: 'text-status-attention' }
    if (node.gitStatus === 'untracked') return { letter: 'A', label: 'Added', className: 'text-status-success' }
    return null
  }

  return (
    <div className="flex h-full flex-col" data-testid="files-tree-panel">
      <div className="flex h-7 shrink-0 items-center justify-end gap-0.5 border-b border-border px-2">
        <Tooltip content="Create regular file">
          <button
            type="button"
            aria-label="Create regular file"
            data-testid="file-create-root"
            onClick={() => setMutationIntent({ kind: 'create', parentPath: '' })}
            className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          >
            <FilePlus2 className="size-3.5" aria-hidden="true" />
          </button>
        </Tooltip>
        <Tooltip content="Refresh tree">
          <button
            type="button"
            aria-label="Refresh tree"
            onClick={() => void loadTree(instanceId, { force: true })}
            className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          >
            <RefreshCw className="size-3.5" aria-hidden="true" />
          </button>
        </Tooltip>
        <Tooltip content="Collapse all folders">
          <button
            type="button"
            aria-label="Collapse all folders"
            onClick={() => useFilesStore.getState().collapseAll(instanceId)}
            className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          >
            <ChevronsDownUp className="size-3.5" aria-hidden="true" />
          </button>
        </Tooltip>
      </div>
      <div
        ref={listRef}
        role="tree"
        aria-label="Project files"
        aria-multiselectable={false}
        tabIndex={-1}
        className="min-h-0 flex-1 overflow-y-auto p-1"
        onKeyDown={onKeyDown}
      >
        {rows.map((row, index) => {
          const { node } = row
          const isActive = node.kind === 'file' && (node.path === activeFile || node.path === secondary?.active)
          const isDirty = dirtySet.has(node.path)
          const git = gitLetter(node)
          return (
            <ContextMenu key={node.path}>
              <ContextMenuTrigger asChild>
                {/* Keyboard interaction lives on the tree container (roving tabindex). */}
                {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events */}
                <div
                  ref={(el) => {
                    if (el) rowRefs.current.set(node.path, el)
                    else rowRefs.current.delete(node.path)
                  }}
                  role="treeitem"
                  aria-selected={isActive}
                  aria-expanded={row.expandable ? row.expanded : undefined}
                  aria-level={row.depth + 1}
                  aria-label={
                    node.readOnly ? `${node.name} (read-only)` : isDirty ? `${node.name} (unsaved changes)` : node.name
                  }
                  tabIndex={index === focusIndex ? 0 : -1}
                  data-testid={`tree-row-${node.path}`}
                  data-path={node.path}
                  className={cn(
                    'group flex cursor-default items-center gap-1.5 rounded-sm pr-2 text-sm outline-none transition-colors duration-instant',
                    touch ? 'h-10' : 'h-7',
                    isActive ? 'bg-active text-foreground' : 'text-foreground hover:bg-hover',
                    'focus-visible:bg-hover focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-focus',
                  )}
                  style={{ paddingLeft: `${8 + row.depth * 12}px` }}
                  onClick={() => {
                    setFocusIndex(index)
                    activateRow(row)
                  }}
                  onFocus={() => setFocusIndex(index)}
                >
                  {node.kind === 'directory' ? (
                    <span
                      aria-hidden="true"
                      className={cn(
                        'inline-flex size-3 shrink-0 items-center justify-center text-foreground-tertiary transition-transform duration-fast',
                        row.expanded && 'rotate-90',
                      )}
                    >
                      ›
                    </span>
                  ) : (
                    <span className="size-3 shrink-0" aria-hidden="true" />
                  )}
                  <FileGlyph
                    path={node.path}
                    kind={node.kind}
                    expanded={row.expanded}
                    className="size-4 shrink-0 text-foreground-secondary"
                  />
                  <span className="min-w-0 flex-1 truncate">{node.name}</span>
                  {isDirty ? (
                    <Tooltip content="Unsaved changes — not yet saved">
                      <CircleDot className="size-3 shrink-0 text-accent" aria-label="Unsaved changes" />
                    </Tooltip>
                  ) : null}
                  {node.readOnly ? (
                    <Tooltip content="Read-only — outside this application's permitted folder">
                      <Lock className="size-3 shrink-0 text-foreground-tertiary" aria-label="Read-only" />
                    </Tooltip>
                  ) : null}
                  {git ? (
                    <Tooltip content={git.label}>
                      <span className={cn('shrink-0 font-mono text-xs font-semibold', git.className)} aria-hidden="true">
                        {git.letter}
                      </span>
                    </Tooltip>
                  ) : null}
                </div>
              </ContextMenuTrigger>
              <ContextMenuContent className="w-56 bg-surface">
                {node.kind === 'file' ? (
                  <ContextMenuItem onSelect={() => openFile(node.path)}>
                    <FileSearch className="size-4" aria-hidden="true" />
                    Open
                  </ContextMenuItem>
                ) : null}
                {node.kind === 'file' && secondary ? (
                  <ContextMenuItem onSelect={() => openFile(node.path, 'secondary')}>
                    <ExternalLink className="size-4" aria-hidden="true" />
                    Open to the side
                  </ContextMenuItem>
                ) : null}
                {node.kind === 'directory' ? (
                  <ContextMenuItem onSelect={() => setMutationIntent({ kind: 'create', parentPath: node.path })}>
                    <FilePlus2 className="size-4" aria-hidden="true" />
                    Create file here
                  </ContextMenuItem>
                ) : null}
                {node.kind === 'file' ? (
                  <ContextMenuItem
                    disabled={node.readOnly}
                    onSelect={() => void beginPathMutation('rename', node)}
                  >
                    <Pencil className="size-4" aria-hidden="true" />
                    Rename reviewed file
                  </ContextMenuItem>
                ) : null}
                <ContextMenuItem onSelect={() => copyPath(node.path)}>
                  <Copy className="size-4" aria-hidden="true" />
                  Copy relative path
                </ContextMenuItem>
                <ContextMenuItem onSelect={() => useFilesStore.getState().reveal(instanceId, node.path)}>
                  <FolderTree className="size-4" aria-hidden="true" />
                  Reveal in project tree
                </ContextMenuItem>
                <ContextMenuSeparator />
                {node.kind === 'file' ? (
                  <ContextMenuItem onSelect={() => sendFileToConversation(node.path)}>
                    <MessageSquare className="size-4" aria-hidden="true" />
                    Send to Conversation
                  </ContextMenuItem>
                ) : null}
                <ContextMenuItem onSelect={() => openInTerminal(node.path)}>
                  <SquareTerminal className="size-4" aria-hidden="true" />
                  Open in Terminal
                </ContextMenuItem>
                {node.kind === 'file' ? (
                  <>
                    <ContextMenuSeparator />
                    <ContextMenuItem
                      disabled={node.readOnly}
                      onSelect={() => void beginPathMutation('delete', node)}
                      className="text-status-danger focus:text-status-danger"
                    >
                      <Trash2 className="size-4" aria-hidden="true" />
                      Delete reviewed file
                    </ContextMenuItem>
                  </>
                ) : null}
              </ContextMenuContent>
            </ContextMenu>
          )
        })}
      </div>
      <FileMutationDialog
        instanceId={instanceId}
        intent={mutationIntent}
        onOpenChange={(open) => {
          if (!open) setMutationIntent(null)
        }}
        onCompleted={mutationCompleted}
      />
    </div>
  )
}
