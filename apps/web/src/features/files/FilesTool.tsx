/**
 * FilesTool — the Files + Editor workbench tool
 * (`#/app/:instanceId/workbench/files`, files.md).
 *
 * A professional project workspace with the governed write flow:
 * edit → dirty → diff preview (never silent save) → typed write with
 * expectedRevision → receipt / honest conflict / path-policy outcomes.
 *
 * Composition: file-tree nav panel (registered into the workbench frame),
 * tab strip + breadcrumbs + CodeMirror editor panes (split supported),
 * editor status strip, quick open (Ctrl/Cmd+P), save preview dialog,
 * discard / dirty-close / leave-with-unsaved confirmations, bridge
 * patch-draft intake (opened in the governed preview, never auto-applied),
 * and mobile file-picker + full-screen editor.
 */
import {
  CircleDot,
  Columns2,
  Copy,
  FileDiff,
  FileSearch,
  FolderTree,
  ListTree,
  MessageSquare,
  MoreHorizontal,
  Receipt,
  Save,
  WrapText,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { Panel, Separator } from 'react-resizable-panels'
import type { EditorView } from '@codemirror/view'

import type { EditorSettings, Receipt as ClientReceipt } from '@/client'
import { getClient } from '@/client'
import { ConfirmDialog, EmptyState, Kbd, SkeletonRows, Tooltip, copyText } from '@/components'
import { sendToBridge, useBridgeStore } from '@/features/bridge/bridgeStore'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { PanelGroup } from '@/components/ui/resizable'
import { useCurrentInstance } from '@/shell/currentInstance'
import type { ShellCommand } from '@/shell/commands'
import { useRegisterCommands } from '@/shell/commands'
import { useShortcutAction, useShortcutScope } from '@/shell/shortcutRegistry'
import { useIsMobile, MOD_LABEL } from '@/shell/platform'
import { WorkbenchToolHeader } from '@/shell/workbench/ToolHeader'
import { useRegisterToolPanel } from '@/shell/workbench/WorkbenchSlots'
import { useSessionStore, useWorkspaceStore } from '@/state'
import type { OpenFile } from '@/state/workspace'

import type { EditorCursor, EditorSelectionInfo } from './CodeEditor'
import { openFindInView } from './editorCommands'
import { EditorPane } from './EditorPane'
import { FilesTreePanel } from './FilesTreePanel'
import { QuickOpen } from './QuickOpen'
import { SavePreviewDialog } from './SavePreviewDialog'
import { dirtyPathsOf, useFilesStore } from './filesStore'

/** Fallback while global settings load (mirrors the mock defaults). */
const DEFAULT_EDITOR_SETTINGS: EditorSettings = {
  fontFamily: 'JetBrains Mono',
  fontSize: 13,
  lineHeight: 1.55,
  tabSize: 2,
  indentWith: 'spaces',
  wordWrap: false,
  minimap: false,
  ligatures: false,
  formatOnSave: false,
  autoCloseBrackets: true,
  showWhitespace: false,
  previewDiffBeforeSave: true,
  restoreOpenFiles: true,
  restoreCursorPositions: true,
  autosave: false,
}

/** Stable empty list for selectors (never a fresh `?? []` per snapshot). */
const NO_OPEN_FILES: OpenFile[] = []

type PaneId = 'primary' | 'secondary'

interface PendingClose {
  pane: PaneId
  /** Files that would be discarded (dirty). */
  dirty: string[]
  /** All files the close applies to. */
  paths: string[]
  /** For close-others: the file that stays open. */
  keep?: string
}

export default function FilesTool() {
  const params = useParams<{ instanceId: string }>()
  const { instance } = useCurrentInstance()
  const instanceId = instance?.id ?? params.instanceId ?? ''
  const navigate = useNavigate()
  const [, setSearchParams] = useSearchParams()
  const isMobile = useIsMobile()

  // ── Stores ────────────────────────────────────────────────────────────────
  const wsOpenFiles = useWorkspaceStore((s) => s.openFiles[instanceId] ?? NO_OPEN_FILES)
  const activeFile = useWorkspaceStore((s) => s.activeFile[instanceId] ?? null)
  const docs = useFilesStore((s) => s.docs[instanceId])
  const tree = useFilesStore((s) => s.trees[instanceId])
  const secondary = useFilesStore((s) => s.secondary[instanceId])
  const quickOpenOpen = useFilesStore((s) => s.quickOpenOpen)
  const savePreviewOpen = useFilesStore((s) => s.savePreviewOpen)
  const openInPane = useFilesStore((s) => s.openInPane[instanceId] ?? 'primary')
  const wordWrapOverride = useFilesStore((s) => s.wordWrapOverride[instanceId])

  const primaryPaths = useMemo(() => wsOpenFiles.map((f) => f.path), [wsOpenFiles])
  const secondaryPaths = useMemo(() => secondary?.open ?? [], [secondary])
  const secondaryActive = secondary?.active ?? null

  const dirtyPaths = useMemo(() => dirtyPathsOf(docs), [docs])
  const anyDirty = dirtyPaths.length > 0

  // ── Settings ──────────────────────────────────────────────────────────────
  const [settings, setSettings] = useState<EditorSettings | null>(null)
  useEffect(() => {
    let cancelled = false
    getClient()
      .globalSettings.get()
      .then((global) => {
        if (!cancelled) setSettings(global.editor)
      })
      .catch(() => {
        if (!cancelled) setSettings(DEFAULT_EDITOR_SETTINGS)
      })
    return () => {
      cancelled = true
    }
  }, [])
  const editorSettings = settings ?? DEFAULT_EDITOR_SETTINGS
  const wordWrap = wordWrapOverride ?? editorSettings.wordWrap

  // ── Restore open files + load tree (once settings are known) ──────────────
  const restoredRef = useRef<string | null>(null)
  useEffect(() => {
    if (!instanceId || !settings || restoredRef.current === instanceId) return
    restoredRef.current = instanceId
    const ws = useWorkspaceStore.getState()
    const persisted = (ws.openFiles[instanceId] ?? []).map((f) => f.path)
    if (settings.restoreOpenFiles) {
      for (const path of persisted) void useFilesStore.getState().openDocument(instanceId, path)
    } else {
      for (const path of persisted) ws.closeFile(instanceId, path)
    }
    void useFilesStore.getState().loadTree(instanceId)
  }, [instanceId, settings])

  // ── Workbench frame integration ───────────────────────────────────────────
  useRegisterToolPanel('files', FilesTreePanel)
  useShortcutScope('files')

  // ── Pane/editor runtime state ─────────────────────────────────────────────
  const [paneCursor, setPaneCursor] = useState<Record<PaneId, EditorCursor | null>>({ primary: null, secondary: null })
  const [paneSelection, setPaneSelection] = useState<Record<PaneId, EditorSelectionInfo | null>>({
    primary: null,
    secondary: null,
  })
  const viewsRef = useRef(new Map<string, EditorView>())
  const registerView = useCallback((pane: PaneId, path: string, view: EditorView | null) => {
    const key = `${pane}:${path}`
    if (view) viewsRef.current.set(key, view)
    else viewsRef.current.delete(key)
  }, [])
  const focusedPane: PaneId = secondary ? openInPane : 'primary'
  const focusedActive = focusedPane === 'primary' ? activeFile : secondaryActive
  const activeView = useCallback((): EditorView | null => {
    const pane: PaneId = secondary ? (useFilesStore.getState().openInPane[instanceId] ?? 'primary') : 'primary'
    const active =
      pane === 'primary'
        ? (useWorkspaceStore.getState().activeFile[instanceId] ?? null)
        : (useFilesStore.getState().secondary[instanceId]?.active ?? null)
    if (!active) return null
    return viewsRef.current.get(`${pane}:${active}`) ?? null
  }, [instanceId, secondary])

  const [announcement, setAnnouncement] = useState('')
  // Re-announce identical messages: clear first, then set on the next tick.
  const announce = useCallback((message: string) => {
    setAnnouncement('')
    window.setTimeout(() => setAnnouncement(message), 30)
  }, [])

  // Cursor persistence (debounced — the workspace store is persisted).
  const cursorTimer = useRef<number | null>(null)
  const onCursor = useCallback(
    (pane: PaneId, path: string, cursor: EditorCursor) => {
      setPaneCursor((c) => ({ ...c, [pane]: cursor }))
      if (cursorTimer.current !== null) window.clearTimeout(cursorTimer.current)
      cursorTimer.current = window.setTimeout(() => {
        useWorkspaceStore.getState().setCursor(instanceId, path, cursor)
      }, 400)
    },
    [instanceId],
  )
  const onSelection = useCallback((pane: PaneId, selection: EditorSelectionInfo | null) => {
    setPaneSelection((s) => ({ ...s, [pane]: selection }))
  }, [])

  // ── Save preview scope (all dirty | single file | patch draft) ────────────
  const [previewScope, setPreviewScope] = useState<{ paths: string[] | null; origin: string | null }>({
    paths: null,
    origin: null,
  })
  const openSavePreview = useCallback((scope?: { paths: string[]; origin?: string }) => {
    setPreviewScope({ paths: scope?.paths ?? null, origin: scope?.origin ?? null })
    useFilesStore.getState().setSavePreviewOpen(true)
  }, [])

  // ── Toast with receipt link + announcement after a validated write ────────
  const onSaved = useCallback(
    (path: string, receipt: ClientReceipt) => {
      useSessionStore.getState().pushToast({
        kind: 'success',
        title: 'File change saved',
        body: `${path} · View receipt`,
        route: `/app/${instanceId}/workbench/receipts/${receipt.id}`,
      })
    },
    [instanceId],
  )

  // ── Bridge: patch drafts from Conversation open in the governed preview ───
  useEffect(() => {
    if (!instanceId) return
    const payloads = useBridgeStore.getState().consume(instanceId, ['patch-draft'])
    if (payloads.length === 0) return
    void (async () => {
      for (const payload of payloads) {
        if (payload.kind !== 'patch-draft') continue
        const doc = await useFilesStore.getState().openDocument(instanceId, payload.path)
        if (!doc) continue
        if (doc.readOnly) {
          useSessionStore.getState().pushToast({
            kind: 'error',
            title: 'Proposed change not staged',
            body: `${payload.path} is read-only.`,
          })
          continue
        }
        useFilesStore.getState().setDraft(instanceId, payload.path, payload.proposed)
        useWorkspaceStore.getState().openFile(instanceId, payload.path)
        openSavePreview({
          paths: [payload.path],
          origin: 'A change proposed in Conversation.',
        })
      }
    })()
  }, [instanceId, openSavePreview])

  // ── File open/close helpers ───────────────────────────────────────────────
  const openInPrimary = useCallback(
    (path: string) => {
      void useFilesStore.getState().openDocument(instanceId, path)
      useWorkspaceStore.getState().openFile(instanceId, path)
    },
    [instanceId],
  )

  const [pendingClose, setPendingClose] = useState<PendingClose | null>(null)

  const doClose = useCallback(
    (pane: PaneId, path: string) => {
      if (pane === 'primary') useWorkspaceStore.getState().closeFile(instanceId, path)
      else useFilesStore.getState().closeSecondaryFile(instanceId, path)
      // The document unloads only when no pane shows it anymore.
      const stillOpen =
        pane === 'primary'
          ? (useFilesStore.getState().secondary[instanceId]?.open ?? []).includes(path)
          : (useWorkspaceStore.getState().openFiles[instanceId] ?? []).some((f) => f.path === path)
      if (!stillOpen) useFilesStore.getState().closeDocument(instanceId, path)
    },
    [instanceId],
  )

  const requestClose = useCallback(
    (pane: PaneId, path: string) => {
      const doc = useFilesStore.getState().docs[instanceId]?.[path]
      const dirty = doc ? doc.draft !== doc.savedContent && doc.status === 'ready' : false
      if (dirty) setPendingClose({ pane, paths: [path], dirty: [path] })
      else doClose(pane, path)
    },
    [doClose, instanceId],
  )

  const requestCloseOthers = useCallback(
    (pane: PaneId, keep: string) => {
      const paths = pane === 'primary' ? primaryPaths : secondaryPaths
      const others = paths.filter((p) => p !== keep)
      const store = useFilesStore.getState()
      const dirty = others.filter((p) => {
        const doc = store.docs[instanceId]?.[p]
        return doc && doc.status === 'ready' && doc.draft !== doc.savedContent
      })
      if (dirty.length > 0) setPendingClose({ pane, paths: others, dirty, keep })
      else for (const p of others) doClose(pane, p)
    },
    [doClose, instanceId, primaryPaths, secondaryPaths],
  )

  const confirmPendingClose = useCallback(() => {
    if (!pendingClose) return
    for (const path of pendingClose.paths) doClose(pendingClose.pane, path)
    setPendingClose(null)
  }, [doClose, pendingClose])

  const reorder = useCallback(
    (pane: PaneId, from: number, to: number) => {
      const ws = useWorkspaceStore.getState()
      const store = useFilesStore.getState()
      const current = pane === 'primary' ? (ws.openFiles[instanceId] ?? []).map((f) => f.path) : [...(store.secondary[instanceId]?.open ?? [])]
      if (from < 0 || from >= current.length || to < 0 || to >= current.length) return
      const next = [...current]
      const [moved] = next.splice(from, 1)
      next.splice(to, 0, moved)
      if (pane === 'primary') {
        const active = ws.activeFile[instanceId] ?? null
        for (const p of current) ws.closeFile(instanceId, p)
        for (const p of next) ws.openFile(instanceId, p)
        ws.setActiveFile(instanceId, active)
      } else {
        const active = store.secondary[instanceId]?.active ?? null
        for (const p of current) store.closeSecondaryFile(instanceId, p)
        for (const p of next) store.openSecondaryFile(instanceId, p)
        store.setSecondaryActive(instanceId, active)
      }
    },
    [instanceId],
  )

  const moveToOtherPane = useCallback(
    (pane: PaneId, path: string) => {
      if (pane === 'primary') {
        if (!useFilesStore.getState().secondary[instanceId]) return
        useWorkspaceStore.getState().closeFile(instanceId, path)
        useFilesStore.getState().openSecondaryFile(instanceId, path)
      } else {
        useFilesStore.getState().closeSecondaryFile(instanceId, path)
        useWorkspaceStore.getState().openFile(instanceId, path)
      }
    },
    [instanceId],
  )

  const revealInTree = useCallback(
    (path: string) => {
      useFilesStore.getState().reveal(instanceId, path)
      // Make sure the nav panel is actually visible.
      const layout = useWorkspaceStore.getState().getLayout(instanceId)
      if (layout.navCollapsed) useWorkspaceStore.getState().setLayout(instanceId, { navCollapsed: false })
    },
    [instanceId],
  )

  // ── Split editor ──────────────────────────────────────────────────────────
  const toggleSplit = useCallback(() => {
    const store = useFilesStore.getState()
    const ws = useWorkspaceStore.getState()
    const current = store.secondary[instanceId]
    if (current) {
      // Closing the split never loses tabs: they fold back into the primary pane.
      const active = ws.activeFile[instanceId] ?? null
      for (const path of current.open) {
        if (!(ws.openFiles[instanceId] ?? []).some((f) => f.path === path)) ws.openFile(instanceId, path)
      }
      ws.setActiveFile(instanceId, active)
      store.toggleSecondary(instanceId)
      store.setOpenInPane(instanceId, 'primary')
      announce('Editor panes joined.')
    } else {
      store.toggleSecondary(instanceId, activeFile ?? undefined)
      store.setOpenInPane(instanceId, 'secondary')
      announce('Editor split into two panes.')
    }
  }, [instanceId, activeFile, announce])

  // ── Send selection / copy path / receipt ──────────────────────────────────
  const sendSelection = useCallback(
    (path: string, selection: EditorSelectionInfo) => {
      sendToBridge({
        kind: 'file-selection',
        instanceId,
        path,
        text: selection.text,
        lineStart: selection.lineStart,
        lineEnd: selection.lineEnd,
      })
      void navigate(`/app/${instanceId}/conversation`)
    },
    [instanceId, navigate],
  )

  // ── Unsaved-change protection: in-app navigation modal + beforeunload ─────
  const [pendingNav, setPendingNav] = useState<string | null>(null)

  const openReceipt = useCallback(
    (receiptId: string) => {
      if (anyDirty) setPendingNav(`/app/${instanceId}/workbench/receipts/${receiptId}`)
      else void navigate(`/app/${instanceId}/workbench/receipts/${receiptId}`)
    },
    [anyDirty, instanceId, navigate],
  )
  useEffect(() => {
    if (!anyDirty) return
    const onClick = (e: MouseEvent) => {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
      const target = e.target as HTMLElement | null
      const anchor = target?.closest?.('a[href]') as HTMLAnchorElement | null
      if (!anchor) return
      const href = anchor.getAttribute('href') ?? ''
      if (!href.startsWith('#/')) return
      e.preventDefault()
      e.stopPropagation()
      setPendingNav(href.slice(1))
    }
    document.addEventListener('click', onClick, true)
    return () => document.removeEventListener('click', onClick, true)
  }, [anyDirty])

  useEffect(() => {
    if (!anyDirty) return
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', onBeforeUnload)
    return () => window.removeEventListener('beforeunload', onBeforeUnload)
  }, [anyDirty])

  // ── Shortcuts (files scope chords via useShortcutAction) ──────────────────
  useShortcutAction('global.quick_open', () => useFilesStore.getState().setQuickOpenOpen(true))
  useShortcutAction('files.save_preview', () => {
    if (dirtyPathsOf(useFilesStore.getState().docs[instanceId]).length > 0) openSavePreview()
    else announce('No unsaved changes.')
  })
  useShortcutAction('files.split_editor', toggleSplit)
  useShortcutAction('files.find', () => {
    if (!openFindInView(activeView())) announce('No editor is active.')
  })

  // ── Palette commands ──────────────────────────────────────────────────────
  const commands = useMemo<ShellCommand[]>(
    () => [
      {
        id: 'files.quick_open',
        title: 'Quick open file',
        group: 'Actions',
        icon: FileSearch,
        shortcut: 'mod+p',
        keywords: ['open', 'file', 'go to'],
        run: () => useFilesStore.getState().setQuickOpenOpen(true),
      },
      {
        id: 'files.save_preview',
        title: 'Review & save changes',
        group: 'Actions',
        icon: Save,
        shortcut: 'mod+s',
        keywords: ['save', 'preview', 'diff', 'review'],
        when: () => dirtyPathsOf(useFilesStore.getState().docs[instanceId]).length > 0,
        run: () => openSavePreview(),
      },
      {
        id: 'files.split_editor',
        title: secondary ? 'Join editor panes' : 'Split editor',
        group: 'Actions',
        icon: Columns2,
        shortcut: 'mod+\\',
        keywords: ['split', 'pane'],
        run: toggleSplit,
      },
      {
        id: 'files.toggle_word_wrap',
        title: wordWrap ? 'Word wrap: off' : 'Word wrap: on',
        group: 'Actions',
        icon: WrapText,
        keywords: ['wrap', 'editor'],
        run: () => {
          useFilesStore.getState().toggleWordWrapOverride(instanceId, wordWrap)
          announce(wordWrap ? 'Word wrap off.' : 'Word wrap on.')
        },
      },
      {
        id: 'files.send_selection',
        title: 'Send selection to Conversation',
        group: 'Actions',
        icon: MessageSquare,
        keywords: ['conversation', 'context', 'selection'],
        when: () => {
          const pane = useFilesStore.getState().secondary[instanceId]
            ? (useFilesStore.getState().openInPane[instanceId] ?? 'primary')
            : 'primary'
          return Boolean(paneSelection[pane])
        },
        run: () => {
          const pane = useFilesStore.getState().secondary[instanceId]
            ? (useFilesStore.getState().openInPane[instanceId] ?? 'primary')
            : 'primary'
          const selection = paneSelection[pane]
          const active =
            pane === 'primary'
              ? (useWorkspaceStore.getState().activeFile[instanceId] ?? null)
              : (useFilesStore.getState().secondary[instanceId]?.active ?? null)
          if (selection && active) sendSelection(active, selection)
        },
      },
      {
        id: 'files.reveal_in_tree',
        title: 'Reveal active file in project tree',
        group: 'Actions',
        icon: FolderTree,
        keywords: ['reveal', 'tree', 'active'],
        when: () => Boolean(useWorkspaceStore.getState().activeFile[instanceId]),
        run: () => {
          const active = useWorkspaceStore.getState().activeFile[instanceId]
          if (active) revealInTree(active)
        },
      },
      {
        id: 'files.copy_path',
        title: 'Copy relative path of active file',
        group: 'Actions',
        icon: Copy,
        keywords: ['copy', 'path'],
        when: () => Boolean(useWorkspaceStore.getState().activeFile[instanceId]),
        run: () => {
          const active = useWorkspaceStore.getState().activeFile[instanceId]
          if (active) void copyText(active)
        },
      },
      {
        id: 'files.compare_saved',
        title: 'Compare active file with last saved',
        group: 'Actions',
        icon: FileDiff,
        keywords: ['diff', 'compare', 'saved'],
        when: () => {
          const active = useWorkspaceStore.getState().activeFile[instanceId]
          if (!active) return false
          return dirtyPathsOf(useFilesStore.getState().docs[instanceId]).includes(active)
        },
        run: () => {
          const active = useWorkspaceStore.getState().activeFile[instanceId]
          if (active) openSavePreview({ paths: [active] })
        },
      },
    ],
    [instanceId, openSavePreview, paneSelection, revealInTree, secondary, sendSelection, toggleSplit, wordWrap, announce],
  )
  useRegisterCommands(commands)

  // ── Maximize (focus mode deep link, owned by the workbench frame) ─────────
  const maximize = useCallback(() => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        next.set('focus', '1')
        return next
      },
      { replace: true },
    )
  }, [setSearchParams])

  // ── Mobile file picker ────────────────────────────────────────────────────
  const [pickerOpen, setPickerOpen] = useState(false)

  // ── Derived view state ────────────────────────────────────────────────────
  const treeEmpty = Boolean(tree && !tree.loading && !tree.error && (tree.nodes ?? []).length === 0)
  const recentFiles = useMemo(() => {
    const seen = new Set<string>()
    const out: string[] = []
    for (const key of Object.keys(useWorkspaceStore.getState().cursorPositions)) {
      const [id, ...rest] = key.split(':')
      if (id !== instanceId) continue
      const path = rest.join(':')
      if (!seen.has(path)) {
        seen.add(path)
        out.push(path)
      }
    }
    return out.slice(0, 5)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [instanceId, activeFile, primaryPaths.length])

  if (!instanceId) return null

  // Settings still loading → faithful skeleton, never a blank pane.
  if (!settings) {
    return (
      <div className="flex h-full flex-col bg-app" data-testid="files-loading">
        <div className="h-9 border-b border-border bg-surface" />
        <SkeletonRows rows={8} className="p-4" />
      </div>
    )
  }

  const activeDoc = focusedActive ? docs?.[focusedActive] : undefined
  const anyActiveDirty = activeDoc ? activeDoc.status === 'ready' && activeDoc.draft !== activeDoc.savedContent : false

  const placeholder = (
    <div className="flex h-full items-center justify-center bg-sunken" data-testid="editor-placeholder">
      {treeEmpty ? (
        <EmptyState
          icon={FolderTree}
          title="No files yet"
          description="This application's project folder is empty or no repository is registered. Files appear here once content exists in the project folder."
        />
      ) : (
        <div className="flex max-w-sm flex-col items-center gap-3 px-6 text-center">
          <FileSearch className="size-5 text-foreground-tertiary" aria-hidden="true" />
          <h2 className="text-lg text-foreground">No file selected</h2>
          <p className="text-sm text-foreground-secondary">
            Open a file from the project tree or quick open.
          </p>
          <div className="mt-1 flex items-center gap-2">
            <Button size="sm" onClick={() => (isMobile ? setPickerOpen(true) : useFilesStore.getState().setQuickOpenOpen(true))}>
              <FileSearch aria-hidden="true" />
              Quick open
              <Kbd className="ml-1">{MOD_LABEL}+P</Kbd>
            </Button>
          </div>
          {recentFiles.length > 0 ? (
            <div className="mt-3 w-full">
              <p className="mb-1 text-left text-xs font-medium text-foreground-secondary">Recent files</p>
              <ul className="flex flex-col">
                {recentFiles.map((path) => (
                  <li key={path}>
                    <button
                      type="button"
                      onClick={() => openInPrimary(path)}
                      className="tnum flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left font-mono text-xs text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                    >
                      <FileSearch className="size-3.5 shrink-0" aria-hidden="true" />
                      <span className="truncate">{path}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}
    </div>
  )

  const paneProps = {
    instanceId,
    settings: editorSettings,
    wordWrap,
    onReveal: revealInTree,
    onCompare: (path: string) => openSavePreview({ paths: [path] }),
    onReviewSave: () => openSavePreview(),
    onSendSelection: sendSelection,
    onOpenReceipt: openReceipt,
    onCursor,
    onSelection,
    registerView,
  }

  const editorArea = (
    <>
      {primaryPaths.length === 0 && secondaryPaths.length === 0 ? (
        placeholder
      ) : (
        <PanelGroup orientation="horizontal" className="h-full">
          <Panel id="editor-primary" minSize="25%" className="flex min-w-0 flex-col">
            <EditorPane
              {...paneProps}
              pane="primary"
              paths={primaryPaths}
              active={activeFile}
              cursor={paneCursor.primary}
              selection={paneSelection.primary}
              onFocusPane={() => useFilesStore.getState().setOpenInPane(instanceId, 'primary')}
              onSelect={(path) => useWorkspaceStore.getState().setActiveFile(instanceId, path)}
              onClose={(path) => requestClose('primary', path)}
              onCloseOthers={(path) => requestCloseOthers('primary', path)}
              onReorder={(from, to) => reorder('primary', from, to)}
              onMoveToOtherPane={secondary ? (path) => moveToOtherPane('primary', path) : undefined}
            />
          </Panel>
          {secondary ? (
            <>
              <Separator
                aria-label="Resize editor panes"
                className="relative w-1 shrink-0 cursor-col-resize before:absolute before:inset-y-0 before:left-1/2 before:w-px before:bg-border before:transition-colors before:duration-instant hover:before:bg-border-strong"
              />
              <Panel id="editor-secondary" minSize="25%" className="flex min-w-0 flex-col">
                <EditorPane
                  {...paneProps}
                  pane="secondary"
                  paths={secondaryPaths}
                  active={secondaryActive}
                  cursor={paneCursor.secondary}
                  selection={paneSelection.secondary}
                  onFocusPane={() => useFilesStore.getState().setOpenInPane(instanceId, 'secondary')}
                  onSelect={(path) => useFilesStore.getState().setSecondaryActive(instanceId, path)}
                  onClose={(path) => requestClose('secondary', path)}
                  onCloseOthers={(path) => requestCloseOthers('secondary', path)}
                  onReorder={(from, to) => reorder('secondary', from, to)}
                  onMoveToOtherPane={(path) => moveToOtherPane('secondary', path)}
                />
              </Panel>
            </>
          ) : null}
        </PanelGroup>
      )}
    </>
  )

  const overlays = (
    <>
      <QuickOpen
        instanceId={instanceId}
        open={quickOpenOpen}
        onOpenChange={(open) => useFilesStore.getState().setQuickOpenOpen(open)}
        onOpenFile={openInPrimary}
      />
      <SavePreviewDialog
        instanceId={instanceId}
        open={savePreviewOpen}
        onOpenChange={(open) => useFilesStore.getState().setSavePreviewOpen(open)}
        paths={previewScope.paths}
        originNote={previewScope.origin}
        settings={editorSettings}
        onSaved={onSaved}
        onAnnounce={(message) => setAnnouncement(message)}
      />
      <ConfirmDialog
        open={pendingClose !== null}
        onOpenChange={(open) => {
          if (!open) setPendingClose(null)
        }}
        title="Discard unsaved changes?"
        description={
          pendingClose && pendingClose.dirty.length > 1
            ? 'These files have unsaved changes. Closing discards the edits.'
            : 'This file has unsaved changes. Closing discards the edits.'
        }
        target={pendingClose?.dirty.join(', ')}
        effect="Close and return to the last saved version"
        reversibility="This cannot be undone — only the last saved version is restored."
        confirmLabel="Discard and close"
        destructive
        onConfirm={confirmPendingClose}
      />
      <ConfirmDialog
        open={pendingNav !== null}
        onOpenChange={(open) => {
          if (!open) setPendingNav(null)
        }}
        title="Leave Files with unsaved changes?"
        description="You have unsaved edits. They are kept in the editor, so you can come back and save them later."
        target={dirtyPaths.join(', ')}
        effect="Navigate away from the Files tool"
        reversibility="Unsaved changes stay in the editor and are restored when you return."
        confirmLabel="Leave"
        onConfirm={() => {
          const to = pendingNav
          setPendingNav(null)
          if (to) void navigate(to)
        }}
      />
      <div aria-live="polite" className="sr-only" data-testid="files-announcements">
        {announcement}
      </div>
    </>
  )

  // ── Mobile: file picker + full-screen editor (files.md §Mobile) ───────────
  if (isMobile) {
    return (
      <div className="flex h-full flex-col" data-testid="files-stub">
        <header className="flex h-9 shrink-0 items-center gap-1 border-b border-border bg-surface px-2">
          <button
            type="button"
            onClick={() => setPickerOpen(true)}
            aria-label="Open file picker"
            className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            data-testid="mobile-file-picker"
          >
            <ListTree className="size-4" aria-hidden="true" />
          </button>
          {focusedActive ? (
            <span className="tnum flex min-w-0 flex-1 items-center gap-1.5 truncate px-1 font-mono text-xs text-foreground">
              <span className="truncate">{focusedActive.split('/').pop()}</span>
              {anyActiveDirty ? <CircleDot className="size-3 shrink-0 text-accent" aria-label="Unsaved changes" /> : null}
              {activeDoc?.readOnly ? (
                <span className="text-xs text-foreground-tertiary">Read-only</span>
              ) : null}
            </span>
          ) : (
            <span className="flex-1 px-1 text-sm text-foreground-secondary">Files</span>
          )}
          {anyDirty ? (
            <Button size="sm" className="h-7" onClick={() => openSavePreview()} data-testid="mobile-review-save">
              <Save aria-hidden="true" />
              Review
            </Button>
          ) : null}
          <DropdownMenu>
            <DropdownMenuTrigger
              aria-label="Editor options"
              className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            >
              <MoreHorizontal className="size-4" aria-hidden="true" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-60 bg-surface">
              <DropdownMenuItem disabled={!focusedActive} onSelect={() => openFindInView(activeView())}>
                <FileSearch className="size-4" aria-hidden="true" />
                Find in file
              </DropdownMenuItem>
              <DropdownMenuItem
                onSelect={() => {
                  useFilesStore.getState().toggleWordWrapOverride(instanceId, wordWrap)
                }}
              >
                <WrapText className="size-4" aria-hidden="true" />
                {wordWrap ? 'Word wrap: off' : 'Word wrap: on'}
              </DropdownMenuItem>
              <DropdownMenuItem disabled={!focusedActive} onSelect={() => focusedActive && void copyText(focusedActive)}>
                <Copy className="size-4" aria-hidden="true" />
                Copy relative path
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                disabled={!paneSelection[focusedPane]}
                onSelect={() => {
                  const sel = paneSelection[focusedPane]
                  if (sel && focusedActive) sendSelection(focusedActive, sel)
                }}
              >
                <MessageSquare className="size-4" aria-hidden="true" />
                Send selection to Conversation
              </DropdownMenuItem>
              <DropdownMenuItem disabled={!anyActiveDirty} onSelect={() => focusedActive && openSavePreview({ paths: [focusedActive] })}>
                <FileDiff className="size-4" aria-hidden="true" />
                Compare with saved
              </DropdownMenuItem>
              {activeDoc?.lastReceiptId ? (
                <DropdownMenuItem onSelect={() => activeDoc.lastReceiptId && openReceipt(activeDoc.lastReceiptId)}>
                  <Receipt className="size-4" aria-hidden="true" />
                  Open related receipt
                </DropdownMenuItem>
              ) : null}
            </DropdownMenuContent>
          </DropdownMenu>
        </header>

        <div className="min-h-0 flex-1">
          {primaryPaths.length === 0 ? (
            placeholder
          ) : (
            <EditorPane
              {...paneProps}
              pane="primary"
              paths={primaryPaths}
              active={activeFile}
              showTabs={false}
              cursor={paneCursor.primary}
              selection={paneSelection.primary}
              onFocusPane={() => useFilesStore.getState().setOpenInPane(instanceId, 'primary')}
              onSelect={(path) => useWorkspaceStore.getState().setActiveFile(instanceId, path)}
              onClose={(path) => requestClose('primary', path)}
              onCloseOthers={(path) => requestCloseOthers('primary', path)}
              onReorder={(from, to) => reorder('primary', from, to)}
            />
          )}
        </div>

        <Dialog open={pickerOpen} onOpenChange={setPickerOpen}>
          <DialogContent
            className="inset-0 top-0 left-0 flex h-[100dvh] w-full max-w-none translate-x-0 translate-y-0 flex-col gap-0 rounded-none border-border bg-surface p-0"
            showCloseButton
            data-testid="mobile-picker-sheet"
          >
            <DialogTitle className="flex h-11 shrink-0 items-center border-b border-border px-4 text-lg">
              Project files
            </DialogTitle>
            <div className="min-h-0 flex-1 overflow-hidden">
              <FilesTreePanel instanceId={instanceId} tool="files" touch onFileOpen={() => setPickerOpen(false)} />
            </div>
          </DialogContent>
        </Dialog>

        {overlays}
      </div>
    )
  }

  // ── Desktop / tablet ──────────────────────────────────────────────────────
  return (
    <div className="flex h-full flex-col" data-testid="files-stub">
      <WorkbenchToolHeader
        name="Files"
        icon={FolderTree}
        state={
          anyDirty ? (
            <span className="flex items-center gap-1 text-xs text-foreground-secondary" data-testid="dirty-count">
              <CircleDot className="size-3 text-accent" aria-hidden="true" />
              {dirtyPaths.length} unsaved
            </span>
          ) : undefined
        }
        primaryAction={
          anyDirty ? (
            <Tooltip content={`Review & save · ${MOD_LABEL}+S`}>
              <Button size="sm" className="h-7" onClick={() => openSavePreview()} data-testid="review-save">
                <Save aria-hidden="true" />
                Review &amp; save
              </Button>
            </Tooltip>
          ) : undefined
        }
        onMaximize={maximize}
      />
      <div className="min-h-0 flex-1">{editorArea}</div>
      {overlays}
    </div>
  )
}
