/**
 * Files tool store — runtime state for the Files + Editor workbench tool
 * (files.md). Ephemeral by design: durable continuity (open files, active
 * file, cursor positions) lives in the workspace store; this store holds
 * loaded documents, dirty drafts, tree state, and tool-local UI state.
 *
 * The governed write flow never touches this store directly for writes —
 * components call `client.files.write(expectedRevision)` and then record the
 * outcome here via `applyEntry` / `setConflict`.
 */
import { create } from 'zustand'

import type { FileEntry, FileNode } from '@/client'
import { getClient } from '@/client'

/** files.md: files above 512 KB open a read-only fast-view with "Load anyway". */
export const LARGE_FILE_BYTES = 512 * 1024

export interface FileConflict {
  detail: string
  currentRevision: string
  currentContent: string
}

export interface FileDoc {
  path: string
  status: 'loading' | 'ready' | 'error'
  error: unknown | null
  /** Content as of the last successful read or validated write. */
  savedContent: string
  /** Current editor content (dirty when different from savedContent). */
  draft: string
  /** Revision of savedContent — sent as expectedRevision on write. */
  revision: string
  readOnly: boolean
  encoding: 'utf-8'
  modifiedAt: string
  /** Large-file guard: render the fast-view until the user opts in. */
  large: boolean
  loadAnyway: boolean
  /** Receipt of the last validated write for this document. */
  lastReceiptId: string | null
  /** Present when a write returned a revision conflict. */
  conflict: FileConflict | null
}

export interface TreeState {
  nodes: FileNode[] | null
  loading: boolean
  error: unknown | null
}

/** Second editor pane (split editor): its own tab list and active file. */
export interface SecondaryPane {
  open: string[]
  active: string | null
}

export function docIsDirty(doc: FileDoc): boolean {
  return doc.status === 'ready' && doc.draft !== doc.savedContent
}

const EMPTY_TREE: TreeState = { nodes: null, loading: false, error: null }

/** Flatten a tree into file paths (depth-first, stable for quick open). */
export function flattenFilePaths(nodes: FileNode[] | null | undefined): string[] {
  if (!nodes) return []
  const out: string[] = []
  const walk = (list: FileNode[]) => {
    for (const node of list) {
      if (node.kind === 'file') out.push(node.path)
      if (node.children) walk(node.children)
    }
  }
  walk(nodes)
  return out
}

/** Find a node by path. */
export function findNode(nodes: FileNode[] | null | undefined, path: string): FileNode | null {
  if (!nodes) return null
  for (const node of nodes) {
    if (node.path === path) return node
    const child = findNode(node.children, path)
    if (child) return child
  }
  return null
}

/** Ancestor directory paths of a file path (`a/b/c.nix` → ['a', 'a/b']). */
export function ancestorDirs(path: string): string[] {
  const parts = path.split('/')
  const dirs: string[] = []
  for (let i = 1; i < parts.length; i += 1) dirs.push(parts.slice(0, i).join('/'))
  return dirs
}

/** Byte length of a string (utf-8 approximation is fine for the size guard). */
function byteLength(text: string): number {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(text).length
  return text.length * 2
}

interface FilesState {
  trees: Record<string, TreeState>
  /** instanceId → path → document. */
  docs: Record<string, Record<string, FileDoc>>
  /** instanceId → dirPath → expanded. */
  expanded: Record<string, Record<string, boolean>>
  /** One-shot reveal request consumed by the tree panel. */
  revealPath: { instanceId: string; path: string } | null
  /** Split-editor second pane per instance (null = single pane). */
  secondary: Record<string, SecondaryPane | null>
  quickOpenOpen: boolean
  savePreviewOpen: boolean
  /** Per-instance word-wrap toggle override (default comes from settings). */
  wordWrapOverride: Record<string, boolean>
  /** Which editor pane tree opens target (last focused pane). */
  openInPane: Record<string, 'primary' | 'secondary'>

  loadTree(instanceId: string, opts?: { force?: boolean }): Promise<FileNode[] | null>
  toggleDir(instanceId: string, path: string): void
  setDirExpanded(instanceId: string, path: string, expanded: boolean): void
  collapseAll(instanceId: string): void
  reveal(instanceId: string, path: string): void
  clearReveal(): void

  openDocument(instanceId: string, path: string): Promise<FileDoc | null>
  reloadDocument(instanceId: string, path: string): Promise<FileDoc | null>
  closeDocument(instanceId: string, path: string): void
  setDraft(instanceId: string, path: string, draft: string): void
  discardDraft(instanceId: string, path: string): void
  setLoadAnyway(instanceId: string, path: string): void
  applyEntry(instanceId: string, path: string, entry: FileEntry, receiptId: string | null): void
  setConflict(instanceId: string, path: string, conflict: FileConflict | null): void

  toggleSecondary(instanceId: string, seedPath?: string | null): void
  openSecondaryFile(instanceId: string, path: string): void
  closeSecondaryFile(instanceId: string, path: string): void
  setSecondaryActive(instanceId: string, path: string | null): void

  setQuickOpenOpen(open: boolean): void
  setSavePreviewOpen(open: boolean): void
  /** Sets the wrap override to the opposite of the current effective value. */
  toggleWordWrapOverride(instanceId: string, currentEffective: boolean): void
  setOpenInPane(instanceId: string, pane: 'primary' | 'secondary'): void

  resetForTests(): void
}

function docFromEntry(entry: FileEntry): FileDoc {
  const large = byteLength(entry.content) > LARGE_FILE_BYTES
  return {
    path: entry.path,
    status: 'ready',
    error: null,
    savedContent: entry.content,
    draft: entry.content,
    revision: entry.revision,
    readOnly: entry.readOnly,
    encoding: entry.encoding,
    modifiedAt: entry.modifiedAt,
    large,
    loadAnyway: !large,
    lastReceiptId: null,
    conflict: null,
  }
}

function loadingDoc(path: string): FileDoc {
  return {
    path,
    status: 'loading',
    error: null,
    savedContent: '',
    draft: '',
    revision: '',
    readOnly: false,
    encoding: 'utf-8',
    modifiedAt: '',
    large: false,
    loadAnyway: false,
    lastReceiptId: null,
    conflict: null,
  }
}

function errorDoc(path: string, error: unknown): FileDoc {
  return { ...loadingDoc(path), status: 'error', error }
}

/** Dedupe in-flight reads so double-open never double-fetches. */
const pendingReads = new Map<string, Promise<FileDoc | null>>()
interface PendingTreeRequest {
  token: symbol
  promise: Promise<FileNode[] | null>
}

/**
 * Tree reads are cancellable by replacement rather than by transport abort.
 * An old request may still resolve after a reset or forced refresh, but it
 * must never repopulate the current store or clear the newer request.
 */
const pendingTrees = new Map<string, PendingTreeRequest>()
const treeRequestTokens = new Map<string, symbol>()

export const useFilesStore = create<FilesState>()((set, get) => {
  const setDoc = (instanceId: string, path: string, doc: FileDoc) =>
    set((s) => ({
      docs: {
        ...s.docs,
        [instanceId]: { ...(s.docs[instanceId] ?? {}), [path]: doc },
      },
    }))

  const patchDoc = (instanceId: string, path: string, patch: Partial<FileDoc>) => {
    const current = get().docs[instanceId]?.[path]
    if (!current) return
    setDoc(instanceId, path, { ...current, ...patch })
  }

  return {
    trees: {},
    docs: {},
    expanded: {},
    revealPath: null,
    secondary: {},
    quickOpenOpen: false,
    savePreviewOpen: false,
    wordWrapOverride: {},
    openInPane: {},

    loadTree: async (instanceId, opts) => {
      const existing = get().trees[instanceId] ?? EMPTY_TREE
      const pending = pendingTrees.get(instanceId)
      if (!opts?.force) {
        if (existing.nodes !== null) return existing.nodes
        if (pending) return pending.promise
      }

      const token = Symbol(`tree:${instanceId}`)
      treeRequestTokens.set(instanceId, token)
      set((s) => ({
        trees: { ...s.trees, [instanceId]: { ...existing, loading: true, error: null } },
      }))
      const request: PendingTreeRequest = { token, promise: Promise.resolve(null) }
      pendingTrees.set(instanceId, request)
      const isCurrent = () => treeRequestTokens.get(instanceId) === token
      // Begin after the request is registered: a synchronous adapter failure
      // still observes its identity and cannot strand a stale pending entry.
      request.promise = Promise.resolve()
        .then(async (): Promise<FileNode[] | null> => {
          try {
            const nodes = await getClient().files.listTree(instanceId)
            if (isCurrent()) {
              set((s) => ({ trees: { ...s.trees, [instanceId]: { nodes, loading: false, error: null } } }))
            }
            return nodes
          } catch (error) {
            if (isCurrent()) {
              set((s) => ({
                trees: {
                  ...s.trees,
                  [instanceId]: { nodes: get().trees[instanceId]?.nodes ?? null, loading: false, error },
                },
              }))
            }
            return null
          }
        })
        .finally(() => {
          if (isCurrent()) {
            treeRequestTokens.delete(instanceId)
            pendingTrees.delete(instanceId)
          }
        })
      return request.promise
    },

    toggleDir: (instanceId, path) =>
      set((s) => {
        const current = s.expanded[instanceId] ?? {}
        return { expanded: { ...s.expanded, [instanceId]: { ...current, [path]: !current[path] } }
        }
      }),

    setDirExpanded: (instanceId, path, expanded) =>
      set((s) => ({
        expanded: {
          ...s.expanded,
          [instanceId]: { ...(s.expanded[instanceId] ?? {}), [path]: expanded },
        },
      })),

    collapseAll: (instanceId) =>
      set((s) => ({ expanded: { ...s.expanded, [instanceId]: {} } })),

    reveal: (instanceId, path) =>
      set((s) => {
        const current = { ...(s.expanded[instanceId] ?? {}) }
        for (const dir of ancestorDirs(path)) current[dir] = true
        return {
          expanded: { ...s.expanded, [instanceId]: current },
          revealPath: { instanceId, path },
        }
      }),

    clearReveal: () => set({ revealPath: null }),

    openDocument: async (instanceId, path) => {
      const existing = get().docs[instanceId]?.[path]
      if (existing && existing.status !== 'error') return existing
      const key = `${instanceId}${path}`
      const pending = pendingReads.get(key)
      if (pending) return pending
      if (!existing) setDoc(instanceId, path, loadingDoc(path))
      const promise = (async (): Promise<FileDoc | null> => {
        try {
          const entry = await getClient().files.read(instanceId, path)
          // A draft typed while reloading is never clobbered (error-retry path).
          const live = get().docs[instanceId]?.[path]
          const loaded = docFromEntry(entry)
          const doc =
            live && live.status === 'error' && live.draft && live.draft !== live.savedContent
              ? { ...loaded, draft: live.draft }
              : loaded
          setDoc(instanceId, path, doc)
          return doc
        } catch (error) {
          const live = get().docs[instanceId]?.[path]
          setDoc(instanceId, path, { ...errorDoc(path, error), draft: live?.draft ?? '' })
          return null
        } finally {
          pendingReads.delete(key)
        }
      })()
      pendingReads.set(key, promise)
      return promise
    },

    reloadDocument: async (instanceId, path) => {
      const doc = get().docs[instanceId]?.[path]
      if (!doc) return get().openDocument(instanceId, path)
      patchDoc(instanceId, path, { status: 'loading', error: null, conflict: null })
      try {
        const entry = await getClient().files.read(instanceId, path)
        const loaded = docFromEntry(entry)
        // Preserve an unsaved draft typed after the reload started.
        const live = get().docs[instanceId]?.[path]
        const dirtyDraft = live && live.draft !== live.savedContent ? live.draft : null
        setDoc(instanceId, path, dirtyDraft !== null ? { ...loaded, draft: dirtyDraft } : loaded)
        return get().docs[instanceId]?.[path] ?? null
      } catch (error) {
        patchDoc(instanceId, path, { status: 'error', error })
        return null
      }
    },

    closeDocument: (instanceId, path) =>
      set((s) => {
        const docs = { ...(s.docs[instanceId] ?? {}) }
        delete docs[path]
        const secondary = s.secondary[instanceId]
        return {
          docs: { ...s.docs, [instanceId]: docs },
          ...(secondary && secondary.open.includes(path)
            ? {
                secondary: {
                  ...s.secondary,
                  [instanceId]: {
                    open: secondary.open.filter((p) => p !== path),
                    active: secondary.active === path ? (secondary.open.filter((p) => p !== path).at(-1) ?? null) : secondary.active,
                  },
                },
              }
            : {}),
        }
      }),

    setDraft: (instanceId, path, draft) => {
      const doc = get().docs[instanceId]?.[path]
      if (!doc || doc.readOnly) return
      patchDoc(instanceId, path, { draft })
    },

    discardDraft: (instanceId, path) => {
      const doc = get().docs[instanceId]?.[path]
      if (!doc) return
      patchDoc(instanceId, path, { draft: doc.savedContent, conflict: null })
    },

    setLoadAnyway: (instanceId, path) => patchDoc(instanceId, path, { loadAnyway: true }),

    applyEntry: (instanceId, path, entry, receiptId) => {
      const doc = get().docs[instanceId]?.[path]
      if (!doc) {
        setDoc(instanceId, path, { ...docFromEntry(entry), lastReceiptId: receiptId })
        return
      }
      setDoc(instanceId, path, {
        ...doc,
        status: 'ready',
        error: null,
        savedContent: entry.content,
        draft: entry.content,
        revision: entry.revision,
        readOnly: entry.readOnly,
        modifiedAt: entry.modifiedAt,
        lastReceiptId: receiptId,
        conflict: null,
      })
    },

    setConflict: (instanceId, path, conflict) => patchDoc(instanceId, path, { conflict }),

    toggleSecondary: (instanceId, seedPath) =>
      set((s) => {
        const current = s.secondary[instanceId]
        if (current) return { secondary: { ...s.secondary, [instanceId]: null } }
        return {
          secondary: {
            ...s.secondary,
            [instanceId]: { open: seedPath ? [seedPath] : [], active: seedPath ?? null },
          },
        }
      }),

    openSecondaryFile: (instanceId, path) =>
      set((s) => {
        const current = s.secondary[instanceId] ?? { open: [], active: null }
        const open = current.open.includes(path) ? current.open : [...current.open, path]
        return { secondary: { ...s.secondary, [instanceId]: { open, active: path } } }
      }),

    closeSecondaryFile: (instanceId, path) =>
      set((s) => {
        const current = s.secondary[instanceId]
        if (!current) return s
        const open = current.open.filter((p) => p !== path)
        const active = current.active === path ? (open.at(-1) ?? null) : current.active
        return { secondary: { ...s.secondary, [instanceId]: { open, active } } }
      }),

    setSecondaryActive: (instanceId, path) =>
      set((s) => {
        const current = s.secondary[instanceId]
        if (!current) return s
        return { secondary: { ...s.secondary, [instanceId]: { ...current, active: path } } }
      }),

    setQuickOpenOpen: (quickOpenOpen) => set({ quickOpenOpen }),
    setSavePreviewOpen: (savePreviewOpen) => set({ savePreviewOpen }),

    toggleWordWrapOverride: (instanceId, currentEffective) =>
      set((s) => ({
        wordWrapOverride: { ...s.wordWrapOverride, [instanceId]: !currentEffective },
      })),

    setOpenInPane: (instanceId, pane) =>
      set((s) => ({ openInPane: { ...s.openInPane, [instanceId]: pane } })),

    resetForTests: () => {
      pendingReads.clear()
      pendingTrees.clear()
      treeRequestTokens.clear()
      set({
        trees: {},
        docs: {},
        expanded: {},
        revealPath: null,
        secondary: {},
        quickOpenOpen: false,
        savePreviewOpen: false,
        wordWrapOverride: {},
        openInPane: {},
      })
    },
  }
})

/** Dirty paths for an instance (stable order = document insertion order). */
export function dirtyPathsOf(docs: Record<string, FileDoc> | undefined): string[] {
  if (!docs) return []
  return Object.values(docs)
    .filter(docIsDirty)
    .map((d) => d.path)
}
