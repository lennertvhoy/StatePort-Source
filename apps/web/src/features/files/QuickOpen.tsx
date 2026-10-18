/**
 * QuickOpen (design.md §9.6, files.md §Keyboard) — Ctrl/Cmd+P: palette-style
 * fuzzy file picker over the current application's tree (fuzzysort). Open
 * files rank as recents on an empty query; ↑↓ navigate, Enter opens,
 * Escape closes. Files of the current app only — never commands, never
 * other apps (that's the command palette's job).
 */
import fuzzysort from 'fuzzysort'
import { CircleDot, FileSearch } from 'lucide-react'
import type { ReactNode } from 'react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { Kbd } from '@/components'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import { useWorkspaceStore } from '@/state'

import { FileGlyph } from './fileIcons'
import { dirtyPathsOf, flattenFilePaths, useFilesStore } from './filesStore'

/** Stable empty list for the openFiles selector (no fresh `?? []`). */
const NO_OPEN_FILES: { path: string; cursor?: { line: number; column: number } }[] = []

export interface QuickOpenProps {
  instanceId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  onOpenFile: (path: string) => void
}

interface Row {
  path: string
  name: ReactNode
  recent: boolean
}

export function QuickOpen({ instanceId, open, onOpenChange, onOpenFile }: QuickOpenProps) {
  const tree = useFilesStore((s) => s.trees[instanceId])
  const docs = useFilesStore((s) => s.docs[instanceId])
  const openFiles = useWorkspaceStore((s) => s.openFiles[instanceId] ?? NO_OPEN_FILES)
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  // Reset on open (derived-state-during-render pattern).
  const [wasOpen, setWasOpen] = useState(false)
  if (open !== wasOpen) {
    setWasOpen(open)
    if (open) {
      setQuery('')
      setActiveIndex(0)
    }
  }
  useEffect(() => {
    // Load the tree lazily so quick open works before the panel painted.
    if (open) void useFilesStore.getState().loadTree(instanceId)
  }, [open, instanceId])

  const allPaths = useMemo(() => flattenFilePaths(tree?.nodes), [tree?.nodes])
  const dirtySet = useMemo(() => new Set(dirtyPathsOf(docs)), [docs])

  const rows = useMemo<Row[]>(() => {
    const trimmed = query.trim()
    if (!trimmed) {
      // Recents = currently open files (tab order), then the rest alphabetically.
      const recents = openFiles.map((f) => f.path).filter((p) => allPaths.includes(p))
      const rest = allPaths.filter((p) => !recents.includes(p)).sort()
      return [...recents.map((path) => ({ path, name: path.split('/').pop() ?? path, recent: true })),
        ...rest.map((path) => ({ path, name: path.split('/').pop() ?? path, recent: false }))]
    }
    const results = fuzzysort.go(trimmed, allPaths, { threshold: -10_000, limit: 50 })
    return results.map((result) => ({
      path: result.target,
      name: (
        <>
          {result.highlight((m: string, i: number) => (
            <mark key={i} className="bg-transparent font-semibold text-foreground">
              {m}
            </mark>
          ))}
        </>
      ),
      recent: false,
    }))
  }, [query, allPaths, openFiles])

  const pick = (path: string) => {
    onOpenChange(false)
    onOpenFile(path)
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActiveIndex((i) => Math.min(rows.length - 1, i + 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActiveIndex((i) => Math.max(0, i - 1))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const row = rows[Math.min(activeIndex, rows.length - 1)]
      if (row) pick(row.path)
    }
  }

  useEffect(() => {
    listRef.current
      ?.querySelector(`[data-index="${activeIndex}"]`)
      ?.scrollIntoView({ block: 'nearest' })
  }, [activeIndex])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="top-[12vh] w-[min(560px,92vw)] translate-y-0 gap-0 overflow-hidden rounded-lg border-border bg-surface p-0 shadow-2 sm:max-w-[min(560px,92vw)]"
        showCloseButton={false}
        onOpenAutoFocus={(e) => {
          e.preventDefault()
          inputRef.current?.focus()
        }}
        data-testid="quick-open"
      >
        <DialogTitle className="sr-only">Quick open file</DialogTitle>
        <div className="flex h-11 items-center gap-2 border-b border-border px-3">
          <FileSearch className="size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setActiveIndex(0)
            }}
            onKeyDown={onKeyDown}
            placeholder="Quick open file by name…"
            aria-label="Quick open file"
            role="combobox"
            aria-expanded="true"
            aria-controls="quick-open-list"
            aria-activedescendant={rows[activeIndex] ? `quick-open-row-${rows[activeIndex].path}` : undefined}
            className="min-w-0 flex-1 bg-transparent text-sm text-foreground outline-none placeholder:text-foreground-tertiary"
            spellCheck={false}
            autoComplete="off"
          />
        </div>
        <div ref={listRef} role="listbox" id="quick-open-list" aria-label="Files" className="max-h-[50vh] overflow-y-auto p-1">
          {rows.length === 0 ? (
            <p className="px-3 py-6 text-center text-sm text-foreground-secondary">
              {query.trim() ? 'No files match.' : 'No files in this project yet.'}
            </p>
          ) : (
            rows.map((row, index) => (
              <button
                key={row.path}
                type="button"
                role="option"
                id={`quick-open-row-${row.path}`}
                aria-selected={index === activeIndex}
                data-index={index}
                data-testid={`quick-open-row-${row.path}`}
                className={cn(
                  'flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm outline-none transition-colors duration-instant',
                  index === activeIndex ? 'bg-active text-foreground' : 'text-foreground-secondary hover:bg-hover',
                )}
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => pick(row.path)}
              >
                <FileGlyph path={row.path} kind="file" className="size-4 shrink-0 text-foreground-secondary" />
                <span className="min-w-0 flex-1 truncate">
                  {row.name}
                  <span className="tnum ml-2 font-mono text-xs text-foreground-tertiary">{row.path}</span>
                </span>
                {dirtySet.has(row.path) ? <CircleDot className="size-3 shrink-0 text-accent" aria-label="Unsaved changes" /> : null}
              </button>
            ))
          )}
        </div>
        <div className="flex h-7 items-center gap-3 border-t border-border px-3 text-xs text-foreground-tertiary">
          <span className="flex items-center gap-1">
            <Kbd>↑↓</Kbd> navigate
          </span>
          <span className="flex items-center gap-1">
            <Kbd>↵</Kbd> open
          </span>
          <span className="flex items-center gap-1">
            <Kbd>esc</Kbd> close
          </span>
        </div>
      </DialogContent>
    </Dialog>
  )
}
