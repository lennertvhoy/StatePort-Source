/**
 * FindBar — terminal output search (terminal.md: floating top-right, search
 * addon, match count, prev/next, Esc closes; Ctrl/Cmd+F opens).
 */
import { ChevronDown, ChevronUp, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

import { Tooltip } from '@/components'
import { cn } from '@/lib/utils'

import type { SessionRuntime } from './sessionRuntime'
import { getRuntime } from './sessionRuntime'

function literalMatchCount(text: string, query: string): number {
  if (!query) return 0
  const haystack = text.toLocaleLowerCase()
  const needle = query.toLocaleLowerCase()
  let count = 0
  let offset = 0
  while (offset <= haystack.length - needle.length) {
    const found = haystack.indexOf(needle, offset)
    if (found < 0) break
    count += 1
    offset = found + Math.max(needle.length, 1)
  }
  return count
}

export interface FindBarProps {
  /** Manager tab key — the bar resolves the live runtime from the registry. */
  tabKey: string
  onClose: () => void
}

export function FindBar({ tabKey, onClose }: FindBarProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<{ index: number; count: number } | null>(null)
  const [matched, setMatched] = useState<boolean | null>(null)
  const [bufferMatchCount, setBufferMatchCount] = useState<number | null>(null)
  const runtime: SessionRuntime | undefined = getRuntime(tabKey)

  useEffect(() => {
    inputRef.current?.focus()
    inputRef.current?.select()
    if (!runtime) return
    return runtime.onSearchResults((result) => {
      setResults(result ? { index: result.resultIndex, count: result.resultCount } : null)
      // Some xterm renderer paths can select a valid result before the
      // optional decoration counter has populated. Never let a transient
      // zero-count event overwrite the direct boolean search result.
      if (result && result.resultCount > 0) setMatched(true)
    })
  }, [runtime])

  useEffect(() => () => runtime?.clearSearch(), [runtime])

  if (!runtime) return null

  const search = (direction: 'next' | 'previous') => {
    const q = query
    if (!q) {
      runtime.clearSearch()
      setResults(null)
      setMatched(null)
      setBufferMatchCount(null)
      return
    }
    const count = literalMatchCount(runtime.exportText(), q)
    setBufferMatchCount(count)
    if (direction === 'next') {
      const found = runtime.findNext(q, { incremental: true })
      setMatched(found || count > 0)
    } else {
      const found = runtime.findPrevious(q)
      setMatched(found || count > 0)
    }
  }

  return (
    <div
      className="absolute top-2 right-3 z-ribbon flex items-center gap-1 rounded-md border border-border bg-surface p-1 shadow-1"
      role="search"
      aria-label="Search terminal output"
      data-testid="terminal-find-bar"
    >
      <input
        ref={inputRef}
        value={query}
        onChange={(e) => {
          setQuery(e.target.value)
          if (!e.target.value) {
            runtime.clearSearch()
            setResults(null)
            setMatched(null)
            setBufferMatchCount(null)
          }
        }}
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            e.stopPropagation()
            onClose()
          } else if (e.key === 'Enter') {
            search(e.shiftKey ? 'previous' : 'next')
          }
        }}
        placeholder="Find in output"
        aria-label="Find in terminal output"
        className="h-control-sm w-44 rounded-sm border border-input bg-surface px-2 text-sm text-foreground outline-none placeholder:text-foreground-tertiary focus-visible:border-accent"
        data-testid="terminal-find-input"
      />
      <span className={cn('min-w-12 text-center text-xs text-foreground-tertiary tnum')} aria-live="polite">
        {results && results.count > 0 && query
          ? `${results.index + 1}/${results.count}`
          : query
            ? bufferMatchCount !== null
              ? `${bufferMatchCount} ${bufferMatchCount === 1 ? 'match' : 'matches'}`
              : matched
                ? 'Match'
                : '0/0'
            : ''}
      </span>
      <Tooltip content="Previous match · Shift+Enter">
        <button
          type="button"
          aria-label="Previous match"
          onClick={() => search('previous')}
          className="inline-flex min-h-7 min-w-7 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <ChevronUp className="size-4" aria-hidden="true" />
        </button>
      </Tooltip>
      <Tooltip content="Next match · Enter">
        <button
          type="button"
          aria-label="Next match"
          onClick={() => search('next')}
          className="inline-flex min-h-7 min-w-7 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <ChevronDown className="size-4" aria-hidden="true" />
        </button>
      </Tooltip>
      <Tooltip content="Close · Esc">
        <button
          type="button"
          aria-label="Close find"
          onClick={onClose}
          className="inline-flex min-h-7 min-w-7 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <X className="size-4" aria-hidden="true" />
        </button>
      </Tooltip>
    </div>
  )
}
