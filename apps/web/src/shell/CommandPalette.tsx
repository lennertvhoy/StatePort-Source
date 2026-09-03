/**
 * CommandPalette (design.md §9.6) — Ctrl/Cmd+K modal: fuzzy-matched
 * (fuzzysort), grouped results, context- and capability-aware (unavailable
 * commands are omitted via their `when` gate), recents on empty query,
 * arrow-key navigation, Enter executes, Escape closes with focus restored.
 */
import { Command as CommandIcon } from 'lucide-react'
import fuzzysort from 'fuzzysort'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { ReactNode } from 'react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { Kbd } from '@/components'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import { useSessionStore } from '@/state'

import type { ShellCommand } from './commands'
import { availableCommands, COMMAND_GROUP_ORDER, useCommandStore } from './commands'
import { formatChord } from './platform'

type Row =
  | { type: 'header'; id: string; label: string }
  | { type: 'command'; id: string; command: ShellCommand; title: ReactNode }

/** Group commands in the canonical order; empty groups are dropped. */
function groupRows(commands: ShellCommand[], titleFor: (c: ShellCommand) => ReactNode, recentIds: string[], emptyQuery: boolean): Row[] {
  const rows: Row[] = []
  if (emptyQuery && recentIds.length > 0) {
    const recents = recentIds
      .map((id) => commands.find((c) => c.id === id))
      .filter((c): c is ShellCommand => Boolean(c))
    if (recents.length > 0) {
      rows.push({ type: 'header', id: 'h:Recent', label: 'Recent' })
      for (const command of recents) rows.push({ type: 'command', id: command.id, command, title: titleFor(command) })
    }
  }
  for (const group of COMMAND_GROUP_ORDER) {
    const inGroup = commands.filter((c) => c.group === group)
    if (inGroup.length === 0) continue
    rows.push({ type: 'header', id: `h:${group}`, label: group })
    for (const command of inGroup) rows.push({ type: 'command', id: command.id, command, title: titleFor(command) })
  }
  return rows
}

export function CommandPalette() {
  const open = useCommandStore((s) => s.paletteOpen)
  const setOpen = useCommandStore((s) => s.setPaletteOpen)
  const commands = useCommandStore((s) => s.commands)
  const recents = useCommandStore((s) => s.recents)
  const recordRun = useCommandStore((s) => s.recordRun)
  const pushToast = useSessionStore((s) => s.pushToast)

  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (open) {
      setQuery('')
      setActiveIndex(0)
    }
  }, [open])

  const available = useMemo(() => (open ? availableCommands(commands) : []), [commands, open])

  const rows = useMemo<Row[]>(() => {
    const trimmed = query.trim()
    if (!trimmed) {
      return groupRows(available, (c) => c.title, recents, true)
    }
    const results = fuzzysort.go(trimmed, available, {
      keys: ['title', (c: ShellCommand) => (c.keywords ?? []).join(' ')],
      threshold: -10_000,
      limit: 60,
    })
    const withHighlight = results.map((result) => ({
      command: result.obj,
      title: result[0].highlight((match, i) => (
        <span key={i} className="font-semibold text-foreground">
          {match}
        </span>
      )) as ReactNode,
    }))
    return groupRows(
      withHighlight.map((r) => r.command),
      (c) => withHighlight.find((r) => r.command === c)?.title ?? c.title,
      [],
      false,
    )
  }, [available, query, recents])

  const selectable = useMemo(() => rows.filter((r): r is Extract<Row, { type: 'command' }> => r.type === 'command'), [rows])

  useEffect(() => {
    setActiveIndex(0)
  }, [rows.length, query])

  // TanStack Virtual intentionally owns mutable measurement callbacks; React
  // Compiler safely leaves this component un-memoized.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: (index) => (rows[index]?.type === 'header' ? 28 : 36),
    overscan: 8,
  })

  useEffect(() => {
    const row = selectable[activeIndex]
    if (!row) return
    const flatIndex = rows.findIndex((r) => r.id === row.id)
    if (flatIndex >= 0) virtualizer.scrollToIndex(flatIndex, { align: 'auto' })
  }, [activeIndex, selectable, rows, virtualizer])

  const runCommand = async (command: ShellCommand) => {
    setOpen(false)
    recordRun(command.id)
    try {
      await command.run()
    } catch (error) {
      pushToast({
        kind: 'error',
        title: `Command failed: ${command.title}`,
        body: error instanceof Error ? error.message : String(error),
      })
    }
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActiveIndex((i) => Math.min(i + 1, selectable.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActiveIndex((i) => Math.max(i - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const row = selectable[activeIndex]
      if (row) void runCommand(row.command)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent
        showCloseButton={false}
        className="fixed left-1/2 top-[12vh] z-palette flex w-[640px] max-w-[92vw] -translate-x-1/2 flex-col gap-0 overflow-hidden rounded-lg border border-border bg-surface p-0 shadow-2 duration-med ease-enter data-[state=open]:slide-in-from-top-2 data-[state=open]:fade-in-0"
        aria-label="Command palette"
        data-testid="command-palette"
        onOpenAutoFocus={(e) => {
          e.preventDefault()
          inputRef.current?.focus()
        }}
      >
        <DialogTitle className="sr-only">Command palette</DialogTitle>
        <div className="flex h-11 items-center gap-2 border-b border-border px-3">
          <CommandIcon className="size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Search or command…"
            aria-label="Search commands"
            aria-expanded="true"
            aria-controls="command-palette-list"
            role="combobox"
            aria-activedescendant={selectable[activeIndex] ? `cmd-${selectable[activeIndex].id}` : undefined}
            className="h-full min-w-0 flex-1 bg-transparent text-sm text-foreground outline-none placeholder:text-foreground-tertiary"
            spellCheck={false}
            autoComplete="off"
          />
        </div>

        <div ref={scrollRef} className="max-h-[50vh] overflow-y-auto" id="command-palette-list" role="listbox" aria-label="Commands">
          {selectable.length === 0 ? (
            <p className="px-3 py-6 text-center text-sm text-foreground-secondary">No matching commands.</p>
          ) : (
            <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
              {virtualizer.getVirtualItems().map((virtualRow) => {
                const row = rows[virtualRow.index]
                if (!row) return null
                if (row.type === 'header') {
                  return (
                    <div
                      key={row.id}
                      className="flex items-center px-3 text-xs font-medium text-foreground-secondary"
                      style={{ position: 'absolute', top: virtualRow.start, left: 0, right: 0, height: virtualRow.size }}
                    >
                      {row.label}
                    </div>
                  )
                }
                const commandIndex = selectable.findIndex((r) => r.id === row.id)
                const active = commandIndex === activeIndex
                const Icon = row.command.icon
                return (
                  <div
                    key={row.id}
                    id={`cmd-${row.id}`}
                    role="option"
                    aria-selected={active}
                    // Focus stays on the combobox input (aria-activedescendant);
                    // options are programmatically focusable and Enter-activable.
                    tabIndex={-1}
                    className={cn(
                      'flex cursor-pointer items-center gap-2 px-3',
                      active ? 'bg-accent-soft text-accent-soft-text' : 'text-foreground',
                    )}
                    style={{ position: 'absolute', top: virtualRow.start, left: 0, right: 0, height: virtualRow.size }}
                    onMouseMove={() => setActiveIndex(commandIndex)}
                    onClick={() => void runCommand(row.command)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        void runCommand(row.command)
                      }
                    }}
                    data-testid="command-row"
                  >
                    {Icon ? <Icon className={cn('size-4 shrink-0', active ? 'text-accent' : 'text-foreground-secondary')} aria-hidden="true" /> : null}
                    <span className="min-w-0 flex-1 truncate text-sm">{row.title}</span>
                    {row.command.shortcut ? <Kbd>{formatChord(row.command.shortcut)}</Kbd> : null}
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <div className="flex items-center gap-3 border-t border-border px-3 py-1.5 text-xs text-foreground-tertiary">
          <span className="inline-flex items-center gap-1">
            <Kbd>↑↓</Kbd> navigate
          </span>
          <span className="inline-flex items-center gap-1">
            <Kbd>↵</Kbd> select
          </span>
          <span className="inline-flex items-center gap-1">
            <Kbd>esc</Kbd> close
          </span>
        </div>
      </DialogContent>
    </Dialog>
  )
}
