/**
 * Shortcuts group — the full shortcut list from the shortcuts store with
 * search, click-to-rebind capture, conflict detection with “Reassign anyway”,
 * per-row reset, and reset-all (ConfirmDialog). Platform-aware labels via
 * the shell's formatChord.
 */
import { RotateCcw, TriangleAlert } from 'lucide-react'
import { useMemo, useState } from 'react'

import { ConfirmDialog, Kbd } from '@/components'
import { Button } from '@/components/ui/button'
import { normalizeKeys, useShortcutsStore } from '@/state'
import type { ShortcutView } from '@/state'
import { chordFromEvent, formatChord } from '@/shell/platform'

import { SettingSubsection } from './controls'

const GROUP_ORDER = ['Global', 'Workbench', 'Files', 'Conversation', 'Terminal'] as const

/** Modifiers tried (in order) when a displaced default needs a new home. */
const SPARE_MODIFIERS = ['shift', 'alt', 'ctrl'] as const

interface RebindError {
  commandId: string
  chord: string
  message: string
  /** True when the error is a same-scope conflict that can be reassigned. */
  conflictId: string | null
}

/** Find a free chord for a displaced command: its keys plus a spare modifier. */
function findFreeChord(cmd: ShortcutView, list: readonly ShortcutView[]): string | null {
  const base = normalizeKeys(cmd.keys)
  if (!base) return null
  const baseParts = base.split('+')
  const taken = new Set(list.filter((c) => c.scope === cmd.scope && c.id !== cmd.id).map((c) => c.keys))
  const candidates: string[] = []
  for (const mod of SPARE_MODIFIERS) {
    if (!baseParts.includes(mod)) candidates.push(normalizeKeys([mod, ...baseParts].join('+')) ?? '')
  }
  for (const a of SPARE_MODIFIERS) {
    for (const b of SPARE_MODIFIERS) {
      if (a !== b && !baseParts.includes(a) && !baseParts.includes(b)) {
        candidates.push(normalizeKeys([a, b, ...baseParts].join('+')) ?? '')
      }
    }
  }
  for (const candidate of candidates) {
    if (!candidate) continue
    if (cmd.dangerous && !candidate.includes('+')) continue
    if (!taken.has(candidate) && candidate !== base) return candidate
  }
  return null
}

export function ShortcutsGroup() {
  useShortcutsStore((s) => s.overrides) // re-render on any rebinding change
  const [query, setQuery] = useState('')
  const [capturingId, setCapturingId] = useState<string | null>(null)
  const [error, setError] = useState<RebindError | null>(null)
  const [note, setNote] = useState<string | null>(null)
  const [confirmResetAll, setConfirmResetAll] = useState(false)

  const list = useShortcutsStore.getState().list()

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = q
      ? list.filter((cmd) => cmd.label.toLowerCase().includes(q) || formatChord(cmd.keys).toLowerCase().includes(q))
      : list
    return GROUP_ORDER.map((group) => ({ group, rows: filtered.filter((cmd) => cmd.group === group) })).filter(
      (g) => g.rows.length > 0,
    )
  }, [list, query])

  const attemptRebind = (commandId: string, rawChord: string) => {
    const chord = normalizeKeys(rawChord)
    if (!chord) {
      setError({ commandId, chord: rawChord, message: `“${rawChord}” is not a valid shortcut.`, conflictId: null })
      return
    }
    const result = useShortcutsStore.getState().rebind(commandId, chord)
    if (result.ok) {
      setCapturingId(null)
      setError(null)
      setNote(null)
      return
    }
    const view = useShortcutsStore.getState().list()
    const target = view.find((c) => c.id === commandId)
    const conflict = target
      ? view.find((c) => c.id !== commandId && c.scope === target.scope && c.keys === chord)
      : undefined
    setError({ commandId, chord, message: result.error, conflictId: conflict?.id ?? null })
    setNote(null)
  }

  const reassignAnyway = (commandId: string, chord: string, conflictId: string) => {
    const store = useShortcutsStore.getState()
    const view = store.list()
    const conflict = view.find((c) => c.id === conflictId)
    if (!conflict) {
      attemptRebind(commandId, chord)
      return
    }
    let resolution: string
    if (conflict.overridden) {
      // The other binding was customized — clearing it restores its default.
      store.reset(conflict.id)
      resolution = `“${conflict.label}” was reset to its default (${formatChord(conflict.defaultKeys)}).`
    } else {
      // The other binding is a default — move it to the nearest free chord.
      const free = findFreeChord(conflict, view)
      if (!free) {
        setError({
          commandId,
          chord,
          message: `Could not find a free shortcut for “${conflict.label}”. Pick a different chord.`,
          conflictId: null,
        })
        return
      }
      const moved = useShortcutsStore.getState().rebind(conflict.id, free)
      if (!moved.ok) {
        setError({ commandId, chord, message: moved.error, conflictId: null })
        return
      }
      resolution = `“${conflict.label}” moved to ${formatChord(free)}.`
    }
    const result = useShortcutsStore.getState().rebind(commandId, chord)
    if (result.ok) {
      setCapturingId(null)
      setError(null)
      setNote(resolution)
    } else {
      setError({ commandId, chord, message: result.error, conflictId: null })
    }
  }

  return (
    <div className="flex flex-col gap-5" data-testid="settings-group-shortcuts">
      <div>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search shortcuts…"
          aria-label="Search shortcuts"
          className="h-control w-full max-w-sm rounded-sm border border-input bg-surface px-2 text-sm text-foreground outline-none placeholder:text-foreground-tertiary focus-visible:border-focus"
          spellCheck={false}
          data-testid="shortcut-search"
        />
      </div>

      {note ? (
        <p className="text-xs text-foreground-secondary" role="status">
          {note}
        </p>
      ) : null}

      {groups.length === 0 ? (
        <p className="py-4 text-sm text-foreground-secondary">No shortcuts match “{query}”.</p>
      ) : (
        groups.map(({ group, rows }) => (
          <SettingSubsection key={group} title={`${group} shortcuts`}>
            <ul className="flex flex-col" data-testid={`shortcut-group-${group.toLowerCase()}`}>
              {rows.map((cmd) => {
                const capturing = capturingId === cmd.id
                const rowError = error?.commandId === cmd.id ? error : null
                const conflictLabel = cmd.conflictWith
                  ? (list.find((c) => c.id === cmd.conflictWith)?.label ?? cmd.conflictWith)
                  : null
                return (
                  <li key={cmd.id} className="border-b border-border/60 py-2 last:border-b-0">
                    <div className="flex min-h-11 flex-wrap items-center justify-between gap-x-6 gap-y-2">
                      <div className="min-w-0 flex-1 basis-52">
                        <span className="block text-sm font-medium text-foreground">{cmd.label}</span>
                        <span className="mt-0.5 block text-xs text-foreground-secondary">
                          {cmd.scope === 'global' ? 'Everywhere' : `Scope: ${cmd.scope}`}
                          {cmd.overridden ? ' · customized' : ''}
                        </span>
                        {conflictLabel ? (
                          <span className="mt-0.5 flex items-center gap-1 text-xs text-status-danger">
                            <TriangleAlert className="size-3 shrink-0" aria-hidden="true" />
                            Also bound to “{conflictLabel}” in this scope
                          </span>
                        ) : null}
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        {capturing ? (
                          <input
                            ref={(el) => el?.focus()}
                            readOnly
                            value=""
                            placeholder="Press keys…"
                            aria-label={`New shortcut for ${cmd.label}`}
                            onKeyDown={(e) => {
                              e.preventDefault()
                              e.stopPropagation()
                              if (e.key === 'Escape') {
                                setCapturingId(null)
                                setError(null)
                                return
                              }
                              const chord = chordFromEvent(e.nativeEvent)
                              if (chord) attemptRebind(cmd.id, chord)
                            }}
                            onBlur={() => {
                              if (capturingId === cmd.id) setCapturingId(null)
                            }}
                            className="h-control w-44 rounded-sm border border-accent bg-surface px-2 text-sm text-foreground outline-none placeholder:text-foreground-tertiary"
                            data-testid={`shortcut-capture-${cmd.id}`}
                          />
                        ) : (
                          <button
                            type="button"
                            onClick={() => {
                              setCapturingId(cmd.id)
                              setError(null)
                              setNote(null)
                            }}
                            aria-label={`Rebind ${cmd.label}, currently ${formatChord(cmd.keys)}`}
                            className="rounded-xs outline-none transition-colors duration-instant hover:bg-hover focus-visible:ring-2 focus-visible:ring-focus"
                            data-testid={`shortcut-rebind-${cmd.id}`}
                          >
                            <Kbd>{formatChord(cmd.keys)}</Kbd>
                          </button>
                        )}
                        {cmd.overridden ? (
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label={`Reset ${cmd.label} to default`}
                            onClick={() => {
                              useShortcutsStore.getState().reset(cmd.id)
                              setError(null)
                            }}
                            data-testid={`shortcut-reset-${cmd.id}`}
                          >
                            <RotateCcw className="size-3.5" aria-hidden="true" />
                          </Button>
                        ) : null}
                      </div>
                    </div>
                    {rowError ? (
                      <div className="mt-1.5 flex flex-wrap items-center gap-2" role="alert">
                        <p className="flex items-center gap-1 text-xs text-status-danger">
                          <TriangleAlert className="size-3 shrink-0" aria-hidden="true" />
                          {formatChord(rowError.chord)} — {rowError.message}
                        </p>
                        {rowError.conflictId ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => reassignAnyway(rowError.commandId, rowError.chord, rowError.conflictId!)}
                            data-testid="shortcut-reassign-anyway"
                          >
                            Reassign anyway
                          </Button>
                        ) : null}
                      </div>
                    ) : null}
                  </li>
                )
              })}
            </ul>
          </SettingSubsection>
        ))
      )}

      <div className="flex items-center justify-between gap-3 border-t border-border pt-4">
        <p className="text-xs text-foreground-secondary">
          Chords the browser owns (like {formatChord('mod+w')} or {formatChord('mod+t')}) can never be bound.
        </p>
        <Button variant="outline" size="sm" onClick={() => setConfirmResetAll(true)} data-testid="shortcut-reset-all">
          Reset all shortcuts
        </Button>
      </div>

      <ConfirmDialog
        open={confirmResetAll}
        onOpenChange={setConfirmResetAll}
        title="Reset all shortcuts?"
        description="Every customized key binding returns to its default."
        effect="All shortcut overrides are removed."
        reversibility="You can rebind any shortcut again afterwards."
        confirmLabel="Reset all"
        onConfirm={() => {
          useShortcutsStore.getState().resetAll()
          setError(null)
          setNote(null)
        }}
      />
    </div>
  )
}

