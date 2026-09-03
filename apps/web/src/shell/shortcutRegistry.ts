/**
 * Shortcut action registry — the non-component half of the global keyboard
 * handler (design.md §9.7). Actions register by id via useShortcutAction;
 * scopes activate by route context via useShortcutScope. Kept outside
 * KeyboardShortcuts.tsx so the component module stays a clean fast-refresh
 * boundary.
 */
import { useEffect, useRef } from 'react'

import type { ShortcutScope } from '@/state'
import { SHORTCUT_COMMANDS } from '@/state'

interface RegisteredAction {
  handler: () => void
  enabled: () => boolean
}

const actionRegistry = new Map<string, RegisteredAction>()
const activeScopes = new Set<ShortcutScope>(['global'])

/** Read the registered action for a command id (global keydown handler). */
export function getShortcutAction(id: string): RegisteredAction | undefined {
  return actionRegistry.get(id)
}

/** Register the handler for a shortcut command id (from SHORTCUT_COMMANDS). */
export function useShortcutAction(id: string, handler: () => void, opts?: { enabled?: boolean }): void {
  const handlerRef = useRef(handler)
  const enabledRef = useRef(opts?.enabled ?? true)

  // Refs update in effects, never during render.
  useEffect(() => {
    handlerRef.current = handler
    enabledRef.current = opts?.enabled ?? true
  }, [handler, opts?.enabled])

  useEffect(() => {
    actionRegistry.set(id, { handler: () => handlerRef.current(), enabled: () => enabledRef.current })
    return () => {
      actionRegistry.delete(id)
    }
  }, [id])
}

/** Activate a shortcut scope while mounted (e.g. WorkbenchShell → 'workbench'). */
export function useShortcutScope(scope: ShortcutScope, active = true): void {
  useEffect(() => {
    if (!active) return
    activeScopes.add(scope)
    return () => {
      activeScopes.delete(scope)
    }
  }, [scope, active])
}

/** Test seam: inspect which command id a chord currently resolves to. */
export function resolveChord(chord: string, keysById: Record<string, string>): string | null {
  let globalMatch: string | null = null
  for (const cmd of SHORTCUT_COMMANDS) {
    if (keysById[cmd.id] !== chord) continue
    if (cmd.scope === 'global') {
      globalMatch = globalMatch ?? cmd.id
    } else if (activeScopes.has(cmd.scope)) {
      return cmd.id // scoped commands win over global
    }
  }
  return globalMatch
}
