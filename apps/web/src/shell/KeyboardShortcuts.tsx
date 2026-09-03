/**
 * KeyboardShortcuts — the global keyboard handler (design.md §9.7).
 *
 * - Wired to useShortcutsStore (effective, rebindable chords).
 * - Platform-aware: `mod` = Cmd on macOS, Ctrl elsewhere.
 * - IME-safe (skips composing events) and input-safe: chords without a
 *   modifier never fire from editable targets; explicit chords do.
 * - Escape closes the topmost escape layer (overlays, then focus mode).
 * - `?` opens the shortcuts reference (never in editable targets).
 *
 * Actions are registered by id via useShortcutAction; scopes are activated
 * by route context via useShortcutScope ('workbench' while on workbench
 * routes; 'files'/'conversation'/'terminal' by feature tools).
 */
import { useEffect } from 'react'

import { normalizeKeys, SHORTCUT_COMMANDS, useShortcutsStore } from '@/state'

import { escapeTopLayer } from './escape'
import { chordFromEvent, isEditableTarget } from './platform'
import { getShortcutAction, resolveChord } from './shortcutRegistry'

// ── Global handler ───────────────────────────────────────────────────────────

export function KeyboardShortcuts() {
  const overrides = useShortcutsStore((s) => s.overrides)

  useEffect(() => {
    // Both sides are normalized through the store's normalizeKeys so modifier
    // order differences ('mod+shift+enter' vs 'shift+mod+enter') can't miss.
    const keysById: Record<string, string> = Object.fromEntries(
      SHORTCUT_COMMANDS.map((cmd) => [cmd.id, normalizeKeys(overrides[cmd.id] ?? cmd.defaultKeys) ?? cmd.defaultKeys]),
    )

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.isComposing) return // IME-safe

      // Escape: overlays first (topmost layer), then registered close action.
      if (e.key === 'Escape') {
        if (escapeTopLayer()) {
          e.preventDefault()
          return
        }
        const close = getShortcutAction('global.close_overlay')
        if (close?.enabled()) {
          close.handler()
          e.preventDefault()
        }
        return
      }

      const rawChord = chordFromEvent(e)
      if (!rawChord) return
      const chord = normalizeKeys(rawChord) ?? rawChord

      const editable = isEditableTarget(e.target)
      const hasModifier = e.metaKey || e.ctrlKey || e.altKey
      // Input-safe: bare keys (incl. '?') never fire from editable targets.
      if (editable && !hasModifier) return

      const commandId = resolveChord(chord, keysById)
      if (!commandId) return
      const action = getShortcutAction(commandId)
      if (!action || !action.enabled()) return
      e.preventDefault()
      action.handler()
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [overrides])

  return null
}
