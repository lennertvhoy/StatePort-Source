/**
 * Shortcut conflict detection — rebinding onto another command's chord is
 * rejected with a plain-language error; the resolved list exposes conflicts.
 */
import { afterEach, describe, expect, it } from 'vitest'

import { SHORTCUT_COMMANDS, useShortcutsStore } from '@/state'

afterEach(() => {
  useShortcutsStore.getState().resetAll()
})

describe('shortcut conflict detection', () => {
  it('rejects a chord already bound to another command', () => {
    // global.command_palette owns mod+k by default.
    const result = useShortcutsStore.getState().rebind('global.open_settings', 'mod+k')
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.error).toMatch(/Command palette/i)
    // The rejected rebind did not take.
    expect(useShortcutsStore.getState().keysFor('global.open_settings')).toBe('mod+,')
  })

  it('conflicts only apply within the same scope', () => {
    // workbench.toggle_bottom_panel owns mod+j in the workbench scope.
    const taken = useShortcutsStore.getState().rebind('workbench.toggle_terminal', 'mod+j')
    expect(taken.ok).toBe(false)
    // The same chord is free in the global scope.
    const otherScope = useShortcutsStore.getState().rebind('global.open_settings', 'mod+j')
    expect(otherScope.ok).toBe(true)
  })

  it('allows rebinding to a free chord and resetting to defaults', () => {
    const result = useShortcutsStore.getState().rebind('global.toggle_sidebar', 'mod+shift+b')
    expect(result.ok).toBe(true)
    // Rebound chords are stored normalized (modifier-sorted).
    expect(useShortcutsStore.getState().keysFor('global.toggle_sidebar')).toBe('shift+mod+b')
    const row = useShortcutsStore
      .getState()
      .list()
      .find((r) => r.id === 'global.toggle_sidebar')
    expect(row?.overridden).toBe(true)
    useShortcutsStore.getState().reset('global.toggle_sidebar')
    expect(useShortcutsStore.getState().keysFor('global.toggle_sidebar')).toBe('mod+b')
  })

  it('every default chord is unique per scope (no shipped conflicts)', () => {
    const byScope = new Map<string, Set<string>>()
    for (const cmd of SHORTCUT_COMMANDS) {
      const seen = byScope.get(cmd.scope) ?? new Set<string>()
      expect(seen.has(cmd.defaultKeys)).toBe(false)
      seen.add(cmd.defaultKeys)
      byScope.set(cmd.scope, seen)
    }
    for (const row of useShortcutsStore.getState().list()) {
      expect(row.conflictWith).toBeNull()
    }
  })

  it('rejects chords reserved by the browser', () => {
    const result = useShortcutsStore.getState().rebind('global.toggle_sidebar', 'mod+w')
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.error).toMatch(/reserved/i)
  })
})
