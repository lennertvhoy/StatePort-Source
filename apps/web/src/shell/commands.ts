/**
 * Command registry — THE contract feature agents use to surface commands in
 * the command palette (design.md §9.6).
 *
 * ```tsx
 * useRegisterCommands([
 *   { id: 'files.save_preview', title: 'Open save preview', group: 'Actions',
 *     shortcut: 'mod+s', icon: Save, run: openSavePreview,
 *     when: () => capabilityAvailable('editor') },
 * ])
 * ```
 *
 * - Registration is scoped to the calling component: commands auto-unregister
 *   on unmount. Pass a stable (memoized) array.
 * - `when` gates availability — unavailable capabilities must never appear in
 *   the palette (omit, never disable — §2.8).
 * - `shortcut` is a normalized chord (`mod+k`) rendered platform-aware; the
 *   shortcut itself is wired via useShortcutAction / the shortcuts store.
 * - Destructive commands must never be palette one-hitters: `run` should open
 *   the relevant ConfirmDialog instead of performing the action (§9.6).
 */
import type { LucideIcon } from 'lucide-react'
import { useEffect } from 'react'
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type ShellCommandGroup =
  | 'Navigation'
  | 'Applications'
  | 'Workbench tools'
  | 'Actions'
  | 'Settings'
  | 'Help'

/** Palette group display order (design.md §9.6). */
export const COMMAND_GROUP_ORDER: readonly ShellCommandGroup[] = [
  'Navigation',
  'Applications',
  'Workbench tools',
  'Actions',
  'Settings',
  'Help',
]

export interface ShellCommand {
  id: string
  title: string
  group: ShellCommandGroup
  icon?: LucideIcon
  /** Normalized chord for display (`mod+k`); platform-aware rendering is automatic. */
  shortcut?: string
  keywords?: string[]
  run: () => void | Promise<void>
  /** Availability gate — return false to omit the command entirely. */
  when?: () => boolean
}

interface CommandRegistryState {
  /** id → command (last registration wins; registrations are namespaced by id). */
  commands: Record<string, ShellCommand>
  paletteOpen: boolean
  shortcutsOpen: boolean
  /** Recent command ids (most recent first; shown on empty query). */
  recents: string[]
  register(commands: readonly ShellCommand[]): () => void
  setPaletteOpen(open: boolean): void
  setShortcutsOpen(open: boolean): void
  recordRun(id: string): void
}

export const useCommandStore = create<CommandRegistryState>()(
  persist(
    (set, get) => ({
      commands: {},
      paletteOpen: false,
      shortcutsOpen: false,
      recents: [],

      register: (commands) => {
        const ids = commands.map((c) => c.id)
        set((s) => ({
          commands: {
            ...s.commands,
            ...Object.fromEntries(commands.map((c) => [c.id, c])),
          },
        }))
        return () => {
          set((s) => {
            const next = { ...s.commands }
            for (const id of ids) {
              // Only remove when the entry is still the one this registration added.
              const registered = commands.find((c) => c.id === id)
              if (registered && next[id] === registered) delete next[id]
            }
            return { commands: next }
          })
        }
      },

      setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
      setShortcutsOpen: (shortcutsOpen) => set({ shortcutsOpen }),

      recordRun: (id) => {
        if (!get().commands[id]) return
        set((s) => ({ recents: [id, ...s.recents.filter((r) => r !== id)].slice(0, 8) }))
      },
    }),
    {
      name: 'stateport.commands.v1',
      version: 1,
      // Only recents persist — commands/functions are runtime registrations.
      partialize: (s) => ({ recents: s.recents }),
    },
  ),
)

/**
 * Register palette commands for the lifetime of the calling component.
 * Auto-unregisters on unmount. Pass a stable array (useMemo) to avoid churn.
 */
export function useRegisterCommands(commands: readonly ShellCommand[]): void {
  const register = useCommandStore((s) => s.register)
  useEffect(() => register(commands), [register, commands])
}

/** Available commands right now (passes `when` gates), in registration order. */
export function availableCommands(commands: Record<string, ShellCommand>): ShellCommand[] {
  return Object.values(commands).filter((command) => {
    try {
      return command.when ? command.when() : true
    } catch {
      return false
    }
  })
}
