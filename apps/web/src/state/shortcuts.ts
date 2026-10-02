/**
 * Command/shortcut model (design.md §9.7 + brief keyboard section).
 *
 * - Defaults from the brief; `mod` = Cmd on macOS, Ctrl elsewhere.
 * - Rebindable, persisted overrides only (`stateport.shortcuts.v1`).
 * - Conflict detection: two commands with identical normalized keys in the
 *   SAME scope conflict (cross-scope chords like `mod+f` in files vs terminal
 *   are intentional — the focused scope wins).
 * - Browser-critical chords (mod+w/t/n/l/r) can never be bound.
 * - Commands flagged `dangerous` can never be bound to a bare single key.
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export const SHORTCUTS_STORAGE_KEY = 'stateport.shortcuts.v1'

export type ShortcutScope = 'global' | 'workbench' | 'files' | 'conversation' | 'terminal'

export interface ShortcutCommand {
  id: string
  label: string
  group: 'Global' | 'Workbench' | 'Files' | 'Conversation' | 'Terminal'
  scope: ShortcutScope
  defaultKeys: string
  dangerous?: boolean
}

export const SHORTCUT_COMMANDS: readonly ShortcutCommand[] = [
  // Global
  { id: 'global.command_palette', label: 'Command palette', group: 'Global', scope: 'global', defaultKeys: 'mod+k' },
  { id: 'global.quick_open', label: 'Quick open', group: 'Global', scope: 'global', defaultKeys: 'mod+p' },
  { id: 'global.toggle_sidebar', label: 'Toggle sidebar', group: 'Global', scope: 'global', defaultKeys: 'mod+b' },
  { id: 'global.open_settings', label: 'Open settings', group: 'Global', scope: 'global', defaultKeys: 'mod+,' },
  { id: 'global.open_approvals', label: 'Open approvals', group: 'Global', scope: 'global', defaultKeys: 'mod+shift+a' },
  { id: 'global.shortcut_reference', label: 'Shortcut reference', group: 'Global', scope: 'global', defaultKeys: '?' },
  { id: 'global.close_overlay', label: 'Close overlay / leave focus mode', group: 'Global', scope: 'global', defaultKeys: 'escape' },
  // Workbench
  { id: 'workbench.toggle_terminal', label: 'Toggle or focus terminal', group: 'Workbench', scope: 'workbench', defaultKeys: 'ctrl+`' },
  { id: 'workbench.toggle_bottom_panel', label: 'Toggle lower panel', group: 'Workbench', scope: 'workbench', defaultKeys: 'mod+j' },
  { id: 'workbench.maximize_tool', label: 'Maximize or restore active tool', group: 'Workbench', scope: 'workbench', defaultKeys: 'mod+shift+enter' },
  { id: 'workbench.tool_1', label: 'Workbench tool: Overview', group: 'Workbench', scope: 'workbench', defaultKeys: 'mod+1' },
  { id: 'workbench.tool_2', label: 'Workbench tool: Files', group: 'Workbench', scope: 'workbench', defaultKeys: 'mod+2' },
  { id: 'workbench.tool_3', label: 'Workbench tool: Terminal', group: 'Workbench', scope: 'workbench', defaultKeys: 'mod+3' },
  { id: 'workbench.tool_4', label: 'Workbench tool: Deployments', group: 'Workbench', scope: 'workbench', defaultKeys: 'mod+4' },
  { id: 'workbench.tool_5', label: 'Workbench tool: Orchestration', group: 'Workbench', scope: 'workbench', defaultKeys: 'mod+5' },
  { id: 'workbench.tool_6', label: 'Workbench tool: Receipts', group: 'Workbench', scope: 'workbench', defaultKeys: 'mod+6' },
  // Files
  { id: 'files.find', label: 'Find in current file', group: 'Files', scope: 'files', defaultKeys: 'mod+f' },
  { id: 'files.save_preview', label: 'Open save preview', group: 'Files', scope: 'files', defaultKeys: 'mod+s' },
  { id: 'files.split_editor', label: 'Split editor', group: 'Files', scope: 'files', defaultKeys: 'mod+\\' },
  // Conversation
  { id: 'conversation.send', label: 'Send message', group: 'Conversation', scope: 'conversation', defaultKeys: 'enter' },
  { id: 'conversation.newline', label: 'New line', group: 'Conversation', scope: 'conversation', defaultKeys: 'shift+enter' },
  { id: 'conversation.send_always', label: 'Send (always)', group: 'Conversation', scope: 'conversation', defaultKeys: 'mod+enter' },
  { id: 'conversation.stop_stream', label: 'Stop current stream', group: 'Conversation', scope: 'conversation', defaultKeys: 'escape' },
  // Terminal
  { id: 'terminal.search', label: 'Search terminal output', group: 'Terminal', scope: 'terminal', defaultKeys: 'mod+f' },
  { id: 'terminal.new_session', label: 'New terminal session', group: 'Terminal', scope: 'terminal', defaultKeys: 'ctrl+shift+`' },
]

/** Chords the browser owns; they can never be bound (design.md §9.7). */
const RESERVED = new Set(['mod+w', 'mod+t', 'mod+n', 'mod+l', 'mod+r'])

const MODIFIER_ORDER = ['ctrl', 'alt', 'shift', 'mod'] as const

/** Normalize a chord string: modifiers sorted, key lowercased. null = invalid. */
export function normalizeKeys(input: string): string | null {
  const parts = input
    .trim()
    .toLowerCase()
    .split('+')
    .map((p) => p.trim())
    .filter(Boolean)
  if (parts.length === 0) return null
  const mods: string[] = []
  const keys: string[] = []
  for (const part of parts) {
    if ((MODIFIER_ORDER as readonly string[]).includes(part)) mods.push(part)
    else keys.push(part)
  }
  if (keys.length !== 1) return null
  mods.sort((a, b) => MODIFIER_ORDER.indexOf(a as (typeof MODIFIER_ORDER)[number]) - MODIFIER_ORDER.indexOf(b as (typeof MODIFIER_ORDER)[number]))
  return [...mods, keys[0]].join('+')
}

export interface ShortcutView extends ShortcutCommand {
  keys: string
  overridden: boolean
  conflictWith: string | null
}

interface ShortcutsState {
  overrides: Record<string, string>
  keysFor(id: string): string
  list(): ShortcutView[]
  rebind(id: string, keys: string): { ok: true } | { ok: false; error: string }
  reset(id: string): void
  resetAll(): void
}

export const useShortcutsStore = create<ShortcutsState>()(
  persist(
    (set, get) => ({
      overrides: {},

      keysFor: (id) => {
        const cmd = SHORTCUT_COMMANDS.find((c) => c.id === id)
        if (!cmd) return ''
        return get().overrides[id] ?? cmd.defaultKeys
      },

      list: () => {
        const { overrides } = get()
        const effective = SHORTCUT_COMMANDS.map((cmd) => ({
          ...cmd,
          keys: overrides[cmd.id] ?? cmd.defaultKeys,
          overridden: cmd.id in overrides,
        }))
        return effective.map((cmd) => {
          const conflict = effective.find(
            (other) => other.id !== cmd.id && other.scope === cmd.scope && other.keys === cmd.keys,
          )
          return { ...cmd, conflictWith: conflict?.id ?? null }
        })
      },

      rebind: (id, keys) => {
        const cmd = SHORTCUT_COMMANDS.find((c) => c.id === id)
        if (!cmd) return { ok: false as const, error: `Unknown command: ${id}` }
        const normalized = normalizeKeys(keys)
        if (!normalized) return { ok: false as const, error: `“${keys}” is not a valid shortcut.` }
        if (RESERVED.has(normalized)) {
          return { ok: false as const, error: 'This chord is reserved by the browser and cannot be used.' }
        }
        if (cmd.dangerous && !normalized.includes('+')) {
          return { ok: false as const, error: 'Dangerous actions cannot use a bare single-key shortcut.' }
        }
        const conflict = SHORTCUT_COMMANDS.find((other) => {
          if (other.id === id || other.scope !== cmd.scope) return false
          const otherKeys = get().overrides[other.id] ?? other.defaultKeys
          return otherKeys === normalized
        })
        if (conflict) {
          return { ok: false as const, error: `Conflicts with “${conflict.label}”.` }
        }
        set((s) => ({ overrides: { ...s.overrides, [id]: normalized } }))
        return { ok: true as const }
      },

      reset: (id) =>
        set((s) => {
          const overrides = { ...s.overrides }
          delete overrides[id]
          return { overrides }
        }),

      resetAll: () => set({ overrides: {} }),
    }),
    {
      name: SHORTCUTS_STORAGE_KEY,
      version: 1,
      partialize: (s) => ({ overrides: s.overrides }),
    },
  ),
)
