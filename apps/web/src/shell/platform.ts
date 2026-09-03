/**
 * Platform + media-query helpers for the shell.
 * - `mod` means Cmd on macOS, Ctrl elsewhere (mirrors src/state/shortcuts.ts).
 */
import { useCallback, useSyncExternalStore } from 'react'

import { useWorkspaceStore } from '@/state/workspace'

export const IS_MAC: boolean =
  typeof navigator !== 'undefined' && /mac|iphone|ipad/i.test(`${navigator.platform} ${navigator.userAgent}`)

/** Human label for the `mod` modifier on this platform. */
export const MOD_LABEL = IS_MAC ? '⌘' : 'Ctrl'

const KEY_LABELS_MAC: Record<string, string> = {
  enter: '↵',
  escape: 'Esc',
  shift: '⇧',
  ctrl: 'Ctrl',
  alt: '⌥',
  mod: '⌘',
  '`': '`',
  ',': ',',
  '?': '?',
  '\\': '\\',
}

const KEY_LABELS_OTHER: Record<string, string> = {
  enter: 'Enter',
  escape: 'Esc',
  shift: 'Shift',
  ctrl: 'Ctrl',
  alt: 'Alt',
  mod: 'Ctrl',
}

/** Format a normalized chord (`mod+shift+enter`) for display on this platform. */
export function formatChord(chord: string): string {
  if (!chord) return ''
  const labels = IS_MAC ? KEY_LABELS_MAC : KEY_LABELS_OTHER
  const parts = chord.split('+')
  const rendered = parts.map((part) => {
    if (part in labels) return labels[part]
    return part.length === 1 ? part.toUpperCase() : part[0].toUpperCase() + part.slice(1)
  })
  if (chord === '?') return '?'
  return IS_MAC ? rendered.join('') : rendered.join('+')
}

const MODIFIER_ORDER = ['ctrl', 'alt', 'shift', 'mod'] as const

/**
 * Normalize a keyboard event into a chord string compatible with
 * `normalizeKeys` in src/state/shortcuts.ts. Returns null for pure modifier
 * presses and unrecognized keys.
 */
export function chordFromEvent(e: KeyboardEvent): string | null {
  const key = e.key
  if (key === 'Control' || key === 'Shift' || key === 'Alt' || key === 'Meta') return null

  let normalized = key.toLowerCase()
  if (normalized === ' ') normalized = 'space'
  if (normalized === 'esc') normalized = 'escape'
  if (normalized === 'arrowup') normalized = 'up'
  if (normalized === 'arrowdown') normalized = 'down'
  if (normalized === 'arrowleft') normalized = 'left'
  if (normalized === 'arrowright') normalized = 'right'

  const mods: string[] = []
  // `mod` = Cmd on macOS, Ctrl elsewhere. Physical Ctrl on macOS stays `ctrl`.
  if (IS_MAC ? e.metaKey : e.ctrlKey) mods.push('mod')
  if (IS_MAC && e.ctrlKey) mods.push('ctrl')
  if (e.altKey) mods.push('alt')
  if (e.shiftKey) mods.push('shift')
  mods.sort((a, b) => MODIFIER_ORDER.indexOf(a as (typeof MODIFIER_ORDER)[number]) - MODIFIER_ORDER.indexOf(b as (typeof MODIFIER_ORDER)[number]))

  return [...mods, normalized].join('+')
}

/** True when the event target accepts text input (IME/input-safe guard). */
export function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  if (target.isContentEditable) return true
  const tag = target.tagName
  if (tag === 'TEXTAREA' || tag === 'SELECT') return true
  if (tag === 'INPUT') {
    const type = (target as HTMLInputElement).type
    return !['checkbox', 'radio', 'button', 'range', 'color'].includes(type)
  }
  return false
}

/** Reactive matchMedia hook. */
export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (onChange: () => void) => {
      const mql = window.matchMedia(query)
      mql.addEventListener('change', onChange)
      return () => mql.removeEventListener('change', onChange)
    },
    [query],
  )
  const getSnapshot = useCallback(() => window.matchMedia(query).matches, [query])
  const getServerSnapshot = useCallback(() => false, [])
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot)
}

/** True below the md breakpoint (mobile presentation, design.md §9.8). */
export function useIsMobile(): boolean {
  return useMediaQuery('(max-width: 767px)')
}

/** True below the configured expanded-sidebar threshold (auto-collapse, §9.2). */
export function useIsBelowSidebarThreshold(): boolean {
  const px = useWorkspaceStore((s) => s.sidebarAutoCollapseBelowPx)
  return useMediaQuery(`(max-width: ${px - 1}px)`)
}
