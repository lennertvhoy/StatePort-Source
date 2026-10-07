/**
 * Terminal theme — builds the xterm theme from StatePort CSS tokens
 * (terminal.md: "`--bg-sunken` theme-synced", settings: terminal theme pref
 * match_interface / light / dark). No raw hex in components; the only values
 * are the design-token fallbacks from design.md §3 used when computed styles
 * are unavailable (e.g. jsdom tests).
 */
import type { ITheme } from '@xterm/xterm'

export type TerminalThemePreference = 'match_interface' | 'light' | 'dark'

/** Token names the xterm theme is composed from. */
const TOKEN_NAMES = [
  '--bg-sunken',
  '--bg-active',
  '--text-primary',
  '--text-secondary',
  '--text-tertiary',
  '--accent',
  '--accent-soft-bg',
  '--status-success-text',
  '--status-attention-text',
  '--status-waiting-text',
  '--status-danger-text',
  '--status-informational-text',
] as const

type TokenName = (typeof TOKEN_NAMES)[number]

/** design.md §3.1 light values — fallback only when computed CSS is absent. */
const FALLBACK: Record<TokenName, string> = {
  '--bg-sunken': '#F6F6F4',
  '--bg-active': '#E7E9E4',
  '--text-primary': '#262B31',
  '--text-secondary': '#57606A',
  '--text-tertiary': '#67717C',
  '--accent': '#2E5AAC',
  '--accent-soft-bg': '#E8EEF9',
  '--status-success-text': '#256B43',
  '--status-attention-text': '#8A6100',
  '--status-waiting-text': '#5748B5',
  '--status-danger-text': '#B3261E',
  '--status-informational-text': '#2E5AAC',
}

function readTokens(preference: TerminalThemePreference): Record<TokenName, string> {
  const out = { ...FALLBACK }
  if (typeof window === 'undefined' || typeof document === 'undefined' || !document.documentElement) {
    return out
  }
  try {
    if (preference === 'match_interface') {
      const cs = window.getComputedStyle(document.documentElement)
      for (const name of TOKEN_NAMES) {
        const value = cs.getPropertyValue(name).trim()
        if (value) out[name] = value
      }
      return out
    }
    // Forced light/dark: probe an element carrying the theme attribute so the
    // forced palette still comes from the token sheet, not from literals.
    const probe = document.createElement('div')
    probe.setAttribute('data-theme', preference)
    probe.style.display = 'none'
    document.body.appendChild(probe)
    try {
      const cs = window.getComputedStyle(probe)
      for (const name of TOKEN_NAMES) {
        const value = cs.getPropertyValue(name).trim()
        if (value) out[name] = value
      }
    } finally {
      probe.remove()
    }
  } catch {
    // jsdom / detached documents: fallbacks already applied.
  }
  return out
}

/** Build the xterm theme for the given terminal-theme preference. */
export function buildXtermTheme(preference: TerminalThemePreference): ITheme {
  const t = readTokens(preference)
  return {
    background: t['--bg-sunken'],
    foreground: t['--text-primary'],
    cursor: t['--accent'],
    cursorAccent: t['--bg-sunken'],
    selectionBackground: t['--accent-soft-bg'],
    selectionForeground: t['--text-primary'],
    // ANSI palette — semantic status tokens so color always pairs with the
    // theme and keeps the audited contrast (§3.3). Bright variants reuse the
    // same tokens (single-tone token system).
    black: t['--text-tertiary'],
    brightBlack: t['--text-secondary'],
    white: t['--text-secondary'],
    brightWhite: t['--text-primary'],
    red: t['--status-danger-text'],
    brightRed: t['--status-danger-text'],
    green: t['--status-success-text'],
    brightGreen: t['--status-success-text'],
    yellow: t['--status-attention-text'],
    brightYellow: t['--status-attention-text'],
    blue: t['--status-informational-text'],
    brightBlue: t['--status-informational-text'],
    magenta: t['--status-waiting-text'],
    brightMagenta: t['--status-waiting-text'],
    cyan: t['--accent'],
    brightCyan: t['--accent'],
  }
}
