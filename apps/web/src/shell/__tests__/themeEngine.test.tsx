/**
 * ThemeEngine — resolves the theme/density/motion/focus/font-scale
 * preferences onto <html> attributes (the token contract).
 */
import { act, cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { useWorkspaceStore } from '@/state'
import { readFileSync } from 'node:fs'

const tokens = readFileSync('src/styles/tokens.css', 'utf8')

import { ThemeEngine } from '../ThemeEngine'
import { resolveTheme } from '../theme'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  useWorkspaceStore.setState({
    theme: 'system',
    highContrast: false,
    highContrastBase: 'dark',
    density: 'compact',
    fontScale: 100,
    panelContrast: 'default',
    reducedMotion: false,
    disableNonessentialAnimation: false,
    strongFocus: false,
  })
  document.documentElement.removeAttribute('data-panel-contrast')
  document.documentElement.removeAttribute('data-theme')
  document.documentElement.removeAttribute('data-density')
  document.documentElement.removeAttribute('data-motion')
  document.documentElement.removeAttribute('data-decorative-motion')
  document.documentElement.removeAttribute('data-focus')
  document.documentElement.style.removeProperty('--font-scale')
})

describe('resolveTheme', () => {
  it('resolves explicit themes', () => {
    expect(resolveTheme({ theme: 'light', highContrast: false, prefersDark: false })).toBe('light')
    expect(resolveTheme({ theme: 'dark', highContrast: false, prefersDark: false })).toBe('dark')
  })

  it('follows the system preference', () => {
    expect(resolveTheme({ theme: 'system', highContrast: false, prefersDark: true })).toBe('dark')
    expect(resolveTheme({ theme: 'system', highContrast: false, prefersDark: false })).toBe('light')
  })

  it('high contrast overlays the resolved base', () => {
    expect(resolveTheme({ theme: 'system', highContrast: true, prefersDark: true })).toBe('hc-dark')
    expect(resolveTheme({ theme: 'light', highContrast: true, prefersDark: true })).toBe('hc-light')
    expect(resolveTheme({ theme: 'high_contrast', highContrast: false, prefersDark: true })).toBe('hc-dark')
    expect(resolveTheme({ theme: 'high_contrast', highContrast: false, prefersDark: false })).toBe('hc-light')
  })
})

describe('ThemeEngine attributes', () => {
  it('disables decorative effects independently of the reduced-motion preference', () => {
    render(<ThemeEngine />)
    act(() => useWorkspaceStore.getState().setDisableNonessentialAnimation(true))
    expect(document.documentElement.dataset.decorativeMotion).toBe('none')
    expect(document.documentElement.dataset.motion).toBe('full')
    act(() => useWorkspaceStore.getState().setDisableNonessentialAnimation(false))
    expect(document.documentElement.dataset.decorativeMotion).toBe('full')
  })

  it('uses the saved HC fallback only when neither system palette matches and reacts to preference changes', () => {
    let palette: 'light' | 'dark' | null = null
    const listeners = new Set<() => void>()
    const original = window.matchMedia.bind(window)
    vi.spyOn(window, 'matchMedia').mockImplementation(query => ({
      ...original(query),
      media: query,
      get matches() { return palette !== null && query === `(prefers-color-scheme: ${palette})` },
      addEventListener: (_event: string, callback: EventListenerOrEventListenerObject) => { listeners.add(callback as () => void) },
      removeEventListener: (_event: string, callback: EventListenerOrEventListenerObject) => { listeners.delete(callback as () => void) },
    }))
    useWorkspaceStore.setState({ theme: 'high_contrast', highContrastBase: 'dark' })
    const mounted = render(<ThemeEngine />)
    expect(document.documentElement.dataset.theme).toBe('hc-dark')
    act(() => useWorkspaceStore.getState().setHighContrastBase('light'))
    expect(document.documentElement.dataset.theme).toBe('hc-light')
    act(() => { palette = 'dark'; for (const listener of listeners) listener() })
    expect(document.documentElement.dataset.theme).toBe('hc-dark')
    act(() => { palette = 'light'; for (const listener of listeners) listener() })
    expect(document.documentElement.dataset.theme).toBe('hc-light')
    act(() => useWorkspaceStore.getState().setHighContrastBase('dark'))
    expect(document.documentElement.dataset.theme).toBe('hc-light')
    mounted.unmount()
    expect(listeners.size).toBe(0)
  })

  it('applies theme/density/motion/focus/font-scale to <html>', () => {
    useWorkspaceStore.setState({
      theme: 'dark',
      density: 'comfortable',
      fontScale: 125,
      reducedMotion: true,
      strongFocus: true,
    })
    render(<ThemeEngine />)
    const root = document.documentElement
    expect(root.dataset.theme).toBe('dark')
    expect(root.dataset.density).toBe('comfortable')
    expect(root.dataset.motion).toBe('reduced')
    expect(root.dataset.focus).toBe('strong')
    expect(root.style.getPropertyValue('--font-scale')).toBe('1.25')
  })

  it('system theme resolves through matchMedia (stub: light) and HC forces strong focus', () => {
    useWorkspaceStore.setState({ theme: 'system', highContrast: true })
    render(<ThemeEngine />)
    const root = document.documentElement
    expect(root.dataset.theme).toBe('hc-light')
    expect(root.dataset.focus).toBe('strong')
    expect(root.dataset.motion).toBe('full')
  })
})


it.each([
  ['light', false, '#E3E3DE', '#C9C9C2'],
  ['dark', false, '#2A2E36', '#3B414C'],
  ['light', true, '#525252', '#1F1F1F'],
  ['dark', true, '#6E6E6E', '#A0A0A0'],
] as const)('increased panel contrast uses the existing strong border in %s HC=%s without changing other tokens', (theme, highContrast, normal, strong) => {
  const style = document.createElement('style')
  style.textContent = tokens
  document.head.append(style)
  try {
    useWorkspaceStore.setState({ theme, highContrast, panelContrast: 'default', highContrastBase: 'dark', disableNonessentialAnimation: true })
    render(<ThemeEngine />)
    const root = document.documentElement
    const before = getComputedStyle(root)
    const background = before.getPropertyValue('--bg-surface')
    const status = before.getPropertyValue('--status-success-border')
    expect(before.getPropertyValue('--border-default').trim()).toBe(normal)
    act(() => useWorkspaceStore.getState().setPanelContrast('increased'))
    const increased = getComputedStyle(root)
    expect(root.dataset.panelContrast).toBe('increased')
    expect(increased.getPropertyValue('--border-default').trim()).toBe('var(--border-strong)')
    expect(increased.getPropertyValue('--border-strong').trim()).toBe(strong)
    expect(increased.getPropertyValue('--bg-surface')).toBe(background)
    expect(increased.getPropertyValue('--status-success-border')).toBe(status)
    expect(useWorkspaceStore.getState().highContrastBase).toBe('dark')
    expect(root.dataset.decorativeMotion).toBe('none')
    act(() => useWorkspaceStore.getState().setPanelContrast('default'))
    expect(getComputedStyle(root).getPropertyValue('--border-default').trim()).toBe(normal)
  } finally { style.remove() }
})
