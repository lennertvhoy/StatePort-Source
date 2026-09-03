/**
 * ThemeEngine — resolves the theme/density/motion/focus/font-scale
 * preferences onto <html> attributes (the token contract).
 */
import { cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { useWorkspaceStore } from '@/state'

import { ThemeEngine } from '../ThemeEngine'
import { resolveTheme } from '../theme'

afterEach(() => {
  cleanup()
  useWorkspaceStore.setState({
    theme: 'system',
    highContrast: false,
    density: 'compact',
    fontScale: 100,
    reducedMotion: false,
    strongFocus: false,
  })
  document.documentElement.removeAttribute('data-theme')
  document.documentElement.removeAttribute('data-density')
  document.documentElement.removeAttribute('data-motion')
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
