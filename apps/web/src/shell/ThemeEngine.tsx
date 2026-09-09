/**
 * ThemeEngine — applies appearance preferences to <html> attributes.
 *
 * Attribute contract (consumed by src/styles/tokens.css):
 *   data-theme    "light" | "dark" | "hc-light" | "hc-dark"
 *   data-panel-contrast "default" | "increased"
 *   data-density  "compact" | "comfortable"
 *   data-motion   "full" | "reduced"     (user setting ∪ prefers-reduced-motion)
 *   data-focus    "standard" | "strong"
 *   style --font-scale  0.875 | 1 | 1.125 | 1.25
 *
 * theme "system" follows prefers-color-scheme via matchMedia (live);
 * "high_contrast" follows the OS light/dark preference for its base.
 */
import { useEffect } from 'react'

import { useWorkspaceStore } from '@/state'

import { resolveTheme } from './theme'

const darkMedia = () => window.matchMedia('(prefers-color-scheme: dark)')
const lightMedia = () => window.matchMedia('(prefers-color-scheme: light)')
const motionMedia = () => window.matchMedia('(prefers-reduced-motion: reduce)')

export function ThemeEngine() {
  const theme = useWorkspaceStore((s) => s.theme)
  const highContrast = useWorkspaceStore((s) => s.highContrast)
  const highContrastBase = useWorkspaceStore((s) => s.highContrastBase)
  const density = useWorkspaceStore((s) => s.density)
  const fontScale = useWorkspaceStore((s) => s.fontScale)
  const panelContrast = useWorkspaceStore((s) => s.panelContrast)
  const reducedMotion = useWorkspaceStore((s) => s.reducedMotion)
  const disableNonessentialAnimation = useWorkspaceStore((s) => s.disableNonessentialAnimation)
  const strongFocus = useWorkspaceStore((s) => s.strongFocus)

  useEffect(() => {
    const root = document.documentElement

    const apply = () => {
      const systemDark = darkMedia().matches
      const useFallback = theme === 'high_contrast' && !systemDark && !lightMedia().matches
      const resolved = resolveTheme({
        theme, highContrast, prefersDark: useFallback ? highContrastBase === 'dark' : systemDark,
      })
      root.dataset.theme = resolved
      root.dataset.density = density
      root.dataset.panelContrast = panelContrast
      root.dataset.motion = reducedMotion || motionMedia().matches ? 'reduced' : 'full'
      root.dataset.decorativeMotion = disableNonessentialAnimation ? 'none' : 'full'
      root.dataset.focus = strongFocus || resolved.startsWith('hc-') ? 'strong' : 'standard'
      root.style.setProperty('--font-scale', String(fontScale / 100))
    }

    apply()

    const dark = darkMedia()
    const light = lightMedia()
    const motion = motionMedia()
    dark.addEventListener('change', apply)
    light.addEventListener('change', apply)
    motion.addEventListener('change', apply)
    return () => {
      dark.removeEventListener('change', apply)
      light.removeEventListener('change', apply)
      motion.removeEventListener('change', apply)
    }
  }, [theme, highContrast, highContrastBase, density, fontScale, panelContrast, reducedMotion, disableNonessentialAnimation, strongFocus])

  return null
}
