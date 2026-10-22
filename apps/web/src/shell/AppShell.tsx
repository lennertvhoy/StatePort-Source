/**
 * AppShell (design.md §9) — the persistent frame: sidebar (left) · topbar
 * (top) · content (center). Owns the responsive presentation switch, global
 * overlays, service/operation polling, and built-in palette commands.
 */
import {
  Activity,
  Keyboard,
  LayoutGrid,
  Moon,
  Package,
  PanelLeft,
  Settings,
  ShieldCheck,
  Stethoscope,
  Sun,
} from 'lucide-react'
import { lazy, Suspense, useMemo } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'

import { useWorkspaceStore } from '@/state'

import { CommandPalette } from './CommandPalette'
import type { ShellCommand } from './commands'
import { useCommandStore, useRegisterCommands } from './commands'
import { instanceGlyph } from './instanceGlyph'
import { useApplications, useOperationsPolling, useSavedNavigationSettings, useServiceStatusPolling } from './data'
import { KeyboardShortcuts } from './KeyboardShortcuts'
import { useShortcutAction } from './shortcutRegistry'
import { MobileNavDrawer, Sidebar } from './Sidebar'
import { useIsMobile } from './platform'
import { OperationCenter } from './OperationCenter'
import { ShortcutsReference } from './ShortcutsReference'
import { ThemeEngine } from './ThemeEngine'
import { TitleManager } from './TitleManager'
import { Toaster } from './Toaster'
import { Topbar } from './Topbar'
import { useShellUiStore } from './shellUi'

// Development-only tools (Scenario Lab, mock reset). `import.meta.env.DEV` is
// a build-time constant: a product build folds this to `null` and the module
// is never emitted.
const DevTools = import.meta.env.DEV ? lazy(() => import('./DevTools')) : null

/** Global shortcut actions (wired to the shortcuts store chords). */
function GlobalShortcutActions() {
  const navigate = useNavigate()
  const setPaletteOpen = useCommandStore((s) => s.setPaletteOpen)
  const setShortcutsOpen = useCommandStore((s) => s.setShortcutsOpen)
  const toggleSidebar = useWorkspaceStore((s) => s.toggleSidebar)
  const setMobileNavOpen = useShellUiStore((s) => s.setMobileNavOpen)
  const isMobile = useIsMobile()

  useShortcutAction('global.command_palette', () => setPaletteOpen(!useCommandStore.getState().paletteOpen))
  useShortcutAction('global.toggle_sidebar', () => {
    if (isMobile) setMobileNavOpen(!useShellUiStore.getState().mobileNavOpen)
    else toggleSidebar()
  })
  useShortcutAction('global.open_settings', () => void navigate('/settings'))
  useShortcutAction('global.open_approvals', () => void navigate('/approvals'))
  useShortcutAction('global.shortcut_reference', () => setShortcutsOpen(true))
  // No global quick-open command is advertised: there is no file search
  // surface in this release to open.
  return null
}

/** Built-in palette commands: navigation, app switching, actions, settings, help. */
function BuiltInCommands() {
  const navigate = useNavigate()
  const location = useLocation()
  const { instances } = useApplications()
  const toggleSidebar = useWorkspaceStore((s) => s.toggleSidebar)
  const theme = useWorkspaceStore((s) => s.theme)
  const setTheme = useWorkspaceStore((s) => s.setTheme)
  const toggleOperationCenter = useShellUiStore((s) => s.toggleOperationCenter)
  const setShortcutsOpen = useCommandStore((s) => s.setShortcutsOpen)

  const commands = useMemo<ShellCommand[]>(() => {
    const list: ShellCommand[] = [
      // ── Navigation ────────────────────────────────────────────────────────
      { id: 'nav.applications', title: 'Go to Applications', group: 'Navigation', icon: LayoutGrid, run: () => void navigate('/applications') },
      { id: 'nav.platform', title: 'Go to Platform', group: 'Navigation', icon: Settings, keywords: ['runtime', 'execution host', 'updates', 'authority', 'model', 'provider'], run: () => void navigate('/platform') },
      { id: 'nav.catalog', title: 'Go to Catalog', group: 'Navigation', icon: Package, run: () => void navigate('/catalog') },
      { id: 'nav.approvals', title: 'Go to Approvals', group: 'Navigation', icon: ShieldCheck, shortcut: 'mod+shift+a', run: () => void navigate('/approvals') },
      { id: 'nav.settings', title: 'Go to Settings', group: 'Navigation', icon: Settings, shortcut: 'mod+,', run: () => void navigate('/settings') },
      // ── Actions ───────────────────────────────────────────────────────────
      {
        id: 'action.toggle_sidebar',
        title: 'Toggle sidebar',
        group: 'Actions',
        icon: PanelLeft,
        shortcut: 'mod+b',
        run: () => toggleSidebar(),
      },
      {
        id: 'action.operation_center',
        title: 'Open operation center',
        group: 'Actions',
        icon: Activity,
        run: () => toggleOperationCenter(),
      },
      {
        id: 'action.theme_light',
        title: 'Theme: Light',
        group: 'Actions',
        icon: Sun,
        keywords: ['appearance', 'dark', 'mode'],
        when: () => theme !== 'light',
        run: () => setTheme('light'),
      },
      {
        id: 'action.theme_dark',
        title: 'Theme: Dark',
        group: 'Actions',
        icon: Moon,
        keywords: ['appearance', 'light', 'mode'],
        when: () => theme !== 'dark',
        run: () => setTheme('dark'),
      },
      {
        id: 'action.theme_system',
        title: 'Theme: Follow system',
        group: 'Actions',
        icon: Sun,
        keywords: ['appearance'],
        when: () => theme !== 'system',
        run: () => setTheme('system'),
      },
      // ── Settings ──────────────────────────────────────────────────────────
      { id: 'settings.appearance', title: 'Appearance settings', group: 'Settings', icon: Sun, run: () => void navigate('/settings/appearance') },
      { id: 'settings.shortcuts', title: 'Keyboard shortcuts settings', group: 'Settings', icon: Keyboard, run: () => void navigate('/settings/shortcuts') },
      // ── Help ──────────────────────────────────────────────────────────────
      {
        id: 'help.shortcuts',
        title: 'Shortcut reference',
        group: 'Help',
        icon: Keyboard,
        shortcut: '?',
        run: () => setShortcutsOpen(true),
      },
      {
        id: 'help.diagnostics',
        title: 'Open diagnostics',
        group: 'Help',
        icon: Stethoscope,
        run: () => void navigate('/settings/advanced'),
      },
    ]

    // App switching (Applications group) — recents/pinned first.
    for (const instance of instances) {
      list.push({
        id: `app.open.${instance.id}`,
        title: `Open ${instance.name}`,
        group: 'Applications',
        icon: instanceGlyph(instance),
        keywords: [instance.packageDisplayName, instance.packageName],
        when: () => !location.pathname.startsWith(`/app/${instance.id}`),
        run: () => void navigate(`/app/${instance.id}`),
      })
    }

    return list
  }, [instances, location.pathname, navigate, theme, toggleSidebar, toggleOperationCenter, setTheme, setShortcutsOpen])

  useRegisterCommands(commands)

  return null
}

/**
 * Bypass block (WCAG 2.4.1): the first Tab stop on every route. It is visually
 * hidden until focused and moves focus into <main>, so a keyboard user reaches
 * the page's primary action after Tab, Enter, Tab instead of tabbing through
 * the whole sidebar and topbar first. It is not a hash link on purpose: the app
 * uses hash routing, and `#main-content` would navigate away.
 */
function SkipToContent() {
  return (
    <a
      href="#main-content"
      data-testid="skip-to-content"
      onClick={(event) => {
        event.preventDefault()
        const main = document.getElementById('main-content')
        if (main instanceof HTMLElement) main.focus()
      }}
      className="sr-only rounded-sm bg-surface px-3 py-2 text-sm font-medium text-foreground shadow-2 ring-2 ring-accent focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-toast"
    >
      Skip to main content
    </a>
  )
}

export function AppShell() {
  useServiceStatusPolling()
  useOperationsPolling()
  useSavedNavigationSettings()

  return (
    <div className="flex h-dvh overflow-hidden bg-app text-foreground" data-testid="app-shell">
      <SkipToContent />
      <ThemeEngine />
      <TitleManager />
      <KeyboardShortcuts />
      <GlobalShortcutActions />
      <BuiltInCommands />

      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main id="main-content" tabIndex={-1} className="min-h-0 flex-1 overflow-hidden outline-none">
          <Outlet />
        </main>
        {DevTools ? (
          <Suspense fallback={null}>
            <DevTools />
          </Suspense>
        ) : null}
      </div>

      <MobileNavDrawer />
      <CommandPalette />
      <ShortcutsReference />
      <OperationCenter />
      <Toaster />
    </div>
  )
}
