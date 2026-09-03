/**
 * AppShell (design.md §9) — the persistent frame: sidebar (left) · topbar
 * (top) · content (center) · status bar slot (bottom, workbench contexts
 * render their own). Owns the responsive presentation switch, global
 * overlays, service/operation polling, and built-in palette commands.
 *
 * Focus mode (workbench, `?focus=1`): chrome hides; WorkbenchShell renders
 * the floating restore bar.
 */
import {
  Activity,
  FlaskConical,
  Keyboard,
  LayoutGrid,
  Moon,
  Package,
  PanelLeft,
  Settings,
  ShieldCheck,
  Stethoscope,
  Sun,
  Trash2,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import { Outlet, useLocation, useNavigate, useSearchParams } from 'react-router-dom'

import { getClient } from '@/client'
import { ConfirmDialog } from '@/components'
import { useSessionStore, useWorkspaceStore } from '@/state'

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
import { ScenarioLab, ScenarioRibbon } from './ScenarioLab'
import { ShortcutsReference } from './ShortcutsReference'
import { ThemeEngine } from './ThemeEngine'
import { TitleManager } from './TitleManager'
import { Toaster } from './Toaster'
import { Topbar } from './Topbar'
import { useShellUiStore } from './shellUi'

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
  // Quick open is registered only while the application-scoped Files surface
  // is mounted; no unimplemented global search command is advertised.
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
  const setScenarioLabOpen = useSessionStore((s) => s.setScenarioLabOpen)
  const pushToast = useSessionStore((s) => s.pushToast)
  const [resetOpen, setResetOpen] = useState(false)

  const commands = useMemo<ShellCommand[]>(() => {
    const list: ShellCommand[] = [
      // ── Navigation ────────────────────────────────────────────────────────
      { id: 'nav.applications', title: 'Go to Applications', group: 'Navigation', icon: LayoutGrid, run: () => void navigate('/applications') },
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

    // Dev-only Scenario Lab + destructive reset (never a one-hitter: opens confirm).
    if (import.meta.env.DEV) {
      list.push({
        id: 'dev.scenario_lab',
        title: 'Open Scenario Lab',
        group: 'Help',
        icon: FlaskConical,
        keywords: ['mock', 'state', 'debug', 'scenario'],
        run: () => setScenarioLabOpen(true),
      })
      list.push({
        id: 'dev.reset_mock',
        title: 'Reset mock data…',
        group: 'Actions',
        icon: Trash2,
        keywords: ['reseed', 'mock'],
        run: () => setResetOpen(true),
      })
    }
    return list
  }, [instances, location.pathname, navigate, theme, toggleSidebar, toggleOperationCenter, setTheme, setShortcutsOpen, setScenarioLabOpen])

  useRegisterCommands(commands)

  return (
    <ConfirmDialog
      open={resetOpen}
      onOpenChange={setResetOpen}
      title="Reset mock data"
      description="Wipes persisted mock state and reseeds the deterministic baseline."
      target="mock state"
      effect="All mock instances, receipts, and scenario overrides return to the seeded baseline."
      reversibility="Not reversible — unsaved mock edits are lost."
      destructive
      requireTypedConfirmation="reset"
      confirmLabel="Reset mock data"
      onConfirm={async () => {
        await getClient().scenario.resetMockState()
        pushToast({ kind: 'success', title: 'Mock data reset', body: 'The seeded baseline was restored.' })
      }}
    />
  )
}

export function AppShell() {
  useServiceStatusPolling()
  useOperationsPolling()
  useSavedNavigationSettings()

  const location = useLocation()
  const [searchParams] = useSearchParams()
  const focusActive = location.pathname.includes('/workbench') && searchParams.get('focus') === '1'

  return (
    <div className="flex h-dvh overflow-hidden bg-app text-foreground" data-testid="app-shell">
      <ThemeEngine />
      <TitleManager />
      <KeyboardShortcuts />
      <GlobalShortcutActions />
      <BuiltInCommands />

      {focusActive ? null : <Sidebar />}
      <div className="flex min-w-0 flex-1 flex-col">
        {focusActive ? null : <Topbar />}
        <main id="main-content" tabIndex={-1} className="min-h-0 flex-1 overflow-hidden outline-none">
          <Outlet />
        </main>
        <ScenarioRibbon />
      </div>

      <MobileNavDrawer />
      <CommandPalette />
      <ShortcutsReference />
      <OperationCenter />
      <ScenarioLab />
      <Toaster />
    </div>
  )
}
