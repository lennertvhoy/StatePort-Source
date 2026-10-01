/**
 * Topbar (design.md §9.4) — 44 px (48 comfortable): mobile hamburger, context
 * breadcrumb with application switcher, command trigger (Ctrl/Cmd+K),
 * operation center, approvals indicator, notifications, service status chip,
 * overflow menu (help, theme quick toggle, build info).
 */
import {
  Activity,
  Bell,
  Check,
  ChevronDown,
  Command,
  EllipsisVertical,
  Info,
  LayoutGrid,
  Menu,
  Moon,
  Search,
  ShieldQuestion,
  Sun,
  SunMoon,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom'

import { Drawer, Kbd, Tooltip } from '@/components'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { localServicePresentation } from '@/semantic'
import { cn } from '@/lib/utils'
import { useSessionStore, useWorkspaceStore } from '@/state'
import type { ThemeSetting } from '@/state'

import { InstanceGlyphTile } from './appIcon'
import { useCommandStore } from './commands'
import {
  hasLiveOperation,
  sidebarInstances,
  useApplications,
  useInstanceName,
  usePendingApprovalsCount,
  useUnreadNotificationsCount,
} from './data'
import { MOD_LABEL, useIsMobile } from './platform'
import { NotificationsPopover } from './NotificationsPopover'
import { ServiceStatusPopover } from './ServiceStatusPopover'
import { useShellUiStore } from './shellUi'

const TOOL_NAMES: Record<string, string> = {
  files: 'Files',
  terminal: 'Terminal',
  deployments: 'Deployments',
  orchestration: 'Orchestration',
  receipts: 'Receipts',
}

/** Derive breadcrumb segments from the hash route. */
function useBreadcrumb(): { instanceId?: string; leaf: string } {
  const location = useLocation()
  const parts = location.pathname.split('/').filter(Boolean)
  if (parts[0] === 'app' && parts[1]) {
    const instanceId = parts[1]
    const section = parts[2]
    if (section === 'conversation') return { instanceId, leaf: 'Conversation' }
    if (section === 'runs') return { instanceId, leaf: 'Governed Runs' }
    if (section === 'settings') return { instanceId, leaf: 'Settings' }
    if (section === 'receipts') return { instanceId, leaf: 'Receipts' }
    if (section === 'workbench') {
      const tool = parts[3]
      return { instanceId, leaf: tool && TOOL_NAMES[tool] ? TOOL_NAMES[tool] : 'Workbench' }
    }
    return { instanceId, leaf: 'Overview' }
  }
  const leaves: Record<string, string> = {
    applications: 'Applications',
    catalog: 'Catalog',
    sources: 'Application Sources',
    platform: 'Platform',
    'execution-host': 'Execution Host',
    deployments: 'Platform Deployments',
    authority: 'Standing Authority',
    updater: 'Installed Updater',
    'preview-routes': 'Preview Routes',
    statebench: 'StateBench Evidence',
    approvals: 'Approvals',
    settings: 'Settings',
  }
  return { leaf: leaves[parts[0] ?? ''] ?? 'Applications' }
}

function AppSwitcher({ instanceId }: { instanceId: string }) {
  const { instances } = useApplications()
  const navigate = useNavigate()
  const current = instances.find((i) => i.id === instanceId)
  const name = useInstanceName(instanceId)
  const rows = useMemo(() => sidebarInstances(instances, 5), [instances])

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className="flex min-w-0 max-w-full items-center gap-1 rounded-sm px-1 py-0.5 text-sm font-medium text-foreground transition-colors duration-instant hover:bg-hover sm:max-w-56"
        aria-label="Switch application"
        data-testid="app-switcher"
      >
        <span className="truncate">{current?.name ?? name ?? '…'}</span>
        <ChevronDown className="size-3.5 shrink-0 text-foreground-secondary" aria-hidden="true" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="max-h-80 w-64 overflow-y-auto bg-surface">
        <DropdownMenuLabel>Switch application</DropdownMenuLabel>
        {rows.map((instance) => (
          <DropdownMenuItem key={instance.id} onSelect={() => void navigate(`/app/${instance.id}`)}>
            <InstanceGlyphTile instance={instance} />
            <span className="min-w-0 flex-1 truncate">{instance.name}</span>
            {instance.id === instanceId ? <Check className="size-4 text-accent" aria-hidden="true" /> : null}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => void navigate('/applications')}>
          <LayoutGrid className="size-4" aria-hidden="true" />
          All applications
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function ThemeQuickToggle() {
  const theme = useWorkspaceStore((s) => s.theme)
  const setTheme = useWorkspaceStore((s) => s.setTheme)
  const options: { value: ThemeSetting; label: string; icon: typeof Sun }[] = [
    { value: 'system', label: 'Follow system', icon: SunMoon },
    { value: 'light', label: 'Light', icon: Sun },
    { value: 'dark', label: 'Dark', icon: Moon },
  ]
  return (
    <>
      <DropdownMenuLabel>Theme</DropdownMenuLabel>
      {options.map((opt) => (
        <DropdownMenuItem key={opt.value} onSelect={() => setTheme(opt.value)}>
          <opt.icon className="size-4" aria-hidden="true" />
          <span className="flex-1">{opt.label}</span>
          {theme === opt.value ? <Check className="size-4 text-accent" aria-hidden="true" /> : null}
        </DropdownMenuItem>
      ))}
      <DropdownMenuItem
        onSelect={() => setTheme('high_contrast')}
      >
        <SunMoon className="size-4" aria-hidden="true" />
        <span className="flex-1">High contrast</span>
        {theme === 'high_contrast' ? <Check className="size-4 text-accent" aria-hidden="true" /> : null}
      </DropdownMenuItem>
    </>
  )
}

function BuildInfoDrawer({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const buildInfo = useSessionStore((s) => s.buildInfo)
  return (
    <Drawer open={open} onOpenChange={onOpenChange} title="Build information" description="Current build and adapter">
      <dl className="flex flex-col gap-2 text-sm">
        {(
          [
            ['Version', buildInfo?.version],
            ['Commit', buildInfo?.commit],
            ['Built', buildInfo?.builtAt],
            ['Adapter', buildInfo?.adapter],
            ['Mode', buildInfo?.mode],
          ] as const
        ).map(([key, value]) => (
          <div key={key} className="flex items-baseline gap-2">
            <dt className="w-20 shrink-0 text-xs font-medium text-foreground-secondary">{key}</dt>
            <dd className="tnum font-mono text-xs text-foreground">{value ?? '…'}</dd>
          </div>
        ))}
      </dl>
    </Drawer>
  )
}

export function Topbar() {
  const isMobile = useIsMobile()
  const location = useLocation()
  const navigate = useNavigate()
  const setMobileNavOpen = useShellUiStore((s) => s.setMobileNavOpen)
  const toggleOperationCenter = useShellUiStore((s) => s.toggleOperationCenter)
  const setPaletteOpen = useCommandStore((s) => s.setPaletteOpen)
  const setShortcutsOpen = useCommandStore((s) => s.setShortcutsOpen)
  const operations = useSessionStore((s) => s.operations)
  const serviceStatus = useSessionStore((s) => s.serviceStatus)
  const { count: pendingApprovals, error: pendingApprovalsError } = usePendingApprovalsCount()
  const { count: unread, error: unreadError } = useUnreadNotificationsCount()
  const { instanceId, leaf } = useBreadcrumb()
  const [buildInfoOpen, setBuildInfoOpen] = useState(false)

  const onWorkbenchRoute = location.pathname.includes('/workbench')
  const service = localServicePresentation(serviceStatus?.state ?? 'unknown')
  const live = hasLiveOperation(operations)

  return (
    <header
      className="flex h-topbar shrink-0 items-center gap-2 border-b border-border bg-surface px-2 md:px-3"
      data-testid="topbar"
    >
      {isMobile ? (
        <button
          type="button"
          aria-label="Open navigation"
          onClick={() => setMobileNavOpen(true)}
          className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <Menu className="size-5" aria-hidden="true" />
        </button>
      ) : null}

      {/* Context breadcrumb */}
      <nav aria-label="Breadcrumb" className="flex min-w-0 flex-1 items-center gap-1 overflow-hidden text-sm">
        {instanceId ? (
          <>
            <NavLink to="/applications" className="hidden shrink-0 rounded-sm px-1 text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground sm:inline">
              Applications
            </NavLink>
            <span className="hidden text-foreground-tertiary sm:inline" aria-hidden="true">
              /
            </span>
            <AppSwitcher instanceId={instanceId} />
            <span className="hidden text-foreground-tertiary sm:inline" aria-hidden="true">
              /
            </span>
            <span className="sr-only text-foreground sm:not-sr-only sm:truncate" aria-current="page">
              {leaf}
            </span>
          </>
        ) : (
          <span className="truncate font-medium text-foreground" aria-current="page">
            {leaf}
          </span>
        )}
      </nav>

      {/* Command trigger */}
      <button
        type="button"
        onClick={() => setPaletteOpen(true)}
        aria-label={`Search or command · ${MOD_LABEL}+K`}
        className={cn(
          'hidden items-center gap-2 rounded-sm border border-border bg-surface-2 px-2 text-foreground-secondary transition-colors duration-instant hover:border-border-strong hover:text-foreground lg:flex lg:h-control lg:w-56',
        )}
        data-testid="command-trigger"
      >
        <Search className="size-4 shrink-0" aria-hidden="true" />
        <span className="flex-1 truncate text-left text-sm">Search or command…</span>
        <Kbd>{MOD_LABEL} K</Kbd>
      </button>
      <Tooltip content={`Search or command · ${MOD_LABEL}+K`}>
        <button
          type="button"
          onClick={() => setPaletteOpen(true)}
          aria-label="Search or command"
          className="hidden min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground md:inline-flex lg:hidden"
        >
          <Command className="size-4" aria-hidden="true" />
        </button>
      </Tooltip>

      {/* Operation center */}
      <Tooltip content="Operation center">
        <button
          type="button"
          onClick={toggleOperationCenter}
          aria-label="Operation center"
          className="relative hidden min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground md:inline-flex"
          data-testid="operation-center-trigger"
        >
          <Activity className={cn('size-4', live && 'text-status-waiting')} aria-hidden="true" />
          {live ? <span className="absolute right-1.5 top-1.5 size-1.5 rounded-full bg-status-waiting" aria-label="Operation active" /> : null}
        </button>
      </Tooltip>

      {/* Approvals */}
      <Tooltip
        content={
          pendingApprovalsError
            ? 'Approvals · count unavailable'
            : pendingApprovals > 0
              ? `Approvals · ${pendingApprovals} pending`
              : 'Approvals'
        }
      >
        <Link
          to="/approvals"
          aria-label={
            pendingApprovalsError
              ? 'Approvals, count unavailable'
              : pendingApprovals > 0
                ? `Approvals, ${pendingApprovals} pending`
                : 'Approvals'
          }
          className="relative hidden min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground md:inline-flex"
        >
          <ShieldQuestion className="size-4" aria-hidden="true" />
          {pendingApprovalsError ? (
            <span className="tnum absolute -right-0.5 -top-0.5 inline-flex h-4 min-w-4 items-center justify-center rounded-round bg-active px-1 text-xs font-medium text-foreground-secondary ring-1 ring-border">
              ?
            </span>
          ) : pendingApprovals > 0 ? (
            <span className="tnum absolute -right-0.5 -top-0.5 inline-flex h-4 min-w-4 items-center justify-center rounded-round bg-active px-1 text-xs font-medium text-foreground-secondary ring-1 ring-border">
              {pendingApprovals}
            </span>
          ) : null}
        </Link>
      </Tooltip>

      {/* Notifications */}
      <NotificationsPopover>
        <button
          type="button"
          aria-label={unreadError ? 'Notifications, count unavailable' : unread > 0 ? `Notifications, ${unread} unread` : 'Notifications'}
          className="relative inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <Bell className="size-4" aria-hidden="true" />
          {unreadError ? (
            <span className="absolute right-2 top-2 size-1.5 rounded-full bg-status-neutral" aria-hidden="true" />
          ) : unread > 0 ? (
            <span className="absolute right-2 top-2 size-1.5 rounded-full bg-accent" aria-hidden="true" />
          ) : null}
        </button>
      </NotificationsPopover>

      {/* Service status — label chip on global routes, icon-only on workbench routes (§9.4) */}
      <ServiceStatusPopover>
        <button
          type="button"
          aria-label={`Local service: ${service.label}`}
          className={cn(
            'inline-flex min-h-10 items-center gap-1.5 rounded-sm px-2 text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground',
            (serviceStatus?.state ?? 'unknown') !== 'connected' && 'text-status-blocked',
          )}
          data-testid="service-chip"
        >
          <service.icon className="size-4" aria-hidden="true" />
          {!onWorkbenchRoute ? <span className="hidden text-xs font-medium sm:inline">{service.label}</span> : null}
        </button>
      </ServiceStatusPopover>

      {/* Overflow */}
      <DropdownMenu>
        <DropdownMenuTrigger
          aria-label="More actions"
          className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <EllipsisVertical className="size-4" aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56 bg-surface">
          {isMobile ? (
            <>
              <DropdownMenuLabel>Application actions</DropdownMenuLabel>
              <DropdownMenuItem onSelect={() => setPaletteOpen(true)}>
                <Search className="size-4" aria-hidden="true" />
                Search or command
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={toggleOperationCenter}>
                <Activity className={cn('size-4', live && 'text-status-waiting')} aria-hidden="true" />
                <span className="flex-1">Operation center</span>
                {live ? <span className="text-xs text-status-waiting">Active</span> : null}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => void navigate('/approvals')}>
                <ShieldQuestion className="size-4" aria-hidden="true" />
                <span className="flex-1">Approvals</span>
                {pendingApprovalsError ? (
                  <span className="text-xs text-foreground-secondary">count unavailable</span>
                ) : pendingApprovals > 0 ? (
                  <span className="tnum text-xs text-foreground-secondary">
                    {pendingApprovals} pending
                  </span>
                ) : null}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
            </>
          ) : null}
          <DropdownMenuItem onSelect={() => setShortcutsOpen(true)}>
            <Command className="size-4" aria-hidden="true" />
            Help & shortcuts
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <ThemeQuickToggle />
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setBuildInfoOpen(true)}>
            <Info className="size-4" aria-hidden="true" />
            Build information
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <BuildInfoDrawer open={buildInfoOpen} onOpenChange={setBuildInfoOpen} />
    </header>
  )
}
