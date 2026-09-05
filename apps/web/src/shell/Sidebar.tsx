/**
 * Sidebar (design.md §9.1–9.3) — one navigation, three presentations:
 * expanded 248 px (desktop default), collapsed rail 52 px (user preference;
 * auto below the configured threshold, default 1200 px), mobile drawer < 768 px.
 *
 * Destinations: Applications · Catalog · Approvals (pending badge) · Settings,
 * recent/pinned applications switcher, and a single service-health spot in
 * the utility cluster. Collapse preference persists; Ctrl/Cmd+B toggles.
 * The rail pins its Expand control in the fixed top header, mirroring the
 * expanded sidebar's Collapse control.
 */
import {
  Activity,
  Bell,
  CircleHelp,
  LayoutGrid,
  Package,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Settings,
  Server,
  ShieldCheck,
  X,
} from 'lucide-react'
import type { ComponentProps, ComponentType } from 'react'
import { useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'

import type { ApplicationInstance } from '@/client'
import { BrandLockup, BrandMark, StatusDot, Tooltip } from '@/components'
import { instanceHealthPresentation } from '@/semantic'
import { cn } from '@/lib/utils'
import { useSessionStore, useWorkspaceStore } from '@/state'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'

import { InstanceGlyphTile } from './appIcon'
import { useCommandStore } from './commands'
import {
  hasLiveOperation,
  sidebarInstances,
  useApplications,
  usePendingApprovalsCount,
  useUnreadNotificationsCount,
} from './data'
import { MOD_LABEL, useIsBelowSidebarThreshold, useIsMobile } from './platform'
import { NotificationsPopover } from './NotificationsPopover'
import { ServiceStatusPopover } from './ServiceStatusPopover'
import { useShellUiStore } from './shellUi'

interface Destination {
  to: string
  label: string
  icon: ComponentType<{ className?: string }>
  isActive: (pathname: string) => boolean
  badge?: number
  /** True when the badge count could not be fetched — never show 0 instead. */
  badgeError?: boolean
}

function useDestinations(): Destination[] {
  const { count: pendingApprovals, error: pendingApprovalsError } = usePendingApprovalsCount()
  return [
    {
      to: '/applications',
      label: 'Applications',
      icon: LayoutGrid,
      isActive: (p) => p.startsWith('/applications') || p.startsWith('/app/'),
    },
    { to: '/catalog', label: 'Catalog', icon: Package, isActive: (p) => p.startsWith('/catalog') },
    {
      to: '/approvals',
      label: 'Approvals',
      icon: ShieldCheck,
      isActive: (p) => p.startsWith('/approvals'),
      badge: pendingApprovals,
      badgeError: pendingApprovalsError != null,
    },
    { to: '/platform', label: 'Platform', icon: Server, isActive: (p) => ['/platform', '/sources', '/execution-host', '/deployments', '/authority', '/updater', '/preview-routes', '/statebench'].some((route) => p === route || p.startsWith(`${route}/`)) },
    { to: '/settings', label: 'Settings', icon: Settings, isActive: (p) => p.startsWith('/settings') },
  ]
}

/** Neutral count chip (§9.1 — never red; accent only never). */
function CountBadge({ count, label }: { count: number; label: string }) {
  if (count <= 0) return null
  return (
    <span
      className="tnum ml-auto inline-flex h-4 min-w-4 items-center justify-center rounded-round bg-active px-1 text-xs font-medium text-foreground-secondary"
      aria-label={label}
    >
      {count}
    </span>
  )
}

/** Indeterminate chip for a count that could not be fetched (honest unavailable). */
function UnavailableBadge({ label }: { label: string }) {
  return (
    <span
      className="tnum ml-auto inline-flex h-4 min-w-4 items-center justify-center rounded-round bg-active px-1 text-xs font-medium text-foreground-secondary"
      aria-label={label}
    >
      ?
    </span>
  )
}

// ── Expanded content (shared by desktop sidebar + mobile drawer) ─────────────

function ExpandedContent({ onNavigate }: { onNavigate?: () => void }) {
  const location = useLocation()
  const navigate = useNavigate()
  const destinations = useDestinations()
  const { instances } = useApplications()
  const toggleOperationCenter = useShellUiStore((s) => s.toggleOperationCenter)
  const operations = useSessionStore((s) => s.operations)
  const { count: unread, error: unreadError } = useUnreadNotificationsCount()
  const setShortcutsOpen = useCommandStore((s) => s.setShortcutsOpen)

  const rows = sidebarInstances(instances)

  return (
    <div className="flex h-full flex-col" data-testid="sidebar-expanded">
      <nav aria-label="Primary" className="flex flex-col gap-0.5 px-2 pt-2">
        {destinations.map((dest) => {
          const active = dest.isActive(location.pathname)
          return (
            <Link
              key={dest.to}
              to={dest.to}
              onClick={onNavigate}
              data-active={active}
              aria-current={active ? 'page' : undefined}
              className={cn(
                'nav-item relative flex h-nav-row items-center gap-2 rounded-sm px-3 text-sm font-medium transition-colors duration-instant',
                active
                  ? 'bg-accent-soft text-accent-soft-text before:absolute before:inset-y-1 before:left-0 before:w-0.5 before:rounded-full before:bg-accent'
                  : 'text-foreground hover:bg-hover',
              )}
            >
              <dest.icon className={cn('size-4 shrink-0', active && 'text-accent')} aria-hidden="true" />
              <span className="truncate">{dest.label}</span>
              {dest.badgeError ? (
                <UnavailableBadge label={`${dest.label} count unavailable`} />
              ) : dest.badge ? (
                <CountBadge count={dest.badge} label={`${dest.badge} pending approvals`} />
              ) : null}
            </Link>
          )
        })}
      </nav>

      <div className="mt-4 flex items-center justify-between px-4">
        <span className="text-xs font-medium text-foreground-secondary">Applications</span>
        <Tooltip content="New instance…">
          <button
            type="button"
            aria-label="New instance"
            className="inline-flex min-h-6 min-w-6 items-center justify-center rounded-sm p-0.5 text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            onClick={() => {
              onNavigate?.()
              void navigate('/catalog')
            }}
          >
            <Plus className="size-4" aria-hidden="true" />
          </button>
        </Tooltip>
      </div>
      <div className="mt-1 flex flex-col gap-0.5 px-2" role="list" aria-label="Pinned and recent applications">
        {rows.map((instance) => (
          <AppRow key={instance.id} instance={instance} pathname={location.pathname} onNavigate={onNavigate} />
        ))}
        {rows.length === 0 ? (
          <p className="px-3 py-1 text-xs text-foreground-tertiary">No applications yet. Install one from the Catalog.</p>
        ) : null}
      </div>

      <div className="flex-1" />

      <div className="flex flex-col gap-0.5 border-t border-border px-2 py-2" aria-label="Utilities">
        <NotificationsPopover>
          <UtilityRow
            icon={Bell}
            label="Notifications"
            trailing={
              unreadError ? (
                <UnavailableBadge label="Unread notifications count unavailable" />
              ) : unread > 0 ? (
                <CountBadge count={unread} label={`${unread} unread`} />
              ) : null
            }
          />
        </NotificationsPopover>
        <UtilityRow
          icon={Activity}
          label="Operation center"
          trailing={hasLiveOperation(operations) ? <span className="size-2 rounded-full bg-status-waiting" aria-label="Operation active" /> : null}
          onClick={toggleOperationCenter}
        />
        <ServiceStatusPopover>
          <ServiceUtilityRow />
        </ServiceStatusPopover>
        <UtilityRow icon={CircleHelp} label="Help & shortcuts" onClick={() => setShortcutsOpen(true)} />
      </div>
    </div>
  )
}

function AppRow({
  instance,
  pathname,
  onNavigate,
}: {
  instance: ApplicationInstance
  pathname: string
  onNavigate?: () => void
}) {
  const active = pathname.startsWith(`/app/${instance.id}`)
  const health = instanceHealthPresentation(instance.health)
  return (
    <Link
      to={`/app/${instance.id}`}
      onClick={onNavigate}
      data-active={active}
      aria-current={active ? 'page' : undefined}
      role="listitem"
      className={cn(
        'nav-item flex h-nav-row items-center gap-2 rounded-sm px-3 text-sm transition-colors duration-instant',
        active ? 'bg-accent-soft text-accent-soft-text' : 'text-foreground hover:bg-hover',
      )}
    >
      <InstanceGlyphTile instance={instance} />
      <span className="min-w-0 flex-1 truncate">{instance.name}</span>
      <StatusDot state={health.state} label={health.label} showLabel={false} />
    </Link>
  )
}

function UtilityRow({
  icon: Icon,
  label,
  trailing,
  onClick,
}: {
  icon: ComponentType<{ className?: string }>
  label: string
  trailing?: React.ReactNode
  onClick?: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex h-nav-row w-full items-center gap-2 rounded-sm px-3 text-sm text-foreground transition-colors duration-instant hover:bg-hover"
    >
      <Icon className="size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
      <span className="truncate">{label}</span>
      {trailing ? <span className="ml-auto inline-flex items-center">{trailing}</span> : null}
    </button>
  )
}

function ServiceUtilityRow(props: ComponentProps<'button'>) {
  const status = useSessionStore((s) => s.serviceStatus)
  const state = status?.state ?? 'unknown'
  const label =
    state === 'connected' ? 'Connected' : state === 'degraded' ? 'Service degraded' : state === 'offline' ? 'Service offline' : 'Not checked'
  return (
    <button {...props} type="button" aria-label="Local service status" className="flex h-nav-row w-full items-center gap-2 rounded-sm px-3 text-sm text-foreground">
      <ServiceStateIcon state={state} />
      <span className="truncate">{label}</span>
    </button>
  )
}

export function ServiceStateIcon({ state }: { state: 'connected' | 'degraded' | 'offline' | 'unknown' }) {
  const dot =
    state === 'connected'
      ? 'bg-status-success'
      : state === 'degraded'
        ? 'bg-status-attention'
        : state === 'offline'
          ? 'bg-status-danger'
          : 'bg-status-neutral'
  return <span className={cn('size-2 shrink-0 rounded-full', dot)} aria-hidden="true" />
}

// ── Rail presentation (52 px) ────────────────────────────────────────────────

function RailContent() {
  const location = useLocation()
  const destinations = useDestinations()
  const { instances } = useApplications()
  const setSidebar = useWorkspaceStore((s) => s.setSidebar)
  const toggleOperationCenter = useShellUiStore((s) => s.toggleOperationCenter)
  const operations = useSessionStore((s) => s.operations)
  const rows = sidebarInstances(instances)

  return (
    <div className="flex h-full flex-col items-center" data-testid="sidebar-rail">
      {/* The expand control is the first visible and keyboard-reachable rail
          control, pinned in a fixed header like the expanded sidebar's
          collapse control. */}
      <div className="flex h-topbar w-full shrink-0 items-center justify-center border-b border-border">
        <Tooltip side="right" content={`Expand sidebar · ${MOD_LABEL}+B`}>
          <button
            type="button"
            aria-label="Expand sidebar"
            onClick={() => setSidebar('expanded', { userChosen: true })}
            className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          >
            <PanelLeftOpen className="size-4" aria-hidden="true" />
          </button>
        </Tooltip>
      </div>
      <Tooltip content="Applications" side="right">
        <Link
          to="/applications"
          aria-label="StatePort — Applications"
          className="mt-2 inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground"
        >
          <BrandMark size={24} />
        </Link>
      </Tooltip>

      <nav aria-label="Primary" className="mt-1 flex flex-col items-center gap-1">
        {destinations.map((dest) => {
          const active = dest.isActive(location.pathname)
          return (
            <Tooltip
              key={dest.to}
              side="right"
              content={
                dest.badgeError
                  ? `${dest.label} · count unavailable`
                  : dest.badge
                    ? `${dest.label} · ${dest.badge} pending`
                    : dest.label
              }
            >
              <Link
                to={dest.to}
                aria-label={dest.label}
                data-active={active}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'nav-item relative inline-flex h-9 w-9 items-center justify-center rounded-sm transition-colors duration-instant',
                  active
                    ? 'bg-accent-soft text-accent before:absolute before:inset-y-1 before:left-0 before:w-0.5 before:rounded-full before:bg-accent'
                    : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
                )}
              >
                <dest.icon className="size-4" aria-hidden="true" />
                {dest.badge || dest.badgeError ? (
                  <span className="absolute right-0.5 top-0.5 size-1.5 rounded-full bg-status-neutral" aria-hidden="true" />
                ) : null}
              </Link>
            </Tooltip>
          )
        })}
      </nav>

      <div className="my-2 h-px w-6 bg-border" aria-hidden="true" />

      <div className="flex flex-col items-center gap-1" role="list" aria-label="Pinned and recent applications">
        {rows.map((instance) => {
          const active = location.pathname.startsWith(`/app/${instance.id}`)
          const health = instanceHealthPresentation(instance.health)
          return (
            <Tooltip key={instance.id} side="right" content={`${instance.name} · ${health.label}`}>
              <Link
                to={`/app/${instance.id}`}
                aria-label={`${instance.name} — ${health.label}`}
                data-active={active}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'nav-item relative inline-flex h-8 w-8 items-center justify-center rounded-sm transition-colors duration-instant',
                  active ? 'bg-accent-soft' : 'hover:bg-hover',
                )}
              >
                <InstanceGlyphTile instance={instance} />
                <span
                  className={cn(
                    'absolute bottom-0 right-0 size-2 rounded-full ring-2 ring-sidebar',
                    health.state === 'success'
                      ? 'bg-status-success'
                      : health.state === 'attention'
                        ? 'bg-status-attention'
                        : health.state === 'blocked'
                          ? 'bg-status-blocked'
                          : health.state === 'danger'
                            ? 'bg-status-danger'
                            : 'bg-status-neutral',
                  )}
                  aria-hidden="true"
                />
              </Link>
            </Tooltip>
          )
        })}
      </div>

      <div className="flex-1" />

      <div className="flex flex-col items-center gap-1 pb-1">
        <Tooltip side="right" content="Operation center">
          <button
            type="button"
            aria-label="Operation center"
            onClick={toggleOperationCenter}
            className="relative inline-flex h-9 w-9 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          >
            <Activity className="size-4" aria-hidden="true" />
            {hasLiveOperation(operations) ? (
              <span className="absolute right-1 top-1 size-1.5 rounded-full bg-status-waiting" aria-hidden="true" />
            ) : null}
          </button>
        </Tooltip>
        <ServiceStatusPopover>
          <button type="button" aria-label="Local service status" className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-sm hover:bg-hover">
            <RailServiceIcon />
          </button>
        </ServiceStatusPopover>
      </div>
    </div>
  )
}

function RailServiceIcon() {
  const status = useSessionStore((s) => s.serviceStatus)
  const state = status?.state ?? 'unknown'
  const label =
    state === 'connected' ? 'Local service: Connected' : state === 'degraded' ? 'Local service: Degraded' : state === 'offline' ? 'Local service: Offline' : 'Local service: Not checked'
  return (
    <Tooltip side="right" content={label}>
      <span className="inline-flex items-center justify-center" aria-label={label} role="img">
        <ServiceStateIcon state={state} />
      </span>
    </Tooltip>
  )
}

// ── Public components ────────────────────────────────────────────────────────

/** Desktop/tablet sidebar (expanded 248 px or rail 52 px). Hidden on mobile. */
export function Sidebar() {
  const isMobile = useIsMobile()
  const belowThreshold = useIsBelowSidebarThreshold()
  const sidebar = useWorkspaceStore((s) => s.sidebar)
  const sidebarUserChosen = useWorkspaceStore((s) => s.sidebarUserChosen)
  const setSidebar = useWorkspaceStore((s) => s.setSidebar)

  // Auto-collapse below 1200 px never overrides an explicit user choice (§9.2).
  const collapsed = sidebar === 'collapsed' || (!sidebarUserChosen && belowThreshold)

  if (isMobile) return null

  return (
    <aside
      aria-label="Sidebar"
      className={cn(
        'flex h-full shrink-0 flex-col border-r border-border bg-sidebar transition-[width] duration-layout ease-standard',
        collapsed ? 'w-[52px]' : 'w-[248px]',
      )}
    >
      {collapsed ? (
        <RailContent />
      ) : (
        <>
          <div className="flex h-topbar shrink-0 items-center justify-between border-b border-border pl-4 pr-2">
            <Link to="/applications" aria-label="StatePort — Applications" className="rounded-sm">
              <BrandLockup />
            </Link>
            <Tooltip content={`Collapse sidebar · ${MOD_LABEL}+B`}>
              <button
                type="button"
                aria-label="Collapse sidebar"
                onClick={() => setSidebar('collapsed', { userChosen: true })}
                className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
              >
                <PanelLeftClose className="size-4" aria-hidden="true" />
              </button>
            </Tooltip>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            <ExpandedContent />
          </div>
        </>
      )}
    </aside>
  )
}

/** Mobile drawer (< 768 px): focus trap, Escape, scrim, close-on-nav, focus restore (§9.3). */
export function MobileNavDrawer() {
  const open = useShellUiStore((s) => s.mobileNavOpen)
  const setOpen = useShellUiStore((s) => s.setMobileNavOpen)
  const location = useLocation()

  // Close after navigation.
  useEffect(() => {
    setOpen(false)
  }, [location.pathname, setOpen])

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent
        showCloseButton={false}
        className={cn(
          // DialogContent centers itself with translate-x/y-[-50%]; the drawer
          // is left-anchored, so the centering translate must be reset.
          'fixed inset-y-0 left-0 z-drawer flex h-full w-[292px] max-w-[84vw] translate-x-0 translate-y-0 flex-col gap-0 rounded-none border-r border-border bg-surface p-0 shadow-2 duration-med ease-enter data-[state=open]:slide-in-from-left data-[state=closed]:slide-out-to-left sm:max-w-[84vw]',
        )}
        aria-label="Navigation"
        data-testid="mobile-nav-drawer"
      >
        <DialogTitle className="sr-only">Navigation</DialogTitle>
        <div className="flex h-topbar shrink-0 items-center justify-between border-b border-border pl-4 pr-2">
          <BrandLockup />
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setOpen(false)}
            className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          >
            <X className="size-4" aria-hidden="true" />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto pb-[env(safe-area-inset-bottom)]">
          <ExpandedContent onNavigate={() => setOpen(false)} />
        </div>
      </DialogContent>
    </Dialog>
  )
}
