/**
 * Applications home (`#/applications`) — the resume dashboard
 * (applications.md): "I opened StatePort; put me back to work."
 * Hierarchy: continue → needs you → everything installed.
 *
 * Sections: Continue where you left off · Needs attention · Active/recent
 * operations · Recently used · All applications (pinned group first, search /
 * sort / density, New instance). First run swaps the inventory for the honest
 * empty state + dismissible onboarding strip.
 *
 * Keyboard (this route): ↑↓/Home/End move through row lists (roving tabindex),
 * Enter opens, Space opens the row menu, P pins the focused row,
 * Alt+↑/Alt+↓ reorders pinned rows, `/` focuses the filter,
 * Ctrl/Cmd+1…9 jumps to pinned applications 1–9.
 *
 * data-testid="applications-stub" is kept on the layout root as a legacy
 * alias: the shell route-smoke test asserts it until the shell suite moves to
 * the new id (applications-page).
 */
import { History, LayoutGrid, ListFilter, Plus, Rows2, Rows3, Search, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import type { ApplicationInstance, AttentionItem } from '@/client'
import { getClient } from '@/client'
import { EmptyState, ErrorState, InlineNotice, OperationStateLabel, SectionHeader, Skeleton, TimeAgo } from '@/components'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'
import { reconnectService } from '@/shell/data'
import type { ShellCommand } from '@/shell/commands'
import { useRegisterCommands } from '@/shell/commands'
import { useSessionStore, useWorkspaceStore } from '@/state'

import { AttentionFeed } from './components/AttentionFeed'
import { buildAttentionFeed } from './lib/attentionFeed'
import { ContinueHero } from './components/ContinueHero'
import { resumeTargetFor, useWorkspaceContinuity } from './lib/continuity'
import { InstanceCard, InstanceRow, RecentInstanceRow } from './components/InstanceRow'
import { OnboardingStrip } from './components/OnboardingStrip'
import { RenameDialog } from './components/RenameDialog'
import { useApplicationsDashboard, useServiceOffline } from './lib/dashboardData'
import type { DominantStatus } from './lib/dominantStatus'
import { dominantInstanceStatus, LIVE_OP_STATES } from './lib/dominantStatus'
import type { ApplicationsSort } from './lib/prefsStore'
import { useApplicationsPrefs } from './lib/prefsStore'
import { useRovingFocus } from './lib/useRovingFocus'

const MAX_ATTENTION_ROWS = 5
const MAX_OPERATION_ROWS = 5
const MAX_RECENT_ROWS = 5

const SORT_LABELS: Record<ApplicationsSort, string> = { recent: 'Recent', name: 'Name', package: 'Package' }

export default function ApplicationsPage() {
  const navigate = useNavigate()
  const { instances, pendingApprovals, operations, loading, error, stale, refresh } = useApplicationsDashboard()
  const serviceOffline = useServiceOffline()
  const readOnly = serviceOffline
  const canRename = getClient().applications.canRename
  const pushToast = useSessionStore((s) => s.pushToast)

  // ── preferences (persisted) ────────────────────────────────────────────────
  const sort = useApplicationsPrefs((s) => s.sort)
  const setSort = useApplicationsPrefs((s) => s.setSort)
  const onboardingDismissed = useApplicationsPrefs((s) => s.onboardingDismissed)
  const dismissOnboarding = useApplicationsPrefs((s) => s.dismissOnboarding)
  const pinnedOrder = useApplicationsPrefs((s) => s.pinnedOrder)
  const reconcilePinned = useApplicationsPrefs((s) => s.reconcilePinned)
  const movePinned = useApplicationsPrefs((s) => s.movePinned)

  // ── workspace continuity + global density ─────────────────────────────────
  const continuity = useWorkspaceContinuity()
  const density = useWorkspaceStore((s) => s.density)
  const setDensity = useWorkspaceStore((s) => s.setDensity)

  // ── local UI state ─────────────────────────────────────────────────────────
  const [filter, setFilter] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const [renameTarget, setRenameTarget] = useState<ApplicationInstance | null>(null)
  const filterRef = useRef<HTMLInputElement>(null)
  const dragIdRef = useRef<string | null>(null)

  // ── pinned order reconciliation (client pin flags ↔ persisted user order) ──
  const pinnedKey = instances.filter((i) => i.pinned).map((i) => i.id).join(',')
  useEffect(() => {
    reconcilePinned(pinnedKey ? pinnedKey.split(',') : [])
  }, [pinnedKey, reconcilePinned])

  // ── dominant per-instance status (the ONE honest status per row) ──────────
  const statusById = useMemo(() => {
    const map = new Map<string, DominantStatus>()
    for (const instance of instances) {
      map.set(
        instance.id,
        dominantInstanceStatus({
          instance,
          pendingApprovals: pendingApprovals.filter((a) => a.instanceId === instance.id).length,
          operations: operations.filter((o) => o.instanceId === instance.id),
          capabilityDegraded: instance.capabilities.some((c) => c.status === 'degraded'),
        }),
      )
    }
    return map
  }, [instances, pendingApprovals, operations])

  const statusOf = useCallback(
    (instance: ApplicationInstance) =>
      statusById.get(instance.id) ?? dominantInstanceStatus({ instance }),
    [statusById],
  )

  const feed = useMemo(
    () => buildAttentionFeed({ instances, pendingApprovals, operations }),
    [instances, pendingApprovals, operations],
  )

  // ── Continue hero: last active workspace (fallback: most recently opened) ──
  const hero = useMemo(() => {
    if (instances.length === 0) return null
    const last = continuity.lastInstanceId ? instances.find((i) => i.id === continuity.lastInstanceId) : undefined
    if (last) return last
    return [...instances].sort((a, b) => (b.lastOpenedAt ?? '').localeCompare(a.lastOpenedAt ?? ''))[0] ?? null
  }, [instances, continuity.lastInstanceId])
  const heroTarget = useMemo(() => (hero ? resumeTargetFor(hero, continuity) : null), [hero, continuity])
  const heroLiveOp = hero ? operations.find((o) => o.instanceId === hero.id && LIVE_OP_STATES.includes(o.state)) : undefined

  // ── Recently used (excluding the hero, most recent first) ──────────────────
  const recents = useMemo(
    () =>
      [...instances]
        .filter((i) => i.id !== hero?.id)
        .sort((a, b) => (b.lastOpenedAt ?? '').localeCompare(a.lastOpenedAt ?? ''))
        .slice(0, MAX_RECENT_ROWS),
    [instances, hero],
  )

  // ── All applications: pinned group (user order) then the rest (sorted) ─────
  const { pinnedRows, restRows } = useMemo(() => {
    const pinned = pinnedOrder
      .map((id) => instances.find((i) => i.id === id && i.pinned))
      .filter((i): i is ApplicationInstance => Boolean(i))
    const rest = instances.filter((i) => !i.pinned)
    const sorted =
      sort === 'name'
        ? [...rest].sort((a, b) => a.name.localeCompare(b.name))
        : sort === 'package'
          ? [...rest].sort((a, b) => a.packageDisplayName.localeCompare(b.packageDisplayName) || a.name.localeCompare(b.name))
          : [...rest].sort((a, b) => (b.lastOpenedAt ?? '').localeCompare(a.lastOpenedAt ?? ''))
    return { pinnedRows: pinned, restRows: sorted }
  }, [instances, pinnedOrder, sort])

  const query = filter.trim().toLowerCase()
  const matches = useCallback(
    (i: ApplicationInstance) =>
      !query || i.name.toLowerCase().includes(query) || i.packageDisplayName.toLowerCase().includes(query),
    [query],
  )
  const visiblePinned = pinnedRows.filter(matches)
  const visibleRest = restRows.filter(matches)
  const flatRows = useMemo(() => [...visiblePinned, ...visibleRest], [visiblePinned, visibleRest])

  // ── actions ────────────────────────────────────────────────────────────────
  const open = useCallback((instance: ApplicationInstance) => void navigate(`/app/${instance.id}`), [navigate])
  const openSettings = useCallback(
    (instance: ApplicationInstance) => void navigate(`/app/${instance.id}/settings`),
    [navigate],
  )

  const togglePin = useCallback(
    async (instance: ApplicationInstance) => {
      const next = !instance.pinned
      try {
        await getClient().applications.setPinned(instance.id, next)
        pushToast({
          kind: 'success',
          title: next ? `Pinned ${instance.name}` : `Unpinned ${instance.name}`,
          body: next ? 'Unpin anytime from the row menu or by pressing P on the row.' : undefined,
        })
      } catch {
        pushToast({ kind: 'error', title: `Couldn't ${next ? 'pin' : 'unpin'} ${instance.name}`, body: 'Nothing changed.' })
      } finally {
        refresh()
      }
    },
    [pushToast, refresh],
  )

  const acknowledge = useCallback(
    async (item: AttentionItem) => {
      try {
        await getClient().activity.acknowledgeAttention(item.id)
      } catch {
        pushToast({ kind: 'error', title: `Couldn't acknowledge “${item.title}”`, body: 'Nothing changed.' })
      } finally {
        refresh()
      }
    },
    [pushToast, refresh],
  )

  const rename = useCallback(
    async (instance: ApplicationInstance, name: string) => {
      await getClient().applications.rename(instance.id, name)
      pushToast({ kind: 'success', title: `Renamed to ${name}` })
      refresh()
    },
    [pushToast, refresh],
  )

  const move = useCallback(
    (instance: ApplicationInstance, direction: -1 | 1) => {
      const index = pinnedOrder.indexOf(instance.id)
      if (index === -1) return
      movePinned(instance.id, index + direction)
    },
    [pinnedOrder, movePinned],
  )

  // ── row-list keyboard model (roving tabindex over the flat visible rows) ───
  const roving = useRovingFocus(flatRows.length)
  const recentsRoving = useRovingFocus(recents.length)

  // ── route keyboard: Ctrl/Cmd+1…9 pinned jump, `/` filter focus ────────────
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null
      const editable = Boolean(target?.closest('input, textarea, select, [contenteditable="true"]'))
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && /^[1-9]$/.test(e.key)) {
        const pinned = pinnedOrder
          .map((id) => instances.find((i) => i.id === id && i.pinned))
          .filter((i): i is ApplicationInstance => Boolean(i))
        const instance = pinned[Number(e.key) - 1]
        if (instance) {
          e.preventDefault()
          void navigate(`/app/${instance.id}`)
        }
        return
      }
      if (e.key === '/' && !editable) {
        e.preventDefault()
        setSearchOpen(true)
        filterRef.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [pinnedOrder, instances, navigate])

  // ── palette commands: switch to recent apps, reopen last workspace ─────────
  const switchCommands = useMemo<ShellCommand[]>(() => {
    const byRecency = [...instances].sort((a, b) => (b.lastOpenedAt ?? '').localeCompare(a.lastOpenedAt ?? '')).slice(0, 5)
    const commands: ShellCommand[] = byRecency.map((instance) => ({
      id: `applications.switch.${instance.id}`,
      title: `Switch to ${instance.name}`,
      group: 'Applications',
      icon: LayoutGrid,
      keywords: ['application', 'switch', instance.packageDisplayName],
      run: () => void navigate(`/app/${instance.id}`),
    }))
    if (hero && heroTarget && continuity.lastInstanceId === hero.id) {
      commands.unshift({
        id: 'applications.reopen_last_workspace',
        title: `Reopen last workspace (${hero.name} · ${heroTarget.viewLabel})`,
        group: 'Applications',
        icon: History,
        keywords: ['resume', 'continue'],
        run: () => void navigate(heroTarget.route),
      })
    }
    return commands
  }, [instances, hero, heroTarget, continuity.lastInstanceId, navigate])
  useRegisterCommands(switchCommands)

  // ── render ─────────────────────────────────────────────────────────────────

  // Loading: layout-faithful bones (Continue slot reserves its height).
  if (loading && instances.length === 0) {
    return (
      <div className="h-full overflow-y-auto bg-app" data-testid="applications-page">
        <div className="mx-auto flex w-full max-w-[1120px] flex-col gap-6 p-4 md:p-6">
          <h1 className="sr-only">Applications</h1>
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-row w-full" />
          <Skeleton className="h-row w-full" />
          <Skeleton className="h-5 w-52" />
          <Skeleton className="h-row w-full" />
          <Skeleton className="h-row w-full" />
        </div>
      </div>
    )
  }

  // Error with no cached snapshot: full ErrorState with Retry.
  if (error && instances.length === 0 && !stale) {
    return (
      <div className="flex h-full items-center justify-center bg-app p-6" data-testid="applications-page">
        <ErrorState
          title="Applications couldn't be loaded"
          error={error}
          preservedNote="Nothing was changed."
          onRetry={refresh}
          retryLabel="Retry"
        />
      </div>
    )
  }

  const empty = instances.length === 0

  return (
    <div className="h-full overflow-y-auto bg-app" data-testid="applications-page">
      {/* Legacy alias for the shell route-smoke test (kept until the shell suite migrates). */}
      <div className="mx-auto flex w-full max-w-[1120px] flex-col gap-6 p-4 md:p-6" data-testid="applications-stub">
        <h1 className="sr-only">Applications</h1>

        {serviceOffline ? (
          <InlineNotice
            tone="blocked"
            title="Local service is offline"
            action={
              <div className="flex items-center gap-1">
                <Button size="sm" variant="ghost" onClick={() => void reconnectService()}>
                  Retry connection
                </Button>
                <Button size="sm" variant="ghost" onClick={() => void navigate('/settings')}>
                  Review endpoint
                </Button>
              </div>
            }
          >
            Workspaces are read-only snapshots.
          </InlineNotice>
        ) : null}

        {stale && !serviceOffline ? (
          <InlineNotice
            tone="attention"
            title="Showing last known state"
            action={
              <Button size="sm" variant="ghost" onClick={refresh}>
                Retry
              </Button>
            }
          >
            Applications couldn't be refreshed just now.
          </InlineNotice>
        ) : null}

        {empty ? (
          <>
            {!onboardingDismissed ? <OnboardingStrip onDismiss={dismissOnboarding} /> : null}
            <div className="rounded-md border border-border bg-surface">
              <EmptyState
                icon={LayoutGrid}
                title="No applications yet"
                description="Install a reviewed package to create your first governed workspace."
                action={{ label: 'Browse Catalog', onClick: () => void navigate('/catalog') }}
                secondaryAction={{ label: 'Import a local repository', onClick: () => void navigate('/catalog?import=1') }}
              />
            </div>
          </>
        ) : (
          <>
            {/* ── Section 1 · Continue where you left off ─────────────────── */}
            {hero && heroTarget ? (
              <section aria-label="Continue where you left off" data-testid="continue-section">
                <SectionHeader title="Continue where you left off" className="mb-2" />
                <ContinueHero
                  instance={hero}
                  liveOperation={heroLiveOp}
                  target={heroTarget}
                  onContinue={() => void navigate(heroTarget.route)}
                />
              </section>
            ) : null}

            {/* ── Section 2 · Needs attention (only when non-empty) ────────── */}
            {feed.length > 0 ? (
              <section aria-label="Needs attention" data-testid="needs-attention-section">
                <SectionHeader
                  title="Needs attention"
                  className="mb-2"
                  actions={
                    pendingApprovals.length > 0 ? (
                      <Link
                        to="/approvals"
                        className="text-xs font-medium text-accent hover:underline"
                        aria-label={`View all in Approvals, ${pendingApprovals.length} pending`}
                      >
                        Approvals inbox ({pendingApprovals.length})
                      </Link>
                    ) : undefined
                  }
                />
                <div className="rounded-md border border-border bg-surface px-1">
                  <AttentionFeed items={feed.slice(0, MAX_ATTENTION_ROWS)} readOnly={readOnly} onAcknowledge={acknowledge} />
                </div>
                {feed.length > MAX_ATTENTION_ROWS ? (
                  <Link to="/approvals" className="mt-1.5 inline-block text-xs font-medium text-accent hover:underline">
                    View all in Approvals
                  </Link>
                ) : null}
              </section>
            ) : null}

            {/* ── Section 3 · Active / recent operations (only when any) ───── */}
            {operations.length > 0 ? (
              <section aria-label="Active and recent operations" className="max-md:hidden" data-testid="operations-section">
                <SectionHeader title="Operations" className="mb-2" />
                <ul className="divide-y divide-border rounded-md border border-border bg-surface px-1">
                  {[...operations]
                    .sort((a, b) => Number(LIVE_OP_STATES.includes(b.state)) - Number(LIVE_OP_STATES.includes(a.state)) || b.updatedAt.localeCompare(a.updatedAt))
                    .slice(0, MAX_OPERATION_ROWS)
                    .map((op) => (
                      <li key={op.id} className="flex min-h-row items-center gap-2 px-2 py-1.5" data-testid={`operation-row-${op.id}`}>
                        <OperationStateLabel state={op.state} startedAt={op.startedAt} />
                        <span className="min-w-0 flex-1 truncate text-sm text-foreground">{op.title}</span>
                        <span className="hidden w-36 truncate text-xs text-foreground-tertiary lg:inline">
                          {instances.find((i) => i.id === op.instanceId)?.name ?? 'Unknown application'}
                        </span>
                        {typeof op.progressPercent === 'number' ? (
                          <span className="tnum w-10 text-right text-xs text-foreground-tertiary">{op.progressPercent}%</span>
                        ) : null}
                        <TimeAgo date={op.updatedAt} className="shrink-0" />
                        <button
                          type="button"
                          onClick={() => void navigate(`/app/${op.instanceId}`)}
                          className="inline-flex min-h-8 items-center rounded-sm border border-border px-2 text-xs font-medium text-accent transition-colors duration-instant hover:bg-hover"
                        >
                          Open
                        </button>
                      </li>
                    ))}
                </ul>
              </section>
            ) : null}

            {/* ── Section 4 · Recently used (desktop/tablet only per design) ── */}
            {recents.length > 0 ? (
              <section aria-label="Recently used" className="max-md:hidden" data-testid="recently-used-section">
                <SectionHeader title="Recently used" className="mb-2" />
                <ul
                  aria-label="Recently used applications"
                  className="rounded-md border border-border bg-surface px-1 py-1"
                  {...recentsRoving.listProps}
                >
                  {recents.map((instance, index) => (
                    <RecentInstanceRow
                      key={instance.id}
                      instance={instance}
                      status={statusOf(instance)}
                      readOnly={readOnly}
                      index={index}
                      roving={recentsRoving}
                      onOpen={open}
                      onTogglePin={togglePin}
                      onRename={canRename ? (i) => setRenameTarget(i) : undefined}
                      onOpenSettings={openSettings}
                    />
                  ))}
                </ul>
              </section>
            ) : null}

            {/* ── Section 5 · All applications ─────────────────────────────── */}
            <section aria-label="All applications" data-testid="all-applications-section">
              <SectionHeader
                title="All applications"
                className="mb-2"
                actions={
                  !readOnly ? (
                    <Button size="sm" onClick={() => void navigate('/catalog')} aria-label="New instance">
                      <Plus aria-hidden="true" />
                      <span className="max-md:hidden">New instance</span>
                    </Button>
                  ) : undefined
                }
              />

              {/* Toolbar: filter · sort · density (moves to overflow on mobile) */}
              <div className="mb-2 flex items-center gap-1.5">
                <div className={cn('relative flex-1 max-w-xs', !searchOpen && 'max-md:hidden')}>
                  <Search className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 text-foreground-tertiary" aria-hidden="true" />
                  <input
                    ref={filterRef}
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Escape') {
                        e.stopPropagation()
                        setFilter('')
                        e.currentTarget.blur()
                      }
                    }}
                    type="search"
                    placeholder="Filter applications…"
                    aria-label="Filter applications"
                    className="h-control w-full rounded-sm border border-input bg-surface pl-8 pr-7 text-sm text-foreground placeholder:text-foreground-tertiary"
                    data-testid="filter-input"
                  />
                  {filter ? (
                    <button
                      type="button"
                      aria-label="Clear filter"
                      onClick={() => setFilter('')}
                      className="absolute right-1 top-1/2 inline-flex min-h-6 min-w-6 -translate-y-1/2 items-center justify-center rounded-sm text-foreground-tertiary hover:text-foreground"
                    >
                      <X className="size-3.5" aria-hidden="true" />
                    </button>
                  ) : null}
                </div>
                <button
                  type="button"
                  aria-label="Show filter"
                  aria-expanded={searchOpen}
                  onClick={() => {
                    setSearchOpen(true)
                    filterRef.current?.focus()
                  }}
                  className={cn(
                    'inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm border border-border bg-surface text-foreground-secondary md:hidden',
                    searchOpen && 'hidden',
                  )}
                >
                  <Search className="size-4" aria-hidden="true" />
                </button>

                {/* Sort menu (desktop select-style; inside overflow on mobile) */}
                <DropdownMenu>
                  <DropdownMenuTrigger className="inline-flex min-h-10 items-center gap-1.5 rounded-sm border border-border bg-surface px-2 text-xs font-medium text-foreground-secondary transition-colors duration-instant hover:bg-hover max-md:min-w-10 max-md:justify-center md:min-h-control">
                    <ListFilter className="size-4" aria-hidden="true" />
                    <span className="max-md:hidden">Sort: {SORT_LABELS[sort]}</span>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="bg-surface">
                    <DropdownMenuRadioGroup value={sort} onValueChange={(v) => setSort(v as ApplicationsSort)}>
                      <DropdownMenuRadioItem value="recent">Recent</DropdownMenuRadioItem>
                      <DropdownMenuRadioItem value="name">Name</DropdownMenuRadioItem>
                      <DropdownMenuRadioItem value="package">Package</DropdownMenuRadioItem>
                    </DropdownMenuRadioGroup>
                    <DropdownMenuSeparator className="md:hidden" />
                    <DropdownMenuItem className="md:hidden" onSelect={() => setDensity(density === 'compact' ? 'comfortable' : 'compact')}>
                      {density === 'compact' ? <Rows2 aria-hidden="true" /> : <Rows3 aria-hidden="true" />}
                      {density === 'compact' ? 'Comfortable density' : 'Compact density'}
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>

                <button
                  type="button"
                  aria-label={density === 'compact' ? 'Switch to comfortable density' : 'Switch to compact density'}
                  aria-pressed={density === 'comfortable'}
                  onClick={() => setDensity(density === 'compact' ? 'comfortable' : 'compact')}
                  className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm border border-border bg-surface text-foreground-secondary transition-colors duration-instant hover:bg-hover max-md:hidden md:min-h-control md:min-w-control"
                  data-testid="density-toggle"
                >
                  {density === 'compact' ? <Rows2 className="size-4" aria-hidden="true" /> : <Rows3 className="size-4" aria-hidden="true" />}
                </button>
              </div>

              {flatRows.length === 0 ? (
                <div className="rounded-md border border-border bg-surface px-4 py-6 text-center">
                  <p className="text-sm text-foreground-secondary">No applications match “{filter}”.</p>
                  <button type="button" onClick={() => setFilter('')} className="mt-1 text-xs font-medium text-accent hover:underline">
                    Clear filter
                  </button>
                </div>
              ) : density === 'compact' ? (
                <ul
                  aria-label="Installed applications"
                  className="rounded-md border border-border bg-surface px-1 py-1"
                  {...roving.listProps}
                >
                  {visiblePinned.length > 0 ? (
                    <li aria-hidden="true" className="px-2 pb-0.5 pt-1 text-xs font-medium text-foreground-tertiary">
                      Pinned
                    </li>
                  ) : null}
                  {visiblePinned.map((instance, index) => (
                    <InstanceRow
                      key={instance.id}
                      instance={instance}
                      status={statusOf(instance)}
                      readOnly={readOnly}
                      index={index}
                      roving={roving}
                      pinnedPosition={{ index, count: visiblePinned.length }}
                      onDragStartRow={(i) => {
                        dragIdRef.current = i.id
                      }}
                      onDropOnRow={(target) => {
                        const dragged = dragIdRef.current
                        dragIdRef.current = null
                        if (!dragged || dragged === target.id) return
                        const toIndex = pinnedOrder.indexOf(target.id)
                        if (toIndex !== -1) movePinned(dragged, toIndex)
                      }}
                      onOpen={open}
                      onTogglePin={togglePin}
                      onRename={canRename ? (i) => setRenameTarget(i) : undefined}
                      onOpenSettings={openSettings}
                      onMove={move}
                    />
                  ))}
                  {visiblePinned.length > 0 && visibleRest.length > 0 ? (
                    <li aria-hidden="true" className="px-2 pb-0.5 pt-2 text-xs font-medium text-foreground-tertiary">
                      All applications
                    </li>
                  ) : null}
                  {visibleRest.map((instance, restIndex) => (
                    <InstanceRow
                      key={instance.id}
                      instance={instance}
                      status={statusOf(instance)}
                      readOnly={readOnly}
                      index={visiblePinned.length + restIndex}
                      roving={roving}
                      onOpen={open}
                      onTogglePin={togglePin}
                      onRename={canRename ? (i) => setRenameTarget(i) : undefined}
                      onOpenSettings={openSettings}
                      onMove={move}
                    />
                  ))}
                </ul>
              ) : (
                <ul
                  aria-label="Installed applications"
                  className="grid grid-cols-1 gap-3 xl:grid-cols-2"
                  {...roving.listProps}
                >
                  {visiblePinned.map((instance, index) => (
                    <InstanceCard
                      key={instance.id}
                      instance={instance}
                      status={statusOf(instance)}
                      readOnly={readOnly}
                      index={index}
                      roving={roving}
                      pinnedPosition={{ index, count: visiblePinned.length }}
                      onDragStartRow={(i) => {
                        dragIdRef.current = i.id
                      }}
                      onDropOnRow={(target) => {
                        const dragged = dragIdRef.current
                        dragIdRef.current = null
                        if (!dragged || dragged === target.id) return
                        const toIndex = pinnedOrder.indexOf(target.id)
                        if (toIndex !== -1) movePinned(dragged, toIndex)
                      }}
                      onOpen={open}
                      onTogglePin={togglePin}
                      onRename={canRename ? (i) => setRenameTarget(i) : undefined}
                      onOpenSettings={openSettings}
                      onMove={move}
                    />
                  ))}
                  {visibleRest.map((instance, restIndex) => (
                    <InstanceCard
                      key={instance.id}
                      instance={instance}
                      status={statusOf(instance)}
                      readOnly={readOnly}
                      index={visiblePinned.length + restIndex}
                      roving={roving}
                      onOpen={open}
                      onTogglePin={togglePin}
                      onRename={canRename ? (i) => setRenameTarget(i) : undefined}
                      onOpenSettings={openSettings}
                      onMove={move}
                    />
                  ))}
                </ul>
              )}
            </section>
          </>
        )}
      </div>

      {canRename ? (
        <RenameDialog
          open={renameTarget !== null}
          currentName={renameTarget?.name ?? ''}
          onOpenChange={(openDialog) => {
            if (!openDialog) setRenameTarget(null)
          }}
          onSubmit={async (name) => {
            if (renameTarget) await rename(renameTarget, name)
          }}
        />
      ) : null}
    </div>
  )
}
