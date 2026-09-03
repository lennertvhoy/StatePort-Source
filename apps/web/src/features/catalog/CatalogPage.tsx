/**
 * CatalogPage (`#/catalog`) — the reviewed package installation surface
 * (catalog.md). A curated shelf, not a marketplace: rows of factual package
 * identity, review classification, release status, capabilities, instance
 * counts; detail drawer deep-linked via `?package=:id`; install always goes
 * through the plain-language review step (InstallReview).
 *
 * Keyboard: `/` focus search · ↑/↓ move between rows · Enter opens detail ·
 * `I` opens the install review for the focused row · Esc closes (radix).
 */
import { Database, ListFilter, MoreHorizontal, Package, PackageOpen, Search, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import type { ApplicationInstance, CapabilityId, CatalogPackage } from '@/client'
import { getClient } from '@/client'
import {
  Drawer,
  EmptyState,
  ErrorState,
  InlineNotice,
  Kbd,
  SectionHeader,
  SkeletonRows,
  StatusBadge,
  Tooltip,
} from '@/components'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { useSessionStore } from '@/state'
import { InstanceGlyphTile } from '@/shell/appIcon'
import { isEditableTarget } from '@/shell/platform'
import { useRegisterCommands } from '@/shell/commands'

import {
  CAPABILITY_PRESENTATION,
  EMPTY_CATALOG_FILTERS,
  activeFacetCount,
  catalogCapabilities,
  filterCatalog,
  instanceCountLabel,
  isFilterActive,
  releaseStatusLabel,
  reviewClassificationPresentation,
} from './catalogModel'
import type { CatalogFilters } from './catalogModel'
import { InstallReview } from './InstallReview'
import { ImportRepositoryDrawer } from './ImportRepositoryDrawer'
import { PackageDetailContent } from './PackageDetailContent'

function rowDomId(packageId: string): string {
  return `catalog-row-${packageId}`
}

const EMPTY_PACKAGES: CatalogPackage[] = []
const EMPTY_INSTANCES: ApplicationInstance[] = []

export default function CatalogPage() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const activeScenario = useSessionStore((s) => s.activeScenario)

  // Keyed fetch result: packages/loading/error/staleCache derive from whether
  // the in-flight key has landed, so the effect never sets state synchronously.
  const [result, setResult] = useState<{
    key: string
    packages: CatalogPackage[]
    instances: ApplicationInstance[]
    staleCache: boolean
    error: unknown
  } | null>(null)
  const [nonce, setNonce] = useState(0)
  const lastGood = useRef<CatalogPackage[] | null>(null)

  const [filters, setFilters] = useState<CatalogFilters>(EMPTY_CATALOG_FILTERS)
  const [secondaryNotice, setSecondaryNotice] = useState<'template' | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  const [drawerView, setDrawerView] = useState<'detail' | 'install'>('detail')

  const searchRef = useRef<HTMLInputElement>(null)

  // ── Data ─────────────────────────────────────────────────────────────────
  const refresh = useCallback(() => setNonce((n) => n + 1), [])
  const requestKey = `${nonce}#${activeScenario ?? ''}`

  useEffect(() => {
    let cancelled = false
    Promise.all([getClient().catalog.list(), getClient().applications.list()])
      .then(([catalogList, instanceList]) => {
        if (cancelled) return
        lastGood.current = catalogList
        setResult({ key: requestKey, packages: catalogList, instances: instanceList, staleCache: false, error: null })
      })
      .catch((err) => {
        if (cancelled) return
        // Honest fallback: keep the last loaded catalog visible with a stale
        // banner instead of fabricating data (catalog.md states).
        const last = lastGood.current
        if (last) {
          setResult((prev) => ({ key: requestKey, packages: last, instances: prev?.instances ?? [], staleCache: true, error: null }))
        } else {
          setResult({ key: requestKey, packages: [], instances: [], staleCache: false, error: err })
        }
      })
    return () => {
      cancelled = true
    }
  }, [nonce, activeScenario, requestKey])

  const landed = result && result.key === requestKey ? result : null
  // Stale-while-revalidate: the previous list stays visible during a refresh
  // (e.g. the install success screen keeps its drawer context).
  const packages = (landed ?? result)?.packages ?? EMPTY_PACKAGES
  const instances = (landed ?? result)?.instances ?? EMPTY_INSTANCES
  const staleCache = landed?.staleCache ?? false
  const error = landed?.error ?? null
  const loading = !landed

  const filtered = useMemo(() => filterCatalog(packages, filters), [packages, filters])
  const updates = useMemo(() => packages.filter((p) => p.updateAvailable), [packages])
  const capabilityOptions = useMemo(() => catalogCapabilities(packages), [packages])

  // ── Deep-linked detail drawer (?package=:id) ─────────────────────────────
  const selectedPackageId = searchParams.get('package')
  const importRequested = searchParams.get('import') === '1'
  const selectedEntry = useMemo(
    () => packages.find((p) => p.pkg.id === selectedPackageId) ?? null,
    [packages, selectedPackageId],
  )

  const closeDrawer = useCallback(() => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        next.delete('package')
        return next
      },
      { replace: true },
    )
  }, [setSearchParams])

  const setPackageParam = useCallback(
    (packageId: string) => {
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          next.set('package', packageId)
          return next
        },
        { replace: true },
      )
    },
    [setSearchParams],
  )

  const openDetail = useCallback(
    (packageId: string) => {
      setDrawerView('detail')
      setPackageParam(packageId)
    },
    [setPackageParam],
  )

  const openInstall = useCallback(
    (packageId: string) => {
      const entry = packages.find((candidate) => candidate.pkg.id === packageId)
      if (!entry || entry.installAvailable === false) return
      setDrawerView('install')
      setPackageParam(packageId)
    },
    [packages, setPackageParam],
  )

  // ── Commands + page keyboard ─────────────────────────────────────────────
  const commands = useMemo(
    () => [
      {
        id: 'catalog.open',
        title: 'Open catalog',
        group: 'Navigation' as const,
        icon: Package,
        run: () => navigate('/catalog'),
        when: () => typeof window !== 'undefined' && !window.location.hash.startsWith('#/catalog'),
      },
      {
        id: 'catalog.search',
        title: 'Search packages',
        group: 'Actions' as const,
        icon: Search,
        run: () => searchRef.current?.focus(),
      },
    ],
    [navigate],
  )
  useRegisterCommands(commands)

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.isComposing || e.metaKey || e.ctrlKey || e.altKey) return
      if (isEditableTarget(e.target)) return
      if (document.querySelector('[data-testid="drawer"][data-state="open"], [role="dialog"]')) return
      const ids = filtered.map((p) => p.pkg.id)
      if (e.key === '/') {
        e.preventDefault()
        searchRef.current?.focus()
        return
      }
      if (ids.length === 0) return
      const activeId = document.activeElement instanceof HTMLElement ? document.activeElement.id : ''
      const current = ids.findIndex((id) => rowDomId(id) === activeId)
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault()
        const next =
          e.key === 'ArrowDown'
            ? current < 0
              ? 0
              : Math.min(ids.length - 1, current + 1)
            : current < 0
              ? ids.length - 1
              : Math.max(0, current - 1)
        document.getElementById(rowDomId(ids[next]))?.focus()
        return
      }
      if ((e.key === 'i' || e.key === 'I') && current >= 0) {
        e.preventDefault()
        openInstall(ids[current])
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [filtered, openInstall])

  // ── Render ───────────────────────────────────────────────────────────────

  const facetCount = activeFacetCount(filters)

  return (
    // Legacy hook: the shell route-smoke test (src/shell/__tests__/routes.test.tsx,
    // orchestrator-owned) still selects `catalog-stub`; keep it on the real surface.
    <div className="flex h-full min-h-0 flex-col bg-app" data-testid="catalog-stub">
      <div className="mx-auto flex w-full max-w-[1120px] min-h-0 flex-1 flex-col px-4 py-4">
        {/* Header */}
        <header className="flex flex-wrap items-center gap-2">
          <h1 className="text-xl text-foreground">Catalog</h1>
          <p className="hidden text-xs text-foreground-tertiary sm:block">Reviewed packages for this device</p>
          <div className="ml-auto flex items-center gap-2">
            <Button asChild variant="ghost" size="sm">
              <Link to="/sources">
                <Database aria-hidden="true" />
                Source status
              </Link>
            </Button>
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-foreground-tertiary"
                aria-hidden="true"
              />
              <Input
                ref={searchRef}
                type="search"
                placeholder="Search packages…"
                aria-label="Search packages"
                value={filters.query}
                onChange={(e) => setFilters((f) => ({ ...f, query: e.target.value }))}
                onKeyDown={(e) => {
                  if (e.key === 'Escape' && filters.query) {
                    e.stopPropagation()
                    setFilters((f) => ({ ...f, query: '' }))
                  }
                }}
                className="h-control-sm w-48 pl-8 pr-7 sm:w-56"
              />
              <Kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-foreground-tertiary">
                /
              </Kbd>
            </div>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" aria-label="Filter packages">
                  <ListFilter aria-hidden="true" />
                  Filters
                  {facetCount > 0 ? (
                    <span className="inline-flex min-w-5 items-center justify-center rounded-sm bg-accent-soft px-1 text-xs font-semibold text-accent-soft-text">
                      {facetCount}
                    </span>
                  ) : null}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-60">
                <DropdownMenuLabel>Capability</DropdownMenuLabel>
                {capabilityOptions.map((cap: CapabilityId) => (
                  <DropdownMenuCheckboxItem
                    key={cap}
                    checked={filters.capabilities.includes(cap)}
                    onSelect={(e) => e.preventDefault()}
                    onCheckedChange={(checked) =>
                      setFilters((f) => ({
                        ...f,
                        capabilities: checked
                          ? [...f.capabilities, cap]
                          : f.capabilities.filter((c) => c !== cap),
                      }))
                    }
                  >
                    {CAPABILITY_PRESENTATION[cap].label}
                  </DropdownMenuCheckboxItem>
                ))}
                <DropdownMenuSeparator />
                <DropdownMenuLabel>Installed state</DropdownMenuLabel>
                <DropdownMenuRadioGroup
                  value={filters.installed}
                  onValueChange={(value) =>
                    setFilters((f) => ({ ...f, installed: value as CatalogFilters['installed'] }))
                  }
                >
                  <DropdownMenuRadioItem value="all">All packages</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem value="installed">Installed</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem value="not_installed">Not installed</DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
                <DropdownMenuSeparator />
                <DropdownMenuCheckboxItem
                  checked={filters.updatesOnly}
                  onCheckedChange={(checked) => setFilters((f) => ({ ...f, updatesOnly: checked === true }))}
                >
                  Updates available only
                </DropdownMenuCheckboxItem>
              </DropdownMenuContent>
            </DropdownMenu>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon-sm" aria-label="More catalog actions">
                  <MoreHorizontal aria-hidden="true" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onSelect={() => setImportOpen(true)}>
                  Import a local repository
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setSecondaryNotice('template')}>
                  Create from a reviewed template
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        {/* Secondary paths — honest about the current backend contract. */}
        {secondaryNotice ? (
          <InlineNotice
            tone="informational"
            className="mt-3"
            action={
              <Button variant="ghost" size="icon-sm" aria-label="Dismiss" onClick={() => setSecondaryNotice(null)}>
                <X aria-hidden="true" />
              </Button>
            }
          >
            {secondaryNotice === 'template'
              ? 'Creating a package from a template is not exposed by the current backend. Installing a reviewed package is the supported starting point. Importing an allowlisted local repository is the governed secondary path.'
              : null}
          </InlineNotice>
        ) : null}

        {staleCache ? (
          <InlineNotice
            tone="attention"
            className="mt-3"
            action={
              <Button size="sm" variant="ghost" onClick={refresh}>
                Retry
              </Button>
            }
          >
            The catalog could not be refreshed — showing the last loaded copy.
          </InlineNotice>
        ) : null}

        {/* Body */}
        {loading ? (
          <SkeletonRows rows={5} className="mt-4" />
        ) : error ? (
          <div className="mt-4 rounded-md border border-border bg-surface">
            <ErrorState
              title="The package catalog couldn't be loaded"
              error={error}
              preservedNote="No packages were installed or changed."
              onRetry={refresh}
            />
          </div>
        ) : (
          <div className="mt-4 min-h-0 flex-1 overflow-y-auto">
            {/* Updates section — quiet, reviewed actions only */}
            {updates.length > 0 && !isFilterActive(filters) ? (
              <section aria-label="Updates available" className="mb-4 rounded-md border border-border bg-surface px-3 py-2">
                <SectionHeader
                  title="Updates available"
                  description="Reviewed release metadata. Applying an update is not yet exposed by the current web contract."
                  className="px-0 py-1"
                />
                <ul className="divide-y divide-border">
                  {updates.map((entry) => (
                    <li key={entry.pkg.id} className="flex items-center gap-2 py-1.5 text-sm">
                      <InstanceGlyphTile instance={{ packageName: entry.pkg.name, name: entry.pkg.name }} />
                      <span className="font-medium text-foreground">{entry.pkg.displayName}</span>
                      <span className="tnum text-xs text-foreground-secondary">
                        v{entry.updateAvailable!.fromVersion} → v{entry.updateAvailable!.toVersion}
                      </span>
                      <span className="hidden min-w-0 flex-1 truncate text-foreground-secondary sm:block">
                        {entry.updateAvailable!.releaseNotes}
                      </span>
                      <Button size="sm" variant="ghost" className="ml-auto" onClick={() => openDetail(entry.pkg.id)}>
                        What’s new
                      </Button>
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}

            {filtered.length === 0 ? (
              <div className="rounded-md border border-border bg-surface">
                <EmptyState
                  icon={PackageOpen}
                  title="No packages match"
                  description="No reviewed package matches the current search and filters."
                  action={
                    isFilterActive(filters)
                      ? { label: 'Clear filters', onClick: () => setFilters(EMPTY_CATALOG_FILTERS) }
                      : undefined
                  }
                />
              </div>
            ) : (
              <ul aria-label="Packages" className="rounded-md border border-border bg-surface" data-testid="package-list">
                {filtered.map((entry) => {
                  const { pkg } = entry
                  const classification = reviewClassificationPresentation(pkg)
                  const installed = entry.installedInstanceCount > 0
                  return (
                    <li key={pkg.id} className="border-b border-border last:border-b-0">
                      <div className="flex items-center gap-2 px-2 py-1.5">
                        <button
                          type="button"
                          id={rowDomId(pkg.id)}
                          onClick={() => openDetail(pkg.id)}
                          className="flex min-h-14 min-w-0 flex-1 items-center gap-3 rounded-sm px-2 py-1 text-left transition-colors duration-instant hover:bg-hover focus-visible:outline-2 focus-visible:outline-focus"
                          aria-label={`${pkg.displayName} — open details`}
                          data-testid="package-row"
                        >
                          <InstanceGlyphTile
                            instance={{ packageName: pkg.name, name: pkg.name }}
                            className="size-8 rounded-md [&_svg]:size-4"
                          />
                          <span className="min-w-0 flex-1">
                            <span className="flex items-center gap-2">
                              <span className="truncate text-md font-semibold text-foreground">{pkg.displayName}</span>
                              <StatusBadge
                                state={classification.state}
                                label={classification.label}
                                icon={classification.icon}
                              />
                            </span>
                            <span className="block truncate text-xs text-foreground-secondary">{pkg.description}</span>
                          </span>
                          <span className="hidden shrink-0 items-center gap-1 lg:flex" aria-label="Capabilities">
                            {pkg.capabilities.slice(0, 5).map((cap) => {
                              const { label, icon: Icon } = CAPABILITY_PRESENTATION[cap]
                              return (
                                <Tooltip key={cap} content={label}>
                                  <span className="inline-flex size-6 items-center justify-center rounded-sm text-foreground-tertiary">
                                    <Icon className="size-3.5" aria-hidden="true" />
                                    <span className="sr-only">{label}</span>
                                  </span>
                                </Tooltip>
                              )
                            })}
                          </span>
                          <span className="hidden w-36 shrink-0 text-right md:block">
                            <span className="tnum block text-xs text-foreground-secondary">
                              {releaseStatusLabel(pkg.releaseStatus)} · v{pkg.version}
                            </span>
                            <span className="block text-xs text-foreground-tertiary">
                              {instanceCountLabel(entry.installedInstanceCount)}
                            </span>
                            {entry.updateAvailable ? (
                              <span className="block text-xs text-status-informational">
                                v{entry.updateAvailable.toVersion} available
                              </span>
                            ) : null}
                          </span>
                        </button>
                        {entry.installAvailable === false ? (
                          <span
                            className="hidden max-w-56 shrink-0 text-right text-xs text-foreground-tertiary sm:block"
                            data-testid={`install-unavailable-reason-${pkg.name}`}
                          >
                            {entry.installUnavailableReason ?? 'The connected service did not offer an installable exact identity.'}
                          </span>
                        ) : null}
                        <Button
                          size="sm"
                          variant={installed ? 'secondary' : 'default'}
                          className="shrink-0"
                          onClick={() => openInstall(pkg.id)}
                          disabled={entry.installAvailable === false}
                          title={entry.installAvailable === false ? entry.installUnavailableReason : installed ? 'Already installed — this creates an additional instance.' : undefined}
                          data-testid={`install-${pkg.name}`}
                        >
                          {entry.installAvailable === false ? 'Unavailable' : installed ? 'New instance' : 'Install'}
                        </Button>
                      </div>
                    </li>
                  )
                })}
              </ul>
            )}

            {/* Quiet secondary path at the foot of the list */}
            <p className="px-1 py-3 text-xs text-foreground-tertiary">
              Advanced:{' '}
              <button
                type="button"
                className="text-accent underline-offset-2 hover:underline"
                onClick={() => setImportOpen(true)}
              >
                Import a local repository
              </button>{' '}
              — reviewed installation stays the ordinary path.
            </p>
          </div>
        )}
      </div>

      {/* Detail drawer / install review (deep-linked) */}
      <ImportRepositoryDrawer
        open={importOpen || importRequested}
        onOpenChange={(open) => {
          setImportOpen(open)
          if (importRequested) {
            setSearchParams(
              (previous) => {
                const next = new URLSearchParams(previous)
                next.delete('import')
                return next
              },
              { replace: true },
            )
          }
          // A completed registration adds an instance — refresh the catalog
          // when the drawer closes so the new application appears.
          if (!open) refresh()
        }}
      />
      <Drawer
        open={selectedEntry !== null}
        onOpenChange={(open) => {
          if (!open) closeDrawer()
        }}
        title={drawerView === 'install' ? `Install ${selectedEntry?.pkg.displayName ?? ''}` : (selectedEntry?.pkg.displayName ?? '')}
        description={
          selectedEntry
            ? drawerView === 'install'
              ? 'Review what this package can do before anything is installed.'
              : `${releaseStatusLabel(selectedEntry.pkg.releaseStatus)} · v${selectedEntry.pkg.version}`
            : undefined
        }
        footer={
          drawerView === 'detail' && selectedEntry ? (
            <Button
              onClick={() => setDrawerView('install')}
              disabled={selectedEntry.installAvailable === false}
              title={
                selectedEntry.installAvailable === false
                  ? selectedEntry.installUnavailableReason
                  : selectedEntry.installedInstanceCount > 0
                    ? 'Already installed — this creates an additional instance.'
                    : undefined
              }
              data-testid="drawer-install"
            >
              {selectedEntry.installAvailable === false
                ? 'Unavailable'
                : selectedEntry.installedInstanceCount > 0
                  ? 'New instance'
                  : 'Install'}
            </Button>
          ) : undefined
        }
      >
        {selectedEntry ? (
          drawerView === 'install' ? (
            <InstallReview
              entry={selectedEntry}
              open
              onOpenChange={(open) => {
                if (!open) closeDrawer()
              }}
              onInstalled={() => {
                // The refresh re-lists applications, picking up the install.
                refresh()
              }}
            />
          ) : (
            <PackageDetailContent
              entry={selectedEntry}
              instances={instances.filter((i) => i.packageId === selectedEntry.pkg.id)}
            />
          )
        ) : null}
      </Drawer>
    </div>
  )
}
