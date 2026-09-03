/**
 * Catalog presentation model — capability labels/icons, review classification,
 * network-policy language, and list-filter helpers for CatalogPage.
 *
 * The catalog is a reviewed package installation surface, not a marketplace:
 * rows stay factual (identity, review classification, release status,
 * capabilities, instance count); hashes/provenance stay behind the Details
 * disclosure (catalog.md / design.md §2).
 */
import {
  Award,
  BadgeCheck,
  Bell,
  DatabaseBackup,
  FolderOpen,
  Gauge,
  MessageSquare,
  ScrollText,
  Server,
  SquarePen,
  SquareTerminal,
  Target,
  Users,
  Workflow,
  Wrench,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import type {
  ApplicationPackage,
  CapabilityId,
  CatalogPackage,
  NetworkPolicy,
  SemanticState,
} from '@/client'

// ── Capability presentation ──────────────────────────────────────────────────

export const CAPABILITY_PRESENTATION: Record<CapabilityId, { label: string; icon: LucideIcon }> = {
  conversation: { label: 'Conversation', icon: MessageSquare },
  workbench: { label: 'Workbench', icon: Wrench },
  file_viewer: { label: 'Files', icon: FolderOpen },
  editor: { label: 'Editor', icon: SquarePen },
  terminal: { label: 'Terminal', icon: SquareTerminal },
  progress_dashboard: { label: 'Progress', icon: Gauge },
  goal_execution: { label: 'Goals', icon: Target },
  cto_orchestration: { label: 'Orchestration', icon: Workflow },
  benchmark_evidence: { label: 'Evidence', icon: Award },
  proactive_notifications: { label: 'Notifications', icon: Bell },
  backup: { label: 'Backup', icon: DatabaseBackup },
  infrastructure: { label: 'Infrastructure', icon: Server },
  receipts: { label: 'Receipts', icon: ScrollText },
}

export function capabilityLabel(id: CapabilityId): string {
  return CAPABILITY_PRESENTATION[id]?.label ?? id
}

// ── Review classification / release status / network policy ──────────────────

export function reviewClassificationPresentation(pkg: ApplicationPackage): {
  state: SemanticState
  label: string
  icon: LucideIcon
} {
  return pkg.reviewClassification === 'reviewed'
    ? { state: 'informational', label: 'Reviewed', icon: BadgeCheck }
    : { state: 'neutral', label: 'Community — unreviewed', icon: Users }
}

export function releaseStatusLabel(status: ApplicationPackage['releaseStatus']): string {
  switch (status) {
    case 'stable':
      return 'Stable'
    case 'beta':
      return 'Beta'
    case 'experimental':
      return 'Experimental'
  }
}

export function networkPolicyLabel(policy: NetworkPolicy): string {
  switch (policy) {
    case 'none':
      return 'No network access'
    case 'local_only':
      return 'Local network only'
    case 'restricted':
      return 'Restricted network access'
    case 'full':
      return 'Full network access'
  }
}

/** Elevated scope (catalog.md §install review): terminal rights or any network. */
export function hasElevatedScope(pkg: ApplicationPackage): boolean {
  return pkg.capabilities.includes('terminal') || pkg.networkPolicy !== 'none'
}

// ── Filters ──────────────────────────────────────────────────────────────────

export interface CatalogFilters {
  query: string
  /** Union match: a package passes when it has ANY selected capability. */
  capabilities: CapabilityId[]
  installed: 'all' | 'installed' | 'not_installed'
  updatesOnly: boolean
}

export const EMPTY_CATALOG_FILTERS: CatalogFilters = {
  query: '',
  capabilities: [],
  installed: 'all',
  updatesOnly: false,
}

export function isFilterActive(filters: CatalogFilters): boolean {
  return (
    filters.query.trim() !== '' ||
    filters.capabilities.length > 0 ||
    filters.installed !== 'all' ||
    filters.updatesOnly
  )
}

export function activeFacetCount(filters: CatalogFilters): number {
  let n = 0
  if (filters.capabilities.length > 0) n += 1
  if (filters.installed !== 'all') n += 1
  if (filters.updatesOnly) n += 1
  return n
}

export function filterCatalog(packages: CatalogPackage[], filters: CatalogFilters): CatalogPackage[] {
  const q = filters.query.trim().toLowerCase()
  return packages.filter((entry) => {
    if (q) {
      const haystack = `${entry.pkg.displayName} ${entry.pkg.name} ${entry.pkg.description}`.toLowerCase()
      if (!haystack.includes(q)) return false
    }
    if (filters.capabilities.length > 0) {
      if (!filters.capabilities.some((cap) => entry.pkg.capabilities.includes(cap))) return false
    }
    if (filters.installed === 'installed' && entry.installedInstanceCount === 0) return false
    if (filters.installed === 'not_installed' && entry.installedInstanceCount > 0) return false
    if (filters.updatesOnly && !entry.updateAvailable) return false
    return true
  })
}

/** Every capability present in at least one catalog package (filter options). */
export function catalogCapabilities(packages: CatalogPackage[]): CapabilityId[] {
  const seen = new Set<CapabilityId>()
  for (const entry of packages) for (const cap of entry.pkg.capabilities) seen.add(cap)
  return [...seen]
}

export function instanceCountLabel(count: number): string {
  if (count === 0) return 'Not installed'
  return count === 1 ? '1 instance' : `${count} instances`
}
