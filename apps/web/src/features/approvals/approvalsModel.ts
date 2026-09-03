/**
 * Approvals presentation model (approvals.md / design.md §7).
 *
 * Risk → semantic mapping (Routine / Elevated / Destructive), filter + sort
 * helpers, expiry and stale-plan detection, and exact-target extraction for
 * destructive confirmation. Pending is `waiting`, never danger; destructive
 * actions are never bulk-approvable.
 */
import { OctagonAlert, ShieldCheck, TriangleAlert } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import type { Approval, RiskLevel, SemanticState } from '@/client'

// ── Risk presentation ────────────────────────────────────────────────────────

export const RISK_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 }

export function riskPresentation(risk: RiskLevel): { state: SemanticState; label: string; icon: LucideIcon } {
  switch (risk) {
    case 'low':
      return { state: 'informational', label: 'Routine', icon: ShieldCheck }
    case 'medium':
      return { state: 'attention', label: 'Elevated', icon: TriangleAlert }
    case 'high':
      return { state: 'danger', label: 'Destructive', icon: OctagonAlert }
  }
}

// ── Status presentation (decided view) ───────────────────────────────────────

export function approvalStatusPresentation(status: Approval['status']): {
  state: SemanticState
  label: string
  icon: LucideIcon
} {
  switch (status) {
    case 'pending':
      return { state: 'waiting', label: 'Awaiting approval', icon: ShieldCheck }
    case 'approved':
      return { state: 'success', label: 'Approved', icon: ShieldCheck }
    case 'rejected':
      return { state: 'neutral', label: 'Rejected', icon: ShieldCheck }
    case 'expired':
      return { state: 'neutral', label: 'Expired', icon: ShieldCheck }
  }
}

// ── Expiry / staleness ───────────────────────────────────────────────────────

export const EXPIRING_SOON_MS = 12 * 3_600_000
const EXPIRY_URGENT_MS = 3_600_000 // attention styling under 1 h (approvals.md)

export function isExpired(approval: Approval, now = Date.now()): boolean {
  return (
    approval.status === 'pending' &&
    approval.expiresAt !== undefined &&
    new Date(approval.expiresAt).getTime() <= now
  )
}

export function isExpiringSoon(approval: Approval, now = Date.now()): boolean {
  if (!approval.expiresAt || approval.status !== 'pending' || isExpired(approval, now)) return false
  return new Date(approval.expiresAt).getTime() - now <= EXPIRING_SOON_MS
}

export function isExpiryUrgent(approval: Approval, now = Date.now()): boolean {
  if (!approval.expiresAt || approval.status !== 'pending' || isExpired(approval, now)) return false
  return new Date(approval.expiresAt).getTime() - now <= EXPIRY_URGENT_MS
}

/** Stale: the underlying state moved since the plan was prepared (digest mismatch). */
export function isStale(approval: Approval): boolean {
  return (
    approval.status === 'pending' &&
    Boolean(approval.currentDigest) &&
    approval.currentDigest!.value !== approval.planDigest.value
  )
}

// ── Filters + sort ───────────────────────────────────────────────────────────

export type ApprovalView = 'pending' | 'decided'
export type ApprovalSort = 'newest' | 'risk' | 'expiring'

export interface ApprovalFilters {
  view: ApprovalView
  query: string
  risks: RiskLevel[]
  instanceId: string | null
  operationType: string | null
  expiringSoon: boolean
}

export const EMPTY_APPROVAL_FILTERS: ApprovalFilters = {
  view: 'pending',
  query: '',
  risks: [],
  instanceId: null,
  operationType: null,
  expiringSoon: false,
}

export function activeFacetCount(filters: ApprovalFilters): number {
  let n = 0
  if (filters.risks.length > 0) n += 1
  if (filters.instanceId) n += 1
  if (filters.operationType) n += 1
  if (filters.expiringSoon) n += 1
  return n
}

export function filterApprovals(
  approvals: Approval[],
  filters: ApprovalFilters,
  instanceName: (instanceId: string) => string | undefined,
  now = Date.now(),
): Approval[] {
  const q = filters.query.trim().toLowerCase()
  return approvals.filter((a) => {
    if (filters.view === 'pending' ? a.status !== 'pending' : a.status === 'pending') return false
    if (filters.risks.length > 0 && !filters.risks.includes(a.risk)) return false
    if (filters.instanceId && a.instanceId !== filters.instanceId) return false
    if (filters.operationType && a.operationType !== filters.operationType) return false
    if (filters.expiringSoon && !isExpiringSoon(a, now)) return false
    if (q) {
      const haystack = `${a.title} ${a.operationType} ${instanceName(a.instanceId) ?? ''}`.toLowerCase()
      if (!haystack.includes(q)) return false
    }
    return true
  })
}

export function sortApprovals(list: Approval[], sort: ApprovalSort): Approval[] {
  const copy = [...list]
  switch (sort) {
    case 'newest':
      return copy.sort((a, b) => b.requestedAt.localeCompare(a.requestedAt))
    case 'risk':
      // Most dangerous first; ties fall back to newest.
      return copy.sort(
        (a, b) => RISK_ORDER[b.risk] - RISK_ORDER[a.risk] || b.requestedAt.localeCompare(a.requestedAt),
      )
    case 'expiring':
      // Soonest expiry first.
      return copy.sort((a, b) => (a.expiresAt ?? '\uffff').localeCompare(b.expiresAt ?? '\uffff'))
  }
}

export function operationTypesOf(approvals: Approval[]): string[] {
  return [...new Set(approvals.map((a) => a.operationType))].sort()
}

// ── Exact-target extraction (destructive confirmation) ───────────────────────

/**
 * The exact target name restated in destructive ConfirmDialogs. Scope lines
 * look like "Target: homelab-dev (local virtual machine)"; the typed token is
 * the name itself, without the parenthetical kind.
 */
export function exactTargetName(approval: Approval): string {
  const line = approval.scope.find((s) => /^target:/i.test(s.trim()))
  if (line) {
    const rest = line.replace(/^target:/i, '').trim()
    const paren = rest.indexOf('(')
    const name = (paren === -1 ? rest : rest.slice(0, paren)).trim()
    if (name) return name
  }
  return approval.targetId ?? approval.instanceId
}

/** Destroy-class actions (typed confirmation) — destroy/delete operations. */
export function isDestroyClass(approval: Approval): boolean {
  const haystack = `${approval.title} ${approval.operationType} ${approval.scope.join(' ')}`
  return /\b(destroy|delete|deleting|destruction)\b/i.test(haystack)
}

/** Plain-language expiry text for rows and headers. */
export function expiryText(approval: Approval, distance: string, now = Date.now()): string {
  if (approval.status === 'expired' || isExpired(approval, now)) return 'Expired'
  if (!approval.expiresAt) return 'No automatic expiry'
  return `expires in ${distance}`
}

/** Stable DOM id for an approval row (keyboard focus targets). */
export function approvalRowDomId(approvalId: string): string {
  return `approval-row-${approvalId}`
}
