/**
 * Dominant instance status — the ONE honest status for an application row or
 * overview header (design.md §7 + applications.md "never a repeated Ready
 * wall"). All mapping flows through the semantic layer (`@/semantic`); this
 * module only *chooses* which concurrent condition is dominant and collects
 * the rest for the tooltip ("1 awaiting approval · backup due").
 *
 * Priority (most actionable first):
 *   failed operation → pending approval → backup due → attention items →
 *   blocked → degraded (health or capability) → offline → live operation →
 *   quiet (`Idle` on the dashboard, `Ready` on the overview).
 */
import { Circle, CircleX, Clock, ShieldQuestion, TriangleAlert } from 'lucide-react'

import type { ApplicationInstance, OperationRecord } from '@/client'
import type { SemanticPresentation } from '@/semantic'
import { CONDITION_PRESENTATIONS, instanceHealthPresentation } from '@/semantic'

/** Backend operation states that remain actionable before a terminal outcome. */
export const LIVE_OP_STATES = [
  'draft', 'proposed', 'preparing', 'prepared', 'awaiting_approval', 'approved',
  'queued', 'running', 'cancelling', 'paused', 'interrupted', 'validating',
]

export function isLiveOperationState(state: string | undefined): boolean {
  return state !== undefined && LIVE_OP_STATES.includes(state)
}

export interface DominantStatusInput {
  instance: ApplicationInstance
  /** Pending approvals for this instance. */
  pendingApprovals?: number
  /** Operation records for this instance (any state). */
  operations?: OperationRecord[]
  /** True when any capability is degraded. */
  capabilityDegraded?: boolean
}

export interface DominantStatus {
  presentation: SemanticPresentation
  /** Other concurrent states, short lowercase phrases for tooltips. */
  others: string[]
}

const FAILED_OPERATION: SemanticPresentation = { state: 'danger', label: 'Operation failed', icon: CircleX }
const AWAITING_APPROVAL: SemanticPresentation = { state: 'waiting', label: 'Awaiting approval', icon: ShieldQuestion }
const NEEDS_ATTENTION: SemanticPresentation = { state: 'attention', label: 'Needs attention', icon: TriangleAlert }
const ACTIVE_OPERATION: SemanticPresentation = { state: 'waiting', label: 'Active operation', icon: Clock }
const IDLE: SemanticPresentation = { state: 'neutral', label: 'Idle', icon: Circle }
const DATA_UNAVAILABLE: SemanticPresentation = { state: 'blocked', label: 'Data unavailable', icon: CircleX }
const DATA_STALE: SemanticPresentation = { state: 'attention', label: 'Showing last known data', icon: TriangleAlert }

function plural(n: number, singular: string): string {
  return n === 1 ? `1 ${singular}` : `${n} ${singular}s`
}

export function dominantInstanceStatus(
  { instance, pendingApprovals = 0, operations = [], capabilityDegraded = false }: DominantStatusInput,
  opts?: { quiet?: 'idle' | 'ready'; dataState?: 'fresh' | 'stale' | 'unavailable' },
): DominantStatus {
  const quiet = opts?.quiet ?? 'idle'
  const dataState = opts?.dataState ?? 'fresh'
  const instanceOperations = operations.filter((o) => o.instanceId === instance.id)
  const failedOps = instanceOperations.filter((o) => o.state === 'failed').length
  const liveOps = instanceOperations.filter((o) => isLiveOperationState(o.state)).length
  const unacknowledged = instance.attention.filter((a) => !a.acknowledged).length
  const backupDue = instance.recovery.state === 'due'

  const others: string[] = []
  if (failedOps > 0) others.push(plural(failedOps, 'failed operation'))
  if (pendingApprovals > 0) others.push(plural(pendingApprovals, 'awaiting approval'))
  if (backupDue) others.push('backup due')
  if (unacknowledged > 0) others.push(plural(unacknowledged, 'attention item'))
  if (liveOps > 0) others.push('operation in progress')

  // First match wins; the rest stay listed in `others`.
  if (failedOps > 0) return { presentation: FAILED_OPERATION, others: others.slice(1) }
  if (pendingApprovals > 0) return { presentation: AWAITING_APPROVAL, others: others.slice(1) }
  if (backupDue) return { presentation: CONDITION_PRESENTATIONS.backupDue, others: others.slice(1) }
  if (unacknowledged > 0) return { presentation: NEEDS_ATTENTION, others: others.slice(1) }
  if (instance.health === 'blocked') return { presentation: instanceHealthPresentation('blocked'), others }
  if (instance.health === 'degraded' || capabilityDegraded) {
    return { presentation: instanceHealthPresentation('degraded'), others }
  }
  if (instance.health === 'offline') return { presentation: instanceHealthPresentation('offline'), others }
  if (liveOps > 0) return { presentation: ACTIVE_OPERATION, others: others.filter((o) => o !== 'operation in progress') }
  if (dataState === 'unavailable') return { presentation: DATA_UNAVAILABLE, others }
  if (dataState === 'stale') return { presentation: DATA_STALE, others }
  if (quiet === 'ready') return { presentation: instanceHealthPresentation('ready'), others }
  return { presentation: IDLE, others }
}

/** Tooltip body: dominant label + " · "-joined secondary states. */
export function dominantStatusTooltip(status: DominantStatus): string {
  return status.others.length > 0 ? `${status.presentation.label} · ${status.others.join(' · ')}` : status.presentation.label
}
