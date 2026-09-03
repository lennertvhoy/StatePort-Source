/**
 * The semantic status layer (design.md §7 — binding contract).
 *
 * This is the ONLY module that maps domain/backend states to presentation.
 * Components never map backend strings to colors directly; they call these
 * mappers and render the returned `{ state, label, icon }`.
 *
 * Color values live in the token CSS (owned by the styling agent); this module
 * owns the state → semantic-name → label → icon mapping only.
 */
import {
  BadgeCheck,
  Circle,
  CircleCheck,
  CircleDot,
  CircleDashed,
  CircleEqual,
  CircleOff,
  CirclePause,
  CircleSlash,
  CircleX,
  ClipboardCheck,
  Clock,
  DatabaseBackup,
  GitCommitHorizontal,
  HeartPulse,
  KeyRound,
  Loader2,
  OctagonX,
  PenLine,
  Plug,
  ShieldQuestion,
  Square,
  TriangleAlert,
  Unplug,
  UserCheck,
  Lock,
  Fingerprint,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import type {
  CapabilityStatus,
  HealthState,
  InstanceHealth,
  LocalServiceState,
  OperationState,
  ReceiptResult,
  ReceiptValidationState,
  SSHState,
  SemanticState,
  TerminalSessionState,
  VMPowerState,
} from './client/types'

export interface SemanticPresentation {
  state: SemanticState
  label: string
  icon: LucideIcon
  /** True when the icon should spin (preparing/running/validating). */
  spin?: boolean
}

// ─────────────────────────────────────────────────────────────────────────────
// §7.1 — the honest operation states
// ─────────────────────────────────────────────────────────────────────────────

const OPERATION_STATE_MAP: Record<OperationState, SemanticPresentation> = {
  draft: { state: 'neutral', label: 'Draft', icon: PenLine },
  proposed: { state: 'informational', label: 'Proposed', icon: CircleDashed },
  preparing: { state: 'waiting', label: 'Preparing', icon: Loader2, spin: true },
  prepared: { state: 'informational', label: 'Prepared', icon: ClipboardCheck },
  awaiting_approval: { state: 'waiting', label: 'Awaiting approval', icon: ShieldQuestion },
  approved: { state: 'success', label: 'Approved', icon: CircleCheck },
  queued: { state: 'waiting', label: 'Queued', icon: Clock },
  running: { state: 'waiting', label: 'Running', icon: Loader2, spin: true },
  completed: { state: 'informational', label: 'Completed', icon: CircleDot },
  cancelling: { state: 'waiting', label: 'Cancelling', icon: Loader2, spin: true },
  paused: { state: 'neutral', label: 'Paused', icon: CirclePause },
  interrupted: { state: 'attention', label: 'Interrupted', icon: TriangleAlert },
  applied: { state: 'informational', label: 'Applied', icon: CircleDot },
  validating: { state: 'waiting', label: 'Validating', icon: Loader2, spin: true },
  validated: { state: 'success', label: 'Validated', icon: BadgeCheck },
  completed_without_change: { state: 'neutral', label: 'No changes', icon: CircleEqual },
  rejected: { state: 'neutral', label: 'Rejected', icon: CircleSlash },
  cancelled: { state: 'neutral', label: 'Cancelled', icon: CircleOff },
  blocked: { state: 'blocked', label: 'Blocked', icon: OctagonX },
  unavailable: { state: 'blocked', label: 'Unavailable', icon: Unplug },
  failed: { state: 'danger', label: 'Failed', icon: CircleX },
  human_accepted: { state: 'success', label: 'Accepted', icon: UserCheck },
}

export function operationStatePresentation(state: OperationState): SemanticPresentation {
  return OPERATION_STATE_MAP[state]
}

// ─────────────────────────────────────────────────────────────────────────────
// §7.2 — health / capability / environment
// ─────────────────────────────────────────────────────────────────────────────

export function localServicePresentation(state: LocalServiceState): SemanticPresentation {
  switch (state) {
    case 'connected':
      return { state: 'success', label: 'Connected', icon: BadgeCheck }
    case 'degraded':
      return { state: 'attention', label: 'Degraded', icon: TriangleAlert }
    case 'offline':
      return { state: 'blocked', label: 'Service offline', icon: Unplug }
    case 'unknown':
      return { state: 'neutral', label: 'Not checked', icon: CircleDashed }
  }
}

export function instanceHealthPresentation(health: InstanceHealth): SemanticPresentation {
  switch (health) {
    case 'ready':
      return { state: 'success', label: 'Ready', icon: CircleCheck }
    case 'attention_needed':
      return { state: 'attention', label: 'Needs attention', icon: TriangleAlert }
    case 'degraded':
      return { state: 'attention', label: 'Degraded', icon: TriangleAlert }
    case 'blocked':
      return { state: 'blocked', label: 'Blocked', icon: OctagonX }
    case 'offline':
      return { state: 'neutral', label: 'Offline', icon: Circle }
  }
}

/** Capability `available` intentionally renders NO badge (design.md §7.2). */
export function capabilityPresentation(status: CapabilityStatus): SemanticPresentation | null {
  switch (status) {
    case 'available':
      return null
    case 'degraded':
      return { state: 'attention', label: 'Degraded', icon: TriangleAlert }
    case 'environment_gated':
      return { state: 'neutral', label: 'Unavailable in this environment', icon: Lock }
    case 'unavailable':
      return { state: 'blocked', label: 'Unavailable', icon: OctagonX }
  }
}

export function vmStatePresentation(state: VMPowerState): SemanticPresentation {
  switch (state) {
    case 'not_defined':
      return { state: 'neutral', label: 'Not created', icon: Square }
    case 'stopped':
      return { state: 'neutral', label: 'Stopped', icon: Square }
    case 'starting':
      return { state: 'waiting', label: 'Starting', icon: Loader2, spin: true }
    case 'running':
      return { state: 'success', label: 'Running', icon: CircleCheck }
    case 'stopping':
      return { state: 'waiting', label: 'Stopping', icon: Loader2, spin: true }
    case 'unavailable':
      return { state: 'blocked', label: 'Target unavailable', icon: Unplug }
  }
}

export function sshStatePresentation(state: SSHState): SemanticPresentation {
  switch (state) {
    case 'ready':
      return { state: 'success', label: 'SSH ready', icon: KeyRound }
    case 'unavailable_vm_not_defined':
      return { state: 'neutral', label: 'SSH unavailable — VM not created', icon: KeyRound }
    case 'unavailable_vm_stopped':
      return { state: 'neutral', label: 'SSH unavailable — VM stopped', icon: KeyRound }
    case 'failed':
      return { state: 'danger', label: 'SSH connection failed', icon: KeyRound }
    case 'not_checked':
      return { state: 'neutral', label: 'SSH not checked', icon: CircleDashed }
  }
}

export function healthStatePresentation(state: HealthState): SemanticPresentation {
  switch (state) {
    case 'healthy':
      return { state: 'success', label: 'Healthy', icon: HeartPulse }
    case 'checking':
      return { state: 'waiting', label: 'Checking', icon: Loader2, spin: true }
    case 'unhealthy':
      return { state: 'danger', label: 'Unhealthy', icon: HeartPulse }
    case 'not_checked':
      return { state: 'attention', label: 'Not checked', icon: HeartPulse }
    case 'unavailable':
      return { state: 'blocked', label: 'Unavailable', icon: Unplug }
  }
}

export function terminalStatePresentation(state: TerminalSessionState): SemanticPresentation {
  switch (state) {
    case 'idle':
      return { state: 'neutral', label: 'Ready to connect', icon: Plug }
    case 'connecting':
      return { state: 'waiting', label: 'Connecting', icon: Loader2, spin: true }
    case 'connected':
      return { state: 'success', label: 'Connected', icon: CircleCheck }
    case 'reconnecting':
      return { state: 'waiting', label: 'Reconnecting', icon: Loader2, spin: true }
    case 'failed':
      return { state: 'danger', label: 'Connection failed', icon: Unplug }
    case 'ended':
      return { state: 'neutral', label: 'Session ended', icon: CircleOff }
  }
}

export function receiptResultPresentation(result: ReceiptResult): SemanticPresentation {
  switch (result) {
    case 'approved':
      return OPERATION_STATE_MAP.approved
    case 'applied':
      return OPERATION_STATE_MAP.applied
    case 'executed':
      return { state: 'informational', label: 'Executed', icon: CircleDot }
    case 'completed':
      return { state: 'informational', label: 'Completed', icon: CircleDot }
    case 'validated':
      return OPERATION_STATE_MAP.validated
    case 'completed_without_change':
      return OPERATION_STATE_MAP.completed_without_change
    case 'rejected':
      return OPERATION_STATE_MAP.rejected
    case 'cancelled':
      return OPERATION_STATE_MAP.cancelled
    case 'failed':
      return OPERATION_STATE_MAP.failed
    case 'human_accepted':
      return OPERATION_STATE_MAP.human_accepted
  }
}

export function receiptValidationPresentation(state: ReceiptValidationState): SemanticPresentation {
  switch (state) {
    case 'not_recorded':
      return { state: 'neutral', label: 'Not recorded', icon: CircleDashed }
    case 'not_required':
      return { state: 'neutral', label: 'Not required', icon: CircleEqual }
    case 'validating':
      return OPERATION_STATE_MAP.validating
    case 'validated':
      return OPERATION_STATE_MAP.validated
    case 'failed':
      return OPERATION_STATE_MAP.failed
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Named conditions from §7.2 that surfaces reuse verbatim
// ─────────────────────────────────────────────────────────────────────────────

export const CONDITION_PRESENTATIONS = {
  backupDue: { state: 'attention', label: 'Backup due', icon: DatabaseBackup },
  repositoryDirty: { state: 'attention', label: 'Uncommitted changes', icon: GitCommitHorizontal },
  targetUnavailable: { state: 'blocked', label: 'Target unavailable', icon: Unplug },
  identityMissing: { state: 'blocked', label: 'Identity missing', icon: Fingerprint },
  notConfigured: { state: 'neutral', label: 'Not configured', icon: CircleDashed },
  verified: { state: 'success', label: 'Verified', icon: BadgeCheck },
} as const satisfies Record<string, SemanticPresentation>

export function repositoryCleanPresentation(clean: boolean): SemanticPresentation {
  return clean
    ? { state: 'success', label: 'Clean', icon: CircleCheck }
    : CONDITION_PRESENTATIONS.repositoryDirty
}
