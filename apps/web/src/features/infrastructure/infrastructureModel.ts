/**
 * Infrastructure presentation model (design/infrastructure.md — binding).
 *
 * Pure derivations shared by the Deployments canvas, the nav panel, and the
 * tests. The rule here is honesty: each truth (VM power, SSH, health,
 * repository cleanliness, authorization, plan, run) keeps its own semantic
 * label — they are never merged into one green/red verdict, and "running" is
 * never green before health checks prove it.
 */
import {
  CircleEqual,
  Container,
  Eye,
  FileCheck2,
  HeartPulse,
  Loader2,
  Play,
  RotateCcw,
  Square,
  Trash2,
  Unplug,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import type {
  InfrastructureOperation,
  InfrastructurePlan,
  InfrastructureTarget,
  OperationState,
} from '@/client'
import type { SemanticPresentation } from '@/semantic'
import {
  healthStatePresentation,
  repositoryCleanPresentation,
  sshStatePresentation,
  vmStatePresentation,
} from '@/semantic'

// ── Operation catalog ────────────────────────────────────────────────────────

export type OperationGroup = 'inspect' | 'operate' | 'destructive'

export interface OperationMeta {
  operation: InfrastructureOperation
  /** Button label (imperative). */
  label: string
  group: OperationGroup
  icon: LucideIcon
  /** Read-only operations never require approval (brief: inspection may not). */
  readOnly: boolean
  /** Retry is offered after a failed run only when re-running is safe. */
  safeToRetry: boolean
  /** One-line "what this does" for menus and tooltips. */
  description: string
}

export const OPERATION_META: Record<InfrastructureOperation, OperationMeta> = {
  observe: {
    operation: 'observe',
    label: 'Observe VM',
    group: 'inspect',
    icon: Eye,
    readOnly: true,
    safeToRetry: true,
    description: 'Read the current VM, SSH, and health truth. Changes nothing.',
  },
  validate: {
    operation: 'validate',
    label: 'Validate configuration',
    group: 'inspect',
    icon: FileCheck2,
    readOnly: true,
    safeToRetry: true,
    description: 'Evaluate the Nix configuration (nix flake check). Changes nothing.',
  },
  health_check: {
    operation: 'health_check',
    label: 'Run health checks',
    group: 'inspect',
    icon: HeartPulse,
    readOnly: true,
    safeToRetry: true,
    description: 'Run the health check suite against the running VM.',
  },
  create_or_update: {
    operation: 'create_or_update',
    label: 'Create or update VM',
    group: 'operate',
    icon: Container,
    readOnly: false,
    safeToRetry: false,
    description: 'Apply the repository-owned VM creation or rebuild workflow.',
  },
  start: {
    operation: 'start',
    label: 'Start VM',
    group: 'operate',
    icon: Play,
    readOnly: false,
    safeToRetry: true,
    description: 'Power on the virtual machine and wait for SSH.',
  },
  stop: {
    operation: 'stop',
    label: 'Stop VM',
    group: 'operate',
    icon: Square,
    readOnly: false,
    safeToRetry: true,
    description: 'Gracefully shut down the virtual machine.',
  },
  restart: {
    operation: 'restart',
    label: 'Restart VM',
    group: 'operate',
    icon: RotateCcw,
    readOnly: false,
    safeToRetry: true,
    description: 'Graceful shutdown, then power on again.',
  },
  destroy: {
    operation: 'destroy',
    label: 'Prepare destruction…',
    group: 'destructive',
    icon: Trash2,
    readOnly: false,
    safeToRetry: false,
    description: 'Delete the virtual machine and its disk. Not reversible.',
  },
}

export const INSPECT_OPERATIONS: readonly OperationMeta[] = [
  OPERATION_META.observe,
  OPERATION_META.validate,
  OPERATION_META.health_check,
]

export const OPERATE_OPERATIONS: readonly OperationMeta[] = [
  OPERATION_META.create_or_update,
  OPERATION_META.start,
  OPERATION_META.stop,
  OPERATION_META.restart,
]

export function isReadOnlyOperation(operation: InfrastructureOperation): boolean {
  return OPERATION_META[operation].readOnly
}

// ── The distinct truths ──────────────────────────────────────────────────────

/**
 * VM power fact. Binding nuance (infrastructure.md "States"): a running VM is
 * NOT green until health checks pass — power shows Running with a neutral
 * treatment while health is unchecked/unknown.
 */
export function vmPowerPresentation(target: InfrastructureTarget): SemanticPresentation {
  const base = vmStatePresentation(target.vm.state)
  if (target.vm.state === 'running' && target.health.state !== 'healthy') {
    return { ...base, state: 'neutral', label: 'Running' }
  }
  return base
}

export function sshPresentation(target: InfrastructureTarget): SemanticPresentation {
  return sshStatePresentation(target.ssh.state)
}

export function healthPresentation(target: InfrastructureTarget): SemanticPresentation {
  return healthStatePresentation(target.health.state)
}

export function repositoryPresentation(target: InfrastructureTarget): SemanticPresentation {
  return repositoryCleanPresentation(target.repository.clean)
}

/**
 * The one dominant badge for the target (nav rows, tool header). Secondary
 * states stay in the fact row — never more than one badge per entity (§7.3).
 */
export function dominantTargetPresentation(target: InfrastructureTarget): SemanticPresentation {
  if (!target.available || target.vm.state === 'unavailable') {
    return { state: 'blocked', label: 'Target unavailable', icon: Unplug }
  }
  switch (target.vm.state) {
    case 'not_defined':
      return { state: 'neutral', label: 'Not created', icon: Square }
    case 'stopped':
      return { state: 'neutral', label: 'Stopped', icon: Square }
    case 'starting':
      return { state: 'waiting', label: 'Starting', icon: Loader2, spin: true }
    case 'stopping':
      return { state: 'waiting', label: 'Stopping', icon: Loader2, spin: true }
    case 'running':
      if (target.health.state === 'healthy') {
        return { state: 'success', label: 'Healthy', icon: HeartPulse }
      }
      if (target.health.state === 'unhealthy') {
        return { state: 'danger', label: 'Unhealthy', icon: HeartPulse }
      }
      // Running, health unchecked/checking — explicitly not green.
      return { state: 'neutral', label: 'Running — health not checked', icon: CircleEqual }
    default:
      return { state: 'blocked', label: 'Target unavailable', icon: Unplug }
  }
}

// ── Risk ─────────────────────────────────────────────────────────────────────

export type RiskPresentation = { label: string; tone: 'informational' | 'attention' | 'danger' }

export function riskPresentation(risk: InfrastructurePlan['risk']): RiskPresentation {
  switch (risk) {
    case 'low':
      return { label: 'Routine', tone: 'informational' }
    case 'medium':
      return { label: 'Elevated', tone: 'attention' }
    case 'high':
      return { label: 'Destructive', tone: 'danger' }
  }
}

// ── Plan stepper (Prepare → Review → Approve → Run → Validate → Receipt) ─────

export type PlanStageId = 'prepare' | 'review' | 'approve' | 'run' | 'validate' | 'receipt'

export type StepState = 'done' | 'current' | 'upcoming' | 'failed' | 'skipped'

export interface PlanStage {
  id: PlanStageId
  label: string
  state: StepState
}

export const PLAN_STAGE_LABELS: Record<PlanStageId, string> = {
  prepare: 'Prepare',
  review: 'Review',
  approve: 'Approve',
  run: 'Run',
  validate: 'Validate',
  receipt: 'Receipt',
}

/** Where the run currently sits (driven by PlanProgressEvent consumption). */
export type RunPhase = 'idle' | 'running' | 'validating' | 'done' | 'failed' | 'reconciling'

/**
 * Derive per-step states for the plan stepper from the plan's operation state
 * plus the local run phase. Read-only plans skip the Approve step; plans
 * covered by the daily-driver authorization skip it too (it is approved by
 * policy, not by a new decision).
 */
export function planStageStates(plan: InfrastructurePlan, runPhase: RunPhase): PlanStage[] {
  const needsDecision = plan.requiresApproval && !plan.coveredByAuthorization
  const state = plan.state

  const stages: PlanStage[] = [
    { id: 'prepare', label: PLAN_STAGE_LABELS.prepare, state: 'done' },
    { id: 'review', label: PLAN_STAGE_LABELS.review, state: 'upcoming' },
    { id: 'approve', label: PLAN_STAGE_LABELS.approve, state: needsDecision ? 'upcoming' : 'skipped' },
    { id: 'run', label: PLAN_STAGE_LABELS.run, state: 'upcoming' },
    { id: 'validate', label: PLAN_STAGE_LABELS.validate, state: 'upcoming' },
    { id: 'receipt', label: PLAN_STAGE_LABELS.receipt, state: 'upcoming' },
  ]
  const set = (id: PlanStageId, stepState: StepState) => {
    const stage = stages.find((s) => s.id === id)
    if (stage) stage.state = stepState
  }

  const failed = state === 'failed' || runPhase === 'failed'

  if (state === 'rejected' || state === 'cancelled') {
    set('review', 'done')
    if (needsDecision) set('approve', state === 'rejected' ? 'failed' : 'skipped')
    set('run', 'skipped')
    set('validate', 'skipped')
    set('receipt', 'skipped')
    return stages
  }

  if (state === 'awaiting_approval') {
    set('review', 'done')
    set('approve', 'current')
    return stages
  }

  // prepared / approved / running / validating / terminal-success states.
  set('review', 'done')
  if (needsDecision) set('approve', state === 'prepared' ? 'current' : 'done')

  const ran = runPhase === 'done' || state === 'validated' || state === 'completed_without_change'
  // reconciling means this attempt executed nothing but the backend may hold
  // a live run for the exact plan: show the run step as current, never failed.
  const running =
    runPhase === 'running' ||
    runPhase === 'validating' ||
    runPhase === 'reconciling' ||
    state === 'running' ||
    state === 'validating'

  if (failed) {
    set('run', 'failed')
    set('validate', 'skipped')
    set('receipt', 'skipped')
    return stages
  }
  if (ran) {
    set('run', 'done')
    set('validate', 'done')
    set('receipt', plan.receiptId ? 'done' : 'current')
    return stages
  }
  if (running) {
    set('run', runPhase === 'validating' || state === 'validating' ? 'done' : 'current')
    set('validate', runPhase === 'validating' || state === 'validating' ? 'current' : 'upcoming')
    return stages
  }
  return stages
}

// ── Run progress timeline ────────────────────────────────────────────────────

/** One row in the live run timeline: a plan step or the final validation. */
export interface RunTimelineRow {
  key: string
  title: string
  detail?: string
  state: OperationState
}

export function runTimelineRows(
  plan: InfrastructurePlan,
  stepStates: Record<number, OperationState>,
  runPhase: RunPhase,
): RunTimelineRow[] {
  const rows: RunTimelineRow[] = plan.steps.map((step, index) => ({
    key: step.id,
    title: step.title,
    detail: step.detail,
    state: stepStates[index] ?? 'queued',
  }))
  if (runPhase === 'validating' || runPhase === 'done') {
    rows.push({
      key: 'validate',
      title: 'Validating final state',
      state: runPhase === 'done' ? 'validated' : 'validating',
    })
  }
  if (runPhase === 'failed') {
    rows.push({ key: 'failed', title: 'Run halted — see the log for the failing step', state: 'failed' })
  }
  if (runPhase === 'reconciling') {
    rows.push({
      key: 'reconciling',
      title: 'Not re-executed — a run for this exact plan may already be in progress',
      state: 'interrupted',
    })
  }
  return rows
}

// ── Copy / export ────────────────────────────────────────────────────────────

/** Plain-text rendering of a plan for Copy plan / Export plan. */
export function serializePlan(plan: InfrastructurePlan, target: InfrastructureTarget | null): string {
  const lines: string[] = [
    `Plan: ${plan.title}`,
    `Plan ID: ${plan.id}`,
    `State: ${plan.state}`,
    `Operation: ${plan.operation}`,
    `Risk: ${riskPresentation(plan.risk).label} (${plan.risk})`,
    `Digest: ${plan.digest.algorithm}:${plan.digest.value}`,
    `Prepared: ${plan.createdAt}`,
    '',
    'Identity',
    `  Target: ${target?.name ?? plan.targetId} (${target?.kind === 'local_vm' ? 'Local VM' : 'target'})`,
    `  Repository: ${planRepositoryLine(target)}`,
    '',
    'Steps',
    ...plan.steps.map((step, index) => `  ${index + 1}. [${step.kind}] ${step.title} — ${step.detail}`),
    '',
    'Expected effects',
    `  Before: ${plan.beforeSummary}`,
    `  After: ${plan.afterSummary}`,
    '',
    'Rollback',
    `  ${plan.rollbackNotes}`,
    '',
    'Approval',
    `  ${approvalLine(plan)}`,
  ]
  return lines.join('\n')
}

function planRepositoryLine(target: InfrastructureTarget | null): string {
  if (!target) return 'unknown'
  const repo = target.repository
  return `${repo.name} @ ${repo.branch} (${repo.clean ? 'clean' : 'uncommitted changes'})`
}

export function approvalLine(plan: InfrastructurePlan): string {
  if (plan.coveredByAuthorization) return 'Covered by the active daily-driver authorization.'
  if (!plan.requiresApproval) return 'No approval required (read-only inspection).'
  switch (plan.state) {
    case 'approved':
      return 'Approved.'
    case 'awaiting_approval':
      return `Awaiting approval${plan.approvalId ? ` (${plan.approvalId})` : ''}.`
    default:
      return 'Requires approval.'
  }
}

export function planExportFilename(plan: InfrastructurePlan): string {
  return `${plan.id}-${plan.operation}.txt`
}

// ── Misc ─────────────────────────────────────────────────────────────────────

export const TARGET_KIND_LABEL: Record<InfrastructureTarget['kind'], string> = {
  local_vm: 'Local VM',
}
