/**
 * Orchestration presentation model (design/orchestration.md + brief 1530–1617
 * — binding). Pure derivations for the 13-stage bounded-slice flow. The CTO
 * Orchestration tool coordinates ONE bounded slice per session; it is never
 * an autonomous background agent, so the model has no notion of hidden loops,
 * auto-continuation, or auto-execution — every advance is an explicit client
 * transition driven from the current stage's controls.
 */
import type { OrchestrationMode, OrchestrationSession, OrchestrationStage } from '@/client'

// ── The 13 stages ────────────────────────────────────────────────────────────

export interface StageMeta {
  id: OrchestrationStage
  label: string
  /** One-line "what happens here" for the stage panel header. */
  summary: string
}

export const STAGES: readonly StageMeta[] = [
  { id: 'enter_objective', label: 'Objective', summary: 'State the one bounded objective for this slice.' },
  { id: 'select_mode', label: 'Mode', summary: 'Choose how much StatePort may do, and how it asks.' },
  { id: 'prepare_slice', label: 'Prepare slice', summary: 'StatePort prepares the bounded slice — nothing runs yet.' },
  { id: 'review_base', label: 'Review base', summary: 'Review the exact repository base the slice builds on.' },
  { id: 'review_plan', label: 'Review plan', summary: 'Review the proposed steps and their scope.' },
  { id: 'review_permissions', label: 'Review permissions', summary: 'Review exactly which permissions the slice requires.' },
  { id: 'review_budget', label: 'Review budget', summary: 'Review the maximum step and time budget.' },
  { id: 'approve', label: 'Approve', summary: 'Approve the slice — the one decision that lets it run.' },
  { id: 'run', label: 'Run', summary: 'Run the approved slice — inspection or bounded execution.' },
  { id: 'review_result', label: 'Review result', summary: 'Review what the run actually did against the objective.' },
  { id: 'independent_review', label: 'Independent review', summary: 'A reviewer separate from the implementer signs off.' },
  { id: 'close', label: 'Close & stop', summary: 'Close the slice — closing stops everything.' },
  { id: 'receipt', label: 'Receipt', summary: 'The closed slice leaves its receipt in the audit trail.' },
] as const

export const STAGE_COUNT = STAGES.length

export function stageIndex(stage: OrchestrationStage): number {
  return STAGES.findIndex((s) => s.id === stage)
}

export function stageLabel(stage: OrchestrationStage): string {
  return STAGES[stageIndex(stage)]?.label ?? stage
}

/**
 * Review sub-stages (review_base → review_plan → review_permissions →
 * review_budget → approve) are client-side review paging: the mock session
 * rests at review_base while the user pages through the reviews. Only the
 * Approve transition at the end calls the client.
 */
export const REVIEW_SEQUENCE: readonly OrchestrationStage[] = [
  'review_base',
  'review_plan',
  'review_permissions',
  'review_budget',
  'approve',
]

/**
 * Effective stepper position: the session stage, refined by the local review
 * sub-stage while the session rests at review_base / review_result.
 */
export function effectiveStage(
  session: OrchestrationSession | null,
  localStage: OrchestrationStage | null,
): OrchestrationStage {
  if (!session) return localStage ?? 'enter_objective'
  if (session.stage === 'review_base' && localStage && stageIndex(localStage) > stageIndex('review_base')) {
    return localStage
  }
  if (session.stage === 'review_result' && localStage === 'independent_review') {
    return 'independent_review'
  }
  return session.stage
}

export type StepperItemState = 'done' | 'current' | 'upcoming' | 'failed'

export interface StepperItem {
  id: OrchestrationStage
  label: string
  index: number
  state: StepperItemState
}

export function stepperItems(current: OrchestrationStage, cancelled: boolean): StepperItem[] {
  const currentIndex = stageIndex(current)
  return STAGES.map((stage, index) => ({
    id: stage.id,
    label: stage.label,
    index,
    state:
      index < currentIndex
        ? 'done'
        : index === currentIndex
          ? cancelled
            ? 'failed'
            : 'current'
          : 'upcoming',
  }))
}

// ── Modes ────────────────────────────────────────────────────────────────────

export interface ModeMeta {
  id: OrchestrationMode
  label: string
  description: string
}

export const MODES: readonly ModeMeta[] = [
  {
    id: 'advisory',
    label: 'Advisory',
    description: 'Inspection only. StatePort reads and reports — nothing is written.',
  },
  {
    id: 'assisted',
    label: 'Assisted',
    description: 'One bounded slice runs, with your explicit approval at the gate.',
  },
  {
    id: 'managed_approved_queue',
    label: 'Managed queue',
    description: 'Approved steps may run in sequence, always inside the budget you review.',
  },
  {
    id: 'off',
    label: 'Off',
    description: 'Orchestration is off. No slice is prepared and nothing runs.',
  },
] as const

export function modeMeta(mode: OrchestrationMode): ModeMeta {
  return MODES.find((m) => m.id === mode) ?? MODES[1]
}

// ── Derived display facts ────────────────────────────────────────────────────

/** Numbered review steps derived from the slice's scope (mock has no step list). */
export interface ReviewStep {
  title: string
  detail: string
}

export function reviewSteps(session: OrchestrationSession): ReviewStep[] {
  const steps: ReviewStep[] = [
    {
      title: 'Inspect the recorded base',
      detail: `${session.baseIdentity.name} @ ${session.baseIdentity.branch} (${session.baseIdentity.revision.slice(0, 10)})`,
    },
    ...session.scope.map((path) => ({
      title: 'Draft the bounded change',
      detail: path,
    })),
    { title: 'Run checks and summarize', detail: 'Results are reported for your review — nothing merges itself.' },
  ]
  return steps
}

export function budgetExhausted(session: OrchestrationSession): boolean {
  return session.budget.usedOperations >= session.budget.maxOperations
}
