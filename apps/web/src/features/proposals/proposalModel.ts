/** Pure verdict and proposal presentation rules shared by checks, proposals and the overview card. */
import { CircleCheck, CircleDashed, CircleX } from 'lucide-react'

import type { RunRecord, SemanticState } from '@/client'
import type { EvaluatorResult, EvaluatorVerdict, FileChangeKind } from '@/client/proposals'

export interface ProposalControls {
  apply: boolean
  reject: boolean
  applyLabel: string
}

/**
 * Which decisions the exact run status allows. A proposal without patch text
 * cannot be reviewed, so it can only be rejected.
 */
export function proposalControls(run: RunRecord, reviewable: boolean): ProposalControls {
  if (!reviewable) return { apply: false, reject: run.status === 'state_change_proposed', applyLabel: 'Apply' }
  if (run.status === 'state_change_proposed') return { apply: true, reject: true, applyLabel: 'Apply' }
  if (run.status === 'state_change_approved') return { apply: true, reject: false, applyLabel: 'Apply approved change' }
  return { apply: false, reject: false, applyLabel: 'Apply' }
}

export const VERDICT_PRESENTATION: Record<EvaluatorVerdict, { label: string; state: SemanticState; icon: typeof CircleCheck }> = {
  passed: { label: 'Passed', state: 'success', icon: CircleCheck },
  not_yet: { label: 'Not yet', state: 'attention', icon: CircleDashed },
  invalid: { label: 'Invalid', state: 'danger', icon: CircleX },
}

export function verdictLabel(result: EvaluatorResult | null): string {
  return result ? VERDICT_PRESENTATION[result.verdict].label : 'Not recorded'
}

const RANK: Record<EvaluatorVerdict, number> = { invalid: 0, not_yet: 1, passed: 2 }

/** True when the candidate is judged worse than the base (ADR-0007 §4 auto-apply rule). */
export function verdictWorsened(before: EvaluatorResult | null, after: EvaluatorResult | null): boolean {
  if (!before || !after) return false
  return RANK[after.verdict] < RANK[before.verdict]
}

export const CHANGE_PRESENTATION: Record<FileChangeKind, { label: string; state: SemanticState }> = {
  added: { label: 'Added', state: 'success' },
  modified: { label: 'Modified', state: 'informational' },
  deleted: { label: 'Deleted', state: 'danger' },
  renamed: { label: 'Renamed', state: 'neutral' },
}

/** "+12 −3", or "binary" when line counts do not apply. */
export function changeCountLabel(additions: number | null, deletions: number | null, binary: boolean): string {
  if (binary) return 'binary'
  if (additions === null && deletions === null) return 'counts not reported'
  return `+${additions ?? 0} −${deletions ?? 0}`
}

export function shortCommit(commit: string | null): string | null {
  return commit ? commit.slice(0, 12) : null
}

export function durationLabel(seconds: number | null): string {
  if (seconds === null) return 'Not recorded'
  if (seconds < 60) return `${Math.round(seconds)} s`
  const minutes = Math.floor(seconds / 60)
  const rest = Math.round(seconds % 60)
  return rest ? `${minutes} min ${rest} s` : `${minutes} min`
}
