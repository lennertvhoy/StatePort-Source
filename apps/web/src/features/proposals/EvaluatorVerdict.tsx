/**
 * Evaluator verdicts (ADR-0007 §1: `E(S) -> pass | not yet | invalid` with a
 * reason). A verdict is the template's deterministic check, never a model's
 * opinion; an unrecognised or missing verdict reads "Not recorded".
 */
import { ArrowRight, HelpCircle } from 'lucide-react'

import type { EvaluatorResult } from '@/client/proposals'
import { StatusBadge } from '@/components'

import { VERDICT_PRESENTATION } from './proposalModel'

export function VerdictBadge({ result }: { result: EvaluatorResult | null }) {
  if (!result) return <StatusBadge state="neutral" label="Not recorded" icon={HelpCircle} />
  const presentation = VERDICT_PRESENTATION[result.verdict]
  return <StatusBadge state={presentation.state} label={presentation.label} icon={presentation.icon} />
}

export function VerdictDetail({
  result,
  title,
  testId,
}: {
  result: EvaluatorResult | null
  title?: string
  testId?: string
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5" data-testid={testId} data-verdict={result?.verdict ?? 'none'}>
      <div className="flex flex-wrap items-center gap-2">
        {title ? <span className="text-xs font-medium text-foreground-secondary">{title}</span> : null}
        <VerdictBadge result={result} />
      </div>
      {result?.summary ? <p className="text-sm text-foreground">{result.summary}</p> : null}
      {!result ? (
        <p className="text-xs text-foreground-tertiary">No verdict that StatePort recognises was recorded.</p>
      ) : null}
      {result && result.findings.length > 0 ? (
        <ul className="flex flex-col gap-1 text-xs text-foreground-secondary" aria-label={`${title ?? 'Check'} findings`}>
          {result.findings.map((finding, index) => (
            <li key={index} className="flex min-w-0 gap-1.5">
              <span aria-hidden="true">•</span>
              <span className="min-w-0 break-words">
                {finding.path ? <span className="font-mono text-foreground">{finding.path}: </span> : null}
                {finding.message}
                {finding.severity ? <span className="text-foreground-tertiary"> ({finding.severity})</span> : null}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}

export function VerdictComparison({
  before,
  after,
}: {
  before: EvaluatorResult | null
  after: EvaluatorResult | null
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-[1fr_auto_1fr]" data-testid="verdict-comparison">
      <VerdictDetail result={before} title="Before" testId="verdict-before" />
      <ArrowRight className="hidden size-4 self-center text-foreground-tertiary sm:block" aria-hidden="true" />
      <VerdictDetail result={after} title="After this change" testId="verdict-after" />
    </div>
  )
}
