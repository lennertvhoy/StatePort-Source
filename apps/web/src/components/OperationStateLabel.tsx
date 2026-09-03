/**
 * OperationStateLabel (design.md §7.3.4) — the canonical renderer for the 19
 * honest operation states (§7.1): icon + label + optional elapsed timer.
 * Inline text, NOT a pill. Color is reinforcement only (icon + words carry it).
 */
import { useEffect, useState } from 'react'

import type { OperationState } from '@/client'
import { operationStatePresentation } from '@/semantic'
import { formatElapsed } from '@/lib/time'
import { cn } from '@/lib/utils'

const STATE_TEXT: Record<string, string> = {
  success: 'text-status-success',
  neutral: 'text-status-neutral',
  attention: 'text-status-attention',
  waiting: 'text-status-waiting',
  blocked: 'text-status-blocked',
  danger: 'text-status-danger',
  informational: 'text-status-informational',
}

export interface OperationStateLabelProps {
  state: OperationState
  /** Override the canonical label (rare; prefer the honest default). */
  label?: string
  /** ISO start time; when set (and > 2 s elapsed) a mono elapsed timer renders. */
  startedAt?: string
  className?: string
}

export function OperationStateLabel({ state, label, startedAt, className }: OperationStateLabelProps) {
  const presentation = operationStatePresentation(state)
  const Icon = presentation.icon
  const showTimer = Boolean(startedAt) && (state === 'running' || state === 'preparing' || state === 'validating' || state === 'queued')

  return (
    <span
      className={cn('inline-flex items-center gap-1.5 text-sm font-medium', STATE_TEXT[presentation.state], className)}
      data-testid="operation-state-label"
      data-state={state}
    >
      <Icon className={cn('size-4 shrink-0', presentation.spin && 'icon-spin')} aria-hidden="true" />
      <span className="truncate">{label ?? presentation.label}</span>
      {showTimer ? <ElapsedTicker startedAt={startedAt!} /> : null}
    </span>
  )
}

function ElapsedTicker({ startedAt }: { startedAt: string }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])
  const elapsed = now - new Date(startedAt).getTime()
  if (elapsed < 2000) return null
  return <span className="tnum font-mono text-xs text-foreground-tertiary">{formatElapsed(elapsed)}</span>
}
