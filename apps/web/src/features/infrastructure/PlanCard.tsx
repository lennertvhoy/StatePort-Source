/**
 * PlanCard — the current plan / run region of the Deployments canvas
 * (design/infrastructure.md § "Current plan / run region"). Plan and run stay
 * visibly separate: the prepared plan is reviewed first; the run timeline and
 * its receipt only appear after an explicit Run.
 *
 * Accessibility: the stepper exposes `aria-current="step"`, run progress is
 * announced through an aria-live region, and every state is icon + text.
 */
import {
  CircleCheck,
  CircleDashed,
  CircleX,
  Copy,
  Download,
  ListChecks,
  Play,
  Receipt,
  RotateCcw,
  Send,
  ShieldQuestion,
  SquareTerminal,
  X,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import type { InfrastructurePlan, InfrastructureTarget, OperationState } from '@/client'
import {
  ConfirmDialog,
  Disclosure,
  InlineNotice,
  OperationStateLabel,
  StatusBadgeFrom,
  TimeAgo,
  Tooltip,
  formatElapsed,
} from '@/components'
import { copyText } from '@/components'
import { Button } from '@/components/ui/button'
import { sendToBridge } from '@/features/bridge/bridgeStore'
import { cn } from '@/lib/utils'
import { receiptResultPresentation } from '@/semantic'

import type { RunState } from './useInfrastructure'
import type { PlanStage } from './infrastructureModel'
import { planStageStates, riskPresentation, runTimelineRows, serializePlan, planExportFilename } from './infrastructureModel'

const STEP_STATE_CLASSES: Record<PlanStage['state'], string> = {
  done: 'border-status-success text-status-success',
  current: 'border-accent text-accent',
  upcoming: 'border-border-strong text-foreground-tertiary border-dashed',
  failed: 'border-status-danger text-status-danger',
  skipped: 'border-border text-foreground-disabled border-dashed',
}

function PlanStepper({ stages }: { stages: PlanStage[] }) {
  return (
    <ol className="flex flex-wrap items-center gap-y-2" aria-label="Plan progress" data-testid="plan-stepper">
      {stages.map((stage, index) => {
        const Icon =
          stage.state === 'done' ? CircleCheck : stage.state === 'failed' ? CircleX : CircleDashed
        return (
          <li key={stage.id} className="flex items-center">
            {index > 0 ? <span className="mx-1.5 h-px w-4 bg-border" aria-hidden="true" /> : null}
            <span
              className={cn(
                'inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 text-xs font-medium',
                STEP_STATE_CLASSES[stage.state],
                stage.state === 'skipped' && 'line-through',
              )}
              aria-current={stage.state === 'current' ? 'step' : undefined}
              data-stage={stage.id}
              data-state={stage.state}
            >
              <Icon className="size-3" aria-hidden="true" />
              {stage.label}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

export interface PlanCardProps {
  instanceId: string
  plan: InfrastructurePlan
  target: InfrastructureTarget
  run: RunState | null
  running: boolean
  onRun: (plan: InfrastructurePlan) => void
  onDiscard: () => void
}

export function PlanCard({ instanceId, plan, target, run, running, onRun, onDiscard }: PlanCardProps) {
  const navigate = useNavigate()
  const [confirmRun, setConfirmRun] = useState(false)

  const isThisRun = run?.planId === plan.id
  const runPhase = isThisRun && run ? run.phase : 'idle'
  const stages = useMemo(() => planStageStates(plan, runPhase), [plan, runPhase])
  const risk = riskPresentation(plan.risk)
  const repo = target.repository

  const runnable =
    !running &&
    (plan.state === 'approved' ||
      (plan.state === 'prepared' && (!plan.requiresApproval || plan.coveredByAuthorization)))
  const awaitingApproval = plan.state === 'awaiting_approval'
  const failed = runPhase === 'failed' || plan.state === 'failed'
  const done = runPhase === 'done' || plan.state === 'validated' || plan.state === 'completed_without_change'
  const receiptId = run?.receipt?.id ?? plan.receiptId
  const durationMs =
    isThisRun && run?.finishedAt ? new Date(run.finishedAt).getTime() - new Date(run.startedAt).getTime() : null

  // ── Run progress announcement (aria-live announces text changes) ──────────
  const announcement = useMemo(() => {
    if (!isThisRun || !run) return ''
    if (run.phase === 'done') {
      return `Run finished: ${run.receipt?.result === 'validated' ? 'validated' : 'completed without change'}.`
    }
    if (run.phase === 'failed') return `Run failed. ${run.error ?? ''}`
    if (run.phase === 'reconciling') return `Not re-executed. ${run.error ?? ''}`
    const currentIndex = plan.steps.findIndex((_, i) => run.stepStates[i] === 'running')
    if (currentIndex >= 0) {
      return `Running step ${currentIndex + 1} of ${plan.steps.length}: ${plan.steps[currentIndex].title}`
    }
    if (run.phase === 'validating') return 'Validating final state.'
    return ''
  }, [isThisRun, run, plan.steps])

  const copyPlan = async () => {
    await copyText(serializePlan(plan, target))
  }

  const exportPlan = () => {
    const blob = new Blob([serializePlan(plan, target)], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = planExportFilename(plan)
    anchor.click()
    URL.revokeObjectURL(url)
  }

  const sendPlanToConversation = () => {
    sendToBridge({ kind: 'plan', instanceId, planId: plan.id })
    void navigate(`/app/${instanceId}/conversation`)
  }

  const openRelatedTerminal = () => {
    void navigate(`/app/${instanceId}/workbench/terminal`)
  }

  const timelineRows = useMemo(
    () => (isThisRun && run ? runTimelineRows(plan, run.stepStates, run.phase) : []),
    [isThisRun, run, plan],
  )

  return (
    <section
      className="rounded-md border border-border bg-surface"
      aria-label={`Plan: ${plan.title}`}
      data-testid="plan-card"
      data-plan-id={plan.id}
      data-plan-digest={plan.digest.value}
    >
      <div aria-live="polite" className="sr-only">
        {announcement}
      </div>

      {/* Header */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <ListChecks className="size-4 text-foreground-secondary" aria-hidden="true" />
        <h3 className="text-sm font-semibold text-foreground">{plan.title}</h3>
        <OperationStateLabel state={plan.state} />
        <span className="text-xs text-foreground-tertiary">
          prepared <TimeAgo date={plan.createdAt} />
        </span>
      </div>

      {/* Scrollable review region — scrolls independently on mobile so the
          action footer never hides (infrastructure.md mobile contract). */}
      <div className="flex max-h-[min(60vh,560px)] flex-col gap-3 overflow-y-auto px-3 py-3">
        <PlanStepper stages={stages} />

        {!repo.clean ? (
          <InlineNotice tone="attention" title="Repository has uncommitted changes">
            The plan records the current revision anyway.
          </InlineNotice>
        ) : null}

        {/* Identity restated */}
        <div className="grid gap-2 sm:grid-cols-2" data-testid="plan-identity">
          <div className="rounded-sm border border-border px-2.5 py-2">
            <p className="text-xs font-medium text-foreground-secondary">Repository</p>
            <p className="tnum truncate font-mono text-xs text-foreground">
              {repo.name} @ {repo.branch}
            </p>
            <p className="tnum truncate font-mono text-xs text-foreground-tertiary">
              {repo.revision.slice(0, 10)} · {repo.clean ? 'clean' : 'uncommitted changes'}
            </p>
          </div>
          <div className="rounded-sm border border-border px-2.5 py-2">
            <p className="text-xs font-medium text-foreground-secondary">Target</p>
            <p className="tnum truncate font-mono text-xs text-foreground">{target.name} · Local VM</p>
            <p className="tnum truncate font-mono text-xs text-foreground-tertiary">{plan.targetId}</p>
          </div>
        </div>

        {/* Steps / commands */}
        <div>
          <p className="mb-1 text-xs font-medium text-foreground-secondary">Steps and commands</p>
          <ol className="divide-y divide-border rounded-sm border border-border">
            {plan.steps.map((step, index) => (
              <li key={step.id} className="flex items-baseline gap-2 px-2.5 py-1.5">
                <span className="tnum shrink-0 font-mono text-xs text-foreground-tertiary">{index + 1}.</span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-xs font-medium text-foreground">{step.title}</span>
                  <code className="tnum block truncate font-mono text-xs text-foreground-secondary">{step.detail}</code>
                </span>
                <span className="shrink-0 text-xs text-foreground-tertiary">{step.kind}</span>
              </li>
            ))}
          </ol>
        </div>

        {/* Risk */}
        <InlineNotice tone={risk.tone} title={`Risk: ${risk.label}`}>
          {plan.operation === 'destroy'
            ? 'Destroying a target is irreversible and is never covered by a daily-driver authorization.'
            : plan.requiresApproval
              ? 'This operation changes what is running on this machine.'
              : 'Read-only inspection — nothing about the target changes.'}
        </InlineNotice>

        {/* Expected effects + rollback */}
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-sm border border-border px-2.5 py-2">
            <p className="text-xs font-medium text-foreground-secondary">Expected effects</p>
            <ul className="mt-0.5 list-disc pl-4 text-xs text-foreground">
              <li>{plan.beforeSummary}</li>
              <li>{plan.afterSummary}</li>
            </ul>
          </div>
          <div className="rounded-sm border border-border px-2.5 py-2">
            <p className="text-xs font-medium text-foreground-secondary">Rollback</p>
            <p className="mt-0.5 text-xs text-foreground">{plan.rollbackNotes}</p>
          </div>
        </div>

        {/* Approval state */}
        <div data-testid="plan-approval-state">
          {plan.coveredByAuthorization ? (
            <p className="flex items-center gap-1.5 text-xs text-status-success">
              <CircleCheck className="size-3.5" aria-hidden="true" />
              Covered by the active daily-driver authorization.
            </p>
          ) : awaitingApproval ? (
            <div className="flex flex-wrap items-center gap-2">
              <p className="flex items-center gap-1.5 text-xs text-status-waiting">
                <ShieldQuestion className="size-3.5" aria-hidden="true" />
                {plan.operation === 'destroy'
                  ? 'Destructive — always needs its own exact approval.'
                  : 'Awaiting approval before this plan can run.'}
              </p>
              {plan.approvalId ? (
                <Button size="sm" variant="outline" onClick={() => void navigate(`/approvals/${plan.approvalId}`)}>
                  <ShieldQuestion aria-hidden="true" />
                  Go to approval
                </Button>
              ) : null}
            </div>
          ) : plan.state === 'approved' ? (
            <p className="flex items-center gap-1.5 text-xs text-status-success">
              <CircleCheck className="size-3.5" aria-hidden="true" />
              Approved — ready to run.
            </p>
          ) : !plan.requiresApproval ? (
            <p className="flex items-center gap-1.5 text-xs text-foreground-secondary">
              <CircleCheck className="size-3.5" aria-hidden="true" />
              Read-only — no approval required.
            </p>
          ) : null}
        </div>

        {/* Run region — appears only after an explicit Run (or for plans that
            already ran). Kept visually distinct from the review region above. */}
        {isThisRun && run ? (
          <div className="rounded-sm border border-border bg-surface-2 px-2.5 py-2" data-testid="run-region">
            <div className="mb-1.5 flex items-center justify-between gap-2">
              <p className="text-xs font-medium text-foreground-secondary">Run progress</p>
              {run.phase === 'running' || run.phase === 'validating' ? (
                <OperationStateLabel state={run.phase === 'validating' ? 'validating' : 'running'} startedAt={run.startedAt} />
              ) : null}
            </div>
            <ol className="flex flex-col gap-1" data-testid="run-timeline">
              {timelineRows.map((row) => (
                <RunRow key={row.key} title={row.title} detail={row.detail} state={row.state} />
              ))}
            </ol>
            {run.logs.length > 0 ? (
              <Disclosure title={`Log (${run.logs.length} lines)`} className="mt-2">
                <pre
                  className="max-h-44 overflow-auto rounded-sm bg-sunken p-2 font-mono text-xs text-foreground-secondary"
                  data-testid="run-log-view"
                >
                  {run.logs.join('\n')}
                </pre>
              </Disclosure>
            ) : null}

            {/* Outcome */}
            {run.phase === 'done' && run.receipt ? (
              <div className="mt-2 border-t border-border pt-2" data-testid="run-outcome">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadgeFrom presentation={receiptResultPresentation(run.receipt.result)} />
                  {durationMs !== null ? (
                    <span className="tnum font-mono text-xs text-foreground-tertiary">
                      {formatElapsed(durationMs)}
                    </span>
                  ) : null}
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => void navigate(`/app/${instanceId}/workbench/receipts/${run.receipt!.id}`)}
                  >
                    <Receipt aria-hidden="true" />
                    View receipt
                  </Button>
                </div>
                <p className="mt-1 text-xs text-foreground-secondary">{run.receipt.summary}</p>
              </div>
            ) : null}
            {run.phase === 'failed' ? (
              <div className="mt-2 border-t border-border pt-2" data-testid="run-outcome">
                <OperationStateLabel state="failed" />
                <p className="mt-1 text-xs text-foreground-secondary">{run.error}</p>
                <InlineNotice tone="attention" title="Rollback guidance" className="mt-2">
                  {plan.rollbackNotes}
                </InlineNotice>
              </div>
            ) : null}
            {run.phase === 'reconciling' ? (
              <div className="mt-2 border-t border-border pt-2" data-testid="run-outcome">
                <OperationStateLabel state="interrupted" />
                <p className="mt-1 text-xs text-foreground-secondary">{run.error}</p>
              </div>
            ) : null}
          </div>
        ) : null}
      </div>

      {/* Action footer (sticky so it never scrolls away on mobile) */}
      <div className="sticky bottom-0 flex flex-wrap items-center gap-1.5 border-t border-border bg-surface px-3 py-2">
        {runnable ? (
          <Button
            size="sm"
            onClick={() => (plan.operation === 'destroy' ? setConfirmRun(true) : onRun(plan))}
            data-testid="plan-run"
          >
            <Play aria-hidden="true" />
            Run
          </Button>
        ) : null}
        {failed && plan.operation !== 'destroy' ? (
          <Button size="sm" variant="outline" onClick={() => onRun(plan)} data-testid="plan-retry">
            <RotateCcw aria-hidden="true" />
            Retry
          </Button>
        ) : null}
        {done && receiptId && !(isThisRun && run?.phase === 'done') ? (
          <Button
            size="sm"
            variant="outline"
            onClick={() => void navigate(`/app/${instanceId}/workbench/receipts/${receiptId}`)}
          >
            <Receipt aria-hidden="true" />
            View receipt
          </Button>
        ) : null}
        <Tooltip content="Copy plan as text">
          <Button size="sm" variant="ghost" onClick={() => void copyPlan()} aria-label="Copy plan">
            <Copy aria-hidden="true" />
          </Button>
        </Tooltip>
        <Tooltip content="Export plan as a text file">
          <Button size="sm" variant="ghost" onClick={exportPlan} aria-label="Export plan">
            <Download aria-hidden="true" />
          </Button>
        </Tooltip>
        <Button size="sm" variant="ghost" onClick={sendPlanToConversation}>
          <Send aria-hidden="true" />
          Send to Conversation
        </Button>
        <Tooltip content="Open the related terminal">
          <Button size="sm" variant="ghost" onClick={openRelatedTerminal} aria-label="Open related terminal">
            <SquareTerminal aria-hidden="true" />
          </Button>
        </Tooltip>
        <div className="flex-1" />
        {!running && !done ? (
          <Button size="sm" variant="ghost" onClick={onDiscard} data-testid="plan-discard">
            <X aria-hidden="true" />
            Discard plan
          </Button>
        ) : null}
      </div>

      {/* Destructive runs restate the irreversible effect (mock: a destroy run
          cannot be cancelled once started). */}
      <ConfirmDialog
        open={confirmRun}
        onOpenChange={setConfirmRun}
        title="Run destruction plan?"
        description="The approved plan will run now."
        target={target.name}
        effect="The virtual machine and its virtual disk will be deleted."
        reversibility="Not reversible — and this run cannot be cancelled once started."
        confirmLabel="Run destruction"
        destructive
        onConfirm={() => onRun(plan)}
      />
    </section>
  )
}

function RunRow({ title, detail, state }: { title: string; detail?: string; state: OperationState }) {
  return (
    <li className="flex items-baseline gap-2" data-testid="run-timeline-row" data-state={state}>
      <OperationStateLabel state={state} label={title} className="text-xs" />
      {detail ? (
        <code className="tnum hidden truncate font-mono text-xs text-foreground-tertiary sm:inline">{detail}</code>
      ) : null}
    </li>
  )
}
