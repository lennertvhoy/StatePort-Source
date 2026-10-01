/**
 * OrchestrationTool — the bounded CTO Orchestration surface
 * (#/app/:id/workbench/orchestration; design/orchestration.md — binding).
 *
 * ONE bounded slice at a time, coordinated through the 13-stage flow:
 * objective → mode → prepare → review base → review plan → review
 * permissions → review budget → approve → run → review result → independent
 * review → close & stop → receipt. Only the current stage's controls render;
 * nothing advances by itself — no hidden loops, no auto-continuation, no
 * auto-execution. Closing stops everything.
 *
 * Accessibility: the stepper is a real ordered list with aria-current, stage
 * transitions and run progress are announced via aria-live, and every state
 * is icon + text (never color-only). Mobile: the stepper becomes a vertical
 * timeline; Stop stays reachable as a sticky action while running.
 */
import {
  CircleCheck,
  CircleDashed,
  CircleX,
  ClipboardCheck,
  FileText,
  FolderGit2,
  GitBranch,
  OctagonX,
  Play,
  Receipt,
  RefreshCw,
  ShieldCheck,
  Square,
  Workflow,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

import type { ApplicationInstance, OrchestrationMode, OrchestrationSession, OrchestrationStage } from '@/client'
import { ClientError, getClient } from '@/client'
import {
  ConfirmDialog,
  Disclosure,
  EmptyState,
  ErrorState,
  InlineNotice,
  OperationStateLabel,
  SkeletonRows,
  StatusDotFrom,
  TimeAgo,
} from '@/components'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { useCurrentInstance } from '@/shell/currentInstance'
import type { ShellCommand } from '@/shell/commands'
import { useRegisterCommands } from '@/shell/commands'
import { useIsMobile } from '@/shell/platform'
import { WorkbenchToolHeader } from '@/shell/workbench/ToolHeader'
import { useRegisterToolPanel } from '@/shell/workbench/WorkbenchSlots'
import { cn } from '@/lib/utils'
import { repositoryCleanPresentation } from '@/semantic'

import { OrchestrationNavPanel } from './OrchestrationNavPanel'

import type { StepperItem } from './orchestrationModel'
import {
  MODES,
  REVIEW_SEQUENCE,
  STAGE_COUNT,
  STAGES,
  budgetExhausted,
  effectiveStage,
  modeMeta,
  reviewSteps,
  stageIndex,
  stageLabel,
  stepperItems,
} from './orchestrationModel'
import { useOrchestration } from './useOrchestration'

export default function OrchestrationTool() {
  const params = useParams<{ instanceId: string }>()
  const { instance, capability } = useCurrentInstance()
  const instanceId = instance?.id ?? params.instanceId ?? ''
  const navigate = useNavigate()
  const isMobile = useIsMobile()

  const orch = useOrchestration(instanceId)
  const { canStop, canRejectReview, canDiscard } = getClient().orchestration
  const { session, status, reload } = orch
  const [stopConfirm, setStopConfirm] = useState(false)
  const [discardConfirm, setDiscardConfirm] = useState(false)
  const [discardError, setDiscardError] = useState<string | null>(null)
  const stagePanelRef = useRef<HTMLDivElement | null>(null)

  // Capability facts come from the shell context; when the tool renders
  // outside the context (tests), fall back to the typed client.
  const [fetchedInstance, setFetchedInstance] = useState<ApplicationInstance | null>(null)
  useEffect(() => {
    if (instance || !instanceId) return
    let cancelled = false
    getClient()
      .applications.get(instanceId)
      .then((inst) => {
        if (!cancelled) setFetchedInstance(inst)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [instance, instanceId])
  const contextCapability = capability('cto_orchestration')
  const orchestrationCapability =
    contextCapability ?? (instance ?? fetchedInstance)?.capabilities.find((c) => c.id === 'cto_orchestration')
  const degraded = orchestrationCapability?.status === 'degraded'

  useRegisterToolPanel('orchestration', OrchestrationNavPanel)

  const current = effectiveStage(session, orch.localStage)
  const cancelled = session?.state === 'cancelled'
  const items = useMemo(() => stepperItems(current, cancelled), [current, cancelled])
  // A running record is never enough to invent a Stop transition: the action
  // renders only when the selected adapter explicitly supports it.
  const sliceRunning = orch.run.running || session?.state === 'running'
  const canDiscardSession = Boolean(
    canDiscard &&
      session &&
      (session.state === 'prepared' || session.state === 'approved') &&
      !orch.busy &&
      !sliceRunning,
  )

  const discard = async () => {
    setDiscardError(null)
    try {
      await orch.discard()
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      setDiscardError(
        `Discard could not be confirmed: ${detail} Refresh the current state before trying again.`,
      )
    }
  }

  // Stage transitions are announced via aria-live (text changes announce).
  const announcement = session
    ? `Stage ${stageIndex(current) + 1} of ${STAGE_COUNT}: ${stageLabel(current)}.`
    : 'No orchestration session. Enter an objective to prepare a bounded slice.'

  // Palette: "next stage" never advances by itself — it focuses the current
  // stage's primary control, which is the only thing allowed to act.
  const commands = useMemo<ShellCommand[]>(
    () => [
      {
        id: 'orchestration.next_stage',
        title: 'Orchestration: Go to the current stage action',
        group: 'Actions',
        icon: Workflow,
        keywords: ['orchestration', 'stage', 'next'],
        when: () => Boolean(instanceId) && status === 'ready',
        run: () => {
          const primary = stagePanelRef.current?.querySelector<HTMLElement>('[data-orchestration-primary]')
          primary?.focus()
          stagePanelRef.current?.scrollIntoView({ block: 'nearest' })
        },
      },
      {
        id: 'orchestration.reload',
        title: 'Orchestration: Reload state',
        group: 'Actions',
        icon: RefreshCw,
        keywords: ['orchestration', 'reload'],
        when: () => Boolean(instanceId),
        run: () => reload(),
      },
    ],
    [instanceId, status, reload],
  )
  useRegisterCommands(commands)

  if (status === 'loading') {
    return (
      <div className="flex h-full flex-col bg-app" data-testid="orchestration-loading">
        <WorkbenchToolHeader name="Orchestration" icon={Workflow} />
        <SkeletonRows rows={6} className="p-4" />
      </div>
    )
  }

  if (status === 'error') {
    return (
      <div className="flex h-full flex-col bg-app">
        <WorkbenchToolHeader name="Orchestration" icon={Workflow} />
        <ErrorState
          title="Could not load orchestration state"
          error={orch.errorDetail}
          preservedNote="Nothing was changed."
          onRetry={orch.reload}
        />
      </div>
    )
  }

  if (status === 'unavailable') {
    return (
      <div className="flex h-full flex-col bg-app">
        <WorkbenchToolHeader name="Orchestration" icon={Workflow} />
        {/* ONE blocked state — never a full disabled form behind it. */}
        <div className="flex flex-1 items-center justify-center p-6" data-testid="orchestration-unavailable">
          <div
            className="flex w-full max-w-md flex-col items-center gap-2 rounded-md border border-status-blocked-border bg-status-blocked-bg px-6 py-10 text-center"
            role="status"
          >
            <OctagonX className="size-5 text-status-blocked" aria-hidden="true" />
            <h2 className="text-lg text-foreground">Orchestration state unavailable</h2>
            <p className="text-sm text-foreground-secondary">
              Exact governed state could not be loaded. Execution controls are inactive.
            </p>
            <div className="mt-2 flex items-center gap-2">
              <Button size="sm" onClick={orch.reload} data-testid="orchestration-reload">
                <RefreshCw aria-hidden="true" />
                Reload state
              </Button>
            </div>
            <Disclosure title="Inspect technical details" className="mt-2 w-full text-left">
              <pre className="overflow-auto rounded-sm bg-sunken p-2 font-mono text-xs text-foreground-secondary" data-testid="orchestration-unavailable-detail">
                {orch.unavailableDetail ?? 'No detail provided.'}
              </pre>
            </Disclosure>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col bg-app" data-testid="orchestration-tool">
      {/* Route-smoke compat (see DeploymentsTool note). */}
      <span hidden data-testid="orchestration-stub" aria-hidden="true" />
      <div aria-live="polite" className="sr-only">
        {announcement}
      </div>

      <WorkbenchToolHeader
        name="Orchestration"
        icon={Workflow}
        state={session ? <OperationStateLabel state={session.state} /> : null}
        primaryAction={
          sliceRunning && canStop ? (
            <Button
              size="sm"
              variant="outline"
              className="border-status-danger-border text-status-danger hover:bg-status-danger-bg"
              onClick={() => setStopConfirm(true)}
              data-testid="orchestration-stop-header"
            >
              <Square aria-hidden="true" />
              Stop
            </Button>
          ) : canDiscardSession ? (
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setDiscardError(null)
                setDiscardConfirm(true)
              }}
              data-testid="orchestration-discard"
            >
              Discard slice
            </Button>
          ) : null
        }
      />

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto flex max-w-5xl flex-col gap-3 p-3">
          {session ? (
            <SafetyBar
              session={session}
              current={current}
              running={sliceRunning && canStop}
              onStop={() => setStopConfirm(true)}
              onOpenReceipt={(receiptId) => void navigate(`/app/${instanceId}/workbench/receipts/${receiptId}`)}
            />
          ) : null}

          {session && sliceRunning && !canStop ? (
            <InlineNotice tone="informational" title="Stop is unavailable">
              The connected service has no stop transition for an in-flight slice. This view will report the
              exact result when the bounded request returns.
            </InlineNotice>
          ) : null}

          {discardError ? (
            <InlineNotice
              tone="danger"
              title="Could not confirm discard"
              action={
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setDiscardError(null)
                    reload()
                  }}
                >
                  Refresh state
                </Button>
              }
            >
              {discardError}
            </InlineNotice>
          ) : null}

          <StageStepper items={items} vertical={isMobile} />

          {session && budgetExhausted(session) && session.state !== 'human_accepted' ? (
            <InlineNotice tone="attention" title="Step budget reached">
              The slice used all {session.budget.maxOperations} steps. Review the result, then close —
              nothing continues on its own.
            </InlineNotice>
          ) : null}

          <div ref={stagePanelRef} data-testid="stage-panel">
            <StagePanel
              instanceId={instanceId}
              orch={orch}
              current={current}
              degraded={degraded}
              degradedReason={orchestrationCapability?.reason}
              canRejectReview={canRejectReview}
              onOpenReceipt={(receiptId) => void navigate(`/app/${instanceId}/workbench/receipts/${receiptId}`)}
            />
          </div>
        </div>
      </div>

      {/* Mobile: Stop stays reachable without scrolling while running. */}
      {sliceRunning && canStop && isMobile ? (
        <div className="sticky bottom-0 border-t border-border bg-surface px-3 py-2">
          <Button
            size="sm"
            variant="outline"
            className="w-full border-status-danger-border text-status-danger hover:bg-status-danger-bg"
            onClick={() => setStopConfirm(true)}
            data-testid="orchestration-stop-sticky"
          >
            <Square aria-hidden="true" />
            Stop the running slice
          </Button>
        </div>
      ) : null}

      <ConfirmDialog
        open={canStop && stopConfirm}
        onOpenChange={setStopConfirm}
        title="Stop orchestration?"
        description="The slice stops after the current step and moves to Close. Nothing continues in the background."
        target={session?.objective}
        effect="The running inspection/execution halts; the log so far stays available for review."
        reversibility="Not a failure — you can review what ran and close the slice."
        confirmLabel="Stop after current step"
        destructive
        onConfirm={() => orch.stop()}
      />
      <ConfirmDialog
        open={canDiscardSession && discardConfirm}
        onOpenChange={setDiscardConfirm}
        title="Discard prepared slice?"
        description="This abandons the prepared or approved slice before execution."
        target={session?.objective}
        effect="Release this slice and return to a fresh objective. Nothing runs, closes, or creates a receipt."
        reversibility="This cannot resume the discarded approval. Prepare and review a new slice if you still want to proceed."
        confirmLabel="Discard slice"
        destructive
        onConfirm={discard}
      />
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Safety bar — always-visible governed facts (orchestration.md: persistent)
// ─────────────────────────────────────────────────────────────────────────────

function SafetyBar({
  session,
  current,
  running,
  onStop,
  onOpenReceipt,
}: {
  session: OrchestrationSession
  current: OrchestrationStage
  running: boolean
  onStop: () => void
  onOpenReceipt: (receiptId: string) => void
}) {
  const base = session.baseIdentity
  return (
    <section aria-label="Safety facts" data-testid="safety-bar" className="rounded-md border border-border bg-surface">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-xs">
        <span className="inline-flex items-center gap-1 font-mono text-foreground">
          <FolderGit2 className="size-3.5 text-foreground-secondary" aria-hidden="true" />
          {base.name} @ {base.branch}
          <span className="text-foreground-tertiary">({base.revision.slice(0, 10)})</span>
        </span>
        <StatusDotFrom presentation={repositoryCleanPresentation(base.clean)} />
        <span className="text-foreground-secondary">
          mode <span className="font-medium text-foreground">{modeMeta(session.mode).label}</span>
        </span>
        <span className="tnum font-mono text-foreground-secondary" data-testid="safety-budget">
          {session.budget.usedOperations}/{session.budget.maxOperations} steps · {session.budget.maxMinutes}m cap
        </span>
        <span className="text-foreground-secondary">
          stage <span className="font-medium text-foreground">{stageLabel(current)}</span>
        </span>
        <div className="flex-1" />
        {running ? (
          <Button
            size="sm"
            variant="outline"
            className="border-status-danger-border text-status-danger hover:bg-status-danger-bg"
            onClick={onStop}
            data-testid="orchestration-stop"
          >
            <Square aria-hidden="true" />
            Stop
          </Button>
        ) : null}
      </div>
      <Disclosure title="Safety details" className="border-t border-border px-3 py-1.5">
        <dl className="grid gap-x-4 gap-y-1 py-1 text-xs sm:grid-cols-2" data-testid="safety-details">
          <div className="flex items-baseline gap-2 sm:col-span-2">
            <dt className="shrink-0 font-medium text-foreground-secondary">Objective</dt>
            <dd className="text-foreground">{session.objective}</dd>
          </div>
          <div className="flex items-baseline gap-2">
            <dt className="shrink-0 font-medium text-foreground-secondary">Scope</dt>
            <dd className="font-mono text-foreground">{session.scope.join(', ')}</dd>
          </div>
          <div className="flex items-baseline gap-2">
            <dt className="shrink-0 font-medium text-foreground-secondary">Permissions</dt>
            <dd className="text-foreground">{session.permissions.join(' · ')}</dd>
          </div>
          <div className="flex items-baseline gap-2">
            <dt className="shrink-0 font-medium text-foreground-secondary">Implementer</dt>
            <dd className="text-foreground">{session.implementer}</dd>
          </div>
          <div className="flex items-baseline gap-2">
            <dt className="shrink-0 font-medium text-foreground-secondary">Reviewer</dt>
            <dd className="text-foreground">{session.reviewer}</dd>
          </div>
          {session.resultSummary ? (
            <div className="flex items-baseline gap-2 sm:col-span-2">
              <dt className="shrink-0 font-medium text-foreground-secondary">Result</dt>
              <dd className="text-foreground">{session.resultSummary}</dd>
            </div>
          ) : null}
          {session.receiptId ? (
            <div className="flex items-baseline gap-2">
              <dt className="shrink-0 font-medium text-foreground-secondary">Receipt</dt>
              <dd>
                <button
                  type="button"
                  className="inline-flex items-center gap-1 text-accent hover:underline"
                  onClick={() => onOpenReceipt(session.receiptId!)}
                >
                  <Receipt className="size-3" aria-hidden="true" />
                  Close receipt
                </button>
              </dd>
            </div>
          ) : null}
        </dl>
      </Disclosure>
    </section>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Stepper — horizontal on desktop, vertical timeline on mobile (aria-current)
// ─────────────────────────────────────────────────────────────────────────────

const STEPPER_STATE_CLASSES: Record<StepperItem['state'], string> = {
  done: 'border-status-success text-status-success',
  current: 'border-accent text-accent',
  upcoming: 'border-border text-foreground-tertiary border-dashed',
  failed: 'border-status-danger text-status-danger',
}

function StageStepper({ items, vertical }: { items: StepperItem[]; vertical: boolean }) {
  const currentItem = items.find((i) => i.state === 'current' || i.state === 'failed')
  if (vertical) {
    // Mobile: compact position summary + the full vertical timeline.
    return (
      <div data-testid="orchestration-stepper">
        {currentItem ? (
          <p className="mb-2 text-xs text-foreground-secondary">
            Stage <span className="font-medium text-foreground">{currentItem.index + 1} of {STAGE_COUNT}</span> —{' '}
            {currentItem.label}
          </p>
        ) : null}
        <ol className="flex flex-col" aria-label="Orchestration stages">
          {items.map((item) => {
            const Icon = item.state === 'done' ? CircleCheck : item.state === 'failed' ? CircleX : CircleDashed
            return (
              <li key={item.id} className="flex items-stretch gap-2">
                <span className="flex flex-col items-center" aria-hidden="true">
                  <span
                    className={cn(
                      'mt-0.5 inline-flex size-5 items-center justify-center rounded-full border bg-surface',
                      STEPPER_STATE_CLASSES[item.state],
                    )}
                  >
                    <Icon className="size-3" />
                  </span>
                  {item.index < items.length - 1 ? <span className="w-px flex-1 bg-border" /> : null}
                </span>
                <span
                  className={cn(
                    'pb-2 text-xs',
                    item.state === 'current' ? 'font-medium text-foreground' : 'text-foreground-tertiary',
                  )}
                  aria-current={item.state === 'current' ? 'step' : undefined}
                  data-stage={item.id}
                  data-state={item.state}
                >
                  {item.label}
                </span>
              </li>
            )
          })}
        </ol>
      </div>
    )
  }

  return (
    <ol
      className="flex items-center gap-y-2 overflow-x-auto pb-1"
      aria-label="Orchestration stages"
      data-testid="orchestration-stepper"
    >
      {items.map((item, index) => {
        const Icon = item.state === 'done' ? CircleCheck : item.state === 'failed' ? CircleX : CircleDashed
        return (
          <li key={item.id} className="flex shrink-0 items-center">
            {index > 0 ? <span className="mx-1 h-px w-3 bg-border" aria-hidden="true" /> : null}
            <span
              className={cn(
                'inline-flex items-center gap-1 whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-xs',
                STEPPER_STATE_CLASSES[item.state],
              )}
              aria-current={item.state === 'current' ? 'step' : undefined}
              data-stage={item.id}
              data-state={item.state}
            >
              <Icon className="size-3" aria-hidden="true" />
              {item.label}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage panel — ONLY the current stage's controls render
// ─────────────────────────────────────────────────────────────────────────────

interface StagePanelProps {
  instanceId: string
  orch: ReturnType<typeof useOrchestration>
  current: OrchestrationStage
  degraded: boolean
  degradedReason?: string
  canRejectReview: boolean
  onOpenReceipt: (receiptId: string) => void
}

function StagePanel({ instanceId, orch, current, degraded, degradedReason, canRejectReview, onOpenReceipt }: StagePanelProps) {
  const { session } = orch

  if (!session) {
    return <ObjectiveForm degraded={degraded} degradedReason={degradedReason} orch={orch} />
  }

  const reviewIndex = REVIEW_SEQUENCE.indexOf(current)
  if (reviewIndex >= 0) {
    return (
      <ReviewStagePanel session={session} current={current} reviewIndex={reviewIndex} orch={orch} />
    )
  }

  switch (current) {
    case 'run':
      return <RunStagePanel session={session} orch={orch} />
    case 'review_result':
      return <ReviewResultPanel session={session} orch={orch} onOpenReceipt={onOpenReceipt} />
    case 'independent_review':
      return <IndependentReviewPanel session={session} orch={orch} canRejectReview={canRejectReview} />
    case 'close':
      return <CloseStagePanel session={session} orch={orch} />
    case 'receipt':
      return <ReceiptStagePanel session={session} orch={orch} onOpenReceipt={onOpenReceipt} instanceId={instanceId} />
    default:
      return <ObjectiveForm degraded={degraded} degradedReason={degradedReason} orch={orch} />
  }
}

function StageShell({
  stage,
  children,
  actions,
}: {
  stage: OrchestrationStage
  children: React.ReactNode
  actions?: React.ReactNode
}) {
  const meta = STAGES[stageIndex(stage)]
  return (
    <section
      className="rounded-md border border-border bg-surface"
      aria-label={`Stage ${stageIndex(stage) + 1} of ${STAGE_COUNT}: ${meta.label}`}
      data-testid={`stage-${stage}`}
    >
      <div className="border-b border-border px-3 py-2">
        <p className="text-xs text-foreground-tertiary">
          Stage {stageIndex(stage) + 1} of {STAGE_COUNT}
        </p>
        <h3 className="text-sm font-semibold text-foreground">{meta.label}</h3>
        <p className="text-xs text-foreground-secondary">{meta.summary}</p>
      </div>
      <div className="flex flex-col gap-3 px-3 py-3">{children}</div>
      {actions ? (
        <div className="flex flex-wrap items-center gap-1.5 border-t border-border px-3 py-2">{actions}</div>
      ) : null}
    </section>
  )
}

// ── Stages 1–3: objective + mode + prepare ──────────────────────────────────

const HOW_IT_WORKS_KEY = 'stateport.orchestration.how-it-works.dismissed'

/** Plain, actionable copy for a prepare the backend can never honour. */
const BACKEND_UNAVAILABLE_COPY =
  'Governed execution is unavailable: no execution backend is configured on this host. Nothing was prepared or run. Wait for a StatePort release that configures a governed execution backend; turning orchestration off stays available.'

function prepareErrorCopy(err: unknown): string {
  if (err instanceof ClientError && err.code === 'goal_backend_unavailable') {
    return BACKEND_UNAVAILABLE_COPY
  }
  return err instanceof Error ? err.message : String(err)
}

function ObjectiveForm({
  degraded,
  degradedReason,
  orch,
}: {
  degraded: boolean
  degradedReason?: string
  orch: ReturnType<typeof useOrchestration>
}) {
  const [objective, setObjective] = useState('')
  const [mode, setMode] = useState<OrchestrationMode>('assisted')
  const [error, setError] = useState<string | null>(null)
  const [howOpen, setHowOpen] = useState(() => {
    try {
      return window.localStorage.getItem(HOW_IT_WORKS_KEY) !== '1'
    } catch {
      return true
    }
  })

  const dismissHow = (open: boolean) => {
    setHowOpen(open)
    if (!open) {
      try {
        window.localStorage.setItem(HOW_IT_WORKS_KEY, '1')
      } catch {
        /* private mode */
      }
    }
  }

  const submit = async () => {
    setError(null)
    try {
      await orch.prepareSlice({ objective: objective.trim(), mode })
    } catch (err) {
      setError(prepareErrorCopy(err))
    }
  }

  const backendUnavailable = orch.backend?.status === 'unavailable'

  return (
    <div className="flex flex-col gap-3">
      <EmptyState
        icon={Workflow}
        title="No orchestration session"
        description="Orchestration coordinates one bounded slice at a time, with your approval at the gate. It is not an autonomous background agent — nothing runs until you approve it, and closing stops everything."
        action={{
          label: 'New slice',
          icon: ClipboardCheck,
          onClick: () => document.getElementById('orchestration-objective')?.focus(),
        }}
      />
      <Disclosure title="How orchestration works" open={howOpen} onOpenChange={dismissHow}>
        <p className="px-1 pb-1 text-xs text-foreground-secondary">
          You state one bounded objective and pick a mode. StatePort prepares the slice and shows you the
          exact base, plan, permissions, and budget — you approve or stop at every gate. The run happens
          once, is reviewed by someone other than the implementer, and closing the slice stops everything.
        </p>
      </Disclosure>

      <StageShell
        stage="enter_objective"
        actions={
          <>
            {mode !== 'off' ? (
              <Button
                size="sm"
                onClick={() => void submit()}
                disabled={orch.busy || backendUnavailable || objective.trim().length === 0}
                data-orchestration-primary
                data-testid="orchestration-prepare"
              >
                <Play aria-hidden="true" />
                {orch.busy ? 'Preparing…' : 'Prepare slice'}
              </Button>
            ) : (
              <p className="text-xs text-foreground-tertiary" data-testid="orchestration-off-note">
                Orchestration is off — no slice will be prepared and nothing runs.
              </p>
            )}
          </>
        }
      >
        {degraded ? (
          <div data-testid="orchestration-degraded">
            <InlineNotice tone="attention" title="Assisted mode only">
              {degradedReason ?? 'Orchestration is limited to Assisted mode for this application.'}
            </InlineNotice>
          </div>
        ) : null}

        {backendUnavailable ? (
          <div data-testid="orchestration-backend-unavailable">
            <InlineNotice tone="blocked" title="Governed execution unavailable">
              {orch.backend?.message ?? BACKEND_UNAVAILABLE_COPY}{' '}
              {orch.backend?.nextAction ??
                'Wait for a StatePort release that configures a governed execution backend.'}
            </InlineNotice>
          </div>
        ) : null}

        <div>
          <label htmlFor="orchestration-objective" className="mb-1 block text-xs font-medium text-foreground-secondary">
            Objective — the one bounded thing this slice should do
          </label>
          <Textarea
            id="orchestration-objective"
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
            placeholder="e.g. Review the README and draft an update for the setup section"
            rows={3}
            className="bg-surface"
            data-testid="orchestration-objective"
          />
        </div>

        <fieldset>
          <legend className="mb-1 text-xs font-medium text-foreground-secondary">Mode</legend>
          <div className="grid gap-1.5 sm:grid-cols-2" role="radiogroup" aria-label="Orchestration mode">
            {MODES.map((m) => {
              const disabled = degraded && m.id !== 'assisted'
              const selected = mode === m.id
              return (
                <button
                  key={m.id}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  disabled={disabled}
                  onClick={() => setMode(m.id)}
                  className={cn(
                    'rounded-sm border px-2.5 py-2 text-left transition-colors duration-instant',
                    selected ? 'border-accent bg-accent-muted' : 'border-border bg-surface hover:bg-hover',
                    disabled && 'cursor-not-allowed opacity-50',
                  )}
                  data-testid={`mode-${m.id}`}
                >
                  <span className="block text-xs font-medium text-foreground">{m.label}</span>
                  <span className="block text-xs text-foreground-secondary">{m.description}</span>
                </button>
              )
            })}
          </div>
        </fieldset>

        {error ? (
          <p className="text-xs text-status-danger" role="alert">
            {error}
          </p>
        ) : null}
      </StageShell>
    </div>
  )
}

// ── Stages 4–8: review paging (base / plan / permissions / budget → approve) ─

function ReviewStagePanel({
  session,
  current,
  reviewIndex,
  orch,
}: {
  session: OrchestrationSession
  current: OrchestrationStage
  reviewIndex: number
  orch: ReturnType<typeof useOrchestration>
}) {
  const [error, setError] = useState<string | null>(null)
  const back = () => orch.setLocalStage(reviewIndex > 0 ? REVIEW_SEQUENCE[reviewIndex - 1] : 'review_base')
  const next = () => orch.setLocalStage(REVIEW_SEQUENCE[reviewIndex + 1] ?? null)
  const isApprove = current === 'approve'

  const approve = async () => {
    setError(null)
    try {
      await orch.approve()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <StageShell
      stage={current}
      actions={
        <>
          {reviewIndex > 0 ? (
            <Button size="sm" variant="ghost" onClick={back}>
              Back
            </Button>
          ) : null}
          {isApprove ? (
            <Button size="sm" onClick={() => void approve()} disabled={orch.busy} data-orchestration-primary data-testid="orchestration-approve">
              <ShieldCheck aria-hidden="true" />
              {orch.busy ? 'Approving…' : 'Approve slice'}
            </Button>
          ) : (
            <Button size="sm" onClick={next} data-orchestration-primary data-testid="orchestration-mark-reviewed">
              <CircleCheck aria-hidden="true" />
              Mark reviewed
            </Button>
          )}
        </>
      }
    >
      {current === 'review_base' ? (
        <>
          <div className="rounded-sm border border-border px-2.5 py-2" data-testid="review-base-identity">
            <p className="text-xs font-medium text-foreground-secondary">Exact base</p>
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="inline-flex items-center gap-1 text-sm text-foreground">
                <FolderGit2 className="size-4 text-foreground-secondary" aria-hidden="true" />
                {session.baseIdentity.name}
              </span>
              <span className="inline-flex items-center gap-1 text-xs text-foreground-secondary">
                <GitBranch className="size-3.5" aria-hidden="true" />
                {session.baseIdentity.branch}
              </span>
              <span className="tnum font-mono text-xs text-foreground-tertiary">
                {session.baseIdentity.revision.slice(0, 10)}
              </span>
              <StatusDotFrom presentation={repositoryCleanPresentation(session.baseIdentity.clean)} />
            </div>
          </div>
          <p className="text-xs text-foreground-secondary">
            This exact base is recorded with the slice. The run cannot drift from it — a base that changes
            under the slice would stop it, not get absorbed silently.
          </p>
        </>
      ) : null}

      {current === 'review_plan' ? (
        <>
          <ol className="divide-y divide-border rounded-sm border border-border" data-testid="review-plan-steps">
            {reviewSteps(session).map((step, index) => (
              <li key={index} className="flex items-baseline gap-2 px-2.5 py-1.5">
                <span className="tnum shrink-0 font-mono text-xs text-foreground-tertiary">{index + 1}.</span>
                <span className="min-w-0 flex-1">
                  <span className="block text-xs font-medium text-foreground">{step.title}</span>
                  <code className="tnum block truncate font-mono text-xs text-foreground-secondary">{step.detail}</code>
                </span>
              </li>
            ))}
          </ol>
          <p className="text-xs text-foreground-secondary">
            Scope is bounded to {session.scope.length} path{session.scope.length === 1 ? '' : 's'}:{' '}
            <span className="font-mono">{session.scope.join(', ')}</span>. Nothing outside the scope is touched.
          </p>
        </>
      ) : null}

      {current === 'review_permissions' ? (
        <>
          <ul className="flex flex-col gap-1" data-testid="review-permissions-list">
            {session.permissions.map((permission) => (
              <li key={permission} className="flex items-center gap-1.5 text-xs text-foreground">
                <ShieldCheck className="size-3.5 text-status-warning" aria-hidden="true" />
                {permission}
              </li>
            ))}
          </ul>
          <p className="text-xs text-foreground-secondary">
            The slice asks for exactly these permissions — nothing broader, nothing that outlives the slice.
          </p>
        </>
      ) : null}

      {current === 'review_budget' ? (
        <>
          <dl className="grid grid-cols-3 gap-2" data-testid="review-budget-facts">
            <div className="rounded-sm border border-border px-2.5 py-2">
              <dt className="text-xs font-medium text-foreground-secondary">Max steps</dt>
              <dd className="tnum font-mono text-sm text-foreground">{session.budget.maxOperations}</dd>
            </div>
            <div className="rounded-sm border border-border px-2.5 py-2">
              <dt className="text-xs font-medium text-foreground-secondary">Max minutes</dt>
              <dd className="tnum font-mono text-sm text-foreground">{session.budget.maxMinutes}</dd>
            </div>
            <div className="rounded-sm border border-border px-2.5 py-2">
              <dt className="text-xs font-medium text-foreground-secondary">Used so far</dt>
              <dd className="tnum font-mono text-sm text-foreground">{session.budget.usedOperations}</dd>
            </div>
          </dl>
          <p className="text-xs text-foreground-secondary">
            The slice halts at the budget cap — reaching it is a stop, not an overrun.
          </p>
        </>
      ) : null}

      {current === 'approve' ? (
        <>
          <p className="text-xs text-foreground-secondary" data-testid="approve-summary">
            Approve the slice “{session.objective}” ({modeMeta(session.mode).label} mode) on base{' '}
            <span className="font-mono">
              {session.baseIdentity.name} @ {session.baseIdentity.branch} ({session.baseIdentity.revision.slice(0, 10)})
            </span>
            , scoped to {session.scope.length} path{session.scope.length === 1 ? '' : 's'}, with{' '}
            {session.permissions.length} permission{session.permissions.length === 1 ? '' : 's'}, inside a budget of{' '}
            {session.budget.maxOperations} steps / {session.budget.maxMinutes} minutes.
          </p>
          <p className="text-xs text-foreground-secondary">
            Approving lets the slice run once. It does not loop, queue more work, or continue after the run.
          </p>
        </>
      ) : null}

      {error ? (
        <p className="text-xs text-status-danger" role="alert">
          {error}
        </p>
      ) : null}
    </StageShell>
  )
}

// ── Stage 9: run ─────────────────────────────────────────────────────────────

function RunStagePanel({ session, orch }: { session: OrchestrationSession; orch: ReturnType<typeof useOrchestration> }) {
  const [error, setError] = useState<string | null>(null)
  const running = orch.run.running
  const stopCopy = getClient().orchestration.canStop
    ? 'Stop is available — it halts after the current step.'
    : 'This service cannot stop a running slice from this view.'

  const run = async () => {
    setError(null)
    try {
      await orch.runSlice()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <StageShell
      stage="run"
      actions={
        <>
          {session.state === 'approved' && !running ? (
            <Button size="sm" onClick={() => void run()} data-orchestration-primary data-testid="orchestration-run">
              <Play aria-hidden="true" />
              Run the approved slice
            </Button>
          ) : null}
          {orch.run.error && session.state === 'approved' && !running ? (
            <Button size="sm" variant="outline" onClick={() => void run()} data-orchestration-primary data-testid="orchestration-run-retry">
              <Play aria-hidden="true" />
              Retry run
            </Button>
          ) : null}
          {session.stop && !running ? (
            <Button size="sm" variant="outline" onClick={orch.startNewSlice} data-orchestration-primary data-testid="orchestration-new-objective">
              Prepare a new slice
            </Button>
          ) : null}
        </>
      }
    >
      {session.stop ? (
        <div data-testid="orchestration-terminal-stop">
          <InlineNotice tone="danger" title="Run stopped">
            {session.stop.message} Prepare a new slice and review its approval before running again.
          </InlineNotice>
        </div>
      ) : null}
      {session.state === 'approved' && !running && orch.run.logs.length === 0 ? (
        <p className="text-xs text-foreground-secondary">
          The slice runs once — {modeMeta(session.mode).id === 'advisory' ? 'inspection only, nothing is written' : 'inside its approved scope and budget'} — then stops and waits for your review.
        </p>
      ) : null}

      {session.state === 'running' && !running ? (
        <div data-testid="orchestration-running-remote">
          <OperationStateLabel state="running" />
          <p className="mt-1 text-xs text-foreground-secondary">
            The slice is running ({session.budget.usedOperations}/{session.budget.maxOperations} steps used).
            {' '}{stopCopy}
          </p>
        </div>
      ) : null}

      {running ? (
        <div data-testid="orchestration-progress">
          <div aria-live="polite" className="sr-only">
            {`Running — ${orch.run.logs.length} steps logged.`}
          </div>
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <OperationStateLabel state="running" startedAt={orch.run.startedAt} />
            <span className="tnum font-mono text-xs text-foreground-tertiary">
              {session.budget.usedOperations}/{session.budget.maxOperations} steps
            </span>
          </div>
          <pre
            className="max-h-52 overflow-auto rounded-sm bg-sunken p-2 font-mono text-xs text-foreground-secondary"
            data-testid="orchestration-log"
          >
            {orch.run.logs.join('\n')}
          </pre>
          <p className="mt-1 text-xs text-foreground-secondary">
            {stopCopy}
          </p>
        </div>
      ) : null}

      {orch.run.error ? (
        <div data-testid="orchestration-run-error">
          <InlineNotice tone="danger" title="Run failed">
            {orch.run.error}
          </InlineNotice>
        </div>
      ) : null}

      {error ? (
        <p className="text-xs text-status-danger" role="alert">
          {error}
        </p>
      ) : null}
    </StageShell>
  )
}

// ── Stage 10: review result ─────────────────────────────────────────────────

function ReviewResultPanel({
  session,
  orch,
  onOpenReceipt,
}: {
  session: OrchestrationSession
  orch: ReturnType<typeof useOrchestration>
  onOpenReceipt: (receiptId: string) => void
}) {
  return (
    <StageShell
      stage="review_result"
      actions={
        <Button
          size="sm"
          onClick={() => orch.setLocalStage('independent_review')}
          data-orchestration-primary
          data-testid="orchestration-to-independent-review"
        >
          <CircleCheck aria-hidden="true" />
          Continue to independent review
        </Button>
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        <OperationStateLabel state={session.state} />
        <span className="tnum font-mono text-xs text-foreground-tertiary">
          budget used {session.budget.usedOperations}/{session.budget.maxOperations} steps
        </span>
      </div>
      <p className="text-xs text-foreground" data-testid="review-result-summary">
        {session.resultSummary ?? 'The run finished.'}
      </p>
      {orch.run.receipt ? (
        <button
          type="button"
          className="inline-flex w-fit items-center gap-1 text-xs text-accent hover:underline"
          onClick={() => onOpenReceipt(orch.run.receipt!.id)}
          data-testid="orchestration-run-receipt"
        >
          <Receipt className="size-3" aria-hidden="true" />
          Run receipt
        </button>
      ) : null}
      {orch.run.logs.length > 0 ? (
        <Disclosure title={`Run log (${orch.run.logs.length} lines)`}>
          <pre className="max-h-44 overflow-auto rounded-sm bg-sunken p-2 font-mono text-xs text-foreground-secondary">
            {orch.run.logs.join('\n')}
          </pre>
        </Disclosure>
      ) : null}
    </StageShell>
  )
}

// ── Stage 11: independent review ────────────────────────────────────────────

function IndependentReviewPanel({
  session,
  orch,
  canRejectReview,
}: {
  session: OrchestrationSession
  orch: ReturnType<typeof useOrchestration>
  canRejectReview: boolean
}) {
  const [flagging, setFlagging] = useState(false)
  const [notes, setNotes] = useState('')
  const [error, setError] = useState<string | null>(null)

  const submit = async (accepted: boolean) => {
    setError(null)
    try {
      await orch.submitReview(accepted ? { accepted: true } : { accepted: false, notes: notes.trim() || undefined })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <StageShell
      stage="independent_review"
      actions={
        <>
          <Button size="sm" variant="ghost" onClick={() => orch.setLocalStage('review_result')}>
            Back
          </Button>
          {!flagging ? (
            <>
              <Button size="sm" onClick={() => void submit(true)} disabled={orch.busy} data-orchestration-primary data-testid="orchestration-accept">
                <CircleCheck aria-hidden="true" />
                Looks correct
              </Button>
              {canRejectReview ? (
                <Button size="sm" variant="outline" onClick={() => setFlagging(true)} data-testid="orchestration-flag">
                  <CircleX aria-hidden="true" />
                  Flag issue
                </Button>
              ) : null}
            </>
          ) : (
            <Button
              size="sm"
              variant="outline"
              className="border-status-danger-border text-status-danger hover:bg-status-danger-bg"
              onClick={() => void submit(false)}
              disabled={orch.busy}
              data-orchestration-primary
              data-testid="orchestration-submit-flag"
            >
              <CircleX aria-hidden="true" />
              Flag and send back
            </Button>
          )}
        </>
      }
    >
      <p className="text-xs text-foreground-secondary">
        Proposed by <span className="font-medium text-foreground">{session.implementer}</span> — reviewed by{' '}
        <span className="font-medium text-foreground">{session.reviewer}</span>. The reviewer is never the
        implementer.
      </p>
      {!canRejectReview ? (
        <InlineNotice tone="informational" title="Send-back is unavailable">
          The connected service exposes the exact independent-review acceptance transition, but no rejection
          or reviewer-notes transition. Use Back to keep the result unaccepted.
        </InlineNotice>
      ) : null}
      <ul className="flex flex-col gap-1" data-testid="independent-review-facts">
        <li className="flex items-center gap-1.5 text-xs text-foreground">
          <FileText className="size-3.5 text-foreground-secondary" aria-hidden="true" />
          Base stayed {session.baseIdentity.name} @ {session.baseIdentity.branch} ({session.baseIdentity.revision.slice(0, 10)})
        </li>
        <li className="flex items-center gap-1.5 text-xs text-foreground">
          <FileText className="size-3.5 text-foreground-secondary" aria-hidden="true" />
          Scope stayed {session.scope.join(', ')}
        </li>
        <li className="flex items-center gap-1.5 text-xs text-foreground">
          <FileText className="size-3.5 text-foreground-secondary" aria-hidden="true" />
          Budget used {session.budget.usedOperations} of {session.budget.maxOperations} steps
        </li>
      </ul>
      {flagging ? (
        <div>
          <label htmlFor="orchestration-review-notes" className="mb-1 block text-xs font-medium text-foreground-secondary">
            What is wrong? The notes go on the record.
          </label>
          <Textarea
            id="orchestration-review-notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
            className="bg-surface"
            data-testid="orchestration-review-notes"
          />
        </div>
      ) : null}
      {error ? (
        <p className="text-xs text-status-danger" role="alert">
          {error}
        </p>
      ) : null}
    </StageShell>
  )
}

// ── Stage 12: close & stop ──────────────────────────────────────────────────

function CloseStagePanel({ session, orch }: { session: OrchestrationSession; orch: ReturnType<typeof useOrchestration> }) {
  const [error, setError] = useState<string | null>(null)
  const close = async () => {
    setError(null)
    try {
      await orch.close()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }
  return (
    <StageShell
      stage="close"
      actions={
        <Button size="sm" onClick={() => void close()} disabled={orch.busy} data-orchestration-primary data-testid="orchestration-close">
          <Square aria-hidden="true" />
          {orch.busy ? 'Closing…' : 'Close and stop'}
        </Button>
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        <OperationStateLabel state={session.state} />
      </div>
      <p className="text-xs text-foreground-secondary">
        {session.state === 'cancelled'
          ? 'The slice was stopped before completion. Closing archives it and writes the receipt.'
          : session.state === 'rejected'
            ? 'The reviewer flagged the result. Closing archives the slice and writes the receipt.'
            : 'The slice was reviewed and accepted. Closing archives it and writes the receipt.'}{' '}
        Closing stops everything — nothing continues after close.
      </p>
      {error ? (
        <p className="text-xs text-status-danger" role="alert">
          {error}
        </p>
      ) : null}
    </StageShell>
  )
}

// ── Stage 13: receipt ───────────────────────────────────────────────────────

function ReceiptStagePanel({
  session,
  orch,
  onOpenReceipt,
}: {
  session: OrchestrationSession
  orch: ReturnType<typeof useOrchestration>
  onOpenReceipt: (receiptId: string) => void
  instanceId: string
}) {
  return (
    <StageShell
      stage="receipt"
      actions={
        <Button size="sm" variant="outline" onClick={orch.startNewSlice} data-orchestration-primary data-testid="orchestration-new-slice">
          <ClipboardCheck aria-hidden="true" />
          Start a new slice
        </Button>
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        <OperationStateLabel state={session.state} />
        {session.receiptId ? (
          <Button size="sm" variant="outline" onClick={() => onOpenReceipt(session.receiptId!)} data-testid="orchestration-close-receipt">
            <Receipt aria-hidden="true" />
            View close receipt
          </Button>
        ) : null}
      </div>
      <p className="text-xs text-foreground-secondary">
        Session archived <TimeAgo date={session.updatedAt} />. Orchestration is stopped — nothing continues
        in the background, and a new slice would start from stage 1 with its own approval.
      </p>
    </StageShell>
  )
}
