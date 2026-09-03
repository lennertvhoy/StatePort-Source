import {
  Check,
  CirclePause,
  CornerUpLeft,
  FilePenLine,
  Play,
  RotateCcw,
  Route,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import type { ApplicationInstance, GovernedAction, RunOperation, RunRecord, StudyStatePackageData } from '@/client'
import { getClient } from '@/client'
import { Disclosure, InlineNotice } from '@/components'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { useApplicationsPrefs } from '@/features/applications/lib/prefsStore'

const RECORD_ACTION = 'studystate.sample.record-evidence/v1'
const START_ACTION = 'studystate.sample.start-activity/v1'
const PAUSE_ACTION = 'studystate.sample.pause-activity/v1'
const REDIRECT_ACTION = 'studystate.sample.redirect-activity/v1'
const UNDO_ACTION = 'studystate.sample.undo-last-evidence/v1'

type JourneyMode = 'ready' | 'drafting' | 'proposal' | 'applied'
type ProposalIntent = 'record' | 'undo' | 'start' | 'pause' | 'redirect'
type ControlIntent = Extract<ProposalIntent, 'start' | 'pause' | 'redirect'>

class OutcomeUnknownError extends Error {}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function operationOf(run: RunRecord | null): Record<string, unknown> | null {
  const proposal = run?.proposal
  const operation = proposal && typeof proposal === 'object' ? proposal.operation : null
  return operation && typeof operation === 'object' && !Array.isArray(operation)
    ? operation as Record<string, unknown>
    : null
}

function requireText(operation: Record<string, unknown>, field: string): string {
  const value = operation[field]
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`StudyState did not bind ${field} into the exact change proposal.`)
  }
  return value
}

function requireDigest(operation: Record<string, unknown>, field: string): string {
  const value = requireText(operation, field)
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new Error(`StudyState did not bind a valid ${field} into the exact change proposal.`)
  }
  return value
}

function exactReviewOperation(run: RunRecord, intent: ProposalIntent): Record<string, unknown> {
  const operation = operationOf(run)
  if (!operation) throw new Error('StudyState did not return an exact change proposal.')

  if (intent === 'record' || intent === 'undo') {
    requireText(operation, 'activityTitle')
    requireText(operation, 'reflection')
    requireDigest(operation, intent === 'record' ? 'beforePlanDigest' : 'expectedCurrentPlanDigest')
    requireDigest(operation, intent === 'record' ? 'afterPlanDigest' : 'restoredPlanDigest')
    return operation
  }

  requireDigest(operation, 'expectedPlanDigest')
  requireDigest(operation, 'resultingPlanDigest')
  if (intent === 'redirect') {
    if (
      operation.type !== 'redirect_activity'
      || operation.fromPriorStatus !== 'in_progress'
      || operation.fromResultingStatus !== 'paused'
      || !['planned', 'paused'].includes(String(operation.toPriorStatus))
      || operation.toResultingStatus !== 'in_progress'
    ) {
      throw new Error('StudyState did not bind the exact durable Redirect transition into the proposal.')
    }
    requireText(operation, 'fromActivityId')
    requireText(operation, 'fromActivityTitle')
    requireText(operation, 'toActivityId')
    requireText(operation, 'toActivityTitle')
    if (operation.fromActivityId === operation.toActivityId) {
      throw new Error('StudyState returned the same activity as both Redirect source and target.')
    }
    return operation
  }

  const expected = intent === 'start'
    ? { type: 'start_activity', prior: ['planned', 'paused'], resulting: 'in_progress' }
    : { type: 'pause_activity', prior: ['in_progress'], resulting: 'paused' }
  if (
    operation.type !== expected.type
    || !expected.prior.includes(String(operation.priorStatus))
    || operation.resultingStatus !== expected.resulting
  ) {
    throw new Error(`StudyState did not bind the exact durable ${intent === 'start' ? 'Start' : 'Pause'} transition into the proposal.`)
  }
  requireText(operation, 'activityId')
  requireText(operation, 'activityTitle')
  return operation
}

function controlReceiptId(run: RunRecord): string {
  const receipt = run.closureReceipt
  const validation = receipt && typeof receipt.validation === 'object' && receipt.validation
    ? receipt.validation as Record<string, unknown>
    : null
  if (
    !receipt
    || typeof run.receiptId !== 'string'
    || !run.receiptId
    || receipt.receiptId !== run.receiptId
    || receipt.runId !== run.id
    || receipt.instanceId !== run.instanceId
    || receipt.status !== 'applied'
    || validation?.state !== 'validated'
  ) {
    throw new OutcomeUnknownError('StatePort applied the request but did not return the exact validated closure receipt. Re-read the durable learning state before retrying.')
  }
  return run.receiptId
}

function statusLabel(value: unknown): string {
  if (value === 'not_started' || value === 'planned') return 'Not started'
  if (value === 'in_progress') return 'In progress'
  if (value === 'paused') return 'Paused'
  if (value === 'done' || value === 'completed') return 'Done'
  return 'Unknown'
}

function sentenceStatus(value: unknown): string {
  return statusLabel(value).toLowerCase()
}

function isControlIntent(intent: ProposalIntent): intent is ControlIntent {
  return intent === 'start' || intent === 'pause' || intent === 'redirect'
}

async function transition(run: RunRecord, operation: RunOperation): Promise<RunRecord> {
  return getClient().runs.transition(run.id, operation, {
    expectedInstanceId: run.instanceId,
    expectedRevision: run.revision,
  })
}

export function StudyJourney({
  instance,
  study,
  onDurableStateChanged,
}: {
  instance: ApplicationInstance
  study: StudyStatePackageData
  onDurableStateChanged: () => Promise<void> | void
}) {
  const pendingActivities = useMemo(
    () => study.activities.filter((activity) => activity.state !== 'done'),
    [study.activities],
  )
  const activeActivity = pendingActivities.find((activity) => activity.state === 'in_progress')
  const [selectedId, setSelectedId] = useState(activeActivity?.id ?? pendingActivities[0]?.id ?? '')
  const [mode, setMode] = useState<JourneyMode>('ready')
  const [redirectOpen, setRedirectOpen] = useState(false)
  const [redirectTargetId, setRedirectTargetId] = useState('')
  const reflectionDrafts = useApplicationsPrefs((state) => state.studyReflectionDrafts)
  const setReflectionDraft = useApplicationsPrefs((state) => state.setStudyReflectionDraft)
  const clearReflectionDraft = useApplicationsPrefs((state) => state.clearStudyReflectionDraft)
  const [actions, setActions] = useState<GovernedAction[]>([])
  const [actionsError, setActionsError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [outcomeUnknown, setOutcomeUnknown] = useState(false)
  const [run, setRun] = useState<RunRecord | null>(null)
  const [intent, setIntent] = useState<ProposalIntent>('record')
  const [appliedReceiptId, setAppliedReceiptId] = useState<string | null>(null)
  const reflectionRef = useRef<HTMLTextAreaElement>(null)
  const primaryControlRef = useRef<HTMLButtonElement>(null)
  const firstRedirectTargetRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    let cancelled = false
    getClient().runs.listActions(instance.id)
      .then((value) => {
        if (!cancelled) setActions(value)
      })
      .catch((caught: unknown) => {
        if (!cancelled) setActionsError(message(caught))
      })
    return () => {
      cancelled = true
    }
  }, [instance.id])

  useEffect(() => {
    if (activeActivity && !redirectOpen) {
      setSelectedId(activeActivity.id)
    } else if (!pendingActivities.some((activity) => activity.id === selectedId)) {
      setSelectedId(pendingActivities[0]?.id ?? '')
    }
  }, [activeActivity, pendingActivities, redirectOpen, selectedId])

  useEffect(() => {
    if (mode === 'drafting') reflectionRef.current?.focus()
  }, [mode])

  useEffect(() => {
    if (redirectOpen) firstRedirectTargetRef.current?.focus()
  }, [redirectOpen])

  const selected = pendingActivities.find((activity) => activity.id === selectedId) ?? pendingActivities[0]
  const redirectTargets = activeActivity
    ? pendingActivities.filter((activity) => activity.id !== activeActivity.id)
    : []
  const redirectTarget = redirectTargets.find((activity) => activity.id === redirectTargetId)
  const reflectionKey = selected ? `${instance.id}:${selected.id}` : ''
  const reflection = (reflectionDrafts[reflectionKey] ?? '').slice(0, 280)
  const hiddenDrafts = pendingActivities.filter(
    (activity) => activity.id !== selected?.id && Boolean(reflectionDrafts[`${instance.id}:${activity.id}`]?.trim()),
  )
  const operation = operationOf(run)
  const recordAction = actions.find((action) => action.id === RECORD_ACTION)
  const startAction = actions.find((action) => action.id === START_ACTION)
  const pauseAction = actions.find((action) => action.id === PAUSE_ACTION)
  const redirectAction = actions.find((action) => action.id === REDIRECT_ACTION)
  const undoAction = actions.find((action) => action.id === UNDO_ACTION)
  const details = run ? {
    runId: run.id,
    engineId: run.engineId,
    proposalDigest: run.proposalDigest?.value,
  } : null

  const prepareProposal = async (
    action: GovernedAction,
    inputs: Record<string, unknown>,
    nextIntent: ProposalIntent,
  ) => {
    setBusy(true)
    setError(null)
    setOutcomeUnknown(false)
    setAppliedReceiptId(null)
    try {
      const engines = await getClient().runs.listEngines()
      const engine = engines.find((item) => item.id === 'synthetic' && item.available)
      if (!engine) throw new Error('The local public-safe StudyState engine is unavailable.')
      let next = await getClient().runs.prepare(instance.id, {
        actionId: action.id,
        engineId: engine.id,
        inputs,
      })
      next = await transition(next, 'approve')
      next = await transition(next, 'execute')
      if (next.status !== 'state_change_proposed') {
        throw new Error('StudyState did not produce an exact state-change proposal.')
      }
      exactReviewOperation(next, nextIntent)
      setIntent(nextIntent)
      setRun(next)
      setRedirectOpen(false)
      setMode('proposal')
    } catch (caught: unknown) {
      setError(message(caught))
    } finally {
      setBusy(false)
    }
  }

  const approveAndApply = async () => {
    if (!run) return
    setBusy(true)
    setError(null)
    setOutcomeUnknown(false)
    try {
      let next = await transition(run, 'proposal-approve')
      try {
        next = await transition(next, 'apply')
      } catch {
        throw new OutcomeUnknownError('StatePort could not confirm the apply response. Re-read the durable learning state before retrying.')
      }
      if (next.status !== 'applied') {
        throw new OutcomeUnknownError('StatePort could not verify that the approved StudyState change was applied.')
      }
      const receiptId = isControlIntent(intent) ? controlReceiptId(next) : next.receiptId ?? null
      setRun(next)
      try {
        await onDurableStateChanged()
      } catch {
        throw new OutcomeUnknownError('The apply response arrived, but StatePort could not re-read the durable learning state. Verify current state before retrying.')
      }
      if (intent === 'record' && operation && typeof operation.activityId === 'string') {
        clearReflectionDraft(instance.id, operation.activityId)
      }
      setAppliedReceiptId(receiptId)
      setMode('applied')
    } catch (caught: unknown) {
      setOutcomeUnknown(caught instanceof OutcomeUnknownError)
      setError(message(caught))
    } finally {
      setBusy(false)
    }
  }

  if (!study.planDigest || pendingActivities.length === 0 && !study.canUndo) return null

  const reviewActivity = typeof operation?.activityTitle === 'string' ? operation.activityTitle : ''
  const reviewReflection = typeof operation?.reflection === 'string' ? operation.reflection : ''
  const priorStatus = sentenceStatus(operation?.priorStatus)
  const restoredStatus = sentenceStatus(operation?.restoreStatus)
  const completedCount = study.activities.filter((activity) => activity.state === 'done').length
  const progressAfterRecord = study.activities.length > 0
    ? Math.round(((completedCount + 1) / study.activities.length) * 100)
    : study.goalProgressPercent
  const progressAfterUndo = study.activities.length > 0
    ? Math.round((Math.max(0, completedCount - 1) / study.activities.length) * 100)
    : study.goalProgressPercent
  const proposedBeforeDigest = operation
    ? intent === 'record'
      ? operation.beforePlanDigest
      : intent === 'undo'
        ? operation.expectedCurrentPlanDigest
        : operation.expectedPlanDigest
    : undefined
  const proposedAfterDigest = operation
    ? intent === 'record'
      ? operation.afterPlanDigest
      : intent === 'undo'
        ? operation.restoredPlanDigest
        : operation.resultingPlanDigest
    : undefined

  const appliedTitle = intent === 'record'
    ? 'Self-reported reflection saved to durable learning state'
    : intent === 'undo'
      ? 'Prior learning plan restored'
      : intent === 'start'
        ? 'Activity started in durable learning state'
        : intent === 'pause'
          ? 'Activity paused in durable learning state'
          : 'Learning activity redirected in durable state'

  return (
    <section
      aria-labelledby="study-next-activity-heading"
      className="border-l-2 border-accent pl-4 sm:pl-5"
      data-testid="study-native-journey"
    >
      <div className="min-w-0">
        <p className="text-xs font-semibold uppercase tracking-wide text-accent">
          {activeActivity ? 'Current activity from your learning state' : 'Next from your learning state'}
        </p>
        <h2 id="study-next-activity-heading" className="mt-2 max-w-3xl text-2xl font-semibold leading-tight tracking-tight text-foreground sm:text-3xl">
          {selected?.title ?? 'Your learning plan is complete'}
        </h2>
        {selected ? (
          <>
            <p className="mt-2 text-sm font-medium text-foreground-secondary" data-testid="study-durable-status">
              Durable state · {statusLabel(selected.state)}
            </p>
            <div className="mt-4 max-w-2xl" data-testid="study-activity-reason">
              <p className="text-xs font-semibold uppercase tracking-wide text-foreground-tertiary">Why now</p>
              <p className="mt-1 text-sm leading-relaxed text-foreground-secondary">
                {selected.reason ?? 'This is the next unfinished activity in the durable learning plan.'}
              </p>
            </div>
          </>
        ) : null}
      </div>

      {actionsError ? (
        <div className="mt-4">
          <InlineNotice tone="danger" title="Study actions are unavailable">{actionsError}</InlineNotice>
        </div>
      ) : null}
      {error ? (
        <div className="mt-4">
          <InlineNotice
            tone="danger"
            title={outcomeUnknown ? 'Apply outcome needs verification' : 'The learning state was not changed'}
          >
            {error}
          </InlineNotice>
        </div>
      ) : null}
      {hiddenDrafts.length > 0 ? (
        <div className="mt-4">
          <InlineNotice tone="informational" title="Another reflection draft is preserved">
            <span>Your draft for “{hiddenDrafts[0].title}” is stored in this browser only. </span>
            {!activeActivity ? (
              <button
                type="button"
                className="font-medium underline underline-offset-2"
                onClick={() => {
                  setSelectedId(hiddenDrafts[0].id)
                  setMode('drafting')
                }}
              >
                Return to draft
              </button>
            ) : null}
          </InlineNotice>
        </div>
      ) : null}

      {mode === 'ready' || mode === 'drafting' ? (
        <>
          <div className="mt-5" data-testid="study-durable-controls">
            <p className="text-xs font-semibold uppercase tracking-wide text-foreground-tertiary">Activity controls</p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              {activeActivity ? (
                <Button
                  ref={primaryControlRef}
                  onClick={() => pauseAction && void prepareProposal(pauseAction, {
                    activityId: activeActivity.id,
                    expectedPlanDigest: study.planDigest,
                  }, 'pause')}
                  disabled={busy || !pauseAction}
                  data-testid="study-pause"
                >
                  <CirclePause aria-hidden="true" />
                  {busy ? 'Preparing review…' : 'Pause activity'}
                </Button>
              ) : selected ? (
                <Button
                  ref={primaryControlRef}
                  onClick={() => startAction && void prepareProposal(startAction, {
                    activityId: selected.id,
                    expectedPlanDigest: study.planDigest,
                  }, 'start')}
                  disabled={busy || !startAction}
                  data-testid="study-start"
                >
                  <Play aria-hidden="true" />
                  {busy ? 'Preparing review…' : selected.state === 'paused' ? 'Resume activity' : 'Start activity'}
                </Button>
              ) : null}
              {activeActivity && redirectTargets.length > 0 ? (
                <Button
                  variant="outline"
                  onClick={() => {
                    setRedirectTargetId('')
                    setRedirectOpen((value) => !value)
                  }}
                  disabled={busy || !redirectAction}
                  data-testid="study-redirect"
                >
                  <Route aria-hidden="true" />
                  Choose another activity
                </Button>
              ) : null}
              {!activeActivity && pendingActivities.length > 1 ? (
                <Disclosure title="Select activity to start" className="basis-full sm:basis-auto">
                  <div className="mt-2 flex flex-col items-start gap-1">
                    {pendingActivities.map((activity) => (
                      <button
                        type="button"
                        key={activity.id}
                        aria-pressed={selected?.id === activity.id}
                        onClick={() => setSelectedId(activity.id)}
                        className={cn(
                          'min-h-10 rounded-sm px-2.5 text-left text-sm transition-colors duration-instant focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                          selected?.id === activity.id ? 'bg-active font-medium text-foreground' : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
                        )}
                      >
                        {activity.title} · {statusLabel(activity.state)}
                      </button>
                    ))}
                  </div>
                </Disclosure>
              ) : null}
              {selected ? (
                <Button
                  variant="ghost"
                  onClick={() => setMode('drafting')}
                  data-testid="study-open-reflection"
                >
                  <FilePenLine aria-hidden="true" />
                  {reflection.trim() ? 'Continue browser draft' : 'Write reflection'}
                </Button>
              ) : null}
              {reflection.trim() && selected ? (
                <Button
                  variant="ghost"
                  onClick={() => clearReflectionDraft(instance.id, selected.id)}
                  data-testid="study-discard-draft"
                >
                  <Trash2 aria-hidden="true" />
                  Discard browser draft
                </Button>
              ) : null}
              {study.canUndo && undoAction ? (
                <Button
                  variant="outline"
                  onClick={() => void prepareProposal(undoAction, { expectedPlanDigest: study.planDigest }, 'undo')}
                  disabled={busy}
                  data-testid="study-undo"
                >
                  <RotateCcw aria-hidden="true" />
                  {busy ? 'Preparing Undo…' : 'Review undo of last change'}
                </Button>
              ) : null}
            </div>
            <p className="mt-2 text-xs text-foreground-tertiary">
              Start, Pause, and Redirect change durable learning state only after exact review and approval. Reflection drafts stay in this browser until separately approved as evidence.
            </p>
          </div>

          {redirectOpen && activeActivity ? (
            <fieldset className="mt-4 border-y border-border py-4" data-testid="study-redirect-options">
              <legend className="px-1 text-sm font-medium text-foreground">Redirect to</legend>
              <p className="mt-1 text-xs text-foreground-secondary">
                Redirect will pause “{activeActivity.title}” and start exactly one selected activity after review.
              </p>
              <div className="mt-3 flex flex-col gap-1">
                {redirectTargets.map((activity, index) => (
                  <button
                    ref={index === 0 ? firstRedirectTargetRef : undefined}
                    type="button"
                    key={activity.id}
                    aria-pressed={redirectTargetId === activity.id}
                    onClick={() => setRedirectTargetId(activity.id)}
                    data-testid={`study-redirect-target-${activity.id}`}
                    className={cn(
                      'flex min-h-11 w-full items-center justify-between gap-3 rounded-sm px-3 text-left text-sm transition-colors duration-instant focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                      redirectTargetId === activity.id ? 'bg-active font-medium text-foreground' : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
                    )}
                  >
                    <span>{activity.title}</span>
                    <span className="shrink-0 text-xs">{statusLabel(activity.state)}</span>
                  </button>
                ))}
              </div>
              <div className="mt-3 flex flex-wrap justify-end gap-2">
                <Button variant="ghost" onClick={() => setRedirectOpen(false)}>Cancel</Button>
                <Button
                  onClick={() => redirectAction && redirectTarget && void prepareProposal(redirectAction, {
                    fromActivityId: activeActivity.id,
                    toActivityId: redirectTarget.id,
                    expectedPlanDigest: study.planDigest,
                  }, 'redirect')}
                  disabled={busy || !redirectTarget || !redirectAction}
                  data-testid="study-review-redirect"
                >
                  <ShieldCheck aria-hidden="true" />
                  {busy ? 'Preparing review…' : 'Review redirect'}
                </Button>
              </div>
            </fieldset>
          ) : null}

          {mode === 'drafting' && selected ? (
            <div className="mt-5 animate-in fade-in-0 slide-in-from-bottom-1 duration-med motion-reduce:animate-none">
              {reflection.trim() ? (
                <InlineNotice tone="informational" title="Browser-local draft">
                  It is not canonical learning state or evidence until you review and approve the exact proposal.
                </InlineNotice>
              ) : null}
              <form
                className="mt-4"
                onSubmit={(event) => {
                  event.preventDefault()
                  if (recordAction && reflection.trim()) {
                    void prepareProposal(recordAction, {
                      activityId: selected.id,
                      evidenceSummary: reflection.trim(),
                    }, 'record')
                  }
                }}
              >
                <label htmlFor={`study-reflection-${instance.id}`} className="text-sm font-medium text-foreground">
                  What changed in your understanding?
                </label>
                <textarea
                  ref={reflectionRef}
                  id={`study-reflection-${instance.id}`}
                  value={reflection}
                  maxLength={280}
                  rows={4}
                  aria-describedby={`study-reflection-help-${instance.id}`}
                  onChange={(event) => setReflectionDraft(instance.id, selected.id, event.target.value)}
                  className="mt-1.5 w-full resize-y rounded-sm border border-input bg-surface px-3 py-2 text-sm text-foreground outline-none transition-colors duration-instant placeholder:text-foreground-tertiary focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/40"
                  placeholder="Write one short, concrete reflection. Do not include secrets."
                />
                <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
                  <span id={`study-reflection-help-${instance.id}`} className="text-xs text-foreground-tertiary">
                    {reflection.length}/280 · stored in this browser only; self-reported and unassessed after approval
                  </span>
                  <div className="flex flex-wrap gap-2">
                    <Button type="button" variant="ghost" onClick={() => setMode('ready')}>Close draft</Button>
                    <Button type="submit" disabled={busy || !recordAction || !reflection.trim()} data-testid="study-review-change">
                      <ShieldCheck aria-hidden="true" />
                      {busy ? 'Preparing review…' : 'Review exact change'}
                    </Button>
                  </div>
                </div>
              </form>
            </div>
          ) : null}
        </>
      ) : null}

      {mode === 'proposal' && operation ? (
        <div className="mt-5 animate-in fade-in-0 slide-in-from-bottom-1 duration-med motion-reduce:animate-none" data-testid="study-change-preview">
          <h3 className="text-base font-semibold text-foreground">
            {intent === 'record'
              ? 'Review the durable change'
              : intent === 'undo'
                ? 'Review the exact Undo'
                : `Review ${intent === 'redirect' ? 'Redirect' : intent === 'start' ? 'Start' : 'Pause'}`}
          </h3>
          <div className="mt-3 border-y border-border py-4">
            <dl className="grid gap-x-4 gap-y-3 text-sm sm:grid-cols-[9rem_1fr]">
              {intent === 'redirect' ? (
                <>
                  <dt className="font-medium text-foreground-secondary">Current activity</dt>
                  <dd className="font-medium text-foreground" data-testid="study-review-activity">{String(operation.fromActivityTitle)}</dd>
                  <dt className="font-medium text-foreground-secondary">Redirect target</dt>
                  <dd className="font-medium text-foreground" data-testid="study-review-target">{String(operation.toActivityTitle)}</dd>
                </>
              ) : (
                <>
                  <dt className="font-medium text-foreground-secondary">Activity</dt>
                  <dd className="font-medium text-foreground" data-testid="study-review-activity">{reviewActivity}</dd>
                </>
              )}
              {intent === 'record' || intent === 'undo' ? (
                <>
                  <dt className="font-medium text-foreground-secondary">
                    {intent === 'record' ? 'Your reflection' : 'Reflection to remove'}
                  </dt>
                  <dd className="whitespace-pre-wrap text-foreground" data-testid="study-review-reflection">{reviewReflection}</dd>
                  <dt className="font-medium text-foreground-secondary">Assessment</dt>
                  <dd className="text-foreground">Self-reported · not assessed</dd>
                </>
              ) : (
                <>
                  <dt className="font-medium text-foreground-secondary">Durable result</dt>
                  <dd className="text-foreground" data-testid="study-review-result">
                    {intent === 'start'
                      ? `${statusLabel(operation.priorStatus)} → In progress`
                      : intent === 'pause'
                        ? 'In progress → Paused'
                        : 'Current activity paused · selected activity started'}
                  </dd>
                </>
              )}
            </dl>
            <div className="mt-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-foreground-tertiary">Exact proposed changes</p>
              <ul className="mt-2 space-y-1.5 text-sm text-foreground" data-testid="study-human-readable-changes">
                {intent === 'record' ? (
                  <>
                    <li>Change “{reviewActivity}” from {priorStatus} to completed.</li>
                    <li>Add the exact reflection above as self-reported evidence; it will not be labelled verified.</li>
                    <li>Update learning progress from {study.goalProgressPercent}% to {progressAfterRecord}%.</li>
                  </>
                ) : intent === 'undo' ? (
                  <>
                    <li>Change “{reviewActivity}” from completed to {restoredStatus}.</li>
                    <li>Remove the exact self-reported reflection shown above.</li>
                    <li>Restore learning progress from {study.goalProgressPercent}% to {progressAfterUndo}% and restore the exact prior plan digest.</li>
                    <li>Keep all browser-local drafts unchanged.</li>
                  </>
                ) : intent === 'start' ? (
                  <li>Change “{reviewActivity}” from {sentenceStatus(operation.priorStatus)} to in progress.</li>
                ) : intent === 'pause' ? (
                  <li>Change “{reviewActivity}” from in progress to paused.</li>
                ) : (
                  <>
                    <li>Pause “{String(operation.fromActivityTitle)}”.</li>
                    <li>Start “{String(operation.toActivityTitle)}” from {sentenceStatus(operation.toPriorStatus)}.</li>
                    <li>Apply both changes atomically, leaving exactly one activity in progress.</li>
                  </>
                )}
              </ul>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap items-center justify-end gap-2">
            <Button
              variant="ghost"
              onClick={() => {
                setRun(null)
                setMode(intent === 'record' ? 'drafting' : 'ready')
              }}
              disabled={busy}
            >
              <CornerUpLeft aria-hidden="true" />
              Go back
            </Button>
            <Button onClick={() => void approveAndApply()} disabled={busy} data-testid="study-approve-apply">
              <Check aria-hidden="true" />
              {busy
                ? 'Applying…'
                : intent === 'record'
                  ? 'Approve and apply'
                  : intent === 'undo'
                    ? 'Approve Undo'
                    : `Approve ${intent === 'redirect' ? 'Redirect' : intent === 'start' ? 'Start' : 'Pause'}`}
            </Button>
          </div>
        </div>
      ) : null}

      {mode === 'applied' ? (
        <div className="mt-5 animate-in fade-in-0 slide-in-from-bottom-1 duration-med motion-reduce:animate-none" data-testid="study-applied">
          <p className="flex items-center gap-2 text-sm font-semibold text-status-success">
            <Check className="size-4" aria-hidden="true" />
            {appliedTitle}
          </p>
          <p className="mt-1 text-sm text-foreground-secondary">
            {isControlIntent(intent)
              ? 'StatePort received a validated closure receipt and re-read the durable instance state.'
              : 'StatePort re-read the instance after apply. A saved reflection remains unassessed unless a separate assessment verifies it.'}
          </p>
          {appliedReceiptId ? (
            <p className="mt-1 break-all font-mono text-xs text-foreground-tertiary" data-testid="study-control-receipt">
              Receipt {appliedReceiptId}
            </p>
          ) : null}
          <div className="mt-3">
            <Button
              variant="ghost"
              onClick={() => {
                setRun(null)
                setAppliedReceiptId(null)
                setMode('ready')
                requestAnimationFrame(() => primaryControlRef.current?.focus())
              }}
            >
              Continue
            </Button>
          </div>
        </div>
      ) : null}

      <Disclosure title="Technical details" className="mt-5">
        <dl className="grid gap-x-4 gap-y-1 text-xs text-foreground-secondary sm:grid-cols-[auto_1fr]" data-testid="study-journey-details">
          <dt>Current plan digest</dt><dd className="font-mono break-all">{study.planDigest}</dd>
          {operation ? <><dt>Before digest</dt><dd className="font-mono break-all" data-testid="study-before-plan-digest">{String(proposedBeforeDigest)}</dd></> : null}
          {operation ? <><dt>After digest</dt><dd className="font-mono break-all" data-testid="study-after-plan-digest">{String(proposedAfterDigest)}</dd></> : null}
          <dt>State source</dt><dd>Instance-owned state/LEARNING.yaml</dd>
          <dt>Execution</dt><dd>Runs locally; exact proposal approval required. Network isolation is not yet observed under an enforced boundary, so no network-disabled claim is made.</dd>
          {details ? <><dt>Run</dt><dd className="font-mono break-all">{details.runId}</dd></> : null}
          {details?.proposalDigest ? <><dt>Proposal digest</dt><dd className="font-mono break-all">{details.proposalDigest}</dd></> : null}
          {appliedReceiptId ? <><dt>Closure receipt</dt><dd className="font-mono break-all">{appliedReceiptId}</dd></> : null}
          {details?.engineId ? <><dt>Engine</dt><dd>{details.engineId} · public-safe fixture only</dd></> : null}
        </dl>
      </Disclosure>
    </section>
  )
}
