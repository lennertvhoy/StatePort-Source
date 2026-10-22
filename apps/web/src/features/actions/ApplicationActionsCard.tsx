/**
 * Application actions (ADR-0007 §1) on the app overview: the instance's
 * `check` and `agent` actions with kind badges.
 *
 * - Run on a check: the template's own check on a read-only copy; its verdict
 *   (passed / not yet / invalid) with summary and findings.
 * - Run on an agent action: needs a ready model route (else it explains and
 *   links to Settings → Models). The owner's click is the run approval; the
 *   card states what will be sent and to which model route, then follows the
 *   run and opens the proposal for review.
 * - Actions with declared inputs open a form generated from the schema; the
 *   entered values are shown in the confirmation before anything runs.
 */
import { Bot, ListChecks, Play, RefreshCw, Sparkles } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import type { ApplicationInstance, RunRecord } from '@/client'
import {
  AGENT_ACTION_CLASS,
  agentRouteReadiness,
  destinationLabel,
  type AgentRouteReadiness,
} from '@/client/modelsClient'
import { InlineNotice, SectionHeader, SkeletonRows, Spinner, StatusBadge, TimeAgo } from '@/components'
import { Button } from '@/components/ui/button'
import { VerdictDetail } from '@/features/proposals/EvaluatorVerdict'
import { ProposalReview } from '@/features/proposals/ProposalReview'
import { cn } from '@/lib/utils'

import { ActionInputForm } from './ActionInputForm'
import {
  actionInputFields,
  agentOutcomeOf,
  checkOutcomeOf,
  inputSummary,
  isSetupAction,
  phaseLabel,
  type ActionInputValues,
  type KindedAction,
} from './actionsModel'
import { useApplicationActions, type ActionActivity, type ModelsState } from './useApplicationActions'

type Actions = ReturnType<typeof useApplicationActions>

function useElapsedSeconds(startedAt: number | null): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (startedAt === null) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [startedAt])
  return startedAt === null ? 0 : Math.max(0, Math.round((now - startedAt) / 1000))
}

function KindBadge({ kind }: { kind: KindedAction['kind'] }) {
  return kind === 'check'
    ? <StatusBadge state="informational" label="Check" icon={ListChecks} />
    : <StatusBadge state="neutral" label="Agent" icon={Bot} />
}

function readinessFor(action: KindedAction, models: ModelsState): AgentRouteReadiness | null {
  if (action.kind !== 'agent' || !models.view) return null
  return agentRouteReadiness(models.view, action.actionClass ?? AGENT_ACTION_CLASS)
}

function RouteLine({ action, models }: { action: KindedAction; models: ModelsState }) {
  if (action.kind === 'check') {
    return (
      <p className="text-xs text-foreground-tertiary">
        Runs this application's own check on a read-only copy, on this machine. Nothing is changed or sent.
      </p>
    )
  }
  if (models.status === 'loading' || models.status === 'idle') {
    return <Spinner size={12} label="Checking the model route…" />
  }
  if (models.status === 'error' || !models.view) {
    return (
      <InlineNotice
        tone="blocked"
        title="Agent actions are off"
        action={<Link to="/settings/models" className="text-xs font-medium text-accent hover:underline">Settings → Models</Link>}
      >
        StatePort could not read its model routes, so it will not send anything to a model.
      </InlineNotice>
    )
  }
  const readiness = agentRouteReadiness(models.view, action.actionClass ?? AGENT_ACTION_CLASS)
  if (!readiness.ready) {
    const needsConsent = readiness.code === 'not_consented' || readiness.code === 'route_not_consented'
    return (
      <InlineNotice
        tone="attention"
        title={needsConsent ? 'Free models need your consent' : 'No model is chosen yet'}
        action={<Link to="/settings/models" className="text-xs font-medium text-accent hover:underline" data-testid={`action-models-link-${action.id}`}>Open Settings → Models</Link>}
      >
        {readiness.reason}
      </InlineNotice>
    )
  }
  return (
    <p className="text-xs text-foreground-secondary" data-testid={`action-route-${action.id}`}>
      Sends a copy of this application's files and the action's instructions to{' '}
      <span className="font-mono text-foreground">{readiness.model}</span> ({destinationLabel(readiness.destination)}). You
      review the result before anything changes.
    </p>
  )
}

function Progress({ action, activity }: { action: KindedAction; activity: ActionActivity }) {
  const elapsed = useElapsedSeconds(activity.startedAt)
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs text-foreground-secondary" role="status" data-testid={`action-progress-${action.id}`}>
      <Spinner size={12} />
      <span>{phaseLabel(activity.phase, action.kind)}</span>
      <span className="tnum text-foreground-tertiary">
        {elapsed} s{activity.phase === 'running' && action.timeoutSeconds ? ` (limit ${action.timeoutSeconds} s)` : ''}
      </span>
      <div className="h-0.5 w-full overflow-hidden rounded-full bg-active" aria-hidden="true">
        <div className="h-full w-1/3 animate-pulse rounded-full bg-accent" />
      </div>
    </div>
  )
}

function Outcome({
  action,
  run,
  fromThisSession,
  busy,
  canOpenRuns,
  instanceId,
  onApply,
  onReject,
}: {
  action: KindedAction
  run: RunRecord
  fromThisSession: boolean
  busy: boolean
  canOpenRuns: boolean
  instanceId: string
  onApply: () => Promise<unknown>
  onReject: () => Promise<unknown>
}) {
  const [expanded, setExpanded] = useState(fromThisSession || run.status === 'state_change_proposed')
  if (action.kind === 'check') {
    const outcome = checkOutcomeOf(run)
    if (outcome.kind === 'pending') return null
    if (outcome.kind === 'failed') {
      return (
        <InlineNotice tone="danger" title="The check did not finish">
          {outcome.reason}
        </InlineNotice>
      )
    }
    return (
      <div className="flex flex-col gap-1" data-testid={`action-verdict-${action.id}`}>
        <VerdictDetail result={outcome.kind === 'verdict' ? outcome.result : null} title="Result" />
        <span className="text-xs text-foreground-tertiary">Checked <TimeAgo date={outcome.at} className="inline" /></span>
      </div>
    )
  }
  const outcome = agentOutcomeOf(run)
  if (outcome.kind === 'pending') return null
  if (outcome.kind === 'failed') {
    return (
      <InlineNotice tone="danger" title="The agent run did not finish">
        {outcome.reason}
      </InlineNotice>
    )
  }
  if (outcome.kind === 'no_change') {
    return (
      <div className="flex flex-col gap-1 text-xs text-foreground-secondary" data-testid={`action-no-change-${action.id}`}>
        <p>The agent finished without proposing a change.</p>
        {outcome.summary ? <p className="whitespace-pre-wrap text-foreground">{outcome.summary}</p> : null}
      </div>
    )
  }
  if (outcome.kind === 'other_proposal') {
    return (
      <p className="text-xs text-foreground-secondary">
        This action produced a typed proposal.{' '}
        {canOpenRuns ? <Link to={`/app/${instanceId}/runs`} className="font-medium text-accent hover:underline">Review it on the Runs page</Link> : 'Review it on the Runs page.'}
      </p>
    )
  }
  const pending = run.status === 'state_change_proposed' || run.status === 'state_change_approved'
  return (
    <div className="flex flex-col gap-2">
      {!expanded ? (
        <div className="flex flex-wrap items-center gap-2 text-xs text-foreground-secondary">
          <span>
            {pending ? 'A proposal is waiting for your review' : run.status === 'applied' ? 'Last proposal was applied' : 'Last proposal'}
            {' · '}
            <TimeAgo date={run.updatedAt} className="inline" />
          </span>
          <Button size="sm" variant="outline" onClick={() => setExpanded(true)} data-testid={`action-review-${action.id}`}>
            {pending ? 'Review' : 'Show'}
          </Button>
        </div>
      ) : (
        <div className="rounded-sm border border-border p-3">
          <ProposalReview run={run} proposal={outcome.proposal} busy={busy} onApply={onApply} onReject={onReject} />
        </div>
      )}
    </div>
  )
}

function ActionRow({
  action,
  actions,
  highlight,
  readOnly,
  canOpenRuns,
  instanceId,
}: {
  action: KindedAction
  actions: Actions
  highlight: boolean
  readOnly: boolean
  canOpenRuns: boolean
  instanceId: string
}) {
  const fields = actionInputFields(action)
  const [stage, setStage] = useState<'idle' | 'form' | 'confirm'>('idle')
  const [values, setValues] = useState<ActionInputValues | undefined>(undefined)
  const [inputs, setInputs] = useState<Record<string, unknown>>({})
  const readiness = readinessFor(action, actions.models)
  const routeReady = action.kind === 'check' || Boolean(readiness?.ready)
  const activity = actions.activity
  const mine = activity?.actionId === action.id
  const run = actions.latestRuns.get(action.id)
  const error = actions.errors[action.id]
  const disabled = readOnly || activity !== null || !routeReady
  const summary = inputSummary(fields, inputs)

  const start = () => {
    // An agent action always shows a confirmation first: the owner's click is
    // the approval, and the confirmation names the model route and what is
    // sent there. A check runs on this machine and changes nothing, so it
    // needs no second click.
    if (action.kind === 'check') {
      void actions.runAction(action, {})
      return
    }
    if (fields.length > 0) {
      setStage('form')
      return
    }
    setStage('confirm')
  }

  const confirm = () => {
    setStage('idle')
    void actions.runAction(action, inputs)
  }

  return (
    <li
      className={cn('flex flex-col gap-2 px-3 py-3', highlight && 'border-l-2 border-accent bg-accent-soft/20')}
      data-testid={`action-row-${action.id}`}
      data-kind={action.kind}
    >
      <div className="flex flex-wrap items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <KindBadge kind={action.kind} />
            <h3 className="text-sm font-medium text-foreground">{action.title}</h3>
            {highlight ? <StatusBadge state="attention" label="Start here" icon={Sparkles} /> : null}
          </div>
          {action.description ? <p className="mt-1 text-xs text-foreground-secondary">{action.description}</p> : null}
        </div>
        {stage === 'idle' ? (
          <Button size="sm" disabled={disabled} onClick={start} data-testid={`action-run-${action.id}`}>
            <Play aria-hidden="true" />
            {mine ? 'Running…' : 'Run'}
          </Button>
        ) : null}
      </div>

      {!mine ? <RouteLine action={action} models={actions.models} /> : null}

      {stage === 'form' ? (
        <ActionInputForm
          actionId={action.id}
          fields={fields}
          initialValues={values}
          onCancel={() => setStage('idle')}
          onSubmit={(parsed, entered) => {
            setInputs(parsed)
            setValues(entered)
            setStage('confirm')
          }}
        />
      ) : null}

      {stage === 'confirm' ? (
        <div className="flex flex-col gap-2 rounded-sm border border-border bg-surface-2 p-3" data-testid={`action-confirm-${action.id}`}>
          {summary.length > 0 ? (
            <dl className="grid gap-x-3 gap-y-1 text-xs sm:grid-cols-[10rem_1fr]">
              {summary.map((item) => (
                <div key={item.label} className="contents">
                  <dt className="font-medium text-foreground-secondary">{item.label}</dt>
                  <dd className="whitespace-pre-wrap break-words text-foreground">{item.value}</dd>
                </div>
              ))}
            </dl>
          ) : null}
          <p className="text-xs text-foreground-secondary">
            {action.kind === 'agent' && readiness?.ready ? (
              <>
                {summary.length > 0 ? 'These words and a copy of the application go to ' : "A copy of this application's files and the action's instructions go to "}
                <span className="font-mono text-foreground">{readiness.model}</span> ({destinationLabel(readiness.destination)}).
                You review the result before anything changes.
              </>
            ) : (
              'This check runs on this machine. Nothing is sent anywhere and nothing is changed.'
            )}
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" disabled={disabled} onClick={confirm} data-testid={`action-confirm-run-${action.id}`}>
              <Play aria-hidden="true" />
              Run
            </Button>
            {fields.length > 0 ? (
              <Button size="sm" variant="outline" onClick={() => setStage('form')}>Edit</Button>
            ) : null}
            <Button size="sm" variant="ghost" onClick={() => setStage('idle')}>Cancel</Button>
          </div>
        </div>
      ) : null}

      {mine && activity ? <Progress action={action} activity={activity} /> : null}

      {error ? (
        <InlineNotice tone="danger" title="The run did not complete">
          {error}
        </InlineNotice>
      ) : null}

      {run && !mine ? (
        <Outcome
          key={run.id}
          action={action}
          run={run}
          fromThisSession={actions.sessionRunIds.has(run.id)}
          busy={activity !== null || readOnly}
          canOpenRuns={canOpenRuns}
          instanceId={instanceId}
          onApply={() => actions.applyProposal(action.id, run)}
          onReject={() => actions.rejectProposal(action.id, run)}
        />
      ) : null}
    </li>
  )
}

export function ApplicationActionsCard({
  instance,
  readOnly,
  canOpenRuns,
}: {
  instance: ApplicationInstance
  readOnly: boolean
  canOpenRuns: boolean
}) {
  const actions = useApplicationActions(instance.id)
  return (
    <section aria-label="Actions" data-testid="application-actions">
      <SectionHeader
        title="Actions"
        description="Checks look at this application's state. Agent actions ask a model to propose a change for you to review."
        className="mb-2"
        actions={
          <div className="flex items-center gap-1">
            {canOpenRuns ? (
              <Link to={`/app/${instance.id}/runs`} className="text-xs font-medium text-accent hover:underline">All runs</Link>
            ) : null}
            <Button size="sm" variant="ghost" onClick={actions.refresh} aria-label="Refresh actions">
              <RefreshCw aria-hidden="true" />
            </Button>
          </div>
        }
      />
      <div className="rounded-md border border-border bg-surface">
        {actions.status === 'loading' ? (
          <SkeletonRows rows={2} className="p-3" />
        ) : actions.status === 'error' ? (
          <div className="p-3">
            <InlineNotice
              tone="danger"
              title="Actions could not be loaded"
              action={<Button size="sm" variant="outline" onClick={actions.refresh}>Retry</Button>}
            >
              {actions.loadError instanceof Error ? actions.loadError.message : String(actions.loadError)} Nothing was run.
            </InlineNotice>
          </div>
        ) : actions.actions.length === 0 ? (
          <p className="px-3 py-4 text-sm text-foreground-secondary" data-testid="application-actions-empty">
            This application declares no check or agent actions.
            {actions.otherActionCount > 0
              ? canOpenRuns
                ? ' Its other governed actions are on the Runs page.'
                : ' It declares other governed actions that are not run from here.'
              : ''}
          </p>
        ) : (
          <>
            {actions.setupFirst ? (
              <p className="border-b border-border px-3 py-2 text-xs text-foreground-secondary" data-testid="application-actions-setup-hint">
                Start with setup: it records what this application is for, so the other actions have something to work from.
              </p>
            ) : null}
            <ul className="divide-y divide-border">
              {actions.actions.map((action) => (
                <ActionRow
                  key={action.id}
                  action={action}
                  actions={actions}
                  highlight={actions.setupFirst && isSetupAction(action.id)}
                  readOnly={readOnly}
                  canOpenRuns={canOpenRuns}
                  instanceId={instance.id}
                />
              ))}
            </ul>
          </>
        )}
      </div>
    </section>
  )
}
