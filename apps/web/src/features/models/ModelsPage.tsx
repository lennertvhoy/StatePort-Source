/**
 * Settings → Models (`#/settings/models`): the keep-up loop, level 1
 * (ADR-0007 §3, docs/design/keep-up-loop.md "UI").
 *
 * Shows the free-model consent, the current route per action class, a pending
 * route proposal, "Keep up automatically", the observed catalogue with
 * practice-suite results and Evaluate, and the receipt history. Every control
 * performs its effect through `/v1/models*` and the page then re-reads the
 * service; nothing here is a local guess. Scores come from StatePort's
 * practice tasks, never from the owner's work.
 */
import { ChevronLeft, FlaskConical, History, Pin, PinOff, RefreshCw } from 'lucide-react'
import { useId, useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'

import {
  AGENT_ACTION_CLASS,
  LEASE_DAYS,
  actionClassLabel,
  ageLabel,
  catalogueScore,
  destinationLabel,
  destinationOf,
  freeModelsConsented,
  getModelsClient,
  proposalSentence,
  routeFor,
  scoreLabel,
  type ModelsView,
} from '@/client/modelsClient'
import { ConfirmDialog, Disclosure, ErrorState, InlineNotice, SkeletonRows, StatusBadge, TimeAgo } from '@/components'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'

import { ConsentCard } from './ConsentCard'
import { acceptFreeModelTerms } from './consent'
import { useModelsView, type ModelsViewState } from './useModelsView'

const MAX_HISTORY = 20

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function Section({ title, description, children, testId }: { title: string; description?: string; children: ReactNode; testId?: string }) {
  const id = useId()
  return (
    <section aria-labelledby={id} className="flex flex-col gap-2" data-testid={testId}>
      <div>
        <h2 id={id} className="text-base font-semibold text-foreground">{title}</h2>
        {description ? <p className="mt-0.5 text-xs text-foreground-secondary">{description}</p> : null}
      </div>
      {children}
    </section>
  )
}

function StatusBanner({ view }: { view: ModelsView }) {
  const { status } = view
  if (status.state === 'ready') {
    return (
      <div data-testid="models-status">
        <InlineNotice tone="informational" title="A model route is ready">
          {status.detail}
        </InlineNotice>
      </div>
    )
  }
  if (status.state === 'harness_unavailable') {
    return (
      <div data-testid="models-status">
        <InlineNotice tone="blocked" title="The model program is not available on this machine">
          {status.detail} Agent actions stay off until it is available.
        </InlineNotice>
      </div>
    )
  }
  if (status.state === 'not_consented') {
    return (
      <div data-testid="models-status">
        <InlineNotice tone="attention" title="Free models are off">
          {status.detail}
        </InlineNotice>
      </div>
    )
  }
  return (
    <div data-testid="models-status">
      <InlineNotice tone="attention" title="No model is chosen yet">
        {status.detail || 'Accept the free-model terms, evaluate a model, and choose it below.'}
      </InlineNotice>
    </div>
  )
}

function FreeModelsSection({
  view,
  models,
  lastAction,
  setLastAction,
}: {
  view: ModelsView
  models: ModelsViewState
  lastAction: string | null
  setLastAction: (action: string) => void
}) {
  const [deferred, setDeferred] = useState(false)
  const [confirmWithdraw, setConfirmWithdraw] = useState(false)
  const consent = view.consent
  if (consent.state === 'granted') {
    return (
      <div className="flex flex-col gap-2 rounded-md border border-border bg-surface p-4" data-testid="consent-granted">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge state="success" label="Free models allowed" />
          {consent.grantedAt ? (
            <span className="text-xs text-foreground-tertiary">since <TimeAgo date={consent.grantedAt} className="inline" /></span>
          ) : null}
          <Button size="sm" variant="outline" className="ml-auto" disabled={models.busy} onClick={() => setConfirmWithdraw(true)} data-testid="consent-withdraw">
            Withdraw consent
          </Button>
        </div>
        <p className="text-xs text-foreground-secondary">
          Agent actions and practice tasks may send a copy of an application's files to the free-model service.
        </p>
        <Disclosure title="Terms you accepted">
          <blockquote className="whitespace-pre-wrap break-words px-2 pb-2 text-sm text-foreground-secondary">{consent.terms.text}</blockquote>
        </Disclosure>
        <ConfirmDialog
          open={confirmWithdraw}
          onOpenChange={setConfirmWithdraw}
          title="Withdraw free-model consent?"
          effect="StatePort stops sending anything to the free-model service. Routes that use free models become “none” until you accept again."
          reversibility="You can accept the terms again at any time."
          confirmLabel="Withdraw consent"
          onConfirm={async () => {
            setLastAction('withdraw')
            await models.mutate(() => getModelsClient().withdrawConsent(consent.destination))
          }}
        />
      </div>
    )
  }
  if (consent.state === 'stale') {
    return (
      <div data-testid="consent-stale">
        <InlineNotice tone="attention" title="The free-model terms changed">
          The terms the provider publishes now differ from the ones you accepted. Read them again below and accept them to
          keep using free models.
        </InlineNotice>
      </div>
    )
  }
  if (deferred) {
    return (
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-surface px-4 py-3 text-sm text-foreground-secondary" data-testid="consent-deferred">
        Free models are off. Nothing is sent to the free-model service.
        <Button size="sm" variant="outline" onClick={() => setDeferred(false)}>Review the terms</Button>
      </div>
    )
  }
  return (
    <ConsentCard
      consent={consent}
      busy={models.busy}
      error={lastAction === 'consent' ? models.mutationError : null}
      onAccept={() => {
        setLastAction('consent')
        void models.mutate(() => acceptFreeModelTerms(consent))
      }}
      onDecline={() => setDeferred(true)}
    />
  )
}

function RoutesSection({ view, models, setLastAction }: { view: ModelsView; models: ModelsViewState; setLastAction: (action: string) => void }) {
  if (view.routes.length === 0) {
    return (
      <p className="rounded-md border border-border bg-surface px-4 py-3 text-sm text-foreground-secondary" data-testid="routes-empty">
        No model is chosen for agent actions, so they stay off. Accept free models and evaluate one below.
      </p>
    )
  }
  return (
    <ul className="divide-y divide-border rounded-md border border-border bg-surface" data-testid="routes">
      {view.routes.map((route) => {
        const destination = route.model ? destinationLabel(destinationOf(route.model)) : null
        return (
          <li key={route.actionClass} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3" data-testid={`route-${route.actionClass}`}>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-foreground">{actionClassLabel(route.actionClass)}</p>
              {route.model ? (
                <p className="mt-0.5 text-xs text-foreground-secondary">
                  <span className="font-mono text-foreground" data-testid={`route-model-${route.actionClass}`}>{route.model}</span>
                  {destination ? ` · ${destination}` : ''}
                </p>
              ) : (
                <p className="mt-0.5 text-xs text-foreground-secondary" data-testid={`route-model-${route.actionClass}`}>
                  None{route.refusal ? ` — ${route.refusal.message}` : '. Actions of this kind cannot run.'}
                </p>
              )}
            </div>
            <dl className="grid grid-cols-[auto_auto] gap-x-2 text-xs">
              <dt className="text-foreground-tertiary">Last score</dt>
              <dd className="tnum text-foreground" data-testid={`route-score-${route.actionClass}`}>{scoreLabel(route.score)}</dd>
              <dt className="text-foreground-tertiary">Measured</dt>
              <dd className="text-foreground" data-testid={`route-age-${route.actionClass}`}>
                {route.score?.finishedAt ? <TimeAgo date={route.score.finishedAt} /> : 'Never'}
              </dd>
              <dt className="text-foreground-tertiary">Chosen</dt>
              <dd className="text-foreground" data-testid={`route-chosen-${route.actionClass}`}>
                {ageLabel(route.ageSeconds) ?? (route.setAt ? <TimeAgo date={route.setAt} /> : 'Never')}
              </dd>
            </dl>
            {route.pinned ? <StatusBadge state="informational" label="Pinned" icon={Pin} /> : null}
            {route.model ? (
              <Button
                size="sm"
                variant="outline"
                disabled={models.busy}
                data-testid={`route-pin-${route.actionClass}`}
                onClick={() => {
                  setLastAction('route')
                  void models.mutate(() => getModelsClient().setRoute({ actionClass: route.actionClass, model: route.model, pin: !route.pinned }))
                }}
              >
                {route.pinned ? <PinOff aria-hidden="true" /> : <Pin aria-hidden="true" />}
                {route.pinned ? 'Unpin' : 'Pin'}
              </Button>
            ) : null}
          </li>
        )
      })}
    </ul>
  )
}

function ProposalSection({ view, models, setLastAction }: { view: ModelsView; models: ModelsViewState; setLastAction: (action: string) => void }) {
  // Every pending proposal, one per kind of action: after the first evaluation there is one for agent actions AND one
  // for chat, and showing only the newest hid the second until the first was decided.
  const listed = view.proposals.filter((item) => item.status === 'pending')
  const pending = listed.length ? listed : view.proposal ? [view.proposal] : []
  if (!pending.length) return null
  return (
    <div className="flex flex-col gap-2">
      {pending.map((proposal) => {
        const decide = (decision: 'switch' | 'dismiss') => {
          setLastAction('proposal')
          void models.mutate(() => getModelsClient().decideProposal(proposal.id, decision))
        }
        return (
          <div key={proposal.id} className="flex flex-col gap-2 rounded-md border border-status-attention-border bg-status-attention-bg p-4" data-testid={`route-proposal-${proposal.actionClass}`}>
            <p className="text-sm font-semibold text-foreground" data-testid={`route-proposal-sentence-${proposal.actionClass}`}>{proposalSentence(proposal)}</p>
            <p className="text-xs text-foreground-secondary">
              For {actionClassLabel(proposal.actionClass).toLowerCase()}
              {proposal.from ? <>, replacing <span className="font-mono">{proposal.from}</span></> : null}.
              {proposal.reason ? ` ${proposal.reason}` : ''} Scores are from StatePort's practice tasks.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" disabled={models.busy} onClick={() => decide('switch')} aria-label={`Switch ${actionClassLabel(proposal.actionClass).toLowerCase()}`} data-testid={`route-proposal-switch-${proposal.actionClass}`}>Switch</Button>
              <Button size="sm" variant="outline" disabled={models.busy} onClick={() => decide('dismiss')} aria-label={`Dismiss for ${actionClassLabel(proposal.actionClass).toLowerCase()}`} data-testid={`route-proposal-dismiss-${proposal.actionClass}`}>Dismiss</Button>
            </div>
          </div>
        )
      })}
    </div>
  )
}

function LeaseSection({ view, models, setLastAction }: { view: ModelsView; models: ModelsViewState; setLastAction: (action: string) => void }) {
  const id = useId()
  const lease = view.lease
  const days = lease.defaultDays ?? LEASE_DAYS
  return (
    <div className="flex flex-col gap-2 rounded-md border border-border bg-surface p-4" data-testid="lease">
      <div className="flex items-center gap-3">
        <Switch
          id={id}
          checked={lease.enabled}
          disabled={models.busy}
          onCheckedChange={(enabled) => {
            setLastAction('lease')
            void models.mutate(() => getModelsClient().setLease({ enabled, days }))
          }}
          data-testid="lease-switch"
        />
        <label htmlFor={id} className="text-sm font-medium text-foreground">Keep up automatically</label>
        <span className="ml-auto text-xs text-foreground-secondary" data-testid="lease-state">
          {lease.enabled
            ? lease.expiresAt ? <>On until <TimeAgo date={lease.expiresAt} className="inline" /></> : 'On'
            : lease.state === 'expired' ? 'Off (the last grant expired)'
              : 'Off'}
        </span>
      </div>
      <p className="text-xs text-foreground-secondary">
        Once a day StatePort checks the free model list and, when a model clearly beats the current one on the practice
        tasks, switches to it and records why. It never changes a pinned route and never moves you to a different
        provider without asking. Granted for {days} days at a time.
      </p>
      {lease.enabled && !freeModelsConsented(view) ? (
        <p className="text-xs text-foreground-tertiary">Free models are evaluated only after you accept their terms.</p>
      ) : null}
    </div>
  )
}

/** A probe's cause in words; the codes come from the service (model_routes.py failure classes). */
const PROBE_CAUSE_LABEL: Record<string, string> = {
  free_usage_limit: 'the free usage limit is reached',
  rate_limited: 'too many requests just now',
  model_unavailable: 'not offered right now',
  upstream_error: 'the provider had an error',
  timeout: 'no answer in time',
  empty_reply: 'an empty answer',
  harness_misconfigured: 'StatePort’s request was rejected',
  sandbox_refused: 'the sandbox did not start',
}

const RUN_ERROR_TEXT: Record<string, string> = {
  free_usage_limit:
    'OpenCode’s free models refused every request: the free usage limit for this computer is reached. Nothing was learned about the models. Try again later; your work and your current choices stay as they are.',
}

function EvaluationProgress({ models }: { models: ModelsViewState }) {
  const run = models.suiteRun
  if (models.suiteRunError) {
    return (
      <InlineNotice tone="danger" title="The evaluation could not be followed">
        {message(models.suiteRunError)} Refresh to see its recorded result.
      </InlineNotice>
    )
  }
  if (!run) return null
  const done = run.progress.completedTasks
  const total = run.progress.totalTasks
  const percent = total > 0 ? Math.round((done / total) * 100) : 0
  const settled = run.state === 'completed' || run.state === 'failed' || run.state === 'interrupted'
  return (
    <div className="flex flex-col gap-2 rounded-md border border-border bg-surface p-4" data-testid="evaluation-progress" data-status={run.state}>
      <p className="text-sm font-medium text-foreground">
        {settled
          ? run.state === 'completed' ? 'Evaluation finished' : run.state === 'failed' ? 'Evaluation failed' : 'Evaluation interrupted'
          : `Evaluating ${run.requestedModels.join(', ') || 'models'}`}
      </p>
      <div
        role="progressbar"
        aria-label="Practice tasks done"
        aria-valuemin={0}
        aria-valuemax={total || undefined}
        aria-valuenow={total ? done : undefined}
        className="h-1 overflow-hidden rounded-full bg-active"
      >
        <div
          className={settled ? 'h-full bg-status-success' : total ? 'h-full bg-accent transition-[width]' : 'h-full w-1/3 animate-pulse bg-accent'}
          style={total ? { width: `${percent}%` } : undefined}
        />
      </div>
      <p className="tnum text-xs text-foreground-secondary">
        {total ? `${done} of ${total} practice tasks done` : 'Waiting for the first practice task'}
      </p>
      {run.models.length > 0 ? (
        <ul className="text-xs text-foreground-secondary">
          {run.models.map((model) => (
            <li key={model.model}>
              <span className="font-mono text-foreground">{model.model}</span>: {scoreLabel(model.totals)}
              {model.available ? '' : ` (did not answer: ${PROBE_CAUSE_LABEL[model.probeCause ?? ''] ?? 'no answer'})`}
            </li>
          ))}
        </ul>
      ) : null}
      {run.error ? <p className="text-xs text-status-danger">{RUN_ERROR_TEXT[run.error] ?? run.error}</p> : null}
    </div>
  )
}

function CatalogueSection({ view, models, setLastAction }: { view: ModelsView; models: ModelsViewState; setLastAction: (action: string) => void }) {
  const consented = freeModelsConsented(view)
  const route = routeFor(view, AGENT_ACTION_CLASS)
  const evaluating = models.suiteRun !== null && !['completed', 'failed', 'interrupted'].includes(models.suiteRun.state)
  const catalogue = view.catalogue
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2 text-xs text-foreground-secondary">
        <span>
          {catalogue.observedAt ? <>Model list checked <TimeAgo date={catalogue.observedAt} className="inline" /></> : 'The model list has not been checked yet'}
          {catalogue.harness?.version ? ` · OpenCode ${catalogue.harness.version}` : ''}
        </span>
        <Button
          size="sm"
          variant="outline"
          className="ml-auto"
          disabled={models.busy}
          onClick={() => {
            setLastAction('observe')
            void models.mutate(() => getModelsClient().observe())
          }}
          data-testid="catalogue-refresh"
        >
          <RefreshCw aria-hidden="true" />
          Check the model list
        </Button>
      </div>
      {catalogue.lastError ? (
        <InlineNotice tone="attention" title="The last check of the model list failed">
          {catalogue.lastError.code}
        </InlineNotice>
      ) : null}
      {catalogue.models.length === 0 ? (
        <p className="rounded-md border border-border bg-surface px-4 py-3 text-sm text-foreground-secondary" data-testid="catalogue-empty">
          No models have been observed yet. Check the model list to look for free models.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-md border border-border bg-surface">
          <table className="w-full min-w-[560px] text-left text-xs" data-testid="catalogue">
            <thead className="border-b border-border text-foreground-tertiary">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">Model</th>
                <th scope="col" className="px-3 py-2 font-medium">Type</th>
                <th scope="col" className="px-3 py-2 font-medium">Last seen</th>
                <th scope="col" className="px-3 py-2 font-medium">Practice score</th>
                <th scope="col" className="px-3 py-2 font-medium"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {catalogue.models.map((model) => {
                const blocked = model.free && !consented
                const inUse = route?.model === model.id
                return (
                  <tr key={model.id} data-testid={`catalogue-row-${model.id}`}>
                    <td className="break-all px-3 py-2 font-mono text-foreground">{model.id}</td>
                    <td className="px-3 py-2 text-foreground-secondary">{model.free ? 'Free, no account' : 'Your account'}</td>
                    <td className="px-3 py-2 text-foreground-secondary">
                      {!model.listedNow ? 'Gone from the latest list' : model.lastSeenAt ? <TimeAgo date={model.lastSeenAt} /> : '—'}
                    </td>
                    <td className="tnum px-3 py-2 text-foreground" data-testid={`catalogue-score-${model.id}`}>
                      {scoreLabel(catalogueScore(model.latestResult))}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex justify-end gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={models.busy || evaluating || blocked}
                          title={blocked ? 'Accept the free-model terms first: practice tasks are sent to the provider.' : undefined}
                          onClick={() => {
                            setLastAction('evaluate')
                            void models.evaluate([model.id])
                          }}
                          data-testid={`evaluate-${model.id}`}
                        >
                          <FlaskConical aria-hidden="true" />
                          Evaluate
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={models.busy || blocked || inUse || !model.usable}
                          title={blocked ? 'Accept the free-model terms first.' : undefined}
                          onClick={() => {
                            setLastAction('route')
                            void models.mutate(() => getModelsClient().setRoute({ actionClass: AGENT_ACTION_CLASS, model: model.id, pin: route?.pinned ?? false }))
                          }}
                          data-testid={`use-${model.id}`}
                        >
                          {inUse ? 'In use' : 'Use'}
                        </Button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      {!consented && catalogue.models.some((model) => model.free) ? (
        <p className="text-xs text-foreground-tertiary">Free models can be evaluated or used after you accept their terms above.</p>
      ) : null}
    </div>
  )
}

function HistorySection({ view }: { view: ModelsView }) {
  const [showAll, setShowAll] = useState(false)
  const receipts = useMemo(() => [...view.receipts].sort((a, b) => b.at.localeCompare(a.at)), [view.receipts])
  if (receipts.length === 0) {
    return <p className="text-sm text-foreground-secondary" data-testid="history-empty">Nothing has been recorded yet.</p>
  }
  const visible = showAll ? receipts : receipts.slice(0, MAX_HISTORY)
  return (
    <div className="flex flex-col gap-1">
      <ul className="divide-y divide-border rounded-md border border-border bg-surface" data-testid="history">
        {visible.map((receipt) => (
          <li key={receipt.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-4 py-2 text-xs">
            <TimeAgo date={receipt.at} className="shrink-0" />
            <span className="min-w-0 flex-1 text-foreground">{receipt.summary}</span>
            {receipt.by ? <span className="text-foreground-tertiary">by {receipt.by}</span> : null}
          </li>
        ))}
      </ul>
      {receipts.length > MAX_HISTORY && !showAll ? (
        <button type="button" onClick={() => setShowAll(true)} className="self-start text-xs font-medium text-accent hover:underline">
          Show all {receipts.length}
        </button>
      ) : null}
    </div>
  )
}

export default function ModelsPage() {
  const models = useModelsView()
  const [lastAction, setLastAction] = useState<string | null>(null)
  const view = models.view

  return (
    <div className="h-full overflow-y-auto bg-app" data-testid="models-page">
      <div className="mx-auto flex w-full max-w-[880px] flex-col gap-6 p-4 md:p-6">
        <header className="flex flex-col gap-2">
          <Link to="/settings" className="inline-flex min-h-8 items-center gap-1 self-start text-xs font-medium text-accent hover:underline">
            <ChevronLeft className="size-3.5" aria-hidden="true" />
            Settings
          </Link>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <h1 className="text-xl font-semibold text-foreground">Models</h1>
              <p className="mt-1 max-w-2xl text-sm text-foreground-secondary">
                StatePort uses an AI model only when you run an agent action or chat. Agent actions use OpenCode’s free
                models (no account) in this release; chat can also use{' '}
                <Link to="/settings/provider" className="font-medium text-accent hover:underline">your own OpenCode sign-in or API key</Link>.
                Scores below come from StatePort's own practice tasks, not from your applications or your work.
              </p>
            </div>
            <Button size="sm" variant="ghost" onClick={models.refresh} disabled={models.busy} aria-label="Refresh models">
              <RefreshCw aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </header>

        {models.status === 'loading' ? <SkeletonRows rows={6} /> : null}
        {models.status === 'error' ? (
          <ErrorState
            title="Model routes could not be loaded"
            error={models.loadError}
            preservedNote="No model is in use until this loads, so agent actions stay off."
            onRetry={models.refresh}
          />
        ) : null}

        {view ? (
          <>
            {models.loadError ? (
              <InlineNotice tone="attention" title="Showing the last known state">
                The latest refresh failed: {message(models.loadError)}
              </InlineNotice>
            ) : null}
            {models.mutationError && lastAction !== 'consent' ? (
              <InlineNotice
                tone="danger"
                title="The service did not make that change"
                action={<Button size="sm" variant="ghost" onClick={models.clearMutationError}>Dismiss</Button>}
              >
                {message(models.mutationError)} The page shows the state the service recorded.
              </InlineNotice>
            ) : null}

            <StatusBanner view={view} />

            <Section title="Free models" description="No account needed. Off until you accept the provider's terms." testId="free-models-section">
              <FreeModelsSection view={view} models={models} lastAction={lastAction} setLastAction={setLastAction} />
            </Section>

            <Section title="Current route" description="Which model runs each kind of agent action." testId="routes-section">
              <ProposalSection view={view} models={models} setLastAction={setLastAction} />
              <RoutesSection view={view} models={models} setLastAction={setLastAction} />
            </Section>

            <Section title="Automatic updates" testId="lease-section">
              <LeaseSection view={view} models={models} setLastAction={setLastAction} />
            </Section>

            <Section
              title="Available models"
              description="Evaluate runs StatePort's practice tasks with a model, one at a time on this machine. Your own work is never used."
              testId="catalogue-section"
            >
              <EvaluationProgress models={models} />
              <CatalogueSection view={view} models={models} setLastAction={setLastAction} />
            </Section>

            <Section title="History" description="Consent, model list changes, evaluations and route changes, as recorded." testId="history-section">
              <div className="flex items-center gap-1 text-xs text-foreground-tertiary">
                <History className="size-3.5" aria-hidden="true" />
                Newest first
              </div>
              <HistorySection view={view} />
            </Section>
          </>
        ) : null}
      </div>
    </div>
  )
}
