/**
 * Governed Runs — app-level execution cockpit for every application with a
 * usable goal_execution capability. It intentionally does not depend on the
 * Workbench capability, so domain applications such as StudyState retain
 * their governed actions without inheriting development tools.
 */
import {
  CirclePlay,
  History,
  Plus,
  RefreshCw,
  ShieldX,
} from 'lucide-react'
import { useMemo, useState } from 'react'

import type { GovernedAction, RunRecord } from '@/client'
import {
  EmptyState,
  ErrorState,
  InlineNotice,
  OperationStateLabel,
  SkeletonRows,
  TimeAgo,
} from '@/components'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { useCurrentInstance } from '@/shell/currentInstance'
import { useRegisterCommands, type ShellCommand } from '@/shell/commands'

import { RunDetailDrawer } from './RunDetailDrawer'
import { RunPreparation } from './RunPreparation'
import { receiptBasePathFor, runStatusLabel } from './runsModel'
import { RunWorkspace } from './RunWorkspace'
import { useRuns } from './useRuns'

function RunRail({
  actions,
  history,
  selectedActionId,
  activeRunId,
  onSelectAction,
  onSelectRun,
}: {
  actions: GovernedAction[]
  history: RunRecord[]
  selectedActionId?: string
  activeRunId?: string
  onSelectAction: (action: GovernedAction) => void
  onSelectRun: (run: RunRecord) => void
}) {
  return (
    <aside
      className="flex max-h-72 shrink-0 flex-col overflow-y-auto border-b border-border bg-surface lg:max-h-none lg:w-72 lg:border-b-0 lg:border-r"
      aria-label="Actions and run history"
    >
      <section className="py-2" aria-labelledby="declared-actions-heading">
        <h2
          id="declared-actions-heading"
          className="flex items-center gap-1.5 px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-foreground-tertiary"
        >
          <CirclePlay className="size-3.5" aria-hidden="true" />
          Declared actions
        </h2>
        {actions.length === 0 ? (
          <p className="px-3 py-2 text-xs text-foreground-tertiary" data-testid="runs-actions-empty">
            No governed actions are declared.
          </p>
        ) : (
          <ul className="flex flex-col" data-testid="runs-actions">
            {actions.map((action) => {
              const selected = action.id === selectedActionId && !activeRunId
              return (
                <li key={action.id}>
                  <button
                    type="button"
                    onClick={() => onSelectAction(action)}
                    aria-current={selected ? 'true' : undefined}
                    className={cn(
                      'w-full border-l-2 px-3 py-2 text-left transition-colors duration-instant',
                      selected
                        ? 'border-accent bg-active'
                        : 'border-transparent hover:bg-hover',
                    )}
                    data-testid={`runs-action-${action.id}`}
                  >
                    <span className="block text-sm font-medium text-foreground">{action.title}</span>
                    <span className="tnum mt-0.5 block truncate font-mono text-xs text-foreground-tertiary">
                      {action.id}
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </section>

      <section className="border-t border-border py-2" aria-labelledby="recent-runs-heading">
        <h2
          id="recent-runs-heading"
          className="flex items-center gap-1.5 px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-foreground-tertiary"
        >
          <History className="size-3.5" aria-hidden="true" />
          Recent runs
        </h2>
        {history.length === 0 ? (
          <p className="px-3 py-2 text-xs text-foreground-tertiary" data-testid="runs-history-empty">
            No runs have been prepared yet.
          </p>
        ) : (
          <ul className="flex flex-col" data-testid="runs-history">
            {history.slice(0, 30).map((run) => {
              const selected = run.id === activeRunId
              return (
                <li key={run.id}>
                  <button
                    type="button"
                    onClick={() => onSelectRun(run)}
                    aria-current={selected ? 'true' : undefined}
                    className={cn(
                      'w-full border-l-2 px-3 py-2 text-left transition-colors duration-instant',
                      selected
                        ? 'border-accent bg-active'
                        : 'border-transparent hover:bg-hover',
                    )}
                    data-testid={`runs-history-${run.id}`}
                  >
                    <span className="flex min-w-0 items-center justify-between gap-2">
                      <span className="tnum min-w-0 truncate font-mono text-xs font-medium text-foreground">
                        {run.id}
                      </span>
                      <TimeAgo date={run.updatedAt} />
                    </span>
                    <span className="mt-1 flex flex-wrap items-center gap-1.5">
                      <OperationStateLabel state={run.state} className="text-xs" />
                      <span className="text-xs text-foreground-tertiary">{runStatusLabel(run.status)}</span>
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </section>
    </aside>
  )
}

function GovernedRunsSurface({
  instanceId,
  benchmarkEnabled,
  receiptBasePath,
  degradedReason,
}: {
  instanceId: string
  benchmarkEnabled: boolean
  receiptBasePath?: string
  degradedReason?: string
}) {
  const runs = useRuns(instanceId)
  const { dismissActiveRun, refresh } = runs
  const [selectedActionId, setSelectedActionId] = useState<string | null>(null)
  const [evidenceRun, setEvidenceRun] = useState<RunRecord | null>(null)
  const selectedAction =
    runs.actions.find((action) => action.id === selectedActionId) ?? runs.actions[0]
  const activeAction = runs.activeRun
    ? runs.actions.find((action) => action.id === runs.activeRun?.actionId)
    : undefined
  const activeEngine = runs.activeRun
    ? runs.engines.find((engine) => engine.id === runs.activeRun?.engineId)
    : undefined

  const commands = useMemo<ShellCommand[]>(
    () => [
      {
        id: 'runs.prepare_new',
        title: 'Runs: Prepare a new run',
        group: 'Actions',
        icon: Plus,
        keywords: ['execution', 'action', 'run'],
        run: dismissActiveRun,
      },
      {
        id: 'runs.refresh',
        title: 'Runs: Refresh exact state',
        group: 'Actions',
        icon: RefreshCw,
        keywords: ['execution', 'reload', 'history'],
        run: refresh,
      },
    ],
    [dismissActiveRun, refresh],
  )
  useRegisterCommands(commands)

  if (runs.status === 'loading') {
    return (
      <div className="flex h-full flex-col bg-app" data-testid="runs-loading">
        <header className="border-b border-border px-4 py-3">
          <h1 className="text-xl font-semibold text-foreground">Governed runs</h1>
        </header>
        <SkeletonRows rows={8} className="p-4" />
      </div>
    )
  }

  if (runs.status === 'error') {
    return (
      <div className="flex h-full flex-col bg-app" data-testid="runs-stub">
        <header className="border-b border-border px-4 py-3">
          <h1 className="text-xl font-semibold text-foreground">Governed runs</h1>
        </header>
        <ErrorState
          title="Could not load governed execution"
          error={runs.loadError}
          preservedNote="No run was prepared or changed."
          onRetry={runs.refresh}
        />
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col bg-app" data-testid="runs-stub">
      <header className="flex shrink-0 flex-wrap items-start justify-between gap-3 border-b border-border px-4 py-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">Governed runs</h1>
          <p className="mt-0.5 max-w-2xl text-xs text-foreground-secondary">
            Prepare, approve, execute, inspect proposals, apply, and verify evidence without granting processors ownership of application truth.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={runs.dismissActiveRun} data-testid="runs-new">
            <Plus aria-hidden="true" />
            New run
          </Button>
          <Button size="sm" variant="ghost" onClick={runs.refresh} aria-label="Refresh governed runs">
            <RefreshCw aria-hidden="true" />
            Refresh
          </Button>
        </div>
      </header>

      {degradedReason ? (
        <div className="shrink-0 px-4 pt-3">
          <InlineNotice tone="attention" title="Governed execution is degraded">
            {degradedReason}
          </InlineNotice>
        </div>
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <RunRail
          actions={runs.actions}
          history={runs.history}
          selectedActionId={selectedAction?.id}
          activeRunId={runs.activeRun?.id}
          onSelectAction={(action) => {
            setSelectedActionId(action.id)
            runs.dismissActiveRun()
          }}
          onSelectRun={runs.selectRun}
        />

        <main className="min-h-0 min-w-0 flex-1 overflow-y-auto" aria-label="Governed run workspace">
          {runs.transitionError && !runs.activeRun ? (
            <div className="px-4 pt-4 md:px-6">
              <InlineNotice
                tone="danger"
                title="The run could not be prepared"
                action={
                  <Button size="sm" variant="outline" onClick={runs.clearTransitionError}>
                    Dismiss
                  </Button>
                }
              >
                {runs.transitionError instanceof Error
                  ? runs.transitionError.message
                  : String(runs.transitionError)}
              </InlineNotice>
            </div>
          ) : null}

          {runs.activeRun ? (
            <RunWorkspace
              run={runs.activeRun}
              action={activeAction}
              engine={activeEngine}
              busy={runs.busy}
              transitionError={runs.transitionError}
              onTransition={(operation) => runs.transition(runs.activeRun!, operation)}
              onRefresh={runs.refresh}
              onNewRun={runs.dismissActiveRun}
              onOpenEvidence={() => setEvidenceRun(runs.activeRun)}
            />
          ) : selectedAction ? (
            <RunPreparation
              key={selectedAction.id}
              action={selectedAction}
              engines={runs.engines}
              busy={runs.busy}
              onPrepare={runs.prepare}
            />
          ) : (
            <EmptyState
              icon={CirclePlay}
              title="No governed actions declared"
              description="This application exposes goal execution but its current descriptor does not declare an action to prepare."
              action={{ label: 'Refresh actions', onClick: runs.refresh, icon: RefreshCw }}
            />
          )}
        </main>
      </div>

      {evidenceRun ? (
        <RunDetailDrawer
          key={evidenceRun.id}
          run={evidenceRun}
          benchmarkEnabled={benchmarkEnabled}
          receiptBasePath={receiptBasePath}
          onClose={() => setEvidenceRun(null)}
        />
      ) : null}
    </div>
  )
}

export default function RunsPage() {
  const { instance, capability, hasCapability } = useCurrentInstance()
  if (!instance) {
    return <ErrorState title="No application selected" error="Governed runs require an application." />
  }
  if (!hasCapability('goal_execution')) {
    const state = capability('goal_execution')
    return (
      <div className="flex h-full flex-col bg-app" data-testid="runs-gated">
        <EmptyState
          icon={ShieldX}
          title="Governed runs unavailable"
          description={state?.reason ?? 'This application does not declare a usable goal_execution capability.'}
        />
      </div>
    )
  }
  const goalCapability = capability('goal_execution')
  const receiptBasePath = receiptBasePathFor(instance)
  return (
    <GovernedRunsSurface
      instanceId={instance.id}
      benchmarkEnabled={hasCapability('benchmark_evidence')}
      receiptBasePath={receiptBasePath}
      degradedReason={goalCapability?.status === 'degraded' ? goalCapability.reason : undefined}
    />
  )
}
