import {
  CirclePlay,
  ClipboardCheck,
  FileCheck2,
  FileSearch,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Square,
  X,
} from 'lucide-react'
import { useState } from 'react'

import type {
  ExecutionEngine,
  GovernedAction,
  RunOperation,
  RunRecord,
} from '@/client'
import {
  ConfirmDialog,
  CopyButton,
  Disclosure,
  InlineNotice,
  OperationStateLabel,
  TimeAgo,
} from '@/components'
import { Button } from '@/components/ui/button'

import {
  canRequestRunEvidence,
  runControls,
  runStatusLabel,
  safeEvidenceValue,
} from './runsModel'

function failureDetail(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function stringField(value: unknown, key: string): string | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  const candidate = (value as Record<string, unknown>)[key]
  return typeof candidate === 'string' ? candidate : undefined
}

function objectField(value: unknown, key: string): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  const candidate = (value as Record<string, unknown>)[key]
  return typeof candidate === 'object' && candidate !== null && !Array.isArray(candidate)
    ? (candidate as Record<string, unknown>)
    : undefined
}

function ExactJson({ value, testId }: { value: unknown; testId?: string }) {
  const safe = safeEvidenceValue(value)
  return (
    <pre
      className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-sm border border-border bg-sunken p-2 font-mono text-xs text-foreground-secondary"
      data-testid={testId}
    >
      {JSON.stringify(safe, null, 2)}
    </pre>
  )
}

function StatusTruth({ run }: { run: RunRecord }) {
  if (!run.status) {
    return (
      <InlineNotice tone="blocked" title="Exact run status unavailable">
        Transition controls are inactive because this projection does not expose the persisted status.
      </InlineNotice>
    )
  }
  if (run.status === 'awaiting_approval') {
    return (
      <InlineNotice tone="attention" title="Awaiting exact run approval">
        Review the compiled identity, capabilities, budget, and policies below. Approval does not execute the run.
      </InlineNotice>
    )
  }
  if (run.status === 'approved') {
    return (
      <InlineNotice tone="informational" title="Approved, not executed">
        The exact revision is approved. Execution remains a separate action.
      </InlineNotice>
    )
  }
  if (run.status === 'state_change_proposed') {
    return (
      <InlineNotice tone="attention" title="Typed state change awaits a decision">
        Execution produced a proposal. Canonical state has not been changed by this proposal.
      </InlineNotice>
    )
  }
  if (run.status === 'state_change_approved') {
    return (
      <InlineNotice tone="informational" title="Proposal approved, not applied">
        Applying the exact approved proposal remains a separate StatePort transaction.
      </InlineNotice>
    )
  }
  if (run.status === 'completed' && run.result?.canonicalStateUnchanged === true) {
    return (
      <InlineNotice tone="informational" title="Execution completed without canonical change">
        The recorded result explicitly reports that canonical application state remained unchanged.
      </InlineNotice>
    )
  }
  if (run.status === 'result_validating' && run.lifecycleState === 'CLOSED') {
    return (
      <InlineNotice tone="informational" title="Result recorded; no project change applied">
        The result passed its typed-result check and the run closed without a canonical state change.
      </InlineNotice>
    )
  }
  if (run.status === 'applied') {
    const validation = stringField(run.postApplyValidation, 'status')
    return validation === 'passed' ? (
      <InlineNotice tone="informational" title="Applied; post-apply validation recorded as passed">
        Apply and validation are separate recorded facts. Human acceptance and remote acceptance are not implied.
      </InlineNotice>
    ) : (
      <InlineNotice tone="attention" title="Applied; validation is not recorded as passed">
        Applied is not automatically validated. Inspect the post-apply evidence before drawing a stronger conclusion.
      </InlineNotice>
    )
  }
  if (run.status === 'cancelled') {
    return (
      <InlineNotice tone="informational" title="Cancellation recorded">
        This status records the run cancellation transition; it does not assert compensation of external effects.
      </InlineNotice>
    )
  }
  if (['failed', 'apply_failed', 'timed_out', 'result_rejected'].includes(run.status)) {
    return (
      <InlineNotice tone="danger" title={runStatusLabel(run.status)}>
        The run did not reach a successful closure. Inspect its exact result and rollback record.
      </InlineNotice>
    )
  }
  return (
    <InlineNotice tone="informational">
      Current exact status: <span className="font-medium">{runStatusLabel(run.status)}</span>.
    </InlineNotice>
  )
}

function ProposalReview({ run }: { run: RunRecord }) {
  const operations =
    run.proposal && Array.isArray(run.proposal.operations)
      ? run.proposal.operations.filter(
          (operation): operation is Record<string, unknown> =>
            typeof operation === 'object' && operation !== null && !Array.isArray(operation),
        )
      : []
  return (
    <section aria-labelledby="proposal-heading" className="border-t border-border pt-5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h3 id="proposal-heading" className="text-sm font-semibold text-foreground">Typed state proposal</h3>
          <p className="mt-0.5 text-xs text-foreground-tertiary">
            Inspect the exact proposal digest and operations before deciding.
          </p>
        </div>
        {run.proposalDigest ? (
          <CopyButton text={run.proposalDigest.value} label="Copy proposal digest" />
        ) : null}
      </div>
      {operations.length ? (
        <ol className="mt-3 divide-y divide-border border-y border-border" data-testid="run-proposal-operations">
          {operations.map((operation, index) => (
            <li key={index} className="grid gap-1 py-2 text-xs sm:grid-cols-[8rem_1fr]">
              <span className="font-medium text-foreground">
                {typeof operation.operation === 'string' ? operation.operation : `Operation ${index + 1}`}
              </span>
              <span className="tnum break-all font-mono text-foreground-secondary">
                {typeof operation.path === 'string'
                  ? String(safeEvidenceValue(operation.path))
                  : 'No path exposed'}
              </span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="mt-3 text-xs text-foreground-tertiary">No structured operation list is exposed.</p>
      )}
      <Disclosure title="Exact proposal JSON" className="mt-2">
        <ExactJson value={run.proposal ?? { proposalDigest: run.proposalDigest }} testId="run-proposal-json" />
      </Disclosure>
    </section>
  )
}

function ResultSummary({ run }: { run: RunRecord }) {
  if (!run.result) return null
  const item = objectField(run.result, 'item')
  const activity = objectField(run.result, 'activity')
  const resultLabel = stringField(item, 'label') ?? stringField(activity, 'label')
  const resultStatus = stringField(item, 'status') ?? stringField(activity, 'status')
  const actionId = stringField(run.result, 'actionId')
  const engine = objectField(run.result, 'engineIdentity')
  const engineLabel = stringField(engine, 'model') ?? stringField(engine, 'id')
  const projectState =
    run.result.canonicalStateUnchanged === true
      ? 'Unchanged'
      : run.result.canonicalStateUnchanged === false
        ? 'Change proposed or applied'
        : 'Not recorded'

  return (
    <section aria-labelledby="result-heading" className="border-t border-border pt-5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h3 id="result-heading" className="text-sm font-semibold text-foreground">Result</h3>
          <p className="mt-0.5 text-xs text-foreground-tertiary">
            The useful output of this run, separated from approval and execution status.
          </p>
        </div>
        {resultStatus ? (
          <span className="rounded-sm bg-sunken px-2 py-1 text-xs font-medium text-foreground-secondary">
            {resultStatus}
          </span>
        ) : null}
      </div>
      {resultLabel ? (
        <p className="mt-3 rounded-sm border border-border bg-sunken px-3 py-3 text-sm text-foreground">
          {resultLabel}
        </p>
      ) : null}
      <dl className="mt-3 divide-y divide-border border-y border-border text-xs">
        {actionId ? (
          <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
            <dt className="font-medium text-foreground-secondary">Action</dt>
            <dd className="font-mono text-foreground">{actionId}</dd>
          </div>
        ) : null}
        {engineLabel ? (
          <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
            <dt className="font-medium text-foreground-secondary">Engine</dt>
            <dd className="text-foreground">{engineLabel}</dd>
          </div>
        ) : null}
        <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
          <dt className="font-medium text-foreground-secondary">Project state</dt>
          <dd className="text-foreground">{projectState}</dd>
        </div>
      </dl>
      <Disclosure title="Exact result JSON" className="mt-2">
        <ExactJson value={run.result} testId="run-result-json" />
      </Disclosure>
    </section>
  )
}

function ClosureEvidence({ run }: { run: RunRecord }) {
  const validationStatus = stringField(run.postApplyValidation, 'status')
  return (
    <section aria-labelledby="closure-heading" className="border-t border-border pt-5">
      <h3 id="closure-heading" className="text-sm font-semibold text-foreground">Apply, validation, and rollback truth</h3>
      <div className="mt-3 divide-y divide-border border-y border-border text-xs">
        <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
          <span className="font-medium text-foreground-secondary">Apply status</span>
          <span className="text-foreground">{run.status === 'applied' ? 'Applied' : 'Not recorded as applied'}</span>
        </div>
        <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
          <span className="font-medium text-foreground-secondary">Post-validation</span>
          <span className="flex items-center gap-2 text-foreground" data-testid="run-validation-truth">
            {validationStatus === 'passed' ? <OperationStateLabel state="validated" /> : null}
            {validationStatus ?? 'No post-apply validation status exposed'}
          </span>
        </div>
        <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
          <span className="font-medium text-foreground-secondary">Rollback</span>
          <span className="text-foreground">
            {run.rollback ? 'A rollback record is exposed below' : 'No rollback record is exposed'}
          </span>
        </div>
      </div>
      {run.postApplyValidation ? (
        <Disclosure title="Post-apply validation record" className="mt-2">
          <ExactJson value={run.postApplyValidation} />
        </Disclosure>
      ) : null}
      {run.rollback ? (
        <Disclosure title="Rollback record" className="mt-2">
          <ExactJson value={run.rollback} />
        </Disclosure>
      ) : null}
      <p className="mt-2 text-xs text-foreground-tertiary">
        Filesystem rollback cannot prove compensation of network, financial, or other external side effects.
      </p>
    </section>
  )
}

export function RunWorkspace({
  run,
  action,
  engine,
  busy,
  transitionError,
  onTransition,
  onRefresh,
  onNewRun,
  onOpenEvidence,
}: {
  run: RunRecord
  action?: GovernedAction
  engine?: ExecutionEngine
  busy: boolean
  transitionError: unknown
  onTransition: (operation: RunOperation) => Promise<unknown>
  onRefresh: () => void
  onNewRun: () => void
  onOpenEvidence: () => void
}) {
  const controls = runControls(run)
  const [confirmCancel, setConfirmCancel] = useState(false)
  const [confirmReject, setConfirmReject] = useState(false)

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-5 px-4 py-5 md:px-6" data-testid="run-workspace">
      <header className="flex flex-col gap-3 border-b border-border pb-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="tnum truncate font-mono text-xs text-foreground-tertiary">{run.id}</p>
            <h2 className="mt-1 text-2xl font-semibold tracking-tight text-foreground">
              {action?.title ?? run.actionId}
            </h2>
            <p className="mt-1 text-sm text-foreground-secondary">
              {engine?.label ?? run.engineId} · revision <span className="tnum font-mono">{run.revision}</span>
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <OperationStateLabel state={run.state} />
            <span className="rounded-sm bg-sunken px-2 py-1 text-xs font-medium text-foreground-secondary" data-testid="run-exact-status">
              {runStatusLabel(run.status)}
            </span>
            {run.lifecycleState ? (
              <span className="tnum font-mono text-xs text-foreground-tertiary">{run.lifecycleState}</span>
            ) : null}
          </div>
        </div>
        <StatusTruth run={run} />
      </header>

      {transitionError ? (
        <InlineNotice
          tone="danger"
          title="The service refused the transition"
          action={
            <Button size="sm" variant="outline" onClick={onRefresh}>
              <RefreshCw aria-hidden="true" />
              Refresh
            </Button>
          }
        >
          {failureDetail(transitionError)} Nothing was retried automatically.
        </InlineNotice>
      ) : null}

      <ResultSummary run={run} />

      <section aria-labelledby="identity-heading">
        <h3 id="identity-heading" className="text-sm font-semibold text-foreground">Exact prepared identity</h3>
        <dl className="mt-3 divide-y divide-border border-y border-border text-xs">
          <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
            <dt className="font-medium text-foreground-secondary">Application</dt>
            <dd className="tnum break-all font-mono text-foreground">{run.instanceId}</dd>
          </div>
          <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
            <dt className="font-medium text-foreground-secondary">Action</dt>
            <dd className="tnum break-all font-mono text-foreground">{run.actionId}</dd>
          </div>
          <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
            <dt className="font-medium text-foreground-secondary">Engine</dt>
            <dd className="tnum break-all font-mono text-foreground">{run.engineId}</dd>
          </div>
          <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
            <dt className="font-medium text-foreground-secondary">Run spec digest</dt>
            <dd className="flex min-w-0 items-center gap-1">
              <span className="tnum min-w-0 flex-1 truncate font-mono text-foreground">
                {run.runSpecDigest?.value ?? 'Not exposed'}
              </span>
              {run.runSpecDigest ? (
                <CopyButton text={run.runSpecDigest.value} label="Copy run spec digest" />
              ) : null}
            </dd>
          </div>
          <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
            <dt className="font-medium text-foreground-secondary">Last transition</dt>
            <dd className="text-foreground"><TimeAgo date={run.updatedAt} /></dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="negotiation-heading">
        <h3 id="negotiation-heading" className="text-sm font-semibold text-foreground">Compiled scope and negotiation</h3>
        <p className="mt-0.5 text-xs text-foreground-tertiary">
          This is the service projection of the exact run, not a frontend capability grant.
        </p>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <Disclosure title="Run specification" defaultOpen={run.status === 'awaiting_approval'} className="border-y border-border">
            <ExactJson value={run.runSpec ?? { runSpecDigest: run.runSpecDigest }} testId="run-spec-json" />
          </Disclosure>
          <Disclosure title="Capability negotiation" defaultOpen={run.status === 'awaiting_approval'} className="border-y border-border">
            <ExactJson value={run.negotiation ?? { status: 'Not exposed' }} testId="run-negotiation-json" />
          </Disclosure>
          <Disclosure title="Declared action policies" className="border-y border-border">
            <ExactJson
              value={{
                contextPolicy: action?.contextPolicy,
                requiredCapabilities: action?.requiredCapabilities,
                optionalCapabilities: action?.optionalCapabilities,
                mutationPolicy: action?.mutationPolicy,
                networkPolicy: action?.networkPolicy,
                toolPolicy: action?.toolPolicy,
                budgetDefaults: action?.budgetDefaults,
                validationPolicy: action?.validationPolicy,
              }}
            />
          </Disclosure>
          <Disclosure title="Execution gate" className="border-y border-border">
            <ExactJson value={run.executionGate ?? { status: 'Not exposed' }} />
          </Disclosure>
        </div>
      </section>

      {run.proposal || run.proposalDigest ? <ProposalReview run={run} /> : null}
      {run.status === 'applied' || run.status === 'apply_failed' || run.postApplyValidation || run.rollback ? (
        <ClosureEvidence run={run} />
      ) : null}

      <section aria-label="Run actions" className="border-t border-border pt-4">
        <div className="flex flex-wrap items-center gap-2" data-testid="run-controls">
          {controls.approve ? (
            <Button disabled={busy} onClick={() => void onTransition('approve')} data-testid="run-approve">
              <ShieldCheck aria-hidden="true" />
              Approve exact run
            </Button>
          ) : null}
          {controls.execute ? (
            <Button disabled={busy} onClick={() => void onTransition('execute')} data-testid="run-execute">
              <CirclePlay aria-hidden="true" />
              Execute approved run
            </Button>
          ) : null}
          {controls.proposalReview ? (
            <>
              <Button
                disabled={busy}
                onClick={() => void onTransition('proposal-approve')}
                data-testid="run-proposal-approve"
              >
                <ClipboardCheck aria-hidden="true" />
                Approve exact proposal
              </Button>
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => setConfirmReject(true)}
                data-testid="run-proposal-reject"
              >
                <X aria-hidden="true" />
                Reject proposal
              </Button>
            </>
          ) : null}
          {controls.apply ? (
            <Button disabled={busy} onClick={() => void onTransition('apply')} data-testid="run-apply">
              <FileCheck2 aria-hidden="true" />
              Apply approved proposal
            </Button>
          ) : null}
          {controls.cancel ? (
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setConfirmCancel(true)}
              data-testid="run-cancel"
            >
              <Square aria-hidden="true" />
              Request cancellation
            </Button>
          ) : null}
          {canRequestRunEvidence(run) ? (
            <Button variant="outline" onClick={onOpenEvidence} data-testid="run-open-evidence">
              <FileSearch aria-hidden="true" />
              Inspect evidence
            </Button>
          ) : null}
          <Button variant="ghost" onClick={onRefresh} disabled={busy}>
            <RefreshCw aria-hidden="true" />
            Refresh
          </Button>
          <Button variant="ghost" onClick={onNewRun} disabled={busy} data-testid="run-new">
            <RotateCcw aria-hidden="true" />
            Prepare another
          </Button>
        </div>
        {!controls.approve &&
        !controls.execute &&
        !controls.proposalReview &&
        !controls.apply &&
        !controls.cancel ? (
          <p className="mt-2 text-xs text-foreground-tertiary">
            No lifecycle transition is available from this exact status.
          </p>
        ) : null}
      </section>

      <ConfirmDialog
        open={confirmCancel}
        onOpenChange={setConfirmCancel}
        title="Request run cancellation?"
        target={run.id}
        effect="Ask StatePort to record the governed cancel transition for this exact run revision."
        reversibility="Cancellation cannot be undone; external side effects are not automatically compensated."
        confirmLabel="Request cancellation"
        onConfirm={async () => {
          await onTransition('cancel')
        }}
      />
      <ConfirmDialog
        open={confirmReject}
        onOpenChange={setConfirmReject}
        title="Reject this exact proposal?"
        target={run.proposalDigest?.value ?? run.id}
        effect="Record proposal rejection. The proposal will not be applied."
        reversibility="A new run is required to produce another proposal."
        confirmLabel="Reject proposal"
        onConfirm={async () => {
          await onTransition('proposal-reject')
        }}
      />
    </div>
  )
}
