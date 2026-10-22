/**
 * ProposalReview — review of an agent's file proposal (ADR-0007 §1):
 * changed files with +/− counts, the exact unified diff, the evaluator before
 * and after, and the model route and duration. "Apply" records the proposal
 * approval and then applies it as a Git commit; "Reject" discards it. After
 * apply, the commit from the apply receipt and the evaluator re-run show.
 *
 * Controls derive from the exact run status only. Applied is never presented
 * as accepted.
 */
import { CircleCheck, FileCheck2, GitCommitHorizontal, X } from 'lucide-react'
import { useMemo } from 'react'

import type { RunRecord } from '@/client'
import { appliedOutcomeOf, type FileProposalView } from '@/client/proposals'
import { CopyButton, InlineNotice, StatusBadge } from '@/components'
import { Button } from '@/components/ui/button'

import { VerdictComparison, VerdictDetail } from './EvaluatorVerdict'
import { PatchView } from './PatchView'
import { mergeFileList, parseUnifiedDiff } from './unifiedDiff'
import {
  CHANGE_PRESENTATION,
  changeCountLabel,
  durationLabel,
  proposalControls,
  shortCommit,
  verdictWorsened,
} from './proposalModel'

export interface ProposalReviewProps {
  run: RunRecord
  proposal: FileProposalView
  busy: boolean
  error?: unknown
  onApply: () => Promise<unknown>
  onReject: () => Promise<unknown>
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function StatusLine({ run }: { run: RunRecord }) {
  switch (run.status) {
    case 'state_change_proposed':
      return <p className="text-xs text-foreground-secondary">Waiting for your decision. Nothing in the application has changed.</p>
    case 'state_change_approved':
      return <p className="text-xs text-foreground-secondary">Approved but not applied yet. Apply records it as a commit.</p>
    case 'applying':
      return <p className="text-xs text-foreground-secondary">Applying…</p>
    case 'state_change_rejected':
      return (
        <InlineNotice tone="informational" title="Rejected">
          The proposal was discarded. Nothing in the application changed.
        </InlineNotice>
      )
    case 'apply_failed':
      return (
        <InlineNotice tone="danger" title="Apply failed">
          The change was not recorded as applied. Refresh before trying again.
        </InlineNotice>
      )
    default:
      return null
  }
}

export function ProposalReview({ run, proposal, busy, error, onApply, onReject }: ProposalReviewProps) {
  const parsed = useMemo(() => parseUnifiedDiff(proposal.patch), [proposal.patch])
  const files = useMemo(() => mergeFileList(proposal.files, parsed), [proposal.files, parsed])
  const reviewable = proposal.patch.trim().length > 0
  const controls = proposalControls(run, reviewable)
  const outcome = appliedOutcomeOf(run)
  const worsened = verdictWorsened(proposal.evaluatorBefore, proposal.evaluatorAfter)
  const totals = files.reduce(
    (sum, file) => ({ additions: sum.additions + (file.additions ?? 0), deletions: sum.deletions + (file.deletions ?? 0) }),
    { additions: 0, deletions: 0 },
  )

  return (
    <section aria-labelledby={`proposal-${run.id}-heading`} className="flex flex-col gap-4" data-testid="proposal-review" data-status={run.status}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 id={`proposal-${run.id}-heading`} className="text-sm font-semibold text-foreground">Proposed change</h3>
          <p className="mt-0.5 text-xs text-foreground-secondary">
            An agent worked on a copy of this application and proposes these file changes. Nothing changes until you apply them.
          </p>
        </div>
        {run.proposalDigest ? <CopyButton text={run.proposalDigest.value} label="Copy proposal digest" /> : null}
      </div>

      <dl className="grid gap-x-4 gap-y-1 text-xs sm:grid-cols-[9rem_1fr]">
        <dt className="font-medium text-foreground-secondary">Model route</dt>
        <dd className="break-all text-foreground" data-testid="proposal-route">{proposal.route?.label ?? 'Not recorded'}</dd>
        <dt className="font-medium text-foreground-secondary">Duration</dt>
        <dd className="text-foreground" data-testid="proposal-duration">{durationLabel(proposal.durationSeconds)}</dd>
        {proposal.baseCommit ? (
          <>
            <dt className="font-medium text-foreground-secondary">Based on commit</dt>
            <dd className="font-mono text-foreground">{shortCommit(proposal.baseCommit)}</dd>
          </>
        ) : null}
      </dl>

      {proposal.agentSummary ? (
        <div className="rounded-sm border border-border bg-sunken px-3 py-2">
          <p className="text-xs font-medium text-foreground-secondary">The agent's note</p>
          <p className="mt-1 whitespace-pre-wrap break-words text-sm text-foreground">{proposal.agentSummary}</p>
        </div>
      ) : null}

      <div className="flex flex-col gap-2">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-foreground-tertiary">The application's check</h4>
        <VerdictComparison before={proposal.evaluatorBefore} after={proposal.evaluatorAfter} />
        {worsened ? (
          <InlineNotice tone="attention" title="The check is worse after this change">
            The application's own check judges the result worse than the current state. Review carefully before applying.
          </InlineNotice>
        ) : null}
      </div>

      <div className="flex flex-col gap-2">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-foreground-tertiary">
          {files.length === 1 ? '1 file' : `${files.length} files`}
          {files.length > 0 ? <span className="tnum font-normal normal-case"> · +{totals.additions} −{totals.deletions}</span> : null}
        </h4>
        {files.length > 0 ? (
          <ul className="divide-y divide-border rounded-sm border border-border" data-testid="proposal-files">
            {files.map((file) => {
              const change = CHANGE_PRESENTATION[file.change]
              return (
                <li key={file.path} className="flex flex-wrap items-center gap-2 px-2 py-1.5 text-xs" data-testid="proposal-file" data-change={file.change}>
                  <StatusBadge state={change.state} label={change.label} />
                  <span className="min-w-0 flex-1 break-all font-mono text-foreground">
                    {file.oldPath && file.oldPath !== file.path ? `${file.oldPath} → ${file.path}` : file.path}
                  </span>
                  <span className="tnum text-foreground-secondary">{changeCountLabel(file.additions, file.deletions, file.binary)}</span>
                </li>
              )
            })}
          </ul>
        ) : null}
        <PatchView patch={proposal.patch} files={parsed} />
      </div>

      {outcome ? (
        <div className="flex flex-col gap-2 rounded-sm border border-border bg-surface-2 p-3" data-testid="proposal-applied">
          <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-foreground">
            <CircleCheck className="size-4 text-status-success" aria-hidden="true" />
            Applied
            {outcome.commit ? (
              <span className="inline-flex items-center gap-1 font-mono text-xs font-normal text-foreground-secondary" data-testid="proposal-commit">
                <GitCommitHorizontal className="size-3.5" aria-hidden="true" />
                commit {shortCommit(outcome.commit)}
                <CopyButton text={outcome.commit} label="Copy commit id" />
              </span>
            ) : (
              <span className="text-xs font-normal text-foreground-tertiary">The apply receipt carries no commit id.</span>
            )}
          </p>
          <VerdictDetail result={outcome.evaluator} title="Check after applying" testId="proposal-applied-verdict" />
          {outcome.validation ? (
            <p className="text-xs text-foreground-secondary" data-testid="proposal-applied-validation">
              Post-apply validation: {outcome.validation.state}
              {outcome.validation.detail ? ` — ${outcome.validation.detail}` : ''}
            </p>
          ) : (
            <p className="text-xs text-foreground-tertiary" data-testid="proposal-applied-validation">
              No post-apply validation was recorded for this change.
            </p>
          )}
          <p className="text-xs text-foreground-tertiary">Applied is a recorded change, not an acceptance of the work.</p>
        </div>
      ) : (
        <StatusLine run={run} />
      )}

      {!reviewable && run.status === 'state_change_proposed' ? (
        <InlineNotice tone="blocked" title="Nothing to review">
          This proposal carries no patch, so it cannot be applied from here. Reject it and run the action again.
        </InlineNotice>
      ) : null}

      {error ? (
        <InlineNotice tone="danger" title="The service refused the decision">
          {message(error)} Refresh before trying again; nothing was retried automatically.
        </InlineNotice>
      ) : null}

      {controls.apply || controls.reject ? (
        <div className="flex flex-wrap items-center gap-2" data-testid="proposal-controls">
          {controls.apply ? (
            <Button disabled={busy} onClick={() => void onApply()} data-testid="proposal-apply">
              <FileCheck2 aria-hidden="true" />
              {busy ? 'Working…' : controls.applyLabel}
            </Button>
          ) : null}
          {controls.reject ? (
            <Button variant="outline" disabled={busy} onClick={() => void onReject()} data-testid="proposal-reject">
              <X aria-hidden="true" />
              Reject
            </Button>
          ) : null}
        </div>
      ) : null}
    </section>
  )
}
