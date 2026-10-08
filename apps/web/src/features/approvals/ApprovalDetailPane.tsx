/**
 * ApprovalDetailPane — the review half of the approvals inbox (approvals.md).
 * Top→bottom: header (operation type + state, risk, instance, request time,
 * expiry), What will happen, Exact scope (target identity, plan digest),
 * Before → After (diff or fact table), plan steps in their own scroll region,
 * Why approval is required, related links, stale-plan guard, and the sticky
 * action bar (only the decisions supported by the indexed authority;
 * destructive approvals go through ConfirmDialog with the exact target
 * restated).
 */
import { formatDistanceToNowStrict, parseISO } from 'date-fns'
import {
  ArrowLeft,
  ArrowUpRight,
  Check,
  CircleAlert,
  FileCode2,
  Loader2,
  Terminal,
} from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import type { Approval, InfrastructurePlan } from '@/client'
import { ClientError, getClient } from '@/client'
import {
  ConfirmDialog,
  CopyButton,
  Disclosure,
  ErrorState,
  InlineNotice,
  OperationStateLabel,
  Skeleton,
  StatusBadge,
  TimeAgo,
} from '@/components'
import { Button } from '@/components/ui/button'
import { useApplicationReceiptBaseRoute } from '@/features/application-experience/useApplicationReceiptRoute'
import { sendToBridge } from '@/features/bridge/bridgeStore'
import { cn } from '@/lib/utils'
import { useSessionStore } from '@/state'

import {
  approvalStatusPresentation,
  exactTargetName,
  expiryText,
  isDestroyClass,
  isExpired,
  isExpiryUrgent,
  isStale,
  riskPresentation,
} from './approvalsModel'

// ── Small pieces ─────────────────────────────────────────────────────────────

function FactRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-2 py-0.5">
      <dt className="w-28 shrink-0 text-xs text-foreground-secondary">{label}</dt>
      <dd className="min-w-0 text-sm text-foreground">{children}</dd>
    </div>
  )
}

function DigestValue({ value, testId }: { value: string; testId?: string }) {
  const short = value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value
  return (
    <span
      className="inline-flex items-center gap-1"
      data-testid={testId}
      data-digest={value}
      aria-label={value}
    >
      <span className="tnum font-mono text-xs text-foreground">{short}</span>
      <CopyButton text={value} label="Copy plan digest" />
    </span>
  )
}

function decisionRoute(approval: Approval, action: 'approve' | 'reject'): string | null {
  const instanceId = encodeURIComponent(approval.instanceId)
  const runId = approval.runId ? encodeURIComponent(approval.runId) : null
  switch (approval.decision.kind) {
    case 'run_approval':
      return action === 'approve' && runId ? `/v1/runs/${runId}/approve` : null
    case 'run_proposal':
      return runId ? `/v1/runs/${runId}/${action === 'approve' ? 'proposal-approve' : 'proposal-reject'}` : null
    case 'infrastructure_plan':
      return action === 'approve' ? `/v1/instances/${instanceId}/infrastructure/approve` : null
    case 'authorization_grant':
      return action === 'approve' ? `/v1/instances/${instanceId}/infrastructure/grant/approve` : null
    case 'goal_execution':
      return action === 'approve' ? `/v1/instances/${instanceId}/goal-execution/approve` : null
    case 'template_upgrade':
      return approval.targetId
        ? `/v1/instances/${instanceId}/template-upgrade/${action}`
        : null
  }
}

/** Unified diff, mono 12.5 px with added/removed line tints (design.md §14). */
function DiffBlock({ unified }: { unified: string }) {
  return (
    <pre
      className="max-h-72 overflow-auto rounded-md border border-border bg-sunken p-2 font-mono text-code text-foreground"
      data-testid="approval-diff"
    >
      {unified.split('\n').map((line, i) => (
        <div
          key={i}
          className={cn(
            'whitespace-pre-wrap break-all px-1',
            line.startsWith('+') && !line.startsWith('+++') && 'bg-status-success-bg',
            line.startsWith('-') && !line.startsWith('---') && 'bg-status-danger-bg',
          )}
        >
          {line || ' '}
        </div>
      ))}
    </pre>
  )
}

// ── Main pane ────────────────────────────────────────────────────────────────

export interface ApprovalDetailPaneProps {
  approvalId: string
  /** Resolve an instance id to its display name (undefined while unknown). */
  instanceName: (instanceId: string) => string | undefined
  onDecided: (approval: Approval) => void
  /** Mobile back-to-list. */
  onBack: () => void
  now: number
}

export function ApprovalDetailPane({ approvalId, instanceName, onDecided, onBack, now }: ApprovalDetailPaneProps) {
  const [approval, setApproval] = useState<Approval | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<unknown>(null)
  const [nonce, setNonce] = useState(0)

  const [plan, setPlan] = useState<InfrastructurePlan | null>(null)
  const [busy, setBusy] = useState<'approve' | 'reject' | 'revalidate' | null>(null)
  const [rejectOpen, setRejectOpen] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [actionError, setActionError] = useState<unknown>(null)
  const [revalidatedNote, setRevalidatedNote] = useState(false)
  const receiptBaseRoute = useApplicationReceiptBaseRoute(approval?.instanceId ?? '')

  // ── Load the approval (independent of the list — detail pane failures stay local)
  useEffect(() => {
    let cancelled = false
    // Reset the detail transaction before starting a new authoritative read.
    setLoading(true)
    setError(null)
    setApproval(null)
    setPlan(null)
    setActionError(null)
    setRejectOpen(false)
    setRevalidatedNote(false)
    getClient()
      .approvals.get(approvalId)
      .then((result) => {
        if (cancelled) return
        setApproval(result)
        setLoading(false)
      })
      .catch((err) => {
        if (cancelled) return
        setError(err)
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [approvalId, nonce])

  // ── Related plan (steps + rollback) — hidden honestly when not fetchable
  useEffect(() => {
    if (!approval?.planId) return
    let cancelled = false
    getClient()
      .infrastructure.getPlan(approval.instanceId, approval.planId)
      .then((result) => {
        if (!cancelled) setPlan(result)
      })
      .catch(() => {
        if (!cancelled) setPlan(null)
      })
    return () => {
      cancelled = true
    }
  }, [approval])

  const reload = useCallback(() => setNonce((n) => n + 1), [])

  const doApprove = useCallback(async () => {
    if (!approval) return
    setBusy('approve')
    setActionError(null)
    const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
    try {
      const result = await getClient().approvals.approve(approval.id, {
        expectedDigest: approval.planDigest.value,
      })
      setApproval(result.approval)
      onDecided(result.approval)
    } catch (err) {
      // Honest stale/expired surfacing: reload the current truth; the stale
      // guard or expiry notice replaces the actions.
      setActionError(err)
      reload()
    } finally {
      releaseOperationsMutation()
      setBusy(null)
    }
  }, [approval, onDecided, reload])

  const doReject = useCallback(async () => {
    if (!approval) return
    setBusy('reject')
    setActionError(null)
    const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
    try {
      const result = await getClient().approvals.reject(approval.id, {
        reason: undefined,
      })
      setApproval(result.approval)
      setRejectOpen(false)
      onDecided(result.approval)
    } catch (err) {
      setActionError(err)
      reload()
    } finally {
      releaseOperationsMutation()
      setBusy(null)
    }
  }, [approval, onDecided, reload])

  const revalidate = useCallback(async () => {
    if (!approval) return
    setBusy('revalidate')
    setActionError(null)
    try {
      const fresh = await getClient().approvals.get(approval.id)
      setApproval(fresh)
      if (isStale(fresh)) setRevalidatedNote(true)
    } catch (err) {
      setActionError(err)
    } finally {
      setBusy(null)
    }
  }, [approval])

  // ── States ─────────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex flex-col gap-3 p-4" role="status" aria-label="Loading approval">
        <span className="sr-only">Loading…</span>
        <Skeleton className="h-6 w-2/3" />
        <Skeleton className="h-4 w-1/3" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    )
  }

  if (error) {
    return (
      <ErrorState
        title="This approval couldn't be loaded"
        error={error}
        preservedNote="No decision was made."
        onRetry={reload}
      />
    )
  }

  if (!approval) return null

  const risk = riskPresentation(approval.risk)
  const status = approvalStatusPresentation(approval.status)
  const pending = approval.status === 'pending'
  const stale = isStale(approval)
  const expired = isExpired(approval, now)
  const urgent = isExpiryUrgent(approval, now)
  const targetName = exactTargetName(approval)
  const destroyClass = isDestroyClass(approval)
  const decided = !pending
  const approveRoute = decisionRoute(approval, 'approve')
  const rejectRoute = decisionRoute(approval, 'reject')

  const actionErrorMessage =
    actionError instanceof ClientError
      ? actionError.detail
        ? `${actionError.message} ${actionError.detail}`
        : actionError.message
      : actionError instanceof Error
        ? actionError.message
        : null

  return (
    <div className="flex min-h-0 flex-1 flex-col" data-testid="approval-detail">
      {/* Scrollable review content */}
      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
        {/* Header */}
        <div className="flex items-center gap-2 min-[900px]:hidden">
          <Button variant="ghost" size="sm" onClick={onBack} data-testid="back-to-list">
            <ArrowLeft aria-hidden="true" />
            All approvals
          </Button>
        </div>

        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="text-xs text-foreground-secondary">{approval.operationType}</span>
          {pending ? (
            <OperationStateLabel state="awaiting_approval" />
          ) : (
            <StatusBadge state={status.state} label={status.label} icon={status.icon} />
          )}
          <StatusBadge state={risk.state} label={risk.label} icon={risk.icon} />
        </div>

        <h2 className="mt-1 text-lg text-foreground">{approval.title}</h2>

        <dl className="mt-1 flex flex-col">
          <FactRow label="Application">
            <Link
              to={`/app/${approval.instanceId}`}
              className="inline-flex items-center gap-1 text-accent underline-offset-2 hover:underline"
            >
              {instanceName(approval.instanceId) ?? approval.instanceId}
              <ArrowUpRight className="size-3.5" aria-hidden="true" />
            </Link>
          </FactRow>
          <FactRow label="Requested">
            <TimeAgo date={approval.requestedAt} />
          </FactRow>
          <FactRow label="Expires">
            {pending ? (
              <span className={cn('inline-flex items-center gap-1', urgent && 'text-status-attention')}>
                {urgent ? <CircleAlert className="size-3.5" aria-hidden="true" /> : null}
                {expiryText(
                  approval,
                  approval.expiresAt ? formatDistanceToNowStrict(parseISO(approval.expiresAt)) : '',
                  now,
                )}
              </span>
            ) : (
              <TimeAgo date={approval.decidedAt ?? approval.expiresAt ?? approval.requestedAt} />
            )}
          </FactRow>
        </dl>

        {/* Decided result banner */}
        {decided ? (
          <div className="mt-3 rounded-md border border-border bg-surface-2 px-3 py-2" data-testid="decision-result">
            <div className="flex items-center gap-2">
              <StatusBadge state={status.state} label={status.label} icon={status.icon} />
              {approval.decidedAt ? <TimeAgo date={approval.decidedAt} /> : null}
            </div>
            {approval.decisionReason ? (
              <p className="mt-1 text-sm text-foreground">Reason: {approval.decisionReason}</p>
            ) : null}
            {approval.resultingReceiptId && receiptBaseRoute ? (
              <p className="mt-1 text-sm">
                Receipt recorded —{' '}
                <Link
                  to={`${receiptBaseRoute}/${approval.resultingReceiptId}`}
                  className="text-accent underline-offset-2 hover:underline"
                  data-testid="receipt-link"
                >
                  View receipt
                </Link>
              </p>
            ) : null}
          </div>
        ) : null}

        {/* What will happen */}
        <section aria-label="What will happen" className="mt-4">
          <h3 className="text-sm font-semibold text-foreground">What will happen</h3>
          <p className="mt-1 text-sm text-foreground">{approval.beforeSummary}</p>
          <p className="mt-1 text-sm text-foreground">{approval.afterSummary}</p>
          {plan?.rollbackNotes ? (
            <p className="mt-1 text-sm text-foreground-secondary">Rollback: {plan.rollbackNotes}</p>
          ) : null}
        </section>

        {/* Exact scope */}
        <section aria-label="Exact scope" className="mt-4">
          <h3 className="text-sm font-semibold text-foreground">Exact scope</h3>
          <dl className="mt-1 flex flex-col">
            {approval.scope.map((line, i) => {
              const idx = line.indexOf(':')
              return idx > 0 ? (
                <FactRow key={i} label={line.slice(0, idx).trim()}>
                  {line.slice(idx + 1).trim()}
                </FactRow>
              ) : (
                <FactRow key={i} label="Scope">
                  {line}
                </FactRow>
              )
            })}
            {approval.targetId ? (
              <FactRow label="Target ID">
                <span className="tnum font-mono text-xs">{approval.targetId}</span>
              </FactRow>
            ) : null}
            <FactRow label="Plan digest">
              <DigestValue value={approval.planDigest.value} testId="approval-plan-digest" />
            </FactRow>
            {approval.decision.expectedRevision !== undefined ? (
              <FactRow label="Revision">
                <span className="tnum font-mono text-xs">{approval.decision.expectedRevision}</span>
              </FactRow>
            ) : null}
            {approveRoute ? (
              <FactRow label="Approve route">
                <span className="break-all font-mono text-xs">{approveRoute}</span>
              </FactRow>
            ) : null}
            {rejectRoute ? (
              <FactRow label="Reject route">
                <span className="break-all font-mono text-xs">{rejectRoute}</span>
              </FactRow>
            ) : null}
            {stale && approval.currentDigest ? (
              <FactRow label="Current digest">
                <DigestValue value={approval.currentDigest.value} testId="approval-current-digest" />
              </FactRow>
            ) : null}
          </dl>
        </section>

        {/* Before → After */}
        <section aria-label="Before and after" className="mt-4">
          <h3 className="text-sm font-semibold text-foreground">Before → after</h3>
          {approval.diff ? (
            <div className="mt-1">
              <DiffBlock unified={approval.diff.unified} />
            </div>
          ) : (
            <div className="mt-1 grid gap-2 rounded-md border border-border sm:grid-cols-2">
              <div className="border-b border-border px-3 py-2 sm:border-b-0 sm:border-r">
                <p className="text-xs font-medium text-foreground-secondary">Current</p>
                <p className="mt-0.5 text-sm text-foreground">{approval.beforeSummary}</p>
              </div>
              <div className="px-3 py-2">
                <p className="text-xs font-medium text-foreground-secondary">After</p>
                <p className="mt-0.5 text-sm text-foreground">{approval.afterSummary}</p>
              </div>
            </div>
          )}
        </section>

        {/* Plan steps — own scroll region so Approve never scrolls out of reach */}
        {plan && plan.steps.length > 0 ? (
          <section aria-label="Plan steps" className="mt-4">
            <h3 className="text-sm font-semibold text-foreground">Plan steps</h3>
            <ol className="mt-1 max-h-56 overflow-y-auto rounded-md border border-border" data-testid="plan-steps">
              {plan.steps.map((step, i) => (
                <li key={step.id} className="flex items-start gap-2 border-b border-border px-3 py-2 last:border-b-0">
                  <span className="tnum mt-0.5 w-5 shrink-0 text-right text-xs text-foreground-tertiary">{i + 1}</span>
                  {step.kind === 'command' ? (
                    <Terminal className="mt-0.5 size-3.5 shrink-0 text-foreground-secondary" aria-hidden="true" />
                  ) : step.kind === 'check' ? (
                    <Check className="mt-0.5 size-3.5 shrink-0 text-foreground-secondary" aria-hidden="true" />
                  ) : (
                    <FileCode2 className="mt-0.5 size-3.5 shrink-0 text-foreground-secondary" aria-hidden="true" />
                  )}
                  <div className="min-w-0">
                    <p className="text-sm text-foreground">{step.title}</p>
                    <p className="tnum truncate font-mono text-xs text-foreground-secondary">{step.detail}</p>
                  </div>
                </li>
              ))}
            </ol>
            {plan.coveredByAuthorization ? (
              <p className="mt-1 text-xs text-foreground-secondary">
                Covered by an active daily-driver authorization.
              </p>
            ) : null}
          </section>
        ) : null}

        {/* Why approval is required */}
        <section aria-label="Why approval is required" className="mt-4">
          <InlineNotice tone="informational" title="Why approval is required">
            <p>{approval.whyRequired}</p>
            <Disclosure title="View policy detail" className="mt-1">
              <p className="px-2 pb-2 text-sm">
                StatePort asks before any action that changes an application or infrastructure beyond routine,
                reversible use. This request is classified {risk.label.toLowerCase()} · {approval.operationType}.
              </p>
            </Disclosure>
          </InlineNotice>
        </section>

        {/* Related links */}
        <section aria-label="Related" className="mt-4">
          <h3 className="text-sm font-semibold text-foreground">Related</h3>
          <ul className="mt-1 flex flex-col gap-1 text-sm">
            <li>
              <Link to={`/app/${approval.instanceId}`} className="text-accent underline-offset-2 hover:underline">
                Open application
              </Link>
            </li>
            <li>
              <Link
                to={`/app/${approval.instanceId}/conversation`}
                onClick={() =>
                  sendToBridge({
                    kind: 'approval',
                    instanceId: approval.instanceId,
                    approvalId: approval.id,
                  })
                }
                className="text-accent underline-offset-2 hover:underline"
              >
                {approval.relatedConversationId
                  ? 'Related conversation'
                  : 'Review approval in Conversation'}
              </Link>
            </li>
            {approval.planId ? (
              <li>
                <Link
                  to={`/app/${approval.instanceId}/workbench/deployments`}
                  className="text-accent underline-offset-2 hover:underline"
                >
                  Related plan in Deployments
                </Link>
              </li>
            ) : null}
            {receiptBaseRoute ? (
              <li>
              <Link
                to={receiptBaseRoute}
                className="text-accent underline-offset-2 hover:underline"
              >
                Previous receipts for this application
              </Link>
              </li>
            ) : null}
          </ul>
        </section>
      </div>

      {/* Sticky action region */}
      {pending ? (
        <div className="border-t border-border bg-surface px-4 py-3">
          {actionErrorMessage ? (
            <InlineNotice
              tone="danger"
              className="mb-2"
              action={
                <Button size="sm" variant="ghost" onClick={reload}>
                  Reload
                </Button>
              }
            >
              {actionErrorMessage}
            </InlineNotice>
          ) : null}

          {!approveRoute ? (
            <InlineNotice tone="blocked" title="This request cannot be decided here">
              The indexed request does not carry a supported authoritative decision route. Reload the inbox before
              taking action.
            </InlineNotice>
          ) : expired ? (
            <InlineNotice tone="attention" title="This request has expired">
              <p>It can no longer be approved. Ask the originating tool to prepare a fresh request.</p>
              <p className="mt-1">
                <Link
                  to={`/app/${approval.instanceId}/workbench/deployments`}
                  className="font-medium text-accent underline-offset-2 hover:underline"
                >
                  Request again in Deployments
                </Link>
              </p>
            </InlineNotice>
          ) : stale ? (
            <div data-testid="stale-guard">
              <InlineNotice tone="blocked" title="This plan is out of date">
                The repository changed after it was prepared. Approving the old plan is not possible.
              </InlineNotice>
              {revalidatedNote ? (
                <p className="mt-2 text-sm text-status-blocked" role="status">
                  Still out of date — the underlying state has not settled. Reject this request and prepare a new
                  plan.
                </p>
              ) : null}
              <div className="mt-2 flex items-center justify-end gap-2">
                {rejectRoute ? (
                  <Button variant="ghost" onClick={() => setRejectOpen(true)} id="reject-button">
                    Reject
                  </Button>
                ) : null}
                <Button variant="secondary" onClick={() => void revalidate()} disabled={busy !== null}>
                  {busy === 'revalidate' ? <Loader2 className="animate-spin" aria-hidden="true" /> : null}
                  Revalidate plan
                </Button>
              </div>
            </div>
          ) : (
            <div>
              <div className="flex items-center justify-end gap-2">
                {rejectOpen ? (
                  <>
                    <Button variant="ghost" onClick={() => setRejectOpen(false)} disabled={busy !== null}>
                      Cancel
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={() => void doReject()}
                      disabled={busy !== null}
                      data-testid="confirm-reject"
                    >
                      {busy === 'reject' ? <Loader2 className="animate-spin" aria-hidden="true" /> : null}
                      Reject request
                    </Button>
                  </>
                ) : (
                  <>
                    {rejectRoute ? (
                      <Button variant="ghost" onClick={() => setRejectOpen(true)} id="reject-button">
                        Reject
                      </Button>
                    ) : null}
                    <Button
                      onClick={() => {
                        if (approval.risk === 'high') setConfirmOpen(true)
                        else void doApprove()
                      }}
                      disabled={busy !== null}
                      id="approve-button"
                      data-testid="approve-button"
                    >
                      {busy === 'approve' ? <Loader2 className="animate-spin" aria-hidden="true" /> : null}
                      Approve
                    </Button>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      ) : null}

      {/* Destructive approvals: exact target restated; typed confirmation for destroy-class */}
      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={`Approve “${approval.title}”?`}
        description="This is a destructive action. Review the exact target before confirming."
        target={targetName}
        effect={approval.afterSummary}
        reversibility={plan?.rollbackNotes}
        confirmLabel="Approve"
        destructive
        requireTypedConfirmation={destroyClass ? targetName : undefined}
        onConfirm={doApprove}
      />
    </div>
  )
}
