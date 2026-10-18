/**
 * AuthorizationCard — the daily-driver authorization panel
 * (design/infrastructure.md §6, brief "Daily-driver authorization").
 *
 * Rendered ONLY when a valid target exists — the grant flow never appears in
 * the blocked state. The card always explains: what it covers, what it does
 * not cover, which target it applies to, when it expires, and which receipt
 * created it. Revocation appears only when the adapter exposes a durable,
 * receipted transition.
 */
import { CircleCheck, Receipt, ShieldCheck, ShieldEllipsis, ShieldOff, ShieldQuestion } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import type { AuthorizationGrant, InfrastructureTarget } from '@/client'
import { getClient } from '@/client'
import { ConfirmDialog, StatusBadge, TimeAgo } from '@/components'
import { Button } from '@/components/ui/button'

import { OPERATION_META } from './infrastructureModel'

const APPROVAL_POLL_MS = 3_000

export interface AuthorizationCardProps {
  instanceId: string
  target: InfrastructureTarget
  grant: AuthorizationGrant | null
  busy: boolean
  canRevoke: boolean
  onPropose: () => Promise<void>
  onActivate: (approvalId: string) => Promise<void>
  onRevoke: () => Promise<unknown>
}

export function AuthorizationCard({ instanceId, target, grant, busy, canRevoke, onPropose, onActivate, onRevoke }: AuthorizationCardProps) {
  const navigate = useNavigate()
  const [revokeOpen, setRevokeOpen] = useState(false)
  const [grantApproval, setGrantApproval] = useState<{ id: string; approved: boolean; forGrant: string } | null>(null)
  const [error, setError] = useState<string | null>(null)

  // A proposed grant waits on its approval in the Approvals inbox; poll it so
  // the Activate action appears as soon as the decision is recorded. State is
  // only set asynchronously here (never synchronously in the effect body).
  useEffect(() => {
    if (grant?.status !== 'proposed') return
    const forGrant = grant.id
    let cancelled = false
    const tick = async () => {
      try {
        const pending = await getClient().approvals.list({ instanceId, status: 'pending' })
        if (cancelled) return
        const approval = pending.find((a) => a.kind === 'authorization_grant')
        if (approval) {
          setGrantApproval({ id: approval.id, approved: false, forGrant })
          return
        }
        // No pending grant approval — either approved already or rejected.
        const decided = await getClient().approvals.list({ instanceId })
        if (cancelled) return
        const latest = decided
          .filter((a) => a.kind === 'authorization_grant')
          .sort((a, b) => b.requestedAt.localeCompare(a.requestedAt))[0]
        if (latest?.status === 'approved') {
          setGrantApproval({ id: latest.id, approved: true, forGrant })
        }
      } catch {
        /* transient — next poll retries */
      }
    }
    void tick()
    const timer = window.setInterval(tick, APPROVAL_POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [instanceId, grant?.status, grant?.id])

  // Only trust the approval lookup for the grant it was made for.
  const approval = grant && grantApproval?.forGrant === grant.id ? grantApproval : null
  const pendingApprovalId = approval && !approval.approved ? approval.id : null
  const activateApprovalId = approval?.approved ? approval.id : null

  const wrap = (action: () => Promise<unknown>) => async () => {
    setError(null)
    try {
      await action()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const active = grant?.status === 'active'
  const proposed = grant?.status === 'proposed'

  return (
    <section
      className="rounded-md border border-border bg-surface"
      aria-label="Daily-driver authorization"
      data-testid="authorization-card"
    >
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        {active ? (
          <ShieldCheck className="size-4 text-status-success" aria-hidden="true" />
        ) : (
          <ShieldEllipsis className="size-4 text-foreground-secondary" aria-hidden="true" />
        )}
        <h3 className="text-sm font-semibold text-foreground">Daily-driver authorization</h3>
        {active ? <StatusBadge state="success" label="Active" icon={ShieldCheck} /> : null}
        {proposed ? <StatusBadge state="waiting" label="Proposed" icon={ShieldEllipsis} /> : null}
        {grant?.status === 'expired' ? <StatusBadge state="neutral" label="Expired" /> : null}
        {grant?.status === 'revoked' ? <StatusBadge state="neutral" label="Revoked" /> : null}
        {!grant ? <StatusBadge state="neutral" label="None" /> : null}
      </div>

      <div className="flex flex-col gap-3 px-3 py-3">
        <p className="text-xs text-foreground-secondary">
          One identity-bound local authorization can cover routine operations on this exact target, so each
          start or health check does not need its own approval. Destructive operations are never covered.
        </p>

        {/* Coverage is always visible — even before a grant exists, so the
            decision to propose one is informed. */}
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-sm border border-border px-2.5 py-2" data-testid="authorization-covers">
            <p className="text-xs font-medium text-foreground-secondary">Covers</p>
            <ul className="mt-1 flex flex-col gap-0.5">
              {(['observe', 'validate', 'health_check', 'start', 'stop', 'restart'] as const).map((op) => (
                <li key={op} className="flex items-center gap-1.5 text-xs text-foreground">
                  <CircleCheck className="size-3 text-status-success" aria-hidden="true" />
                  {op === 'stop' ? 'Graceful stop' : OPERATION_META[op].label}
                </li>
              ))}
            </ul>
          </div>
          <div className="rounded-sm border border-border px-2.5 py-2" data-testid="authorization-excludes">
            <p className="text-xs font-medium text-foreground-secondary">Does not cover</p>
            <ul className="mt-1 flex flex-col gap-0.5">
              {(grant?.doesNotCover ?? DEFAULT_EXCLUSIONS).map((line) => (
                <li key={line} className="flex items-center gap-1.5 text-xs text-foreground">
                  <ShieldOff className="size-3 text-status-danger" aria-hidden="true" />
                  {line}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Target + expiry + provenance */}
        {grant ? (
          <dl className="grid gap-x-4 gap-y-1 text-xs sm:grid-cols-2" data-testid="authorization-facts">
            <div className="flex items-baseline gap-2">
              <dt className="shrink-0 font-medium text-foreground-secondary">Target</dt>
              <dd className="tnum truncate font-mono text-foreground">{target.name}</dd>
            </div>
            <div className="flex items-baseline gap-2">
              <dt className="shrink-0 font-medium text-foreground-secondary">Expires</dt>
              <dd className="text-foreground">
                {grant.expiresAt ? <TimeAgo date={grant.expiresAt} /> : 'when target identity changes'}
              </dd>
            </div>
            {grant.createdByReceiptId ? (
              <div className="flex items-baseline gap-2">
                <dt className="shrink-0 font-medium text-foreground-secondary">Created by</dt>
                <dd>
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 text-accent hover:underline"
                    onClick={() =>
                      void navigate(`/app/${instanceId}/workbench/receipts/${grant.createdByReceiptId}`)
                    }
                  >
                    <Receipt className="size-3" aria-hidden="true" />
                    Grant receipt
                  </button>
                </dd>
              </div>
            ) : null}
            {grant.revokeReceiptId ? (
              <div className="flex items-baseline gap-2">
                <dt className="shrink-0 font-medium text-foreground-secondary">Revoked by</dt>
                <dd>
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 text-accent hover:underline"
                    onClick={() =>
                      void navigate(`/app/${instanceId}/workbench/receipts/${grant.revokeReceiptId}`)
                    }
                  >
                    <Receipt className="size-3" aria-hidden="true" />
                    Revocation receipt
                  </button>
                </dd>
              </div>
            ) : null}
          </dl>
        ) : null}

        {error ? (
          <p className="text-xs text-status-danger" role="alert">
            {error}
          </p>
        ) : null}
      </div>

      {/* Actions per grant state */}
      <div className="flex flex-wrap items-center gap-1.5 border-t border-border px-3 py-2">
        {!grant || grant.status === 'expired' || grant.status === 'revoked' ? (
          <Button size="sm" onClick={wrap(onPropose)} disabled={busy} data-testid="authorization-propose">
            <ShieldEllipsis aria-hidden="true" />
            Propose authorization
          </Button>
        ) : null}
        {proposed && !activateApprovalId ? (
          <>
            <p className="flex items-center gap-1.5 text-xs text-status-waiting">
              <ShieldQuestion className="size-3.5" aria-hidden="true" />
              Proposed — review the grant in Approvals to activate it.
            </p>
            {pendingApprovalId ? (
              <Button
                size="sm"
                variant="outline"
                onClick={() => void navigate(`/approvals/${pendingApprovalId}`)}
                data-testid="authorization-review-grant"
              >
                <ShieldQuestion aria-hidden="true" />
                Review grant
              </Button>
            ) : null}
          </>
        ) : null}
        {proposed && activateApprovalId ? (
          <Button size="sm" onClick={wrap(() => onActivate(activateApprovalId))} disabled={busy} data-testid="authorization-activate">
            <ShieldCheck aria-hidden="true" />
            Activate authorization
          </Button>
        ) : null}
        {active && canRevoke ? (
          <Button
            size="sm"
            variant="outline"
            onClick={() => setRevokeOpen(true)}
            disabled={busy}
            data-testid="authorization-revoke"
            className="border-status-danger-border text-status-danger hover:bg-status-danger-bg"
          >
            <ShieldOff aria-hidden="true" />
            Revoke
          </Button>
        ) : null}
        {active && !canRevoke ? (
          <p className="text-xs text-foreground-secondary" data-testid="authorization-revoke-unavailable">
            Revocation is not available through the connected service.
          </p>
        ) : null}
      </div>

      <ConfirmDialog
        open={canRevoke && revokeOpen}
        onOpenChange={setRevokeOpen}
        title="Revoke daily-driver authorization?"
        description="Routine operations on this target will each need their own approval again."
        target={target.name}
        effect="The authorization is revoked immediately; a revocation receipt is recorded."
        reversibility="Reversible — you can propose a new authorization at any time."
        confirmLabel="Revoke authorization"
        destructive
        requireTypedConfirmation={target.name}
        onConfirm={wrap(onRevoke)}
      />
    </section>
  )
}

const DEFAULT_EXCLUSIONS = [
  'Destroy the virtual machine',
  'Change target identity',
  'Change network scope',
  'Expand filesystem scope',
  'Broaden terminal access',
  'Run an unreviewed arbitrary command',
]
