/**
 * Installed updater surface — status, policy, and rollback projections.
 *
 * Read-only observations of the installed updater state. Policy mutation is
 * digest-bound to the observed status digest. Rollback *apply* is NEVER
 * exposed over HTTP — it remains an installed-authority CLI operation. The
 * surface shows that boundary honestly as a limitation, not a fake button.
 */
import { ArrowLeft, RefreshCw, Terminal } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import {
  ClientError,
  getClient,
  type UpdaterPolicyProjection,
  type UpdaterRollbackPlanResult,
  type UpdaterRollbackProjection,
  type UpdaterStatus,
} from '@/client'
import {
  CopyButton,
  Disclosure,
  EmptyState,
  ErrorState,
  InlineNotice,
  SkeletonRows,
  StatusBadge,
} from '@/components'
import { Button } from '@/components/ui/button'

type ReadStatus =
  | { kind: 'loading' }
  | { kind: 'ready'; status: UpdaterStatus; policy: UpdaterPolicyProjection; rollback: UpdaterRollbackProjection }
  | { kind: 'error'; error: unknown }
  | { kind: 'unavailable' }

type Mutation =
  | { kind: 'idle' }
  | { kind: 'working'; what: string }
  | { kind: 'done'; message: string }
  | { kind: 'failed'; error: unknown }

function isUnavailable(error: unknown): boolean {
  return (
    error instanceof ClientError &&
    (error.kind === 'unavailable' ||
      error.code === 'updater_state_unavailable' ||
      error.code === 'updater_access_denied' ||
      error.code === 'control_plane_trust_invalid' ||
      error.status === 403)
  )
}

function PolicyEditor({
  policy,
  statusDigest,
  mutation,
  onApply,
}: {
  policy: Record<string, unknown>
  statusDigest: string
  mutation: Mutation
  onApply: (policy: Record<string, unknown>) => void
}) {
  const [draft, setDraft] = useState<string>(() => JSON.stringify(policy, null, 2))
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setDraft(JSON.stringify(policy, null, 2))
    setError(null)
  }, [policy])

  const commit = () => {
    let parsed: Record<string, unknown>
    try {
      const value = JSON.parse(draft)
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error('policy must be a JSON object')
      }
      parsed = value as Record<string, unknown>
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      return
    }
    setError(null)
    onApply(parsed)
  }

  const busy = mutation.kind === 'working' && mutation.what === 'policy'
  return (
    <div className="flex flex-col gap-2" data-testid="updater-policy-editor">
      <div className="flex items-center gap-2">
        <CopyButton text={statusDigest} label="Copy status digest" />
        <span className="font-mono text-xs text-foreground-secondary">
          bound to status digest {statusDigest.slice(0, 18)}…
        </span>
      </div>
      <textarea
        className="min-h-[120px] w-full rounded-sm border border-border bg-app p-2 font-mono text-xs"
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        spellCheck={false}
        aria-label="Update policy JSON"
      />
      {error ? <p className="text-xs text-status-danger">{error}</p> : null}
      <div className="flex items-center gap-2">
        <Button size="sm" disabled={busy} onClick={commit} data-testid="updater-policy-apply">
          {busy ? 'Applying…' : 'Apply policy'}
        </Button>
        <span className="text-xs text-foreground-tertiary">
          The service binds the policy digest; a stale status digest is refused.
        </span>
      </div>
    </div>
  )
}

export default function UpdaterPage() {
  const client = getClient()
  const [nonce, setNonce] = useState(0)
  const [status, setStatus] = useState<ReadStatus>({ kind: 'loading' })
  const [mutation, setMutation] = useState<Mutation>({ kind: 'idle' })
  const [rollbackPlan, setRollbackPlan] = useState<UpdaterRollbackPlanResult | null>(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [s, p, r] = await Promise.all([
          client.updater.getStatus(),
          client.updater.getPolicy(),
          client.updater.getRollback(),
        ])
        if (!cancelled) setStatus({ kind: 'ready', status: s, policy: p, rollback: r })
      } catch (error) {
        if (!cancelled) {
          setStatus(isUnavailable(error) ? { kind: 'unavailable' } : { kind: 'error', error })
        }
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [client, nonce])

  const refresh = () => {
    setMutation({ kind: 'idle' })
    setRollbackPlan(null)
    setStatus({ kind: 'loading' })
    setNonce((value) => value + 1)
  }

  const applyPolicy = async (policy: Record<string, unknown>) => {
    if (status.kind !== 'ready') return
    setMutation({ kind: 'working', what: 'policy' })
    try {
      await client.updater.setPolicy({ policy, expectedStatusDigest: status.policy.statusDigest })
      setMutation({ kind: 'done', message: 'Update policy applied through canonical installed authority.' })
      setRollbackPlan(null)
      setNonce((value) => value + 1)
    } catch (error) {
      setMutation({ kind: 'failed', error })
    }
  }

  const planRollback = async () => {
    if (status.kind !== 'ready') return
    setMutation({ kind: 'working', what: 'rollback' })
    try {
      const plan = await client.updater.planRollback({ expectedStatusDigest: status.rollback.statusDigest })
      setRollbackPlan(plan)
      setMutation({ kind: 'idle' })
    } catch (error) {
      setMutation({ kind: 'failed', error })
    }
  }

  const ready = status.kind === 'ready' ? status : null

  return (
    <div className="h-full overflow-y-auto bg-app" data-testid="updater-page">
      <div className="mx-auto flex w-full max-w-[1120px] flex-col gap-4 px-4 py-4">
        <header className="flex flex-wrap items-center gap-2">
          <div>
            <h1 className="text-xl text-foreground">Installed updater</h1>
            <p className="mt-0.5 text-sm text-foreground-secondary">
              Status, policy, and rollback projections of the installed updater state.
            </p>
          </div>
          <div className="ml-auto flex items-center gap-1">
            <Button asChild size="sm" variant="ghost">
              <Link to="/preview-routes">
                <ArrowLeft aria-hidden="true" />
                Preview routes
              </Link>
            </Button>
            <Button size="sm" variant="ghost" onClick={refresh}>
              <RefreshCw aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </header>

        {mutation.kind === 'done' ? (
          <InlineNotice tone="informational" title="Updater action completed">
            {mutation.message}
          </InlineNotice>
        ) : null}
        {mutation.kind === 'failed' ? (
          <ErrorState
            title="The updater action was refused"
            error={mutation.error}
            preservedNote="The installed updater state is unchanged by a refused request."
          />
        ) : null}

        {status.kind === 'loading' ? (
          <SkeletonRows rows={4} />
        ) : status.kind === 'unavailable' ? (
          <InlineNotice tone="blocked" title="No installed updater state on this host">
            The connected service reported no durable updater state. This is the honest state when
            no updater has been installed; the projections become available once the installed
            updater records its status.
          </InlineNotice>
        ) : status.kind === 'error' ? (
          <ErrorState
            title="Updater state couldn't be loaded"
            error={status.error}
            preservedNote="No updater state was changed by reading this surface."
            onRetry={refresh}
          />
        ) : ready ? (
          <>
            <InlineNotice tone="attention" title="Rollback apply is reserved to installed authority">
              Applying a staged rollback remains an installed-authority CLI operation
              (<code className="font-mono">stateport-updater apply/rollback</code>). It is never
              exposed over HTTP; the button below only <strong>plans</strong> the rollback.
            </InlineNotice>

            <section className="flex flex-col gap-2 rounded-md border border-border bg-surface p-3">
              <div className="flex items-center gap-2">
                <StatusBadge
                  state={ready.rollback.rollbackAvailable ? 'success' : 'neutral'}
                  label={ready.rollback.rollbackAvailable ? 'Rollback available' : 'No rollback available'}
                />
                <span className="text-xs text-foreground-secondary">phase: {ready.rollback.phase}</span>
                {ready.rollback.pendingPhase ? (
                  <span className="text-xs text-status-attention">pending: {ready.rollback.pendingPhase}</span>
                ) : null}
              </div>
              <Button
                size="sm"
                disabled={!ready.rollback.rollbackAvailable || ready.rollback.pendingPhase !== null}
                onClick={() => void planRollback()}
                data-testid="updater-plan-rollback"
              >
                Plan rollback
              </Button>
              {rollbackPlan ? (
                <div className="rounded-sm border border-border bg-app p-2" data-testid="updater-rollback-plan">
                  <p className="text-xs font-medium text-status-attention">
                    Apply boundary: <code className="font-mono">{rollbackPlan.applyBoundary}</code>
                  </p>
                  <p className="mt-1 text-xs text-foreground-secondary">{rollbackPlan.note}</p>
                  <Disclosure title="Staged rollback plan (raw)">
                    <pre className="overflow-x-auto px-3 pb-3 pt-1 text-xs text-foreground-secondary">
{JSON.stringify(rollbackPlan.plan, null, 2)}
                    </pre>
                  </Disclosure>
                  <div className="mt-2 flex items-start gap-2 rounded-sm bg-status-attention-bg p-2 text-xs text-status-attention">
                    <Terminal className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
                    <span>
                      To apply this rollback, run the installed updater CLI on the host. The HTTP
                      surface intentionally stops at the staged plan.
                    </span>
                  </div>
                </div>
              ) : null}
            </section>

            <section className="flex flex-col gap-2 rounded-md border border-border bg-surface p-3">
              <h2 className="text-sm font-semibold text-foreground">Update policy</h2>
              <PolicyEditor
                policy={ready.policy.policy}
                statusDigest={ready.policy.statusDigest}
                mutation={mutation}
                onApply={(policy) => void applyPolicy(policy)}
              />
            </section>

            <Disclosure title="Installed updater status (raw projection)">
              <pre className="overflow-x-auto px-3 pb-3 pt-1 text-xs text-foreground-secondary" data-testid="updater-status-raw">
{JSON.stringify(ready.status, null, 2)}
              </pre>
            </Disclosure>
          </>
        ) : (
          <EmptyState icon={RefreshCw} title="Updater" description="No updater state." />
        )}
      </div>
    </div>
  )
}
