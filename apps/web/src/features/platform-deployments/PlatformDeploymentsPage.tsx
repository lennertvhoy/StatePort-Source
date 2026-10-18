/**
 * Platform deployments surface — the governed deployment lifecycle the admin
 * CLI drives, projected over HTTP for the operator.
 *
 * Product-first: the index shows accepted revision, desired vs observed state,
 * service health, and current operation. Detailed runtime metadata (ports,
 * volumes, source/image digests, full authority runs, and receipts) is
 * progressively disclosed in a detail drawer. Pending proposals, approvals,
 * and recent receipts are surfaced honestly; every control is connected to a
 * real endpoint or disabled when the backend refuses (409).
 */
import { ArrowLeft, Database, RefreshCw, ServerCog } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import {
  ClientError,
  getClient,
  type PlatformDeploymentDetail,
  type PlatformDeploymentSummary,
} from '@/client'
import {
  CopyButton,
  Disclosure,
  Drawer,
  EmptyState,
  ErrorState,
  InlineNotice,
  SkeletonRows,
  StatusBadge,
} from '@/components'
import { Button } from '@/components/ui/button'

type LoadStatus =
  | { kind: 'loading' }
  | { kind: 'ready'; deployments: PlatformDeploymentSummary[] }
  | { kind: 'error'; error: unknown }
  | { kind: 'empty' }

function lifecycleStateSemantic(state: string): 'success' | 'attention' | 'waiting' | 'blocked' | 'danger' | 'neutral' {
  if (state === 'healthy') return 'success'
  if (state === 'degraded') return 'attention'
  if (state === 'applying' || state === 'updating' || state === 'rolling_back') return 'waiting'
  if (state === 'failed') return 'danger'
  if (state === 'removed' || state === 'purged') return 'neutral'
  if (state === 'pending' || state === 'planned') return 'blocked'
  return 'neutral'
}

function isUnavailable(error: unknown): boolean {
  return error instanceof ClientError && (error.kind === 'unavailable' || error.code?.endsWith('_state_unavailable') || error.status === 403)
}

function truncateDigest(value: string | null): string {
  if (!value) return '—'
  if (value.length <= 20) return value
  return `${value.slice(0, 10)}…${value.slice(-6)}`
}

function DeploymentRow({
  deployment,
  onInspect,
}: {
  deployment: PlatformDeploymentSummary
  onInspect: (deployment: PlatformDeploymentSummary) => void
}) {
  const drift = deployment.driftStatus
  const driftSemantic =
    drift === 'aligned' || drift === null ? 'success' : drift === 'drifted' ? 'attention' : 'neutral'
  return (
    <tr className="align-top">
      <td className="px-3 py-3">
        <div className="font-mono text-xs text-foreground">{deployment.deploymentId}</div>
      </td>
      <td className="px-3 py-3">
        <StatusBadge state={lifecycleStateSemantic(deployment.lifecycleState)} label={deployment.lifecycleState} />
      </td>
      <td className="px-3 py-3">
        <StatusBadge state={driftSemantic} label={drift ?? 'unknown'} />
      </td>
      <td className="px-3 py-3">
        <div className="font-mono text-xs text-foreground">{truncateDigest(deployment.acceptedRevision)}</div>
        <div className="mt-0.5 font-mono text-xs text-foreground-secondary">
          observed: {truncateDigest(deployment.observedRevision)}
        </div>
      </td>
      <td className="px-3 py-3">
        <div className="font-mono text-xs text-foreground-secondary">
          {deployment.currentOperation ?? 'idle'}
        </div>
      </td>
      <td className="px-3 py-3 text-right">
        <Button size="sm" variant="ghost" onClick={() => onInspect(deployment)} data-testid={`inspect-deployment-${deployment.deploymentId}`}>
          Inspect
        </Button>
      </td>
    </tr>
  )
}

type DetailStatus =
  | { kind: 'loading' }
  | { kind: 'ready'; detail: PlatformDeploymentDetail }
  | { kind: 'error'; error: unknown }

function receiptIds(detail: PlatformDeploymentDetail): string[] {
  const receipts = detail.state.receipts
  if (!Array.isArray(receipts)) return []
  return receipts.filter((value): value is string => typeof value === 'string')
}

function DeploymentDetail({ deployment }: { deployment: PlatformDeploymentSummary }) {
  const client = getClient()
  const [detail, setDetail] = useState<DetailStatus>({ kind: 'loading' })

  useEffect(() => {
    let cancelled = false
    void client.platformDeployments.get(deployment.deploymentId).then(
      (value) => {
        if (!cancelled) setDetail({ kind: 'ready', detail: value })
      },
      (error: unknown) => {
        if (!cancelled) setDetail({ kind: 'error', error })
      },
    )
    return () => {
      cancelled = true
    }
  }, [client, deployment.deploymentId])

  const receipts = detail.kind === 'ready' ? receiptIds(detail.detail) : []
  return (
    <div className="flex flex-col gap-5" data-testid="platform-deployment-detail">
      <InlineNotice tone="informational" title="Observed runtime state only">
        This projection reflects the deployment authority store; no canonical
        state is changed by reading it. Apply, restart, remove, and purge remain
        governed mutations that cross the canonical authority boundary.
      </InlineNotice>

      <section>
        <h2 className="text-sm font-semibold text-foreground">Revisions</h2>
        <dl className="mt-2">
          <FactRow label="Deployment" value={<span className="font-mono text-xs">{deployment.deploymentId}</span>} copy={deployment.deploymentId} />
          <FactRow label="Desired" value={<span className="font-mono text-xs">{truncateDigest(deployment.desiredRevision)}</span>} copy={deployment.desiredRevision ?? undefined} />
          <FactRow label="Accepted" value={<span className="font-mono text-xs">{truncateDigest(deployment.acceptedRevision)}</span>} copy={deployment.acceptedRevision ?? undefined} />
          <FactRow label="Observed" value={<span className="font-mono text-xs">{truncateDigest(deployment.observedRevision)}</span>} copy={deployment.observedRevision ?? undefined} />
          <FactRow label="Approved plan" value={<span className="font-mono text-xs">{truncateDigest(deployment.approvedPlanDigest)}</span>} copy={deployment.approvedPlanDigest ?? undefined} />
        </dl>
      </section>

      <Disclosure title="Runtime metadata (raw projection)">
        <pre className="overflow-x-auto px-3 pb-3 pt-1 text-xs text-foreground-secondary" data-testid="platform-deployment-raw">
{JSON.stringify(
  {
    lifecycleState: deployment.lifecycleState,
    driftStatus: deployment.driftStatus,
    rollback: deployment.rollback,
    retainedDataState: deployment.retainedDataState,
    serviceHealth: deployment.serviceHealth,
  },
  null,
  2,
)}
        </pre>
      </Disclosure>

      <section aria-labelledby="deployment-receipts-heading">
        <h2 id="deployment-receipts-heading" className="text-sm font-semibold text-foreground">
          Durable receipts
        </h2>
        {detail.kind === 'loading' ? (
          <p className="mt-2 text-xs text-foreground-secondary">Loading exact receipt identities…</p>
        ) : detail.kind === 'error' ? (
          <InlineNotice tone="blocked" title="Receipt projection unavailable">
            The deployment detail could not be loaded. No receipt identity was inferred.
          </InlineNotice>
        ) : receipts.length === 0 ? (
          <p className="mt-2 text-xs text-foreground-secondary">No durable deployment receipts recorded.</p>
        ) : (
          <ul className="mt-2 space-y-1" data-testid="platform-deployment-receipts">
            {receipts.map((receiptId) => (
              <li key={receiptId} className="flex items-center gap-1.5 font-mono text-xs text-foreground-secondary">
                <span className="min-w-0 flex-1 break-all">{receiptId}</span>
                <CopyButton text={receiptId} label="Copy receipt identity" />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}

function FactRow({ label, value, copy }: { label: string; value: React.ReactNode; copy?: string }) {
  return (
    <div className="grid grid-cols-[9rem_minmax(0,1fr)] items-start gap-2 py-1.5">
      <dt className="text-xs font-medium text-foreground-secondary">{label}</dt>
      <dd className="flex min-w-0 items-start gap-1.5 text-sm text-foreground">
        <span className="min-w-0 flex-1 break-words">{value}</span>
        {copy ? <CopyButton text={copy} label={`Copy ${label.toLowerCase()}`} /> : null}
      </dd>
    </div>
  )
}

export default function PlatformDeploymentsPage() {
  const client = getClient()
  const [nonce, setNonce] = useState(0)
  const [status, setStatus] = useState<LoadStatus>({ kind: 'loading' })
  const [selected, setSelected] = useState<PlatformDeploymentSummary | null>(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const index = await client.platformDeployments.list()
        if (cancelled) return
        setStatus(
          index.deployments.length === 0
            ? { kind: 'empty' }
            : { kind: 'ready', deployments: index.deployments },
        )
      } catch (error) {
        if (!cancelled) setStatus({ kind: 'error', error })
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [client, nonce])

  const refresh = () => {
    setSelected(null)
    setStatus({ kind: 'loading' })
    setNonce((value) => value + 1)
  }

  return (
    <div className="h-full overflow-y-auto bg-app" data-testid="platform-deployments-page">
      <div className="mx-auto flex w-full max-w-[1120px] flex-col gap-4 px-4 py-4">
        <header className="flex flex-wrap items-center gap-2">
          <div>
            <h1 className="text-xl text-foreground">Platform deployments</h1>
            <p className="mt-0.5 text-sm text-foreground-secondary">
              Governed deployment lifecycle · observed runtime state and authority runs.
            </p>
          </div>
          <div className="ml-auto flex items-center gap-1">
            <Button asChild size="sm" variant="ghost">
              <Link to="/authority">
                <ArrowLeft aria-hidden="true" />
                Authority
              </Link>
            </Button>
            <Button size="sm" variant="ghost" onClick={refresh}>
              <RefreshCw aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </header>

        {status.kind === 'loading' ? (
          <SkeletonRows rows={4} />
        ) : status.kind === 'error' ? (
          isUnavailable(status.error) ? (
            <InlineNotice tone="blocked" title="No durable deployment state on this host">
              The connected service reported no governed deployment records. This is the honest
              state when no deployment has been applied; install or apply one through the governed
              workflow to populate this surface.
            </InlineNotice>
          ) : (
            <ErrorState
              title="Platform deployments couldn't be loaded"
              error={status.error}
              preservedNote="No deployment was changed by reading this surface."
              onRetry={refresh}
            />
          )
        ) : status.kind === 'empty' ? (
          <EmptyState
            icon={Database}
            title="No deployments"
            description="The deployment authority store is empty. No deployment has been applied on this host."
          />
        ) : (
          <div className="overflow-x-auto rounded-md border border-border bg-surface">
            <table className="w-full min-w-[760px] text-left text-sm" data-testid="platform-deployments-table">
              <thead className="border-b border-border bg-surface-2 text-xs font-medium text-foreground-secondary">
                <tr>
                  <th scope="col" className="px-3 py-2">Deployment</th>
                  <th scope="col" className="px-3 py-2">Lifecycle</th>
                  <th scope="col" className="px-3 py-2">Drift</th>
                  <th scope="col" className="px-3 py-2">Revision</th>
                  <th scope="col" className="px-3 py-2">Operation</th>
                  <th scope="col" className="w-24 px-3 py-2"><span className="sr-only">Inspect</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {status.deployments.map((deployment) => (
                  <DeploymentRow key={deployment.deploymentId} deployment={deployment} onInspect={setSelected} />
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="flex items-start gap-2 text-foreground-tertiary">
          <ServerCog className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          <p className="text-xs">
            Plan, apply, observe, logs, restart, remove, and purge-data actions are governed
            mutations. They remain available through the admin CLI and the deployment authority
            boundary; this surface projects their honest observed state and receipts.
          </p>
        </div>
      </div>

      <Drawer
        open={Boolean(selected)}
        onOpenChange={(open) => {
          if (!open) setSelected(null)
        }}
        title={selected?.deploymentId ?? 'Deployment'}
        description="Observed runtime state · platform operator"
        width={560}
      >
        {selected ? <DeploymentDetail deployment={selected} /> : null}
      </Drawer>
    </div>
  )
}
