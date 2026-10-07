/**
 * Preview routes surface — the loopback-only reverse-proxy registry.
 *
 * Register/revoke/rewrite are receipted mutations. The derived status
 * (active/expired/revoked) comes from the backend projection; one active
 * route per capsule/service is enforced server-side. Rewrite is the atomic
 * rollback path: a route is rebound to a new revision and port in one locked,
 * receipted write.
 */
import { ArrowLeft, Globe, RefreshCw, Route as RouteIcon } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { ClientError, getClient, type PreviewRoute, type PreviewRouteIndex, type PreviewRouteMutation } from '@/client'
import {
  CopyButton,
  EmptyState,
  ErrorState,
  InlineNotice,
  SkeletonRows,
  StatusBadge,
} from '@/components'
import { Button } from '@/components/ui/button'

type ReadStatus =
  | { kind: 'loading' }
  | { kind: 'ready'; routes: PreviewRoute[]; availability?: PreviewRouteIndex['availability'] }
  | { kind: 'error'; error: unknown }

type Mutation =
  | { kind: 'idle' }
  | { kind: 'working'; what: string }
  | { kind: 'done'; message: string; receipt: PreviewRouteMutation['receipt'] }
  | { kind: 'failed'; error: unknown }

function statusSemantic(status: PreviewRoute['status']): 'success' | 'neutral' | 'blocked' {
  if (status === 'active') return 'success'
  if (status === 'expired') return 'neutral'
  return 'blocked'
}

function isAccessDenied(error: unknown): boolean {
  return (
    error instanceof ClientError &&
    (error.code === 'preview_route_access_denied' || error.status === 403)
  )
}

function truncate(value: string): string {
  return value.length <= 24 ? value : `${value.slice(0, 12)}…${value.slice(-6)}`
}

function RegisterForm({
  busy,
  onRegister,
}: {
  busy: boolean
  onRegister: (input: {
    capsuleId: string
    serviceId: string
    revisionDigest: string
    upstreamPort: number
    ttlSeconds: number
  }) => void
}) {
  const [open, setOpen] = useState(false)
  const [capsuleId, setCapsuleId] = useState('')
  const [serviceId, setServiceId] = useState('')
  const [revisionDigest, setRevisionDigest] = useState('')
  const [upstreamPort, setUpstreamPort] = useState('')
  const [ttlSeconds, setTtlSeconds] = useState('3600')

  const valid =
    capsuleId.trim() &&
    serviceId.trim() &&
    /^sha256:[0-9a-f]{64}$/.test(revisionDigest.trim()) &&
    /^\d+$/.test(upstreamPort) &&
    Number(upstreamPort) >= 1 &&
    Number(upstreamPort) <= 65535 &&
    /^\d+$/.test(ttlSeconds) &&
    Number(ttlSeconds) >= 1 && Number(ttlSeconds) <= 2592000

  if (!open) {
    return (
      <Button size="sm" onClick={() => setOpen(true)} data-testid="preview-route-register-start">
        Register route…
      </Button>
    )
  }

  return (
    <div className="flex flex-col gap-2 rounded-md border border-border bg-surface p-3" data-testid="preview-route-register-form">
      <p className="text-xs text-foreground-secondary">
        Routes bind an opaque (capsule, service, revision) triple to a loopback upstream. One active
        route per capsule/service; non-loopback upstreams are impossible by construction.
      </p>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <label className="text-xs font-medium text-foreground-secondary">
          Capsule id
          <input className="mt-1 w-full rounded-sm border border-border bg-app px-2 py-1 font-mono text-xs" value={capsuleId} onChange={(e) => setCapsuleId(e.target.value)} placeholder="capsule_web" />
        </label>
        <label className="text-xs font-medium text-foreground-secondary">
          Service id
          <input className="mt-1 w-full rounded-sm border border-border bg-app px-2 py-1 font-mono text-xs" value={serviceId} onChange={(e) => setServiceId(e.target.value)} placeholder="web" />
        </label>
        <label className="text-xs font-medium text-foreground-secondary sm:col-span-2">
          Revision digest
          <input className="mt-1 w-full rounded-sm border border-border bg-app px-2 py-1 font-mono text-xs" value={revisionDigest} onChange={(e) => setRevisionDigest(e.target.value)} placeholder="sha256:…" />
        </label>
        <label className="text-xs font-medium text-foreground-secondary">
          Upstream port
          <input className="mt-1 w-full rounded-sm border border-border bg-app px-2 py-1 font-mono text-xs" value={upstreamPort} onChange={(e) => setUpstreamPort(e.target.value)} placeholder="8080" />
        </label>
        <label className="text-xs font-medium text-foreground-secondary">
          TTL (seconds)
          <input className="mt-1 w-full rounded-sm border border-border bg-app px-2 py-1 font-mono text-xs" value={ttlSeconds} onChange={(e) => setTtlSeconds(e.target.value)} placeholder="3600" />
        </label>
      </div>
      <div className="flex items-center gap-2">
        <Button
          size="sm"
          disabled={busy || !valid}
          onClick={() => {
            onRegister({
              capsuleId: capsuleId.trim(),
              serviceId: serviceId.trim(),
              revisionDigest: revisionDigest.trim(),
              upstreamPort: Number(upstreamPort),
              ttlSeconds: Number(ttlSeconds),
            })
            setOpen(false)
            setCapsuleId('')
            setServiceId('')
            setRevisionDigest('')
            setUpstreamPort('')
            setTtlSeconds('3600')
          }}
          data-testid="preview-route-register-confirm"
        >
          Register
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>
          Cancel
        </Button>
      </div>
    </div>
  )
}

function RouteRow({
  route,
  mutation,
  onRevoke,
  onRewrite,
}: {
  route: PreviewRoute
  mutation: Mutation
  onRevoke: (routeId: string, reason: string, expectedRouteDigest: string) => void
  onRewrite: (routeId: string, revisionDigest: string, upstreamPort: number, expectedRouteDigest: string) => void
}) {
  const [revoking, setRevoking] = useState(false)
  const [reason, setReason] = useState('')
  const [rewriting, setRewriting] = useState(false)
  const [newDigest, setNewDigest] = useState('')
  const [newPort, setNewPort] = useState('')
  const [reviewedDigest, setReviewedDigest] = useState(route.routeDigest)
  const busy = mutation.kind === 'working'
  const disabled = route.status !== 'active'

  return (
    <tr className="align-top">
      <td className="px-3 py-3">
        <div className="font-mono text-xs text-foreground">{route.capsuleId}/{route.serviceId}</div>
        <div className="mt-0.5 flex items-center gap-1">
          <span className="truncate font-mono text-xs text-foreground-secondary" title={route.revisionDigest}>
            {truncate(route.revisionDigest)}
          </span>
          <CopyButton text={route.revisionDigest} label={`Copy revision for ${route.routeId}`} />
        </div>
      </td>
      <td className="px-3 py-3 font-mono text-xs text-foreground-secondary">
        {route.upstream.host}:{route.upstream.port}
        {route.status === 'active' && route.previewPath ? (
          <div className="mt-1 flex items-center gap-1">
            <a href={route.previewPath} target="_blank" rel="noopener noreferrer" className="underline">Open preview</a>
            <CopyButton text={route.previewPath} label={`Copy preview path for ${route.routeId}`} />
          </div>
        ) : null}
      </td>
      <td className="px-3 py-3">
        <StatusBadge state={statusSemantic(route.status)} label={route.status} />
        <div className="mt-0.5 text-xs text-foreground-tertiary">expires {route.expiresAt}</div>
      </td>
      <td className="px-3 py-3 text-right">
        {revoking ? (
          <div className="flex flex-col items-end gap-1" data-testid={`preview-route-revoke-form-${route.routeId}`}>
            <input
              className="w-44 rounded-sm border border-border bg-app px-2 py-1 text-xs"
              placeholder="Reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              aria-label="Revocation reason"
            />
            <div className="flex gap-1">
              <Button
                size="sm"
                disabled={busy || !reason.trim() || disabled}
                onClick={() => {
                  onRevoke(route.routeId, reason.trim(), reviewedDigest)
                  setRevoking(false)
                  setReason('')
                }}
                data-testid={`preview-route-revoke-confirm-${route.routeId}`}
              >
                Revoke
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setRevoking(false)}>
                Cancel
              </Button>
            </div>
          </div>
        ) : rewriting ? (
          <div className="flex flex-col items-end gap-1" data-testid={`preview-route-rewrite-form-${route.routeId}`}>
            <input
              className="w-48 rounded-sm border border-border bg-app px-2 py-1 font-mono text-xs"
              placeholder="sha256:… (new revision)"
              value={newDigest}
              onChange={(e) => setNewDigest(e.target.value)}
              aria-label="New revision digest"
            />
            <input
              className="w-48 rounded-sm border border-border bg-app px-2 py-1 font-mono text-xs"
              placeholder="new port"
              value={newPort}
              onChange={(e) => setNewPort(e.target.value)}
              aria-label="New upstream port"
            />
            <div className="flex gap-1">
              <Button
                size="sm"
                disabled={busy || !/^sha256:[0-9a-f]{64}$/.test(newDigest.trim()) || !/^\d+$/.test(newPort) || Number(newPort) < 1 || Number(newPort) > 65535 || disabled}
                onClick={() => {
                  onRewrite(route.routeId, newDigest.trim(), Number(newPort), reviewedDigest)
                  setRewriting(false)
                  setNewDigest('')
                  setNewPort('')
                }}
                data-testid={`preview-route-rewrite-confirm-${route.routeId}`}
              >
                Rewrite
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setRewriting(false)}>
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex justify-end gap-1">
            <Button size="sm" variant="ghost" disabled={disabled} onClick={() => { setReviewedDigest(route.routeDigest); setRewriting(true) }} data-testid={`preview-route-rewrite-start-${route.routeId}`}>
              Rewrite…
            </Button>
            <Button size="sm" variant="ghost" disabled={disabled} onClick={() => { setReviewedDigest(route.routeDigest); setRevoking(true) }} data-testid={`preview-route-revoke-start-${route.routeId}`}>
              Revoke…
            </Button>
          </div>
        )}
      </td>
    </tr>
  )
}

export default function PreviewRoutesPage() {
  const client = getClient()
  const [nonce, setNonce] = useState(0)
  const [status, setStatus] = useState<ReadStatus>({ kind: 'loading' })
  const [mutation, setMutation] = useState<Mutation>({ kind: 'idle' })

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const index = await client.previewRoutes.list()
        if (!cancelled) setStatus({ kind: 'ready', routes: index.routes, availability: index.availability })
      } catch (error) {
        if (!cancelled) {
          setStatus(
            isAccessDenied(error)
              ? { kind: 'error', error }
              : { kind: 'error', error },
          )
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
    setStatus({ kind: 'loading' })
    setNonce((value) => value + 1)
  }

  const withRefresh = async (what: string, fn: () => Promise<PreviewRouteMutation>, done: string) => {
    setMutation({ kind: 'working', what })
    try {
      const result = await fn()
      setMutation({ kind: 'done', message: done, receipt: result.receipt })
      setNonce((value) => value + 1)
    } catch (error) {
      setMutation({ kind: 'failed', error })
    }
  }

  const routes = status.kind === 'ready' ? status.routes : null
  const availability = status.kind === 'ready' ? status.availability : undefined
  const previewsDisabled = availability?.status === 'disabled'

  return (
    <div className="h-full overflow-y-auto bg-app" data-testid="preview-routes-page">
      <div className="mx-auto flex w-full max-w-[1120px] flex-col gap-4 px-4 py-4">
        <header className="flex flex-wrap items-center gap-2">
          <div>
            <h1 className="text-xl text-foreground">Preview routes</h1>
            <p className="mt-0.5 text-sm text-foreground-secondary">
              Loopback-only reverse-proxy bindings · session-gated, receipted mutations.
            </p>
          </div>
          <div className="ml-auto flex items-center gap-1">
            <Button asChild size="sm" variant="ghost">
              <Link to="/deployments">
                <ArrowLeft aria-hidden="true" />
                Deployments
              </Link>
            </Button>
            <Button size="sm" variant="ghost" onClick={refresh}>
              <RefreshCw aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </header>

        {previewsDisabled ? (
          <InlineNotice tone="blocked" title="Preview unavailable — disabled for security">
            <span data-testid="preview-routes-disabled">
              {availability?.message ??
                'Previews are disabled because preview content would share the StatePort origin.'}{' '}
              {availability?.nextAction ??
                'Wait for a StatePort release that serves previews from a credential-isolated origin.'}
            </span>
          </InlineNotice>
        ) : null}

        {mutation.kind === 'done' ? (
          <InlineNotice tone="informational" title="Preview route action completed">
            {mutation.message}
            <details className="mt-2" data-testid="preview-route-receipt">
              <summary>View receipt · {mutation.receipt.event}</summary>
              <p>{mutation.receipt.actor} · {mutation.receipt.createdAt}</p>
              <p className="font-mono text-xs">{mutation.receipt.receiptId}</p>
              <CopyButton text={JSON.stringify(mutation.receipt, null, 2)} label="Copy preview receipt" />
            </details>
          </InlineNotice>
        ) : null}
        {mutation.kind === 'failed' ? (
          <ErrorState
            title="The preview route action was refused"
            error={mutation.error}
            preservedNote="The operation did not return verified completion. Refresh the registry before retrying; interrupted writes may require recovery."
          />
        ) : null}

        {routes && !previewsDisabled ? (
          <RegisterForm
            busy={mutation.kind === 'working'}
            onRegister={(input) =>
              void withRefresh(
                'register',
                () => client.previewRoutes.register(input),
                `Route registered for ${input.capsuleId}/${input.serviceId}.`,
              )
            }
          />
        ) : null}

        {status.kind === 'loading' ? (
          <SkeletonRows rows={3} />
        ) : status.kind === 'error' ? (
          isAccessDenied(status.error) ? (
            <InlineNotice tone="blocked" title="Preview route access denied">
              The connected service denied preview-route access to this session.
            </InlineNotice>
          ) : (
            <ErrorState
              title="Preview routes couldn't be loaded"
              error={status.error}
              preservedNote="No route binding was changed by reading this surface."
              onRetry={refresh}
            />
          )
        ) : routes && !previewsDisabled ? (
          routes.length === 0 ? (
            <EmptyState icon={RouteIcon} title="No preview routes" description="The loopback preview registry is empty." />
          ) : (
            <div className="overflow-x-auto rounded-md border border-border bg-surface">
              <table className="w-full min-w-[720px] text-left text-sm" data-testid="preview-routes-table">
                <thead className="border-b border-border bg-surface-2 text-xs font-medium text-foreground-secondary">
                  <tr>
                    <th scope="col" className="px-3 py-2">Capsule / service</th>
                    <th scope="col" className="px-3 py-2">Upstream</th>
                    <th scope="col" className="px-3 py-2">Status</th>
                    <th scope="col" className="w-72 px-3 py-2"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {routes.map((route) => (
                    <RouteRow
                      key={route.routeId}
                      route={route}
                      mutation={mutation}
                      onRevoke={(routeId, reason, expectedRouteDigest) =>
                        void withRefresh(
                          'revoke',
                          () => client.previewRoutes.revoke(routeId, { reason, expectedRouteDigest }),
                          `Route ${routeId} revoked.`,
                        )
                      }
                      onRewrite={(routeId, revisionDigest, upstreamPort, expectedRouteDigest) =>
                        void withRefresh(
                          'rewrite',
                          () => client.previewRoutes.rewrite(routeId, { revisionDigest, upstreamPort, expectedRouteDigest }),
                          `Route ${routeId} atomically rewritten.`,
                        )
                      }
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : null}

        {!previewsDisabled ? (
          <div className="flex items-start gap-2 text-foreground-tertiary">
            <Globe className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            <p className="text-xs">
              Proxied requests require the operator session, but StatePort identity never crosses the
              gateway: inbound Cookie/Origin/CSRF headers are stripped and upstream Set-Cookie values
              are rewritten to host-only cookies scoped to the route path.
            </p>
          </div>
        ) : null}
      </div>
    </div>
  )
}
