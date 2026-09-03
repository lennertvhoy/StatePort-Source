/**
 * Standing authority surface — profiles, grants, and pause control.
 *
 * Read-only projections of the local authority store. Grant revocation
 * requires an owner directive + reason and binds the exact grant digest;
 * unpause binds the control digest. The UI collects the directive/reason and
 * confirms the digest the operator reviewed before the request lands.
 */
import { ArrowLeft, Pause, Play, RefreshCw, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { ClientError, getClient, type AuthorityGrant, type AuthorityIndex } from '@/client'
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

interface Projection {
  index: AuthorityIndex
}

type LoadStatus =
  | { kind: 'loading' }
  | { kind: 'ready'; projection: Projection }
  | { kind: 'error'; error: unknown }
  | { kind: 'unavailable'; message: string }

type Action =
  | { kind: 'idle' }
  | { kind: 'revoking'; grantId: string }
  | { kind: 'pausing'; paused: boolean }
  | { kind: 'done'; message: string; receiptId?: string | null }
  | { kind: 'failed'; error: unknown }

function isUnavailable(error: unknown): boolean {
  return (
    error instanceof ClientError &&
    (error.kind === 'unavailable' ||
      error.code === 'authority_access_denied' ||
      error.code === 'authority_state_unavailable' ||
      error.status === 403)
  )
}

function truncate(value: string): string {
  return value.length <= 24 ? value : `${value.slice(0, 12)}…${value.slice(-6)}`
}

function PauseControl({
  paused,
  controlDigest,
  action,
  onConfirm,
}: {
  paused: boolean
  controlDigest: string
  action: Action
  onConfirm: (input: { paused: boolean; ownerDirectiveId: string; reason: string; controlDigest: string }) => void
}) {
  const [open, setOpen] = useState<null | { paused: boolean }>(null)
  const [directive, setDirective] = useState('')
  const [reason, setReason] = useState('')

  const target = open?.paused
  const busy = action.kind === 'pausing'

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge state={paused ? 'blocked' : 'success'} label={paused ? 'Paused' : 'Active'} />
        <Button
          size="sm"
          variant="ghost"
          disabled={busy || !paused}
          onClick={() => {
            setDirective('')
            setReason('')
            setOpen({ paused: false })
          }}
          data-testid="authority-unpause-start"
        >
          <Play aria-hidden="true" />
          Unpause…
        </Button>
        <Button
          size="sm"
          variant="ghost"
          disabled={busy || paused}
          onClick={() => {
            setDirective('')
            setReason('')
            setOpen({ paused: true })
          }}
          data-testid="authority-pause-start"
        >
          <Pause aria-hidden="true" />
          Pause…
        </Button>
      </div>

      {open ? (
        <div className="rounded-md border border-border bg-surface p-3" data-testid="authority-pause-form">
          <p className="text-xs text-foreground-secondary">
            {target
              ? 'Pausing refuses all governed mutations until the operator unpauses. Requires an owner directive.'
              : 'Unpausing is digest-bound to the current authority control digest. Requires an owner directive.'}
          </p>
          <label className="mt-2 block text-xs font-medium text-foreground-secondary">
            Owner directive id
            <input
              className="mt-1 w-full rounded-sm border border-border bg-app px-2 py-1 font-mono text-xs"
              value={directive}
              onChange={(e) => setDirective(e.target.value)}
              placeholder="od_…"
              data-testid="authority-directive-input"
            />
          </label>
          <label className="mt-2 block text-xs font-medium text-foreground-secondary">
            Reason
            <textarea
              className="mt-1 w-full rounded-sm border border-border bg-app px-2 py-1 text-xs"
              rows={2}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              data-testid="authority-reason-input"
            />
          </label>
          <div className="mt-2 flex items-center gap-2">
            <Button
              size="sm"
              disabled={busy || !directive.trim() || !reason.trim()}
              onClick={() => {
                onConfirm({
                  paused: target ?? false,
                  ownerDirectiveId: directive.trim(),
                  reason: reason.trim(),
                  controlDigest,
                })
                setOpen(null)
              }}
              data-testid="authority-pause-confirm"
            >
              Confirm {target ? 'pause' : 'unpause'}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setOpen(null)}>
              Cancel
            </Button>
          </div>
          <div className="mt-2 font-mono text-[11px] text-foreground-secondary" data-testid="authority-control-digest">
            Reviewed control digest: {controlDigest}
          </div>
        </div>
      ) : null}
    </div>
  )
}

function GrantRow({
  grant,
  action,
  onRevoke,
}: {
  grant: AuthorityGrant
  action: Action
  onRevoke: (grantId: string, grantDigest: string, ownerDirectiveId: string, reason: string) => void
}) {
  const [directive, setDirective] = useState('')
  const [reason, setReason] = useState('')
  const [open, setOpen] = useState(false)
  const busy = action.kind === 'revoking' && action.grantId === grant.grantId
  const inactive = grant.status !== 'active'
  return (
    <tr className="align-top">
      <td className="px-3 py-3">
        <div className="font-mono text-xs text-foreground">{grant.grantId}</div>
        <div className="mt-0.5 flex items-center gap-1">
          <span className="truncate font-mono text-xs text-foreground-secondary" title={grant.grantDigest}>
            {truncate(grant.grantDigest)}
          </span>
          <CopyButton text={grant.grantDigest} label={`Copy digest for ${grant.grantId}`} />
        </div>
      </td>
      <td className="px-3 py-3">
        <StatusBadge state={inactive ? 'blocked' : 'success'} label={String(grant.status ?? 'unknown')} />
      </td>
      <td className="px-3 py-3 font-mono text-xs text-foreground-secondary">
        {String(grant.profile ?? grant.capability ?? '—')}
      </td>
      <td className="px-3 py-3 text-right">
        {open ? (
          <div className="flex flex-col items-end gap-1" data-testid={`authority-revoke-form-${grant.grantId}`}>
            <input
              className="w-48 rounded-sm border border-border bg-app px-2 py-1 font-mono text-xs"
              placeholder="od_…"
              value={directive}
              onChange={(e) => setDirective(e.target.value)}
              aria-label="Owner directive id"
            />
            <input
              className="w-48 rounded-sm border border-border bg-app px-2 py-1 text-xs"
              placeholder="Reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              aria-label="Revocation reason"
            />
            <div className="flex gap-1">
              <Button
                size="sm"
                disabled={busy || !directive.trim() || !reason.trim()}
                onClick={() => {
                  onRevoke(grant.grantId, grant.grantDigest, directive.trim(), reason.trim())
                  setOpen(false)
                }}
                data-testid={`authority-revoke-confirm-${grant.grantId}`}
              >
                Revoke
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <Button size="sm" variant="ghost" disabled={inactive} onClick={() => setOpen(true)} data-testid={`authority-revoke-start-${grant.grantId}`}>
            Revoke…
          </Button>
        )}
      </td>
    </tr>
  )
}

export default function AuthorityPage() {
  const client = getClient()
  const [nonce, setNonce] = useState(0)
  const [status, setStatus] = useState<LoadStatus>({ kind: 'loading' })
  const [action, setAction] = useState<Action>({ kind: 'idle' })

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const index = await client.authority.getIndex()
        if (!cancelled) setStatus({ kind: 'ready', projection: { index } })
      } catch (error) {
        if (cancelled) return
        setStatus(
          isUnavailable(error)
            ? { kind: 'unavailable', message: error instanceof ClientError ? error.message : String(error) }
            : { kind: 'error', error },
        )
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [client, nonce])

  const refresh = () => {
    setAction({ kind: 'idle' })
    setStatus({ kind: 'loading' })
    setNonce((value) => value + 1)
  }

  const projection = status.kind === 'ready' ? status.projection : null

  const onRevoke = async (grantId: string, grantDigest: string, directive: string, reason: string) => {
    setAction({ kind: 'revoking', grantId })
    try {
      const result = await client.authority.revokeGrant(grantId, { ownerDirectiveId: directive, reason, grantDigest })
      setAction({
        kind: 'done',
        message: `Grant ${grantId} revoked under owner directive ${directive}.`,
        receiptId: result.receiptId,
      })
      setNonce((value) => value + 1)
    } catch (error) {
      setAction({ kind: 'failed', error })
    }
  }

  const onPaused = async (input: { paused: boolean; ownerDirectiveId: string; reason: string; controlDigest: string }) => {
    setAction({ kind: 'pausing', paused: input.paused })
    try {
      const result = await client.authority.setPaused(input)
      setAction({
        kind: 'done',
        message: input.paused ? 'Authority store paused.' : 'Authority store unpaused.',
        receiptId: result.receiptId,
      })
      setNonce((value) => value + 1)
    } catch (error) {
      setAction({ kind: 'failed', error })
    }
  }

  // Pass-through adapters that read the inline form state from the DOM-driven
  // closures above. The forms own their own inputs; this hook bridges confirm.
  return (
    <div className="h-full overflow-y-auto bg-app" data-testid="authority-page">
      <div className="mx-auto flex w-full max-w-[1120px] flex-col gap-4 px-4 py-4">
        <header className="flex flex-wrap items-center gap-2">
          <div>
            <h1 className="text-xl text-foreground">Standing authority</h1>
            <p className="mt-0.5 text-sm text-foreground-secondary">
              Profiles, grants, and pause control for the local authority store.
            </p>
          </div>
          <div className="ml-auto flex items-center gap-1">
            <Button asChild size="sm" variant="ghost">
              <Link to="/updater">
                <ArrowLeft aria-hidden="true" />
                Updater
              </Link>
            </Button>
            <Button size="sm" variant="ghost" onClick={refresh}>
              <RefreshCw aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </header>

        {action.kind === 'done' ? (
          <InlineNotice tone="informational" title="Authority action completed">
            {action.message} A durable receipt was recorded by the authority store.
            {action.receiptId ? ` Receipt: ${action.receiptId}` : ''}
          </InlineNotice>
        ) : null}
        {action.kind === 'failed' ? (
          <ErrorState
            title="The authority action was refused"
            error={action.error}
            preservedNote="The authority store is unchanged by a refused request."
          />
        ) : null}

        {status.kind === 'loading' ? (
          <SkeletonRows rows={4} />
        ) : status.kind === 'unavailable' ? (
          <InlineNotice tone="blocked" title="Authority store unavailable on this host">
            {status.message} The connected service exposes no authority projections to this session.
          </InlineNotice>
        ) : status.kind === 'error' ? (
          <ErrorState
            title="Authority state couldn't be loaded"
            error={status.error}
            preservedNote="No grant, profile, or pause state was changed by reading this surface."
            onRetry={refresh}
          />
        ) : projection ? (
          <>
            <section className="flex flex-col gap-2 rounded-md border border-border bg-surface p-3">
              <h2 className="text-sm font-semibold text-foreground">Pause control</h2>
              <PauseControl
                paused={projection.index.control.paused}
                controlDigest={projection.index.reviewableDigests.controlDigest}
                action={action}
                onConfirm={(input) => void onPaused(input)}
              />
            </section>

            <section>
              <h2 className="text-sm font-semibold text-foreground">Grants</h2>
              {projection.index.activeGrants.length + projection.index.inactiveGrants.length === 0 ? (
                <div className="mt-2">
                  <EmptyState icon={ShieldCheck} title="No standing grants" description="No active grants are projected by the local authority store." />
                </div>
              ) : (
                <div className="mt-2 overflow-x-auto rounded-md border border-border bg-surface">
                  <table className="w-full min-w-[640px] text-left text-sm" data-testid="authority-grants-table">
                    <thead className="border-b border-border bg-surface-2 text-xs font-medium text-foreground-secondary">
                      <tr>
                        <th scope="col" className="px-3 py-2">Grant</th>
                        <th scope="col" className="px-3 py-2">Status</th>
                        <th scope="col" className="px-3 py-2">Profile</th>
                        <th scope="col" className="w-64 px-3 py-2"><span className="sr-only">Revoke</span></th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {[...projection.index.activeGrants, ...projection.index.inactiveGrants].map((grant) => (
                        <GrantRow
                          key={grant.grantId}
                          grant={grant}
                          action={action}
                          onRevoke={(grantId, grantDigest, directive, reason) => void onRevoke(grantId, grantDigest, directive, reason)}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <Disclosure title="Authority policy (raw projection)">
              <pre className="overflow-x-auto px-3 pb-3 pt-1 text-xs text-foreground-secondary" data-testid="authority-policy-raw">
{JSON.stringify(
  {
                    defaultProfile: projection.index.policy.defaultProfile,
                    policyDigest: projection.index.policy.policyDigest,
                    hardDeny: projection.index.policy.hardDeny,
                    mergeRequirements: projection.index.policy.mergeRequirements,
                    subagentDefaultDeny: projection.index.policy.subagentDefaultDeny,
  },
  null,
  2,
)}
        </pre>
            </Disclosure>
          </>
        ) : null}
      </div>
    </div>
  )
}
