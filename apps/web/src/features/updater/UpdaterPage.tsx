/**
 * Installed updater surface: read-only status, policy and rollback
 * availability of the installed updater.
 *
 * Nothing here changes the updater. Changing the update policy and applying a
 * rollback are installed-authority operations on the host
 * (`stateport-updater`); this page only reports what the updater recorded.
 * The service shows it to the platform operator role only, so a local-user
 * session sees one plain sentence saying so instead of a page of controls
 * that would be refused.
 */
import { RefreshCw } from 'lucide-react'
import { useEffect, useState } from 'react'

import {
  ClientError,
  getClient,
  type UpdaterPolicyProjection,
  type UpdaterRollbackProjection,
  type UpdaterStatus,
} from '@/client'
import {
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
  | { kind: 'operator_only' }
  | { kind: 'no_state' }

function isOperatorOnly(error: unknown): boolean {
  return (
    error instanceof ClientError &&
    (error.code === 'updater_access_denied' || error.status === 403)
  )
}

function isNoState(error: unknown): boolean {
  return (
    error instanceof ClientError &&
    (error.kind === 'unavailable' ||
      error.code === 'updater_state_unavailable' ||
      error.code === 'control_plane_trust_invalid')
  )
}

export default function UpdaterPage() {
  const client = getClient()
  const [nonce, setNonce] = useState(0)
  const [status, setStatus] = useState<ReadStatus>({ kind: 'loading' })

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
        if (cancelled) return
        setStatus(
          isOperatorOnly(error)
            ? { kind: 'operator_only' }
            : isNoState(error)
              ? { kind: 'no_state' }
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
    setStatus({ kind: 'loading' })
    setNonce((value) => value + 1)
  }

  const ready = status.kind === 'ready' ? status : null

  return (
    <div className="h-full overflow-y-auto bg-app" data-testid="updater-page">
      <div className="mx-auto flex w-full max-w-[1120px] flex-col gap-4 px-4 py-4">
        <header className="flex flex-wrap items-center gap-2">
          <div>
            <h1 className="text-xl text-foreground">Installed updater</h1>
            <p className="mt-0.5 text-sm text-foreground-secondary">
              Read-only status of the installed updater: its policy and whether a rollback is available.
            </p>
          </div>
          <div className="ml-auto flex items-center gap-1">
            <Button size="sm" variant="ghost" onClick={refresh}>
              <RefreshCw aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </header>

        {status.kind === 'loading' ? (
          <SkeletonRows rows={4} />
        ) : status.kind === 'operator_only' ? (
          <InlineNotice tone="blocked" title="Updater status is not available to this session">
            The service shows updater status to the platform operator role only, and this session is a
            local-user session. Nothing is wrong with your installation.
          </InlineNotice>
        ) : status.kind === 'no_state' ? (
          <InlineNotice tone="blocked" title="No installed updater state on this host">
            The service reported no durable updater state. That is the normal state when no updater has
            recorded its status yet.
          </InlineNotice>
        ) : status.kind === 'error' ? (
          <ErrorState
            title="Updater state couldn't be loaded"
            error={status.error}
            preservedNote="Reading this page changes nothing."
            onRetry={refresh}
          />
        ) : ready ? (
          <>
            <InlineNotice tone="informational" title="Changes are made on the host">
              Changing the update policy or applying a rollback is done with the installed updater
              command on the host (<code className="font-mono">stateport-updater</code>). This page
              cannot do either.
            </InlineNotice>

            <section className="flex flex-col gap-2 rounded-md border border-border bg-surface p-3">
              <h2 className="text-sm font-semibold text-foreground">Rollback</h2>
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
            </section>

            <section className="flex flex-col gap-2 rounded-md border border-border bg-surface p-3">
              <h2 className="text-sm font-semibold text-foreground">Update policy</h2>
              <pre
                className="overflow-x-auto rounded-sm border border-border bg-app p-2 font-mono text-xs text-foreground-secondary"
                data-testid="updater-policy-raw"
              >
{JSON.stringify(ready.policy.policy, null, 2)}
              </pre>
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
