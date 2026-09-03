/**
 * OperationCenter (design.md §14) — drawer listing long-running operations
 * from client.operations: stage, progress, elapsed, Pause/Cancel when
 * supported, details (log lines) on demand. Minimized operations never
 * become invisible (topbar spinner + status bar item persist).
 */
import { Activity, CirclePause, CircleStop, ListChecks } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import type { OperationRecord } from '@/client'
import { getClient } from '@/client'
import { Disclosure, Drawer, EmptyState, OperationStateLabel, TimeAgo } from '@/components'
import { Button } from '@/components/ui/button'
import { useApplicationReceiptBaseRoute } from '@/features/application-experience/useApplicationReceiptRoute'
import { cn } from '@/lib/utils'
import { useSessionStore } from '@/state'

import { useInstanceName } from './data'
import { useShellUiStore } from './shellUi'

function ProgressBar({ percent }: { percent?: number }) {
  if (percent === undefined) {
    // Indeterminate: 1.2 s slide of a 40 % highlight across a 2 px track (§6.2).
    return (
      <div className="relative h-0.5 w-full overflow-hidden rounded-xs bg-active" aria-label="Progress indeterminate">
        <div className="absolute inset-y-0 w-2/5 animate-[indeterminate_1.2s_linear_infinite] bg-accent" />
      </div>
    )
  }
  return (
    <div
      className="h-0.5 w-full overflow-hidden rounded-xs bg-active"
      role="progressbar"
      aria-valuenow={Math.round(percent)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div className="h-full bg-accent transition-[width] duration-fast linear" style={{ width: `${percent}%` }} />
    </div>
  )
}

function OperationRow({ record }: { record: OperationRecord }) {
  const appName = useInstanceName(record.instanceId)
  const receiptBaseRoute = useApplicationReceiptBaseRoute(record.instanceId)
  const upsertOperation = useSessionStore((s) => s.upsertOperation)
  const [busy, setBusy] = useState(false)

  const act = async (action: 'pause' | 'cancel') => {
    setBusy(true)
    try {
      const updated =
        action === 'pause'
          ? await getClient().operations.pause(record.id)
          : await getClient().operations.cancel(record.id)
      upsertOperation(updated)
    } catch {
      // The next poll reconciles; the action stays honest by not pretending.
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="flex flex-col gap-1.5 border-b border-border px-1 py-3 last:border-b-0" data-testid="operation-row">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-foreground">{record.title}</p>
          <p className="text-xs text-foreground-secondary">
            {appName ?? record.instanceId} · {record.stageLabel}
          </p>
        </div>
        <OperationStateLabel state={record.state} startedAt={record.startedAt} className="shrink-0 text-xs" />
      </div>
      <ProgressBar percent={record.progressPercent} />
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-foreground-tertiary">
          Started <TimeAgo date={record.startedAt} />
        </span>
        <span className="flex items-center gap-1">
          {record.canPause && record.state === 'running' ? (
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => void act('pause')}>
              <CirclePause aria-hidden="true" />
              Pause
            </Button>
          ) : null}
          {record.canCancel && ['running', 'queued', 'preparing', 'validating', 'paused'].includes(record.state) ? (
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => void act('cancel')}>
              <CircleStop aria-hidden="true" />
              Cancel
            </Button>
          ) : null}
          {record.relatedReceiptId && receiptBaseRoute ? (
            <Button size="sm" variant="ghost" asChild>
              <Link to={`${receiptBaseRoute}/${record.relatedReceiptId}`}>Receipt</Link>
            </Button>
          ) : null}
        </span>
      </div>
      {record.error ? <p className="text-xs text-status-danger">{record.error}</p> : null}
      {record.log.length > 0 ? (
        <Disclosure title={`Details · ${record.log.length} log lines`}>
          <pre className="max-h-40 overflow-auto whitespace-pre-wrap rounded-sm bg-sunken p-2 font-mono text-xs text-foreground-secondary">
            {record.log.join('\n')}
          </pre>
        </Disclosure>
      ) : null}
    </li>
  )
}

export function OperationCenter() {
  const open = useShellUiStore((s) => s.operationCenterOpen)
  const setOpen = useShellUiStore((s) => s.setOperationCenterOpen)
  const operations = useSessionStore((s) => s.operations)
  const operationsError = useSessionStore((s) => s.operationsError)

  return (
    <Drawer
      open={open}
      onOpenChange={setOpen}
      title={
        <span className="inline-flex items-center gap-2">
          <Activity className="size-4 text-foreground-secondary" aria-hidden="true" />
          Operation center
        </span>
      }
      description="Long-running operations across applications"
      width={480}
    >
      {operationsError && operations.length > 0 ? (
        <p className="pb-2 text-xs text-foreground-tertiary" data-testid="operations-stale">
          Refresh failed — showing the last known operations.
        </p>
      ) : null}
      {operations.length === 0 ? (
        operationsError ? (
          <EmptyState
            icon={ListChecks}
            title="Operations unavailable"
            description="The operation list could not be loaded. This is not confirmation that nothing is running — check the local service and try again."
          />
        ) : (
          <EmptyState
            icon={ListChecks}
            title="No operations"
            description="Nothing is running right now. Long-running work will appear here with live progress."
          />
        )
      ) : (
        <ul className={cn('flex flex-col')} aria-label="Operations">
          {operations.map((record) => (
            <OperationRow key={record.id} record={record} />
          ))}
        </ul>
      )}
    </Drawer>
  )
}
