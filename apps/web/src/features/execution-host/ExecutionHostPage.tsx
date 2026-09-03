/**
 * Execution Host — real lifecycle of the sanctioned execution-host daemon.
 *
 * This surface renders ONLY bounded daemon receipts through the sanctioned
 * control-plane proxy: execution-host health, the default developer
 * workspace's lifecycle, its bounded logs, and typed lifecycle controls.
 * Every displayed state comes from the live daemon or is explicitly
 * unavailable — no mock data is ever presented as execution.
 */
import { useEffect, useState } from 'react'

import { getClient } from '@/client'
import type {
  ExecutionHostOperationReceipt,
  ExecutionHostResult,
  ExecutionHostStatus,
} from '@/client'
import { useServiceStatusPolling } from '@/shell/data'

const DEFAULT_WORKSPACE = 'default-dev'
const J1_EXEC_ARGV = ['/bin/sh', '-lc', "printf 'stateport-j1-ok\\n'"]
const POLL_MS = 4000

interface LifecycleState {
  state: string
  exitStatus?: string | number | null
  engineStatus?: string
  imageDigest?: string | null
  logs?: string
}

interface ReceiptState {
  receiptId: string
  action: string
  status: string
  createdAt: string
  payloadDigest?: string
}

function lifecycleFromResult(result: ExecutionHostResult): LifecycleState {
  const record = (result.result ?? {}) as Record<string, unknown>
  return {
    state: typeof record.state === 'string' ? record.state : 'unknown',
    exitStatus: (record.exitStatus as string | number | null) ?? undefined,
    engineStatus: typeof record.engineStatus === 'string' ? record.engineStatus : undefined,
    imageDigest: result.observed?.imageDigest ?? null,
    logs: typeof record.output === 'string' ? record.output : undefined,
  }
}

export default function ExecutionHostPage() {
  const [status, setStatus] = useState<ExecutionHostStatus | null>(null)
  const [lifecycle, setLifecycle] = useState<LifecycleState | null>(null)
  const [refusal, setRefusal] = useState<{ reason?: string; detail?: string } | null>(null)
  const [receipt, setReceipt] = useState<ReceiptState | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useServiceStatusPolling()

  const client = getClient()

  const refresh = async () => {
    try {
      const current = await client.executionHost.status()
      setStatus(current)
      if (current.status === 'available') {
        const listed = await client.executionHost.listWorkloads()
        if (!listed.accepted) {
          setRefusal(listed.refusal ?? { reason: 'execution_inventory_unavailable' })
          setLifecycle({ state: 'unavailable' })
          await readReceipts()
          setError(null)
          return
        }
        const found = Array.isArray(listed.result)
          ? (listed.result as Array<{ workloadId?: string }>).find(
              (item) => item.workloadId === DEFAULT_WORKSPACE,
            )
          : undefined
        if (found) {
          setLifecycle(await readLifecycle())
        } else {
          setRefusal(null)
          setLifecycle({ state: 'not_created' })
        }
        await readReceipts()
      } else {
        setLifecycle(null)
      }
      setError(null)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : 'refresh failed')
    }
  }

  const readReceipts = async () => {
    const index = await client.executionHost.listReceipts()
    const latest = index.receipts[0]
    if (latest) setReceipt(latest)
  }

  const readLifecycle = async (): Promise<LifecycleState> => {
    const result = await client.executionHost.workloadStatus(DEFAULT_WORKSPACE)
    if (!result.accepted) {
      setRefusal(result.refusal ?? { reason: 'execution_unavailable' })
      return { state: 'unavailable' }
    }
    setRefusal(null)
    return lifecycleFromResult(result)
  }

  const readLogs = async () => {
    if (!lifecycle || lifecycle.state === 'not_created') return
    setBusy(true)
    try {
      const result = await client.executionHost.workloadLogs(DEFAULT_WORKSPACE)
      if (result.accepted) {
        const record = (result.result ?? {}) as Record<string, unknown>
        setLifecycle((prior) => ({
          ...(prior ?? { state: 'unknown' }),
          logs: typeof record.output === 'string' ? record.output : '(no log output)',
        }))
      } else {
        setRefusal(result.refusal ?? { reason: 'execution_unavailable' })
      }
    } finally {
      setBusy(false)
    }
  }

  const mutate = async (operation: 'create' | 'start' | 'stop' | 'cancel' | 'remove' | 'exec') => {
    setBusy(true)
    try {
      let result: ExecutionHostResult
      if (operation === 'create') result = await client.executionHost.createDefaultWorkload()
      else if (operation === 'start') result = await client.executionHost.startWorkload(DEFAULT_WORKSPACE)
      else if (operation === 'stop') result = await client.executionHost.stopWorkload(DEFAULT_WORKSPACE)
      else if (operation === 'cancel') result = await client.executionHost.cancelWorkload(DEFAULT_WORKSPACE)
      else if (operation === 'remove') result = await client.executionHost.removeWorkload(DEFAULT_WORKSPACE)
      else result = await client.executionHost.execWorkload(DEFAULT_WORKSPACE, J1_EXEC_ARGV)
      if (result.accepted) {
        setRefusal(null)
        if (result.receipt) setReceipt(result.receipt as ExecutionHostOperationReceipt)
        const next = await readLifecycle()
        const record = (result.result ?? {}) as Record<string, unknown>
        setLifecycle({
          ...next,
          logs:
            operation === 'exec' && typeof record.output === 'string'
              ? record.output
              : next.logs,
        })
        await readReceipts()
      } else {
        setRefusal(result.refusal ?? { reason: 'execution_unavailable' })
        if (result.receipt) setReceipt(result.receipt as ExecutionHostOperationReceipt)
      }
      setError(null)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : 'operation failed')
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), POLL_MS)
    return () => window.clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const available = status?.status === 'available'
  const state = lifecycle?.state ?? 'unknown'

  return (
    <div className="flex h-full flex-col gap-4 p-6">
      <div>
        <h1 className="text-xl font-semibold">{'Execution host'}</h1>
        <p className="text-sm text-foreground-tertiary">
          {'Real lifecycle of the sanctioned execution-host daemon through the control-plane proxy.'}
        </p>
      </div>

      {error ? <div className="rounded border border-danger/40 p-3 text-sm">{error}</div> : null}

      <section className="rounded border p-4">
        <h2 className="text-sm font-medium">{'Daemon health'}</h2>
        <div className="mt-2 flex flex-wrap gap-3 text-sm">
          <span>
            <strong>{'Status'}:</strong>{' '}
            {available ? 'available' : status?.reason ?? 'unavailable'}
          </span>
          {status?.contractVersion !== undefined ? (
            <span>
              <strong>{'Contract'}:</strong>{' '}
              v{status.contractVersion}
            </span>
          ) : null}
          {status?.engine ? (
            <span>
              <strong>{'Engine'}:</strong> {status.engine}
              {status.engineVersion ? ` ${status.engineVersion}` : ''}
            </span>
          ) : null}
          <span>
            <strong>{'Grant'}:</strong>{' '}
            {status?.grantBound ? status.grantId ?? 'bound' : 'not bound'}
          </span>
        </div>
        {status?.detail ? <p className="mt-2 text-xs text-foreground-tertiary">{status.detail}</p> : null}
      </section>

      {available ? (
        <section className="rounded border p-4">
          <h2 className="text-sm font-medium">
            {'Workspace'}{' '}
            <code className="rounded bg-surface px-1">{DEFAULT_WORKSPACE}</code>
          </h2>
          <div className="mt-2 flex flex-wrap gap-3 text-sm">
            <span>
              <strong>{'Lifecycle'}:</strong> {state}
            </span>
            {lifecycle?.imageDigest ? (
              <span>
                <strong>{'Image'}:</strong>{' '}
                <code className="rounded bg-surface px-1">{lifecycle.imageDigest.slice(0, 19)}…</code>
              </span>
            ) : null}
            {lifecycle?.engineStatus ? (
              <span>
                <strong>{'Container'}:</strong>{' '}
                {lifecycle.engineStatus}
              </span>
            ) : null}
            {lifecycle?.exitStatus !== undefined && lifecycle.exitStatus !== null ? (
              <span>
                <strong>{'Exit'}:</strong> {String(lifecycle.exitStatus)}
              </span>
            ) : null}
          </div>
          {refusal ? (
            <p className="mt-2 text-xs text-warning">
              {refusal.reason}
              {refusal.detail ? `: ${refusal.detail}` : ''}
            </p>
          ) : null}
          <div className="mt-3 flex flex-wrap gap-2">
            {state === 'not_created' || state === 'removed' ? (
              <button
                className="rounded border px-3 py-1 text-sm disabled:opacity-50"
                disabled={busy}
                onClick={() => void mutate('create')}
              >
                {'Create default workspace'}
              </button>
            ) : (
              <>
                <button
                  className="rounded border px-3 py-1 text-sm disabled:opacity-50"
                  disabled={busy || state === 'running'}
                  onClick={() => void mutate('start')}
                >
                  {'Start'}
                </button>
                <button
                  className="rounded border px-3 py-1 text-sm disabled:opacity-50"
                  disabled={busy || state !== 'running'}
                  onClick={() => void mutate('stop')}
                >
                  {'Stop'}
                </button>
                <button
                  className="rounded border px-3 py-1 text-sm disabled:opacity-50"
                  disabled={busy}
                  onClick={() => void mutate('cancel')}
                >
                  {'Cancel'}
                </button>
                <button
                  className="rounded border px-3 py-1 text-sm disabled:opacity-50"
                  disabled={busy}
                  onClick={() => void mutate('remove')}
                >
                  {'Remove'}
                </button>
                <button
                  className="rounded border px-3 py-1 text-sm disabled:opacity-50"
                  disabled={busy || state !== 'running'}
                  onClick={() => void mutate('exec')}
                >
                  {'Run verification'}
                </button>
              </>
            )}
            <button
              className="rounded border px-3 py-1 text-sm disabled:opacity-50"
              disabled={busy || state === 'not_created' || state === 'removed'}
              onClick={() => void readLogs()}
            >
              {'Logs'}
            </button>
          </div>
          {lifecycle?.logs !== undefined ? (
            <pre className="mt-3 max-h-64 overflow-auto rounded bg-surface p-3 text-xs">
              {lifecycle.logs}
            </pre>
          ) : null}
          {receipt ? (
            <div className="mt-3 rounded bg-surface p-3 text-xs" data-testid="execution-host-receipt">
              <strong>{'Persisted receipt'}:</strong>{' '}
              <code>{receipt.receiptId}</code>{' '}
              <span>{receipt.action}</span>{' '}
              <span>{receipt.status}</span>{' '}
              <time>{receipt.createdAt}</time>
            </div>
          ) : null}
        </section>
      ) : (
        <section className="rounded border p-4">
          <p className="text-sm">
            {'Execution runtime is unavailable. Install with a provisioned execution host to enable real container workloads.'}
          </p>
        </section>
      )}
    </div>
  )
}
