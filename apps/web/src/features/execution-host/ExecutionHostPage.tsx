/** Grant-scoped workload observations and controls through the sanctioned proxy. */
import { useCallback, useEffect, useRef, useState } from 'react'
import { getClient } from '@/client'
import type { ExecutionHostOperationReceipt, ExecutionHostResult, ExecutionHostStatus } from '@/client'
import { ConfirmDialog } from '@/components'
import { Button } from '@/components/ui/button'

interface Workload {
  workloadId: string
  kind?: string
  state: string
  imageDigest?: string
  engineStatus?: string
  lastActivityAt?: string
}
type Action = 'start' | 'stop' | 'cancel' | 'remove'

function inventory(result: ExecutionHostResult): Workload[] {
  const record = result.result
  const values = record && !Array.isArray(record) ? record.workloads : undefined
  if (!Array.isArray(values) || values.some((item) => !item || typeof item.workloadId !== 'string' || typeof item.state !== 'string')) {
    throw new Error('The service returned an invalid workload inventory. Retry or inspect diagnostics.')
  }
  return values as Workload[]
}

export default function ExecutionHostPage() {
  const client = getClient().executionHost
  const [status, setStatus] = useState<ExecutionHostStatus | null>(null)
  const [workloads, setWorkloads] = useState<Workload[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [refusal, setRefusal] = useState<string | null>(null)
  const [receipt, setReceipt] = useState<ExecutionHostOperationReceipt | null>(null)
  const [logs, setLogs] = useState<{ workloadId: string; output: string; byteCount: number; outputByteBound: number; truncated: boolean } | null>(null)
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState<{ action: Action; workload: Workload } | null>(null)
  const alive = useRef(true)
  const refreshing = useRef(false)

  const refresh = useCallback(async () => {
    if (refreshing.current) return
    refreshing.current = true
    try {
      const current = await client.status()
      if (!alive.current) return
      setStatus(current)
      if (current.status !== 'available') { setWorkloads(null); setError(null); return }
      const listed = await client.listWorkloads()
      if (!alive.current) return
      if (!listed.accepted) {
        setWorkloads(null)
        setError(`Inventory refused: ${listed.refusal?.reason ?? 'unavailable'}. ${listed.refusal?.detail ?? 'Review the execution-host grant.'}`)
        return
      }
      setWorkloads(inventory(listed))
      setError(null)
    } catch {
      if (alive.current) { setWorkloads(null); setError('Workload inventory is unavailable. Retry or inspect service diagnostics.') }
    } finally { refreshing.current = false }
  }, [client])

  useEffect(() => {
    alive.current = true
    void refresh()
    const timer = window.setInterval(() => void refresh(), 4000)
    return () => { alive.current = false; window.clearInterval(timer) }
  }, [refresh])

  async function perform(action: Action | 'create', workloadId?: string) {
    setBusy(true)
    setRefusal(null)
    try {
      const result = action === 'create' ? await client.createDefaultWorkload()
        : action === 'start' ? await client.startWorkload(workloadId!)
        : action === 'stop' ? await client.stopWorkload(workloadId!)
        : action === 'cancel' ? await client.cancelWorkload(workloadId!)
        : await client.removeWorkload(workloadId!)
      if (!alive.current) return
      if (result.receipt) setReceipt(result.receipt)
      if (!result.accepted) setRefusal(`${workloadId ?? 'Provisioned workspace'}: ${result.refusal?.reason ?? 'Operation refused'}. ${result.refusal?.detail ?? 'Review the grant and current workload state before retrying.'}`)
      await refresh()
    } catch {
      if (alive.current) setRefusal(`${workloadId ?? 'Provisioned workspace'}: the operation could not be confirmed. Refresh its state before retrying.`)
    } finally { if (alive.current) { setBusy(false); setPending(null) } }
  }

  async function readLogs(workloadId: string) {
    setBusy(true)
    setLogs(null)
    setRefusal(null)
    try {
      const result = await client.workloadLogs(workloadId)
      if (!alive.current) return
      if (!result.accepted) setRefusal(`${workloadId}: ${result.refusal?.reason ?? 'Logs unavailable'}. ${result.refusal?.detail ?? ''}`)
      else {
        const value = result.result
        if (!value || Array.isArray(value) || typeof value.output !== 'string' || typeof value.truncated !== 'boolean'
          || typeof value.byteCount !== 'number' || !Number.isSafeInteger(value.byteCount) || value.byteCount < 0
          || typeof value.outputByteBound !== 'number' || !Number.isSafeInteger(value.outputByteBound) || value.outputByteBound < 1
          || value.byteCount > value.outputByteBound) {
          throw new Error('Invalid bounded log response')
        }
        setLogs({ workloadId, output: value.output, byteCount: value.byteCount, outputByteBound: value.outputByteBound, truncated: value.truncated })
      }
    } catch { if (alive.current) setRefusal(`${workloadId}: logs could not be loaded. Retry or inspect diagnostics.`) }
    finally { if (alive.current) setBusy(false) }
  }

  const available = status?.status === 'available'
  return (
    <div className="flex h-full flex-col gap-4 overflow-auto p-4 md:p-6" data-testid="execution-host-page">
      <header>
        <h1 className="text-xl font-semibold">Execution host</h1>
        <p className="mt-1 text-sm text-foreground-secondary">Inspect workloads visible to your execution grant. Use the application to submit approved work; controls here manage its runtime.</p>
      </header>
      <section className="rounded border border-border p-4" aria-label="Execution host health">
        <h2 className="text-sm font-medium">Runtime health</h2>
        <p className="mt-2 text-sm">Status: {available ? 'available' : status?.reason ?? 'not checked'} · Grant: {status?.grantBound ? status.grantId ?? 'bound' : 'not bound'}</p>
        {status?.engine && <p className="mt-1 text-xs">Engine: {status.engine} {status.engineVersion}</p>}
        {status?.detail && <p className="mt-2 text-xs text-foreground-secondary">{status.detail}</p>}
        <Button className="mt-3" size="sm" variant="outline" disabled={busy} onClick={() => void refresh()}>Refresh workloads</Button>
      </section>
      {error && <p role="alert" className="rounded border border-border p-3 text-sm">{error}</p>}
      {refusal && <p role="alert" className="rounded border border-border p-3 text-sm">{refusal}</p>}
      {!available && status && <p className="text-sm">Execution runtime is unavailable. Review installation diagnostics and the provisioned execution grant.</p>}
      {available && workloads && (
        <section aria-label="Managed workloads" className="space-y-3">
          <h2 className="text-base font-semibold">Managed workloads</h2>
          <p className="text-xs text-foreground-secondary">Only grant-scoped workloads are listed. Application and run ownership are not supplied by this runtime inventory.</p>
          {workloads.length === 0 && <p className="text-sm">No workloads are visible to this grant.</p>}
          {!workloads.some((workload) => workload.workloadId === 'default-dev') && <div className="space-y-2"><p className="text-xs text-foreground-secondary">The provisioned development workspace uses the sealed installation profile. Creating arbitrary workload profiles is unavailable here.</p><Button size="sm" variant="outline" disabled={busy || !status.grantBound} onClick={() => void perform('create')}>Create development workspace</Button></div>}
          {workloads.some(workload => workload.workloadId === 'default-dev' && workload.state === 'removed') && <p className="text-sm">The development container was removed. Its workspace volume and audit ledger remain; recreating this workload ID is not supported here. Review platform recovery guidance before changing preserved data.</p>}
          {workloads.map((workload) => (
            <article key={workload.workloadId} aria-label={`Workload ${workload.workloadId}`} className="min-w-0 rounded border border-border p-4">
              <h3 className="break-all font-mono text-sm font-semibold">{workload.workloadId}</h3>
              <p className="mt-2 text-sm">Kind: {workload.kind ?? 'not reported'} · Lifecycle: {workload.state} · Container: {workload.engineStatus ?? 'not reported'}</p>
              {workload.imageDigest && <p className="mt-1 break-all font-mono text-xs">Image: {workload.imageDigest}</p>}
              {workload.lastActivityAt && <p className="mt-1 text-xs">Last activity: <time>{workload.lastActivityAt}</time></p>}
              <div className="mt-3 flex flex-wrap gap-2">
                <Button size="sm" variant="outline" disabled={busy || !status.grantBound || !['created', 'stopped'].includes(workload.state)} onClick={() => void perform('start', workload.workloadId)}>Start</Button>
                <Button size="sm" variant="outline" disabled={busy || !status.grantBound || workload.state !== 'running'} onClick={() => setPending({ action: 'stop', workload })}>Stop</Button>
                <Button size="sm" variant="outline" disabled={busy || !status.grantBound || !['running', 'created', 'reserved'].includes(workload.state)} onClick={() => setPending({ action: 'cancel', workload })}>Cancel work</Button>
                <Button size="sm" variant="outline" disabled={busy || !status.grantBound || workload.state === 'removed'} onClick={() => setPending({ action: 'remove', workload })}>Remove container</Button>
                <Button size="sm" variant="outline" disabled={busy || workload.state === 'removed'} onClick={() => void readLogs(workload.workloadId)}>Logs</Button>
              </div>
            </article>
          ))}
        </section>
      )}
      {logs && <section aria-label={`Logs for ${logs.workloadId}`}><h2 className="break-all text-sm font-medium">Logs: {logs.workloadId}</h2><p className="mt-1 text-xs">{logs.truncated ? `Output truncated: showing the first ${logs.byteCount} bytes (response limit ${logs.outputByteBound} bytes).` : `${logs.byteCount} bytes returned; response limit ${logs.outputByteBound} bytes.`}</p><pre className="mt-2 max-h-64 overflow-auto rounded bg-surface p-3 text-xs">{logs.output}</pre></section>}
      {receipt && <section data-testid="execution-host-receipt" className="break-all rounded bg-surface p-3 text-xs"><h2 className="font-medium">Persisted operation receipt</h2><p>{receipt.workloadId ?? 'Workspace'} · {receipt.action} · {receipt.status}</p><p>{receipt.receiptId} · <time>{receipt.createdAt}</time></p></section>}
      <ConfirmDialog open={pending !== null} onOpenChange={(open) => { if (!open) setPending(null) }} title={pending?.action === 'remove' ? 'Remove workload container?' : pending?.action === 'cancel' ? 'Cancel workload?' : 'Stop workload?'} target={pending?.workload.workloadId} description="This affects the selected workload. The service rechecks its grant and current state." effect={pending?.action === 'remove' ? 'Remove its container. The daemon retains its audit ledger.' : 'Interrupt running processes; in-progress output may be incomplete.'} reversibility={pending?.workload.kind === 'workspace' ? 'The managed workspace volume is preserved. Stopped workspaces can be started again; cancelled work is not automatically resumed.' : 'The workload may reach a terminal state. Use the application to review its result and submit new work if needed.'} confirmLabel="Confirm operation" destructive onConfirm={() => pending ? perform(pending.action, pending.workload.workloadId) : undefined} />
    </div>
  )
}
