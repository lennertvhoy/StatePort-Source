/**
 * Read-only runtime status: what the execution host reports about itself and
 * the workloads visible to this installation's grant. Nothing here starts,
 * stops, cancels, removes or creates a workload; approved work runs from the
 * application that requested it (ADR-0007 section 5). Reading bounded logs is
 * the one request that goes beyond status, and the service checks it against
 * the same grant.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { getClient } from '@/client'
import type { ExecutionHostReceiptIndex, ExecutionHostResult, ExecutionHostStatus } from '@/client'
import { Button } from '@/components/ui/button'

interface Workload {
  workloadId: string
  kind?: string
  state: string
  imageDigest?: string
  engineStatus?: string
  lastActivityAt?: string
  allowedOperations?: string[]
  ownership?: {
    grantId: string
    applicationId?: string | null
    runId?: string | null
  }
  declaredLimits?: {
    memoryMaxBytes: number
    pidsMax: number
    timeoutSeconds: number
    outputByteBound: number
    cpuQuotaPercent?: number
    diskMaxBytes?: number
  }
  resourceEnforcement?: {
    persistentVolumeDiskMaxBytes?: {
      status: string
      requestedBytes: number
      detail: string
    }
  }
}
interface ApplicationWorkspace { terminalAvailable?: boolean; allowedOperations?: string[]; instanceId: string; applicationId: string; workloadId: string; displayName?: string; status: string; reason?: string }

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function positiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
}

function formatBytes(value: number): string {
  if (value >= 1024 ** 3 && value % 1024 ** 3 === 0) return `${value / 1024 ** 3} GiB`
  if (value >= 1024 ** 2 && value % 1024 ** 2 === 0) return `${value / 1024 ** 2} MiB`
  if (value >= 1024 && value % 1024 === 0) return `${value / 1024} KiB`
  return `${value} bytes`
}

function inventory(result: ExecutionHostResult): Workload[] {
  const record = result.result
  const values = record && !Array.isArray(record) ? record.workloads : undefined
  if (!Array.isArray(values) || values.some((item) => !isRecord(item) || typeof item.workloadId !== 'string' || typeof item.state !== 'string')) {
    throw new Error('The service returned an invalid workload inventory. Retry or inspect diagnostics.')
  }
  for (const item of values) {
    if (!isRecord(item)) throw new Error('The service returned an invalid workload inventory. Retry or inspect diagnostics.')
    if (item.allowedOperations !== undefined && (!Array.isArray(item.allowedOperations)
      || item.allowedOperations.some(operation => typeof operation !== 'string')
      || new Set(item.allowedOperations).size !== item.allowedOperations.length)) {
      throw new Error('The service returned invalid workload operations. Retry or inspect diagnostics.')
    }
    if (item.ownership !== undefined && (
      !isRecord(item.ownership)
      || typeof item.ownership.grantId !== 'string'
      || item.ownership.grantId.length === 0
      || (item.ownership.applicationId !== null && item.ownership.applicationId !== undefined && typeof item.ownership.applicationId !== 'string')
      || (item.ownership.runId !== null && item.ownership.runId !== undefined && typeof item.ownership.runId !== 'string')
    )) throw new Error('The service returned invalid workload ownership. Retry or inspect diagnostics.')
    if (item.declaredLimits !== undefined && (
      !isRecord(item.declaredLimits)
      || !positiveInteger(item.declaredLimits.memoryMaxBytes)
      || !positiveInteger(item.declaredLimits.pidsMax)
      || !positiveInteger(item.declaredLimits.timeoutSeconds)
      || !positiveInteger(item.declaredLimits.outputByteBound)
      || (item.declaredLimits.cpuQuotaPercent !== undefined && !positiveInteger(item.declaredLimits.cpuQuotaPercent))
      || (item.declaredLimits.diskMaxBytes !== undefined && !positiveInteger(item.declaredLimits.diskMaxBytes))
    )) throw new Error('The service returned invalid workload limits. Retry or inspect diagnostics.')
    if (item.resourceEnforcement !== undefined && (
      !isRecord(item.resourceEnforcement)
      || (
        item.resourceEnforcement.persistentVolumeDiskMaxBytes !== undefined
        && (
          !isRecord(item.resourceEnforcement.persistentVolumeDiskMaxBytes)
          || typeof item.resourceEnforcement.persistentVolumeDiskMaxBytes.status !== 'string'
          || !positiveInteger(item.resourceEnforcement.persistentVolumeDiskMaxBytes.requestedBytes)
          || typeof item.resourceEnforcement.persistentVolumeDiskMaxBytes.detail !== 'string'
        )
      )
    )) throw new Error('The service returned invalid resource enforcement. Retry or inspect diagnostics.')
  }
  return values as Workload[]
}

interface InventoryProjection {
  workloads: Workload[]
  applicationWorkspaces: ApplicationWorkspace[]
  defaultWorkspaceRefusal: string | null
}

function inventoryProjection(result: ExecutionHostResult): InventoryProjection {
  const workloads = inventory(result)
  const profiles = isRecord(result.result) ? result.result.applicationWorkspaces : undefined
  if (profiles !== undefined && (!Array.isArray(profiles) || profiles.some(item => !isRecord(item) || typeof item.instanceId !== 'string' || typeof item.applicationId !== 'string' || typeof item.workloadId !== 'string' || typeof item.status !== 'string' || (item.terminalAvailable !== undefined && typeof item.terminalAvailable !== 'boolean') || (item.allowedOperations !== undefined && (!Array.isArray(item.allowedOperations) || item.allowedOperations.some(operation => typeof operation !== 'string')))))) throw new Error('Invalid application workspace bindings')
  const defaultRefusal = isRecord(result.result) ? result.result.defaultWorkspaceRefusal : undefined
  return {
    workloads,
    applicationWorkspaces: (profiles ?? []) as ApplicationWorkspace[],
    defaultWorkspaceRefusal: isRecord(defaultRefusal) && typeof defaultRefusal.reason === 'string' ? defaultRefusal.reason : null,
  }
}

function applicationProfileFor(workload: Workload, profiles: ApplicationWorkspace[]): ApplicationWorkspace | undefined {
  const applicationId = workload.ownership?.applicationId
  if (typeof applicationId !== 'string' || applicationId.length === 0) return undefined
  return profiles.find(profile => profile.workloadId === workload.workloadId && profile.applicationId === applicationId)
}

function logsAllowed(
  workload: Workload,
  profiles: ApplicationWorkspace[],
  status: ExecutionHostStatus | null,
): boolean {
  const daemonOperation = 'logs'
  const applicationId = workload.ownership?.applicationId
  const runId = workload.ownership?.runId
  const runOwned = typeof runId === 'string' && runId.length > 0
  const profile = applicationProfileFor(workload, profiles)
  // Application bindings need a current, daemon-verified profile even when
  // the workload row also carries an operation projection.
  if (typeof applicationId === 'string' && applicationId.length > 0 && !runOwned) {
    if (!profile || profile.status !== 'available') return false
    if (workload.allowedOperations !== undefined) return workload.allowedOperations.includes(daemonOperation)
    return profile.allowedOperations?.includes(daemonOperation) ?? false
  }
  // Run-owned jobs need not have an application-workspace profile. Their
  // exact daemon enumeration carries their own grant's operation set too.
  if (workload.allowedOperations !== undefined) return workload.allowedOperations.includes(daemonOperation)
  if (profile && !runOwned) return profile.status === 'available' && (profile.allowedOperations?.includes(daemonOperation) ?? false)
  if (runOwned) return false
  if (status?.status !== 'available' || status.grantBound !== true) return false
  if (status.grantId && workload.ownership?.grantId && workload.ownership.grantId !== status.grantId) return false
  return true
}

function sameWorkloadIdentity(expected: Workload, current: Workload): boolean {
  const expectedOwnership = expected.ownership
  const currentOwnership = current.ownership
  return expected.workloadId === current.workloadId
    && expected.kind === current.kind
    && expected.imageDigest === current.imageDigest
    && expected.lastActivityAt === current.lastActivityAt
    && (expectedOwnership?.grantId ?? null) === (currentOwnership?.grantId ?? null)
    && (expectedOwnership?.applicationId ?? null) === (currentOwnership?.applicationId ?? null)
    && (expectedOwnership?.runId ?? null) === (currentOwnership?.runId ?? null)
}

export default function ExecutionHostPage() {
  const client = getClient().executionHost
  const [status, setStatus] = useState<ExecutionHostStatus | null>(null)
  const [applicationWorkspaces, setApplicationWorkspaces] = useState<ApplicationWorkspace[]>([])
  const [workloads, setWorkloads] = useState<Workload[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [refusal, setRefusal] = useState<string | null>(null)
  const [logs, setLogs] = useState<{ workloadId: string; output: string; byteCount: number; outputByteBound: number; truncated: boolean } | null>(null)
  const [history, setHistory] = useState<ExecutionHostReceiptIndex | null>(null)
  const [historyError, setHistoryError] = useState<string | null>(null)
  const [historyBusy, setHistoryBusy] = useState(false)
  const [busy, setBusy] = useState(false)
  const alive = useRef(true)
  const refreshing = useRef(false)
  const logsGeneration = useRef(0)
  const latestInventory = useRef<InventoryProjection | null>(null)
  const latestStatus = useRef<ExecutionHostStatus | null>(null)

  const invalidateInventory = useCallback((message: string) => {
    latestInventory.current = null
    latestStatus.current = null
    logsGeneration.current += 1
    setWorkloads(null)
    setLogs(null)
    setBusy(false)
    setError(message)
  }, [])

  const applyInventory = useCallback((observed: InventoryProjection, observedStatus: ExecutionHostStatus | null) => {
    const previousInventory = latestInventory.current
    latestInventory.current = observed
    latestStatus.current = observedStatus
    setWorkloads(observed.workloads)
    setApplicationWorkspaces(observed.applicationWorkspaces)
    // Logs stay on screen only while the same workload row is still readable
    // under the grant; any identity change discards them.
    setLogs(previous => {
      if (!previous) return null
      const row = observed.workloads.find(item => item.workloadId === previous.workloadId)
      const priorRow = previousInventory?.workloads.find(item => item.workloadId === previous.workloadId)
      return row && priorRow && sameWorkloadIdentity(priorRow, row)
        && logsAllowed(row, observed.applicationWorkspaces, observedStatus) ? previous : null
    })
  }, [])

  const refresh = useCallback(async () => {
    if (refreshing.current) return
    refreshing.current = true
    try {
      const current = await client.status()
      if (!alive.current) return
      latestStatus.current = current
      setStatus(current)
      const listed = await client.listWorkloads()
      if (!alive.current) return
      if (!listed.accepted) {
        invalidateInventory(`Inventory refused: ${listed.refusal?.reason ?? 'unavailable'}. ${listed.refusal?.detail ?? 'The execution-host grant does not allow listing workloads.'}`)
        return
      }
      const observed = inventoryProjection(listed)
      applyInventory(observed, current)
      setError(null)
    } catch {
      if (alive.current) invalidateInventory('Workload inventory is unavailable. Retry, or open Settings, Advanced for service diagnostics.')
    } finally {
      refreshing.current = false
    }
  }, [applyInventory, client, invalidateInventory])

  useEffect(() => {
    alive.current = true
    void refresh()
    const timer = window.setInterval(() => void refresh(), 4000)
    return () => { alive.current = false; window.clearInterval(timer) }
  }, [refresh])

  async function readLogs(workloadId: string) {
    if (!alive.current || busy) return
    const request = ++logsGeneration.current
    setLogs(null)
    setRefusal(null)
    const observed = latestInventory.current
    const scope = observed?.workloads.find(item => item.workloadId === workloadId)
    if (!observed || !scope || scope.state === 'removed' || !logsAllowed(scope, observed.applicationWorkspaces, latestStatus.current)) {
      setRefusal(`${workloadId} changed or is no longer readable; no logs were requested. Refresh and review its current state.`)
      return
    }
    setBusy(true)
    try {
      const result = await client.workloadLogs(workloadId)
      if (!alive.current || request !== logsGeneration.current) return
      const currentInventory = latestInventory.current
      const current = currentInventory?.workloads.find(item => item.workloadId === workloadId)
      if (!currentInventory || !current || !sameWorkloadIdentity(scope, current) || current.state === 'removed'
        || !logsAllowed(current, currentInventory.applicationWorkspaces, latestStatus.current)) {
        setLogs(null)
        setRefusal(`${workloadId} changed or is no longer readable; logs were discarded.`)
        return
      }
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
    } catch { if (alive.current && request === logsGeneration.current) setRefusal(`${workloadId}: logs could not be loaded. Retry later.`) }
    finally {
      // A newer log request or a completed inventory refresh owns the current
      // generation. Do not let this response clear its busy state.
      if (alive.current && request === logsGeneration.current) setBusy(false)
    }
  }

  async function readHistory() {
    if (historyBusy) return
    setHistoryBusy(true)
    setHistoryError(null)
    try {
      const next = await client.listReceipts()
      if (alive.current) setHistory(next)
    } catch {
      if (alive.current) setHistoryError('Operation history could not be refreshed. Any displayed records are from the previous successful read.')
    } finally { if (alive.current) setHistoryBusy(false) }
  }

  const available = status?.status === 'available'
  return (
    <div className="flex h-full flex-col gap-4 overflow-auto p-4 md:p-6" data-testid="execution-host-page">
      <header>
        <h1 className="text-xl font-semibold">Execution host</h1>
        <p className="mt-1 text-sm text-foreground-secondary">Read-only status of the runtime that carries out approved work. Work is requested and approved in the application; nothing on this page starts, stops or changes it.</p>
      </header>
      <section className="rounded border border-border p-4" aria-label="Execution host health">
        <h2 className="text-sm font-medium">Runtime health</h2>
        <p className="mt-2 text-sm">Status: {available ? 'available' : status?.reason ?? 'not checked'} · Grant: {status?.grantBound ? status.grantId ?? 'bound' : 'not bound'}</p>
        {status?.engine && <p className="mt-1 text-xs">Engine: {status.engine} {status.engineVersion}</p>}
        {status?.detail && <p className="mt-2 text-xs text-foreground-secondary">{status.detail}</p>}
        <Button className="mt-3" size="sm" variant="outline" disabled={busy} onClick={() => void refresh()}>Refresh status</Button>
      </section>
      {error && <p role="alert" className="rounded border border-border p-3 text-sm">{error}</p>}
      {refusal && <p role="alert" className="rounded border border-border p-3 text-sm">{refusal}</p>}
      {!available && status && <p className="text-sm">The execution runtime is not available. Work that needs it cannot run until it is.</p>}
      <section aria-label="Application workspaces" className="space-y-2">
        <h2 className="text-sm font-semibold">Application workspaces</h2>
        {workloads === null
          ? <p className="text-sm">Workspace status is not confirmed. Refresh to read it.</p>
          : applicationWorkspaces.length === 0 && <p className="text-sm">No application workspace has been provisioned for this installation.</p>}
        {applicationWorkspaces.map(profile => {
          const workload = (workloads ?? []).find(item => item.workloadId === profile.workloadId)
          return <div key={profile.instanceId} className="rounded border border-border p-3">
            <p className="text-sm font-medium">{profile.displayName ?? profile.applicationId}</p>
            <p className="text-xs">Application: {profile.applicationId} · {workloads === null ? 'Previous observation; current inventory unavailable' : profile.status === 'available' ? 'Workspace authority configured' : `Unavailable: ${profile.reason ?? 'authority not verified'}`}</p>
            {workload && <p className="text-xs">Workspace: {workload.state}</p>}
            {profile.allowedOperations && <p className="text-xs">Granted operations: {profile.allowedOperations.join(', ')}</p>}
          </div>
        })}
      </section>
      {workloads && (
        <section aria-label="Managed workloads" className="space-y-3">
          <h2 className="text-base font-semibold">Managed workloads</h2>
          {!available && <p className="text-xs text-foreground-secondary">The runtime health probe is unavailable. Application workspaces above still show what the execution host last reported for them.</p>}
          {workloads.length === 0 && <p className="text-sm">No workloads are visible to this grant.</p>}
          {workloads.map((workload) => (
            <article key={workload.workloadId} aria-label={`Workload ${workload.workloadId}`} className="min-w-0 rounded border border-border p-4">
              <h3 className="break-all font-mono text-sm font-semibold">{workload.workloadId}</h3>
              <p className="mt-2 text-sm">Kind: {workload.kind ?? 'not reported'} · Lifecycle: {workload.state} · Container: {workload.engineStatus ?? 'not reported'}</p>
              {workload.ownership && <p className="mt-1 text-xs">Authority grant: <span className="font-mono">{workload.ownership.grantId}</span> · Application: {workload.ownership.applicationId ?? 'not bound'} · Run: {workload.ownership.runId ?? 'not bound'}</p>}
              {workload.imageDigest && <p className="mt-1 break-all font-mono text-xs">Image: {workload.imageDigest}</p>}
              {workload.lastActivityAt && <p className="mt-1 text-xs">Last activity: <time>{workload.lastActivityAt}</time></p>}
              {workload.declaredLimits && <div className="mt-2 text-xs"><p>Declared limits: memory {formatBytes(workload.declaredLimits.memoryMaxBytes)} · PIDs {workload.declaredLimits.pidsMax}{workload.declaredLimits.cpuQuotaPercent ? ` · CPU ${workload.declaredLimits.cpuQuotaPercent}%` : ''}{workload.declaredLimits.diskMaxBytes ? ` · persistent disk ${formatBytes(workload.declaredLimits.diskMaxBytes)}` : ''}</p><p>Runtime timeout {workload.declaredLimits.timeoutSeconds}s · output {formatBytes(workload.declaredLimits.outputByteBound)}</p></div>}
              {workload.resourceEnforcement?.persistentVolumeDiskMaxBytes && <p className="mt-1 text-xs text-foreground-secondary">Persistent disk enforcement: {workload.resourceEnforcement.persistentVolumeDiskMaxBytes.status} — {workload.resourceEnforcement.persistentVolumeDiskMaxBytes.detail}</p>}
              <div className="mt-3 flex flex-wrap gap-2">
                <Button size="sm" variant="outline" disabled={busy || workload.state === 'removed' || !logsAllowed(workload, applicationWorkspaces, status)} onClick={() => void readLogs(workload.workloadId)}>Logs</Button>
              </div>
            </article>
          ))}
        </section>
      )}
      {logs && <section aria-label={`Logs for ${logs.workloadId}`}><h2 className="break-all text-sm font-medium">Logs: {logs.workloadId}</h2><p className="mt-1 text-xs">{logs.truncated ? `Output truncated: showing the first ${logs.byteCount} bytes (response limit ${logs.outputByteBound} bytes).` : `${logs.byteCount} bytes returned; response limit ${logs.outputByteBound} bytes.`}</p><pre className="mt-2 max-h-64 overflow-auto rounded bg-surface p-3 text-xs">{logs.output}</pre></section>}
      <section aria-label="Execution operation history" className="space-y-3 rounded border border-border p-4">
        <h2 className="text-sm font-medium">Operation history</h2>
        <p className="text-xs text-foreground-secondary">Read the latest 50 persisted runtime operation receipts, including refused operations. These records remain available when the execution host is offline.</p>
        <Button size="sm" variant="outline" disabled={historyBusy} onClick={() => void readHistory()}>{historyBusy ? 'Loading history…' : 'Refresh operation history'}</Button>
        {historyError && <p role="alert" className="text-sm">{historyError}</p>}
        {history && history.receipts.length === 0 && !historyError && <p className="text-sm">No runtime operation receipts have been recorded.</p>}
        {history?.receipts.map(item => <details key={item.receiptId} className="break-all rounded border border-border p-3 text-xs">
          <summary className="cursor-pointer">{item.action} · {item.status} · <time>{item.createdAt}</time></summary>
          <p className="mt-2">Receipt: {item.receiptId}</p>
          <p>Payload digest: {item.payloadDigest}</p>
        </details>)}
      </section>
    </div>
  )
}
