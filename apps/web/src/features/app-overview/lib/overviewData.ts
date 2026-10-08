/**
 * Overview data hook — the domain reads the App overview needs beyond the
 * instance itself (which AppContextShell owns): activity, pending approvals,
 * operations, recent receipts, the infrastructure target (capability-gated),
 * and the package version. All through the typed client boundary, in
 * parallel. Each projection keeps its last good value and exposes whether the
 * current value is fresh, stale, or unavailable; an empty fallback is never
 * presented as a successful read.
 */
import { useCallback, useEffect, useRef, useState } from 'react'

import type {
  ActivityItem,
  ApplicationInstance,
  Approval,
  InfrastructureTarget,
  OperationRecord,
  Receipt,
} from '@/client'
import { getClient } from '@/client'
import { useSessionStore } from '@/state'

export interface OverviewData {
  activity: ActivityItem[]
  pendingApprovals: Approval[]
  operations: OperationRecord[]
  receipts: Receipt[]
  infraTarget: InfrastructureTarget | null
  packageVersion: string | null
  loading: boolean
  sourceState: Exclude<OverviewSourceState, 'not_applicable'>
  sourceStates: Record<OverviewSource, OverviewSourceState>
  refresh: () => void
}

export type OverviewSource = 'activity' | 'approvals' | 'operations' | 'receipts' | 'infrastructure' | 'package'
export type OverviewSourceState = 'fresh' | 'stale' | 'unavailable' | 'not_applicable'

const EMPTY = {
  activity: [] as ActivityItem[],
  pendingApprovals: [] as Approval[],
  operations: [] as OperationRecord[],
  receipts: [] as Receipt[],
  infraTarget: null as InfrastructureTarget | null,
  packageVersion: null as string | null,
}

const EMPTY_SOURCE_STATES: Record<OverviewSource, OverviewSourceState> = {
  activity: 'unavailable',
  approvals: 'unavailable',
  operations: 'unavailable',
  receipts: 'unavailable',
  infrastructure: 'not_applicable',
  package: 'unavailable',
}

type ReadResult<T> = { value: T; state: 'fresh' | 'stale' | 'unavailable'; error?: unknown }

type OverviewValues = Pick<
  OverviewData,
  'activity' | 'pendingApprovals' | 'operations' | 'receipts' | 'infraTarget' | 'packageVersion'
>

function read<T>(promise: Promise<T>, fallback: T, previous: T | undefined): Promise<ReadResult<T>> {
  return promise.then(
    (value) => ({ value, state: 'fresh' as const }),
    (error) => ({ value: previous ?? fallback, state: previous === undefined ? 'unavailable' : 'stale', error }),
  )
}

function aggregateSourceState(states: Record<OverviewSource, OverviewSourceState>): Exclude<OverviewSourceState, 'not_applicable'> {
  const values = Object.values(states)
  if (values.some((state) => state === 'unavailable')) return 'unavailable'
  if (values.some((state) => state === 'stale')) return 'stale'
  return 'fresh'
}

export function useOverviewData(instance: ApplicationInstance | null): OverviewData {
  const activeScenario = useSessionStore((s) => s.activeScenario)
  // Keyed fetch result: data/loading derive from whether the in-flight key
  // has landed, so the effect never sets state synchronously.
  const [result, setResult] = useState<{ key: string; data: Omit<OverviewData, 'loading' | 'refresh'> } | null>(
    null,
  )
  const lastGood = useRef<{
    key: string
    values: Partial<OverviewValues>
  } | null>(null)
  const [nonce, setNonce] = useState(0)
  const baseKey = `${instance?.id ?? ''}#${activeScenario ?? ''}`
  const requestKey = `${baseKey}#${nonce}`

  useEffect(() => {
    if (!instance) return
    let cancelled = false
    const client = getClient()
    const hasInfrastructure = instance.capabilities.some(
      (c) => c.id === 'infrastructure' && (c.status === 'available' || c.status === 'degraded'),
    )
    const hasCtoOrchestration = instance.capabilities.some(
      (c) => c.id === 'cto_orchestration' && (c.status === 'available' || c.status === 'degraded'),
    )

    const previous = lastGood.current?.key === baseKey ? lastGood.current.values : undefined
    const previousValue = <K extends keyof OverviewValues>(key: K): OverviewValues[K] | undefined =>
      previous && Object.prototype.hasOwnProperty.call(previous, key) ? previous[key] : undefined
    void Promise.all([
      read(client.activity.listActivity({ instanceId: instance.id, limit: 20 }), [], previousValue('activity')),
      read(client.approvals.list({ instanceId: instance.id, status: 'pending' }), [], previousValue('pendingApprovals')),
      read(client.operations.list(), [], previousValue('operations')),
      read(
        client.receipts.list({ instanceId: instance.id, limit: 8, goalExecution: hasCtoOrchestration }),
        [],
        previousValue('receipts'),
      ),
      hasInfrastructure
        ? read(client.infrastructure.getTarget(instance.id), null, previousValue('infraTarget'))
        : Promise.resolve({ value: null, state: 'fresh' as const }),
      read(client.catalog.get(instance.packageId).then((c) => c.pkg.version), null, previousValue('packageVersion')),
    ]).then(([activityRead, approvalsRead, operationsRead, receiptsRead, infraRead, packageRead]) => {
      if (cancelled) return
      const sourceStates: Record<OverviewSource, OverviewSourceState> = {
        activity: activityRead.state,
        approvals: approvalsRead.state,
        operations: operationsRead.state,
        receipts: receiptsRead.state,
        infrastructure: hasInfrastructure ? infraRead.state : 'not_applicable',
        package: packageRead.state,
      }
      const data = {
        activity: activityRead.value,
        pendingApprovals: approvalsRead.value,
        operations: operationsRead.value.filter((o) => o.instanceId === instance.id),
        receipts: receiptsRead.value,
        infraTarget: infraRead.value,
        packageVersion: packageRead.value,
        sourceState: aggregateSourceState(sourceStates),
        sourceStates,
      }
      const nextGood = { ...previous }
      if (activityRead.state === 'fresh') nextGood.activity = activityRead.value
      if (approvalsRead.state === 'fresh') nextGood.pendingApprovals = approvalsRead.value
      if (operationsRead.state === 'fresh') {
        nextGood.operations = operationsRead.value.filter((o) => o.instanceId === instance.id)
      }
      if (receiptsRead.state === 'fresh') nextGood.receipts = receiptsRead.value
      if (infraRead.state === 'fresh') nextGood.infraTarget = infraRead.value
      if (packageRead.state === 'fresh') nextGood.packageVersion = packageRead.value
      if (Object.keys(nextGood).length > 0) lastGood.current = { key: baseKey, values: nextGood }
      setResult({
        key: requestKey,
        data,
      })
    })

    return () => {
      cancelled = true
    }
  }, [instance, activeScenario, nonce, requestKey, baseKey])

  const refresh = useCallback(() => setNonce((n) => n + 1), [])
  const landed = result && result.key === requestKey ? result.data : null
  // A switched application must not inherit the previous application's data
  // while its own projections are still in flight.
  const previous = result && result.key.startsWith(`${baseKey}#`) ? result.data : null
  const data = landed ?? (previous
    ? {
        ...previous,
        sourceState: previous.sourceState === 'fresh' ? 'stale' : previous.sourceState,
        sourceStates: Object.fromEntries(
          Object.entries(previous.sourceStates).map(([key, state]) => [key, state === 'fresh' ? 'stale' : state]),
        ) as Record<OverviewSource, OverviewSourceState>,
      }
    : { ...EMPTY, sourceState: 'unavailable' as const, sourceStates: EMPTY_SOURCE_STATES })
  return { ...data, loading: !landed, refresh }
}
