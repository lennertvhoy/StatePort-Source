/**
 * Dashboard data hook for the Applications home — loads instances, pending
 * approvals and operation records through the typed client boundary.
 *
 * Behavior contract (applications.md "States"):
 * - Loading: skeleton rows; an 8 s guard turns a hung load into ErrorState.
 * - Error: ErrorState with Retry; when a previous successful load exists the
 *   page keeps rendering it behind a "Showing last known state" banner.
 * - Service offline: reads fail; the page renders the last known snapshot
 *   (kept here module-level so it survives remounts) with mutating actions
 *   hidden.
 */
import { useCallback, useEffect, useRef, useState } from 'react'

import type { ApplicationInstance, Approval, OperationRecord } from '@/client'
import { getClient } from '@/client'
import { useSessionStore } from '@/state'

const LOAD_TIMEOUT_MS = 8_000

export interface DashboardSnapshot {
  instances: ApplicationInstance[]
  pendingApprovals: Approval[]
  operations: OperationRecord[]
}

/** Last good snapshot — survives route changes so offline stays readable. */
let lastGoodSnapshot: DashboardSnapshot | null = null

/** Test seam: drop the cached snapshot between tests. */
export function resetDashboardSnapshotForTests(): void {
  lastGoodSnapshot = null
}

export interface DashboardData extends DashboardSnapshot {
  loading: boolean
  error: unknown
  /** True when rendering the last-known snapshot after a failed load. */
  stale: boolean
  refresh: () => void
}

export function useApplicationsDashboard(): DashboardData {
  const activeScenario = useSessionStore((s) => s.activeScenario)
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(lastGoodSnapshot)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<unknown>(null)
  const [nonce, setNonce] = useState(0)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    // Only show the full loading state when there is nothing to display.
    if (!snapshot) setLoading(true)
    setError(null)

    const timeout = window.setTimeout(() => {
      if (!cancelled && mounted.current) {
        setLoading(false)
        setError(new Error('Loading applications took too long. The local service may be slow or offline.'))
      }
    }, LOAD_TIMEOUT_MS)

    const client = getClient()
    Promise.all([
      client.applications.list(),
      client.approvals.list({ status: 'pending' }),
      client.operations.list(),
    ])
      .then(([instances, pendingApprovals, operations]) => {
        if (cancelled || !mounted.current) return
        window.clearTimeout(timeout)
        const next = { instances, pendingApprovals, operations }
        lastGoodSnapshot = next
        setSnapshot(next)
        setError(null)
        setLoading(false)
      })
      .catch((err) => {
        if (cancelled || !mounted.current) return
        window.clearTimeout(timeout)
        setError(err)
        setLoading(false)
      })

    return () => {
      cancelled = true
      window.clearTimeout(timeout)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- snapshot is intentionally only read at effect start
  }, [nonce, activeScenario])

  const refresh = useCallback(() => setNonce((n) => n + 1), [])

  const data = snapshot ?? lastGoodSnapshot ?? { instances: [], pendingApprovals: [], operations: [] }
  return {
    ...data,
    loading,
    error,
    stale: Boolean(error) && Boolean(snapshot ?? lastGoodSnapshot),
    refresh,
  }
}

/** True when the local service is known to be offline (mutations must hide). */
export function useServiceOffline(): boolean {
  return useSessionStore((s) => s.serviceStatus?.state === 'offline')
}
