/**
 * useInfrastructure — the Deployments surface's data layer.
 *
 * All domain truth flows through the typed client boundary (getClient()); the
 * hook owns loading/error/refresh plus the local plan-run machine (progress
 * events → timeline state). Nothing here mutates outside the client contract:
 * prepare only prepares, run only runs a prepared/approved plan, and every
 * terminal transition comes back with its receipt from the adapter.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type {
  AuthorizationGrant,
  InfrastructureOperation,
  InfrastructurePlan,
  InfrastructureTarget,
  OperationState,
  Receipt,
} from '@/client'
import { ClientError, getClient } from '@/client'
import { useCurrentInstance } from '@/shell/currentInstance'
import { useSessionStore } from '@/state'

import type { RunPhase } from './infrastructureModel'

const APPROVAL_POLL_MS = 3_000

export interface RunState {
  planId: string
  phase: Exclude<RunPhase, 'idle'>
  stepStates: Record<number, OperationState>
  logs: string[]
  startedAt: string
  finishedAt?: string
  receipt?: Receipt
  error?: string
}

export interface InfrastructureState {
  /** Null while the first load is in flight. */
  target: InfrastructureTarget | null
  loading: boolean
  /** Transport/unexpected failure of the initial load. */
  loadError: unknown
  /** True when the target cannot be verified (drives the ONE blocked state). */
  targetUnavailable: boolean
  unavailableReason?: string
  /** Stale-banner: a background refresh failed while data stayed on screen. */
  refreshFailed: boolean
  lastRefreshAt: string | null
  plans: InfrastructurePlan[]
  activePlanId: string | null
  authorization: AuthorizationGrant | null
  /** Latest receipts for this instance (operation history, infrastructure-scoped). */
  receipts: Receipt[]
  run: RunState | null
}

export interface InfrastructureActions {
  refresh: () => void
  observe: () => Promise<void>
  validateConfiguration: () => Promise<void>
  healthCheck: () => Promise<void>
  preparePlan: (operation: InfrastructureOperation) => Promise<InfrastructurePlan>
  selectPlan: (planId: string | null) => void
  /** Clear the current plan from the canvas (the prepared plan stays in history). */
  dismissPlan: () => void
  runPlan: (plan: InfrastructurePlan) => Promise<void>
  proposeAuthorization: () => Promise<void>
  activateAuthorization: (approvalId: string) => Promise<void>
  revokeAuthorization: () => Promise<Receipt | null>
}

export function useInfrastructure(instanceId: string): InfrastructureState & InfrastructureActions {
  const [target, setTarget] = useState<InfrastructureTarget | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<unknown>(null)
  const [targetUnavailable, setTargetUnavailable] = useState(false)
  const [unavailableReason, setUnavailableReason] = useState<string | undefined>(undefined)
  const [refreshFailed, setRefreshFailed] = useState(false)
  const [lastRefreshAt, setLastRefreshAt] = useState<string | null>(null)
  const [plans, setPlans] = useState<InfrastructurePlan[]>([])
  const [activePlanId, setActivePlanId] = useState<string | null>(null)
  const [authorization, setAuthorization] = useState<AuthorizationGrant | null>(null)
  const [receipts, setReceipts] = useState<Receipt[]>([])
  const [run, setRun] = useState<RunState | null>(null)
  const [nonce, setNonce] = useState(0)

  const activePlanIdRef = useRef<string | null>(null)
  activePlanIdRef.current = activePlanId

  const refresh = useCallback(() => setNonce((n) => n + 1), [])
  const { hasCapability } = useCurrentInstance()
  const hasCtoOrchestration = hasCapability('cto_orchestration')

  // ── Load / reload all surface data ─────────────────────────────────────────
  useEffect(() => {
    if (!instanceId) return
    let cancelled = false
    const client = getClient()
    const firstLoad = nonce === 0
    if (firstLoad) setLoading(true)

    const load = async () => {
      let nextTarget: InfrastructureTarget | null = null
      let unavailable = false
      let reason: string | undefined
      try {
        nextTarget = await client.infrastructure.getTarget(instanceId)
        if (!nextTarget.available) {
          unavailable = true
          reason = nextTarget.unavailableReason
        }
      } catch (err) {
        if (err instanceof ClientError && err.kind === 'unavailable') {
          unavailable = true
          reason = err.detail ?? err.message
        } else {
          throw err
        }
      }
      // Secondary facts load only when a target could be verified at all —
      // the blocked state never shows a half-loaded workflow.
      let nextPlans: InfrastructurePlan[] = []
      let nextAuthorization: AuthorizationGrant | null = null
      let nextReceipts: Receipt[] = []
      if (!unavailable) {
        ;[nextPlans, nextAuthorization, nextReceipts] = await Promise.all([
          client.infrastructure.listPlans(instanceId),
          client.infrastructure.getAuthorization(instanceId),
          client.receipts.list({ instanceId, limit: 30, goalExecution: hasCtoOrchestration }),
        ])
      }
      if (cancelled) return
      setTarget(nextTarget)
      setTargetUnavailable(unavailable)
      setUnavailableReason(reason)
      setPlans(nextPlans)
      setAuthorization(nextAuthorization)
      setReceipts(nextReceipts)
      setLoadError(null)
      setRefreshFailed(false)
      setLastRefreshAt(new Date().toISOString())
      setLoading(false)
      // Keep the canvas plan pointing at a real plan; auto-select the newest
      // actionable one when nothing is selected yet.
      const currentId = activePlanIdRef.current
      const stillThere = currentId ? nextPlans.some((p) => p.id === currentId) : false
      if (!stillThere) {
        const actionable = nextPlans.find((p) =>
          ['prepared', 'awaiting_approval', 'approved', 'running', 'validating'].includes(p.state),
        )
        activePlanIdRef.current = actionable?.id ?? null
        setActivePlanId(actionable?.id ?? null)
      }
    }

    load().catch((err) => {
      if (cancelled) return
      if (firstLoad) {
        setLoadError(err)
        setLoading(false)
      } else {
        // Background refresh failure → stale banner, keep the last truth.
        setRefreshFailed(true)
      }
    })
    return () => {
      cancelled = true
    }
  }, [instanceId, nonce, hasCtoOrchestration])

  // ── Poll while a plan awaits approval (the decision lives in Approvals) ────
  const activePlan = useMemo(
    () => plans.find((p) => p.id === activePlanId) ?? null,
    [plans, activePlanId],
  )

  useEffect(() => {
    if (!instanceId || !activePlan || activePlan.state !== 'awaiting_approval') return
    let cancelled = false
    const timer = window.setInterval(async () => {
      try {
        const fresh = await getClient().infrastructure.getPlan(instanceId, activePlan.id)
        if (cancelled) return
        setPlans((prev) => prev.map((p) => (p.id === fresh.id ? fresh : p)))
      } catch {
        /* transient — next poll retries */
      }
    }, APPROVAL_POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [instanceId, activePlan])

  // ── Read-only operations ───────────────────────────────────────────────────
  const observe = useCallback(async () => {
    const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
    try {
      const next = await getClient().infrastructure.observe(instanceId)
      setTarget(next)
      setTargetUnavailable(!next.available)
      setUnavailableReason(next.unavailableReason)
    } finally {
      releaseOperationsMutation()
    }
  }, [instanceId])

  const validateConfiguration = useCallback(async () => {
    const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
    try {
      const result = await getClient().infrastructure.validateConfiguration(instanceId)
      setReceipts((prev) => [result.receipt, ...prev])
    } finally {
      releaseOperationsMutation()
    }
  }, [instanceId])

  const healthCheck = useCallback(async () => {
    const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
    try {
      const result = await getClient().infrastructure.healthCheck(instanceId)
      setTarget(result.target)
      setReceipts((prev) => [result.receipt, ...prev])
    } finally {
      releaseOperationsMutation()
    }
  }, [instanceId])

  // ── Plan lifecycle ─────────────────────────────────────────────────────────
  const preparePlan = useCallback(
    async (operation: InfrastructureOperation): Promise<InfrastructurePlan> => {
      const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
      try {
        const plan = await getClient().infrastructure.preparePlan(instanceId, operation)
        setPlans((prev) => [plan, ...prev.filter((p) => p.id !== plan.id)])
        setActivePlanId(plan.id)
        setRun(null)
        return plan
      } finally {
        releaseOperationsMutation()
      }
    },
    [instanceId],
  )

  const selectPlan = useCallback((planId: string | null) => {
    setActivePlanId(planId)
    setRun(null)
  }, [])

  const dismissPlan = useCallback(() => {
    setActivePlanId(null)
    setRun(null)
  }, [])

  const runPlan = useCallback(
    async (plan: InfrastructurePlan): Promise<void> => {
      const client = getClient()
      const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
      const startedAt = new Date().toISOString()
      setRun({
        planId: plan.id,
        phase: 'running',
        stepStates: {},
        logs: [],
        startedAt,
      })
      const markPlan = (state: OperationState, receiptId?: string) =>
        setPlans((prev) =>
          prev.map((p) => (p.id === plan.id ? { ...p, state, receiptId: receiptId ?? p.receiptId } : p)),
        )
      markPlan('running')
      try {
        const stream = client.infrastructure.runPlan(
          plan.id,
          plan.approvalId ? { approvalId: plan.approvalId } : undefined,
        )
        for await (const event of stream) {
          if (event.type === 'state') {
            if (event.state === 'validating') {
              setRun((prev) => (prev ? { ...prev, phase: 'validating' } : prev))
              markPlan('validating')
            } else {
              markPlan(event.state)
            }
          } else if (event.type === 'step') {
            setRun((prev) =>
              prev
                ? { ...prev, stepStates: { ...prev.stepStates, [event.stepIndex]: event.stepState } }
                : prev,
            )
          } else if (event.type === 'log') {
            setRun((prev) => (prev ? { ...prev, logs: [...prev.logs, event.line] } : prev))
          } else if (event.type === 'done') {
            const finalState: OperationState =
              event.receipt.validation.state === 'validated'
                ? 'validated'
                : event.receipt.result === 'executed'
                  ? 'completed'
                  : event.receipt.result
            markPlan(finalState, event.receipt.id)
            setRun((prev) =>
              prev
                ? {
                    ...prev,
                    phase: 'done',
                    finishedAt: new Date().toISOString(),
                    receipt: event.receipt,
                  }
                : prev,
            )
            setReceipts((prev) => [event.receipt, ...prev])
          } else if (event.type === 'error') {
            markPlan('failed')
            setRun((prev) =>
              prev
                ? { ...prev, phase: 'failed', finishedAt: new Date().toISOString(), error: event.message }
                : prev,
            )
          }
        }
      } catch (err) {
        if (err instanceof ClientError && err.code === 'run_reconciliation_required') {
          // Replay guard: the backend already holds a run record for this
          // exact plan (a previous response was lost or a run is concurrently
          // active). This attempt executed nothing, so it must not read as an
          // execution failure — the run may still be in progress. Say so and
          // re-read the authoritative projection instead of retrying.
          markPlan('interrupted')
          setRun((prev) =>
            prev
              ? {
                  ...prev,
                  phase: 'reconciling',
                  finishedAt: new Date().toISOString(),
                  error:
                    'Run already in progress — reconciliation required. ' +
                    'The backend reports this exact plan may already have a run under way; ' +
                    'it was not re-executed. Refreshing the current state.',
                }
              : prev,
          )
          refresh()
          return
        }
        markPlan('failed')
        setRun((prev) =>
          prev
            ? {
                ...prev,
                phase: 'failed',
                finishedAt: new Date().toISOString(),
                error: err instanceof Error ? err.message : String(err),
              }
            : prev,
        )
      } finally {
        releaseOperationsMutation()
        // Refresh truth after the run settles (VM power/SSH/health moved).
        try {
          const next = await client.infrastructure.getTarget(instanceId)
          setTarget(next)
          setTargetUnavailable(!next.available)
          setUnavailableReason(next.unavailableReason)
        } catch {
          /* target may be destroyed — the next full refresh reflects it */
        }
      }
    },
    [instanceId, refresh],
  )

  // ── Daily-driver authorization ─────────────────────────────────────────────
  const proposeAuthorization = useCallback(async () => {
    const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
    try {
      const grant = await getClient().infrastructure.proposeAuthorization(instanceId)
      setAuthorization(grant)
    } finally {
      releaseOperationsMutation()
    }
  }, [instanceId])

  const activateAuthorization = useCallback(
    async (approvalId: string) => {
      const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
      try {
        const result = await getClient().infrastructure.activateAuthorization(instanceId, { approvalId })
        setAuthorization(result.grant)
        setReceipts((prev) => [result.receipt, ...prev])
      } finally {
        releaseOperationsMutation()
      }
    },
    [instanceId],
  )

  const revokeAuthorization = useCallback(async (): Promise<Receipt | null> => {
    const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
    try {
      const result = await getClient().infrastructure.revokeAuthorization(instanceId)
      setAuthorization(result.grant)
      setReceipts((prev) => [result.receipt, ...prev])
      return result.receipt
    } finally {
      releaseOperationsMutation()
    }
  }, [instanceId])

  return {
    target,
    loading,
    loadError,
    targetUnavailable,
    unavailableReason,
    refreshFailed,
    lastRefreshAt,
    plans,
    activePlanId,
    authorization,
    receipts,
    run,
    refresh,
    observe,
    validateConfiguration,
    healthCheck,
    preparePlan,
    selectPlan,
    dismissPlan,
    runPlan,
    proposeAuthorization,
    activateAuthorization,
    revokeAuthorization,
  }
}
