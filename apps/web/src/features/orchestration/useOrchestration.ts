/**
 * useOrchestration — the CTO Orchestration surface's data layer.
 *
 * Bounded one-slice coordination through the typed client: getCurrent →
 * prepareSlice → (local review paging) → approve → run (progress events) →
 * submitReview → close → receipt, plus an always-available stop. The hook
 * keeps no timers that advance anything by itself — the only polling is a
 * manual Reload, and no transition happens without its stage's control.
 */
import { useCallback, useEffect, useRef, useState } from 'react'

import type {
  OrchestrationBackendAvailability,
  OrchestrationMode,
  OrchestrationSession,
  OrchestrationStage,
  Receipt,
} from '@/client'
import { ClientError, getClient } from '@/client'
import { useSessionStore } from '@/state'

export type OrchestrationStatus = 'loading' | 'ready' | 'unavailable' | 'error'

export interface OrchestrationRunState {
  running: boolean
  logs: string[]
  receipt?: Receipt
  error?: string
  startedAt?: string
  finishedAt?: string
}

export interface OrchestrationState {
  status: OrchestrationStatus
  session: OrchestrationSession | null
  /**
   * Typed backend availability from the connected service. When
   * `unavailable`, the UI must show the plain reason and next action rather
   * than offering active orchestration the backend would always refuse.
   */
  backend?: OrchestrationBackendAvailability
  /** Detail for "Inspect technical details" in the unavailable state. */
  unavailableDetail?: string
  /** Unexpected load failure detail. */
  errorDetail?: string
  /** Local review sub-stage (review paging never touches domain state). */
  localStage: OrchestrationStage | null
  run: OrchestrationRunState
  busy: boolean
}

export interface OrchestrationActions {
  reload: () => void
  prepareSlice: (input: { objective: string; mode: OrchestrationMode }) => Promise<void>
  setLocalStage: (stage: OrchestrationStage | null) => void
  approve: () => Promise<void>
  runSlice: () => Promise<void>
  stop: () => Promise<void>
  submitReview: (input: { accepted: boolean; notes?: string }) => Promise<void>
  close: () => Promise<void>
  /** Let the user start a fresh objective after a closed/receipt session. */
  startNewSlice: () => void
}

export function useOrchestration(instanceId: string): OrchestrationState & OrchestrationActions {
  const [status, setStatus] = useState<OrchestrationStatus>('loading')
  const [session, setSession] = useState<OrchestrationSession | null>(null)
  const [backend, setBackend] = useState<OrchestrationBackendAvailability | undefined>(undefined)
  const [unavailableDetail, setUnavailableDetail] = useState<string | undefined>(undefined)
  const [errorDetail, setErrorDetail] = useState<string | undefined>(undefined)
  const [localStage, setLocalStage] = useState<OrchestrationStage | null>(null)
  const [run, setRun] = useState<OrchestrationRunState>({ running: false, logs: [] })
  const [busy, setBusy] = useState(false)
  const [nonce, setNonce] = useState(0)
  const runRef = useRef<AbortController | null>(null)

  const reload = useCallback(() => setNonce((n) => n + 1), [])

  useEffect(() => {
    if (!instanceId) return
    let cancelled = false
    setStatus('loading')
    getClient()
      .orchestration.getView(instanceId)
      .then((view) => {
        if (cancelled) return
        setSession(view.session)
        setBackend(view.backendAvailability)
        setLocalStage(null)
        setStatus('ready')
      })
      .catch((err) => {
        if (cancelled) return
        if (err instanceof ClientError && err.kind === 'unavailable') {
          setUnavailableDetail(err.detail ?? err.message)
          setStatus('unavailable')
        } else {
          setErrorDetail(err instanceof Error ? err.message : String(err))
          setStatus('error')
        }
      })
    return () => {
      cancelled = true
    }
  }, [instanceId, nonce])

  const withBusy = useCallback(async (action: () => Promise<void>) => {
    setBusy(true)
    const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
    try {
      await action()
    } finally {
      releaseOperationsMutation()
      setBusy(false)
    }
  }, [])

  const prepareSlice = useCallback(
    async (input: { objective: string; mode: OrchestrationMode }) => {
      await withBusy(async () => {
        const prepared = await getClient().orchestration.prepareSlice(instanceId, input)
        setSession(prepared)
        setLocalStage('review_base')
        setRun({ running: false, logs: [] })
      })
    },
    [instanceId, withBusy],
  )

  const approve = useCallback(async () => {
    if (!session) return
    await withBusy(async () => {
      const next = await getClient().orchestration.approve(session.id)
      setSession(next)
      setLocalStage(null)
    })
  }, [session, withBusy])

  const runSlice = useCallback(async () => {
    if (!session) return
    const controller = new AbortController()
    runRef.current = controller
    const releaseOperationsMutation = useSessionStore.getState().beginOperationsMutation()
    setRun({ running: true, logs: [], startedAt: new Date().toISOString() })
    setSession((prev) => (prev ? { ...prev, state: 'running' } : prev))
    try {
      const stream = getClient().orchestration.run(session.id)
      for await (const event of stream) {
        if (controller.signal.aborted) break
        if (event.type === 'log') {
          setRun((prev) => ({ ...prev, logs: [...prev.logs, event.line] }))
        } else if (event.type === 'done') {
          setRun((prev) => ({
            ...prev,
            running: false,
            receipt: event.receipt,
            finishedAt: new Date().toISOString(),
          }))
        }
      }
    } catch (err) {
      setRun((prev) => ({
        ...prev,
        running: false,
        finishedAt: new Date().toISOString(),
        error: err instanceof Error ? err.message : String(err),
      }))
    } finally {
      releaseOperationsMutation()
      // Settle truth from the client (stage/state/budget moved).
      try {
        const current = await getClient().orchestration.getCurrent(instanceId)
        setSession(current)
        setLocalStage(null)
      } catch {
        /* keep the last known state */
      }
      setRun((prev) => ({ ...prev, running: false }))
      runRef.current = null
    }
  }, [session, instanceId])

  const stop = useCallback(async () => {
    if (!session) return
    runRef.current?.abort()
    await withBusy(async () => {
      const next = await getClient().orchestration.stop(session.id)
      setSession(next)
      setLocalStage(null)
      setRun((prev) => ({ ...prev, running: false, finishedAt: new Date().toISOString() }))
    })
  }, [session, withBusy])

  const submitReview = useCallback(
    async (input: { accepted: boolean; notes?: string }) => {
      if (!session) return
      await withBusy(async () => {
        const next = await getClient().orchestration.submitReview(session.id, input)
        setSession(next)
        setLocalStage(null)
      })
    },
    [session, withBusy],
  )

  const close = useCallback(async () => {
    if (!session) return
    await withBusy(async () => {
      await getClient().orchestration.close(session.id)
      const current = await getClient().orchestration.getCurrent(instanceId)
      setSession(current)
      setLocalStage(null)
    })
  }, [session, instanceId, withBusy])

  const startNewSlice = useCallback(() => {
    // The next prepareSlice replaces the archived session in the mock store.
    setSession(null)
    setLocalStage('enter_objective')
    setRun({ running: false, logs: [] })
  }, [])

  return {
    status,
    session,
    backend,
    unavailableDetail,
    errorDetail,
    localStage,
    run,
    busy,
    reload,
    prepareSlice,
    setLocalStage,
    approve,
    runSlice,
    stop,
    submitReview,
    close,
    startNewSlice,
  }
}
