/**
 * Single data owner for the governed Runs surface.
 *
 * Actions, engines, and history load as one keyed snapshot. Transitions bind
 * the exact instance and revision from the loaded run. Failures remain the
 * service's failures: this layer does not relabel a generic 400/409 as stale
 * and never retries a mutation implicitly.
 */
import { useCallback, useEffect, useRef, useState } from 'react'

import type {
  ExecutionEngine,
  GovernedAction,
  RunOperation,
  RunRecord,
} from '@/client'
import { getClient } from '@/client'

interface RunsSnapshot {
  key: string
  actions: GovernedAction[]
  engines: ExecutionEngine[]
  history: RunRecord[]
  error: unknown
}

export interface RunsState {
  status: 'loading' | 'ready' | 'error'
  loadError: unknown
  transitionError: unknown
  actions: GovernedAction[]
  engines: ExecutionEngine[]
  history: RunRecord[]
  activeRun: RunRecord | null
  busy: boolean
}

export interface RunsActions {
  refresh: () => void
  prepare: (input: {
    actionId: string
    engineId: string
    inputs: Record<string, unknown>
  }) => Promise<RunRecord | null>
  transition: (run: RunRecord, operation: RunOperation) => Promise<RunRecord | null>
  selectRun: (run: RunRecord | null) => void
  dismissActiveRun: () => void
  clearTransitionError: () => void
}

export function useRuns(instanceId: string): RunsState & RunsActions {
  const [nonce, setNonce] = useState(0)
  const [snapshot, setSnapshot] = useState<RunsSnapshot | null>(null)
  const [activeRun, setActiveRun] = useState<RunRecord | null>(null)
  const [transitionError, setTransitionError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const requestKey = `${instanceId}#${nonce}`
  const currentRequestKey = useRef(requestKey)
  currentRequestKey.current = requestKey

  useEffect(() => {
    if (!instanceId) return
    let cancelled = false
    const client = getClient()
    Promise.all([
      client.runs.listActions(instanceId),
      client.runs.listEngines(),
      client.runs.getHistory(instanceId),
    ])
      .then(([actions, engines, history]) => {
        if (cancelled) return
        setSnapshot({ key: requestKey, actions, engines, history, error: null })
        setActiveRun((current) =>
          current ? (history.find((run) => run.id === current.id) ?? null) : null,
        )
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setSnapshot({ key: requestKey, actions: [], engines: [], history: [], error })
        }
      })
    return () => {
      cancelled = true
    }
  }, [instanceId, requestKey])

  const landed = snapshot?.key === requestKey ? snapshot : null
  const status = !landed ? 'loading' : landed.error ? 'error' : 'ready'

  const updateRun = useCallback(
    (run: RunRecord) => {
      if (currentRequestKey.current !== requestKey) return
      setActiveRun(run)
      setSnapshot((current) => {
        if (!current || current.key !== requestKey) return current
        return {
          ...current,
          history: [run, ...current.history.filter((item) => item.id !== run.id)],
        }
      })
    },
    [requestKey],
  )

  const refresh = useCallback(() => {
    setTransitionError(null)
    setNonce((value) => value + 1)
  }, [])

  const prepare = useCallback(
    async (input: {
      actionId: string
      engineId: string
      inputs: Record<string, unknown>
    }): Promise<RunRecord | null> => {
      setBusy(true)
      setTransitionError(null)
      try {
        const run = await getClient().runs.prepare(instanceId, input)
        updateRun(run)
        return run
      } catch (error: unknown) {
        setTransitionError(error)
        return null
      } finally {
        setBusy(false)
      }
    },
    [instanceId, updateRun],
  )

  const transition = useCallback(
    async (run: RunRecord, operation: RunOperation): Promise<RunRecord | null> => {
      setBusy(true)
      setTransitionError(null)
      try {
        const next = await getClient().runs.transition(run.id, operation, {
          expectedInstanceId: run.instanceId,
          expectedRevision: run.revision,
        })
        updateRun(next)
        return next
      } catch (error: unknown) {
        setTransitionError(error)
        return null
      } finally {
        setBusy(false)
      }
    },
    [updateRun],
  )

  const selectRun = useCallback((run: RunRecord | null) => {
    setTransitionError(null)
    setActiveRun(run)
  }, [])
  const dismissActiveRun = useCallback(() => {
    setTransitionError(null)
    setActiveRun(null)
  }, [])
  const clearTransitionError = useCallback(() => setTransitionError(null), [])

  return {
    status,
    loadError: landed?.error ?? null,
    transitionError,
    actions: landed?.actions ?? [],
    engines: landed?.engines ?? [],
    history: landed?.history ?? [],
    activeRun,
    busy,
    refresh,
    prepare,
    transition,
    selectRun,
    dismissActiveRun,
    clearTransitionError,
  }
}
