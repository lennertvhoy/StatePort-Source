/**
 * Data owner for the application actions card.
 *
 * One owner click runs the whole governed sequence: prepare → approve the
 * exact compiled run (the click is the approval) → execute → wait while the
 * run is still in flight. Every step binds the run's exact instance and
 * revision; nothing is retried implicitly. Agent actions additionally require
 * a ready model route from `GET /v1/models`.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type { ExecutionEngine, GovernedAction, RunOperation, RunRecord } from '@/client'
import { getClient } from '@/client'
import { getModelsClient, type ModelsView } from '@/client/modelsClient'
import { useCurrentInstance } from '@/shell/currentInstance'
import { invalidateInstanceCache } from '@/shell/data'
import { useSessionStore } from '@/state'

import { cardActions, engineForAction, latestRunByAction, runSettled, type ActionPhase, type KindedAction } from './actionsModel'

export const RUN_POLL_MS = 2000
/** Grace on top of the action's own time limit before the card stops waiting. */
const WAIT_GRACE_MS = 120_000

export interface ActionActivity {
  actionId: string
  phase: ActionPhase
  startedAt: number
}

export interface ModelsState {
  status: 'idle' | 'loading' | 'ready' | 'error'
  view: ModelsView | null
  error: unknown
}

interface Snapshot {
  key: string
  actions: GovernedAction[]
  engines: ExecutionEngine[]
  history: RunRecord[]
  error: unknown
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

const sleep = (ms: number) => new Promise<void>((resolve) => window.setTimeout(resolve, ms))

export function useApplicationActions(instanceId: string) {
  const { refresh: refreshInstanceContext } = useCurrentInstance()
  const [nonce, setNonce] = useState(0)
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [models, setModels] = useState<ModelsState>({ status: 'idle', view: null, error: null })
  const [activity, setActivity] = useState<ActionActivity | null>(null)
  const [sessionRuns, setSessionRuns] = useState<Record<string, RunRecord>>({})
  const [errors, setErrors] = useState<Record<string, string>>({})
  const mounted = useRef(true)
  const requestKey = `${instanceId}#${nonce}`

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    const client = getClient()
    Promise.all([client.runs.listActions(instanceId), client.runs.listEngines(), client.runs.getHistory(instanceId)])
      .then(([actions, engines, history]) => {
        if (!cancelled) setSnapshot({ key: requestKey, actions, engines, history, error: null })
      })
      .catch((error: unknown) => {
        if (!cancelled) setSnapshot({ key: requestKey, actions: [], engines: [], history: [], error })
      })
    return () => {
      cancelled = true
    }
  }, [instanceId, requestKey])

  const landed = snapshot?.key === requestKey ? snapshot : null
  const history = useMemo(() => landed?.history ?? [], [landed])
  const { actions, setupFirst } = useMemo(() => cardActions(landed?.actions ?? [], history), [landed, history])
  const hasAgentAction = actions.some((action) => action.kind === 'agent')

  // Model routes matter only when the instance offers an agent action.
  useEffect(() => {
    if (!hasAgentAction) return
    let cancelled = false
    setModels((current) => ({ ...current, status: current.view ? 'ready' : 'loading' }))
    getModelsClient()
      .getView()
      .then((view) => {
        if (!cancelled) setModels({ status: 'ready', view, error: null })
      })
      .catch((error: unknown) => {
        if (!cancelled) setModels({ status: 'error', view: null, error })
      })
    return () => {
      cancelled = true
    }
  }, [hasAgentAction, nonce])

  const latestRuns = useMemo(() => {
    const latest = latestRunByAction(history)
    for (const [actionId, run] of Object.entries(sessionRuns)) {
      if (run.instanceId === instanceId) latest.set(actionId, run)
    }
    return latest
  }, [history, sessionRuns, instanceId])

  const sessionRunIds = useMemo(() => new Set(Object.values(sessionRuns).map((run) => run.id)), [sessionRuns])

  const otherActionCount = (landed?.actions.length ?? 0) - actions.length

  const refresh = useCallback(() => {
    setErrors({})
    setNonce((value) => value + 1)
  }, [])

  const record = useCallback((actionId: string, run: RunRecord) => {
    if (mounted.current) setSessionRuns((current) => ({ ...current, [actionId]: run }))
  }, [])

  const fail = useCallback((actionId: string, error: unknown) => {
    if (mounted.current) setErrors((current) => ({ ...current, [actionId]: message(error) }))
  }, [])

  const transition = useCallback(
    (run: RunRecord, operation: RunOperation) =>
      getClient().runs.transition(run.id, operation, { expectedInstanceId: run.instanceId, expectedRevision: run.revision }),
    [],
  )

  /** Re-read history until the run leaves its in-flight statuses. */
  const settle = useCallback(
    async (run: RunRecord, timeoutSeconds: number | undefined): Promise<RunRecord> => {
      const deadline = Date.now() + (timeoutSeconds ?? 300) * 1000 + WAIT_GRACE_MS
      let current = run
      while (!runSettled(current)) {
        if (!mounted.current) return current
        if (Date.now() > deadline) {
          throw new Error('The run has not finished yet. Its current state is on the Runs page; nothing was retried.')
        }
        await sleep(RUN_POLL_MS)
        const latest = await getClient().runs.getHistory(instanceId)
        current = latest.find((item) => item.id === run.id) ?? current
      }
      return current
    },
    [instanceId],
  )

  const afterMutation = useCallback(() => {
    invalidateInstanceCache(instanceId)
    refreshInstanceContext()
  }, [instanceId, refreshInstanceContext])

  const begin = useCallback((actionId: string, phase: ActionPhase) => {
    setErrors((current) => {
      if (!(actionId in current)) return current
      const next = { ...current }
      delete next[actionId]
      return next
    })
    setActivity({ actionId, phase, startedAt: Date.now() })
  }, [])

  const setPhase = useCallback((phase: ActionPhase) => {
    if (mounted.current) setActivity((current) => (current ? { ...current, phase } : current))
  }, [])

  /** Prepare → approve → execute → settle. The owner's click is the run approval. */
  const runAction = useCallback(
    async (action: KindedAction, inputs: Record<string, unknown>) => {
      if (activity) return
      const engine = engineForAction(action, landed?.engines ?? [])
      if (!engine) {
        fail(action.id, 'No execution engine that this action allows is available on this StatePort.')
        return
      }
      begin(action.id, 'preparing')
      const release = useSessionStore.getState().beginOperationsMutation()
      try {
        let run = await getClient().runs.prepare(instanceId, { actionId: action.id, engineId: engine.id, inputs })
        record(action.id, run)
        if (run.status === 'awaiting_approval') {
          setPhase('approving')
          run = await transition(run, 'approve')
          record(action.id, run)
        }
        if (run.status === 'approved') {
          setPhase('running')
          run = await transition(run, 'execute')
          record(action.id, run)
        }
        run = await settle(run, action.timeoutSeconds)
        record(action.id, run)
      } catch (error: unknown) {
        fail(action.id, error)
      } finally {
        release()
        if (mounted.current) setActivity(null)
        afterMutation()
      }
    },
    [activity, landed, begin, instanceId, record, setPhase, transition, settle, fail, afterMutation],
  )

  /** Approve the exact proposal (if still pending), then apply it. */
  const applyProposal = useCallback(
    async (actionId: string, run: RunRecord) => {
      if (activity) return
      begin(actionId, 'applying')
      const release = useSessionStore.getState().beginOperationsMutation()
      try {
        let next = run
        if (next.status === 'state_change_proposed') {
          next = await transition(next, 'proposal-approve')
          record(actionId, next)
        }
        if (next.status === 'state_change_approved') {
          next = await transition(next, 'apply')
          record(actionId, next)
        }
        next = await settle(next, undefined)
        record(actionId, next)
      } catch (error: unknown) {
        fail(actionId, `${message(error)} Refresh to see the current state before trying again.`)
      } finally {
        release()
        if (mounted.current) setActivity(null)
        afterMutation()
      }
    },
    [activity, begin, transition, record, settle, fail, afterMutation],
  )

  const rejectProposal = useCallback(
    async (actionId: string, run: RunRecord) => {
      if (activity) return
      begin(actionId, 'rejecting')
      const release = useSessionStore.getState().beginOperationsMutation()
      try {
        record(actionId, await transition(run, 'proposal-reject'))
      } catch (error: unknown) {
        fail(actionId, error)
      } finally {
        release()
        if (mounted.current) setActivity(null)
        afterMutation()
      }
    },
    [activity, begin, transition, record, fail, afterMutation],
  )

  return {
    status: (!landed ? 'loading' : landed.error ? 'error' : 'ready') as 'loading' | 'ready' | 'error',
    loadError: landed?.error ?? null,
    actions,
    setupFirst,
    otherActionCount,
    engines: landed?.engines ?? [],
    latestRuns,
    sessionRunIds,
    models,
    activity,
    errors,
    refresh,
    runAction,
    applyProposal,
    rejectProposal,
  }
}
