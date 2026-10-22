/**
 * Single data owner for model routes in the browser.
 *
 * - The view is always the service's `GET /v1/models` answer; every mutation
 *   is followed by a re-read, never by an optimistic local edit.
 * - A failed load is an error state, never a default "ready".
 * - An evaluation run is polled every 2 s only while it is unsettled and the
 *   consumer is mounted.
 */
import { useCallback, useEffect, useRef, useState } from 'react'

import {
  getModelsClient,
  suiteRunSettled,
  type ModelSuiteRun,
  type ModelsView,
} from '@/client/modelsClient'

export const SUITE_POLL_MS = 2000

export interface ModelsViewState {
  /** `error` only when nothing was ever loaded; a failed refresh keeps the last view. */
  status: 'loading' | 'ready' | 'error'
  view: ModelsView | null
  /** The latest load failure (also set while showing a last-known view). */
  loadError: unknown
  /** The last refused or failed mutation, shown next to the controls. */
  mutationError: unknown
  busy: boolean
  /** The practice-suite run being followed, if any. */
  suiteRun: ModelSuiteRun | null
  suiteRunError: unknown
  refresh: () => void
  /** Run a mutation, then re-read the view. Resolves true on success. */
  mutate: (operation: () => Promise<unknown>) => Promise<boolean>
  evaluate: (models: string[]) => Promise<void>
  clearMutationError: () => void
}

export function useModelsView(): ModelsViewState {
  const [nonce, setNonce] = useState(0)
  const [state, setState] = useState<{ key: number; view: ModelsView | null; error: unknown } | null>(null)
  const [busy, setBusy] = useState(false)
  const [mutationError, setMutationError] = useState<unknown>(null)
  const [suiteRunId, setSuiteRunId] = useState<string | null>(null)
  const [suiteRun, setSuiteRun] = useState<ModelSuiteRun | null>(null)
  const [suiteRunError, setSuiteRunError] = useState<unknown>(null)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    getModelsClient()
      .getView()
      .then((view) => {
        if (cancelled) return
        setState({ key: nonce, view, error: null })
        if (view.evaluation.activeRunId) setSuiteRunId((current) => current ?? view.evaluation.activeRunId)
      })
      .catch((error: unknown) => {
        if (!cancelled) setState((current) => ({ key: nonce, view: current?.view ?? null, error }))
      })
    return () => {
      cancelled = true
    }
  }, [nonce])

  // Follow one evaluation run until it settles; then re-read the view so the
  // new scores (and any route proposal they produced) appear.
  useEffect(() => {
    if (!suiteRunId) return
    let cancelled = false
    let timer: number | undefined
    const poll = async () => {
      try {
        const run = await getModelsClient().getRun(suiteRunId)
        if (cancelled) return
        setSuiteRun(run)
        setSuiteRunError(null)
        if (suiteRunSettled(run)) {
          setSuiteRunId(null)
          setNonce((value) => value + 1)
          return
        }
      } catch (error: unknown) {
        if (cancelled) return
        setSuiteRunError(error)
        setSuiteRunId(null)
        return
      }
      timer = window.setTimeout(() => void poll(), SUITE_POLL_MS)
    }
    void poll()
    return () => {
      cancelled = true
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [suiteRunId])

  const refresh = useCallback(() => {
    setMutationError(null)
    setNonce((value) => value + 1)
  }, [])

  const mutate = useCallback(async (operation: () => Promise<unknown>) => {
    setBusy(true)
    setMutationError(null)
    try {
      await operation()
      return true
    } catch (error: unknown) {
      if (mounted.current) setMutationError(error)
      return false
    } finally {
      if (mounted.current) {
        setBusy(false)
        // Re-read either way: a refused mutation may still have changed nothing
        // or something, and only the service knows which.
        setNonce((value) => value + 1)
      }
    }
  }, [])

  const evaluate = useCallback(
    async (models: string[]) => {
      setSuiteRun(null)
      setSuiteRunError(null)
      let runId: string | null = null
      await mutate(async () => {
        runId = (await getModelsClient().evaluate(models)).runId
      })
      if (runId && mounted.current) setSuiteRunId(runId)
    },
    [mutate],
  )

  const clearMutationError = useCallback(() => setMutationError(null), [])

  const view = state?.view ?? null
  const latestError = state?.key === nonce ? state.error : null

  return {
    status: view ? 'ready' : latestError ? 'error' : 'loading',
    view,
    loadError: latestError,
    mutationError,
    busy,
    suiteRun,
    suiteRunError,
    refresh,
    mutate,
    evaluate,
    clearMutationError,
  }
}
