/**
 * First-run progress for the Applications page: has any application ever run
 * an action? The answer comes from the service's own run history, never from
 * a click in this browser.
 */
import { useEffect, useRef, useState } from 'react'

import type { ApplicationInstance } from '@/client'
import { getClient } from '@/client'

export interface FirstRunProgress {
  /** True when at least one run exists for one of the applications. */
  hasRun: boolean
  loading: boolean
  /** The last failure; the page then says "unknown", not "no runs". */
  error: unknown
}

export function useFirstRunProgress(instances: ApplicationInstance[]): FirstRunProgress {
  const [state, setState] = useState<FirstRunProgress>({ hasRun: false, loading: true, error: null })
  const mounted = useRef(true)
  const key = instances.map((instance) => instance.id).join(',')

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    if (instances.length === 0) {
      setState({ hasRun: false, loading: false, error: null })
      return () => {
        cancelled = true
      }
    }
    setState((current) => ({ ...current, loading: true }))
    void Promise.all(instances.map((instance) => getClient().runs.getHistory(instance.id)))
      .then((histories) => {
        if (cancelled || !mounted.current) return
        setState({ hasRun: histories.some((history) => history.length > 0), loading: false, error: null })
      })
      .catch((error: unknown) => {
        if (cancelled || !mounted.current) return
        setState({ hasRun: false, loading: false, error })
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `key` is the identity of the instance set
  }, [key])

  return state
}
