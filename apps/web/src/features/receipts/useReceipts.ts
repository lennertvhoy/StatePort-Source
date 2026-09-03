/**
 * useReceipts — data hook for the Receipts surface. Loads the instance's
 * receipts through the client boundary, exposes honest loading/error states
 * with Retry, and quietly re-checks for newly appended receipts (the trail
 * is append-only, so a light poll suffices).
 */
import { useCallback, useEffect, useRef, useState } from 'react'

import type { Receipt } from '@/client'
import { getClient } from '@/client'
import { useCurrentInstance } from '@/shell/currentInstance'
import { useSessionStore } from '@/state'

const POLL_MS = 15_000

export interface ReceiptsData {
  receipts: Receipt[]
  loading: boolean
  error: unknown
  refresh: () => void
  /** Ids that arrived after the first load (for the one-sweep highlight). */
  newIds: ReadonlySet<string>
}

interface ReceiptsResult {
  key: string
  receipts: Receipt[]
  error: unknown
}

export function useReceipts(instanceId: string | undefined): ReceiptsData {
  // Keyed fetch result: receipts/loading/error derive from whether the
  // in-flight key has landed, so effects never set state synchronously.
  const [result, setResult] = useState<ReceiptsResult | null>(null)
  const [nonce, setNonce] = useState(0)
  const [newIds, setNewIds] = useState<ReadonlySet<string>>(new Set())
  const loadedInstance = useRef<string | null>(null)
  const activeScenario = useSessionStore((s) => s.activeScenario)
  const { hasCapability } = useCurrentInstance()
  const hasCtoOrchestration = hasCapability('cto_orchestration')

  const refresh = useCallback(() => setNonce((n) => n + 1), [])
  const requestKey = `${instanceId ?? ''}#${nonce}`

  useEffect(() => {
    if (!instanceId) return
    let cancelled = false

    const load = async (initial: boolean) => {
      try {
        const items = await getClient().receipts.list({ instanceId, goalExecution: hasCtoOrchestration })
        if (cancelled) return
        loadedInstance.current = instanceId
        setResult((prev) => {
          const prevSameInstance = prev && prev.key.startsWith(`${instanceId}#`) ? prev : null
          if (!initial && prevSameInstance) {
            const known = new Set(prevSameInstance.receipts.map((r) => r.id))
            const arrived = items.filter((r) => !known.has(r.id)).map((r) => r.id)
            if (arrived.length > 0) {
              setNewIds(new Set(arrived))
              // The highlight sweep plays once, then the ids clear.
              window.setTimeout(() => setNewIds(new Set()), 1200)
            }
          }
          return { key: requestKey, receipts: items, error: null }
        })
      } catch (err) {
        if (cancelled) return
        setResult((prev) => ({
          key: requestKey,
          receipts: prev && prev.key.startsWith(`${instanceId}#`) ? prev.receipts : [],
          error: err,
        }))
      }
    }

    const initial = loadedInstance.current !== instanceId
    void load(initial)
    const timer = window.setInterval(() => void load(false), POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [instanceId, nonce, activeScenario, requestKey, hasCtoOrchestration])

  const landed = result && result.key === requestKey ? result : null
  const sameInstance = result && result.key.startsWith(`${instanceId ?? ''}#`) ? result : null
  // A manual refresh keeps the previous list visible (background reload);
  // only a first load or an instance switch shows the loading state.
  const receipts = (landed ?? sameInstance)?.receipts ?? []
  const loading = Boolean(instanceId) && !landed && !sameInstance
  const error = landed?.error ?? null

  return { receipts, loading, error, refresh, newIds }
}
