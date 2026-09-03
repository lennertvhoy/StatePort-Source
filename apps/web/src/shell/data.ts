/**
 * Shell data hooks — poll the typed client boundary (getClient() only) and
 * mirror into stores for chrome surfaces. Feature agents own their own data;
 * these hooks exist only for shell chrome (service chip, sidebar, badges).
 */
import { useCallback, useEffect, useRef, useState } from 'react'

import type { ApplicationInstance } from '@/client'
import { getClient } from '@/client'
import { useSessionStore, useWorkspaceStore } from '@/state'

// ── Local service status + build info ────────────────────────────────────────

const SERVICE_POLL_MS = 30_000

/**
 * One-shot saved-navigation reconciliation at shell bootstrap. The saved
 * sidebar default applies only when the user never made an explicit sidebar
 * choice; the auto-collapse threshold always applies. When the service is
 * unreachable, the persisted local values stay in force.
 */
export function useSavedNavigationSettings(): void {
  useEffect(() => {
    let cancelled = false
    void getClient()
      .globalSettings.get()
      .then((settings) => {
        if (cancelled) return
        const workspace = useWorkspaceStore.getState()
        // No-op writes are skipped: an identical value must not notify
        // subscribers and re-render the shell for nothing.
        if (
          !workspace.sidebarUserChosen &&
          workspace.sidebar !== settings.navigation.sidebarDefault
        ) {
          workspace.setSidebar(settings.navigation.sidebarDefault, { userChosen: false })
        }
        if (workspace.sidebarAutoCollapseBelowPx !== settings.navigation.autoCollapseBelowPx) {
          workspace.setSidebarAutoCollapseBelowPx(settings.navigation.autoCollapseBelowPx)
        }
      })
      .catch(() => {
        // Offline or malformed settings: the persisted local defaults stand.
      })
    return () => {
      cancelled = true
    }
  }, [])
}

export function useServiceStatusPolling(): void {
  const activeScenario = useSessionStore((s) => s.activeScenario)

  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      try {
        const status = await getClient().session.getLocalServiceStatus()
        if (!cancelled) useSessionStore.getState().setServiceStatus(status)
      } catch {
        if (!cancelled) {
          useSessionStore.getState().setServiceStatus({
            state: 'offline',
            endpoint: '',
            detail: 'The local service could not be reached.',
          })
        }
      }
    }
    void tick()
    const timer = window.setInterval(tick, SERVICE_POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [activeScenario])

  useEffect(() => {
    let cancelled = false
    void getClient()
      .session.getBuildInfo()
      .then((info) => {
        if (!cancelled) useSessionStore.getState().setBuildInfo(info)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [])
}

export async function reconnectService(): Promise<void> {
  try {
    const status = await getClient().session.reconnect()
    useSessionStore.getState().setServiceStatus(status)
  } catch {
    useSessionStore.getState().setServiceStatus({
      state: 'offline',
      endpoint: '',
      detail: 'Reconnect failed — the local service is still unreachable.',
    })
  }
}

// ── Applications list (sidebar, switcher, palette) ───────────────────────────

interface ApplicationsResult {
  instances: ApplicationInstance[]
  loading: boolean
  error: unknown
  refresh: () => void
}

export function useApplications(): ApplicationsResult {
  // Keyed fetch result: instances/loading/error derive from whether the
  // in-flight key has landed, so the effect never sets state synchronously.
  const [result, setResult] = useState<{
    key: string
    instances: ApplicationInstance[]
    error: unknown
  } | null>(null)
  const [nonce, setNonce] = useState(0)
  const activeScenario = useSessionStore((s) => s.activeScenario)
  const requestKey = `${nonce}#${activeScenario ?? ''}`

  useEffect(() => {
    let cancelled = false
    getClient()
      .applications.list()
      .then((list) => {
        if (cancelled) return
        setResult({ key: requestKey, instances: list, error: null })
      })
      .catch((err) => {
        if (cancelled) return
        setResult((prev) => ({ key: requestKey, instances: prev?.instances ?? [], error: err }))
      })
    return () => {
      cancelled = true
    }
  }, [nonce, activeScenario, requestKey])

  const refresh = useCallback(() => setNonce((n) => n + 1), [])
  const landed = result && result.key === requestKey ? result : null
  return {
    instances: result?.instances ?? [],
    loading: !landed,
    error: landed?.error ?? null,
    refresh,
  }
}

/** Pinned first (user order), then up to `max` recents by lastOpenedAt. */
export function sidebarInstances(instances: ApplicationInstance[], maxRecents = 5): ApplicationInstance[] {
  const pinned = instances.filter((i) => i.pinned)
  const recents = instances
    .filter((i) => !i.pinned)
    .sort((a, b) => (b.lastOpenedAt ?? '').localeCompare(a.lastOpenedAt ?? ''))
    .slice(0, maxRecents)
  return [...pinned, ...recents]
}

// ── Instance cache (breadcrumb, titles, app shell) ───────────────────────────

const instanceCache = new Map<string, ApplicationInstance>()
const instanceInflight = new Map<string, Promise<ApplicationInstance>>()

export function primeInstanceCache(instance: ApplicationInstance): void {
  instanceCache.set(instance.id, instance)
}

export function fetchInstanceCached(instanceId: string): Promise<ApplicationInstance> {
  const cached = instanceCache.get(instanceId)
  if (cached) return Promise.resolve(cached)
  const inflight = instanceInflight.get(instanceId)
  if (inflight) return inflight
  const promise = getClient()
    .applications.get(instanceId)
    .then((instance) => {
      instanceCache.set(instanceId, instance)
      instanceInflight.delete(instanceId)
      return instance
    })
    .catch((err) => {
      instanceInflight.delete(instanceId)
      throw err
    })
  instanceInflight.set(instanceId, promise)
  return promise
}

export function invalidateInstanceCache(instanceId?: string): void {
  if (instanceId) instanceCache.delete(instanceId)
  else instanceCache.clear()
}

/** Instance name for chrome (breadcrumb/title). Returns undefined while loading/missing. */
export function useInstanceName(instanceId: string | undefined): string | undefined {
  const [name, setName] = useState<string | undefined>(() =>
    instanceId ? instanceCache.get(instanceId)?.name : undefined,
  )
  // Switching instances re-reads the cache synchronously (render-time
  // adjustment); only a cache miss needs the fetch effect below.
  const [prevInstanceId, setPrevInstanceId] = useState(instanceId)
  if (prevInstanceId !== instanceId) {
    setPrevInstanceId(instanceId)
    setName(instanceId ? instanceCache.get(instanceId)?.name : undefined)
  }
  useEffect(() => {
    if (!instanceId) return
    if (instanceCache.has(instanceId)) return
    let cancelled = false
    fetchInstanceCached(instanceId)
      .then((instance) => {
        if (!cancelled) setName(instance.name)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [instanceId])
  return name
}

// ── Pending approvals count (badges; honest neutral styling) ─────────────────

const APPROVALS_POLL_MS = 30_000

export interface ShellCountResult {
  /** Last successfully fetched count; retained across failed polls. */
  count: number
  /** Set when the latest poll failed — consumers must show an unavailable
   *  indication instead of presenting `count` as fresh truth. */
  error: unknown
}

export function usePendingApprovalsCount(): ShellCountResult {
  const [result, setResult] = useState<ShellCountResult>({ count: 0, error: null })
  const activeScenario = useSessionStore((s) => s.activeScenario)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    const tick = async () => {
      try {
        const list = await getClient().approvals.list({ status: 'pending' })
        if (mounted.current) setResult({ count: list.length, error: null })
      } catch (err) {
        // Honest failure: keep the last known count and flag it as stale
        // rather than reporting a misleading zero.
        if (mounted.current) setResult((prev) => ({ count: prev.count, error: err }))
      }
    }
    void tick()
    const timer = window.setInterval(tick, APPROVALS_POLL_MS)
    return () => {
      mounted.current = false
      window.clearInterval(timer)
    }
  }, [activeScenario])

  return result
}

// ── Operation records (operation center + status bar + topbar spinner) ───────

const OPERATIONS_POLL_MS = 3_000

export function useOperationsPolling(): void {
  const activeScenario = useSessionStore((s) => s.activeScenario)

  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      try {
        const records = await getClient().operations.list()
        if (!cancelled) {
          useSessionStore.getState().setOperations(records)
          useSessionStore.getState().setOperationsError(null)
        }
      } catch {
        // Honest failure: keep the last known operations and record that the
        // projection is unavailable, so consumers never read a failed poll as
        // "no operations".
        if (!cancelled) useSessionStore.getState().setOperationsError('Operations could not be loaded.')
      }
    }
    void tick()
    const timer = window.setInterval(tick, OPERATIONS_POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [activeScenario])
}

/** True when any operation is in a live (non-terminal) state. */
export function hasLiveOperation(records: { state: string }[]): boolean {
  return records.some((r) =>
    ['preparing', 'queued', 'running', 'validating', 'awaiting_approval', 'paused'].includes(r.state),
  )
}

// ── Unread notifications dot ─────────────────────────────────────────────────

export function useUnreadNotificationsCount(): ShellCountResult {
  const [result, setResult] = useState<ShellCountResult>({ count: 0, error: null })
  const activeScenario = useSessionStore((s) => s.activeScenario)

  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      try {
        const list = await getClient().activity.listNotifications()
        if (!cancelled) setResult({ count: list.filter((n) => !n.read).length, error: null })
      } catch (err) {
        // Honest failure: keep the last known count and flag it as stale.
        if (!cancelled) setResult((prev) => ({ count: prev.count, error: err }))
      }
    }
    void tick()
    const timer = window.setInterval(tick, 60_000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [activeScenario])

  return result
}

// ── Workbench layout helpers ─────────────────────────────────────────────────

/** Persist per-instance "last opened" continuity when an app route mounts. */
export function useMarkLastOpened(instanceId: string | undefined, view: string, tool?: string | null): void {
  useEffect(() => {
    if (!instanceId) return
    useWorkspaceStore.getState().setLastOpened(instanceId, view, tool as never)
    void getClient()
      .applications.touchOpened(instanceId)
      .catch(() => undefined)
  }, [instanceId, view, tool])
}
