/**
 * Shell data hooks — poll the typed client boundary (getClient() only) and
 * mirror into stores for chrome surfaces. Feature agents own their own data;
 * these hooks exist only for shell chrome (service chip, sidebar, badges).
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useState, useSyncExternalStore } from 'react'

import { useLocation, useNavigate } from 'react-router-dom'

import type { ApplicationInstance, GlobalSettings } from '@/client'
import { getClient } from '@/client'
import { useSessionStore, useWorkspaceStore } from '@/state'

// ── Local service status + build info ────────────────────────────────────────

const SERVICE_POLL_MS = 30_000

// Share only simultaneous shell/startup reads; never cache a saved preference.
const bootstrapSettingsRequests = new WeakMap<ReturnType<typeof getClient>, Promise<GlobalSettings>>()
export function fetchBootstrapSettings(): Promise<GlobalSettings> {
  const client = getClient()
  const pending = bootstrapSettingsRequests.get(client)
  if (pending) return pending
  const request = client.globalSettings.get().finally(() => {
    if (bootstrapSettingsRequests.get(client) === request) bootstrapSettingsRequests.delete(client)
  })
  bootstrapSettingsRequests.set(client, request)
  return request
}

interface StartupFocusSession {
  settings: Promise<GlobalSettings> | null
  entryKey: string | null
  finished: boolean
  attempt: object | null
}
export const StartupFocusContext = createContext<StartupFocusSession | null>(null)

/** Called by the Workbench only after its existing instance/tool guards pass. */
export function useStartupFocus(eligible: boolean): void {
  const session = useContext(StartupFocusContext)
  const location = useLocation()
  const navigate = useNavigate()
  useEffect(() => {
    if (!session || !eligible || session.finished) return
    if (session.entryKey === null) session.entryKey = location.key
    if (session.entryKey !== location.key) return
    if (new URLSearchParams(location.search).has('focus')) {
      session.finished = true
      return
    }
    let cancelled = false
    const attempt = {}
    session.attempt = attempt
    session.settings ??= fetchBootstrapSettings()
    void session.settings.then((settings) => {
      if (cancelled || session.finished) return
      session.finished = true
      if (settings.general.startInFocusMode !== true) return
      const search = new URLSearchParams(location.search)
      search.set('focus', '1')
      void navigate({ pathname: location.pathname, search: search.toString(), hash: location.hash }, {
        replace: true, state: location.state,
      })
    }).catch(() => { if (!cancelled) session.finished = true })
    return () => {
      cancelled = true
      // StrictMode immediately replaces this attempt; a real departure consumes
      // it, including browser Back restoring the same history location key.
      queueMicrotask(() => {
        if (session.attempt === attempt) session.finished = true
      })
    }
  }, [eligible, location, navigate, session])
}

/**
 * One-shot saved navigation/date-display reconciliation at shell bootstrap. The saved
 * sidebar default applies only when the user never made an explicit sidebar
 * choice; the auto-collapse threshold always applies. When the service is
 * unreachable, the persisted local values stay in force.
 */
export function useSavedNavigationSettings(): StartupFocusSession {
  const session = useMemo<StartupFocusSession>(() => ({ settings: null, entryKey: null, finished: false, attempt: null }), [])
  useEffect(() => {
    let cancelled = false
    const toolOrderGeneration = useWorkspaceStore.getState().workbenchToolOrderGeneration
    const dateTimeGeneration = useWorkspaceStore.getState().dateTimeFormatGeneration
    const layoutPersistenceGeneration = useWorkspaceStore.getState().layoutPersistenceGeneration
    const restoredLayouts = useWorkspaceStore.getState().layouts
    void (session.settings ??= fetchBootstrapSettings())
      .then((settings) => {
        if (cancelled) return
        const workspace = useWorkspaceStore.getState()
        if (workspace.dateTimeFormatGeneration === dateTimeGeneration
          && workspace.dateTimeFormat !== settings.general.dateTimeFormat) {
          workspace.setDateTimeFormat(settings.general.dateTimeFormat)
        }
        if (workspace.workbenchToolOrderGeneration === toolOrderGeneration) {
          workspace.setWorkbenchToolOrder(settings.navigation.workbenchToolOrder)
        }
        if (workspace.layoutPersistenceGeneration === layoutPersistenceGeneration) {
          workspace.setRestoreWorkspaceLayouts(
            settings.general.restoreWorkspaceLayouts,
            workspace.layouts === restoredLayouts,
          )
        }
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
  }, [session])
  return session
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

// Chrome surfaces share one observation and timer for each client/scenario.
// Slow requests cannot overlap, and a stopped subscription cannot publish late data.
function countPoller(load: () => Promise<number>, interval: number) {
  let snapshot: ShellCountResult = { count: 0, error: null }
  const listeners = new Set<() => void>()
  let timer: ReturnType<typeof setInterval> | undefined
  let generation = 0
  let pending = false
  const tick = async () => {
    if (pending) return
    pending = true
    const current = generation
    try {
      const count = await load()
      if (current === generation) snapshot = { count, error: null }
    } catch (error) {
      if (current === generation) snapshot = { ...snapshot, error }
    } finally {
      if (current === generation) {
        pending = false
        listeners.forEach(listener => listener())
      }
    }
  }
  return {
    getSnapshot: () => snapshot,
    subscribe: (listener: () => void) => {
      listeners.add(listener)
      if (listeners.size === 1) {
        void tick()
        timer = setInterval(() => void tick(), interval)
      }
      return () => {
        listeners.delete(listener)
        if (!listeners.size) {
          clearInterval(timer)
          generation += 1
          pending = false
          snapshot = { count: 0, error: null }
        }
      }
    },
  }
}

const countPollers = new WeakMap<ReturnType<typeof getClient>, Map<string, ReturnType<typeof countPoller>>>()
function useSharedCount(kind: 'approvals' | 'notifications'): ShellCountResult {
  const scenario = useSessionStore(s => s.activeScenario)
  const client = getClient()
  const poller = useMemo(() => {
    let cache = countPollers.get(client)
    if (!cache) { cache = new Map(); countPollers.set(client, cache) }
    const key = JSON.stringify([kind, scenario])
    let current = cache.get(key)
    if (!current) {
      current = kind === 'approvals'
        ? countPoller(async () => (await client.approvals.list({ status: 'pending' })).length, APPROVALS_POLL_MS)
        : countPoller(async () => (await client.activity.listNotifications()).filter(n => !n.read).length, 60_000)
      cache.set(key, current)
    }
    return current
  }, [client, kind, scenario])
  return useSyncExternalStore(poller.subscribe, poller.getSnapshot)
}

export function usePendingApprovalsCount(): ShellCountResult {
  return useSharedCount('approvals')
}

// ── Operation records (operation center + status bar + topbar spinner) ───────

const OPERATIONS_ACTIVE_POLL_MS = 3_000
const OPERATIONS_IDLE_POLL_MS = 30_000
const LIVE_OPERATION_STATES = new Set([
  'draft',
  'proposed',
  'preparing',
  'prepared',
  'awaiting_approval',
  'approved',
  'queued',
  'running',
  'cancelling',
  'paused',
  'interrupted',
  'validating',
])

export function useOperationsPolling(): void {
  const activeScenario = useSessionStore((s) => s.activeScenario)

  useEffect(() => {
    let cancelled = false
    let pending = false
    let wakeRequested = false
    let timer: number | undefined
    let live = hasLiveOperation(useSessionStore.getState().operations)

    const schedule = (delay: number) => {
      if (cancelled) return
      if (timer !== undefined) window.clearTimeout(timer)
      timer = window.setTimeout(() => {
        timer = undefined
        void tick()
      }, delay)
    }

    const tick = async () => {
      if (cancelled) return
      if (pending) {
        wakeRequested = true
        return
      }
      pending = true
      wakeRequested = false
      try {
        const records = await getClient().operations.list()
        if (!cancelled) {
          live = hasLiveOperation(records)
          useSessionStore.getState().setOperations(records)
          useSessionStore.getState().setOperationsError(null)
        }
      } catch {
        // Honest failure: keep the last known operations and record that the
        // projection is unavailable, so consumers never read a failed poll as
        // "no operations".
        if (!cancelled) useSessionStore.getState().setOperationsError('Operations could not be loaded.')
      } finally {
        pending = false
        if (!cancelled) {
          const mutationInFlight = useSessionStore.getState().operationsMutationCount > 0
          const delay = wakeRequested
            ? 0
            : mutationInFlight || live
              ? OPERATIONS_ACTIVE_POLL_MS
              : OPERATIONS_IDLE_POLL_MS
          wakeRequested = false
          schedule(delay)
        }
      }
    }

    const unsubscribe = useSessionStore.subscribe((state, previous) => {
      if (
        state.operationsRefreshGeneration === previous.operationsRefreshGeneration &&
        state.operationsMutationCount === previous.operationsMutationCount
      ) return
      wakeRequested = true
      if (!pending) schedule(0)
    })

    void tick()
    return () => {
      cancelled = true
      unsubscribe()
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [activeScenario])
}

/** True when any operation is in a live (non-terminal) state. */
export function hasLiveOperation(records: { state?: string }[]): boolean {
  return records.some((r) => LIVE_OPERATION_STATES.has(r.state ?? ''))
}

// ── Unread notifications dot ─────────────────────────────────────────────────

export function useUnreadNotificationsCount(): ShellCountResult {
  return useSharedCount('notifications')
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
