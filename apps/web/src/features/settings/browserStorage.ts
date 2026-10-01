/**
 * StatePort browser-storage boundary.
 *
 * Web Storage is presentation state, never authority. Values are treated as
 * untrusted on read by their owning stores, and no credential/session token is
 * intentionally stored here. The deletion path is prefix-scoped so it covers
 * both today's registry and future StatePort keys without touching unrelated
 * applications sharing the origin.
 */

export const STATEPORT_BROWSER_STORAGE_PREFIX = 'stateport.'

export type BrowserStorageArea = 'local' | 'session'

export interface BrowserStorageCategory {
  area: BrowserStorageArea
  key: string
  contents: string
}

/**
 * Audited inventory of every browser key currently written by the frontend.
 * Unknown future `stateport.*` keys are still discovered and cleared.
 */
export const STATEPORT_BROWSER_STORAGE_CATEGORIES: readonly BrowserStorageCategory[] = [
  {
    area: 'local',
    key: 'stateport.workspace.v1',
    contents:
      'Appearance, workspace continuity/layouts, open-file paths and cursors, conversation drafts, receipt filters, and search history.',
  },
  {
    area: 'local',
    key: 'stateport.applications.v1',
    contents:
      'Application-list presentation preferences and explicitly local StudyState/ChecklistState drafts.',
  },
  {
    area: 'local',
    key: 'stateport.conversation.v1',
    contents: 'Conversation pins, details-panel state, and last-seen message markers.',
  },
  {
    area: 'local',
    key: 'stateport.receipts-ui.v1',
    contents: 'Named receipt-filter presentation presets.',
  },
  {
    area: 'local',
    key: 'stateport.commands.v1',
    contents: 'Recent command-palette command identifiers.',
  },
  {
    area: 'local',
    key: 'stateport.shortcuts.v1',
    contents: 'Keyboard shortcut overrides.',
  },
  {
    area: 'local',
    key: 'stateport.http.ui-overlay.v1',
    contents: 'HTTP-mode pin, last-opened, and notification-snooze presentation overlays.',
  },
  {
    area: 'local',
    key: 'stateport.http.global-ui-settings.v1',
    contents: 'Frontend-only global presentation preferences.',
  },
  {
    area: 'local',
    key: 'stateport.http.app-ui-settings.v1',
    contents: 'Frontend-only per-application presentation preferences.',
  },
  {
    area: 'local',
    key: 'stateport.orchestration.how-it-works.dismissed',
    contents: 'Dismissal of the orchestration explainer.',
  },
  {
    area: 'local',
    key: 'stateport.mock.v1',
    contents:
      'Development-only Scenario Lab dataset, including mock applications and mock operational history.',
  },
  {
    area: 'session',
    key: 'stateport.terminal.tabs.v1',
    contents:
      'Per-tab terminal tab names, target identifiers, and ended-session continuity markers. Terminal output is never stored.',
  },
] as const

export interface BrowserStorageAreaSnapshot {
  available: boolean
  keys: string[]
}

export interface StatePortBrowserStorageSnapshot {
  local: BrowserStorageAreaSnapshot
  session: BrowserStorageAreaSnapshot
  totalKeys: number
}

export interface BrowserStorageSources {
  local?: Storage | null
  session?: Storage | null
}

export interface ClearStatePortBrowserStorageResult {
  removedLocalKeys: string[]
  removedSessionKeys: string[]
  remaining: StatePortBrowserStorageSnapshot
}

function browserSources(): BrowserStorageSources {
  if (typeof window === 'undefined') return { local: null, session: null }
  let local: Storage | null = null
  let session: Storage | null = null
  try {
    local = window.localStorage
  } catch {
    // Storage can be blocked by browser policy; report it as unavailable.
  }
  try {
    session = window.sessionStorage
  } catch {
    // Storage can be blocked by browser policy; report it as unavailable.
  }
  return { local, session }
}

function inspectArea(storage: Storage | null | undefined): BrowserStorageAreaSnapshot {
  if (!storage) return { available: false, keys: [] }
  try {
    const keys: string[] = []
    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index)
      if (key?.startsWith(STATEPORT_BROWSER_STORAGE_PREFIX)) keys.push(key)
    }
    return { available: true, keys: keys.sort() }
  } catch {
    return { available: false, keys: [] }
  }
}

export function inspectStatePortBrowserStorage(
  sources: BrowserStorageSources = browserSources(),
): StatePortBrowserStorageSnapshot {
  const local = inspectArea(sources.local)
  const session = inspectArea(sources.session)
  return {
    local,
    session,
    totalKeys: local.keys.length + session.keys.length,
  }
}

function clearArea(
  storage: Storage | null | undefined,
  snapshot: BrowserStorageAreaSnapshot,
): string[] {
  if (!storage || !snapshot.available) return []
  const removed: string[] = []
  for (const key of snapshot.keys) {
    try {
      storage.removeItem(key)
      if (storage.getItem(key) === null) removed.push(key)
    } catch {
      // Continue with the remaining keys; the post-clear inventory is truth.
    }
  }
  return removed
}

export function clearStatePortBrowserStorage(
  sources: BrowserStorageSources = browserSources(),
): ClearStatePortBrowserStorageResult {
  const before = inspectStatePortBrowserStorage(sources)
  const removedLocalKeys = clearArea(sources.local, before.local)
  const removedSessionKeys = clearArea(sources.session, before.session)
  return {
    removedLocalKeys,
    removedSessionKeys,
    remaining: inspectStatePortBrowserStorage(sources),
  }
}
