/**
 * Terminal session manager — module-level, survives route changes.
 *
 * Keeps the mock-PTY session state (and, via the output-sink seam, the live
 * xterm instances in `sessionRuntime.ts`) keyed by `instanceId:sessionId`, so
 * navigating away suspends rendering but retains the session, and coming back
 * re-attaches to the same live session.
 *
 * Honesty contract (terminal.md, brief §Terminal continuity):
 * - never connects on its own — every state change traces to an explicit
 *   user action (Connect / End / Retry / Reconnect / command `exit`);
 * - a full page refresh kills the module map AND the in-memory mock
 *   sessions, so restored tabs are marked `lost` and render the honest
 *   "Session ended — refresh does not reconnect" state with an explicit
 *   Connect (which transparently creates a replacement session);
 * - a sessionStorage marker (this tab-session only) is what lets us know a
 *   session existed before the refresh — it is never used to reconnect.
 *
 * This module is xterm-free and DOM-free (only sessionStorage), so it is
 * unit-testable in jsdom without mocking the renderer.
 */
import { create } from 'zustand'

import type { CommandResult, TerminalSession, TerminalSessionState, TerminalTarget } from '@/client'
import { ClientError, getClient } from '@/client'

// ── Types ────────────────────────────────────────────────────────────────────

export interface TerminalTab {
  /** `${instanceId}:${sessionId}` — changes when a lost/ended session is replaced. */
  key: string
  instanceId: string
  sessionId: string
  targetId: string
  name: string
  state: TerminalSessionState
  /**
   * True when the backing mock session is gone (page refresh, mock reset):
   * the honest "Session ended — refresh does not reconnect" variant.
   */
  lost: boolean
  lastError?: string
  cwd?: string
}

interface TerminalManagerState {
  /** instanceId → tabs in creation order. */
  tabs: Record<string, TerminalTab[]>
  /** instanceId → marker already restored this page load. */
  restored: Record<string, true>
}

interface MarkerEntry {
  active: string | null
  tabs: { sessionId: string; name: string; targetId: string }[]
}

const MARKER_KEY = 'stateport.terminal.tabs.v1'
const EMPTY_TABS: readonly TerminalTab[] = []
const MAX_BUFFERED_CHUNKS = 400

export const useTerminalManager = create<TerminalManagerState>()(() => ({ tabs: {}, restored: {} }))

// ── Module internals (not in the reactive store) ─────────────────────────────

const unsubscribers = new Map<string, () => void>()
/** Latest connect/reconnect operation id per key — stale resolves are ignored. */
const opTokens = new Map<string, number>()
/** Keys whose in-flight connect was cancelled by the user. */
const pendingCancels = new Set<string>()
/** Output captured before a runtime attaches (replayed on first start). */
const outputBuffers = new Map<string, string[]>()
/** Live runtime sinks — output flows straight to xterm once attached. */
const outputSinks = new Map<string, (text: string) => void>()
/** Live runtime state hooks — lets the renderer track liveness (exit/ended). */
const stateHooks = new Map<string, (state: TerminalSessionState, error?: string) => void>()

export function keyFor(instanceId: string, sessionId: string): string {
  return `${instanceId}:${sessionId}`
}

// ── Marker persistence (sessionStorage — deliberately per tab-session) ───────

function readMarkers(): Record<string, MarkerEntry> {
  try {
    const raw = window.sessionStorage.getItem(MARKER_KEY)
    if (!raw) return {}
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object') return {}
    return parsed as Record<string, MarkerEntry>
  } catch {
    return {}
  }
}

function writeMarkers(markers: Record<string, MarkerEntry>): void {
  try {
    window.sessionStorage.setItem(MARKER_KEY, JSON.stringify(markers))
  } catch {
    // Private mode / quota: continuity marker is best-effort, never fatal.
  }
}

function persistMarker(instanceId: string, activeSessionId?: string | null): void {
  const markers = readMarkers()
  const tabs = useTerminalManager.getState().tabs[instanceId] ?? []
  const previous = markers[instanceId]
  if (tabs.length === 0) {
    delete markers[instanceId]
  } else {
    markers[instanceId] = {
      active: activeSessionId !== undefined ? activeSessionId : (previous?.active ?? tabs[tabs.length - 1]?.sessionId ?? null),
      tabs: tabs.map((t) => ({ sessionId: t.sessionId, name: t.name, targetId: t.targetId })),
    }
  }
  writeMarkers(markers)
}

/** Record which tab is active so a refresh can restore it (as ended). */
export function markActiveSession(instanceId: string, sessionId: string | null): void {
  persistMarker(instanceId, sessionId)
}

// ── Tab helpers ──────────────────────────────────────────────────────────────

export function tabsFor(instanceId: string): readonly TerminalTab[] {
  return useTerminalManager.getState().tabs[instanceId] ?? EMPTY_TABS
}

export function getTab(key: string): TerminalTab | undefined {
  for (const tabs of Object.values(useTerminalManager.getState().tabs)) {
    const found = tabs.find((t) => t.key === key)
    if (found) return found
  }
  return undefined
}

function updateTab(key: string, patch: Partial<TerminalTab>): void {
  useTerminalManager.setState((s) => {
    const tabs: Record<string, TerminalTab[]> = {}
    let changed = false
    for (const [instanceId, list] of Object.entries(s.tabs)) {
      if (list.some((t) => t.key === key)) {
        tabs[instanceId] = list.map((t) => (t.key === key ? { ...t, ...patch } : t))
        changed = true
      } else {
        tabs[instanceId] = list
      }
    }
    return changed ? { tabs } : s
  })
}

function replaceTabKey(oldKey: string, next: TerminalTab): void {
  useTerminalManager.setState((s) => {
    const tabs: Record<string, TerminalTab[]> = {}
    for (const [instanceId, list] of Object.entries(s.tabs)) {
      tabs[instanceId] = list.some((t) => t.key === oldKey)
        ? list.map((t) => (t.key === oldKey ? next : t))
        : list
    }
    return { tabs }
  })
}

function nextToken(key: string): number {
  const token = (opTokens.get(key) ?? 0) + 1
  opTokens.set(key, token)
  return token
}

// ── Client event subscription (state + pre-runtime output relay) ─────────────

function ensureSubscribed(key: string, sessionId: string): void {
  if (unsubscribers.has(key)) return
  const unsub = getClient().terminal.subscribe(sessionId, (event) => {
    if (event.type === 'output') {
      const sink = outputSinks.get(key)
      if (sink) {
        sink(event.text)
      } else {
        const buffer = outputBuffers.get(key) ?? []
        buffer.push(event.text)
        if (buffer.length > MAX_BUFFERED_CHUNKS) buffer.splice(0, buffer.length - MAX_BUFFERED_CHUNKS)
        outputBuffers.set(key, buffer)
      }
      return
    }
    if (event.type === 'state') {
      // A cancelled connect must not flip the tab back to connected.
      if (event.state === 'connected' && pendingCancels.has(key)) return
      stateHooks.get(key)?.(event.state, event.error)
      updateTab(key, {
        state: event.state,
        lastError: event.state === 'connected' ? undefined : (event.error ?? undefined),
      })
      return
    }
    if (event.type === 'exit') {
      stateHooks.get(key)?.('ended')
    }
  })
  unsubscribers.set(key, unsub)
}

/** Attach the live xterm sink (runtime) — output stops being buffered. */
export function setOutputSink(key: string, sink: ((text: string) => void) | null): void {
  if (sink) outputSinks.set(key, sink)
  else outputSinks.delete(key)
}

/** Attach the runtime's state hook (liveness for the prompt loop). */
export function setStateHook(key: string, hook: ((state: TerminalSessionState, error?: string) => void) | null): void {
  if (hook) stateHooks.set(key, hook)
  else stateHooks.delete(key)
}

/** Output captured before the runtime existed; drained on first start. */
export function drainBufferedOutput(key: string): string[] {
  const buffered = outputBuffers.get(key) ?? []
  outputBuffers.delete(key)
  return buffered
}

/** The active adapter's terminal discipline. */
export function terminalInputMode(): 'line_commands' | 'raw_pty' {
  return getClient().terminal.inputMode
}

/** Send authenticated PTY input for the tab behind a runtime key. */
export function sendTerminalInput(key: string, data: string): void {
  const tab = getTab(key)
  if (!tab) throw new ClientError('http', 'Terminal session is gone', { status: 404 })
  getClient().terminal.sendInput(tab.sessionId, data)
}

/**
 * Forward a fitted xterm viewport to the governed PTY only while its exact
 * client-side session is connected. Fit events can also fire while a view is
 * attaching or detaching; those must never become pre-ready control frames.
 */
export function resizeTerminal(key: string, columns: number, rows: number): void {
  const tab = getTab(key)
  if (
    !tab ||
    tab.state !== 'connected' ||
    !Number.isInteger(columns) ||
    !Number.isInteger(rows) ||
    columns < 1 ||
    columns > 1000 ||
    rows < 1 ||
    rows > 1000
  ) {
    return
  }
  getClient().terminal.resize(tab.sessionId, columns, rows)
}

// ── Restore after refresh (honest "ended", never reconnect) ─────────────────

/**
 * Rebuild the tab strip from the per-tab-session marker after a full page
 * refresh. Restored tabs are `lost` — the mock sessions are gone, and the UI
 * says so. Runs at most once per instance per page load.
 */
export function restoreInstanceTabs(instanceId: string, options: { restoreTabs: boolean }): void {
  const { restored } = useTerminalManager.getState()
  if (restored[instanceId]) return
  useTerminalManager.setState((s) => ({ restored: { ...s.restored, [instanceId]: true } }))
  const marker = readMarkers()[instanceId]
  if (!marker || marker.tabs.length === 0) return
  const selected = options.restoreTabs
    ? marker.tabs
    : marker.tabs.filter((t) => t.sessionId === marker.active).slice(-1)
  const fallback = options.restoreTabs ? [] : marker.tabs.slice(-1)
  const toRestore = (selected.length > 0 ? selected : fallback).filter(
    (t) => t && typeof t.sessionId === 'string' && typeof t.targetId === 'string',
  )
  if (toRestore.length === 0) return
  const tabs: TerminalTab[] = toRestore.map((t) => ({
    key: keyFor(instanceId, t.sessionId),
    instanceId,
    sessionId: t.sessionId,
    targetId: t.targetId,
    name: typeof t.name === 'string' && t.name ? t.name : 'Terminal',
    state: 'ended',
    lost: true,
  }))
  useTerminalManager.setState((s) => ({ tabs: { ...s.tabs, [instanceId]: tabs } }))
  // The marker stays — it now describes these honestly-ended tabs.
}

/** Reconcile with the client: tabs whose session vanished (mock reset) become lost. */
export async function reconcileInstance(instanceId: string): Promise<void> {
  const tabs = tabsFor(instanceId)
  const live = tabs.filter((t) => !t.lost)
  if (live.length === 0) return
  try {
    const sessions = await getClient().terminal.listSessions(instanceId)
    const ids = new Set(sessions.map((s) => s.id))
    for (const tab of live) {
      if (!ids.has(tab.sessionId)) {
        updateTab(tab.key, { state: 'ended', lost: true })
      }
    }
  } catch {
    // Service trouble: leave tabs as they are — the next action reports honestly.
  }
}

// ── Session lifecycle (explicit user actions only) ───────────────────────────

export async function createSessionTab(
  instanceId: string,
  target: TerminalTarget,
  name?: string,
): Promise<TerminalTab> {
  const session = await getClient().terminal.createSession(instanceId, target.id, name)
  const tab: TerminalTab = {
    key: keyFor(instanceId, session.id),
    instanceId,
    sessionId: session.id,
    targetId: session.targetId,
    name: session.name,
    state: 'idle',
    lost: false,
    cwd: session.cwd,
  }
  useTerminalManager.setState((s) => ({
    tabs: { ...s.tabs, [instanceId]: [...(s.tabs[instanceId] ?? []), tab] },
  }))
  ensureSubscribed(tab.key, session.id)
  persistMarker(instanceId, session.id)
  return tab
}

/** Callback fired synchronously when a restart replaces the session (runtime rebind seam). */
export type SessionReplacedHandler = (oldKey: string, newKey: string, newSessionId: string) => void

/**
 * Explicit Connect / Retry. Never called on mount — only from user actions.
 * Returns the tab key (which CHANGES when a lost/ended session is replaced).
 */
export async function connectTab(key: string, onReplaced?: SessionReplacedHandler): Promise<string | null> {
  const tab = getTab(key)
  if (!tab) return null
  if (tab.lost || tab.state === 'ended') {
    return restartSession(key, onReplaced)
  }
  if (tab.state === 'connected' || tab.state === 'connecting' || tab.state === 'reconnecting') return key
  const token = nextToken(key)
  pendingCancels.delete(key)
  updateTab(key, { state: 'connecting', lastError: undefined })
  try {
    const session = await getClient().terminal.connect(tab.sessionId)
    if (pendingCancels.has(key) || opTokens.get(key) !== token) {
      // Cancelled while connecting: return the session to idle honestly.
      pendingCancels.delete(key)
      try {
        await getClient().terminal.disconnect(tab.sessionId)
      } catch {
        /* best effort */
      }
      if (opTokens.get(key) === token) updateTab(key, { state: 'idle' })
      return key
    }
    applySession(key, session)
  } catch (err) {
    if (opTokens.get(key) !== token || pendingCancels.has(key)) return key
    handleSessionError(key, err, 'failed')
  }
  return key
}

/** Cancel an in-flight connect (design: "Connecting… — Cancel available"). */
export function cancelConnect(key: string): void {
  const tab = getTab(key)
  if (!tab || tab.state !== 'connecting') return
  pendingCancels.add(key)
  updateTab(key, { state: 'idle' })
}

/** Explicit End — ends the mock session (buffer stays scrollable). */
export async function endTab(key: string): Promise<void> {
  const tab = getTab(key)
  if (!tab || tab.lost || tab.state === 'ended') return
  try {
    await getClient().terminal.endSession(tab.sessionId)
    updateTab(key, { state: 'ended' })
  } catch (err) {
    handleSessionError(key, err, 'ended')
  }
}

/** Explicit Reconnect of a live (connected/failed) session via the client. */
export async function reconnectLiveTab(key: string, onReplaced?: SessionReplacedHandler): Promise<void> {
  const tab = getTab(key)
  if (!tab || tab.lost || tab.state === 'ended') {
    await restartSession(key, onReplaced)
    return
  }
  const token = nextToken(key)
  updateTab(key, { state: 'reconnecting', lastError: undefined })
  try {
    const session = await getClient().terminal.reconnect(tab.sessionId)
    if (opTokens.get(key) !== token) return
    applySession(key, session)
  } catch (err) {
    if (opTokens.get(key) !== token) return
    handleSessionError(key, err, 'failed')
  }
}

/**
 * Reconnect from `ended`/`lost`: the mock cannot revive an ended session
 * (connect on `ended` throws 409), so an explicit Reconnect transparently
 * creates a replacement session on the same target with the same name and
 * connects it. The tab's rendered buffer (when one exists) is preserved by
 * the runtime across the rebind. Returns the new key (null on failure).
 */
export async function restartSession(key: string, onReplaced?: SessionReplacedHandler): Promise<string | null> {
  const tab = getTab(key)
  if (!tab) return null
  const token = nextToken(key)
  updateTab(key, { state: 'connecting', lastError: undefined })
  let session: TerminalSession
  try {
    session = await getClient().terminal.createSession(tab.instanceId, tab.targetId, tab.name)
  } catch (err) {
    if (opTokens.get(key) === token) handleSessionError(key, err, 'failed')
    return null
  }
  const newKey = keyFor(tab.instanceId, session.id)
  // Migrate per-tab bookkeeping to the new key.
  const sink = outputSinks.get(key)
  if (sink) {
    outputSinks.delete(key)
    outputSinks.set(newKey, sink)
  }
  const hook = stateHooks.get(key)
  if (hook) {
    stateHooks.delete(key)
    stateHooks.set(newKey, hook)
  }
  outputBuffers.delete(key)
  const oldUnsub = unsubscribers.get(key)
  oldUnsub?.()
  unsubscribers.delete(key)
  opTokens.delete(key)
  replaceTabKey(key, {
    ...tab,
    key: newKey,
    sessionId: session.id,
    state: 'idle',
    lost: false,
    lastError: undefined,
    cwd: session.cwd,
  })
  // Rebind the live runtime synchronously — before React can commit the new
  // key — so the view never creates a fresh (buffer-less) runtime by racing.
  onReplaced?.(key, newKey, session.id)
  ensureSubscribed(newKey, session.id)
  persistMarker(tab.instanceId, session.id)
  await connectTab(newKey)
  return newKey
}

/** Close a tab: ends the live session (close-with-end), then removes it. */
export async function closeTab(key: string): Promise<void> {
  const tab = getTab(key)
  if (!tab) return
  if (!tab.lost && tab.state !== 'ended') {
    try {
      await getClient().terminal.endSession(tab.sessionId)
    } catch {
      /* already gone — closing is still honest */
    }
  }
  unsubscribers.get(key)?.()
  unsubscribers.delete(key)
  outputSinks.delete(key)
  stateHooks.delete(key)
  outputBuffers.delete(key)
  opTokens.delete(key)
  pendingCancels.delete(key)
  useTerminalManager.setState((s) => ({
    tabs: {
      ...s.tabs,
      [tab.instanceId]: (s.tabs[tab.instanceId] ?? []).filter((t) => t.key !== key),
    },
  }))
  persistMarker(tab.instanceId)
}

export async function renameTab(key: string, name: string): Promise<void> {
  const tab = getTab(key)
  const trimmed = name.trim()
  if (!tab || !trimmed || tab.name === trimmed) return
  updateTab(key, { name: trimmed })
  persistMarker(tab.instanceId)
  if (tab.lost) return // replacement session takes the new name on reconnect
  try {
    await getClient().terminal.renameSession(tab.sessionId, trimmed)
  } catch {
    // Local name stands; the next reconcile marks the tab lost if it is gone.
  }
}

/** Run one command line (from the runtime's prompt loop). */
export async function submitCommand(key: string, line: string): Promise<CommandResult> {
  const tab = getTab(key)
  if (!tab) throw new ClientError('http', 'Terminal session is gone', { status: 404 })
  try {
    return await getClient().terminal.runCommand(tab.sessionId, line)
  } catch (err) {
    if (err instanceof ClientError && err.status === 404) {
      updateTab(key, { state: 'ended', lost: true })
    }
    throw err
  }
}

// ── internals ────────────────────────────────────────────────────────────────

function applySession(key: string, session: TerminalSession): void {
  updateTab(key, {
    name: session.name,
    state: session.state,
    cwd: session.cwd,
    lastError: session.lastError,
  })
}

function handleSessionError(key: string, err: unknown, fallbackState: TerminalSessionState): void {
  if (err instanceof ClientError && err.status === 404) {
    updateTab(key, { state: 'ended', lost: true })
    return
  }
  const message = err instanceof Error ? err.message : 'The operation failed.'
  updateTab(key, { state: fallbackState, lastError: message })
}

/** Test seam: drop all manager state (simulates a fresh page load). */
export function resetTerminalManagerForTests(): void {
  for (const unsub of unsubscribers.values()) unsub()
  unsubscribers.clear()
  outputSinks.clear()
  stateHooks.clear()
  outputBuffers.clear()
  opTokens.clear()
  pendingCancels.clear()
  useTerminalManager.setState({ tabs: {}, restored: {} })
}
