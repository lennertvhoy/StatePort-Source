/**
 * TerminalTool — the daily-driver terminal workbench tool (terminal.md).
 *
 * Layout: 36 px tool header (session name/target/state/Connect/End/overflow),
 * a 28 px session tab strip when more than one session exists, then the
 * terminal fills the remaining workbench space (fit on resize/panel changes).
 * No explanatory paragraphs above the terminal.
 *
 * State contract (exactly per design):
 * - ready: neutral "Ready to connect" + explicit Connect — never danger-red,
 *   and opening the tool NEVER auto-connects;
 * - connecting (Cancel), connected (prompt loop), reconnecting (input queued),
 * - failed: danger + Retry + diagnostics (buffer preserved when one exists);
 * - ended: neutral, buffer scrollable/copyable + Reconnect/Export;
 * - refresh: "Session ended — refresh does not reconnect" + explicit Connect;
 * - target-unavailable: blocked pane + explanation, session controls hidden.
 */
import {
  Check,
  ChevronDown,
  CircleOff,
  Copy,
  Download,
  Eraser,
  Maximize2,
  MessageSquare,
  Minimize2,
  MoreHorizontal,
  Plug,
  Plus,
  RotateCcw,
  Search,
  Settings,
  SquareTerminal,
  Unplug,
  X,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'

import type { GlobalSettings, TerminalSettings, TerminalTarget } from '@/client'
import { getClient } from '@/client'
import { EmptyState, ErrorState, InlineNotice, Spinner, StatusDotFrom, Tooltip } from '@/components'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useBridgeStore } from '@/features/bridge/bridgeStore'
import { cn } from '@/lib/utils'
import { terminalStatePresentation } from '@/semantic'
import { useRegisterCommands, type ShellCommand } from '@/shell/commands'
import { useEscapeLayer } from '@/shell/escape'
import { useShortcutAction, useShortcutScope } from '@/shell/shortcutRegistry'
import { useIsMobile } from '@/shell/platform'
import { useWorkspaceStore } from '@/state/workspace'

import {
  cancelConnect,
  closeTab,
  connectTab,
  createSessionTab,
  endTab,
  getTab,
  markActiveSession,
  reconnectLiveTab,
  reconcileInstance,
  renameTab,
  restoreInstanceTabs,
  tabsFor,
  useTerminalManager,
  type TerminalTab,
} from './terminalManager'
import { disposeRuntime, getRuntime, moveRuntime } from './sessionRuntime'
import { TerminalView } from './TerminalView'
import { downloadTextFile, exportFilenameFor } from './terminalExport'
import type { TerminalThemePreference } from './terminalTheme'

const EMPTY_TABS: readonly TerminalTab[] = []

export default function TerminalTool() {
  const { instanceId = '' } = useParams<{ instanceId: string }>()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const isMobile = useIsMobile()

  // ── data ─────────────────────────────────────────────────────────────────
  const [phase, setPhase] = useState<'loading' | 'error' | 'ready'>('loading')
  const [loadError, setLoadError] = useState<unknown>(null)
  const [targets, setTargets] = useState<TerminalTarget[]>([])
  const [settings, setSettings] = useState<TerminalSettings | null>(null)
  const [themePref, setThemePref] = useState<TerminalThemePreference>('match_interface')
  const [a11yScreenReader, setA11yScreenReader] = useState(false)

  const tabs = useTerminalManager((s) => s.tabs[instanceId]) ?? EMPTY_TABS
  const activeSessionId = useWorkspaceStore((s) => s.activeTerminalSession[instanceId] ?? null)
  const setActiveTerminalSession = useWorkspaceStore((s) => s.setActiveTerminalSession)
  const activeTab = tabs.find((t) => t.sessionId === activeSessionId) ?? tabs[0] ?? null
  const activeTarget = activeTab ? targets.find((t) => t.id === activeTab.targetId) : undefined
  const targetIssue = activeTab ? !activeTarget || !activeTarget.available : false

  const applyGlobalSettings = useCallback((gs: GlobalSettings) => {
    setSettings(gs.terminal)
    setThemePref(gs.appearance.terminalTheme)
    setA11yScreenReader(gs.accessibility.terminalScreenReaderMode)
  }, [])

  // Async load — every setState happens after an await, never synchronously
  // inside the mount effect. The retry handler resets `phase` in its event.
  const loadInitial = useCallback(async () => {
    try {
      const [targetList, gs] = await Promise.all([
        getClient().terminal.listTargets(instanceId),
        getClient().globalSettings.get(),
      ])
      setTargets(targetList)
      applyGlobalSettings(gs)
      // Refresh honesty: restore tabs as ended (never reconnect), then drop
      // tabs whose mock session vanished (mock reset) to the same state.
      restoreInstanceTabs(instanceId, { restoreTabs: gs.terminal.restoreSessionTabs })
      await reconcileInstance(instanceId)
      setPhase('ready')
    } catch (err) {
      setLoadError(err)
      setPhase('error')
    }
  }, [instanceId, applyGlobalSettings])

  useEffect(() => {
    // Deferred so the async load (and its setStates) never runs synchronously
    // inside the effect body.
    const timer = window.setTimeout(() => void loadInitial(), 0)
    return () => window.clearTimeout(timer)
  }, [loadInitial])

  const retryLoad = useCallback(() => {
    setPhase('loading')
    setLoadError(null)
    void loadInitial()
  }, [loadInitial])

  // Settings apply "live": re-read when the window regains focus (settings
  // page is another route in the same SPA; there is no settings event bus).
  useEffect(() => {
    const onFocus = () => {
      void getClient()
        .globalSettings.get()
        .then(applyGlobalSettings)
        .catch(() => undefined)
    }
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [applyGlobalSettings])

  const refreshTargets = useCallback(async () => {
    try {
      setTargets(await getClient().terminal.listTargets(instanceId))
    } catch {
      /* quiet refresh — explicit Reload shows errors via panes */
    }
  }, [instanceId])

  // ── active-tab sync with the workspace store ─────────────────────────────
  useEffect(() => {
    if (phase !== 'ready') return
    if (tabs.length === 0) return
    const valid = activeSessionId && tabs.some((t) => t.sessionId === activeSessionId)
    if (!valid) {
      const last = tabs[tabs.length - 1]!
      setActiveTerminalSession(instanceId, last.sessionId)
      markActiveSession(instanceId, last.sessionId)
    }
  }, [phase, tabs, activeSessionId, instanceId, setActiveTerminalSession])

  const selectTab = useCallback(
    (tab: TerminalTab) => {
      setActiveTerminalSession(instanceId, tab.sessionId)
      markActiveSession(instanceId, tab.sessionId)
    },
    [instanceId, setActiveTerminalSession],
  )

  // ── actions ──────────────────────────────────────────────────────────────
  const availableTargets = useMemo(() => targets.filter((t) => t.available), [targets])

  const preferredTarget = useCallback((): TerminalTarget | undefined => {
    if (settings?.defaultTargetId) {
      const preferred = availableTargets.find((t) => t.id === settings.defaultTargetId)
      if (preferred) return preferred
    }
    if (activeTab) {
      const current = availableTargets.find((t) => t.id === activeTab.targetId)
      if (current) return current
    }
    return availableTargets[0]
  }, [settings, availableTargets, activeTab])

  const sessionNameFor = useCallback(
    (target: TerminalTarget): string | undefined =>
      settings?.sessionNaming === 'target_based' ? target.label : undefined,
    [settings],
  )

  const handleConnect = useCallback(
    async (tab: TerminalTab) => {
      const newKey = await connectTab(tab.key, (oldKey, nextKey, nextSessionId) =>
        moveRuntime(oldKey, nextKey, nextSessionId),
      )
      if (newKey && newKey !== tab.key) {
        const replaced = getTab(newKey)
        if (replaced) {
          setActiveTerminalSession(instanceId, replaced.sessionId)
          markActiveSession(instanceId, replaced.sessionId)
        }
      }
      if (!isMobile) getRuntime(newKey ?? tab.key)?.focus()
    },
    [instanceId, isMobile, setActiveTerminalSession],
  )

  /** Start pane: one explicit click creates the session AND connects. */
  const handleStartConnect = useCallback(
    async (target: TerminalTarget) => {
      const tab = await createSessionTab(instanceId, target, sessionNameFor(target))
      setActiveTerminalSession(instanceId, tab.sessionId)
      markActiveSession(instanceId, tab.sessionId)
      await handleConnect(tab)
    },
    [instanceId, sessionNameFor, setActiveTerminalSession, handleConnect],
  )

  /** New session (Ctrl+Shift+` / +): creates an idle tab — Connect stays explicit. */
  const handleNewSession = useCallback(async () => {
    const target = preferredTarget()
    if (!target) return
    const tab = await createSessionTab(instanceId, target, sessionNameFor(target))
    setActiveTerminalSession(instanceId, tab.sessionId)
    markActiveSession(instanceId, tab.sessionId)
  }, [instanceId, preferredTarget, sessionNameFor, setActiveTerminalSession])

  const handleCloseTab = useCallback(
    async (tab: TerminalTab) => {
      await closeTab(tab.key)
      disposeRuntime(tab.key)
    },
    [],
  )

  const handleEnd = useCallback(async (tab: TerminalTab) => {
    await endTab(tab.key)
  }, [])

  const handleLiveReconnect = useCallback(async (tab: TerminalTab) => {
    await reconnectLiveTab(tab.key, (oldKey, nextKey, nextSessionId) =>
      moveRuntime(oldKey, nextKey, nextSessionId),
    )
  }, [])

  const exportTab = useCallback((tab: TerminalTab) => {
    const text = getRuntime(tab.key)?.exportText() ?? ''
    if (text) downloadTextFile(exportFilenameFor(tab.name), text)
  }, [])

  // ── find bar + rename editor ─────────────────────────────────────────────
  const [findOpen, setFindOpen] = useState(false)
  const [renaming, setRenaming] = useState(false)
  // Close find bar + rename editor when the active session changes
  // (adjust-during-render).
  const [previousTabKey, setPreviousTabKey] = useState(activeTab?.key)
  if (activeTab?.key !== previousTabKey) {
    setPreviousTabKey(activeTab?.key)
    if (findOpen) setFindOpen(false)
    if (renaming) setRenaming(false)
  }
  const openFind = useCallback(() => {
    if (activeTab && getRuntime(activeTab.key)) setFindOpen(true)
  }, [activeTab])
  useEscapeLayer(findOpen, () => setFindOpen(false), { id: 'terminal-find', priority: 10 })

  // ── bridge command drafts: inserted at the prompt, NEVER executed ────────
  // Pending drafts live in a ref (state mirrors them for the notice); all
  // inserts/clears happen inside external-store subscription callbacks.
  const [drafts, setDrafts] = useState<string[]>([])
  const draftsRef = useRef<string[]>([])
  useEffect(() => {
    const activeConnectedRuntime = () => {
      const tabs = tabsFor(instanceId)
      const activeId = useWorkspaceStore.getState().activeTerminalSession[instanceId]
      const active = tabs.find((t) => t.sessionId === activeId) ?? tabs[0]
      if (!active || active.state !== 'connected') return undefined
      return getRuntime(active.key)
    }
    const insertPending = (): boolean => {
      const pending = draftsRef.current
      if (pending.length === 0) return true
      const runtime = activeConnectedRuntime()
      if (!runtime) return false
      for (const draft of pending) runtime.insertAtPrompt(draft)
      draftsRef.current = []
      setDrafts([])
      return true
    }
    const consumeBridge = () => {
      const payloads = useBridgeStore.getState().consume(instanceId, ['command-draft'])
      const commands = payloads
        .map((p) => (typeof (p as { command?: unknown }).command === 'string' ? (p as { command: string }).command : null))
        .filter((c): c is string => c !== null)
      if (commands.length > 0) {
        draftsRef.current = [...draftsRef.current, ...commands]
        setDrafts(draftsRef.current)
      }
      insertPending()
    }
    const onTransition = () => {
      insertPending()
    }
    const initial = window.setTimeout(consumeBridge, 0)
    const unBridge = useBridgeStore.subscribe(consumeBridge)
    const unManager = useTerminalManager.subscribe(onTransition)
    const unWorkspace = useWorkspaceStore.subscribe(onTransition)
    window.addEventListener('focus', consumeBridge)
    return () => {
      window.clearTimeout(initial)
      unBridge()
      unManager()
      unWorkspace()
      window.removeEventListener('focus', consumeBridge)
    }
  }, [instanceId])

  // ── announcements (state changes → polite live region; adjust-during-render) ──
  const [announcement, setAnnouncement] = useState('')
  const [announcedState, setAnnouncedState] = useState<string | undefined>(undefined)
  if (activeTab?.state && activeTab.state !== announcedState) {
    setAnnouncedState(activeTab.state)
    const messages: Record<string, string> = {
      idle: 'Terminal ready to connect',
      connecting: 'Connecting to the terminal',
      connected: 'Terminal connected',
      reconnecting: 'Reconnecting the terminal — input is queued',
      failed: 'Terminal connection failed',
      ended: activeTab.lost ? 'Session ended — refresh does not reconnect' : 'Terminal session ended',
    }
    const message = messages[activeTab.state]
    if (message) setAnnouncement(`${activeTab.name}: ${message}`)
  }

  // ── shortcuts + palette commands ─────────────────────────────────────────
  useShortcutScope('terminal')
  useShortcutAction('terminal.new_session', () => void handleNewSession())
  useShortcutAction('terminal.search', openFind)

  const commands = useMemo<ShellCommand[]>(() => {
    const activeRuntime = activeTab ? getRuntime(activeTab.key) : undefined
    const reconnectable =
      Boolean(activeTab) &&
      (activeTab!.state === 'failed' || activeTab!.state === 'ended' || activeTab!.lost || activeTab!.state === 'connected')
    return [
      {
        id: 'terminal.new_session',
        title: 'New terminal session',
        group: 'Actions',
        icon: Plus,
        shortcut: 'ctrl+shift+`',
        keywords: ['terminal', 'session', 'shell', 'new'],
        when: () => availableTargets.length > 0,
        run: () => void handleNewSession(),
      },
      {
        id: 'terminal.search',
        title: 'Search terminal output',
        group: 'Actions',
        icon: Search,
        shortcut: 'mod+f',
        keywords: ['find', 'search', 'output'],
        when: () => Boolean(activeTab && getRuntime(activeTab.key)),
        run: openFind,
      },
      {
        id: 'terminal.copy_output',
        title: 'Copy terminal output',
        group: 'Actions',
        icon: Copy,
        keywords: ['copy', 'output', 'scrollback'],
        when: () => Boolean(activeRuntime),
        run: () => activeRuntime?.copyAll(),
      },
      {
        id: 'terminal.export',
        title: 'Export terminal session',
        group: 'Actions',
        icon: Download,
        keywords: ['export', 'transcript', 'download'],
        when: () => Boolean(activeTab && getRuntime(activeTab.key)),
        run: () => activeTab && exportTab(activeTab),
      },
      {
        id: 'terminal.clear',
        title: 'Clear terminal',
        group: 'Actions',
        icon: Eraser,
        keywords: ['clear', 'screen'],
        when: () => Boolean(activeRuntime),
        run: () => activeRuntime?.clear(),
      },
      {
        id: 'terminal.reconnect',
        title: 'Reconnect terminal',
        group: 'Actions',
        icon: RotateCcw,
        keywords: ['reconnect', 'retry', 'connect'],
        when: () => reconnectable && !targetIssue,
        run: () => {
          if (!activeTab) return
          if (activeTab.state === 'connected') void handleLiveReconnect(activeTab)
          else void handleConnect(activeTab)
        },
      },
    ]
  }, [activeTab, availableTargets.length, handleNewSession, openFind, exportTab, handleConnect, handleLiveReconnect, targetIssue])
  useRegisterCommands(commands)

  // ── presentation helpers ─────────────────────────────────────────────────
  const focused = searchParams.get('focus') === '1'
  const toggleFocus = useCallback(() => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        if (next.get('focus') === '1') next.delete('focus')
        else next.set('focus', '1')
        return next
      },
      { replace: true },
    )
  }, [setSearchParams])

  const effectiveSettings = useMemo<TerminalSettings | null>(() => {
    if (!settings) return null
    return {
      ...settings,
      fontSize: isMobile ? Math.max(12, settings.fontSize) : settings.fontSize,
      screenReaderMode: settings.screenReaderMode || a11yScreenReader,
    }
  }, [settings, isMobile, a11yScreenReader])

  const statePresentation = activeTab
    ? targetIssue
      ? { icon: Unplug, label: 'Target unavailable', state: 'attention' as const }
      : terminalStatePresentation(activeTab.state)
    : { icon: CircleOff, label: 'Ready to connect', state: 'neutral' as const }

  const STATE_TEXT_CLASS: Record<string, string> = {
    danger: 'text-status-danger',
    attention: 'text-status-attention',
    success: 'text-status-success',
    waiting: 'text-status-waiting',
    neutral: 'text-foreground-secondary',
  }

  // ── body ─────────────────────────────────────────────────────────────────
  let body: React.ReactNode = null
  if (phase === 'loading') {
    body = (
      <div className="flex h-full items-center justify-center gap-2 text-sm text-foreground-secondary" data-testid="terminal-loading">
        <Spinner className="size-4" />
        Loading terminal…
      </div>
    )
  } else if (phase === 'error') {
    body = (
      <ErrorState
        title="Couldn't load the terminal"
        error={loadError}
        preservedNote="No session was started."
        onRetry={retryLoad}
      />
    )
  } else if (targets.length === 0) {
    body = (
      <EmptyState
        icon={SquareTerminal}
        title="No terminal target available"
        description="This application doesn't have a permitted terminal target in the current environment."
        action={{ label: 'Review capabilities', onClick: () => void navigate(`/app/${instanceId}`) }}
      />
    )
  } else if (tabs.length === 0) {
    body = (
      <NoTabsStart
        targets={targets}
        onConnect={(target) => void handleStartConnect(target)}
      />
    )
  } else if (activeTab && targetIssue) {
    body = (
      <TargetUnavailablePane
        target={activeTarget}
        onRefresh={() => void refreshTargets()}
        onReviewConfiguration={() => void navigate(`/app/${instanceId}/workbench/deployments`)}
      />
    )
  } else if (activeTab && effectiveSettings) {
    const runtime = getRuntime(activeTab.key)
    switch (activeTab.state) {
      case 'idle':
        body = <StartPane targetLabel={activeTarget?.label ?? 'Terminal target'} onConnect={() => void handleConnect(activeTab)} />
        break
      case 'connecting':
        body = <ConnectingPane onCancel={() => cancelConnect(activeTab.key)} />
        break
      case 'connected':
      case 'reconnecting':
        body = (
          <TerminalView
            tab={activeTab}
            instanceId={instanceId}
            targetKind={activeTarget?.kind ?? 'local_pty'}
            settings={effectiveSettings}
            themePref={themePref}
            findOpen={findOpen}
            onFindOpenChange={setFindOpen}
          />
        )
        break
      case 'failed':
        body = runtime ? (
          <div className="flex min-h-0 flex-1 flex-col">
            <FailedStrip tab={activeTab} onRetry={() => void handleConnect(activeTab)} />
            <TerminalView
              tab={activeTab}
              instanceId={instanceId}
              targetKind={activeTarget?.kind ?? 'local_pty'}
              settings={effectiveSettings}
              themePref={themePref}
              findOpen={findOpen}
              onFindOpenChange={setFindOpen}
            />
          </div>
        ) : (
          <ErrorState
            title="Connection failed"
            error={activeTab.lastError ?? 'The connection could not be established.'}
            preservedNote="Nothing ran — the session was never connected."
            onRetry={() => void handleConnect(activeTab)}
          />
        )
        break
      case 'ended':
        if (activeTab.lost && !runtime) {
          body = <LostPane tab={activeTab} targetLabel={activeTarget?.label} onConnect={() => void handleConnect(activeTab)} />
        } else {
          body = (
            <div className="flex min-h-0 flex-1 flex-col">
              {runtime ? (
                <TerminalView
                  tab={activeTab}
                  instanceId={instanceId}
                  targetKind={activeTarget?.kind ?? 'local_pty'}
                  settings={effectiveSettings}
                  themePref={themePref}
                  findOpen={findOpen}
                  onFindOpenChange={setFindOpen}
                />
              ) : null}
              <EndedBar tab={activeTab} lost={activeTab.lost} onReconnect={() => void handleConnect(activeTab)} onExport={() => exportTab(activeTab)} />
            </div>
          )
        }
        break
    }
  }

  const primaryAction = renderPrimaryAction({
    tabs,
    activeTab,
    targetIssue,
    availableTargets,
    onStartConnect: (target) => void handleStartConnect(target),
    onConnect: () => activeTab && void handleConnect(activeTab),
    onCancel: () => activeTab && cancelConnect(activeTab.key),
    onEnd: () => activeTab && void handleEnd(activeTab),
  })

  return (
    // The `terminal-stub` hook is the shell's route-smoke contract
    // (src/shell/__tests__/routes.test.tsx) — kept as a layout-transparent
    // wrapper now that the real tool replaced the stub. `terminal-tool` is
    // the tool's own surface hook.
    <div className="contents" data-testid="terminal-stub">
    <div className="flex h-full min-h-0 flex-col bg-app" data-testid="terminal-tool">
      {/* ── 36 px tool header ── */}
      <header className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-surface px-3">
        <SquareTerminal className="size-4 shrink-0 text-foreground-tertiary" aria-hidden="true" />
        {activeTab ? (
          <SessionName
            name={activeTab.name}
            editing={renaming}
            onStartEdit={() => setRenaming(true)}
            onRename={(name) => {
              setRenaming(false)
              void renameTab(activeTab.key, name)
            }}
            onCancel={() => setRenaming(false)}
          />
        ) : (
          <span className="truncate text-sm font-medium text-foreground">Terminal</span>
        )}
        {activeTab && activeTarget ? (
          <span className="hidden truncate text-xs text-foreground-secondary lg:inline" title={activeTarget.label}>
            {activeTarget.label}
          </span>
        ) : null}
        {activeTab ? (
          <span
            className={cn(
              'hidden shrink-0 items-center gap-1 text-xs sm:inline-flex',
              STATE_TEXT_CLASS[statePresentation.state] ?? 'text-foreground-secondary',
            )}
            data-testid="terminal-state-label"
          >
            <statePresentation.icon
              className={cn('size-3.5', 'spin' in statePresentation && statePresentation.spin && 'animate-spin')}
              aria-hidden="true"
            />
            {activeTab.lost && activeTab.state === 'ended' ? 'Session ended' : statePresentation.label}
          </span>
        ) : null}
        <div className="flex-1" />
        {primaryAction}
        {tabs.length > 1 ? (
          <SessionSelector tabs={tabs} activeTab={activeTab} onSelect={selectTab} />
        ) : null}
        {!isMobile ? (
          <Tooltip content={focused ? 'Exit focus mode' : 'Maximize terminal'}>
            <button
              type="button"
              aria-label={focused ? 'Exit focus mode' : 'Maximize terminal'}
              aria-pressed={focused}
              onClick={toggleFocus}
              className="inline-flex min-h-7 min-w-7 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            >
              {focused ? <Minimize2 className="size-4" aria-hidden="true" /> : <Maximize2 className="size-4" aria-hidden="true" />}
            </button>
          </Tooltip>
        ) : null}
        <TerminalOverflowMenu
          activeTab={activeTab}
          onRename={() => setRenaming(true)}
          onDuplicate={() => void handleNewSession()}
          onExport={() => activeTab && exportTab(activeTab)}
          onCopyOutput={() => activeTab && getRuntime(activeTab.key)?.copyAll()}
          onSendSelection={() => {
            if (!activeTab) return
            const selection = getRuntime(activeTab.key)?.getSelection() ?? ''
            if (!selection) return
            useBridgeStore.getState().send({ kind: 'terminal-selection', instanceId, sessionId: activeTab.sessionId, text: selection })
            void navigate(`/app/${instanceId}/conversation`)
          }}
          onReconnectLive={() => activeTab && void handleLiveReconnect(activeTab)}
          onPreferences={() => void navigate('/settings/terminal')}
          hasRuntime={Boolean(activeTab && getRuntime(activeTab.key))}
          canDuplicate={availableTargets.length > 0}
          isConnected={activeTab?.state === 'connected'}
        />
      </header>

      {/* ── 28 px session tab strip (only with > 1 session) ── */}
      {tabs.length > 1 ? (
        <SessionTabsStrip
          tabs={tabs}
          activeTab={activeTab}
          onSelect={selectTab}
          onClose={(tab) => void handleCloseTab(tab)}
          onNew={availableTargets.length > 0 ? () => void handleNewSession() : undefined}
        />
      ) : null}

      {/* ── command-draft notice (inserted for review only, never run) ── */}
      {drafts.length > 0 && activeTab?.state !== 'connected' ? (
        <InlineNotice
          tone="informational"
          title="The assistant proposed a command"
          action={
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                draftsRef.current = []
                setDrafts([])
              }}
            >
              Dismiss
            </Button>
          }
          className="rounded-none border-x-0 border-t-0"
        >
          <span className="tnum block truncate font-mono text-xs">{drafts[0]}</span>
          Connect to review it at the prompt — it is inserted for review only, never run automatically.
        </InlineNotice>
      ) : null}

      {/* ── body ── */}
      <div className="flex min-h-0 flex-1 flex-col" data-testid="terminal-body">
        {body}
      </div>

      {/* ── mobile accessory keys ── */}
      {isMobile && activeTab?.state === 'connected' ? <AccessoryRow tabKey={activeTab.key} /> : null}

      {/* ── polite announcements for state changes ── */}
      <div aria-live="polite" className="sr-only" data-testid="terminal-announce">
        {announcement}
      </div>
    </div>
    </div>
  )
}

// ── internal presentation components ─────────────────────────────────────────

interface PrimaryActionProps {
  tabs: readonly TerminalTab[]
  activeTab: TerminalTab | null
  targetIssue: boolean
  availableTargets: TerminalTarget[]
  onStartConnect: (target: TerminalTarget) => void
  onConnect: () => void
  onCancel: () => void
  onEnd: () => void
}

/** Header primary action — the explicit Connect/End contract. Hidden when ambiguous. */
function renderPrimaryAction(props: PrimaryActionProps): React.ReactNode {
  const { tabs, activeTab, targetIssue, availableTargets } = props
  if (tabs.length === 0) {
    // With no sessions the header Connect only exists when the target is unambiguous.
    if (availableTargets.length !== 1) return null
    return (
      <Button size="sm" onClick={() => props.onStartConnect(availableTargets[0]!)} data-testid="terminal-connect">
        <Plug aria-hidden="true" />
        Connect
      </Button>
    )
  }
  if (!activeTab || targetIssue) return null // controls hidden while blocked
  switch (activeTab.state) {
    case 'idle':
      return (
        <Button size="sm" onClick={props.onConnect} data-testid="terminal-connect">
          <Plug aria-hidden="true" />
          Connect
        </Button>
      )
    case 'connecting':
      return (
        <Button size="sm" variant="outline" onClick={props.onCancel} data-testid="terminal-cancel-connect">
          <X aria-hidden="true" />
          Cancel
        </Button>
      )
    case 'connected':
      return (
        <Button size="sm" variant="secondary" onClick={props.onEnd} data-testid="terminal-end">
          <CircleOff aria-hidden="true" />
          End
        </Button>
      )
    case 'reconnecting':
      return (
        <Button size="sm" variant="secondary" onClick={props.onEnd} data-testid="terminal-end">
          <CircleOff aria-hidden="true" />
          End
        </Button>
      )
    case 'failed':
      return (
        <Button size="sm" onClick={props.onConnect} data-testid="terminal-retry">
          <RotateCcw aria-hidden="true" />
          Retry
        </Button>
      )
    case 'ended':
      return (
        <Button size="sm" onClick={props.onConnect} data-testid="terminal-reconnect">
          <Plug aria-hidden="true" />
          {activeTab.lost ? 'Connect' : 'Reconnect'}
        </Button>
      )
  }
  return null
}

/** Centered neutral start pane — explicitly NOT danger-colored. */
function StartPane({ targetLabel, onConnect }: { targetLabel: string; onConnect: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 py-10 text-center" data-testid="terminal-start">
      <SquareTerminal className="size-5 text-foreground-tertiary" aria-hidden="true" />
      <h2 className="text-lg text-foreground">Ready to connect</h2>
      <p className="text-sm text-foreground-secondary">{targetLabel}</p>
      <Button size="sm" className="mt-2" onClick={onConnect} data-testid="terminal-connect">
        <Plug aria-hidden="true" />
        Connect
      </Button>
    </div>
  )
}

function NoTabsStart({
  targets,
  onConnect,
}: {
  targets: TerminalTarget[]
  onConnect: (target: TerminalTarget) => void
}) {
  const available = targets.filter((t) => t.available)
  const unavailable = targets.filter((t) => !t.available)
  if (available.length === 1 && unavailable.length === 0) {
    return <StartPane targetLabel={available[0]!.label} onConnect={() => onConnect(available[0]!)} />
  }
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 px-6 py-10" data-testid="terminal-start">
      <SquareTerminal className="size-5 text-foreground-tertiary" aria-hidden="true" />
      <h2 className="text-lg text-foreground">Ready to connect</h2>
      <p className="text-sm text-foreground-secondary">Choose a target to start a session.</p>
      <ul className="flex w-full max-w-sm flex-col gap-1">
        {available.map((target) => (
          <li key={target.id}>
            <button
              type="button"
              onClick={() => onConnect(target)}
              className="flex w-full items-center gap-2 rounded-md border border-border bg-surface px-3 py-2 text-left text-sm text-foreground transition-colors duration-instant hover:border-accent hover:bg-hover"
            >
              <SquareTerminal className="size-4 shrink-0 text-foreground-tertiary" aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate">{target.label}</span>
              <span className="text-xs text-foreground-tertiary">{target.kind === 'ssh' ? 'SSH' : 'Local PTY'}</span>
              <Plug className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
            </button>
          </li>
        ))}
        {unavailable.map((target) => (
          <li
            key={target.id}
            className="flex items-center gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 text-sm text-foreground-tertiary"
          >
            <Unplug className="size-4 shrink-0 text-status-attention" aria-hidden="true" />
            <span className="min-w-0 flex-1 truncate">{target.label}</span>
            <span className="text-xs">{target.unavailableReason ?? 'Unavailable'}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function ConnectingPane({ onCancel }: { onCancel: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 py-10 text-center" data-testid="terminal-connecting">
      <Spinner className="size-5" />
      <h2 className="text-lg text-foreground">Connecting…</h2>
      <p className="text-sm text-foreground-secondary">Establishing the session — nothing is running yet.</p>
      <Button size="sm" variant="outline" className="mt-2" onClick={onCancel}>
        <X aria-hidden="true" />
        Cancel
      </Button>
    </div>
  )
}

function TargetUnavailablePane({
  target,
  onRefresh,
  onReviewConfiguration,
}: {
  target: TerminalTarget | undefined
  onRefresh: () => void
  onReviewConfiguration: () => void
}) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 py-10 text-center" data-testid="terminal-target-unavailable">
      <Unplug className="size-5 text-status-attention" aria-hidden="true" />
      <h2 className="text-lg text-foreground">Target unavailable</h2>
      <p className="max-w-md text-sm text-foreground-secondary">
        {target?.unavailableReason ??
          'The terminal target cannot be verified in the current environment. Terminal access is blocked until the target is reachable.'}
      </p>
      <div className="mt-2 flex items-center gap-2">
        <Button size="sm" variant="outline" onClick={onRefresh}>
          <RotateCcw aria-hidden="true" />
          Refresh
        </Button>
        <Button size="sm" variant="ghost" onClick={onReviewConfiguration}>
          Review configuration
        </Button>
      </div>
    </div>
  )
}

/** Honest post-refresh pane: neutral, explicit Connect, no silent reconnect. */
function LostPane({ tab, targetLabel, onConnect }: { tab: TerminalTab; targetLabel?: string; onConnect: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 py-10 text-center" data-testid="terminal-lost">
      <CircleOff className="size-5 text-foreground-tertiary" aria-hidden="true" />
      <h2 className="text-lg text-foreground">Session ended</h2>
      <p className="max-w-md text-sm text-foreground-secondary">Session ended — refresh does not reconnect.</p>
      <p className="max-w-md text-xs text-foreground-tertiary">
        The page reloaded, so “{tab.name}” and its output are gone. Connect to start a new session
        {targetLabel ? ` on ${targetLabel}` : ''}.
      </p>
      <Button size="sm" className="mt-2" onClick={onConnect} data-testid="terminal-connect">
        <Plug aria-hidden="true" />
        Connect
      </Button>
    </div>
  )
}

/** Ended strip below a preserved buffer — neutral, buffer stays scrollable. */
function EndedBar({
  lost,
  onReconnect,
  onExport,
}: {
  tab: TerminalTab
  lost: boolean
  onReconnect: () => void
  onExport: () => void
}) {
  return (
    <div
      className="flex h-9 shrink-0 items-center gap-2 border-t border-border bg-surface px-3"
      data-testid="terminal-ended-bar"
    >
      <CircleOff className="size-4 shrink-0 text-foreground-tertiary" aria-hidden="true" />
      <span className="truncate text-sm text-foreground-secondary">
        {lost ? 'Session ended — reconnect starts a new session.' : 'Session ended — output stays scrollable.'}
      </span>
      <div className="flex-1" />
      <Button size="sm" variant="ghost" onClick={onExport} data-testid="terminal-export-ended">
        <Download aria-hidden="true" />
        Export
      </Button>
      <Button size="sm" onClick={onReconnect} data-testid="terminal-reconnect">
        <RotateCcw aria-hidden="true" />
        Reconnect
      </Button>
    </div>
  )
}

/** Failure strip over a preserved buffer (danger, with diagnostics). */
function FailedStrip({ tab, onRetry }: { tab: TerminalTab; onRetry: () => void }) {
  const [showDiagnostics, setShowDiagnostics] = useState(false)
  return (
    <div className="shrink-0 border-b border-border" data-testid="terminal-failed-strip">
      <InlineNotice
        tone="danger"
        title="Connection failed"
        action={
          <>
            <Button size="sm" variant="ghost" onClick={() => setShowDiagnostics((v) => !v)}>
              {showDiagnostics ? 'Hide diagnostics' : 'Open diagnostics'}
            </Button>
            <Button size="sm" onClick={onRetry} data-testid="terminal-retry">
              <RotateCcw aria-hidden="true" />
              Retry
            </Button>
          </>
        }
        className="rounded-none border-x-0 border-t-0"
      >
        {tab.lastError ?? 'The connection could not be established.'}
      </InlineNotice>
      {showDiagnostics ? (
        <pre className="max-h-32 overflow-auto border-t border-border bg-surface px-3 py-2 font-mono text-xs whitespace-pre-wrap text-foreground-secondary">
          {`session: ${tab.sessionId}\ntarget: ${tab.targetId}\nstate: ${tab.state}\nerror: ${tab.lastError ?? '—'}`}
        </pre>
      ) : null}
    </div>
  )
}

/** Inline-editable session name (double-click or overflow → rename). */
function SessionName({
  name,
  editing,
  onStartEdit,
  onRename,
  onCancel,
}: {
  name: string
  editing: boolean
  onStartEdit: () => void
  onRename: (name: string) => void
  onCancel: () => void
}) {
  const [value, setValue] = useState(name)
  // Sync the draft when editing (re)opens — adjust-during-render.
  const [wasEditing, setWasEditing] = useState(false)
  if (editing !== wasEditing) {
    setWasEditing(editing)
    if (editing) setValue(name)
  }
  if (!editing) {
    return (
      <button
        type="button"
        onDoubleClick={onStartEdit}
        title="Double-click to rename"
        className="max-w-40 truncate rounded-sm text-sm font-medium text-foreground hover:bg-hover"
        data-testid="terminal-session-name"
      >
        {name}
      </button>
    )
  }
  return (
    <input
      ref={(el) => {
        if (el && document.activeElement !== el) el.focus()
      }}
      value={value}
      aria-label="Session name"
      onChange={(e) => setValue(e.target.value)}
      onBlur={() => (value.trim() ? onRename(value) : onCancel())}
      onKeyDown={(e) => {
        if (e.key === 'Enter') onRename(value)
        else if (e.key === 'Escape') onCancel()
      }}
      className="h-6 w-40 rounded-sm border border-input bg-surface px-1 text-sm text-foreground outline-none focus-visible:border-accent"
      data-testid="terminal-session-name-input"
    />
  )
}

function SessionSelector({
  tabs,
  activeTab,
  onSelect,
}: {
  tabs: readonly TerminalTab[]
  activeTab: TerminalTab | null
  onSelect: (tab: TerminalTab) => void
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label="Switch terminal session"
          className="hidden min-h-7 min-w-7 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground sm:inline-flex"
          data-testid="terminal-session-selector"
        >
          <ChevronDown className="size-4" aria-hidden="true" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="bg-surface">
        <DropdownMenuLabel>Sessions</DropdownMenuLabel>
        {tabs.map((tab) => (
          <DropdownMenuItem key={tab.key} onSelect={() => onSelect(tab)}>
            <StatusDotFrom presentation={terminalStatePresentation(tab.state)} showLabel={false} />
            <span className={cn('min-w-0 flex-1 truncate', tab.sessionId === activeTab?.sessionId && 'font-medium')}>
              {tab.name}
            </span>
            {tab.sessionId === activeTab?.sessionId ? <Check className="ml-auto size-3.5" aria-hidden="true" /> : null}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function SessionTabsStrip({
  tabs,
  activeTab,
  onSelect,
  onClose,
  onNew,
}: {
  tabs: readonly TerminalTab[]
  activeTab: TerminalTab | null
  onSelect: (tab: TerminalTab) => void
  onClose: (tab: TerminalTab) => void
  onNew?: () => void
}) {
  return (
    <div
      className="flex h-7 shrink-0 items-center gap-0.5 overflow-x-auto border-b border-border bg-surface px-1"
      role="tablist"
      aria-label="Terminal sessions"
      data-testid="terminal-tab-strip"
    >
      {tabs.map((tab) => {
        const active = tab.sessionId === activeTab?.sessionId
        return (
          <div
            key={tab.key}
            role="tab"
            aria-selected={active}
            tabIndex={0}
            onClick={() => onSelect(tab)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onSelect(tab)
              }
            }}
            className={cn(
              'group flex h-6 cursor-pointer items-center gap-1.5 rounded-sm px-2 text-xs',
              active ? 'bg-active text-foreground' : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
            )}
          >
            <StatusDotFrom presentation={terminalStatePresentation(tab.state)} showLabel={false} />
            <span className="max-w-32 truncate">{tab.name}</span>
            <button
              type="button"
              aria-label={`Close session ${tab.name}`}
              onClick={(e) => {
                e.stopPropagation()
                onClose(tab)
              }}
              className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-tertiary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            >
              <X className="size-3" aria-hidden="true" />
            </button>
          </div>
        )
      })}
      {onNew ? (
        <Tooltip content="New session · Ctrl+Shift+`">
          <button
            type="button"
            aria-label="New terminal session"
            onClick={onNew}
            className="inline-flex min-h-6 min-w-6 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            data-testid="terminal-new-session"
          >
            <Plus className="size-3.5" aria-hidden="true" />
          </button>
        </Tooltip>
      ) : null}
    </div>
  )
}

function TerminalOverflowMenu({
  activeTab,
  hasRuntime,
  canDuplicate,
  isConnected,
  onRename,
  onDuplicate,
  onExport,
  onCopyOutput,
  onSendSelection,
  onReconnectLive,
  onPreferences,
}: {
  activeTab: TerminalTab | null
  hasRuntime: boolean
  canDuplicate: boolean
  isConnected: boolean
  onRename: () => void
  onDuplicate: () => void
  onExport: () => void
  onCopyOutput: () => void
  onSendSelection: () => void
  onReconnectLive: () => void
  onPreferences: () => void
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label="Terminal options"
          className="inline-flex min-h-7 min-w-7 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          data-testid="terminal-overflow"
        >
          <MoreHorizontal className="size-4" aria-hidden="true" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="bg-surface">
        {activeTab ? (
          <>
            <DropdownMenuItem onSelect={onRename}>Rename session</DropdownMenuItem>
            {canDuplicate ? <DropdownMenuItem onSelect={onDuplicate}>Duplicate session</DropdownMenuItem> : null}
            {isConnected ? <DropdownMenuItem onSelect={onReconnectLive}>Reconnect</DropdownMenuItem> : null}
            <DropdownMenuSeparator />
          </>
        ) : null}
        {hasRuntime ? (
          <>
            <DropdownMenuItem onSelect={onCopyOutput}>
              <Copy className="size-4" aria-hidden="true" />
              Copy output
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={onExport}>
              <Download className="size-4" aria-hidden="true" />
              Export session
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={onSendSelection}>
              <MessageSquare className="size-4" aria-hidden="true" />
              Send selection to Conversation
            </DropdownMenuItem>
            <DropdownMenuSeparator />
          </>
        ) : null}
        <DropdownMenuItem onSelect={onPreferences}>
          <Settings className="size-4" aria-hidden="true" />
          Preferences
        </DropdownMenuItem>
        <DropdownMenuLabel className="max-w-56 text-xs font-normal whitespace-normal text-foreground-tertiary">
          Scrollback follows your settings — full transcripts are not kept; exports are explicit.
        </DropdownMenuLabel>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** Mobile accessory row: Esc Tab Ctrl arrows | ~ — soft-keyboard safe. */
function AccessoryRow({ tabKey }: { tabKey: string }) {
  const [ctrl, setCtrl] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const send = (data: string) => {
    const runtime = getRuntime(tabKey)
    runtime?.sendData(data)
    if (ctrl) {
      setCtrl(false)
      runtime?.setCtrlLatch(false)
    }
  }
  if (collapsed) {
    return (
      <button
        type="button"
        onClick={() => setCollapsed(false)}
        className="flex h-6 shrink-0 items-center justify-center border-t border-border bg-surface text-xs text-foreground-tertiary"
        aria-label="Show terminal accessory keys"
      >
        <ChevronDown className="size-3.5 rotate-180" aria-hidden="true" />
      </button>
    )
  }
  const chip = (label: string, data: string, ariaLabel: string) => (
    <button
      key={label}
      type="button"
      aria-label={ariaLabel}
      onClick={() => send(data)}
      className="inline-flex min-h-7 min-w-8 items-center justify-center rounded-sm border border-border bg-surface px-1.5 font-mono text-xs text-foreground-secondary transition-colors duration-instant hover:bg-hover"
    >
      {label}
    </button>
  )
  return (
    <div
      className="flex h-9 shrink-0 items-center gap-1 overflow-x-auto border-t border-border bg-surface px-2"
      data-testid="terminal-accessory-row"
    >
      {chip('Esc', '\x1b', 'Escape')}
      {chip('Tab', '\t', 'Tab')}
      <button
        type="button"
        aria-label="Ctrl modifier for next key"
        aria-pressed={ctrl}
        onClick={() => {
          const next = !ctrl
          setCtrl(next)
          getRuntime(tabKey)?.setCtrlLatch(next)
        }}
        className={cn(
          'inline-flex min-h-7 min-w-8 items-center justify-center rounded-sm border px-1.5 font-mono text-xs transition-colors duration-instant',
          ctrl ? 'border-accent bg-accent-soft text-accent' : 'border-border bg-surface text-foreground-secondary hover:bg-hover',
        )}
      >
        Ctrl
      </button>
      {chip('↑', '\x1b[A', 'Arrow up')}
      {chip('↓', '\x1b[B', 'Arrow down')}
      {chip('←', '\x1b[D', 'Arrow left')}
      {chip('→', '\x1b[C', 'Arrow right')}
      {chip('|', '|', 'Pipe')}
      {chip('~', '~', 'Tilde')}
      <div className="flex-1" />
      <button
        type="button"
        aria-label="Hide accessory keys"
        onClick={() => setCollapsed(true)}
        className="inline-flex min-h-7 min-w-7 items-center justify-center rounded-sm text-foreground-tertiary hover:bg-hover"
      >
        <ChevronDown className="size-3.5" aria-hidden="true" />
      </button>
    </div>
  )
}
