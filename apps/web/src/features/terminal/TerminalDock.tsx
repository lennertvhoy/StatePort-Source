/**
 * TerminalDock — the terminal in the workbench's collapsible bottom panel:
 * the SAME session/runtime as the tool (attaching here suspends the tool's
 * rendering and vice versa), with a compact header and an expand-to-tool
 * link. When the terminal tool itself is on the canvas, the dock shows a
 * compact session list instead of a second rendering of the same xterm.
 */
import { ChevronDown, CircleOff, Maximize2, Plug, Plus, RotateCcw, SquareTerminal, X } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import type { TerminalSettings, TerminalTarget } from '@/client'
import { getClient } from '@/client'
import { Spinner, StatusDotFrom } from '@/components'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import type { WorkbenchSlotProps } from '@/shell/workbench/WorkbenchSlots'
import { cn } from '@/lib/utils'
import { terminalStatePresentation } from '@/semantic'
import { useWorkspaceStore } from '@/state/workspace'

import { TerminalView } from './TerminalView'
import type { TerminalThemePreference } from './terminalTheme'
import type { TerminalTab } from './terminalManager'
import {
  cancelConnect,
  connectTab,
  createSessionTab,
  endTab,
  markActiveSession,
  useTerminalManager,
} from './terminalManager'
import { moveRuntime } from './sessionRuntime'

const EMPTY_TABS: readonly TerminalTab[] = []

export function TerminalDock({ instanceId, tool }: WorkbenchSlotProps) {
  const navigate = useNavigate()
  const tabs = useTerminalManager((s) => s.tabs[instanceId]) ?? EMPTY_TABS
  const activeSessionId = useWorkspaceStore((s) => s.activeTerminalSession[instanceId] ?? null)
  const setActiveTerminalSession = useWorkspaceStore((s) => s.setActiveTerminalSession)
  const activeTab = tabs.find((t) => t.sessionId === activeSessionId) ?? tabs[0] ?? null

  const [settings, setSettings] = useState<TerminalSettings | null>(null)
  const [themePref, setThemePref] = useState<TerminalThemePreference>('match_interface')
  const [targets, setTargets] = useState<TerminalTarget[]>([])
  const [findOpen, setFindOpen] = useState(false)

  useEffect(() => {
    let cancelled = false
    void Promise.all([getClient().globalSettings.get(), getClient().terminal.listTargets(instanceId)])
      .then(([gs, targetList]) => {
        if (cancelled) return
        setSettings(gs.terminal)
        setThemePref(gs.appearance.terminalTheme)
        setTargets(targetList)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [instanceId])

  const openTool = useCallback(() => void navigate(`/app/${instanceId}/workbench/terminal`), [navigate, instanceId])

  const connect = useCallback(
    async (tab: TerminalTab) => {
      const newKey = await connectTab(tab.key, (oldKey, nextKey, nextSessionId) =>
        moveRuntime(oldKey, nextKey, nextSessionId),
      )
      if (newKey && newKey !== tab.key) {
        const replaced = tabs.find((t) => t.key === newKey)
        if (replaced) {
          setActiveTerminalSession(instanceId, replaced.sessionId)
          markActiveSession(instanceId, replaced.sessionId)
        }
      }
    },
    [tabs, instanceId, setActiveTerminalSession],
  )

  const newSession = useCallback(async () => {
    const target = targets.find((t) => t.available)
    if (!target) return
    const tab = await createSessionTab(instanceId, target)
    setActiveTerminalSession(instanceId, tab.sessionId)
    markActiveSession(instanceId, tab.sessionId)
  }, [targets, instanceId, setActiveTerminalSession])

  // The terminal tool owns the canvas — the dock never mirrors the same xterm.
  if (tool === 'terminal') {
    return (
      <div className="flex h-full flex-col gap-0.5 overflow-y-auto p-2" data-testid="terminal-dock-sessions">
        <div className="px-1 py-0.5 text-xs text-foreground-tertiary">Terminal is open in the canvas.</div>
        {tabs.map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => {
              setActiveTerminalSession(instanceId, tab.sessionId)
              markActiveSession(instanceId, tab.sessionId)
            }}
            className={cn(
              'flex items-center gap-2 rounded-sm px-2 py-1 text-left text-sm',
              tab.sessionId === activeTab?.sessionId
                ? 'bg-active text-foreground'
                : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
            )}
          >
            <StatusDotFrom presentation={terminalStatePresentation(tab.state)} showLabel={false} />
            <span className="min-w-0 flex-1 truncate">{tab.name}</span>
            <span className="text-xs text-foreground-tertiary">{terminalStatePresentation(tab.state).label}</span>
          </button>
        ))}
      </div>
    )
  }

  const presentation = activeTab ? terminalStatePresentation(activeTab.state) : null

  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="terminal-dock">
      {/* compact header */}
      <div className="flex h-7 shrink-0 items-center gap-2 border-b border-border bg-surface px-2">
        <SquareTerminal className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
        {tabs.length > 1 ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                aria-label="Switch terminal session"
                className="flex min-h-6 items-center gap-1 rounded-sm px-1 text-xs font-medium text-foreground hover:bg-hover"
                data-testid="terminal-dock-selector"
              >
                <span className="max-w-32 truncate">{activeTab?.name}</span>
                <ChevronDown className="size-3" aria-hidden="true" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="bg-surface">
              {tabs.map((tab) => (
                <DropdownMenuItem
                  key={tab.key}
                  onSelect={() => {
                    setActiveTerminalSession(instanceId, tab.sessionId)
                    markActiveSession(instanceId, tab.sessionId)
                  }}
                >
                  <StatusDotFrom presentation={terminalStatePresentation(tab.state)} showLabel={false} />
                  <span className="min-w-0 flex-1 truncate">{tab.name}</span>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <span className="max-w-40 truncate text-xs font-medium text-foreground">{activeTab?.name ?? 'Terminal'}</span>
        )}
        {presentation && activeTab ? (
          <span
            className={cn(
              'flex items-center gap-1 text-xs',
              presentation.state === 'danger' && 'text-status-danger',
              presentation.state === 'success' && 'text-status-success',
              presentation.state === 'waiting' && 'text-status-waiting',
              presentation.state === 'neutral' && 'text-foreground-secondary',
            )}
          >
            <presentation.icon className={cn('size-3', presentation.spin && 'animate-spin')} aria-hidden="true" />
            {activeTab.lost && activeTab.state === 'ended' ? 'Session ended' : presentation.label}
          </span>
        ) : null}
        <div className="flex-1" />
        {activeTab ? <DockPrimaryAction tab={activeTab} onConnect={() => void connect(activeTab)} onEnd={() => void endTab(activeTab.key)} onCancel={() => cancelConnect(activeTab.key)} /> : null}
        {targets.some((t) => t.available) ? (
          <button
            type="button"
            aria-label="New terminal session"
            title="New session"
            onClick={() => void newSession()}
            className="inline-flex min-h-6 min-w-6 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            data-testid="terminal-dock-new"
          >
            <Plus className="size-3.5" aria-hidden="true" />
          </button>
        ) : null}
        <button
          type="button"
          aria-label="Open in Terminal tool"
          title="Open in Terminal tool"
          onClick={openTool}
          className="inline-flex min-h-6 min-w-6 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          data-testid="terminal-dock-expand"
        >
          <Maximize2 className="size-3.5" aria-hidden="true" />
        </button>
      </div>

      {/* body */}
      {!activeTab ? (
        <div className="flex flex-1 items-center justify-center gap-2 px-3 text-sm text-foreground-secondary" data-testid="terminal-dock-empty">
          <span>No terminal sessions.</span>
          {targets.some((t) => t.available) ? (
            <Button size="sm" variant="outline" onClick={() => void newSession()}>
              <Plus aria-hidden="true" />
              New session
            </Button>
          ) : null}
        </div>
      ) : activeTab.state === 'connected' || activeTab.state === 'reconnecting' ? (
        settings ? (
          <TerminalView
            tab={activeTab}
            instanceId={instanceId}
            targetKind={targets.find((t) => t.id === activeTab.targetId)?.kind ?? 'local_pty'}
            settings={settings}
            themePref={themePref}
            findOpen={findOpen}
            onFindOpenChange={setFindOpen}
            compact
          />
        ) : (
          <div className="flex flex-1 items-center justify-center gap-2 text-sm text-foreground-secondary">
            <Spinner className="size-4" />
            Loading terminal…
          </div>
        )
      ) : (
        <div className="flex flex-1 items-center justify-center gap-2 px-3 text-center text-sm text-foreground-secondary" data-testid="terminal-dock-state">
          {activeTab.state === 'idle' ? (
            <>
              <span>Ready to connect.</span>
              <Button size="sm" onClick={() => void connect(activeTab)} data-testid="terminal-dock-connect">
                <Plug aria-hidden="true" />
                Connect
              </Button>
            </>
          ) : activeTab.state === 'connecting' ? (
            <>
              <Spinner className="size-4" />
              <span>Connecting…</span>
            </>
          ) : activeTab.state === 'failed' ? (
            <>
              <span className="text-status-danger">Connection failed.</span>
              <Button size="sm" onClick={() => void connect(activeTab)} data-testid="terminal-dock-retry">
                <RotateCcw aria-hidden="true" />
                Retry
              </Button>
            </>
          ) : (
            <>
              <CircleOff className="size-4 text-foreground-tertiary" aria-hidden="true" />
              <span>{activeTab.lost ? 'Session ended — refresh does not reconnect.' : 'Session ended.'}</span>
              <Button size="sm" onClick={() => void connect(activeTab)} data-testid="terminal-dock-reconnect">
                <Plug aria-hidden="true" />
                Connect
              </Button>
            </>
          )}
        </div>
      )}
    </div>
  )
}

function DockPrimaryAction({
  tab,
  onConnect,
  onEnd,
  onCancel,
}: {
  tab: TerminalTab
  onConnect: () => void
  onEnd: () => void
  onCancel: () => void
}) {
  switch (tab.state) {
    case 'idle':
    case 'failed':
    case 'ended':
      return (
        <button
          type="button"
          onClick={onConnect}
          aria-label={tab.state === 'failed' ? 'Retry connection' : 'Connect terminal'}
          className="inline-flex min-h-6 min-w-6 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <Plug className="size-3.5" aria-hidden="true" />
        </button>
      )
    case 'connecting':
      return (
        <button
          type="button"
          onClick={onCancel}
          aria-label="Cancel connecting"
          className="inline-flex min-h-6 min-w-6 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <X className="size-3.5" aria-hidden="true" />
        </button>
      )
    default:
      return (
        <button
          type="button"
          onClick={onEnd}
          aria-label="End terminal session"
          className="inline-flex min-h-6 min-w-6 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <CircleOff className="size-3.5" aria-hidden="true" />
        </button>
      )
  }
}
