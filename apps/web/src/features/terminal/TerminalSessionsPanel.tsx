/**
 * TerminalSessionsPanel — the terminal tool's workbench nav panel: permitted
 * targets and live sessions. Rows show StatusDot + name (double-click renames
 * inline) + close-with-end; "new session" exists only when a target permits.
 */
import { Plus, SquareTerminal, Unplug, X } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'

import type { TerminalTarget } from '@/client'
import { getClient } from '@/client'
import { StatusDotFrom } from '@/components'
import type { WorkbenchSlotProps } from '@/shell/workbench/WorkbenchSlots'
import { cn } from '@/lib/utils'
import { terminalStatePresentation } from '@/semantic'
import { useWorkspaceStore } from '@/state/workspace'

import type { TerminalTab } from './terminalManager'
import { closeTab, createSessionTab, markActiveSession, renameTab, useTerminalManager } from './terminalManager'
import { disposeRuntime } from './sessionRuntime'

const EMPTY_TABS: readonly TerminalTab[] = []

export function TerminalSessionsPanel({ instanceId }: WorkbenchSlotProps) {
  const tabs = useTerminalManager((s) => s.tabs[instanceId]) ?? EMPTY_TABS
  const activeSessionId = useWorkspaceStore((s) => s.activeTerminalSession[instanceId] ?? null)
  const setActiveTerminalSession = useWorkspaceStore((s) => s.setActiveTerminalSession)
  const [targets, setTargets] = useState<TerminalTarget[]>([])
  const [targetNaming, setTargetNaming] = useState(false)

  useEffect(() => {
    let cancelled = false
    void Promise.all([getClient().terminal.listTargets(instanceId), getClient().globalSettings.get()])
      .then(([targetList, gs]) => {
        if (cancelled) return
        setTargets(targetList)
        setTargetNaming(gs.terminal.sessionNaming === 'target_based')
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [instanceId])

  const newSessionFor = useCallback(
    async (target: TerminalTarget) => {
      const tab = await createSessionTab(instanceId, target, targetNaming ? target.label : undefined)
      setActiveTerminalSession(instanceId, tab.sessionId)
      markActiveSession(instanceId, tab.sessionId)
    },
    [instanceId, targetNaming, setActiveTerminalSession],
  )

  const availableTargets = targets.filter((t) => t.available)
  const unavailableTargets = targets.filter((t) => !t.available)

  return (
    <div className="flex flex-col gap-0.5 p-2" data-testid="terminal-sessions-panel">
      <div className="flex items-center justify-between px-1 py-1">
        <span className="text-xs font-medium text-foreground-tertiary">Sessions</span>
        {availableTargets.length > 0 ? (
          <button
            type="button"
            aria-label="New terminal session"
            title="New session · Ctrl+Shift+`"
            onClick={() => void newSessionFor(availableTargets[0]!)}
            className="inline-flex min-h-6 min-w-6 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            data-testid="terminal-panel-new"
          >
            <Plus className="size-3.5" aria-hidden="true" />
          </button>
        ) : null}
      </div>

      {tabs.length === 0 ? (
        <p className="px-1 py-1 text-xs text-foreground-tertiary">No sessions — connect from the tool or a target below.</p>
      ) : (
        <ul className="flex flex-col gap-0.5">
          {tabs.map((tab) => (
            <PanelSessionRow
              key={tab.key}
              tab={tab}
              active={tab.sessionId === activeSessionId}
              onSelect={() => {
                setActiveTerminalSession(instanceId, tab.sessionId)
                markActiveSession(instanceId, tab.sessionId)
              }}
              onClose={() => {
                void closeTab(tab.key)
                disposeRuntime(tab.key)
              }}
            />
          ))}
        </ul>
      )}

      <div className="mt-2 px-1 py-1 text-xs font-medium text-foreground-tertiary">Targets</div>
      {targets.length === 0 ? (
        <p className="px-1 py-1 text-xs text-foreground-tertiary">No permitted terminal target.</p>
      ) : (
        <ul className="flex flex-col gap-0.5">
          {availableTargets.map((target) => (
            <li key={target.id}>
              <button
                type="button"
                onClick={() => void newSessionFor(target)}
                className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm text-foreground transition-colors duration-instant hover:bg-hover"
                title={`New session on ${target.label}`}
              >
                <SquareTerminal className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
                <span className="min-w-0 flex-1 truncate">{target.label}</span>
                <span className="text-xs text-foreground-tertiary">{target.kind === 'ssh' ? 'SSH' : 'Local'}</span>
              </button>
            </li>
          ))}
          {unavailableTargets.map((target) => (
            <li
              key={target.id}
              className="flex items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-foreground-tertiary"
              title={target.unavailableReason ?? 'Unavailable'}
            >
              <Unplug className="size-3.5 shrink-0 text-status-attention" aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate">{target.label}</span>
              <span className="text-xs">Unavailable</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function PanelSessionRow({
  tab,
  active,
  onSelect,
  onClose,
}: {
  tab: TerminalTab
  active: boolean
  onSelect: () => void
  onClose: () => void
}) {
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState(tab.name)
  const presentation = terminalStatePresentation(tab.state)

  return (
    <li
      className={cn(
        'group flex items-center gap-2 rounded-sm px-2 py-1.5 text-sm',
        active ? 'bg-active text-foreground' : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
      )}
    >
      <StatusDotFrom presentation={presentation} showLabel={false} />
      {editing ? (
        <input
          ref={(el) => {
            if (el && document.activeElement !== el) el.focus()
          }}
          value={value}
          aria-label={`Rename ${tab.name}`}
          onChange={(e) => setValue(e.target.value)}
          onBlur={() => {
            setEditing(false)
            if (value.trim()) void renameTab(tab.key, value)
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              setEditing(false)
              if (value.trim()) void renameTab(tab.key, value)
            } else if (e.key === 'Escape') {
              setEditing(false)
              setValue(tab.name)
            }
          }}
          className="h-5 min-w-0 flex-1 rounded-sm border border-input bg-surface px-1 text-xs outline-none focus-visible:border-accent"
        />
      ) : (
        <button
          type="button"
          onClick={onSelect}
          onDoubleClick={() => {
            setValue(tab.name)
            setEditing(true)
          }}
          title="Double-click to rename"
          className="min-w-0 flex-1 truncate text-left"
        >
          {tab.name}
        </button>
      )}
      <button
        type="button"
        aria-label={`Close session ${tab.name}`}
        onClick={onClose}
        className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-tertiary opacity-0 transition-opacity duration-instant group-hover:opacity-100 hover:bg-hover hover:text-foreground focus-visible:opacity-100"
      >
        <X className="size-3" aria-hidden="true" />
      </button>
    </li>
  )
}
