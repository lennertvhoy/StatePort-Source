/**
 * WorkbenchShell (design.md §10, workbench.md) — the panel-dock tool frame:
 * tool tabs (capability-filtered, deep-linkable), resizable nav / right-dock /
 * bottom regions around the routed tool canvas, 7 layout presets, focus /
 * maximize mode (`?focus=1` deep link), per-app persisted layout, and the
 * workbench status bar.
 *
 * Regions around the canvas are filled by feature agents through
 * WorkbenchSlots; until then they show honest placeholders.
 */
import {
  Check,
  ChevronDown,
  FolderTree,
  LayoutGrid,
  Maximize2,
  Minimize2,
  MoreHorizontal,
  Package,
  PanelBottomClose,
  PanelBottomOpen,
  PanelLeftClose,
  PanelLeftOpen,
  PanelRightClose,
  PanelRightOpen,
  PanelsTopLeft,
  Receipt,
  Server,
  SquareTerminal,
  Workflow,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { Panel, Separator } from 'react-resizable-panels'

import { PanelGroup } from '@/components/ui/resizable'

import type { CapabilityId, TerminalSessionState, WorkbenchToolId } from '@/client'
import { getClient } from '@/client'
import { CapabilityDot, Tooltip } from '@/components'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator as DropdownSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'
import type { LayoutPreset } from '@/state'
import { DEFAULT_LAYOUT, useWorkspaceStore } from '@/state'

import { useCurrentInstance } from './currentInstance'
import type { ShellCommand } from './commands'
import { useRegisterCommands } from './commands'
import { useEscapeLayer } from './escape'
import { useShortcutAction, useShortcutScope } from './shortcutRegistry'
import { useIsMobile, MOD_LABEL } from './platform'
import { StatusBar } from './StatusBar'
import { WorkbenchStatusContext } from './workbenchStatus'
import type { WorkbenchStatus } from './workbenchStatus'
import { useWorkbenchSlots } from './workbench/WorkbenchSlots'

// ── Tool registry ────────────────────────────────────────────────────────────

interface ToolDef {
  id: WorkbenchToolId
  label: string
  icon: LucideIcon
  route: string
  /** Tool is offered when ANY of these capabilities is usable. */
  capabilities?: CapabilityId[]
  shortcut?: string
}

const TOOLS: readonly ToolDef[] = [
  { id: 'overview', label: 'Overview', icon: PanelsTopLeft, route: '', shortcut: 'mod+1' },
  { id: 'files', label: 'Files', icon: FolderTree, route: 'files', capabilities: ['file_viewer', 'editor'], shortcut: 'mod+2' },
  { id: 'terminal', label: 'Terminal', icon: SquareTerminal, route: 'terminal', capabilities: ['terminal'], shortcut: 'mod+3' },
  { id: 'deployments', label: 'Deployments', icon: Server, route: 'deployments', capabilities: ['infrastructure'], shortcut: 'mod+4' },
  { id: 'orchestration', label: 'Orchestration', icon: Workflow, route: 'orchestration', capabilities: ['cto_orchestration'], shortcut: 'mod+5' },
  { id: 'receipts', label: 'Receipts', icon: Receipt, route: 'receipts', capabilities: ['receipts'], shortcut: 'mod+6' },
]

// ── Layout presets (design.md §10.2) ─────────────────────────────────────────

const PRESETS: Record<LayoutPreset, { label: string; nav: boolean; right: boolean; bottom: boolean }> = {
  focus: { label: 'Focus', nav: false, right: false, bottom: false },
  code: { label: 'Code', nav: true, right: false, bottom: false },
  code_terminal: { label: 'Code + Terminal', nav: true, right: false, bottom: true },
  conversation_files: { label: 'Conversation + Files', nav: true, right: true, bottom: false },
  conversation_terminal: { label: 'Conversation + Terminal', nav: true, right: true, bottom: true },
  infrastructure: { label: 'Infrastructure', nav: true, right: false, bottom: true },
  review: { label: 'Review', nav: false, right: true, bottom: false },
}

const PRESET_ORDER: LayoutPreset[] = [
  'focus',
  'code',
  'code_terminal',
  'conversation_files',
  'conversation_terminal',
  'infrastructure',
  'review',
]

// ── Region placeholders (honest until feature agents register) ───────────────

function SlotPlaceholder({ region, hint }: { region: string; hint: string }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-1.5 p-4 text-center" data-testid={`slot-placeholder-${region}`}>
      <Package className="size-4 text-foreground-tertiary" aria-hidden="true" />
      <p className="text-xs font-medium text-foreground-secondary">{region}</p>
      <p className="max-w-52 text-xs text-foreground-tertiary">{hint}</p>
    </div>
  )
}

function ResizeSeparator({ vertical, onReset }: { vertical?: boolean; onReset: () => void }) {
  return (
    <Separator
      aria-label="Resize panel"
      onDoubleClick={onReset}
      className={cn(
        'relative shrink-0',
        vertical ? 'h-1 cursor-row-resize' : 'w-1 cursor-col-resize',
        'before:absolute before:bg-border before:transition-colors before:duration-instant hover:before:bg-border-strong',
        vertical ? 'before:inset-x-0 before:top-1/2 before:h-px' : 'before:inset-y-0 before:left-1/2 before:w-px',
      )}
    />
  )
}

// ── The shell ────────────────────────────────────────────────────────────────

export function WorkbenchShell() {
  const { instance, hasCapability, capability } = useCurrentInstance()
  const instanceId = instance?.id ?? ''
  const location = useLocation()
  const navigate = useNavigate()
  const isMobile = useIsMobile()
  const [searchParams, setSearchParams] = useSearchParams()

  const layout = useWorkspaceStore((s) => (instanceId ? (s.layouts[instanceId] ?? DEFAULT_LAYOUT) : DEFAULT_LAYOUT))
  const setLayout = useWorkspaceStore((s) => s.setLayout)
  const resetLayout = useWorkspaceStore((s) => s.resetLayout)
  const setFocusMode = useWorkspaceStore((s) => s.setFocusMode)
  const setMaximizedTool = useWorkspaceStore((s) => s.setMaximizedTool)

  const slots = useWorkbenchSlots()

  // ── Current tool from the route segment after "workbench" ──────────────────
  const segments = location.pathname.split('/').filter(Boolean)
  const toolSegment = segments[3] as WorkbenchToolId | undefined
  const currentTool: WorkbenchToolId = TOOLS.some((t) => t.id === toolSegment) ? (toolSegment as WorkbenchToolId) : 'overview'
  const currentToolDef = TOOLS.find((t) => t.id === currentTool) ?? TOOLS[0]

  const toolAvailable = useCallback(
    (tool: ToolDef) => !tool.capabilities || tool.capabilities.some((c) => hasCapability(c)),
    [hasCapability],
  )
  const availableTools = useMemo(() => TOOLS.filter(toolAvailable), [toolAvailable])

  // ── Guards: no workbench capability / deep link to unavailable tool ────────
  const workbenchAvailable = hasCapability('workbench')
  useEffect(() => {
    if (instance && !workbenchAvailable) {
      void navigate(`/app/${instance.id}`, {
        replace: true,
        state: { note: 'This application does not include the workbench.' },
      })
    }
  }, [instance, workbenchAvailable, navigate])

  useEffect(() => {
    if (instance && workbenchAvailable && !toolAvailable(currentToolDef)) {
      void navigate(`/app/${instance.id}/workbench`, {
        replace: true,
        state: { note: `This application does not include ${currentToolDef.label}.` },
      })
    }
  }, [instance, workbenchAvailable, currentToolDef, toolAvailable, navigate])

  // ── Focus / maximize mode (`?focus=1` deep link) ───────────────────────────
  const focusActive = searchParams.get('focus') === '1'
  // Polite live-region text — derived, so transitions announce themselves.
  const announcement = focusActive
    ? `${currentToolDef.label} maximized. Press Escape to restore.`
    : `${currentToolDef.label} restored.`
  const setFocus = useCallback(
    (on: boolean) => {
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          if (on) next.set('focus', '1')
          else next.delete('focus')
          return next
        },
        { replace: true },
      )
    },
    [setSearchParams],
  )
  useEscapeLayer(focusActive, () => setFocus(false), { priority: -100, id: 'workbench-focus' })
  // Sync focus mode into the workspace store (external system).
  useEffect(() => {
    if (!instanceId) return
    setFocusMode(instanceId, focusActive)
    setMaximizedTool(instanceId, focusActive ? currentTool : null)
  }, [focusActive, currentTool, currentToolDef.label, instanceId, setFocusMode, setMaximizedTool])

  // ── Layout actions ─────────────────────────────────────────────────────────
  const applyPreset = useCallback(
    (preset: LayoutPreset) => {
      const def = PRESETS[preset]
      setLayout(instanceId, {
        preset,
        navCollapsed: !def.nav,
        rightDockCollapsed: !def.right,
        bottomCollapsed: !def.bottom,
      })
    },
    [instanceId, setLayout],
  )

  const toggleBottom = useCallback(
    () => setLayout(instanceId, { bottomCollapsed: !useWorkspaceStore.getState().getLayout(instanceId).bottomCollapsed }),
    [instanceId, setLayout],
  )

  const goTool = useCallback(
    (tool: ToolDef) => {
      const base = `/app/${instanceId}/workbench`
      void navigate(tool.route ? `${base}/${tool.route}` : base)
    },
    [instanceId, navigate],
  )

  // ── Keyboard (workbench scope) ─────────────────────────────────────────────
  useShortcutScope('workbench')
  useShortcutAction('workbench.toggle_bottom_panel', toggleBottom)
  useShortcutAction('workbench.maximize_tool', () => setFocus(!focusActive))
  useShortcutAction('workbench.toggle_terminal', () => {
    const terminal = TOOLS.find((t) => t.id === 'terminal')!
    if (toolAvailable(terminal)) goTool(terminal)
  })
  useShortcutAction('workbench.tool_1', () => availableTools[0] && goTool(availableTools[0]))
  useShortcutAction('workbench.tool_2', () => availableTools[1] && goTool(availableTools[1]))
  useShortcutAction('workbench.tool_3', () => availableTools[2] && goTool(availableTools[2]))
  useShortcutAction('workbench.tool_4', () => availableTools[3] && goTool(availableTools[3]))
  useShortcutAction('workbench.tool_5', () => availableTools[4] && goTool(availableTools[4]))
  useShortcutAction('workbench.tool_6', () => availableTools[5] && goTool(availableTools[5]))

  // ── Palette commands (context-aware; capability-filtered) ──────────────────
  const commands = useMemo<ShellCommand[]>(() => {
    if (!workbenchAvailable) return []
    const list: ShellCommand[] = availableTools.map((tool, index) => ({
      id: `workbench.tool.${tool.id}`,
      title: `Workbench: ${tool.label}`,
      group: 'Workbench tools',
      icon: tool.icon,
      shortcut: index < 6 ? `mod+${index + 1}` : undefined,
      when: () => currentTool !== tool.id,
      run: () => goTool(tool),
    }))
    for (const preset of PRESET_ORDER) {
      list.push({
        id: `workbench.layout.${preset}`,
        title: `Layout: ${PRESETS[preset].label}`,
        group: 'Actions',
        icon: LayoutGrid,
        keywords: ['preset', 'workbench'],
        when: () => layout.preset !== preset,
        run: () => applyPreset(preset),
      })
    }
    list.push(
      {
        id: 'workbench.layout.reset',
        title: 'Reset layout',
        group: 'Actions',
        icon: LayoutGrid,
        keywords: ['preset', 'workbench', 'default'],
        run: () => resetLayout(instanceId),
      },
      {
        id: 'workbench.maximize',
        title: focusActive ? 'Restore tool' : 'Maximize tool',
        group: 'Actions',
        icon: focusActive ? Minimize2 : Maximize2,
        shortcut: 'mod+shift+enter',
        run: () => setFocus(!focusActive),
      },
      {
        id: 'workbench.bottom_panel',
        title: 'Toggle bottom panel',
        group: 'Actions',
        icon: PanelBottomOpen,
        shortcut: 'mod+j',
        run: toggleBottom,
      },
    )
    return list
  }, [workbenchAvailable, availableTools, currentTool, layout.preset, focusActive, applyPreset, goTool, instanceId, resetLayout, setFocus, toggleBottom])
  useRegisterCommands(commands)

  // ── Status bar context (terminal state, target name) ───────────────────────
  const [terminalState, setTerminalState] = useState<TerminalSessionState | null>(null)
  const [targetName, setTargetName] = useState<string | null>(null)
  const terminalAvailable = hasCapability('terminal')
  const deploymentsAvailable = hasCapability('infrastructure')

  useEffect(() => {
    if (!instanceId || !terminalAvailable) return
    let cancelled = false
    const tick = async () => {
      try {
        const sessions = await getClient().terminal.listSessions(instanceId)
        if (cancelled) return
        const live = sessions.find((s) => s.state === 'connected' || s.state === 'connecting' || s.state === 'reconnecting')
        setTerminalState((live ?? sessions[0])?.state ?? null)
      } catch {
        if (!cancelled) setTerminalState(null)
      }
    }
    void tick()
    const timer = window.setInterval(tick, 5_000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [instanceId, terminalAvailable])

  useEffect(() => {
    if (!instanceId || !deploymentsAvailable) return
    let cancelled = false
    const tick = async () => {
      try {
        const target = await getClient().infrastructure.getTarget(instanceId)
        if (!cancelled) setTargetName(target.name)
      } catch {
        if (!cancelled) setTargetName(null)
      }
    }
    void tick()
    const timer = window.setInterval(tick, 10_000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [instanceId, deploymentsAvailable])

  const statusValue = useMemo<WorkbenchStatus | null>(() => {
    if (!instance) return null
    return {
      instanceId,
      instance,
      tool: currentTool,
      terminalState,
      terminalAvailable,
      targetName,
      deploymentsAvailable,
    }
  }, [instance, instanceId, currentTool, terminalState, terminalAvailable, targetName, deploymentsAvailable])

  // ── Persist panel sizes (debounced) ────────────────────────────────────────
  const sizeTimer = useRef<number | null>(null)
  const pendingSizePatch = useRef<Partial<{ navSize: number; rightDockSize: number; bottomSize: number }>>({})
  const persistSize = useCallback(
    (patch: Partial<{ navSize: number; rightDockSize: number; bottomSize: number }>) => {
      // Resizing one region can make the panel library report adjusted sizes
      // for its siblings in the same frame. Preserve every reported dimension:
      // replacing the pending patch here would let the last callback cancel an
      // earlier user-driven resize before the debounce commits it.
      pendingSizePatch.current = { ...pendingSizePatch.current, ...patch }
      if (sizeTimer.current !== null) window.clearTimeout(sizeTimer.current)
      sizeTimer.current = window.setTimeout(() => {
        sizeTimer.current = null
        const next = pendingSizePatch.current
        pendingSizePatch.current = {}
        setLayout(instanceId, next)
      }, 300)
    },
    [instanceId, setLayout],
  )
  useEffect(
    () => () => {
      if (sizeTimer.current !== null) window.clearTimeout(sizeTimer.current)
      sizeTimer.current = null
      const next = pendingSizePatch.current
      pendingSizePatch.current = {}
      if (Object.keys(next).length > 0) setLayout(instanceId, next)
    },
    [instanceId, setLayout],
  )
  const [layoutEpoch, setLayoutEpoch] = useState(0)
  const resetRegion = useCallback(
    (patch: Partial<{ navSize: number; rightDockSize: number; bottomSize: number }>) => {
      setLayout(instanceId, patch)
      setLayoutEpoch((e) => e + 1)
    },
    [instanceId, setLayout],
  )

  if (!instance || !workbenchAvailable) return null

  const base = `/app/${instanceId}/workbench`
  const capabilityDotFor = (tool: ToolDef) => {
    for (const capId of tool.capabilities ?? []) {
      const state = capability(capId)
      if (state && state.status !== 'available') return <CapabilityDot status={state.status} reason={state.reason} />
    }
    return null
  }

  // ── Focus mode: only the canvas + floating restore bar ─────────────────────
  if (focusActive) {
    const Icon = currentToolDef.icon
    return (
      <div className="relative flex h-full flex-col bg-app" data-testid="workbench-focus">
        <div aria-live="polite" className="sr-only">
          {announcement}
        </div>
        <div className="min-h-0 flex-1">
          <Outlet />
        </div>
        <div className="pointer-events-none absolute inset-x-0 top-0 z-overlay flex justify-center">
          <div className="pointer-events-auto mt-2 flex h-9 items-center gap-2 rounded-md border border-border bg-surface px-3 shadow-1">
            <Icon className="size-4 text-foreground-secondary" aria-hidden="true" />
            <span className="text-sm font-medium text-foreground">{currentToolDef.label}</span>
            <button
              type="button"
              onClick={() => setFocus(false)}
              className="inline-flex h-7 items-center gap-1 rounded-sm px-2 text-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            >
              <Minimize2 className="size-3.5" aria-hidden="true" />
              Restore · Esc
            </button>
          </div>
        </div>
      </div>
    )
  }

  const ToolTabs = (
    <>
      {availableTools.map((tool) => (
        <NavLink
          key={tool.id}
          to={tool.route ? `${base}/${tool.route}` : base}
          end={tool.id === 'overview'}
          className={({ isActive }) =>
            cn(
              'relative flex h-full items-center gap-1.5 px-2 text-sm font-medium transition-colors duration-instant',
              isActive
                ? 'text-accent after:absolute after:inset-x-1 after:bottom-0 after:h-0.5 after:bg-accent'
                : 'text-foreground-secondary hover:text-foreground',
            )
          }
        >
          <tool.icon className="size-4 shrink-0" aria-hidden="true" />
          <span className={cn(currentTool !== tool.id && 'hidden lg:inline')}>{tool.label}</span>
          {capabilityDotFor(tool)}
        </NavLink>
      ))}
      <DropdownMenu>
        <DropdownMenuTrigger
          aria-label="More tools"
          className="inline-flex h-full items-center px-1.5 text-foreground-secondary transition-colors duration-instant hover:text-foreground lg:hidden"
        >
          <MoreHorizontal className="size-4" aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="bg-surface">
          {availableTools.map((tool) => (
            <DropdownMenuItem key={tool.id} onSelect={() => goTool(tool)}>
              <tool.icon className="size-4" aria-hidden="true" />
              {tool.label}
              {currentTool === tool.id ? <Check className="ml-auto size-4 text-accent" aria-hidden="true" /> : null}
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  )

  const PresetMenu = (
    <DropdownMenu>
      <Tooltip content="Layout presets">
        <DropdownMenuTrigger
          aria-label="Layout presets"
          className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          data-testid="preset-menu-trigger"
        >
          <PanelsTopLeft className="size-4" aria-hidden="true" />
        </DropdownMenuTrigger>
      </Tooltip>
      <DropdownMenuContent align="end" className="w-56 bg-surface" data-testid="preset-menu">
        <DropdownMenuLabel>Layout presets</DropdownMenuLabel>
        {PRESET_ORDER.map((preset) => (
          <DropdownMenuItem key={preset} onSelect={() => applyPreset(preset)}>
            <LayoutGrid className="size-4" aria-hidden="true" />
            <span className="flex-1">{PRESETS[preset].label}</span>
            {layout.preset === preset ? <Check className="size-4 text-accent" aria-hidden="true" /> : null}
          </DropdownMenuItem>
        ))}
        <DropdownSeparator />
        <DropdownMenuItem onSelect={() => resetLayout(instanceId)}>Reset layout</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )

  // ── Mobile: tool selector + single main tool (workbench.md) ────────────────
  if (isMobile) {
    return (
      <WorkbenchStatusContext.Provider value={statusValue}>
        <div className="flex h-full flex-col" data-testid="workbench-mobile">
          <header className="flex h-9 shrink-0 items-center gap-1 border-b border-border bg-surface px-2">
            <DropdownMenu>
              <DropdownMenuTrigger
                className="flex items-center gap-1.5 rounded-sm px-2 py-1 text-sm font-medium text-foreground"
                aria-label="Select tool"
                data-testid="tool-selector"
              >
                <currentToolDef.icon className="size-4" aria-hidden="true" />
                {currentToolDef.label}
                <ChevronDown className="size-3.5 text-foreground-secondary" aria-hidden="true" />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="bg-surface">
                {availableTools.map((tool) => (
                  <DropdownMenuItem key={tool.id} onSelect={() => goTool(tool)}>
                    <tool.icon className="size-4" aria-hidden="true" />
                    <span className="flex-1">{tool.label}</span>
                    {capabilityDotFor(tool)}
                    {currentTool === tool.id ? <Check className="size-4 text-accent" aria-hidden="true" /> : null}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <div className="flex-1" />
            <Tooltip content={focusActive ? 'Restore' : 'Maximize tool'}>
              <button
                type="button"
                aria-label={focusActive ? 'Restore tool' : 'Maximize tool'}
                onClick={() => setFocus(!focusActive)}
                className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
              >
                <Maximize2 className="size-4" aria-hidden="true" />
              </button>
            </Tooltip>
          </header>
          <div className="min-h-0 flex-1">
            <Outlet />
          </div>
          <StatusBar />
        </div>
      </WorkbenchStatusContext.Provider>
    )
  }

  // ── Desktop / tablet: panel dock ───────────────────────────────────────────
  const NavPanel = slots.toolPanels[currentTool]
  const RightDock = slots.rightDock
  const BottomPanel = slots.bottomPanel

  return (
    <WorkbenchStatusContext.Provider value={statusValue}>
      <div className="flex h-full flex-col" data-testid="workbench-shell">
        <div aria-live="polite" className="sr-only">
          {announcement}
        </div>

        {/* Tool header (36 px) */}
        <header
          className="flex h-9 shrink-0 items-center gap-0.5 border-b border-border bg-surface px-1"
          onDoubleClick={(e) => {
            if ((e.target as HTMLElement).closest('a,button')) return
            setFocus(true)
          }}
          data-testid="tool-header"
        >
          {ToolTabs}
          <div className="flex-1" />
          {PresetMenu}
          <Tooltip content={focusActive ? `Restore · ${MOD_LABEL}+Shift+Enter` : `Maximize tool · ${MOD_LABEL}+Shift+Enter`}>
            <button
              type="button"
              aria-label={focusActive ? 'Restore tool' : 'Maximize tool'}
              onClick={() => setFocus(!focusActive)}
              className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
              data-testid="focus-toggle"
            >
              {focusActive ? <Minimize2 className="size-4" aria-hidden="true" /> : <Maximize2 className="size-4" aria-hidden="true" />}
            </button>
          </Tooltip>
          <DropdownMenu>
            <DropdownMenuTrigger
              aria-label="Tool options"
              className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
            >
              <MoreHorizontal className="size-4" aria-hidden="true" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="bg-surface">
              <DropdownMenuItem
                onSelect={() => {
                  const url = `${window.location.pathname}${window.location.search}#${base}${currentToolDef.route ? `/${currentToolDef.route}` : ''}?window=tool`
                  window.open(url, '_blank', 'noopener')
                }}
              >
                Open tool in new window
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => resetLayout(instanceId)}>Restore defaults</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </header>

        {/* Regions */}
        <div className="flex min-h-0 flex-1">
          {layout.navCollapsed ? (
            <div className="flex w-6 shrink-0 flex-col items-center border-r border-border bg-surface py-1">
              <Tooltip content="Show panel" side="right">
                <button
                  type="button"
                  aria-label="Show navigation panel"
                  onClick={() => setLayout(instanceId, { navCollapsed: false })}
                  className="inline-flex min-h-6 min-w-5 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                >
                  <PanelLeftOpen className="size-3.5" aria-hidden="true" />
                </button>
              </Tooltip>
            </div>
          ) : null}

          <PanelGroup
            key={`${instanceId}-${layoutEpoch}-${String(layout.navCollapsed)}-${String(layout.rightDockCollapsed)}-${String(layout.bottomCollapsed)}`}
            orientation="horizontal"
            className="min-h-0 flex-1"
          >
            {layout.navCollapsed ? null : (
              <>
                <Panel
                  id="nav"
                  defaultSize={`${layout.navSize}px`}
                  minSize="200px"
                  maxSize="480px"
                  onResize={(size) => persistSize({ navSize: Math.round(size.inPixels) })}
                  className="flex flex-col bg-surface"
                >
                  <div className="flex h-7 shrink-0 items-center justify-between border-b border-border px-2">
                    <span className="truncate text-xs font-medium text-foreground-secondary">{currentToolDef.label}</span>
                    <Tooltip content="Collapse panel">
                      <button
                        type="button"
                        aria-label="Collapse navigation panel"
                        onClick={() => setLayout(instanceId, { navCollapsed: true })}
                        className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                      >
                        <PanelLeftClose className="size-3.5" aria-hidden="true" />
                      </button>
                    </Tooltip>
                  </div>
                  <div className="min-h-0 flex-1 overflow-y-auto">
                    {NavPanel ? (
                      <NavPanel instanceId={instanceId} tool={currentTool} />
                    ) : (
                      <SlotPlaceholder region={`${currentToolDef.label} panel`} hint="The tool registers its navigation panel here (file tree, sessions, targets)." />
                    )}
                  </div>
                </Panel>
                <ResizeSeparator onReset={() => resetRegion({ navSize: DEFAULT_LAYOUT.navSize })} />
              </>
            )}

            <Panel id="main" minSize="30%" className="flex min-w-0 flex-col">
              <PanelGroup orientation="vertical" className="min-h-0 flex-1">
                <Panel id="canvas" minSize="15%" className="flex min-h-0 flex-col bg-app">
                  <div className="min-h-0 flex-1 overflow-hidden">
                    <Outlet />
                  </div>
                </Panel>

                {layout.bottomCollapsed || !BottomPanel ? null : (
                  <>
                    <ResizeSeparator vertical onReset={() => resetRegion({ bottomSize: DEFAULT_LAYOUT.bottomSize })} />
                    <Panel
                      id="bottom"
                      defaultSize={`${layout.bottomSize}px`}
                      minSize="120px"
                      maxSize="70vh"
                      onResize={(size) => persistSize({ bottomSize: Math.round(size.inPixels) })}
                      className="flex flex-col bg-surface"
                    >
                      <div className="flex h-7 shrink-0 items-center justify-between border-b border-border px-2">
                        <span className="truncate text-xs font-medium text-foreground-secondary">Panel</span>
                        <Tooltip content={`Close panel · ${MOD_LABEL}+J`}>
                          <button
                            type="button"
                            aria-label="Close bottom panel"
                            onClick={() => setLayout(instanceId, { bottomCollapsed: true })}
                            className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                          >
                            <PanelBottomClose className="size-3.5" aria-hidden="true" />
                          </button>
                        </Tooltip>
                      </div>
                      <div className="min-h-0 flex-1 overflow-y-auto">
                        {BottomPanel ? (
                          <BottomPanel instanceId={instanceId} tool={currentTool} />
                        ) : (
                          <SlotPlaceholder region="Bottom panel" hint="A terminal dock or log view registers here." />
                        )}
                      </div>
                    </Panel>
                  </>
                )}
              </PanelGroup>
            </Panel>

            {layout.rightDockCollapsed ? null : (
              <>
                <ResizeSeparator onReset={() => resetRegion({ rightDockSize: DEFAULT_LAYOUT.rightDockSize })} />
                <Panel
                  id="right"
                  defaultSize={`${layout.rightDockSize}px`}
                  minSize="280px"
                  maxSize="520px"
                  onResize={(size) => persistSize({ rightDockSize: Math.round(size.inPixels) })}
                  className="flex flex-col bg-surface"
                >
                  <div className="flex h-7 shrink-0 items-center justify-between border-b border-border px-2">
                    <span className="truncate text-xs font-medium text-foreground-secondary">Dock</span>
                    <Tooltip content="Close dock">
                      <button
                        type="button"
                        aria-label="Close right dock"
                        onClick={() => setLayout(instanceId, { rightDockCollapsed: true })}
                        className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                      >
                        <PanelRightClose className="size-3.5" aria-hidden="true" />
                      </button>
                    </Tooltip>
                  </div>
                  <div className="min-h-0 flex-1 overflow-y-auto">
                    {RightDock ? (
                      <RightDock instanceId={instanceId} tool={currentTool} />
                    ) : (
                      <SlotPlaceholder region="Right dock" hint="A conversation sidecar or detail view docks here." />
                    )}
                  </div>
                </Panel>
              </>
            )}
          </PanelGroup>

          {layout.rightDockCollapsed ? (
            <div className="flex w-6 shrink-0 flex-col items-center border-l border-border bg-surface py-1">
              <Tooltip content="Show dock" side="left">
                <button
                  type="button"
                  aria-label="Show right dock"
                  onClick={() => setLayout(instanceId, { rightDockCollapsed: false })}
                  className="inline-flex min-h-6 min-w-5 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                >
                  <PanelRightOpen className="size-3.5" aria-hidden="true" />
                </button>
              </Tooltip>
            </div>
          ) : null}
        </div>

        {layout.bottomCollapsed ? (
          <div className="flex h-5 shrink-0 items-center justify-center border-t border-border bg-surface">
            <Tooltip content={`Show panel · ${MOD_LABEL}+J`}>
              <button
                type="button"
                aria-label="Show bottom panel"
                onClick={() => setLayout(instanceId, { bottomCollapsed: false })}
                className="inline-flex min-h-4 items-center justify-center rounded-sm px-2 text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
              >
                <PanelBottomOpen className="size-3" aria-hidden="true" />
              </button>
            </Tooltip>
          </div>
        ) : null}

        <StatusBar />
      </div>
    </WorkbenchStatusContext.Provider>
  )
}

// Re-export the slot contract's prop type from the canonical path for convenience.
export type { WorkbenchSlotProps } from './workbench/WorkbenchSlots'
