/**
 * WorkbenchSlots — THE contract feature agents use to fill the workbench
 * frame regions (design.md §10, workbench.md).
 *
 * The canvas is route-driven (feature pages render as nested routes); these
 * slots fill the three frame regions around it:
 *
 * ```tsx
 * // In the Files tool (mounted by its route):
 * useRegisterToolPanel('files', FileTreePanel)     // left nav panel, per tool
 * useRegisterBottomPanel(TerminalDockPanel)        // bottom panel (any tool)
 * useRegisterRightDock(ConversationSidecar)        // right dock (any tool)
 * ```
 *
 * Every slot component receives `{ instanceId, tool }` — the current
 * application and the active workbench tool. Registration auto-cleans on
 * unmount; regions show honest placeholders until filled.
 */
import type { ComponentType } from 'react'
import { useEffect } from 'react'
import { create } from 'zustand'

import type { WorkbenchToolId } from '@/client'

/** Props every workbench slot component receives. */
export interface WorkbenchSlotProps {
  instanceId: string
  tool: WorkbenchToolId
}

export type WorkbenchSlotComponent = ComponentType<WorkbenchSlotProps>

interface WorkbenchSlotsState {
  /** Per-tool left nav panel content (file tree, session list, …). */
  toolPanels: Partial<Record<WorkbenchToolId, WorkbenchSlotComponent>>
  /** Global right dock content (conversation sidecar, detail context). */
  rightDock: WorkbenchSlotComponent | null
  /** Bottom panel content (terminal dock, logs). */
  bottomPanel: WorkbenchSlotComponent | null
  setToolPanel(toolId: WorkbenchToolId, component: WorkbenchSlotComponent | null): void
  setRightDock(component: WorkbenchSlotComponent | null): void
  setBottomPanel(component: WorkbenchSlotComponent | null): void
}

export const useWorkbenchSlots = create<WorkbenchSlotsState>()((set) => ({
  toolPanels: {},
  rightDock: null,
  bottomPanel: null,
  setToolPanel: (toolId, component) =>
    set((s) => {
      const toolPanels = { ...s.toolPanels }
      if (component) toolPanels[toolId] = component
      else delete toolPanels[toolId]
      return { toolPanels }
    }),
  setRightDock: (rightDock) => set({ rightDock }),
  setBottomPanel: (bottomPanel) => set({ bottomPanel }),
}))

/**
 * Register the left nav panel content for a tool. Mount it in the tool's
 * route component; it unregisters automatically on unmount.
 */
export function useRegisterToolPanel(toolId: WorkbenchToolId, component: WorkbenchSlotComponent): void {
  const setToolPanel = useWorkbenchSlots((s) => s.setToolPanel)
  useEffect(() => {
    setToolPanel(toolId, component)
    return () => setToolPanel(toolId, null)
  }, [toolId, component, setToolPanel])
}

/** Register the right dock content (receives `{ instanceId, tool }`). */
export function useRegisterRightDock(component: WorkbenchSlotComponent): void {
  const setRightDock = useWorkbenchSlots((s) => s.setRightDock)
  useEffect(() => {
    setRightDock(component)
    return () => setRightDock(null)
  }, [component, setRightDock])
}

/** Register the bottom panel content (receives `{ instanceId, tool }`). */
export function useRegisterBottomPanel(component: WorkbenchSlotComponent): void {
  const setBottomPanel = useWorkbenchSlots((s) => s.setBottomPanel)
  useEffect(() => {
    setBottomPanel(component)
    return () => setBottomPanel(null)
  }, [component, setBottomPanel])
}
