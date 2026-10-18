/**
 * Workbench status context — provided by WorkbenchShell, consumed by the
 * StatusBar (design.md §9.5). Lives outside component modules so fast-refresh
 * boundaries stay component-only.
 */
import { createContext } from 'react'

import type { ApplicationInstance, TerminalSessionState, WorkbenchToolId } from '@/client'

export interface WorkbenchStatus {
  instanceId: string
  instance: ApplicationInstance
  tool: WorkbenchToolId
  /** Live terminal session state for this app (null = no sessions). */
  terminalState: TerminalSessionState | null
  terminalAvailable: boolean
  /** Active infrastructure target name (null = none). */
  targetName: string | null
  deploymentsAvailable: boolean
}

export const WorkbenchStatusContext = createContext<WorkbenchStatus | null>(null)
