/**
 * TerminalWorkbenchIntegration — registers the terminal's workbench slots:
 * the docked terminal in the bottom panel and the sessions/targets nav panel
 * for the terminal tool. Renders nothing itself.
 *
 * NOTE (integration contract): the ORCHESTRATOR mounts this component at the
 * workbench level (e.g. inside WorkbenchShell's tree). It must be mounted
 * exactly once — mounting it in two places would double-register the slots
 * (each unmount would unregister the other's panels).
 */
import { useRegisterBottomPanel, useRegisterToolPanel } from '@/shell/workbench/WorkbenchSlots'

import { TerminalDock } from './TerminalDock'
import { TerminalSessionsPanel } from './TerminalSessionsPanel'

export default function TerminalWorkbenchIntegration() {
  useRegisterBottomPanel(TerminalDock)
  useRegisterToolPanel('terminal', TerminalSessionsPanel)
  // Registration-only component: no rendered output.
  return null
}
