/**
 * WorkbenchIntegrations — orchestrator-owned mount point for feature-provided
 * workbench slot registrars (bottom dock, right dock, tool nav panels).
 * Each integration component registers its slots via WorkbenchSlots hooks and
 * renders null. Mounted exactly once around the WorkbenchShell route.
 */
import { WorkbenchShell } from '@/shell/WorkbenchShell'
import TerminalWorkbenchIntegration from '@/features/terminal/TerminalWorkbenchIntegration'
import ConversationWorkbenchIntegration from '@/features/conversation/ConversationWorkbenchIntegration'
import { useCurrentInstance } from '@/shell/currentInstance'

export function WorkbenchIntegrations() {
  const { hasCapability } = useCurrentInstance()

  return (
    <>
      {hasCapability('terminal') ? <TerminalWorkbenchIntegration /> : null}
      {hasCapability('conversation') ? <ConversationWorkbenchIntegration /> : null}
      <WorkbenchShell />
    </>
  )
}
