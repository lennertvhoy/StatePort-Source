/**
 * ConversationWorkbenchIntegration — mounts the conversation sidecar into the
 * workbench right dock (WorkbenchSlots). The orchestrator mounts this
 * component once in WorkbenchShell; it registers on mount, unregisters on
 * unmount, and renders nothing itself.
 */
import { useRegisterRightDock } from '@/shell/workbench/WorkbenchSlots'

import ConversationSidecar from './ConversationSidecar'

export default function ConversationWorkbenchIntegration() {
  useRegisterRightDock(ConversationSidecar)
  return null
}
