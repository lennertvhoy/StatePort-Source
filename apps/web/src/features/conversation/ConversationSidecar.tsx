/**
 * ConversationSidecar — the workbench right-dock conversation view
 * (workbench.md presets "Conversation + Files" / "Conversation + Terminal").
 * Same transcript + composer as the full surface in a dense layout.
 */
import type { WorkbenchSlotProps } from '@/shell/workbench/WorkbenchSlots'

import { ConversationSurface } from './ConversationSurface'

export function ConversationSidecar({ instanceId }: WorkbenchSlotProps) {
  return <ConversationSurface instanceId={instanceId} dense />
}

export default ConversationSidecar
