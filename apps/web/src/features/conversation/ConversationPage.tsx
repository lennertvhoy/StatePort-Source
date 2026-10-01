/**
 * ConversationPage — `#/app/:instanceId/conversation` (design: conversation.md).
 *
 * A primary application surface built for long sessions: compact thread
 * header, calm transcript, excellent sticky composer, honest streaming,
 * explicit context control, and bridges to every other tool — never silent
 * action. The heavy lifting lives in ConversationSurface so the workbench
 * sidecar can reuse the same transcript + composer.
 */
import { useParams } from 'react-router-dom'

import { ErrorState } from '@/components'
import { useShortcutScope } from '@/shell/shortcutRegistry'

import { ConversationSurface } from './ConversationSurface'

export default function ConversationPage() {
  const { instanceId } = useParams<{ instanceId: string }>()

  // Activate the conversation shortcut scope (send/newline/stop chords).
  useShortcutScope('conversation')

  if (!instanceId) {
    return <ErrorState title="No application selected" error="This route needs an application id." />
  }
  return (
    // data-testid="conversation-stub" is a deliberate compatibility alias: the
    // orchestrator-owned shell routes smoke test still selects the stub's id.
    // Drop the alias when the shell test is updated to "conversation-surface".
    <div className="h-full min-h-0" data-testid="conversation-stub">
      <ConversationSurface instanceId={instanceId} />
    </div>
  )
}
