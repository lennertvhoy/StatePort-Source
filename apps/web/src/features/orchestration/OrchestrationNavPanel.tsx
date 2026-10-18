/**
 * OrchestrationNavPanel — the left workbench panel for the Orchestration
 * tool: the current bounded slice (stage + state), or an honest "no session"
 * row. One slice at a time — there is no background queue to list.
 */
import { useEffect, useState } from 'react'
import { ClipboardCheck } from 'lucide-react'

import type { OrchestrationSession } from '@/client'
import { getClient } from '@/client'
import { OperationStateLabel } from '@/components'
import type { WorkbenchSlotProps } from '@/shell/workbench/WorkbenchSlots'

import { stageLabel } from './orchestrationModel'

const POLL_MS = 10_000

export function OrchestrationNavPanel({ instanceId }: WorkbenchSlotProps) {
  const [session, setSession] = useState<OrchestrationSession | null>(null)

  useEffect(() => {
    if (!instanceId) return
    let cancelled = false
    const tick = async () => {
      try {
        const current = await getClient().orchestration.getCurrent(instanceId)
        if (!cancelled) setSession(current)
      } catch {
        if (!cancelled) setSession(null)
      }
    }
    void tick()
    const timer = window.setInterval(tick, POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [instanceId])

  return (
    <div className="flex flex-col py-1" data-testid="orchestration-nav-panel">
      <p className="px-3 pb-1 pt-1.5 text-xs font-medium text-foreground-tertiary">Current slice</p>
      {session ? (
        <div className="flex items-start gap-2 px-3 py-1.5" data-testid="nav-session-row">
          <ClipboardCheck className="mt-0.5 size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm text-foreground">{session.objective}</span>
            <span className="block text-xs text-foreground-tertiary">{stageLabel(session.stage)}</span>
            <OperationStateLabel state={session.state} className="text-xs" />
          </span>
        </div>
      ) : (
        <p className="px-3 py-1.5 text-xs text-foreground-tertiary">
          No slice in progress — orchestration is stopped.
        </p>
      )}
    </div>
  )
}
