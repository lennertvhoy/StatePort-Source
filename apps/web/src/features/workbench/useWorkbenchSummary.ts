/**
 * useWorkbenchSummary — the data for the Workbench Overview tool. Loads
 * everything through the client boundary in parallel; capability-gated
 * sections (terminal/infrastructure/orchestration) are only fetched when the
 * capability is usable, and fail soft to "not checked" rather than taking
 * the page down.
 */
import { useCallback, useEffect, useState } from 'react'

import type {
  ActivityItem,
  Approval,
  ApplicationInstance,
  InfrastructureTarget,
  OperationExecutionRecord,
  OrchestrationSession,
  Receipt,
  TerminalSession,
} from '@/client'
import { getClient } from '@/client'
import { useSessionStore } from '@/state'
import { isLiveOperationState } from '@/features/applications/lib/dominantStatus'

export interface WorkbenchSummary {
  loading: boolean
  error: unknown
  refresh: () => void
  receipts: Receipt[]
  receiptCount: number
  activity: ActivityItem[]
  pendingApprovals: Approval[]
  operations: OperationExecutionRecord[]
  terminalSession: TerminalSession | null
  infraTarget: InfrastructureTarget | null
  orchestration: OrchestrationSession | null
}

export function useWorkbenchSummary(
  instance: ApplicationInstance | null,
  hasCapability: (id: 'terminal' | 'infrastructure' | 'cto_orchestration') => boolean,
): WorkbenchSummary {
  const instanceId = instance?.id
  const [state, setState] = useState<Omit<WorkbenchSummary, 'refresh'>>({
    loading: true,
    error: null,
    receipts: [],
    receiptCount: 0,
    activity: [],
    pendingApprovals: [],
    operations: [],
    terminalSession: null,
    infraTarget: null,
    orchestration: null,
  })
  const [nonce, setNonce] = useState(0)
  const refresh = useCallback(() => setNonce((n) => n + 1), [])
  const activeScenario = useSessionStore((s) => s.activeScenario)

  useEffect(() => {
    if (!instanceId) return
    let cancelled = false
    setState((s) => ({ ...s, loading: true, error: null }))
    const client = getClient()
    const hasCtoOrchestration = hasCapability('cto_orchestration')

    const load = async () => {
      try {
        const [receipts, activity, approvals, operations] = await Promise.all([
          // The goal-execution closure receipt is polled inside receipts.list;
          // skip that poll when the instance has no effective goal capability.
          client.receipts.list({ instanceId, goalExecution: hasCtoOrchestration }),
          client.activity.listActivity({ instanceId, limit: 5 }),
          client.approvals.list({ instanceId, status: 'pending' }),
          client.operations.list(),
        ])

        // Capability-gated sections — best-effort, honest "not checked" on failure.
        const [terminalSessions, infraTarget, orchestration] = await Promise.all([
          hasCapability('terminal')
            ? client.terminal.listSessions(instanceId).catch(() => [] as TerminalSession[])
            : Promise.resolve([] as TerminalSession[]),
          hasCapability('infrastructure')
            ? client.infrastructure.getTarget(instanceId).catch(() => null)
            : Promise.resolve(null),
          hasCapability('cto_orchestration')
            ? client.orchestration.getCurrent(instanceId).catch(() => null)
            : Promise.resolve(null),
        ])

        if (cancelled) return
        const liveTerminal =
          terminalSessions.find((s) => s.state === 'connected' || s.state === 'connecting' || s.state === 'reconnecting') ??
          terminalSessions[0] ??
          null
        setState({
          loading: false,
          error: null,
          receipts: receipts.slice(0, 5),
          receiptCount: receipts.length,
          activity,
          pendingApprovals: approvals,
          operations: operations.filter((op) => op.kind !== 'infrastructure_observation').filter((op) => op.instanceId === instanceId && isLiveOperationState(op.state)),
          terminalSession: liveTerminal,
          infraTarget,
          orchestration,
        })
      } catch (err) {
        if (!cancelled) setState((s) => ({ ...s, loading: false, error: err }))
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [instanceId, nonce, activeScenario, hasCapability])

  return { ...state, refresh }
}
