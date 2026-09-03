/**
 * DeploymentsNavPanel — the left workbench panel for the Deployments tool
 * (design/infrastructure.md: "Nav panel = targets & history"): pinned target
 * rows with the dominant StatusDot, then recent operations as compact rows.
 * Clicking an operation selects its plan in the canvas.
 */
import { useEffect, useState } from 'react'

import type { InfrastructurePlan, InfrastructureTarget } from '@/client'
import { getClient } from '@/client'
import { OperationStateLabel, StatusDotFrom, TimeAgo } from '@/components'
import type { WorkbenchSlotProps } from '@/shell/workbench/WorkbenchSlots'

import { useDeploymentsSelection } from './deploymentsSelection'
import { dominantTargetPresentation } from './infrastructureModel'

const POLL_MS = 10_000

export function DeploymentsNavPanel({ instanceId }: WorkbenchSlotProps) {
  const [target, setTarget] = useState<InfrastructureTarget | null>(null)
  const [plans, setPlans] = useState<InfrastructurePlan[]>([])
  const [error, setError] = useState<unknown>(null)
  const requestSelect = useDeploymentsSelection((s) => s.requestSelect)

  useEffect(() => {
    if (!instanceId) return
    let cancelled = false
    const tick = async () => {
      try {
        const [nextTarget, nextPlans] = await Promise.all([
          getClient().infrastructure.getTarget(instanceId),
          getClient().infrastructure.listPlans(instanceId),
        ])
        if (cancelled) return
        setTarget(nextTarget)
        setPlans(nextPlans)
        setError(null)
      } catch (err) {
        // Honest failure: keep the last known target/plans and surface the
        // failure — never pretend no target or plans exist.
        if (!cancelled) setError(err)
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
    <div className="flex flex-col py-1" data-testid="deployments-nav-panel">
      <p className="px-3 pb-1 pt-1.5 text-xs font-medium text-foreground-tertiary">Targets</p>
      {target ? (
        <div className="flex items-center gap-2 px-3 py-1.5" data-testid="nav-target-row">
          <StatusDotFrom presentation={dominantTargetPresentation(target)} showLabel={false} />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm text-foreground">{target.name}</span>
            <span className="block text-xs text-foreground-tertiary">Local VM</span>
          </span>
        </div>
      ) : error ? (
        <p className="px-3 py-1.5 text-xs text-foreground-tertiary" data-testid="nav-target-unavailable">
          Target status unavailable — could not load deployments.
        </p>
      ) : (
        <p className="px-3 py-1.5 text-xs text-foreground-tertiary">No target verified.</p>
      )}

      <p className="px-3 pb-1 pt-3 text-xs font-medium text-foreground-tertiary">Recent operations</p>
      {plans.length === 0 ? (
        error ? (
          <p className="px-3 py-1.5 text-xs text-foreground-tertiary" data-testid="nav-plans-unavailable">
            Recent operations unavailable — could not load plans.
          </p>
        ) : (
          <p className="px-3 py-1.5 text-xs text-foreground-tertiary">No plans yet.</p>
        )
      ) : (
        <ul>
          {plans.slice(0, 12).map((plan) => (
            <li key={plan.id}>
              <button
                type="button"
                onClick={() => requestSelect(plan.id)}
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left transition-colors duration-instant hover:bg-hover"
                data-testid="nav-operation-row"
              >
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-xs font-medium text-foreground">{plan.title}</span>
                  <OperationStateLabel state={plan.state} className="text-xs" />
                </span>
                <TimeAgo date={plan.createdAt} />
              </button>
            </li>
          ))}
        </ul>
      )}
      {error && (target || plans.length > 0) ? (
        <p className="px-3 py-1.5 text-xs text-foreground-tertiary" data-testid="nav-deployments-stale">
          Refresh failed — showing the last known state.
        </p>
      ) : null}
    </div>
  )
}
