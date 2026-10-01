/**
 * DeploymentsNavPanel — the left workbench panel for the Deployments tool
 * (design/infrastructure.md: "Nav panel = targets & history"): pinned target
 * rows with the dominant StatusDot, then recent operations as compact rows.
 * Clicking an operation selects its plan in the canvas.
 */
import { useEffect, useState } from 'react'

import type { InfrastructurePlan } from '@/client'
import { getClient } from '@/client'
import { OperationStateLabel, StatusDotFrom, TimeAgo } from '@/components'
import { useSharedInfrastructureTarget } from '@/shell/data'
import type { WorkbenchSlotProps } from '@/shell/workbench/WorkbenchSlots'

import { useDeploymentsSelection } from './deploymentsSelection'
import { dominantTargetPresentation } from './infrastructureModel'

const POLL_MS = 10_000

export function DeploymentsNavPanel({ instanceId }: WorkbenchSlotProps) {
  // The target is shared with the workbench status bar (one 10 s read for both
  // mounted surfaces). Plans keep this panel's own poll — they are its data.
  const { target, error: targetError } = useSharedInfrastructureTarget(instanceId, true)
  const [plans, setPlans] = useState<InfrastructurePlan[]>([])
  const [plansError, setPlansError] = useState<unknown>(null)
  const requestSelect = useDeploymentsSelection((s) => s.requestSelect)

  useEffect(() => {
    if (!instanceId) return
    let cancelled = false
    const tick = async () => {
      try {
        const nextPlans = await getClient().infrastructure.listPlans(instanceId)
        if (cancelled) return
        setPlans(nextPlans)
        setPlansError(null)
      } catch (err) {
        // Honest failure: keep the last known plans and surface the failure —
        // never pretend no plans exist.
        if (!cancelled) setPlansError(err)
      }
    }
    void tick()
    const timer = window.setInterval(tick, POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [instanceId])

  // Either observation failing flags the panel stale; the last known target
  // and plans stay on screen.
  const error = plansError ?? targetError

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
