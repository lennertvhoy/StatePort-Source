/**
 * Canvas ⇄ nav-panel coordination for the Deployments tool: which plan the
 * canvas should show when a recent-operation row is clicked in the panel.
 */
import { create } from 'zustand'

interface DeploymentsSelectionState {
  requestedPlanId: string | null
  requestSelect: (planId: string) => void
  clearRequest: () => void
}

export const useDeploymentsSelection = create<DeploymentsSelectionState>()((set) => ({
  requestedPlanId: null,
  requestSelect: (planId) => set({ requestedPlanId: planId }),
  clearRequest: () => set({ requestedPlanId: null }),
}))
