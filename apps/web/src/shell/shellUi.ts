/**
 * Ephemeral shell UI state (not persisted): operation center, mobile nav,
 * shortcuts reference modal visibility lives in the command store.
 */
import { create } from 'zustand'

interface ShellUiState {
  operationCenterOpen: boolean
  mobileNavOpen: boolean
  setOperationCenterOpen(open: boolean): void
  toggleOperationCenter(): void
  setMobileNavOpen(open: boolean): void
}

export const useShellUiStore = create<ShellUiState>()((set) => ({
  operationCenterOpen: false,
  mobileNavOpen: false,
  setOperationCenterOpen: (operationCenterOpen) => set({ operationCenterOpen }),
  toggleOperationCenter: () => set((s) => ({ operationCenterOpen: !s.operationCenterOpen })),
  setMobileNavOpen: (mobileNavOpen) => set({ mobileNavOpen }),
}))
