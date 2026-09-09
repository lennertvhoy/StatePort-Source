/**
 * Session store — ephemeral shell state (not persisted).
 *
 * Local-service status, build info, the active dev scenario (mirrored from
 * the client boundary's scenario store), operation-center records, and
 * toasts. Domain data is fetched through the client; this store only holds
 * what the shell needs between fetches.
 */
import { create } from 'zustand'

import type { BuildInfo, LocalServiceStatus, OperationRecord, ScenarioId } from '@/client'
import { useScenarioStore } from '@/client'

export interface Toast {
  id: string
  kind: 'info' | 'success' | 'error'
  title: string
  body?: string
  createdAt: number
  /** Optional click-through. */
  route?: string
}

interface SessionState {
  serviceStatus: LocalServiceStatus | null
  buildInfo: BuildInfo | null
  /** Dev mirror of the scenario store in the client boundary. */
  activeScenario: ScenarioId | null
  scenarioLabOpen: boolean
  operations: OperationRecord[]
  /** Monotonic wake signal for the shell's operations projection poller. */
  operationsRefreshGeneration: number
  /** Number of in-flight mutations whose operation state may not be projected yet. */
  operationsMutationCount: number
  /** Set when the operations poll fails — the mirrored `operations` are stale. */
  operationsError: string | null
  toasts: Toast[]

  setServiceStatus(status: LocalServiceStatus | null): void
  setBuildInfo(info: BuildInfo | null): void
  setActiveScenario(id: ScenarioId | null): void
  setScenarioLabOpen(open: boolean): void
  setOperations(records: OperationRecord[]): void
  setOperationsError(error: string | null): void
  requestOperationsRefresh(): void
  beginOperationsMutation(): () => void
  upsertOperation(record: OperationRecord): void
  pushToast(toast: Omit<Toast, 'id' | 'createdAt'>): string
  dismissToast(id: string): void
  clearToasts(): void
}

let toastSeq = 0

export const useSessionStore = create<SessionState>()((set) => ({
  serviceStatus: null,
  buildInfo: null,
  activeScenario: useScenarioStore.getState().active,
  scenarioLabOpen: useScenarioStore.getState().labOpen,
  operations: [],
  operationsRefreshGeneration: 0,
  operationsMutationCount: 0,
  operationsError: null,
  toasts: [],

  setServiceStatus: (serviceStatus) => set({ serviceStatus }),
  setBuildInfo: (buildInfo) => set({ buildInfo }),
  setActiveScenario: (activeScenario) => {
    useScenarioStore.getState().setActive(activeScenario)
    set({ activeScenario })
  },
  setScenarioLabOpen: (scenarioLabOpen) => {
    useScenarioStore.getState().setLabOpen(scenarioLabOpen)
    set({ scenarioLabOpen })
  },
  setOperations: (operations) => set({ operations }),
  setOperationsError: (operationsError) => set({ operationsError }),
  requestOperationsRefresh: () => set((s) => ({ operationsRefreshGeneration: s.operationsRefreshGeneration + 1 })),
  beginOperationsMutation: () => {
    set((s) => ({
      operationsRefreshGeneration: s.operationsRefreshGeneration + 1,
      operationsMutationCount: s.operationsMutationCount + 1,
    }))
    let released = false
    return () => {
      if (released) return
      released = true
      set((s) => ({
        operationsRefreshGeneration: s.operationsRefreshGeneration + 1,
        operationsMutationCount: Math.max(0, s.operationsMutationCount - 1),
      }))
    }
  },
  upsertOperation: (record) =>
    set((s) => {
      const idx = s.operations.findIndex((o) => o.id === record.id)
      const operations =
        idx === -1
          ? [record, ...s.operations]
          : s.operations.map((o) => (o.id === record.id ? record : o))
      // Local operation actions (for example Operation Center cancellation)
      // already update the visible row; also wake the projection so the next
      // server read confirms the durable state promptly.
      return { operations, operationsRefreshGeneration: s.operationsRefreshGeneration + 1 }
    }),
  pushToast: (toast) => {
    const id = `toast_${++toastSeq}`
    set((s) => ({ toasts: [...s.toasts, { ...toast, id, createdAt: Date.now() }] }))
    return id
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
  clearToasts: () => set({ toasts: [] }),
}))

// Keep the session mirror in sync when the scenario changes from the client
// side (e.g. `?scenario=` on load, Scenario Lab panel).
useScenarioStore.subscribe((state) => {
  useSessionStore.setState({ activeScenario: state.active, scenarioLabOpen: state.labOpen })
})
