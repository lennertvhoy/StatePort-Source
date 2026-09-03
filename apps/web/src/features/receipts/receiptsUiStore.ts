/**
 * Receipts UI store — user-saved filters for the nav panel (receipts.md:
 * "saved filters"). The *current* filter lives in the workspace store (per
 * instance); this holds only named, user-pinned filter snapshots. Persisted
 * locally; nothing here is domain data.
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

import type { ReceiptsViewFilter } from './receiptsModel'

export interface SavedReceiptFilter {
  id: string
  name: string
  filter: ReceiptsViewFilter
}

interface ReceiptsUiState {
  /** instanceId → saved filters (creation order). */
  saved: Record<string, SavedReceiptFilter[]>
  saveFilter: (instanceId: string, name: string, filter: ReceiptsViewFilter) => void
  removeFilter: (instanceId: string, savedId: string) => void
}

let seq = 0

export const useReceiptsUiStore = create<ReceiptsUiState>()(
  persist(
    (set) => ({
      saved: {},
      saveFilter: (instanceId, name, filter) =>
        set((s) => {
          const trimmed = name.trim()
          if (!trimmed) return s
          const entry: SavedReceiptFilter = {
            id: `srf_${Date.now().toString(36)}_${++seq}`,
            name: trimmed,
            filter: { ...filter },
          }
          return { saved: { ...s.saved, [instanceId]: [...(s.saved[instanceId] ?? []), entry] } }
        }),
      removeFilter: (instanceId, savedId) =>
        set((s) => ({
          saved: {
            ...s.saved,
            [instanceId]: (s.saved[instanceId] ?? []).filter((f) => f.id !== savedId),
          },
        })),
    }),
    { name: 'stateport.receipts-ui.v1', version: 1 },
  ),
)
