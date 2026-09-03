/**
 * Conversation UI store — per-conversation presentation prefs, persisted
 * under `stateport.conversation.v1`. Presentation only: pinned message ids,
 * details-panel open state, and the last-seen message (drives the unread
 * divider). Domain data never lives here.
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export const CONVERSATION_UI_STORAGE_KEY = 'stateport.conversation.v1'

interface ConversationUiState {
  /** conversationKey → pinned message ids (order = pin order). */
  pinned: Record<string, string[]>
  /** conversationKey → details panel open. */
  detailsOpen: Record<string, boolean>
  /** conversationKey → id of the last message the user has seen. */
  lastSeen: Record<string, string>

  togglePin(key: string, messageId: string): void
  isPinned(key: string, messageId: string): boolean
  setDetailsOpen(key: string, open: boolean): void
  setLastSeen(key: string, messageId: string): void
}

export const useConversationUiStore = create<ConversationUiState>()(
  persist(
    (set, get) => ({
      pinned: {},
      detailsOpen: {},
      lastSeen: {},

      togglePin: (key, messageId) =>
        set((s) => {
          const list = s.pinned[key] ?? []
          const next = list.includes(messageId) ? list.filter((id) => id !== messageId) : [...list, messageId]
          return { pinned: { ...s.pinned, [key]: next } }
        }),
      isPinned: (key, messageId) => (get().pinned[key] ?? []).includes(messageId),
      setDetailsOpen: (key, open) => set((s) => ({ detailsOpen: { ...s.detailsOpen, [key]: open } })),
      setLastSeen: (key, messageId) => set((s) => ({ lastSeen: { ...s.lastSeen, [key]: messageId } })),
    }),
    {
      name: CONVERSATION_UI_STORAGE_KEY,
      version: 1,
    },
  ),
)
