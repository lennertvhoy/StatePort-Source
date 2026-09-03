/**
 * Cross-tool bridge — the ONLY supported way for one surface to hand
 * something to another (e.g. editor selection → Conversation, assistant
 * command draft → Terminal). Every bridge preserves explicit user control:
 * payloads are proposals the receiving surface renders for review; nothing
 * executes silently. Owned by the orchestrator — feature agents consume
 * this file but must not modify it.
 */
import { create } from 'zustand'

export type BridgePayload =
  /** Selected editor text or a whole file sent to Conversation as a context chip. */
  | { kind: 'file-selection'; instanceId: string; path: string; text: string; lineStart?: number; lineEnd?: number }
  | { kind: 'file'; instanceId: string; path: string }
  /** Selected terminal output sent to Conversation as a context chip. */
  | { kind: 'terminal-selection'; instanceId: string; sessionId: string; text: string }
  /** Open Conversation with a receipt attached as context (e.g. "summarize this receipt"). */
  | { kind: 'receipt'; instanceId: string; receiptId: string }
  /** Open Conversation with a deployment plan attached (e.g. "review this plan"). */
  | { kind: 'plan'; instanceId: string; planId: string }
  /** Open Conversation with an approval attached. */
  | { kind: 'approval'; instanceId: string; approvalId: string }
  /**
   * Assistant-proposed terminal command. Terminal inserts it at the prompt
   * for explicit review — it must NEVER be executed automatically.
   */
  | { kind: 'command-draft'; instanceId: string; command: string }
  /**
   * Assistant-proposed file change. Files opens it in the governed
   * diff-preview flow — never a silent write.
   */
  | { kind: 'patch-draft'; instanceId: string; path: string; proposed: string }

export type BridgePayloadKind = BridgePayload['kind']

interface BridgeState {
  pending: BridgePayload[]
  /** Enqueue a payload for the owning surface of `instanceId` to consume. */
  send: (payload: BridgePayload) => void
  /**
   * Take (and remove) all pending payloads for an instance, optionally
   * filtered by kind. Receiving surfaces call this on mount / focus.
   */
  consume: (instanceId: string, kinds?: BridgePayloadKind[]) => BridgePayload[]
  /** Peek without removing (for badge indicators). */
  peek: (instanceId: string, kinds?: BridgePayloadKind[]) => BridgePayload[]
  clear: (instanceId?: string) => void
}

export const useBridgeStore = create<BridgeState>()((set, get) => ({
  pending: [],
  send: (payload) => set((s) => ({ pending: [...s.pending, payload] })),
  consume: (instanceId, kinds) => {
    const mine = get().pending.filter(
      (p) => p.instanceId === instanceId && (!kinds || kinds.includes(p.kind)),
    )
    if (mine.length === 0) return []
    set((s) => ({ pending: s.pending.filter((p) => !mine.includes(p)) }))
    return mine
  },
  peek: (instanceId, kinds) =>
    get().pending.filter(
      (p) => p.instanceId === instanceId && (!kinds || kinds.includes(p.kind)),
    ),
  clear: (instanceId) =>
    set((s) => ({
      pending: instanceId ? s.pending.filter((p) => p.instanceId !== instanceId) : [],
    })),
}))

/** Convenience: send a payload to another surface. */
export function sendToBridge(payload: BridgePayload): void {
  useBridgeStore.getState().send(payload)
}
