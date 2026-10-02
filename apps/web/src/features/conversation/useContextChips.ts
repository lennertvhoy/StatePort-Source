/**
 * useContextChips — the explicit, visible context model (conversation.md:
 * "context never silently includes unselected data").
 *
 * Starts from the configured defaults (application + summary), then absorbs
 * inbound bridge payloads (file/selection/terminal/receipt/plan/approval) on
 * mount and window focus as removable chips. After a send, the set returns to
 * defaults — sent chips are recorded on the message itself.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'

import type { ContextChip, ContextChipKind } from '@/client'
import { useBridgeStore } from '@/features/bridge/bridgeStore'

import { bridgePayloadToChip, buildDefaultChips } from './conversationModel'

const INBOUND_KINDS = ['file-selection', 'file', 'terminal-selection', 'receipt', 'plan', 'approval'] as const

export interface ContextChipsState {
  chips: ContextChip[]
  /** Chips beyond the configured defaults (drives row visibility). */
  hasNonDefault: boolean
  removeChip(id: string): void
  /** Reset to defaults after a successful send. */
  resetChips(): void
  /** Drain pending inbound bridge payloads into chips (also on focus). */
  consumeBridge(): void
}

export function useContextChips(
  instanceId: string,
  instanceName: string,
  defaultKinds: ContextChipKind[],
): ContextChipsState {
  const defaults = useMemo(
    () => buildDefaultChips(instanceName, defaultKinds),
    [instanceName, defaultKinds],
  )
  const [extras, setExtras] = useState<ContextChip[]>([])
  const [removedDefaults, setRemovedDefaults] = useState<string[]>([])

  // Fresh conversation → fresh context set (render-adjust, no effect cascade).
  const [prevInstance, setPrevInstance] = useState(instanceId)
  if (prevInstance !== instanceId) {
    setPrevInstance(instanceId)
    setExtras([])
    setRemovedDefaults([])
  }

  const consumeBridge = useCallback(() => {
    const payloads = useBridgeStore.getState().consume(instanceId, [...INBOUND_KINDS])
    if (payloads.length === 0) return
    const chips = payloads
      .map(bridgePayloadToChip)
      .filter((c): c is ContextChip => c !== null)
    if (chips.length > 0) setExtras((prev) => dedupe([...prev, ...chips]))
  }, [instanceId])

  useEffect(() => {
    // Initial drain deferred out of the effect body; then live-subscribe so
    // payloads sent while the surface is open become chips immediately.
    const timer = window.setTimeout(consumeBridge, 0)
    window.addEventListener('focus', consumeBridge)
    const unsubscribe = useBridgeStore.subscribe((state, prev) => {
      if (state.pending !== prev.pending) consumeBridge()
    })
    return () => {
      window.clearTimeout(timer)
      window.removeEventListener('focus', consumeBridge)
      unsubscribe()
    }
  }, [consumeBridge])

  const removeChip = useCallback(
    (id: string) => {
      if (defaults.some((c) => c.id === id)) setRemovedDefaults((prev) => [...prev, id])
      setExtras((prev) => prev.filter((c) => c.id !== id))
    },
    [defaults],
  )

  const resetChips = useCallback(() => {
    setExtras([])
    setRemovedDefaults([])
  }, [])

  const chips = useMemo(
    () => [...defaults.filter((c) => !removedDefaults.includes(c.id)), ...extras],
    [defaults, extras, removedDefaults],
  )

  return useMemo(
    () => ({ chips, hasNonDefault: extras.length > 0, removeChip, resetChips, consumeBridge }),
    [chips, extras.length, removeChip, resetChips, consumeBridge],
  )
}

function dedupe(chips: ContextChip[]): ContextChip[] {
  const seen = new Set<string>()
  return chips.filter((c) => {
    const key = `${c.kind}:${c.refId ?? c.label}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}
