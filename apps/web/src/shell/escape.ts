/**
 * Escape layer stack — deterministic Escape handling across overlays.
 *
 * Radix dialogs/menus handle their own Escape; this stack covers non-Radix
 * surfaces (Scenario Lab panel, workbench focus mode, mobile sheets) and any
 * feature-agent overlay. The topmost (highest priority, latest registered)
 * layer consumes the key. Focus mode registers at priority -100 so it is
 * always the last thing Escape reaches.
 */
import { useEffect, useRef } from 'react'

interface EscapeLayer {
  id: string
  priority: number
  onEscape: () => void
}

let stack: EscapeLayer[] = []
let seq = 0

export function pushEscapeLayer(layer: Omit<EscapeLayer, 'id'> & { id?: string }): () => void {
  const entry: EscapeLayer = { id: layer.id ?? `escape_${++seq}`, priority: layer.priority, onEscape: layer.onEscape }
  stack = [...stack.filter((l) => l.id !== entry.id), entry].sort((a, b) => a.priority - b.priority)
  return () => {
    stack = stack.filter((l) => l.id !== entry.id)
  }
}

/** Run the topmost layer's handler. Returns true when a layer consumed the key. */
export function escapeTopLayer(): boolean {
  const top = stack[stack.length - 1]
  if (!top) return false
  top.onEscape()
  return true
}

/** Register `onEscape` while `active` (callback identity is always fresh). */
export function useEscapeLayer(active: boolean, onEscape: () => void, opts?: { priority?: number; id?: string }): void {
  const ref = useRef(onEscape)
  // Latest-handler ref updates in an effect, never during render.
  useEffect(() => {
    ref.current = onEscape
  })
  const priority = opts?.priority ?? 0
  const id = opts?.id
  useEffect(() => {
    if (!active) return
    return pushEscapeLayer({ id, priority, onEscape: () => ref.current() })
  }, [active, priority, id])
}
