/**
 * useReceiptListKeyboard — the receipts.md keyboard scope, shared by the
 * table and timeline views:
 *
 *   ↑/↓ navigate rows · Enter open detail · Ctrl/Cmd+C copy receipt ID
 *
 * Rows use roving tabindex: one row is tabbable, arrows move it. `f` (focus
 * search) and `v` (toggle view) live in ReceiptsTool where the controls are.
 */
import { useCallback, useRef, useState } from 'react'
import type { KeyboardEvent as ReactKeyboardEvent } from 'react'

import type { Receipt } from '@/client'
import { isEditableTarget } from '@/shell/platform'

export interface ReceiptListKeyboard {
  /** Callback ref that binds the scroll container (keeps ref writes out of render). */
  bindContainer: (el: HTMLDivElement | null) => void
  activeIndex: number
  setActiveIndex: (index: number) => void
  onKeyDown: (e: ReactKeyboardEvent<HTMLElement>) => void
  rowTabIndex: (index: number) => 0 | -1
}

export function useReceiptListKeyboard(
  receipts: readonly Receipt[],
  handlers: {
    onOpen: (receipt: Receipt) => void
    onCopyId: (receipt: Receipt) => void
  },
): ReceiptListKeyboard {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const [activeIndex, setActiveIndex] = useState(0)

  // Keep the active row inside the loaded set (filters shrink the list) —
  // adjusted during render so no effect setState is needed.
  const [prevLength, setPrevLength] = useState(receipts.length)
  if (prevLength !== receipts.length) {
    setPrevLength(receipts.length)
    setActiveIndex((i) => Math.min(i, Math.max(0, receipts.length - 1)))
  }

  const focusRow = useCallback((index: number) => {
    setActiveIndex(index)
    const el = containerRef.current?.querySelector<HTMLElement>(`[data-receipt-row="${index}"]`)
    el?.focus()
  }, [])

  const onKeyDown = useCallback(
    (e: ReactKeyboardEvent<HTMLElement>) => {
      if (isEditableTarget(e.target)) return
      if (receipts.length === 0) return

      if (e.key === 'ArrowDown') {
        e.preventDefault()
        focusRow(Math.min(activeIndex + 1, receipts.length - 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        focusRow(Math.max(activeIndex - 1, 0))
      } else if (e.key === 'Enter') {
        const receipt = receipts[activeIndex]
        if (receipt) {
          e.preventDefault()
          handlers.onOpen(receipt)
        }
      } else if (e.key.toLowerCase() === 'c' && (e.metaKey || e.ctrlKey)) {
        const receipt = receipts[activeIndex]
        if (receipt) {
          // Don't steal copies from a text selection.
          const selection = window.getSelection()
          if (selection && selection.toString()) return
          e.preventDefault()
          handlers.onCopyId(receipt)
        }
      }
    },
    [activeIndex, receipts, focusRow, handlers],
  )

  const bindContainer = useCallback((el: HTMLDivElement | null) => {
    containerRef.current = el
  }, [])

  return {
    bindContainer,
    activeIndex,
    setActiveIndex,
    onKeyDown,
    rowTabIndex: (index) => (index === activeIndex ? 0 : -1),
  }
}
