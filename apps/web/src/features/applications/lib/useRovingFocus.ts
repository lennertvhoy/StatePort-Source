/**
 * useRovingFocus — roving tabindex for the dashboard row lists
 * (applications.md Keyboard: "Arrow keys move through row lists (roving
 * tabindex). Enter opens, Space context menu, P pins focused row").
 *
 * The list container gets `listProps`; each row gets `rowProps(index)` with a
 * tabIndex of 0 only for the active row. Row-level keys (Enter/Space/P) are
 * delegated to callbacks so the DOM stays honest (one focus stop per row,
 * real buttons inside).
 */
import { useCallback, useRef, useState } from 'react'
import type { KeyboardEvent as ReactKeyboardEvent } from 'react'

export interface RovingRowHandlers {
  onOpen: () => void
  onMenu: () => void
  onTogglePin?: () => void
  /** Pinned-group keyboard reorder (Alt+ArrowUp/Down). */
  onMoveUp?: () => void
  onMoveDown?: () => void
}

export function useRovingFocus(count: number) {
  const [activeIndex, setActiveIndex] = useState(0)
  const rowRefs = useRef<Array<HTMLElement | null>>([])

  const move = useCallback(
    (next: number) => {
      const clamped = Math.max(0, Math.min(next, count - 1))
      setActiveIndex(clamped)
      rowRefs.current[clamped]?.focus()
    },
    [count],
  )

  const onListKeyDown = useCallback(
    (e: ReactKeyboardEvent) => {
      if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        move(activeIndex + 1)
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        move(activeIndex - 1)
      } else if (e.key === 'Home') {
        e.preventDefault()
        move(0)
      } else if (e.key === 'End') {
        e.preventDefault()
        move(count - 1)
      }
    },
    [activeIndex, count, move],
  )

  const rowProps = useCallback(
    (index: number, handlers: RovingRowHandlers) => ({
      tabIndex: index === activeIndex ? 0 : -1,
      'aria-keyshortcuts': handlers.onMoveUp
        ? 'Enter Space p Alt+ArrowUp Alt+ArrowDown'
        : 'Enter Space p',
      ref: (el: HTMLElement | null) => {
        rowRefs.current[index] = el
      },
      onFocus: () => setActiveIndex(index),
      onKeyDown: (e: ReactKeyboardEvent<HTMLElement>) => {
        if (e.altKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
          e.preventDefault()
          if (e.key === 'ArrowUp') handlers.onMoveUp?.()
          else handlers.onMoveDown?.()
          return
        }
        if (e.altKey || e.ctrlKey || e.metaKey) return
        if (e.key === 'Enter') {
          e.preventDefault()
          handlers.onOpen()
        } else if (e.key === ' ') {
          e.preventDefault()
          handlers.onMenu()
        } else if (e.key === 'p' || e.key === 'P') {
          e.preventDefault()
          handlers.onTogglePin?.()
        }
      },
    }),
    [activeIndex],
  )

  return { listProps: { onKeyDown: onListKeyDown }, rowProps }
}
