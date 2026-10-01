/**
 * Focus restoration for programmatically opened dialogs (design.md §16).
 *
 * Radix Dialog/AlertDialog restores focus to its trigger element on close,
 * but dialogs opened from state (command palette, save preview, confirms,
 * drawers) have no DialogTrigger, so Radix prevents the FocusScope's own
 * restore and focus falls to <body>. While such a dialog is closed we track
 * the focused element via focusin; the content's onCloseAutoFocus then
 * restores it. The shared ui/dialog + ui/alert-dialog wrappers wire this up
 * through LastFocusedContext so every dialog surface gets it centrally.
 */
import { createContext, useCallback, useContext, useEffect, useRef } from 'react'
import type { RefObject } from 'react'

export type LastFocusedRef = RefObject<HTMLElement | null>

export const LastFocusedContext = createContext<LastFocusedRef>({ current: null })

function focusLastTracked(lastFocusedRef: LastFocusedRef, event: Event): void {
  event.preventDefault()
  const el = lastFocusedRef.current
  if (el && el.isConnected) el.focus()
}

/**
 * While `open` is false, remember the element that holds focus. The last
 * element recorded before the dialog opens is the one focus returns to.
 */
export function useTrackLastFocused(open: boolean): LastFocusedRef {
  const lastFocusedRef = useRef<HTMLElement | null>(null)
  useEffect(() => {
    if (open) return
    const track = (event: FocusEvent) => {
      if (event.target instanceof HTMLElement) lastFocusedRef.current = event.target
    }
    document.addEventListener('focusin', track)
    return () => document.removeEventListener('focusin', track)
  }, [open])
  return lastFocusedRef
}

/** Consume the surrounding dialog root's tracked element (used by the shared wrappers). */
export function useRestoreFocusOnClose(): (event: Event) => void {
  const lastFocusedRef = useContext(LastFocusedContext)
  return useCallback((event: Event) => focusLastTracked(lastFocusedRef, event), [lastFocusedRef])
}

/**
 * Compose a user-supplied onCloseAutoFocus with focus restoration: the user
 * handler runs first and may opt out by calling event.preventDefault().
 */
export function composeCloseAutoFocus(
  userHandler: ((event: Event) => void) | undefined,
  restoreFocus: (event: Event) => void,
): (event: Event) => void {
  return (event) => {
    userHandler?.(event)
    if (!event.defaultPrevented) restoreFocus(event)
  }
}

/**
 * Standalone variant for surfaces that render Radix primitives directly
 * (e.g. Drawer) instead of the shared dialog wrappers.
 */
export function useRestoreFocus(open: boolean): (event: Event) => void {
  const lastFocusedRef = useTrackLastFocused(open)
  return useCallback((event: Event) => focusLastTracked(lastFocusedRef, event), [lastFocusedRef])
}
