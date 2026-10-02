/**
 * Focus restoration (design.md §16) — programmatically opened dialogs return
 * focus to the element focused before they opened instead of dropping it on
 * <body>.
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, describe, expect, it } from 'vitest'

import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'

afterEach(cleanup)

function Harness() {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button type="button" data-testid="trigger" onClick={() => setOpen(true)}>
        Open
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent aria-label="Test dialog">
          <DialogTitle>Test dialog</DialogTitle>
          <input aria-label="inside" />
        </DialogContent>
      </Dialog>
    </>
  )
}

describe('dialog focus restoration', () => {
  it('returns focus to the pre-open element when the dialog closes', async () => {
    render(<Harness />)
    const trigger = screen.getByTestId('trigger')
    // Real clicks focus the button; fireEvent.click does not, so focus first.
    trigger.focus()
    fireEvent.click(trigger)
    expect(document.activeElement).not.toBe(trigger)

    // Dialog opened; focus moved inside.
    const input = await screen.findByLabelText('inside')
    input.focus()
    expect(document.activeElement).toBe(input)

    // Escape closes → focus returns to the trigger, not <body>. Radix runs
    // the close-autofocus as a deferred effect, so await the assertion.
    fireEvent.keyDown(document.activeElement as Element, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByLabelText('inside')).toBeNull())
    await waitFor(() => expect(document.activeElement).toBe(trigger))
  })

  it('does not throw when the pre-open element is gone', async () => {
    function Vanishing() {
      const [open, setOpen] = useState(false)
      const [gone, setGone] = useState(false)
      return (
        <>
          {!gone ? (
            <button
              type="button"
              data-testid="vanishing"
              onClick={() => {
                setGone(true)
                setOpen(true)
              }}
            >
              Open
            </button>
          ) : null}
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogContent aria-label="Vanishing dialog">
              <DialogTitle>Vanishing dialog</DialogTitle>
            </DialogContent>
          </Dialog>
        </>
      )
    }
    render(<Vanishing />)
    fireEvent.click(screen.getByTestId('vanishing'))
    fireEvent.keyDown(document.activeElement as Element, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(document.activeElement).toBe(document.body)
  })
})
