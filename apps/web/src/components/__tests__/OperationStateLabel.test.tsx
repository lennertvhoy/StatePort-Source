/**
 * OperationStateLabel elapsed clock — N live rows share one 1 s interval that
 * starts with the first live ticker and clears with the last (the TimeAgo
 * minute-clock pattern). Terminal states start no clock.
 */
import { act, cleanup, render } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import { OperationStateLabel } from '../OperationStateLabel'

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-09-12T12:00:00.000Z'))
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

it('shares one 1 s clock across live labels and clears it with the last', () => {
  const interval = vi.spyOn(window, 'setInterval')
  const clear = vi.spyOn(window, 'clearInterval')
  const startedAt = new Date(Date.now() - 5_000).toISOString()

  const first = render(<OperationStateLabel state="running" startedAt={startedAt} />)
  const second = render(<OperationStateLabel state="running" startedAt={startedAt} />)
  expect(interval).toHaveBeenCalledTimes(1)
  expect(first.container.textContent).toContain('0:05')
  expect(second.container.textContent).toContain('0:05')

  act(() => vi.advanceTimersByTime(1_000))
  expect(first.container.textContent).toContain('0:06')
  expect(second.container.textContent).toContain('0:06')

  first.unmount()
  expect(clear).not.toHaveBeenCalled()
  second.unmount()
  expect(clear).toHaveBeenCalledTimes(1)
})

it('does not start the clock for terminal states', () => {
  const interval = vi.spyOn(window, 'setInterval')
  const view = render(
    <OperationStateLabel state="completed" startedAt={new Date(Date.now() - 5_000).toISOString()} />,
  )
  expect(interval).not.toHaveBeenCalled()
  expect(view.container.textContent).not.toContain('0:05')
})
