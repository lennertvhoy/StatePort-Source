// Regression: sending while a resumed (in-flight) stream is active must keep the
// streaming chrome bound to the fresh stream (caught by e2e conversation.spec).
import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { resetClientForTests, resetMockState, useScenarioStore } from '@/client'
import { ConversationSurface } from '@/features/conversation/ConversationSurface'

function renderSurface(instanceId: string) {
  return render(
    <MemoryRouter>
      <ConversationSurface instanceId={instanceId} />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  resetClientForTests()
})

afterEach(() => {
  cleanup()
  useScenarioStore.getState().setActive(null)
  resetMockState()
})

describe('stream race: send during resumed stream', () => {
  it('stops both the active response and a replacement still awaiting the adapter', async () => {
    const user = userEvent.setup()
    useScenarioStore.getState().setActive('conversation_streaming')
    renderSurface('ins_cto_pilot')
    // resume attaches
    expect(await screen.findByTestId('streaming-indicator', undefined, { timeout: 6000 })).toBeTruthy()
    // fresh send while resume is in flight
    const input = screen.getByTestId('composer-input')
    await user.click(input)
    await user.type(input, 'stream a long reply please')
    await user.keyboard('{Enter}')
    // Stop immediately: the replacement send may still be waiting on mock
    // latency while the seeded resumed stream owns the visible control.
    await user.click(screen.getByTestId('stop-stream'))

    await waitFor(() => expect(screen.queryByTestId('streaming-indicator')).toBeNull(), { timeout: 6000 })
    await waitFor(() => {
      const assistants = screen.getAllByTestId('message-assistant')
      expect(assistants[assistants.length - 1]?.getAttribute('data-state')).toBe('stopped')
    }, { timeout: 6000 })
  }, 20000)
})
