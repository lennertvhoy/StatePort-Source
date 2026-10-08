// A failed assistant response shows WHY it failed (the service's fixed cause
// sentence), not only "Response interrupted".
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { resetClientForTests, resetMockState, useScenarioStore } from '@/client'
import type { ConversationMessage } from '@/client'
import { ConversationSurface } from '@/features/conversation/ConversationSurface'
import { MessageRow } from '@/features/conversation/MessageRow'

beforeEach(() => {
  resetClientForTests()
})

afterEach(() => {
  cleanup()
  useScenarioStore.getState().setActive(null)
  resetMockState()
})

const FAILED: ConversationMessage = {
  id: 'assistant_pending:msg_1',
  conversationId: 'conv_1',
  role: 'assistant',
  content: '',
  createdAt: '2026-10-02T09:00:00.000Z',
  state: 'failed',
  failureReason:
    "The provider's usage limit has been reached, so it refused the request. Wait for the limit to reset, or choose another model or plan in Coding provider settings, then retry.",
  attachments: [],
  contextChips: [],
  toolEvents: [],
}

const noop = () => {}
const ROW = {
  instanceId: 'ins_1',
  pinned: false,
  onTogglePin: noop,
  onQuote: noop,
  onRetryResponse: noop,
  onResend: noop,
  onEdit: noop,
  onDiscard: noop,
}

describe('failed assistant response', () => {
  it('names the cause next to the retry action', () => {
    render(
      <MemoryRouter>
        <MessageRow {...ROW} message={FAILED} />
      </MemoryRouter>,
    )
    const alert = screen.getByRole('alert')
    expect(within(alert).getByText('Response interrupted')).toBeTruthy()
    expect(within(alert).getByTestId(`failure-reason-${FAILED.id}`).textContent).toContain('usage limit')
    expect(within(alert).getByTestId(`retry-response-${FAILED.id}`)).toBeTruthy()
  })

  it('shows nothing extra when the service gave no cause', () => {
    render(
      <MemoryRouter>
        <MessageRow {...ROW} message={{ ...FAILED, failureReason: undefined }} />
      </MemoryRouter>,
    )
    expect(screen.queryByTestId(`failure-reason-${FAILED.id}`)).toBeNull()
  })

  it('carries the streamed error cause onto the failed message', async () => {
    const user = userEvent.setup()
    useScenarioStore.getState().setActive('conversation_failed')
    render(
      <MemoryRouter>
        <ConversationSurface instanceId="ins_cto_pilot" />
      </MemoryRouter>,
    )
    const input = await screen.findByTestId('composer-input')
    await user.click(input)
    await user.type(input, 'please answer with a reply that is long enough to fail midway through')
    await user.keyboard('{Enter}')
    await waitFor(
      () => {
        const assistants = screen.getAllByTestId('message-assistant')
        const last = assistants[assistants.length - 1]
        expect(last?.getAttribute('data-state')).toBe('failed')
        expect(last?.querySelector('[data-testid^="failure-reason-"]')?.textContent ?? '').toContain(
          'The response failed before completion',
        )
      },
      { timeout: 8000 },
    )
  }, 20000)
})
