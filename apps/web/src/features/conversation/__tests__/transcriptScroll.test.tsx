/**
 * Transcript follow-latest regression coverage.
 *
 * Wheel intent must pause streaming auto-follow synchronously. The browser
 * delivers `scroll` after `wheel`, so waiting for onScroll leaves a race where
 * a stream delta can yank the reader back to the bottom first.
 */
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import type { ConversationMessage, ConversationSettings } from '@/client'

import { Transcript } from '../Transcript'

const settings: ConversationSettings = {
  enterSends: true,
  draftPersistence: true,
  showMessageTimestamps: true,
  compactMessageLayout: false,
  autoScroll: 'when_at_bottom',
  confirmBeforeClearingHistory: true,
  defaultContext: ['application'],
  showDeliveryDetails: true,
  toolEventsExpanded: false,
  soundOnResponseFinished: false,
}

function message(content: string): ConversationMessage {
  return {
    id: 'msg_stream',
    conversationId: 'conv_1',
    role: 'assistant',
    content,
    createdAt: '2026-07-18T20:00:00Z',
    state: 'streaming',
    attachments: [],
    contextChips: [],
    toolEvents: [],
  }
}

describe('Transcript streaming scroll anchoring', () => {
  it('honors upward wheel intent before the delayed scroll event arrives', () => {
    const props = {
      instanceId: 'ins_1',
      pinnedIds: [],
      lastSeenId: null,
      unreadActive: false,
      settings,
      currentMatchId: null,
      onTogglePin: vi.fn(),
      onQuote: vi.fn(),
      onRetryResponse: vi.fn(),
      onResend: vi.fn(),
      onEdit: vi.fn(),
      onDiscard: vi.fn(),
      onAtBottom: vi.fn(),
    }
    const view = render(
      <MemoryRouter>
        <Transcript {...props} messages={[message('partial')]} />
      </MemoryRouter>,
    )
    const transcript = screen.getByTestId('transcript')
    let scrollTop = 50
    Object.defineProperties(transcript, {
      scrollHeight: { configurable: true, get: () => 500 },
      clientHeight: { configurable: true, get: () => 450 },
      scrollTop: {
        configurable: true,
        get: () => scrollTop,
        set: (value: number) => {
          scrollTop = value
        },
      },
    })

    fireEvent.wheel(transcript, { deltaY: -4000 })
    scrollTop = 0
    // Deliberately rerender before `scroll`: this is the browser race.
    view.rerender(
      <MemoryRouter>
        <Transcript {...props} messages={[message('partial response grew')]} />
      </MemoryRouter>,
    )

    expect(scrollTop).toBe(0)
    expect(screen.getByTestId('jump-to-latest')).toBeTruthy()
  })
})
