import { cleanup, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import type { Conversation, ConversationChannel } from '@/client'
import { getClient, resetClientForTests } from '@/client'
import { mapConversation } from '@/client/http/mappers'
import { DetailsPanel } from '../DetailsPanel'
import { ThreadHeader } from '../ThreadHeader'

function mapped(channel: ConversationChannel, bindings: unknown): Conversation {
  return mapConversation({
    formatVersion: 'stateport.conversation-presentation/v1',
    applicationBinding: { applicationId: 'app-one', instanceId: 'ins-one' },
    thread: { conversationId: 'conversation-one', applicationId: 'app-one', instanceId: 'ins-one', channel,
      createdAt: '2026-09-06T00:00:00Z', updatedAt: '2026-09-06T00:00:00Z' },
    channelBindings: bindings, messages: [],
  }, 'ins-one')
}
function mount(conversation: Conversation | null) {
  render(<MemoryRouter>
    <ThreadHeader title="Conversation" conversation={conversation} messageCount={0} streaming={false}
      onStop={() => undefined} searchOpen={false} onToggleSearch={() => undefined} onExport={() => undefined}
      detailsOpen={true} onToggleDetails={() => undefined} onOpenClear={() => undefined}
      focusMode={false} onToggleFocusMode={() => undefined} />
    <DetailsPanel instanceId="ins-one" conversation={conversation} messages={[]} pinnedIds={[]} onJumpToMessage={() => undefined} />
  </MemoryRouter>)
}
function row(label: string) {
  return within(screen.getByTestId('conversation-details')).getByText(label, { exact: true }).parentElement!
}
beforeEach(() => {
  resetClientForTests()
  vi.spyOn(getClient().approvals, 'list').mockResolvedValue([])
  vi.spyOn(getClient().receipts, 'list').mockResolvedValue([])
})
afterEach(() => { cleanup(); vi.restoreAllMocks(); resetClientForTests() })

for (const channel of ['web', 'telegram'] as const) {
  it.each([
    ['delivered', 'Delivered', 'success'],
    ['pending', 'Pending', 'attention'],
    ['failed', 'Delivery failed', 'danger'],
    ['not_configured', 'Not configured', 'neutral'],
  ] as const)(`${channel} explicit %s renders only matching delivery, never connectivity`, (state, label, semantic) => {
    mount(mapped(channel, [{ channel, state }]))
    const name = channel === 'web' ? 'Web' : 'Telegram'
    const other = channel === 'web' ? 'Telegram' : 'Web'
    expect(row(name).textContent).toContain(`Delivery · ${label}`)
    expect(within(row(name)).getByTestId('status-dot').getAttribute('data-state')).toBe(semantic)
    expect(row(other).textContent).toContain('Status unavailable')
    expect(within(row(other)).getByTestId('status-dot').getAttribute('data-state')).toBe('neutral')
    expect(screen.getByTestId('thread-header').textContent).toContain(`${name} · ${label}`)
    expect(screen.getByTestId('conversation-details').textContent).not.toContain('Connected')
    expect(screen.getByRole('link', { name: 'Privacy settings' }).getAttribute('href')).toBe('/settings/privacy')
    expect(screen.getByTestId('thread-header').querySelectorAll('button').length).toBeGreaterThan(0)
  })
  it.each([
    ['absent', undefined], ['empty', []],
    ['active is not delivery', [{ channel, state: 'active' }]],
    ['conflicting', [{ channel, state: 'delivered', status: 'failed' }]],
    ['duplicate', [{ channel, state: 'delivered' }, { channel, state: 'delivered' }]],
    ['wrong channel', [{ channel: channel === 'web' ? 'telegram' : 'web', state: 'delivered' }]],
  ])(`${channel} %s source bindings stay unknown in header and both detail rows`, (_name, bindings) => {
    mount(mapped(channel, bindings))
    for (const name of ['Web', 'Telegram']) {
      expect(row(name).textContent).toContain('Status unavailable')
      expect(within(row(name)).getByTestId('status-dot').getAttribute('data-state')).toBe('neutral')
    }
    expect(screen.getByTestId('thread-header').textContent).toContain('Delivery status unavailable')
    expect(row('Delivery').textContent).toContain('Delivery status unavailable')
    expect(screen.getByTestId('conversation-details').textContent).not.toMatch(/Connected|Not configured|Delivered/)
  })
}
it('missing conversation is unknown, not an inferred Web connection or unconfigured channel', () => {
  mount(null)
  expect(row('Web').textContent).toContain('Status unavailable')
  expect(row('Telegram').textContent).toContain('Status unavailable')
  expect(row('Delivery').textContent).toBe('DeliveryDelivery status unavailable')
  expect(screen.getByTestId('thread-header').textContent).toContain('Delivery status unavailable')
  expect(screen.getByTestId('conversation-details').textContent).not.toMatch(/Connected|Not configured|Web ·/)
})
