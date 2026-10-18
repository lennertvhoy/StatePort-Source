/**
 * Conversation surface tests (vitest + jsdom + testing-library).
 *
 * Covers the binding composer contract (Enter/Shift+Enter/Ctrl+Enter, IME
 * safety, send gating, attachments, drafts) and the streaming lifecycle
 * (stop, retry), plus the inbound bridge -> context-chip flow.
 */
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests, resetMockState, useScenarioStore } from '@/client'
import { sendToBridge, useBridgeStore } from '@/features/bridge/bridgeStore'
import { useConversationController } from '../useConversationController'
import { useSessionStore, useWorkspaceStore } from '@/state'
import { InstanceContext } from '@/shell/currentInstance'
import { buildSeed } from '@/client/mock/seed'

import { ConversationSurface } from '../ConversationSurface'
import { DetailsPanel } from '../DetailsPanel'
import { useConversationUiStore } from '../conversationUiStore'

const INSTANCE = 'ins_checklist_sample' // seeded with an empty conversation

function renderSurface(instanceId = INSTANCE) {
  return render(
    <MemoryRouter>
      <ConversationSurface instanceId={instanceId} />
    </MemoryRouter>,
  )
}

function surface(instanceId: string) {
  return (
    <MemoryRouter>
      <ConversationSurface instanceId={instanceId} />
    </MemoryRouter>
  )
}

function ControllerActionProbe({ instanceId }: { instanceId: string }) {
  const controller = useConversationController(instanceId)
  return (
    <>
      <button type="button" data-testid="controller-export" onClick={() => void controller.exportConversation()}>Export</button>
      <button type="button" data-testid="controller-clear" onClick={() => void controller.clearHistory()}>Clear</button>
    </>
  )
}

async function composerOf(): Promise<HTMLTextAreaElement> {
  return (await screen.findByTestId('composer-input')) as HTMLTextAreaElement
}

async function waitForReady() {
  await screen.findByTestId('composer')
  await waitFor(() => {
    expect(screen.queryByTestId('conversation-loading'), 'conversation finished loading').toBeNull()
  })
}

beforeEach(() => {
  resetClientForTests()
  useWorkspaceStore.setState({ drafts: {} })
  useConversationUiStore.setState({ pinned: {}, detailsOpen: {}, lastSeen: {} })
  useBridgeStore.setState({ pending: [] })
})

afterEach(() => {
  cleanup()
})

describe('composer keyboard contract', () => {
  it('Enter sends on desktop', async () => {
    const user = userEvent.setup()
    renderSurface()
    await waitForReady()
    const input = await composerOf()
    await user.click(input)
    await user.type(input, 'Hello StatePort')
    await user.keyboard('{Enter}')

    expect(await screen.findByText('Hello StatePort')).toBeTruthy()
    expect(input.value).toBe('')
  })

  it('Shift+Enter inserts a newline instead of sending', async () => {
    const user = userEvent.setup()
    renderSurface()
    await waitForReady()
    const input = await composerOf()
    await user.click(input)
    await user.type(input, 'line one')
    await user.keyboard('{Shift>}{Enter}{/Shift}')
    await user.type(input, 'line two')

    expect(input.value).toBe('line one\nline two')
    expect(screen.getByText('No messages yet')).toBeTruthy()
  })

  it('Ctrl+Enter always sends', async () => {
    const user = userEvent.setup()
    renderSurface()
    await waitForReady()
    const input = await composerOf()
    await user.click(input)
    await user.type(input, 'ctrl enter message')
    await user.keyboard('{Control>}{Enter}{/Control}')

    expect(await screen.findByText('ctrl enter message')).toBeTruthy()
  })

  it('never sends during IME composition', async () => {
    const user = userEvent.setup()
    renderSurface()
    await waitForReady()
    const input = await composerOf()
    await user.click(input)
    await user.type(input, 'kanji')

    fireEvent.compositionStart(input)
    await user.keyboard('{Enter}')
    expect(screen.queryByText('No messages yet')).toBeTruthy()
    expect(screen.queryByTestId('message-user')).toBeNull()

    fireEvent.compositionEnd(input)
    await user.keyboard('{Enter}')
    expect(await screen.findByTestId('message-user')).toBeTruthy()
  })

  it('cannot send an empty message', async () => {
    const user = userEvent.setup()
    renderSurface()
    await waitForReady()
    const input = await composerOf()
    const send = screen.getByTestId('composer-send') as HTMLButtonElement
    expect(send.disabled).toBe(true)

    await user.click(input)
    await user.keyboard('{Enter}')
    expect(screen.getByText('No messages yet')).toBeTruthy()
    expect(screen.queryByTestId('message-user')).toBeNull()
  })
})

describe('attachments', () => {
  it('sends a message with only an attachment (no text)', async () => {
    const user = userEvent.setup()
    renderSurface()
    await waitForReady()

    const file = new File(['hello attachment'], 'note.txt', { type: 'text/plain' })
    fireEvent.change(screen.getByTestId('composer-file-input'), { target: { files: [file] } })

    // Upload completes -> chip flips to ready, Send becomes enabled.
    await screen.findByTestId('attachment-ready', undefined, { timeout: 4000 })
    const send = screen.getByTestId('composer-send') as HTMLButtonElement
    expect(send.disabled).toBe(false)

    await user.click(send)
    const message = await screen.findByTestId('message-user')
    expect(within(message).getByText('note.txt')).toBeTruthy()
  })

  it('rejects an over-limit file with an honest error chip', async () => {
    renderSurface()
    await waitForReady()
    const big = new File([new Uint8Array(6 * 1024 * 1024)], 'huge.txt', { type: 'text/plain' })
    fireEvent.change(screen.getByTestId('composer-file-input'), { target: { files: [big] } })

    await screen.findByTestId('attachment-failed')
    expect(screen.getByTestId('limits-hint').textContent).toContain('2 MiB')
    expect((screen.getByTestId('composer-send') as HTMLButtonElement).disabled).toBe(true)
  })

  it('explains an unsupported image inline before any upload is attempted', async () => {
    const client = getClient()
    const upload = vi.spyOn(client.conversation, 'uploadAttachment')
    renderSurface()
    await waitForReady()
    const webp = new File(['not a supported image'], 'capture.webp', { type: 'image/webp' })

    fireEvent.change(screen.getByTestId('composer-file-input'), { target: { files: [webp] } })

    const failed = await screen.findByTestId('attachment-failed')
    const error = within(failed).getByRole('alert')
    expect(error.textContent).toContain('unsupported file type')
    expect(error.textContent).toContain('image/webp')
    expect(error.textContent).toContain('PNG/JPEG')
    expect(upload).not.toHaveBeenCalled()
    expect(screen.getByTestId('limits-hint').textContent).toContain(
      'not sent to the assistant',
    )
  })

  it('deletes a service-stored attachment when it is removed before send', async () => {
    const client = getClient()
    const deleteAttachment = vi.spyOn(client.conversation, 'deleteAttachment')
    const user = userEvent.setup()
    renderSurface()
    await waitForReady()

    const file = new File(['delete me'], 'temporary.txt', { type: 'text/plain' })
    fireEvent.change(screen.getByTestId('composer-file-input'), { target: { files: [file] } })
    const ready = await screen.findByTestId('attachment-ready', undefined, { timeout: 4000 })
    const remove = within(ready).getByRole('button', { name: 'Remove temporary.txt' })
    await user.click(remove)

    await waitFor(() => expect(deleteAttachment).toHaveBeenCalledTimes(1))
    expect(deleteAttachment.mock.calls[0]?.[0]).toBe(INSTANCE)
    await waitFor(() => expect(screen.queryByTestId('attachment-strip')).toBeNull())
  })

  it('keeps a stored attachment visible when deletion is refused', async () => {
    const client = getClient()
    const deleteAttachment = vi
      .spyOn(client.conversation, 'deleteAttachment')
      .mockRejectedValueOnce(new Error('delete refused'))
    const user = userEvent.setup()
    renderSurface()
    await waitForReady()

    const file = new File(['keep me'], 'retained.txt', { type: 'text/plain' })
    fireEvent.change(screen.getByTestId('composer-file-input'), { target: { files: [file] } })
    const ready = await screen.findByTestId('attachment-ready', undefined, { timeout: 4000 })
    await user.click(
      within(ready).getByRole('button', { name: 'Remove retained.txt' }),
    )

    const failed = await screen.findByTestId('attachment-failed')
    expect(deleteAttachment).toHaveBeenCalledTimes(1)
    expect(failed.textContent).toContain('retained.txt')
    expect(screen.getByRole('button', { name: 'Remove retained.txt' })).toBeTruthy()
  })
})

describe('drafts', () => {
  it('flushes the latest draft when a route unmount beats the debounce', async () => {
    const first = renderSurface()
    await waitForReady()
    const input = await composerOf()
    fireEvent.change(input, { target: { value: 'fast route change' } })

    // No debounce wait: route navigation unmounts the composer immediately.
    first.unmount()
    renderSurface()

    const restored = await composerOf()
    expect(restored.value).toBe('fast route change')
  })

  it('persists the draft across unmount/remount', async () => {
    const user = userEvent.setup()
    const first = renderSurface()
    await waitForReady()
    const input = await composerOf()
    await user.click(input)
    await user.type(input, 'draft survives remount')

    await waitFor(() => expect(useWorkspaceStore.getState().drafts[INSTANCE]).toContain('draft survives'))
    first.unmount()

    renderSurface()
    const restored = await composerOf()
    expect(restored.value).toBe('draft survives remount')
  })

  it('flushes each conversation key without leaking the next draft into it', async () => {
    const view = render(surface(INSTANCE))
    await waitForReady()
    fireEvent.change(await composerOf(), { target: { value: 'checklist draft' } })

    // Switch applications before the debounce. React renders the new key
    // before cleaning up effects for the old key.
    view.rerender(surface('ins_nixos_infra'))

    await waitFor(() => {
      expect(useWorkspaceStore.getState().drafts[INSTANCE]).toBe('checklist draft')
    })
    expect(useWorkspaceStore.getState().drafts.ins_nixos_infra).not.toBe('checklist draft')
  })
})

describe('streaming lifecycle', () => {
  it('stop ends the stream honestly with a marker and retry completes it', async () => {
    const user = userEvent.setup()
    renderSurface()
    await waitForReady()
    const input = await composerOf()
    await user.click(input)
    await user.type(input, 'hello')
    await user.keyboard('{Enter}')

    const stop = await screen.findByTestId('stop-stream', undefined, { timeout: 4000 })
    await user.click(stop)

    expect(await screen.findByText('Stopped by you')).toBeTruthy()
    const assistant = await screen.findByTestId('message-assistant')
    expect(assistant.getAttribute('data-state')).toBe('stopped')

    const retry = await screen.findByTestId(/^retry-response-/)
    await user.click(retry)
    await waitFor(
      () => {
        const row = screen.getByTestId('message-assistant')
        expect(row.getAttribute('data-state')).toBe('complete')
        expect(row.textContent).toContain('Three of five items are open')
      },
      { timeout: 6000 },
    )
    expect(screen.queryByText('Stopped by you')).toBeNull()
  })
})

describe('live stream resume on load (conversation_streaming scenario)', () => {
  it('resumes the seeded in-flight reply with a working stop', async () => {
    const user = userEvent.setup()
    useScenarioStore.getState().setActive('conversation_streaming')
    try {
      renderSurface('ins_cto_pilot')
      // The seeded in-flight reply resumes: the stop control appears without a send.
      const stop = await screen.findByTestId('stop-stream', undefined, { timeout: 6000 })
      expect(await screen.findByTestId('streaming-indicator')).toBeTruthy()
      await user.click(stop)

      expect(await screen.findByText('Stopped by you')).toBeTruthy()
      await waitFor(() => expect(screen.queryByTestId('streaming-indicator')).toBeNull())
      const rows = screen.getAllByTestId('message-assistant')
      const resumed = rows[rows.length - 1]
      expect(resumed.getAttribute('data-state')).toBe('stopped')
      expect(resumed.textContent).toContain('Looking at the current plan')
    } finally {
      useScenarioStore.getState().setActive(null)
      resetMockState()
    }
  })
})

describe('bridge -> context chips', () => {
  it('turns an inbound bridge payload into a removable context chip', async () => {
    const user = userEvent.setup()
    sendToBridge({
      kind: 'file-selection',
      instanceId: INSTANCE,
      path: 'src/main.ts',
      text: 'const answer = 42',
      lineStart: 1,
      lineEnd: 3,
    })
    renderSurface()
    await waitForReady()

    const row = await screen.findByTestId('context-chip-row')
    const chip = within(row).getByTestId('context-chip-selection')
    expect(chip.textContent).toContain('src/main.ts:1–3')

    const remove = within(chip).getByRole('button', { name: /remove src\/main\.ts/i })
    await user.click(remove)
    // The last non-default chip is gone, so the whole row collapses.
    expect(screen.queryByTestId('context-chip-selection')).toBeNull()
    expect(screen.queryByTestId('context-chip-row')).toBeNull()
  })

  it('sends chips with the message and records them on it', async () => {
    const user = userEvent.setup()
    sendToBridge({ kind: 'file', instanceId: INSTANCE, path: 'README.md' })
    renderSurface()
    await waitForReady()
    await screen.findByTestId('context-chip-row')

    const input = await composerOf()
    await user.click(input)
    await user.type(input, 'what does this file do')
    await user.keyboard('{Enter}')

    const message = await screen.findByTestId('message-user')
    expect(within(message).getByText('README.md')).toBeTruthy()
  })
})

describe('conversation receipt quick actions', () => {
  it('uses the native receipt route and preserves the receipt bridge context', async () => {
    const client = getClient()
    const instance = buildSeed().instances.find(({ id }) => id === INSTANCE)
    if (!instance) throw new Error('ChecklistState fixture is missing from the mock seed.')
    const conversation = await client.conversation.get(INSTANCE)
    const receipt = await client.receipts.get('rcpt_0006')
    vi.spyOn(client.receipts, 'list').mockResolvedValue([
      { ...receipt, relatedConversationId: conversation.id },
    ])
    const capabilities = new Map(instance.capabilities.map((candidate) => [candidate.id, candidate]))

    render(
      <MemoryRouter initialEntries={[`/app/${INSTANCE}/conversation`]}>
        <InstanceContext.Provider
          value={{
            instance,
            capabilities,
            loading: false,
            error: null,
            refresh: () => undefined,
            hasCapability: (id) => {
              const state = capabilities.get(id)?.status
              return state === 'available' || state === 'degraded'
            },
            capability: (id) => capabilities.get(id),
          }}
        >
          <DetailsPanel
            instanceId={INSTANCE}
            conversation={conversation}
            messages={[]}
            pinnedIds={[]}
            onJumpToMessage={() => undefined}
          />
        </InstanceContext.Provider>
      </MemoryRouter>,
    )

    const link = await screen.findByRole('link', { name: /Checklist item completed/ })
    expect(link.getAttribute('href')).toBe(`/app/${INSTANCE}/receipts/rcpt_0006`)
    fireEvent.click(link)
    expect(useBridgeStore.getState().peek(INSTANCE)).toEqual([
      { kind: 'receipt', instanceId: INSTANCE, receiptId: 'rcpt_0006' },
    ])
  })

  it('renders an explicit unavailable state when resolved experience omits Receipts', async () => {
    const client = getClient()
    const seeded = buildSeed().instances.find(({ id }) => id === INSTANCE)
    if (!seeded) throw new Error('ChecklistState fixture is missing from the mock seed.')
    const instance = {
      ...seeded,
      experienceResolution: 'resolved' as const,
      experience: {
        formatVersion: 'stateport.application-experience-resolution/v1' as const,
        applicationId: 'stateport.development-reference',
        views: [],
        navigation: [],
        advancedControls: [],
      },
    }
    const conversation = await client.conversation.get(INSTANCE)
    const receipt = await client.receipts.get('rcpt_0006')
    vi.spyOn(client.receipts, 'list').mockResolvedValue([
      { ...receipt, relatedConversationId: conversation.id },
    ])
    const capabilities = new Map(instance.capabilities.map((candidate) => [candidate.id, candidate]))

    render(
      <MemoryRouter>
        <InstanceContext.Provider
          value={{
            instance,
            capabilities,
            loading: false,
            error: null,
            refresh: () => undefined,
            hasCapability: (id) => {
              const state = capabilities.get(id)?.status
              return state === 'available' || state === 'degraded'
            },
            capability: (id) => capabilities.get(id),
          }}
        >
          <DetailsPanel
            instanceId={INSTANCE}
            conversation={conversation}
            messages={[]}
            pinnedIds={[]}
            onJumpToMessage={() => undefined}
          />
        </InstanceContext.Provider>
      </MemoryRouter>,
    )

    expect(await screen.findByTestId('conversation-receipts-unavailable')).toBeTruthy()
    expect(screen.queryByRole('link', { name: /Checklist item completed/ })).toBeNull()
  })

  it('routes export and clear notifications to native receipt details without Workbench', async () => {
    const user = userEvent.setup()
    const client = getClient()
    const seeded = buildSeed().instances.find(({ id }) => id === 'ins_study_alpha')
    if (!seeded) throw new Error('StudyState fixture is missing from the mock seed.')
    const exportReceipt = await client.receipts.get('rcpt_0006')
    const clearReceipt = { ...exportReceipt, id: 'rcpt_clear_native' }
    vi.spyOn(client.conversation, 'exportConversation').mockResolvedValue({
      markdown: '# Conversation export\n',
      receipt: { ...exportReceipt, id: 'rcpt_export_native' },
    })
    vi.spyOn(client.conversation, 'clearConversation').mockResolvedValue({ receipt: clearReceipt })
    const capabilities = new Map(seeded.capabilities.map((candidate) => [candidate.id, candidate]))
    useSessionStore.getState().clearToasts()

    render(
      <MemoryRouter>
        <InstanceContext.Provider
          value={{
            instance: seeded,
            capabilities,
            loading: false,
            error: null,
            refresh: () => undefined,
            hasCapability: (id) => {
              const state = capabilities.get(id)?.status
              return state === 'available' || state === 'degraded'
            },
            capability: (id) => capabilities.get(id),
          }}
        >
          <ControllerActionProbe instanceId="ins_study_alpha" />
        </InstanceContext.Provider>
      </MemoryRouter>,
    )

    await user.click(screen.getByTestId('controller-export'))
    await waitFor(() => {
      expect(useSessionStore.getState().toasts.at(-1)?.route).toBe('/app/ins_study_alpha/receipts/rcpt_export_native')
    })

    useSessionStore.getState().clearToasts()
    await user.click(screen.getByTestId('controller-clear'))
    await waitFor(() => {
      expect(useSessionStore.getState().toasts.at(-1)?.route).toBe('/app/ins_study_alpha/receipts/rcpt_clear_native')
    })
  })
})

describe('seeded history rendering', () => {
  it('renders markdown, sent-context chips and collapsed tool events', async () => {
    const user = userEvent.setup()
    renderSurface('ins_cto_pilot')
    await waitForReady()

    // Assistant markdown: inline code renders as <code>.
    const assistantRows = await screen.findAllByTestId('message-assistant')
    expect(assistantRows.length).toBe(2)
    expect(assistantRows[1].querySelector('code')?.textContent).toContain('notes/pilot-notes.md')

    // The user's message shows the context it was sent with.
    const userRows = screen.getAllByTestId('message-user')
    expect(within(userRows[0]).getByText('StatePort CTO Pilot')).toBeTruthy()

    // Tool events: collapsed one-line summary, expanding to detail.
    const toolEvents = within(assistantRows[1]).getByTestId('tool-events')
    const toggle = within(toolEvents).getByRole('button')
    expect(toggle.textContent).toContain('Saved notes/pilot-notes.md')
    expect(toggle.textContent).toContain('expand')
    await user.click(toggle)
    expect(within(toolEvents).getByText('file.write')).toBeTruthy()
  })

  it('renders a governed-operation proposal that routes to approvals', async () => {
    renderSurface('ins_nixos_infra')
    await waitForReady()

    const card = await screen.findByTestId('proposal-card')
    expect(card.textContent).toContain('Start virtual machine')
    expect(card.textContent).toContain('Nothing has been run or changed.')
    expect(within(card).getByTestId('proposal-open-approval').textContent).toContain('approvals flow')
  })

  it('marks the transcript as a log with honest delivery metadata', async () => {
    renderSurface('ins_cto_pilot')
    await waitForReady()
    expect(screen.getByRole('log', { name: 'Conversation transcript' })).toBeTruthy()
    expect(screen.getByTestId('thread-header').textContent).toContain('Web · Delivered')
  })
})


it('saved compact message spacing survives reopening without changing conversation data or controls', async () => {
  const id = 'ins_cto_pilot'
  const client = getClient()
  const before = await client.conversation.get(id)
  await client.globalSettings.update({ conversation: { compactMessageLayout: true } })
  const view = renderSurface(id)
  await waitForReady()
  await waitFor(() => expect(screen.getByTestId('transcript').firstElementChild?.classList.contains('gap-1.5')).toBe(true))
  expect(screen.getByTestId('composer')).toBeTruthy()
  expect(view.container.querySelectorAll('[data-message-id]').length).toBe(before.messages.length)
  view.unmount()
  await client.globalSettings.update({ conversation: { compactMessageLayout: false } })
  renderSurface(id)
  await waitForReady()
  await waitFor(() => expect(screen.getByTestId('transcript').firstElementChild?.classList.contains('gap-3')).toBe(true))
  expect((await client.conversation.get(id)).messages).toEqual(before.messages)
  expect(screen.getByTestId('composer')).toBeTruthy()
}, 20_000)

it.each([false, true] as const)('uses the saved delivery-details preference for per-message facts (%s)', async (showDeliveryDetails) => {
  const client = getClient()
  await client.globalSettings.update({ conversation: { showDeliveryDetails } })

  renderSurface('ins_cto_pilot')
  await waitForReady()

  const delivered = document.querySelector('[data-message-id="msg_0002"]')
  const inbound = document.querySelector('[data-message-id="msg_0001"]')
  const legacy = document.querySelector('[data-message-id="msg_0003"]')
  const failed = document.querySelector('[data-message-id="msg_0004"]')
  expect(delivered).toBeTruthy()
  expect(inbound).toBeTruthy()
  expect(legacy).toBeTruthy()
  expect(failed).toBeTruthy()
  await waitFor(() => {
    expect(delivered?.querySelector('[data-testid="message-delivery-details"]') !== null).toBe(showDeliveryDetails)
    expect(inbound?.querySelector('[data-testid="message-delivery-details"]') !== null).toBe(showDeliveryDetails)
    expect(legacy?.querySelector('[data-testid="message-delivery-details"]') !== null).toBe(showDeliveryDetails)
    expect(failed?.querySelector('[data-testid="message-delivery-details"]') !== null).toBe(showDeliveryDetails)
  })
  if (showDeliveryDetails) {
    expect(delivered?.textContent).toContain('Delivered')
    expect(inbound?.textContent).toContain('Recorded inbound acceptance')
    expect(inbound?.textContent).toContain('Web')
    expect(legacy?.textContent).toContain('Delivery details unavailable')
    expect(failed?.textContent).toContain('Delivery failed')
    expect(failed?.textContent).toContain('telegram-sink-rejected')
  } else {
    expect(failed?.querySelector('[data-testid="message-delivery-failure"]')).toBeTruthy()
    expect(failed?.textContent).toContain('telegram-sink-rejected')
  }
  expect(screen.getByTestId('thread-header').textContent).toContain('Web · Delivered')
  expect(screen.getByTestId('composer')).toBeTruthy()
}, 20_000)


it('shows unknown thread delivery neutrally while keeping transcript and send controls', async () => {
  const client = getClient()
  const conversation = await client.conversation.get('ins_cto_pilot')
  const get = vi.spyOn(client.conversation, 'get').mockResolvedValue({ ...conversation, deliveryState: 'unknown' })
  try {
    renderSurface('ins_cto_pilot')
    await waitForReady()
    const header = screen.getByTestId('thread-header')
    expect(header.textContent).toContain('Delivery status unavailable')
    expect(header.textContent).not.toContain('Delivered')
    expect(header.textContent).not.toContain('Not configured')
    expect(screen.getByRole('log', { name: 'Conversation transcript' })).toBeTruthy()
    expect(screen.getByTestId('composer')).toBeTruthy()
    render(<MemoryRouter><DetailsPanel instanceId="ins_cto_pilot" conversation={{ ...conversation, deliveryState: 'unknown' }}
      messages={conversation.messages} pinnedIds={[]} onJumpToMessage={() => undefined} /></MemoryRouter>)
    expect(screen.getAllByText(/Delivery status unavailable/)).toHaveLength(2)
  } finally { get.mockRestore() }
}, 20_000)
