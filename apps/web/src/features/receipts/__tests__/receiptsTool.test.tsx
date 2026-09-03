/**
 * Receipts tool integration tests (jsdom): the list is human-facing, filters
 * persist to the workspace store, the detail drawer shows digests and
 * related links, verify reports honestly, export downloads, and the empty /
 * no-match states carry the design copy.
 */
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import type { Receipt } from '@/client'
import { getClient, resetClientForTests } from '@/client'
import { useBridgeStore } from '@/features/bridge/bridgeStore'
import { useSessionStore, useWorkspaceStore } from '@/state'

import ReceiptsTool from '../ReceiptsTool'
import ApplicationReceiptsPage, { ApplicationReceiptDetailPage } from '../ApplicationReceiptsPage'
import { useReceiptsUiStore } from '../receiptsUiStore'
import type { StoredReceiptFilter } from '../receiptsModel'
import { ReceiptsNavPanel } from '../ReceiptsNavPanel'

const INSTANCE = 'ins_cto_pilot'
const LIST_ROUTE = `/app/${INSTANCE}/workbench/receipts`

function renderReceipts(initialRoute = LIST_ROUTE) {
  return render(
    <MemoryRouter initialEntries={[initialRoute]}>
      <Routes>
        <Route path="/app/:instanceId/workbench/receipts" element={<ReceiptsTool />} />
        <Route path="/app/:instanceId/workbench/receipts/:receiptId" element={<ReceiptsTool />} />
        <Route path="/approvals/:approvalId" element={<div data-testid="approval-page" />} />
        <Route path="/app/:instanceId/conversation" element={<div data-testid="conversation-page" />} />
        <Route path="/app/:instanceId/workbench/files" element={<div data-testid="files-tool" />} />
      </Routes>
    </MemoryRouter>,
  )
}

function renderNativeReceipts(initialRoute = `/app/${INSTANCE}/receipts`) {
  return render(
    <MemoryRouter initialEntries={[initialRoute]}>
      <Routes>
        <Route path="/app/:instanceId/receipts" element={<ApplicationReceiptsPage />} />
        <Route path="/app/:instanceId/receipts/:receiptId" element={<ApplicationReceiptDetailPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

function makeReceipt(overrides: Partial<Receipt> & { id: string }): Receipt {
  return {
    instanceId: INSTANCE,
    packageId: 'pkg_project_state',
    actionName: 'Infrastructure plan approved',
    eventKind: 'approval.approve',
    actor: 'user',
    result: 'validated',
    createdAt: new Date(Date.now() - 3600_000).toISOString(),
    expectedRevision: 'rev_expected_1',
    resultRevision: 'rev_result_2',
    planDigest: { algorithm: 'sha256', value: 'a'.repeat(64) },
    payloadDigest: { algorithm: 'sha256', value: 'b'.repeat(64) },
    validation: { state: 'validated', detail: 'Response matched the expected revision.' },
    summary: 'Graceful stop of homelab-dev was approved.',
    beforeSummary: 'VM running',
    afterSummary: 'VM stopped',
    relatedApprovalId: 'appr_0001',
    relatedPlanId: 'plan_0001',
    rawJson: JSON.stringify({ id: overrides.id, event: 'approval.approve' }, null, 2),
    ...overrides,
  }
}

// jsdom has no layout; report a real viewport so @tanstack/react-virtual
// renders rows (virtual-core reads borderBoxSize from the observer entry).
class ResizeObserverMock {
  private cb: ResizeObserverCallback
  constructor(cb: ResizeObserverCallback) {
    this.cb = cb
  }
  observe(el: Element) {
    this.cb(
      [{ target: el, borderBoxSize: [{ inlineSize: 800, blockSize: 600 }] } as unknown as ResizeObserverEntry],
      this as unknown as ResizeObserver,
    )
  }
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  // The shared setup defines ResizeObserver non-configurable; assign instead.
  window.ResizeObserver = ResizeObserverMock as unknown as typeof ResizeObserver
  resetClientForTests()
  useWorkspaceStore.setState({ receiptFilters: {} })
  useSessionStore.setState({ toasts: [] })
  useReceiptsUiStore.setState({ saved: {} })
  useBridgeStore.getState().clear()
})

afterEach(() => {
  cleanup()
})

describe('receipts list', () => {
  it('renders human action names and human actors — never raw event kinds', async () => {
    renderReceipts()
    const table = await screen.findByTestId('receipts-table', undefined, { timeout: 5000 })

    // Seed receipts for ins_cto_pilot: human names from the brief.
    expect(await within(table).findByText('File change saved')).toBeTruthy()
    expect(within(table).getByText('Conversation exported')).toBeTruthy()
    expect(within(table).getByText('Backup completed')).toBeTruthy()

    // Human actor labels.
    expect(within(table).getAllByText('You').length).toBeGreaterThan(0)
    expect(within(table).getByText('System')).toBeTruthy()

    // Raw event kinds and raw IDs stay out of the list.
    expect(within(table).queryByText('file.write')).toBeNull()
    expect(within(table).queryByText('conversation.export')).toBeNull()
    expect(within(table).queryByText('rcpt_0001')).toBeNull()

    // Result comes through the semantic layer as StatusBadges.
    expect(within(table).getAllByTestId('status-badge').length).toBeGreaterThan(0)
  })

  it('persists search + facet filters to the workspace store', async () => {
    const user = userEvent.setup()
    renderReceipts()
    const search = await screen.findByTestId('receipts-search', undefined, { timeout: 5000 })

    await user.type(search, 'backup')
    expect(useWorkspaceStore.getState().receiptFilters[INSTANCE]?.query).toBe('backup')
    expect((await screen.findByTestId('receipts-table')).textContent).toContain('Backup completed')
    expect(within(screen.getByTestId('receipts-table')).queryByText('File change saved')).toBeNull()

    // Result facet.
    await user.click(screen.getByTestId('receipts-filter-result'))
    await user.click(await screen.findByRole('option', { name: 'Failed' }))
    expect(useWorkspaceStore.getState().receiptFilters[INSTANCE]?.result).toBe('failed')

    // Nothing matches → honest no-match state with Clear filters.
    expect(await screen.findByText('No receipts match these filters')).toBeTruthy()
    await user.click(screen.getByRole('button', { name: 'Clear filters' }))
    // Cleared facets fall back to undefined in the stored client-contract shape.
    expect(useWorkspaceStore.getState().receiptFilters[INSTANCE]?.result).toBeUndefined()
    expect(useWorkspaceStore.getState().receiptFilters[INSTANCE]?.query).toBeUndefined()
    expect(await screen.findByText('File change saved')).toBeTruthy()
  })

  it('persists the view toggle and renders the timeline with day groups', async () => {
    const user = userEvent.setup()
    renderReceipts()
    await screen.findByTestId('receipts-table', undefined, { timeout: 5000 })

    await user.click(screen.getByRole('radio', { name: 'Timeline view' }))
    expect((useWorkspaceStore.getState().receiptFilters[INSTANCE] as StoredReceiptFilter | undefined)?.view).toBe('timeline')

    const timeline = await screen.findByTestId('receipts-timeline')
    expect(within(timeline).getByText('File change saved')).toBeTruthy()
    // Grouped by day with sticky day headers. The seed is relative to the
    // reset time, so its newest item can legitimately cross midnight; exact
    // Today/Yesterday labelling is covered with a fixed clock by
    // receiptsModel.test.ts.
    const groups = timeline.querySelectorAll('section[role="group"]')
    expect(groups.length).toBeGreaterThanOrEqual(2)
    for (const group of groups) {
      const label = group.getAttribute('aria-label')
      expect(label).toBeTruthy()
      expect(group.querySelector('h3')?.textContent).toBe(label)
    }

    await user.click(screen.getByRole('radio', { name: 'Table view' }))
    expect((useWorkspaceStore.getState().receiptFilters[INSTANCE] as StoredReceiptFilter | undefined)?.view).toBe('table')
  })

  it('nav-panel presets apply to the persisted filter', async () => {
    const user = userEvent.setup()
    render(<ReceiptsNavPanel instanceId={INSTANCE} tool="receipts" />)
    await user.click(screen.getByTestId('receipts-preset-failures'))
    expect(useWorkspaceStore.getState().receiptFilters[INSTANCE]?.result).toBe('failed')
    await user.click(screen.getByTestId('receipts-preset-all'))
    expect(useWorkspaceStore.getState().receiptFilters[INSTANCE]?.result).toBeUndefined()

    // Save the current view as a named filter.
    await user.click(screen.getByTestId('receipts-save-filter'))
    await user.type(screen.getByLabelText('Filter name'), 'Mine')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(useReceiptsUiStore.getState().saved[INSTANCE]?.some((f) => f.name === 'Mine')).toBe(true)
  })

  it('supports keyboard navigation: arrows move, Enter opens the detail', async () => {
    const user = userEvent.setup()
    renderReceipts()
    const table = await screen.findByTestId('receipts-table', undefined, { timeout: 5000 })
    await within(table).findByText('File change saved')

    const firstRow = table.querySelector<HTMLElement>('[data-receipt-row="0"]')!
    firstRow.focus()
    await user.keyboard('{ArrowDown}')
    const secondRow = table.querySelector<HTMLElement>('[data-receipt-row="1"]')!
    expect(document.activeElement).toBe(secondRow)

    await user.keyboard('{Enter}')
    // Seed order is newest-first: row 1 is rcpt_0002 (Conversation exported).
    expect(await screen.findByTestId('receipt-detail', undefined, { timeout: 5000 })).toBeTruthy()
    expect(await within(screen.getByTestId('drawer')).findByText('Conversation exported', undefined, { timeout: 5000 })).toBeTruthy()
  })

  it('copies the focused row receipt ID with Ctrl/Cmd+C and toasts', async () => {
    const user = userEvent.setup()
    renderReceipts()
    const table = await screen.findByTestId('receipts-table', undefined, { timeout: 5000 })
    await within(table).findByText('File change saved')

    const firstRow = table.querySelector<HTMLElement>('[data-receipt-row="0"]')!
    firstRow.focus()
    await user.keyboard('{Control>}c{/Control}')
    const toasts = useSessionStore.getState().toasts
    expect(toasts.some((t) => t.title === 'Receipt ID copied' && t.body === 'rcpt_0001')).toBe(true)
  })
})

describe('receipt detail', () => {
  it('shows completed and missing validation as separate claims', async () => {
    const user = userEvent.setup()
    const client = getClient()
    vi.spyOn(client.receipts, 'get').mockResolvedValue(
      makeReceipt({
        id: 'rcpt_completed',
        actionName: 'Infrastructure operation completed',
        result: 'completed',
        validation: {
          state: 'not_recorded',
          detail: 'No validation evidence was recorded for this receipt.',
        },
      }),
    )

    renderReceipts(`${LIST_ROUTE}/rcpt_completed`)
    const drawer = await screen.findByTestId('drawer', undefined, { timeout: 5000 })
    expect(within(drawer).getByText('Completed')).toBeTruthy()
    expect(within(drawer).queryByText('Validated')).toBeNull()

    await user.click(within(drawer).getByText('IDs, revisions, and digests'))
    const record = await within(drawer).findByTestId('receipt-exact-record')
    expect(within(record).getByText('Not recorded')).toBeTruthy()
    expect(record.textContent).toContain('No validation evidence was recorded')
  })

  it('shows digests, revisions, and the related-approval link', async () => {
    const user = userEvent.setup()
    const client = getClient()
    vi.spyOn(client.receipts, 'get').mockResolvedValue(makeReceipt({ id: 'rcpt_9001' }))

    renderReceipts(`${LIST_ROUTE}/rcpt_9001`)
    const drawer = await screen.findByTestId('drawer', undefined, { timeout: 5000 })

    // Human header + plain-language summary.
    expect(within(drawer).getByText('Infrastructure plan approved')).toBeTruthy()
    expect(within(drawer).getByText(/Graceful stop of homelab-dev was approved/)).toBeTruthy()
    expect(within(drawer).getByText('VM running')).toBeTruthy()
    expect(within(drawer).getByText('VM stopped')).toBeTruthy()

    // Related approval is a navigable link.
    const approvalLink = within(drawer).getByTestId('related-related-approval')
    expect(approvalLink.getAttribute('href')).toBe('/approvals/appr_0001')
    expect(
      within(drawer).getByTestId('related-review-receipt-in-conversation').getAttribute('href'),
    ).toBe(`/app/${INSTANCE}/conversation`)

    // Exact record: open the disclosure and check digests + revisions.
    await user.click(within(drawer).getByText('IDs, revisions, and digests'))
    const record = await within(drawer).findByTestId('receipt-exact-record')
    expect(record.textContent).toContain('rcpt_9001')
    expect(record.textContent).toContain('approval.approve')
    expect(record.textContent).toContain('rev_expected_1')
    expect(record.textContent).toContain('rev_result_2')
    expect(record.textContent).toContain('a'.repeat(64))
    expect(record.textContent).toContain('b'.repeat(64))

    // The caveat lives once in the detail footer.
    expect(screen.getAllByTestId('receipt-caveat')).toHaveLength(1)
  })

  it('opens a related conversation with the reviewed receipt as explicit context', async () => {
    const user = userEvent.setup()
    vi.spyOn(getClient().receipts, 'get').mockResolvedValue(
      makeReceipt({
        id: 'rcpt_conversation',
        relatedApprovalId: undefined,
        relatedPlanId: undefined,
        relatedConversationId: 'conv_7',
      }),
    )

    renderReceipts(`${LIST_ROUTE}/rcpt_conversation`)
    const drawer = await screen.findByTestId('drawer', undefined, { timeout: 5000 })
    await user.click(within(drawer).getByTestId('related-related-conversation'))

    expect(await screen.findByTestId('conversation-page')).toBeTruthy()
    expect(useBridgeStore.getState().peek(INSTANCE)).toEqual([
      {
        kind: 'receipt',
        instanceId: INSTANCE,
        receiptId: 'rcpt_conversation',
      },
    ])
  })

  it('verifies integrity and reports success honestly', async () => {
    const user = userEvent.setup()
    renderReceipts(`${LIST_ROUTE}/rcpt_0001`)
    const drawer = await screen.findByTestId('drawer', undefined, { timeout: 5000 })

    await user.click(await within(drawer).findByTestId('receipt-verify', undefined, { timeout: 5000 }))
    expect(await within(drawer).findByText('Verified — content matches the recorded digests', undefined, { timeout: 5000 })).toBeTruthy()
  })

  it('reports a failed integrity check honestly (danger, no green)', async () => {
    const user = userEvent.setup()
    const client = getClient()
    vi.spyOn(client.receipts, 'verify').mockResolvedValue({
      ok: false,
      detail: 'Payload digest mismatch — this receipt may have been modified.',
    })

    renderReceipts(`${LIST_ROUTE}/rcpt_0001`)
    const drawer = await screen.findByTestId('drawer', undefined, { timeout: 5000 })
    await user.click(await within(drawer).findByTestId('receipt-verify', undefined, { timeout: 5000 }))

    expect(await within(drawer).findByText('Integrity check failed', undefined, { timeout: 5000 })).toBeTruthy()
    expect(within(drawer).getByText(/Payload digest mismatch/)).toBeTruthy()
    expect(within(drawer).queryByText(/Verified — content matches/)).toBeNull()
    expect(within(drawer).getByRole('alert')).toBeTruthy()
  })

  it('closes back to the list', async () => {
    const user = userEvent.setup()
    renderReceipts(`${LIST_ROUTE}/rcpt_0001`)
    const drawer = await screen.findByTestId('drawer', undefined, { timeout: 5000 })
    await user.click(within(drawer).getByRole('button', { name: 'Close' }))
    expect(await screen.findByTestId('receipts-table', undefined, { timeout: 5000 })).toBeTruthy()
    expect(screen.queryByTestId('drawer')).toBeNull()
  })
})

describe('native application receipts', () => {
  it('copies receipt IDs and hides Workbench-only related quick actions', async () => {
    const user = userEvent.setup()
    vi.spyOn(getClient().receipts, 'list').mockResolvedValue([
      makeReceipt({
        id: 'rcpt_native',
        relatedApprovalId: undefined,
        relatedPlanId: 'plan_native',
        relatedConversationId: undefined,
      }),
      makeReceipt({ id: 'rcpt_native_approval', relatedPlanId: undefined }),
    ])
    renderNativeReceipts()

    const table = await screen.findByTestId('receipts-table', undefined, { timeout: 5000 })
    const row = table.querySelector<HTMLElement>('[data-receipt-row="0"]')!
    row.focus()
    await user.keyboard('{Control>}c{/Control}')

    expect(useSessionStore.getState().toasts.some((t) => t.title === 'Receipt ID copied')).toBe(true)
    expect(within(table).queryByRole('button', { name: 'Open related plan' })).toBeNull()
    const relatedApproval = within(table).getByRole('button', { name: 'Open related approval' })
    expect(relatedApproval.tabIndex).toBe(0)
    fireEvent.keyDown(relatedApproval, { key: 'Enter' })
    expect(screen.queryByTestId('application-receipt-page')).toBeNull()
  })

  it('hides operation and plan relationships when the native detail has no supported target', async () => {
    vi.spyOn(getClient().receipts, 'get').mockResolvedValue(
      makeReceipt({
        id: 'rcpt_native_detail',
        relatedApprovalId: undefined,
        relatedPlanId: 'plan_native',
        relatedConversationId: undefined,
      }),
    )
    renderNativeReceipts(`/app/${INSTANCE}/receipts/rcpt_native_detail`)

    const drawer = await screen.findByTestId('drawer', undefined, { timeout: 5000 })
    expect(within(drawer).queryByText('Relationships')).toBeNull()
    expect(within(drawer).queryByRole('link', { name: /related plan/i })).toBeNull()
  })

  it('normalizes a sha256-prefixed native receipt digest query', async () => {
    vi.spyOn(getClient().receipts, 'get').mockResolvedValue(
      makeReceipt({
        id: 'rcpt_prefixed_digest',
        instanceId: 'ins_study_alpha',
        payloadDigest: { algorithm: 'sha256', value: `sha256:${'b'.repeat(64)}` },
      }),
    )
    renderNativeReceipts(`/app/ins_study_alpha/receipts/rcpt_prefixed_digest?digest=sha256:${'b'.repeat(64)}`)

    const drawer = await screen.findByTestId('drawer', undefined, { timeout: 5000 })
    expect(within(drawer).queryByText('Receipt identity is invalid')).toBeNull()
    expect(within(drawer).queryByText('The receipt detail digest does not match the completed installation')).toBeNull()
  })

  it('fails closed when native receipt detail returns a different receipt ID', async () => {
    vi.spyOn(getClient().receipts, 'get').mockResolvedValue(
      makeReceipt({ id: 'rcpt_returned_other', instanceId: 'ins_study_alpha' }),
    )
    renderNativeReceipts('/app/ins_study_alpha/receipts/rcpt_requested')

    const drawer = await screen.findByTestId('drawer', undefined, { timeout: 5000 })
    expect(within(drawer).getByText('Receipt not available')).toBeTruthy()
    expect(within(drawer).getByText('The receipt detail response did not match the requested receipt')).toBeTruthy()
  })
})

describe('export + empty states', () => {
  it('exports the filtered set as JSON via a real download', async () => {
    const user = userEvent.setup()
    const createUrl = vi.fn(() => 'blob:mock')
    const revokeUrl = vi.fn()
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: createUrl, revokeObjectURL: revokeUrl }))
    const clicks = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)

    renderReceipts()
    const table = await screen.findByTestId('receipts-table', undefined, { timeout: 5000 })
    await within(table).findByText('File change saved')

    // Filter down to one receipt, then export JSON.
    await user.type(screen.getByTestId('receipts-search'), 'backup')
    await user.click(screen.getByTestId('receipts-export-menu'))
    await user.click(await screen.findByTestId('receipts-export-json'))

    expect(createUrl).toHaveBeenCalled()
    expect(clicks).toHaveBeenCalled()
    const toasts = useSessionStore.getState().toasts
    expect(toasts.some((t) => t.title === 'Receipts exported' && t.body?.includes('1 receipt'))).toBe(true)
  })

  it('shows the design empty state when there are no receipts', async () => {
    const client = getClient()
    vi.spyOn(client.receipts, 'list').mockResolvedValue([])
    renderReceipts()
    expect(await screen.findByText('No receipts yet', undefined, { timeout: 5000 })).toBeTruthy()
    expect(
      screen.getByText('When you approve, run, save, or export something in this application, the record will appear here.'),
    ).toBeTruthy()
  })
})

describe('mobile presentation', () => {
  it('defaults to the timeline and collapses filters into a badge button', async () => {
    const original = window.matchMedia
    window.matchMedia = ((query: string) => ({
      matches: true,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    })) as typeof window.matchMedia
    try {
      renderReceipts()
      // Timeline is the mobile default (it scans better narrow).
      expect(await screen.findByTestId('receipts-timeline', undefined, { timeout: 5000 })).toBeTruthy()
      // Facets collapse into a Filter button.
      expect(screen.getByTestId('receipts-filter-button')).toBeTruthy()
      expect(screen.queryByTestId('receipts-filter-result')).toBeNull()
    } finally {
      window.matchMedia = original
    }
  })
})

describe('registrations', () => {
  it('registers the receipts commands and the saved-filters nav panel', async () => {
    const { useCommandStore } = await import('@/shell/commands')
    const { useWorkbenchSlots } = await import('@/shell/workbench/WorkbenchSlots')
    renderReceipts()
    await screen.findByTestId('receipts-table', undefined, { timeout: 5000 })

    const commands = useCommandStore.getState().commands
    for (const id of [
      'receipts.search',
      'receipts.toggle_view',
      'receipts.toggle_group',
      'receipts.verify',
      'receipts.copy_id',
      'receipts.export_json',
      'receipts.export_csv',
    ]) {
      expect(commands[id], id).toBeTruthy()
    }
    expect(useWorkbenchSlots.getState().toolPanels.receipts).toBeTruthy()
  })
})
