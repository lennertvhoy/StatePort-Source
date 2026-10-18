/**
 * ApprovalsPage — inbox behavior against the real MockClient boundary:
 * pending count matches the seed, fresh-digest approval produces a receipt
 * link, the stale-plan guard is honest (and stays honest after revalidation),
 * destructive approvals demand exact-target typed confirmation, decision
 * availability follows the authoritative route, and the empty inbox renders
 * the canonical copy.
 *
 * Note: @testing-library/jest-dom is not installed — assertions use plain
 * matchers on textContent / disabled / getAttribute.
 */
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { Approval } from '@/client'
import { getClient, resetClientForTests, useScenarioStore } from '@/client'
import { buildSeed } from '@/client/mock/seed'
import { useBridgeStore } from '@/features/bridge/bridgeStore'
import { useSessionStore } from '@/state'

import ApprovalsPage from '../ApprovalsPage'

function renderApprovals(initial = '/approvals') {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/approvals" element={<ApprovalsPage />} />
        <Route path="/approvals/:approvalId" element={<ApprovalsPage />} />
        <Route path="/app/:instanceId/conversation" element={<div data-testid="conversation-page" />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  resetClientForTests()
  useBridgeStore.getState().clear()
  useSessionStore.setState({ operationsMutationCount: 0 })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  useScenarioStore.getState().setActive(null)
  resetClientForTests()
  useSessionStore.setState({ operationsMutationCount: 0 })
})

describe('ApprovalsPage', () => {
  it('shows a pending count matching the seed', async () => {
    renderApprovals('/approvals')
    // The header renders immediately; wait for the loaded count.
    expect((await screen.findByText('1 pending')).dataset.testid).toBe('pending-count')
    const rows = await screen.findAllByTestId('approval-row')
    expect(rows).toHaveLength(1)
    expect(rows[0].textContent).toContain('Start virtual machine')
    expect(rows[0].textContent).toContain('Elevated')
  })

  it('binds the rendered plan digest to its exact approval identity', async () => {
    const expected = await getClient().approvals.get('appr_0001')
    renderApprovals('/approvals/appr_0001')

    const digest = await screen.findByTestId('approval-plan-digest')
    expect(digest.getAttribute('data-digest')).toBe(expected.planDigest.value)
    expect(digest.getAttribute('aria-label')).toBe(expected.planDigest.value)
    expect(digest.textContent).toContain(
      `${expected.planDigest.value.slice(0, 8)}…${expected.planDigest.value.slice(-6)}`,
    )
  })

  it('approving with a fresh digest produces a receipt link', async () => {
    const user = userEvent.setup()
    renderApprovals('/approvals/appr_0001')

    const approve = await screen.findByTestId('approve-button')
    await user.click(approve)

    const result = await screen.findByTestId('decision-result', undefined, { timeout: 4000 })
    expect(result.textContent).toContain('Approved')
    const link = within(result).getByTestId('receipt-link')
    expect(link.textContent).toBe('View receipt')
    expect(link.getAttribute('href')).toMatch(/#?\/app\/[^/]+\/workbench\/receipts\/rcpt_\d+/)
    expect(useSessionStore.getState().operationsMutationCount).toBe(0)
  })

  it('uses the native receipt routes when the approved application has no Workbench', async () => {
    const client = getClient()
    const instance = buildSeed().instances.find(({ id }) => id === 'ins_study_alpha')
    if (!instance) throw new Error('StudyState fixture is missing from the mock seed.')
    const base = await client.approvals.get('appr_0001')
    const approved: Approval = {
      ...base,
      instanceId: instance.id,
      status: 'approved',
      decidedAt: new Date().toISOString(),
      resultingReceiptId: 'rcpt_0004',
    }
    vi.spyOn(client.applications, 'get').mockResolvedValue(instance)
    vi.spyOn(client.approvals, 'list').mockResolvedValue([approved])
    vi.spyOn(client.approvals, 'get').mockResolvedValue(approved)

    renderApprovals('/approvals/appr_0001')
    const result = await screen.findByTestId('decision-result')
    expect(within(result).getByTestId('receipt-link').getAttribute('href')).toBe(
      '/app/ins_study_alpha/receipts/rcpt_0004',
    )
    expect(screen.getByRole('link', { name: 'Previous receipts for this application' }).getAttribute('href')).toBe(
      '/app/ins_study_alpha/receipts',
    )
  })

  it('stale digest blocks approval with an honest out-of-date guard', async () => {
    useScenarioStore.getState().setActive('approval_stale')
    const user = userEvent.setup()
    renderApprovals('/approvals/appr_0001')

    const guard = await screen.findByTestId('stale-guard')
    expect(guard.textContent).toContain('This plan is out of date')
    expect(guard.textContent).toContain('The repository changed after it was prepared')
    // No approve action is offered while the plan is stale.
    expect(screen.queryByTestId('approve-button')).toBeNull()

    // Revalidation reloads the truth; still stale → honest note, no silent recovery.
    await user.click(screen.getByRole('button', { name: /revalidate plan/i }))
    const note = await screen.findByText(/still out of date/i, undefined, { timeout: 4000 })
    expect(note).toBeTruthy()
    expect(screen.queryByTestId('approve-button')).toBeNull()
  })

  it('destructive approval demands typed exact-target confirmation', async () => {
    const client = getClient()
    const base = await client.approvals.get('appr_0001')
    const destructive: Approval = {
      ...base,
      title: 'Destroy virtual machine',
      operationType: 'Infrastructure · VM destroy',
      risk: 'high',
      scope: [
        'Target: homelab-dev (local virtual machine)',
        'Operation: destroy',
        'Repository: nixos-homelab @ main (clean)',
      ],
    }
    vi.spyOn(client.approvals, 'list').mockResolvedValue([destructive])
    vi.spyOn(client.approvals, 'get').mockResolvedValue(destructive)

    const user = userEvent.setup()
    renderApprovals('/approvals/appr_0001')

    await user.click(await screen.findByTestId('approve-button'))

    const dialog = await screen.findByTestId('confirm-dialog')
    expect(dialog.textContent).toContain('homelab-dev')
    const confirm = within(dialog).getByTestId('confirm-action') as HTMLButtonElement
    expect(confirm.disabled).toBe(true)

    const typed = within(dialog).getByTestId('confirm-typed-input')
    await user.type(typed, 'homelab')
    expect(confirm.disabled).toBe(true)

    await user.clear(typed)
    await user.type(typed, 'homelab-dev')
    expect(confirm.disabled).toBe(false)

    await user.click(confirm)
    const result = await screen.findByTestId('decision-result', undefined, { timeout: 4000 })
    expect(result.textContent).toContain('Approved')
  })

  it('renders and decides a fresh state-change proposal from its typed route', async () => {
    const client = getClient()
    const base = await client.approvals.get('appr_0001')
    const proposal: Approval = {
      ...base,
      id: 'run_proposal:run_7',
      kind: 'orchestration_run',
      title: 'Approve proposed application changes',
      operationType: 'run_proposal',
      runId: 'run_7',
      expiresAt: undefined,
      decision: {
        kind: 'run_proposal',
        expectedInstanceId: base.instanceId,
        expectedRevision: 7,
        expectedDigest: base.planDigest.value,
      },
    }
    vi.spyOn(client.approvals, 'list').mockResolvedValue([proposal])
    vi.spyOn(client.approvals, 'get').mockResolvedValue(proposal)
    const approve = vi.spyOn(client.approvals, 'approve').mockResolvedValue({
      approval: { ...proposal, status: 'approved' },
    })

    const user = userEvent.setup()
    renderApprovals('/approvals/run_proposal:run_7')

    expect(await screen.findByText('/v1/runs/run_7/proposal-approve')).toBeTruthy()
    expect(screen.getByText('/v1/runs/run_7/proposal-reject')).toBeTruthy()
    expect(screen.getByText('No automatic expiry')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Reject' })).toBeTruthy()
    await user.click(screen.getByTestId('approve-button'))

    expect(approve).toHaveBeenCalledWith(proposal.id, {
      expectedDigest: proposal.planDigest.value,
    })
    expect((await screen.findByTestId('decision-result')).textContent).toContain('Approved')
  })

  it('hides Reject when the indexed authority only supports approval', async () => {
    renderApprovals('/approvals/appr_0001')
    await screen.findByTestId('approve-button')
    expect(screen.queryByRole('button', { name: 'Reject' })).toBeNull()
    expect(screen.getByText(/infrastructure\/approve$/).textContent).toContain('/v1/instances/')
  })

  it('opens the related conversation with the reviewed approval as explicit context', async () => {
    const client = getClient()
    const base = await client.approvals.get('appr_0001')
    const related: Approval = {
      ...base,
      relatedConversationId: 'conv_review',
    }
    vi.spyOn(client.approvals, 'list').mockResolvedValue([related])
    vi.spyOn(client.approvals, 'get').mockResolvedValue(related)

    const user = userEvent.setup()
    renderApprovals('/approvals/appr_0001')
    await user.click(await screen.findByRole('link', { name: 'Related conversation' }))

    expect(await screen.findByTestId('conversation-page')).toBeTruthy()
    expect(useBridgeStore.getState().peek(related.instanceId)).toEqual([
      {
        kind: 'approval',
        instanceId: related.instanceId,
        approvalId: related.id,
      },
    ])
  })

  it('offers an explicit Conversation bridge even without a related thread identity', async () => {
    const client = getClient()
    const base = await client.approvals.get('appr_0001')
    const standalone: Approval = {
      ...base,
      relatedConversationId: undefined,
    }
    vi.spyOn(client.approvals, 'list').mockResolvedValue([standalone])
    vi.spyOn(client.approvals, 'get').mockResolvedValue(standalone)

    const user = userEvent.setup()
    renderApprovals('/approvals/appr_0001')
    await user.click(
      await screen.findByRole('link', { name: 'Review approval in Conversation' }),
    )

    expect(await screen.findByTestId('conversation-page')).toBeTruthy()
    expect(useBridgeStore.getState().peek(standalone.instanceId)).toEqual([
      {
        kind: 'approval',
        instanceId: standalone.instanceId,
        approvalId: standalone.id,
      },
    ])
  })

  it('does not present proposal rejection for an initial run approval', async () => {
    const client = getClient()
    const base = await client.approvals.get('appr_0001')
    const runApproval: Approval = {
      ...base,
      id: 'run_approval:run_7',
      kind: 'orchestration_run',
      operationType: 'run_approval',
      runId: 'run_7',
      decision: {
        kind: 'run_approval',
        expectedInstanceId: base.instanceId,
        expectedRevision: 4,
        expectedDigest: base.planDigest.value,
      },
    }
    vi.spyOn(client.approvals, 'list').mockResolvedValue([runApproval])
    vi.spyOn(client.approvals, 'get').mockResolvedValue(runApproval)

    renderApprovals('/approvals/run_approval:run_7')
    expect(await screen.findByText('/v1/runs/run_7/approve')).toBeTruthy()
    expect(screen.queryByText('/v1/runs/run_7/proposal-reject')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Reject' })).toBeNull()
  })

  it('renders the canonical empty-inbox copy', async () => {
    useScenarioStore.getState().setActive('approvals_empty')
    renderApprovals('/approvals')
    expect(await screen.findByText('No pending approvals')).toBeTruthy()
    expect(
      screen.getByText('Actions that need your confirmation will appear here before they change an application.'),
    ).toBeTruthy()
    expect(screen.getByTestId('pending-count').textContent).toBe('0 pending')
  })
})
