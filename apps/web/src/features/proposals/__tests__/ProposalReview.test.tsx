import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { RunRecord } from '@/client'
import { fileProposalOf } from '@/client/proposals'
import { RunWorkspace } from '@/features/runs/RunWorkspace'

import { ProposalReview } from '../ProposalReview'
import { fileProposalRun } from './fixtures'

afterEach(cleanup)

function renderReview(run: RunRecord, busy = false) {
  const onApply = vi.fn(() => Promise.resolve())
  const onReject = vi.fn(() => Promise.resolve())
  render(<ProposalReview run={run} proposal={fileProposalOf(run)!} busy={busy} onApply={onApply} onReject={onReject} />)
  return { onApply, onReject }
}

describe('ProposalReview', () => {
  it('shows files, the evaluator before → after, the route and duration, and offers Apply and Reject', async () => {
    const { onApply, onReject } = renderReview(fileProposalRun())
    const files = within(screen.getByTestId('proposal-files')).getAllByTestId('proposal-file')
    expect(files.map((file) => file.getAttribute('data-change'))).toEqual(['modified', 'added', 'deleted', 'renamed', 'modified'])
    expect(files[0].textContent).toContain('+3 −3')
    expect(files[4].textContent).toContain('binary')
    expect(screen.getByTestId('verdict-before').getAttribute('data-verdict')).toBe('not_yet')
    expect(screen.getByTestId('verdict-after').getAttribute('data-verdict')).toBe('passed')
    expect(screen.getByText('STATE.yaml:')).toBeTruthy()
    expect(screen.getByTestId('proposal-route').textContent).toBe('opencode/deepseek-v4.1-flash-free via opencode 1.18.31')
    expect(screen.getByTestId('proposal-duration').textContent).toBe('41 s')
    expect(screen.getByText('Filled in the next action and logged today.')).toBeTruthy()
    expect(screen.getAllByTestId('patch-file')).toHaveLength(5)

    await userEvent.click(screen.getByTestId('proposal-apply'))
    expect(onApply).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByTestId('proposal-reject'))
    expect(onReject).toHaveBeenCalledTimes(1)
  })

  it('disables both decisions while busy', () => {
    renderReview(fileProposalRun(), true)
    expect((screen.getByTestId('proposal-apply') as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByTestId('proposal-reject') as HTMLButtonElement).disabled).toBe(true)
  })

  it('offers only Apply once the proposal is approved but not applied', () => {
    renderReview(fileProposalRun({ status: 'state_change_approved' }))
    expect(screen.getByTestId('proposal-apply').textContent).toContain('Apply approved change')
    expect(screen.queryByTestId('proposal-reject')).toBeNull()
  })

  it('after apply shows the commit and the evaluator re-run, with no decision controls', () => {
    renderReview(fileProposalRun({
      status: 'applied',
      state: 'applied',
      receipt: { finalGit: 'd'.repeat(40), evaluator: { after: { verdict: 'passed', summary: 'Gate is green after apply.' } } },
    }))
    expect(screen.getByTestId('proposal-commit').textContent).toContain(`commit ${'d'.repeat(12)}`)
    expect(screen.getByTestId('proposal-applied-verdict').getAttribute('data-verdict')).toBe('passed')
    expect(screen.getByText('Gate is green after apply.')).toBeTruthy()
    expect(screen.getByText(/not an acceptance/)).toBeTruthy()
    expect(screen.queryByTestId('proposal-controls')).toBeNull()
  })

  it('records a rejection without controls and warns when the check gets worse', () => {
    renderReview(fileProposalRun({ status: 'state_change_rejected' }, {
      evaluator: { before: { verdict: 'passed' }, after: { verdict: 'invalid', summary: 'STATE.yaml no longer parses.' } },
    }))
    expect(screen.getByText('The proposal was discarded. Nothing in the application changed.')).toBeTruthy()
    expect(screen.getByText('The check is worse after this change')).toBeTruthy()
    expect(screen.queryByTestId('proposal-controls')).toBeNull()
  })

  it('cannot apply a proposal that carries no patch; it can only be rejected', () => {
    renderReview(fileProposalRun({}, { patch: '' }))
    expect(screen.queryByTestId('proposal-apply')).toBeNull()
    expect(screen.getByTestId('proposal-reject')).toBeTruthy()
    expect(screen.getByText('Nothing to review')).toBeTruthy()
  })
})

describe('RunWorkspace proposal views', () => {
  function workspace(run: RunRecord, onApplyProposal?: () => Promise<unknown>) {
    const onTransition = vi.fn(() => Promise.resolve())
    render(
      <RunWorkspace
        run={run}
        busy={false}
        transitionError={null}
        onTransition={onTransition}
        onRefresh={() => undefined}
        onNewRun={() => undefined}
        onOpenEvidence={() => undefined}
        onApplyProposal={onApplyProposal}
      />,
    )
    return onTransition
  }

  it('uses ProposalReview for a files proposal, with one Apply that approves then applies', async () => {
    const applyProposal = vi.fn(() => Promise.resolve())
    const onTransition = workspace(fileProposalRun(), applyProposal)
    expect(screen.getByTestId('proposal-review')).toBeTruthy()
    // The generic two-step controls are replaced by the review's own decision.
    expect(screen.queryByTestId('run-proposal-approve')).toBeNull()
    await userEvent.click(screen.getByTestId('proposal-apply'))
    expect(applyProposal).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByTestId('proposal-reject'))
    expect(onTransition).toHaveBeenCalledWith('proposal-reject')
  })

  it('keeps the semantic proposal view for typed (non-file) proposals', () => {
    workspace(fileProposalRun({ proposal: { proposalId: 'p', operations: [{ operation: 'replace', path: 'state/STUDY.yaml' }] } }))
    expect(screen.queryByTestId('proposal-review')).toBeNull()
    expect(screen.getByTestId('run-proposal-operations')).toBeTruthy()
    expect(screen.getByTestId('run-proposal-approve')).toBeTruthy()
  })
})
