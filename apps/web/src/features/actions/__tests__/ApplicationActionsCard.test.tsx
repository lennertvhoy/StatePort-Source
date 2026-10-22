import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ApplicationInstance, ExecutionEngine, GovernedAction, RunOperation, RunRecord } from '@/client'
import { getClient, resetClientForTests } from '@/client'
import { setModelsClientForTests } from '@/client/modelsClient'
import { FREE, consentedProjection, fakeModelsClient, modelsView, routedWithoutConsent } from '@/features/models/__tests__/fakeModels'
import { fileProposalRun } from '@/features/proposals/__tests__/fixtures'

import { ApplicationActionsCard } from '../ApplicationActionsCard'

const INSTANCE = { id: 'ins_project', name: 'My project' } as ApplicationInstance

const ENGINES: ExecutionEngine[] = [
  { id: 'synthetic', label: 'Synthetic', kind: 'synthetic', availability: 'available', available: true, limitations: [] },
  { id: 'opencode', label: 'OpenCode', kind: 'opencode', availability: 'available', available: true, limitations: [] },
]

const GATE: GovernedAction = { id: 'projectstate.gate/v1', instanceId: INSTANCE.id, title: 'Check the gate', description: 'Runs the ProjectState gate.', engineIds: [], kind: 'check' }
const NEXT: GovernedAction = { id: 'projectstate.next-action/v1', instanceId: INSTANCE.id, title: 'Plan the next action', engineIds: [], kind: 'agent', timeoutSeconds: 300 }
const SETUP: GovernedAction = {
  id: 'projectstate.setup-project/v1',
  instanceId: INSTANCE.id,
  title: 'Set up the project',
  engineIds: [],
  kind: 'agent',
  inputSchema: {
    type: 'object',
    required: ['project', 'outcome'],
    properties: {
      project: { type: 'string', title: 'Project name', maxLength: 20 },
      outcome: { type: 'string', maxLength: 600 },
      firstSlice: { type: 'string', maxLength: 200 },
    },
  },
}
const LEGACY: GovernedAction = { id: 'studystate.record/v1', instanceId: INSTANCE.id, title: 'Record', engineIds: [] }

function runOf(action: GovernedAction, overrides: Partial<RunRecord>): RunRecord {
  return {
    id: `run_${action.id}`, instanceId: INSTANCE.id, actionId: action.id, engineId: 'synthetic', state: 'awaiting_approval',
    status: 'awaiting_approval', revision: 1, inputs: {}, createdAt: '2026-10-21T08:00:00Z', updatedAt: '2026-10-21T08:00:00Z',
    ...overrides,
  }
}

function stubRuns(actions: GovernedAction[], history: RunRecord[] = []) {
  const runs = getClient().runs
  vi.spyOn(runs, 'listActions').mockResolvedValue(actions)
  vi.spyOn(runs, 'listEngines').mockResolvedValue(ENGINES)
  vi.spyOn(runs, 'getHistory').mockResolvedValue(history)
  const prepare = vi.spyOn(runs, 'prepare')
  const transition = vi.spyOn(runs, 'transition')
  return { prepare, transition }
}

/** prepare → awaiting_approval, approve → approved, execute → `executed`. */
function scriptRun(stub: ReturnType<typeof stubRuns>, action: GovernedAction, executed: Partial<RunRecord>, after: Partial<Record<RunOperation, Partial<RunRecord>>> = {}) {
  stub.prepare.mockImplementation(async (_instanceId, input) => runOf(action, { engineId: input.engineId, inputs: input.inputs }))
  stub.transition.mockImplementation(async (_runId, operation, input) => {
    const base = runOf(action, { revision: input.expectedRevision + 1 })
    if (operation === 'approve') return { ...base, status: 'approved', state: 'approved' }
    if (operation === 'execute') return { ...base, ...executed, revision: input.expectedRevision + 1 }
    return { ...base, ...after[operation], revision: input.expectedRevision + 1 }
  })
}

function renderCard() {
  return render(
    <MemoryRouter>
      <ApplicationActionsCard instance={INSTANCE} readOnly={false} canOpenRuns />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  resetClientForTests()
})
afterEach(() => {
  cleanup()
  setModelsClientForTests(null)
})

describe('application actions card', () => {
  it('lists check and agent actions with kind badges and leaves typed actions to the Runs page', async () => {
    setModelsClientForTests(fakeModelsClient(modelsView()))
    stubRuns([GATE, NEXT, LEGACY])
    renderCard()
    const gate = await screen.findByTestId(`action-row-${GATE.id}`)
    expect(within(gate).getByText('Check')).toBeTruthy()
    expect(within(screen.getByTestId(`action-row-${NEXT.id}`)).getByText('Agent')).toBeTruthy()
    expect(screen.queryByTestId(`action-row-${LEGACY.id}`)).toBeNull()
  })

  it('states the empty case plainly', async () => {
    stubRuns([LEGACY])
    renderCard()
    expect((await screen.findByTestId('application-actions-empty')).textContent).toContain('other governed actions are on the Runs page')
  })

  it('runs a check with one click (prepare → approve → execute) and shows its verdict', async () => {
    const stub = stubRuns([GATE])
    scriptRun(stub, GATE, {
      status: 'result_validating', lifecycleState: 'CLOSED', state: 'completed_without_change',
      result: { evaluator: { verdict: 'not_yet', summary: 'Two gate checks fail.', findings: [{ path: 'STATE.yaml', message: 'next_action is empty' }] } },
    })
    renderCard()
    await userEvent.click(await screen.findByTestId(`action-run-${GATE.id}`))
    const verdict = await screen.findByTestId(`action-verdict-${GATE.id}`)
    expect(verdict.querySelector('[data-verdict]')?.getAttribute('data-verdict')).toBe('not_yet')
    expect(within(verdict).getByText('Two gate checks fail.')).toBeTruthy()
    expect(within(verdict).getByText('next_action is empty')).toBeTruthy()
    expect(stub.prepare).toHaveBeenCalledWith(INSTANCE.id, { actionId: GATE.id, engineId: 'synthetic', inputs: {} })
    expect(stub.transition.mock.calls.map((call) => call[1])).toEqual(['approve', 'execute'])
  })

  it('without consent explains why an agent action cannot run and links to Settings → Models', async () => {
    setModelsClientForTests(fakeModelsClient(modelsView(routedWithoutConsent())))
    stubRuns([NEXT])
    renderCard()
    const link = await screen.findByTestId(`action-models-link-${NEXT.id}`)
    expect(link.getAttribute('href')).toBe('/settings/models')
    expect(screen.getByText('Free models need your consent')).toBeTruthy()
    expect((screen.getByTestId(`action-run-${NEXT.id}`) as HTMLButtonElement).disabled).toBe(true)
  })

  it('keeps agent actions off when model routes cannot be read', async () => {
    setModelsClientForTests(fakeModelsClient(() => Promise.reject(new Error('offline'))))
    stubRuns([NEXT])
    renderCard()
    expect(await screen.findByText('Agent actions are off')).toBeTruthy()
    expect((screen.getByTestId(`action-run-${NEXT.id}`) as HTMLButtonElement).disabled).toBe(true)
  })

  it('with a consented route says what is sent where, confirms it, then runs in one click and opens the proposal for Apply', async () => {
    setModelsClientForTests(fakeModelsClient(modelsView(consentedProjection())))
    const stub = stubRuns([NEXT])
    const proposed = fileProposalRun({ id: `run_${NEXT.id}`, actionId: NEXT.id, instanceId: INSTANCE.id })
    scriptRun(stub, NEXT, proposed, {
      'proposal-approve': { ...proposed, status: 'state_change_approved' },
      apply: { ...proposed, status: 'applied', state: 'applied', receipt: { finalGit: 'e'.repeat(40) } },
    })
    renderCard()
    const route = await screen.findByTestId(`action-route-${NEXT.id}`)
    expect(route.textContent).toContain(`a copy of this application's files and the action's instructions to ${FREE}`)
    await userEvent.click(screen.getByTestId(`action-run-${NEXT.id}`))
    // The owner's click is the approval, but only after the confirmation names
    // the route and what leaves the machine.
    const confirm = screen.getByTestId(`action-confirm-${NEXT.id}`)
    expect(confirm.textContent).toContain(`A copy of this application's files and the action's instructions go to ${FREE}`)
    expect(stub.prepare).not.toHaveBeenCalled()
    await userEvent.click(within(confirm).getByTestId(`action-confirm-run-${NEXT.id}`))
    const review = await screen.findByTestId('proposal-review')
    expect(stub.prepare).toHaveBeenCalledWith(INSTANCE.id, { actionId: NEXT.id, engineId: 'opencode', inputs: {} })
    await userEvent.click(within(review).getByTestId('proposal-apply'))
    await waitFor(() => expect(screen.getByTestId('proposal-review').getAttribute('data-status')).toBe('applied'))
    expect(stub.transition.mock.calls.map((call) => call[1])).toEqual(['approve', 'execute', 'proposal-approve', 'apply'])
    expect(screen.getByTestId('proposal-commit').textContent).toContain('e'.repeat(12))
  })

  it('setup with inputs: highlighted first, opens a schema form, confirms the words and the route, then sends them', async () => {
    setModelsClientForTests(fakeModelsClient(modelsView(consentedProjection())))
    const stub = stubRuns([GATE, SETUP])
    scriptRun(stub, SETUP, { status: 'completed', state: 'completed_without_change', result: { summary: 'Nothing to change.' } })
    renderCard()
    const rows = await screen.findAllByTestId(/^action-row-/)
    expect(rows[0].getAttribute('data-testid')).toBe(`action-row-${SETUP.id}`)
    expect(within(rows[0]).getByText('Start here')).toBeTruthy()
    expect(screen.getByTestId('application-actions-setup-hint')).toBeTruthy()

    await userEvent.click(screen.getByTestId(`action-run-${SETUP.id}`))
    const form = screen.getByTestId(`action-form-${SETUP.id}`)
    expect(within(form).getByLabelText(/Project name/).getAttribute('maxLength')).toBe('20')
    expect(within(form).getAllByText('(required)')).toHaveLength(2)
    await userEvent.click(within(form).getByTestId(`action-form-review-${SETUP.id}`))
    expect(within(form).getByText('Project name is required.')).toBeTruthy()
    expect(stub.prepare).not.toHaveBeenCalled()

    await userEvent.type(within(form).getByLabelText(/Project name/), 'StatePort')
    await userEvent.type(within(form).getByLabelText(/Outcome/), 'Ship Alpha.26 to strangers')
    await userEvent.click(within(form).getByTestId(`action-form-review-${SETUP.id}`))
    const confirm = screen.getByTestId(`action-confirm-${SETUP.id}`)
    expect(confirm.textContent).toContain('StatePort')
    expect(confirm.textContent).toContain('Ship Alpha.26 to strangers')
    expect(confirm.textContent).toContain(`These words and a copy of the application go to ${FREE}`)
    expect(stub.prepare).not.toHaveBeenCalled()

    await userEvent.click(within(confirm).getByTestId(`action-confirm-run-${SETUP.id}`))
    await waitFor(() => expect(stub.prepare).toHaveBeenCalledWith(INSTANCE.id, {
      actionId: SETUP.id, engineId: 'opencode', inputs: { project: 'StatePort', outcome: 'Ship Alpha.26 to strangers' },
    }))
    expect(await screen.findByTestId(`action-no-change-${SETUP.id}`)).toBeTruthy()
  })

  it('opens a pending proposal from history for review; an applied one stays collapsed behind Show', async () => {
    setModelsClientForTests(fakeModelsClient(modelsView(consentedProjection())))
    stubRuns([NEXT], [fileProposalRun({ id: 'run_old', actionId: NEXT.id, instanceId: INSTANCE.id })])
    renderCard()
    expect(await screen.findByTestId('proposal-review')).toBeTruthy()
    cleanup()

    stubRuns([NEXT], [fileProposalRun({ id: 'run_done', actionId: NEXT.id, instanceId: INSTANCE.id, status: 'applied', state: 'applied' })])
    renderCard()
    const show = await screen.findByTestId(`action-review-${NEXT.id}`)
    expect(show.textContent).toBe('Show')
    expect(screen.queryByTestId('proposal-review')).toBeNull()
    await userEvent.click(show)
    expect(screen.getByTestId('proposal-review').getAttribute('data-status')).toBe('applied')
  })

  it('reports a refused preparation without running anything else', async () => {
    const stub = stubRuns([GATE])
    stub.prepare.mockRejectedValue(new Error('sandbox_unavailable: bubblewrap is not installed'))
    renderCard()
    await userEvent.click(await screen.findByTestId(`action-run-${GATE.id}`))
    expect((await screen.findByText('The run did not complete')).parentElement?.textContent).toContain('bubblewrap is not installed')
    expect(stub.transition).not.toHaveBeenCalled()
  })
})
