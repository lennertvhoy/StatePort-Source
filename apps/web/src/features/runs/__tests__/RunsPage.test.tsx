import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { getClient, resetClientForTests, resetMockState } from '@/client'
import { buildSeed, INSTANCE_IDS } from '@/client/mock/seed'
import type { CapabilityId, CapabilityState } from '@/client'
import { InstanceContext, type CurrentInstanceContext } from '@/shell/currentInstance'

import RunsPage from '../RunsPage'
import { receiptBasePathFor } from '../runsModel'

async function renderAt(route: string) {
  window.location.hash = route
  return render(<App />)
}

beforeEach(() => {
  resetClientForTests()
  resetMockState()
})

afterEach(() => {
  cleanup()
  window.location.hash = ''
  resetClientForTests()
})

describe('Governed Runs route', () => {
  it('uses the native receipt destination when Workbench is capable but not resolved', () => {
    const seeded = buildSeed().instances.find((item) => item.id === INSTANCE_IDS.studyAlpha)
    expect(seeded).toBeDefined()
    const instance = {
      ...seeded!,
      capabilities: [
        ...seeded!.capabilities,
        { id: 'workbench' as const, status: 'available' as const },
      ],
      experienceResolution: 'resolved' as const,
      experience: {
        formatVersion: 'stateport.application-experience-resolution/v1' as const,
        applicationId: 'studydd',
        views: [],
        navigation: [],
        advancedControls: [
          {
            controlId: 'study-runs',
            label: 'Runs',
            component: 'run_history' as const,
            capability: 'goal_execution' as const,
            order: 25,
            status: 'available' as const,
            reasons: [],
            visible: true,
          },
          {
            controlId: 'study-receipts',
            label: 'Receipts',
            component: 'receipt_list' as const,
            capability: 'receipts' as const,
            order: 35,
            status: 'available' as const,
            reasons: [],
            visible: true,
          },
        ],
      },
    }

    expect(receiptBasePathFor(instance)).toBe('/app/ins_study_alpha/receipts')
  })

  it('is app-level for StudyState and walks the exact proposal lifecycle', async () => {
    const user = userEvent.setup()
    await renderAt('#/app/ins_study_alpha/runs')

    const page = await screen.findByTestId('runs-stub', undefined, { timeout: 10_000 })
    expect(window.location.hash).toBe('#/app/ins_study_alpha/runs')
    expect(screen.queryByText('Workbench', { selector: 'a' })).toBeNull()

    await user.click(within(page).getByTestId('runs-action-act_update_sample'))
    const value = await screen.findByLabelText(/Value/)
    await user.type(value, 'reviewed-value')

    await user.click(screen.getByTestId('run-prepare'))
    expect((await screen.findByTestId('run-exact-status')).textContent).toContain('Awaiting Approval')
    expect(screen.getByText(/does not execute the run/i)).toBeTruthy()

    await user.click(screen.getByTestId('run-approve'))
    await waitFor(() => {
      expect(screen.getByTestId('run-exact-status').textContent).toContain('Approved')
    })
    expect(await screen.findByText(/Approved, not executed/)).toBeTruthy()

    await user.click(screen.getByTestId('run-execute'))
    await waitFor(() => {
      expect(screen.getByTestId('run-exact-status').textContent).toContain('State Change Proposed')
    })
    expect(screen.getByTestId('run-proposal-operations').textContent).toContain('state/SAMPLE.yaml')
    expect(screen.queryByTestId('run-apply')).toBeNull()

    await user.click(screen.getByTestId('run-proposal-approve'))
    await waitFor(() => {
      expect(screen.getByTestId('run-exact-status').textContent).toContain('State Change Approved')
    })
    expect(await screen.findByText(/Proposal approved, not applied/)).toBeTruthy()

    await user.click(screen.getByTestId('run-apply'))
    await waitFor(() => {
      expect(screen.getByTestId('run-exact-status').textContent).toContain('Applied')
    })
    expect(screen.getByTestId('run-validation-truth').textContent).toContain('passed')
    expect(screen.getByText(/Human acceptance and remote acceptance are not implied/)).toBeTruthy()

    await user.click(screen.getByTestId('run-open-evidence'))
    const bundle = await screen.findByTestId('run-bundle')
    expect(bundle.textContent).toContain('Verified')
    expect(await screen.findByTestId('run-statebench')).toBeTruthy()
    expect(screen.getByText(/non-authoritative evidence vector/)).toBeTruthy()
    await user.click(screen.getByText('Raw evidence JSON'))
    expect((await screen.findByTestId('run-raw-json')).textContent).not.toContain('/var/')

    const receiptLink = screen.getByRole('link', { name: /^rcpt_/ })
    await user.click(receiptLink)
    expect(window.location.hash).toMatch(
      /^#\/app\/ins_study_alpha\/receipts\/rcpt_/,
    )
    expect(await screen.findByTestId('receipt-detail')).toBeTruthy()
    expect(screen.getByTestId('receipt-caveat')).toBeTruthy()
  }, 30_000)

  it('fails closed on a direct route without goal_execution', async () => {
    await renderAt('#/app/ins_checklist_sample/runs')
    expect(await screen.findByTestId('app-overview-stub', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(window.location.hash).toBe('#/app/ins_checklist_sample')
    expect(await screen.findByText(/Runs is not part of this application/i)).toBeTruthy()
    expect(screen.queryByTestId('run-prepare')).toBeNull()
  }, 15_000)

  it('does not request StateBench when benchmark_evidence is not usable', async () => {
    const user = userEvent.setup()
    const seeded = buildSeed().instances.find((item) => item.id === INSTANCE_IDS.studyAlpha)
    expect(seeded).toBeDefined()
    const instance = {
      ...seeded!,
      capabilities: seeded!.capabilities.filter((entry) => entry.id !== 'benchmark_evidence'),
    }
    const capabilities = new Map<CapabilityId, CapabilityState>(
      instance.capabilities.map((entry) => [entry.id, entry]),
    )
    const context: CurrentInstanceContext = {
      instance,
      capabilities,
      loading: false,
      error: null,
      refresh: () => undefined,
      hasCapability: (id) => {
        const state = capabilities.get(id)
        return state?.status === 'available' || state?.status === 'degraded'
      },
      capability: (id) => capabilities.get(id),
    }
    const stateBenchSpy = vi.spyOn(getClient().runs, 'getStateBench')
    render(
      <MemoryRouter>
        <InstanceContext.Provider value={context}>
          <RunsPage />
        </InstanceContext.Provider>
      </MemoryRouter>,
    )

    await screen.findByTestId('runs-stub')
    await user.click(screen.getByTestId('run-prepare'))
    await screen.findByTestId('run-exact-status')
    await user.click(screen.getByTestId('run-approve'))
    await waitFor(() => {
      expect(screen.getByTestId('run-exact-status').textContent).toContain('Approved')
    })
    await user.click(screen.getByTestId('run-execute'))
    await waitFor(() => {
      expect(screen.getByTestId('run-exact-status').textContent).toContain('Completed')
    })
    await user.click(screen.getByTestId('run-open-evidence'))
    expect(await screen.findByTestId('run-statebench-gated')).toBeTruthy()
    expect(stateBenchSpy).not.toHaveBeenCalled()
  }, 20_000)
})
