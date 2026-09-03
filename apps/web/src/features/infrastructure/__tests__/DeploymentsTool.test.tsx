/**
 * DeploymentsTool — binding behaviors from design/infrastructure.md:
 * distinct truths with honest semantics (never green-before-health), the ONE
 * blocked state with hidden controls, typed confirmation before destructive
 * prepare, plan-vs-run separation, and the receipt link of a successful run.
 */
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { getClient, resetClientForTests, resetMockState, useScenarioStore } from '@/client'
import type { AuthorizationGrant, ScenarioId } from '@/client'
import { INSTANCE_IDS } from '@/client/mock/seed'

import { AuthorizationCard } from '../AuthorizationCard'
import DeploymentsTool from '../DeploymentsTool'

const NIXOS = INSTANCE_IDS.nixosInfra

function renderTool() {
  return render(
    <MemoryRouter initialEntries={[`/app/${NIXOS}/workbench/deployments`]}>
      <Routes>
        <Route path="/app/:instanceId/workbench/deployments" element={<DeploymentsTool />} />
        <Route path="/app/:instanceId/workbench/receipts/:receiptId" element={<div data-testid="receipt-detail" />} />
        <Route path="/approvals/:approvalId" element={<div data-testid="approval-detail" />} />
      </Routes>
    </MemoryRouter>,
  )
}

function setScenario(id: ScenarioId | null) {
  useScenarioStore.getState().setActive(id)
}

beforeEach(() => {
  resetClientForTests()
  resetMockState()
  setScenario(null)
})

afterEach(() => {
  cleanup()
  setScenario(null)
  resetClientForTests()
})

describe('DeploymentsTool — distinct honest states', () => {
  it('renders a stopped VM as neutral everywhere (never red, never green)', async () => {
    renderTool()
    const vmFact = await screen.findByTestId('fact-vm')
    expect(vmFact.getAttribute('data-state')).toBe('neutral')
    expect(within(vmFact).getByText('Stopped')).toBeTruthy()

    const sshFact = screen.getByTestId('fact-ssh')
    expect(sshFact.getAttribute('data-state')).toBe('neutral')
    expect(within(sshFact).getByText(/SSH unavailable — VM stopped/)).toBeTruthy()

    // Health stays "not checked" (attention) — and nothing claims healthy.
    expect(screen.getByTestId('fact-health').getAttribute('data-state')).toBe('attention')
    expect(screen.queryByText('Healthy')).not.toBeTruthy()
    // The dominant badge is the neutral "Stopped".
    expect(within(screen.getByTestId('workbench-tool-header')).getByText('Stopped')).toBeTruthy()
  })

  it('shows a running-but-unchecked VM as neutral, never green or healthy', async () => {
    setScenario('vm_running_unchecked')
    renderTool()
    const vmFact = await screen.findByTestId('fact-vm')
    expect(vmFact.getAttribute('data-state')).toBe('neutral')
    expect(vmFact.getAttribute('data-state')).not.toBe('success')
    expect(within(vmFact).getByText('Running')).toBeTruthy()

    // The dominant badge names the caveat explicitly and is not green.
    const header = screen.getByTestId('workbench-tool-header')
    const badge = within(header).getByTestId('status-badge')
    expect(badge.getAttribute('data-state')).toBe('neutral')
    expect(within(badge).getByText('Running — health not checked')).toBeTruthy()

    expect(screen.getByTestId('fact-health').getAttribute('data-state')).toBe('attention')
    expect(screen.queryByText('Healthy')).not.toBeTruthy()
  })
})

describe('DeploymentsTool — unavailable target', () => {
  it('shows ONE blocked state and hides operation/grant controls', async () => {
    setScenario('deployment_target_unavailable')
    renderTool()
    const blocked = await screen.findByTestId('deployments-unavailable')
    expect(within(blocked).getByText('Target unavailable')).toBeTruthy()
    // What's missing + recovery actions.
    expect(within(blocked).getByTestId('unavailable-refresh')).toBeTruthy()
    expect(within(blocked).getByTestId('unavailable-review-config')).toBeTruthy()

    // No full disabled workflow behind it: no actions row, no plan card,
    // and no authorization/grant UI.
    expect(screen.queryByTestId('actions-row')).toBeNull()
    expect(screen.queryByTestId('plan-card')).toBeNull()
    expect(screen.queryByTestId('authorization-card')).toBeNull()
    expect(screen.queryByTestId('operations-menu-trigger')).toBeNull()
    expect(screen.queryByText('Propose authorization')).toBeNull()
  })

  it('hides the authorization panel specifically (grant flow needs a valid target)', async () => {
    setScenario('deployment_target_unavailable')
    renderTool()
    await screen.findByTestId('deployments-unavailable')
    expect(screen.queryByTestId('authorization-card')).toBeNull()
  })
})

describe('DeploymentsTool — authorization panel (valid target)', () => {
  it('renders the panel with covers / does-not-cover once a target exists', async () => {
    renderTool()
    const card = await screen.findByTestId('authorization-card')
    expect(within(card).getByTestId('authorization-covers')).toBeTruthy()
    expect(within(card).getByTestId('authorization-excludes')).toBeTruthy()
    expect(within(card).getByText('Graceful stop')).toBeTruthy()
    expect(within(card).getByText('Destroy the virtual machine')).toBeTruthy()
    expect(within(card).getByTestId('authorization-propose')).toBeTruthy()
  })

  it('proposes a grant, activates it after approval, and shows provenance', async () => {
    const user = userEvent.setup()
    renderTool()
    const propose = await screen.findByTestId('authorization-propose')
    await user.click(propose)

    // Proposed state: review-grant deep link appears.
    const review = await screen.findByTestId('authorization-review-grant', {}, { timeout: 5000 })
    expect(review).toBeTruthy()

    // Approve the grant in the Approvals domain (as the inbox would).
    const client = getClient()
    const pending = await client.approvals.list({ instanceId: NIXOS, status: 'pending' })
    const grantApproval = pending.find((a) => a.kind === 'authorization_grant')
    expect(grantApproval).toBeDefined()
    await client.approvals.approve(grantApproval!.id, { expectedDigest: grantApproval!.planDigest.value })

    // The card polls and offers Activate; after activation it shows expiry,
    // the creating receipt link, and Revoke.
    const activate = await screen.findByTestId('authorization-activate', {}, { timeout: 8000 })
    await user.click(activate)
    const card = await screen.findByTestId('authorization-card')
    expect(await within(card).findByText('Active')).toBeTruthy()
    expect(within(card).getByText('Grant receipt')).toBeTruthy()
    expect(within(card).getByTestId('authorization-revoke')).toBeTruthy()
  }, 15_000)

  it('hides revocation when the adapter has no durable revoke transition', async () => {
    const target = await getClient().infrastructure.getTarget(NIXOS)
    const grant: AuthorizationGrant = {
      id: 'grant_active',
      instanceId: NIXOS,
      targetId: target.id,
      status: 'active',
      covers: ['observe', 'validate', 'health_check'],
      doesNotCover: ['Destroy the virtual machine'],
      createdAt: '2026-07-19T10:00:00Z',
    }

    render(
      <MemoryRouter>
        <AuthorizationCard
          instanceId={NIXOS}
          target={target}
          grant={grant}
          busy={false}
          canRevoke={false}
          onPropose={async () => undefined}
          onActivate={async () => undefined}
          onRevoke={async () => undefined}
        />
      </MemoryRouter>,
    )

    const card = await screen.findByTestId('authorization-card')
    expect(within(card).queryByTestId('authorization-revoke')).toBeNull()
    expect(within(card).getByTestId('authorization-revoke-unavailable')).toBeTruthy()
  })
})

describe('DeploymentsTool — plan workflow', () => {
  it('requires typed target confirmation before preparing destruction', async () => {
    const user = userEvent.setup()
    renderTool()
    await screen.findByTestId('actions-row')

    await user.click(screen.getByTestId('operations-menu-trigger'))
    await user.click(await screen.findByTestId('prepare-destruction'))

    const dialog = await screen.findByTestId('confirm-dialog')
    const confirm = within(dialog).getByTestId('confirm-action')
    // Typed gate: confirm stays disabled until the exact target name is typed.
    expect((confirm as HTMLButtonElement).disabled).toBe(true)
    await user.type(within(dialog).getByTestId('confirm-typed-input'), 'wrong-name')
    expect((confirm as HTMLButtonElement).disabled).toBe(true)
    await user.clear(within(dialog).getByTestId('confirm-typed-input'))
    await user.type(within(dialog).getByTestId('confirm-typed-input'), 'homelab-dev')
    expect((confirm as HTMLButtonElement).disabled).toBe(false)
    await user.click(confirm)

    // The destruction plan is prepared — and still needs its own approval.
    const planCard = await screen.findByTestId('plan-card')
    expect(await within(planCard).findByText('Destroy virtual machine')).toBeTruthy()
    expect(await within(planCard).findByText('Awaiting approval')).toBeTruthy()
    expect(within(planCard).getByText('Go to approval')).toBeTruthy()
    // Destructive is never covered by the daily-driver authorization.
    expect(within(planCard).getByText(/never covered by a daily-driver authorization/)).toBeTruthy()
    expect(within(planCard).queryByTestId('plan-run')).toBeNull()
  })

  it('keeps plan and run separate: preparing shows review, not progress', async () => {
    const user = userEvent.setup()
    renderTool()
    await screen.findByTestId('actions-row')

    await user.click(screen.getByTestId('op-observe'))
    const planCard = await screen.findByTestId('plan-card')

    // Plan review content is visible…
    expect(await within(planCard).findByText('Observe target state')).toBeTruthy()
    expect(within(planCard).getByTestId('plan-stepper')).toBeTruthy()
    expect(within(planCard).getByTestId('plan-identity')).toBeTruthy()
    expect(within(planCard).getByText(/Read-only — no approval required/)).toBeTruthy()
    // …but no run has happened: no timeline, no logs, no receipt, Run offered.
    expect(await within(planCard).findByTestId('plan-run')).toBeTruthy()
    expect(within(planCard).queryByTestId('run-region')).toBeNull()
    expect(within(planCard).queryByTestId('run-outcome')).toBeNull()
    expect(within(planCard).queryByText('View receipt')).toBeNull()
  })

  it('runs an approved/read-only plan and links the resulting receipt', async () => {
    const user = userEvent.setup()
    renderTool()
    await screen.findByTestId('actions-row')

    await user.click(screen.getByTestId('op-observe'))
    const planCard = await screen.findByTestId('plan-card')
    await user.click(await within(planCard).findByTestId('plan-run'))

    // Live run region appears, then the outcome with the receipt link.
    await within(planCard).findByTestId('run-region')
    const outcome = await within(planCard).findByTestId('run-outcome', {}, { timeout: 10_000 })
    // Read-only run → honest "No changes" (never green "validated").
    expect(within(outcome).getByText('No changes')).toBeTruthy()
    const viewReceipt = within(outcome).getByText('View receipt')
    expect(viewReceipt).toBeTruthy()

    await user.click(viewReceipt)
    expect(await screen.findByTestId('receipt-detail')).toBeTruthy()
  }, 20_000)
})
