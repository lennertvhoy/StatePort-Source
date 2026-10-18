/**
 * Infrastructure: honest state semantics (stopped = neutral, running +
 * health-unchecked ≠ success), plan prepare → steps → approve → run →
 * receipt, and the unavailable-target scenario hiding operation controls.
 */
import { expect, test } from '@playwright/test'

import { DESKTOP, INSTANCES, gotoApp, onProjects } from './helpers'

const DEPLOY = `#/app/${INSTANCES.nixosInfra}/workbench/deployments`

test.describe('infrastructure state semantics', () => {
  onProjects(DESKTOP)

  test('stopped VM renders a neutral label, not success/danger', async ({ page }) => {
    await gotoApp(page, DEPLOY)
    const vmFact = page.getByTestId('fact-vm')
    await expect(vmFact).toContainText('Stopped')
    await expect(vmFact).toHaveAttribute('data-state', 'neutral')
    // SSH honestly reports why it is unavailable; health is not checked.
    await expect(page.getByTestId('fact-ssh')).toContainText('SSH unavailable — VM stopped')
    await expect(page.getByTestId('fact-health')).toContainText('Not checked')
  })

  test('running VM with health unchecked is NOT presented as success', async ({ page }) => {
    await gotoApp(page, DEPLOY, 'vm_running_unchecked')
    const vmFact = page.getByTestId('fact-vm')
    await expect(vmFact).toContainText('Running')
    // Key contract: "running" without a health check must not look green.
    await expect(vmFact).not.toHaveAttribute('data-state', 'success')
    const healthFact = page.getByTestId('fact-health')
    await expect(healthFact).toContainText('Not checked')
    await expect(healthFact).toHaveAttribute('data-state', 'attention')
  })
})

test.describe('plan workflow', () => {
  onProjects(DESKTOP)

  test('prepare → steps visible → approve → run → receipt link', async ({ page }) => {
    await gotoApp(page, DEPLOY)

    // Prepare: nothing runs until approved + explicitly run.
    const planCard = page.getByTestId('plan-card')
    const previousPlanId = await planCard.getAttribute('data-plan-id')
    await page.getByTestId('op-start').click()
    await expect(planCard).not.toHaveAttribute('data-plan-id', previousPlanId ?? '')
    const preparedPlanId = await planCard.getAttribute('data-plan-id')
    const preparedPlanDigest = await planCard.getAttribute('data-plan-digest')
    expect(preparedPlanId).toMatch(/^plan_/)
    expect(preparedPlanDigest).toMatch(/^[0-9a-f]{64}$/)
    await expect(planCard).toBeVisible()
    await expect(planCard.getByTestId('operation-state-label')).toHaveText('Awaiting approval')
    // Steps are visible in the plan stepper.
    const stepper = page.getByTestId('plan-stepper')
    await expect(stepper).toContainText('Prepare')
    await expect(stepper).toContainText('Approve')
    await expect(stepper).toContainText('Run')
    await expect(stepper).toContainText('Receipt')

    // Approve via the linked approval.
    await page.getByTestId('plan-approval-state').getByRole('button', { name: 'Go to approval' }).click()
    await expect(page).toHaveURL(/#\/approvals\/appr_/)
    await page.getByTestId('approve-button').click()
    await expect(page.getByTestId('decision-result')).toContainText('Approved')
    await expect(page.getByTestId('receipt-link')).toBeVisible()

    // Direct navigation remounts the infrastructure surface. The exact
    // approved plan remains runnable, but nothing has executed yet.
    await gotoApp(page, DEPLOY)
    await expect(planCard).toHaveAttribute('data-plan-id', preparedPlanId ?? '')
    await expect(planCard).toHaveAttribute('data-plan-digest', preparedPlanDigest ?? '')
    await expect(planCard.getByTestId('operation-state-label')).toHaveText('Approved')
    await expect(planCard.getByTestId('plan-approval-state')).toContainText('Approved — ready to run.')
    await expect(planCard.getByTestId('run-region')).toHaveCount(0)
    await expect(page.getByTestId('plan-run')).toBeVisible()
    await page.getByTestId('plan-run').click()

    // Receipt link once the run settles.
    const outcome = page.getByTestId('run-outcome')
    await expect(outcome).toBeVisible({ timeout: 20_000 })
    await expect(outcome).toContainText('Validated')
    const receiptButton = outcome.getByRole('button', { name: 'View receipt' })
    await expect(receiptButton).toBeVisible()
    await receiptButton.click()
    await expect(page).toHaveURL(/workbench\/receipts\/rcpt_/)
  })
})

test.describe('unavailable target', () => {
  onProjects(DESKTOP)

  test('unavailable-target scenario hides operation controls', async ({ page }) => {
    await gotoApp(page, DEPLOY, 'deployment_target_unavailable')
    await expect(page.getByTestId('deployments-unavailable')).toBeVisible()
    await expect(page.getByTestId('deployments-unavailable')).toContainText('Target unavailable')
    // No active-looking controls for an unavailable capability.
    await expect(page.getByTestId('actions-row')).toHaveCount(0)
    await expect(page.getByTestId('op-start')).toHaveCount(0)
    await expect(page.getByTestId('operations-menu-trigger')).toHaveCount(0)
  })
})
