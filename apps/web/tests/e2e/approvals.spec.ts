/**
 * Approvals inbox: seeded pending approval, detail scope + digest, approve →
 * receipt link, exact empty-state copy via scenario.
 */
import { expect, test } from '@playwright/test'

import { DESKTOP, gotoApp, onProjects } from './helpers'

test.describe('approvals', () => {
  onProjects(DESKTOP)

  test('inbox lists the seeded pending approval', async ({ page }) => {
    await gotoApp(page, '#/approvals')
    await expect(page.getByTestId('pending-count')).toHaveText('1 pending')
    const row = page.getByTestId('approval-list').getByTestId('approval-row')
    await expect(row).toHaveCount(1)
    await expect(row).toContainText('Start virtual machine')
    await expect(row).toContainText('NixOS Infrastructure')
    await expect(row.getByTestId('status-badge')).toHaveText('Elevated')
  })

  test('detail shows exact scope and plan digest; approve yields receipt link', async ({ page }) => {
    await gotoApp(page, '#/approvals')
    await page.getByTestId('approval-row').click()
    await expect(page).toHaveURL(/#\/approvals\/appr_0001$/)

    const detail = page.getByTestId('approval-detail')
    await expect(detail).toBeVisible()
    await expect(detail.getByTestId('operation-state-label')).toHaveText('Awaiting approval')

    // Exact scope section with the plan steps and the digest.
    await expect(detail.getByRole('heading', { name: 'Exact scope' })).toBeVisible()
    await expect(page.getByTestId('plan-steps').getByRole('listitem').first()).toBeVisible()
    await expect(detail).toContainText('Plan digest')
    await expect(page.getByRole('button', { name: 'Copy plan digest' })).toBeVisible()
    // The digest renders elided (head…tail of the sha256 hex).
    const digestText = await detail.textContent()
    expect(digestText).toMatch(/[0-9a-f]{6,}…[0-9a-f]{6,}/)

    await page.getByTestId('approve-button').click()
    const result = page.getByTestId('decision-result')
    await expect(result).toContainText('Approved')
    const receipt = page.getByTestId('receipt-link')
    await expect(receipt).toBeVisible()
    await receipt.click()
    await expect(page).toHaveURL(/workbench\/receipts\/rcpt_/)
  })

  test('empty state renders exact copy (scenario)', async ({ page }) => {
    await gotoApp(page, '#/approvals', 'approvals_empty')
    const empty = page.getByTestId('empty-state')
    await expect(empty).toBeVisible()
    await expect(empty).toContainText('No pending approvals')
    await expect(empty).toContainText(
      'Actions that need your confirmation will appear here before they change an application.',
    )
  })
})
