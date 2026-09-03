/**
 * Settings: group navigation + deep links, search, dirty-only save bar,
 * shortcut rebind conflict detection.
 */
import { expect, test } from '@playwright/test'

import { DESKTOP, gotoApp, onProjects } from './helpers'

test.describe('settings', () => {
  onProjects(DESKTOP)

  test('groups are navigable and deep-linkable', async ({ page }) => {
    await gotoApp(page, '#/settings')
    // Lands on the general group by default.
    await expect(page).toHaveURL(/#\/settings\/general$/)
    await expect(page.getByTestId('settings-group-general')).toBeVisible()

    await page.getByRole('button', { name: 'Editor' }).click()
    await expect(page.getByTestId('settings-group-editor')).toBeVisible()

    // Deep link straight into a group.
    await gotoApp(page, '#/settings/appearance')
    await expect(page.getByTestId('settings-group-appearance')).toBeVisible()
  })

  test('search finds "font size" settings', async ({ page }) => {
    await gotoApp(page, '#/settings')
    await page.getByTestId('settings-search').fill('font size')
    const results = page.getByTestId('settings-search-results')
    await expect(results).toBeVisible()
    await expect(results.getByRole('button', { name: /Editor.*Font size/ })).toBeVisible()
    // Activating a result jumps to the owning group.
    await results.getByRole('button', { name: /Editor.*Font size/ }).click()
    await expect(page.getByTestId('settings-group-editor')).toBeVisible()
  })

  test('save bar appears only when dirty', async ({ page }) => {
    await gotoApp(page, '#/settings/appearance')
    await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)

    await page.getByTestId('settings-group-appearance').getByRole('radio', { name: 'Dark' }).click()
    const bar = page.getByTestId('settings-save-bar')
    await expect(bar).toBeVisible()
    await expect(bar).toContainText('Unsaved changes')

    // Saving clears the dirty state.
    await bar.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
    // The saved theme persisted.
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  })

  test('shortcut rebind shows a conflict for a chord taken in the same scope', async ({ page }) => {
    await gotoApp(page, '#/settings/shortcuts')
    // "Command palette" defaults to mod+k; "Quick open" owns mod+p globally.
    await page.getByTestId('shortcut-rebind-global.command_palette').click()
    const capture = page.getByTestId('shortcut-capture-global.command_palette')
    await expect(capture).toBeVisible()
    await capture.press('Control+p')

    // Conflict surfaced, with the escape hatch to reassign anyway.
    await expect(page.getByText(/already bound|conflict|in use/i)).toBeVisible()
    await expect(page.getByTestId('shortcut-reassign-anyway')).toBeVisible()
  })

  test('application context lifecycle keeps operational transitions explicit', async ({ page }) => {
    await gotoApp(page, '#/app/ins_cto_pilot/settings?group=context')

    const surface = page.getByTestId('app-settings-context-lifecycle')
    await expect(surface).toBeVisible()
    await expect(surface).toContainText('Operational context, not application truth')
    await expect(surface).toContainText('Not accepted by this contract')
    await expect(surface).toContainText('Effective policy digest')
    await expect(surface).toContainText('Maximum input budget')
    await expect(surface).toContainText('Included categories')
    await expect(surface).toContainText('Repository identity')
    await expect(surface).toContainText('Candidate default — not benchmarked')
    await expect(surface).toContainText('Expected base commit')

    await surface.getByRole('combobox', { name: 'Context depth' }).selectOption('faster')
    await expect(surface.getByRole('combobox', { name: 'Context depth' })).toHaveValue('faster')

    await surface.getByTestId('context-handoff').click()
    const confirmation = page.getByTestId('confirm-dialog')
    await expect(confirmation).toContainText('Canonical application state remains unchanged')
    await confirmation.getByTestId('confirm-action').click()
    await expect(surface.getByTestId('context-transition-receipt')).toBeVisible()
  })
})
