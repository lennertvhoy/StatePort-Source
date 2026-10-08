/**
 * Files tool: tree → open → edit → dirty dot → Ctrl+S diff preview (never a
 * silent save) → confirm → receipt link; read-only files block edits.
 */
import { expect, test } from '@playwright/test'

import { DESKTOP, INSTANCES, gotoApp, onProjects } from './helpers'

const FILES = `#/app/${INSTANCES.ctoPilot}/workbench/files`

test.describe('files', () => {
  onProjects(DESKTOP)

  test('tree → open → edit → dirty dot → save preview → confirm → receipt', async ({ page }) => {
    await gotoApp(page, FILES)

    // Tree → open file.
    await page.getByTestId('tree-row-package.json').click()
    const editor = page.getByTestId('editor-host-primary-package.json').locator('.cm-content')
    await expect(editor).toBeVisible()
    await expect(editor).toContainText('"name": "cto-pilot"')

    // Edit → dirty dot on the tab + "Unsaved changes" in the status strip.
    await editor.click()
    await page.keyboard.press('Control+End')
    await page.keyboard.type('\n// e2e governed save')
    const tab = page.getByTestId('editor-tab-primary-package.json')
    await expect(tab.getByLabel('Unsaved changes')).toBeVisible()
    await expect(page.getByTestId('editor-status-strip')).toContainText('Unsaved changes')

    // Ctrl+S opens the diff preview — content must NOT be saved silently yet.
    await page.keyboard.press('Control+s')
    const preview = page.getByTestId('save-preview')
    await expect(preview).toBeVisible()
    await expect(preview).toContainText('Review changes — 1 file')
    await expect(preview).toContainText('e2e governed save')
    await expect(page.getByTestId('affected-paths')).toContainText('package.json')
    await expect(page.getByTestId('status-receipt-link')).toHaveCount(0)

    // Confirm → receipt link in the status strip; dirty dot clears.
    await page.getByTestId('confirm-save').click()
    await expect(preview).not.toBeVisible()
    await expect(page.getByTestId('status-receipt-link')).toBeVisible()
    await expect(tab.getByLabel('Unsaved changes')).toHaveCount(0)

    // The receipt link opens the receipt detail.
    await page.getByTestId('status-receipt-link').click()
    await expect(page).toHaveURL(/workbench\/receipts\/rcpt_/)
  })

  test('read-only file blocks editing (scenario)', async ({ page }) => {
    await gotoApp(page, FILES, 'file_read_only')
    await page.getByTestId('tree-row-package.json').click()
    const editor = page.getByTestId('editor-host-primary-package.json').locator('.cm-content')
    await expect(editor).toBeVisible()

    // Lock affordances: read-only tab marker + status strip.
    await expect(page.getByTestId('editor-tab-primary-package.json').getByLabel('Read-only')).toBeVisible()
    await expect(page.getByTestId('editor-status-strip')).toContainText('Read-only')

    // Typing is rejected; no dirty state; Ctrl+S opens no preview.
    await editor.click()
    await page.keyboard.type('SHOULD_NOT_LAND')
    await expect(editor).not.toContainText('SHOULD_NOT_LAND')
    await expect(page.getByTestId('editor-status-strip')).not.toContainText('Unsaved changes')
    await page.keyboard.press('Control+s')
    await expect(page.getByTestId('save-preview')).toHaveCount(0)
  })
})
