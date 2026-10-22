/**
 * Terminal: neutral initial state (no auto-connect, never danger-colored),
 * explicit Connect → prompt, `help` output, multiline paste guard, neutral
 * ended state.
 */
import { expect, test } from '@playwright/test'

import { DESKTOP, INSTANCES, expectNoDangerColor, gotoApp, onProjects } from './helpers'

const TERMINAL = `#/app/${INSTANCES.ctoPilot}/workbench/terminal`

test.describe('terminal', () => {
  onProjects(DESKTOP)

  test('initial state is neutral "Ready to connect" with no auto-connection', async ({ page }) => {
    await gotoApp(page, TERMINAL)

    const start = page.getByTestId('terminal-start')
    await expect(start).toBeVisible()
    await expect(start.getByRole('heading', { name: 'Ready to connect' })).toBeVisible()
    await expect(start.getByTestId('terminal-connect')).toBeVisible()

    // Nothing connected on its own.
    await expect(page.getByTestId('terminal-state-label')).toHaveCount(0)
    await expect(page.getByTestId('terminal-sessions-panel')).toContainText('No sessions')

    // Neutral semantics — the disconnected state must not be danger-colored.
    await expectNoDangerColor(page, 'terminal-start')
  })

  test('explicit Connect produces a shell prompt; help prints output', async ({ page }) => {
    await gotoApp(page, TERMINAL)
    await page.getByTestId('terminal-start').getByTestId('terminal-connect').click()
    await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
    await expect(page.locator('.xterm-rows')).toContainText('$')

    await page.getByTestId('terminal-canvas').click()
    await page.keyboard.type('help')
    await page.keyboard.press('Enter')
    // xterm keeps the full command response in scrollback even when the
    // header naturally scrolls above a short visible viewport. Assert a
    // command-list row rather than coupling this contract to row geometry;
    // the complete response is covered by the runtime's focused unit test.
    await expect(page.locator('.xterm-rows')).toContainText('git status')
  })

  test('multiline paste triggers the safety warning; cancel inserts nothing', async ({ page }) => {
    await gotoApp(page, TERMINAL)
    await page.getByTestId('terminal-start').getByTestId('terminal-connect').click()
    await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
    await page.getByTestId('terminal-canvas').click()

    await page.evaluate(() => {
      const ta = document.querySelector('.xterm-helper-textarea')!
      const dt = new DataTransfer()
      dt.setData('text/plain', 'help\npwd\nls')
      ta.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }))
    })

    const dialog = page.getByTestId('paste-guard-dialog')
    await expect(dialog).toBeVisible()
    await expect(dialog).toContainText('Paste multiple lines?')
    await expect(dialog).toContainText('3 lines')

    await page.getByTestId('paste-guard-cancel').click()
    await expect(dialog).not.toBeVisible()
    // Cancelled paste must not reach the shell.
    await expect(page.locator('.xterm-rows')).not.toContainText('helppwdls')
  })

  test('End returns to a neutral ended state', async ({ page }) => {
    await gotoApp(page, TERMINAL)
    await page.getByTestId('terminal-start').getByTestId('terminal-connect').click()
    await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')

    await page.getByTestId('terminal-end').click()
    await expect(page.getByTestId('terminal-state-label')).toHaveText('Session ended')
    const endedBar = page.getByTestId('terminal-ended-bar')
    await expect(endedBar).toBeVisible()
    await expect(endedBar).toContainText('Session ended')
    // Ended is a neutral state, not a failure color.
    await expectNoDangerColor(page, 'terminal-ended-bar')
  })
})
